"""ffuf — content-discovery fuzzer adapter for the investigation worker.

Wraps ffuf v2.x against a single host. Builds the URL as
`{protocol}://{host}[:{port}]/FUZZ` (protocol + port honored from
`TaskContext.params`; defaults `https` + `443`/`80`). Emits one
`EndpointRecord` per fuzz hit + classifier-driven `FindingRecord` rows for
admin / login / api / upload endpoints discovered.

Output JSON shape (ffuf 2.x):
{
  "commandline": "...", "time": "...",
  "results": [
    {"url": "...", "status": 200, "length": 1234, "words": 100, "lines": 50,
     "content-type": "text/html", "redirectlocation": "", "input": {"FUZZ": "admin"},
     "duration": 12345},
     ...
  ]
}

Authz-gated (active scan traffic).
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
import sys
import tempfile
from pathlib import Path
from urllib.parse import urlparse

from app.pipeline.investigation.stage import (
    EndpointRecord,
    FindingRecord,
    InvestigationResult,
    TaskContext,
)
from app.pipeline.investigation.endpoint_classifier import _classify
from app.workers.sandbox import get_preexec_fn

log = logging.getLogger(__name__)

_BINARY = "ffuf"
_TIMEOUT_SEC = 300
_RAW_CAP_BYTES = 100_000
# All major status codes per user spec. 404 intentionally excluded — most
# wordlist entries return it, would flood the result table with noise.
_MATCH_CODES = "200,204,301,302,307,308,400,401,403,405,500,502,503"
_DEFAULT_WORDLIST = os.environ.get(
    "INVESTIGATION_WORDLIST", "/wordlists/common.txt"
)


class FfufAdapter:
    tool = "ffuf"

    async def execute(self, ctx: TaskContext) -> InvestigationResult:
        binary = shutil.which(_BINARY)
        if binary is None:
            return _tool_error_result("ffuf binary not found on PATH")

        # Wordlist is never client-controllable: an attacker-chosen path here
        # would let ffuf read arbitrary local files (their matched lines leak
        # back via ffuf's own JSON output). Always the server-side default.
        wordlist = _DEFAULT_WORDLIST
        if not Path(wordlist).is_file():
            return _tool_error_result(f"wordlist missing: {wordlist}")

        protocol = (ctx.params.get("protocol") or "https").lower()
        if protocol not in {"http", "https"}:
            protocol = "https"
        host = ctx.asset_canonical_key

        from app.services.net_guard import assert_target_allowed

        try:
            assert_target_allowed(host)
        except ValueError as e:
            return _tool_error_result(str(e))

        port = ctx.params.get("port")
        if port is not None:
            try:
                port = int(port)
            except (TypeError, ValueError):
                port = None
        host_part = host if port is None else f"{host}:{port}"
        url = f"{protocol}://{host_part}/FUZZ"

        from app.services.scan_profiles import resolve_args

        profile_args = resolve_args("ffuf", ctx.params or {})
        if not profile_args:
            profile_args = [
                "-mc", _MATCH_CODES,
                "-t", "40",
                "-timeout", "10",
            ]

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            out_path = Path(f.name)

        cmd = [
            binary,
            "-u", url,
            "-w", wordlist,
            *profile_args,
            "-of", "json",
            "-o", str(out_path),
            "-noninteractive",
        ]

        raw_stderr = ""
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                preexec_fn=get_preexec_fn() if sys.platform != "win32" else None,
            )
            try:
                _, stderr_b = await asyncio.wait_for(
                    proc.communicate(), timeout=_TIMEOUT_SEC
                )
                raw_stderr = (stderr_b or b"").decode("utf-8", errors="replace")
            except asyncio.TimeoutError:
                proc.kill()
                try:
                    await asyncio.wait_for(proc.wait(), timeout=5)
                except asyncio.TimeoutError:
                    pass
                return _tool_error_result(
                    f"ffuf exceeded {_TIMEOUT_SEC}s on {url}",
                    raw_output=raw_stderr[:_RAW_CAP_BYTES],
                    exit_code=proc.returncode,
                    stderr=raw_stderr,
                )

            if not out_path.exists() or out_path.stat().st_size == 0:
                return _tool_error_result(
                    "ffuf produced no output (target unreachable or no matches)",
                    raw_output=raw_stderr[:_RAW_CAP_BYTES],
                    severity="info",
                    exit_code=proc.returncode,
                    stderr=raw_stderr,
                )

            try:
                raw_json = out_path.read_text(encoding="utf-8", errors="replace")
            except OSError as e:
                log.warning("ffuf output read failed: %s", e)
                raw_json = ""

            endpoints, findings = _parse_ffuf_json(raw_json, fallback_url=url)

            raw_output = raw_json
            if len(raw_output) > _RAW_CAP_BYTES:
                raw_output = (
                    raw_output[:_RAW_CAP_BYTES]
                    + f"\n[truncated {len(raw_json) - _RAW_CAP_BYTES} bytes]"
                )

            return InvestigationResult(
                endpoints=endpoints,
                findings=findings,
                raw_output=raw_output,
                exit_code=proc.returncode,
                stderr=raw_stderr,
            )
        finally:
            out_path.unlink(missing_ok=True)


def _tool_error_result(
    msg: str,
    *,
    raw_output: str = "",
    severity: str = "info",
    exit_code: int | None = None,
    stderr: str = "",
) -> InvestigationResult:
    return InvestigationResult(
        findings=[
            FindingRecord(
                kind="tool_error",
                severity=severity,
                title=msg[:200],
                description=msg,
            )
        ],
        raw_output=raw_output or msg,
        exit_code=exit_code,
        stderr=stderr,
    )


def _parse_ffuf_json(
    raw_json: str, *, fallback_url: str
) -> tuple[list[EndpointRecord], list[FindingRecord]]:
    endpoints: list[EndpointRecord] = []
    findings: list[FindingRecord] = []

    if not raw_json.strip():
        return endpoints, findings

    try:
        data = json.loads(raw_json)
    except json.JSONDecodeError as e:
        return [], [
            FindingRecord(
                kind="tool_error",
                severity="info",
                title="ffuf JSON parse error",
                description=str(e),
            )
        ]

    for hit in data.get("results") or []:
        url = hit.get("url") or ""
        if not url:
            continue
        status = hit.get("status")
        length = hit.get("length")
        words = hit.get("words")
        lines = hit.get("lines")
        ctype = hit.get("content-type") or hit.get("contentType")
        redirect = hit.get("redirectlocation") or hit.get("redirect")
        duration = hit.get("duration")
        path = urlparse(url).path or "/"

        endpoints.append(
            EndpointRecord(
                url=url,
                path=path,
                method="GET",
                status_code=int(status) if status is not None else None,
                content_type=ctype,
                content_length=int(length) if length is not None else None,
            )
        )

        flags = _classify(path)
        kind_flags: list[str] = []
        for flag_name, kind in (
            ("is_admin", "admin_panel"),
            ("is_login", "login_form"),
            ("is_api", "api_endpoint"),
            ("is_upload", "upload_form"),
            ("is_signup", "signup_form"),
        ):
            if flags.get(flag_name):
                kind_flags.append(kind)

        # Emit ONE finding per discovered endpoint regardless of classifier hits.
        # Previously only classifier matches produced findings, so plain 200 OK
        # paths never showed up in the UI even though they were valid hits.
        severity = (
            "med" if any(k in {"admin_panel", "upload_form"} for k in kind_flags)
            else "low" if kind_flags
            else "info"
        )
        findings.append(
            FindingRecord(
                kind="discovered_endpoint",
                severity=severity,
                title=f"{status if status is not None else '?'} {path}"[:200],
                description=(
                    f"ffuf discovered {url} (HTTP {status})."
                    + (f" Classifier: {', '.join(kind_flags)}." if kind_flags else "")
                ),
                evidence={
                    "url": url,
                    "path": path,
                    "status": status,
                    "content_type": ctype,
                    "content_length": length,
                    "words": words,
                    "lines": lines,
                    "redirect": redirect,
                    "duration_ms": duration,
                    "flags": kind_flags,
                },
            )
        )

    return endpoints, findings
