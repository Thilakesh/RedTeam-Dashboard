"""dirsearch — directory bruteforcer adapter for the investigation worker.

Wraps dirsearch v0.4.x against a single host. URL built as
`{protocol}://{host}[:{port}]` (protocol/port honored from `TaskContext.params`).

Emits one `EndpointRecord` per hit + `FindingRecord` rows for high-signal
disclosures:
  - `exposed_dotgit`     — paths under /.git/
  - `exposed_dotenv`     — /.env
  - `backup_file`        — *.bak/.swp/.old/.backup/~ trailing
  - `swagger_exposed`    — swagger / openapi / api-docs paths
  - `directory_indexing` — 200 + "Index of /" title (best-effort from content-length cue)
  - admin/login/api/upload via shared endpoint_classifier (low/med)

Output JSON shape (dirsearch v0.4.3):
{
  "info": {"args": "...", "time": "...", "version": "..."},
  "results": [
    {"url": "...", "status": 200, "content-length": 1234,
     "content-type": "text/html", "redirect": "..."}
  ]
}

Authz-gated (active scan traffic).
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import re
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

_BINARY = "dirsearch"
_TIMEOUT_SEC = 300
_RAW_CAP_BYTES = 100_000
_DEFAULT_WORDLIST = os.environ.get(
    "INVESTIGATION_WORDLIST", "/wordlists/common.txt"
)

_BACKUP_RE = re.compile(r"\.(bak|swp|old|backup|orig|save)$|~$", re.I)
_SWAGGER_RE = re.compile(
    r"/(swagger|openapi(\.json|\.yaml)?|api[-_]?docs|swagger-ui)", re.I
)
_DOTGIT_RE = re.compile(r"/\.git(/|$)", re.I)
_DOTENV_RE = re.compile(r"/\.env(\.|$)", re.I)


class DirsearchAdapter:
    tool = "dirsearch"

    async def execute(self, ctx: TaskContext) -> InvestigationResult:
        binary = shutil.which(_BINARY)
        if binary is None:
            return _tool_error_result("dirsearch binary not found on PATH")

        # Wordlist is never client-controllable — see ffuf.py for why. Always
        # the server-side default.
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
        url = f"{protocol}://{host_part}"

        from app.services.scan_profiles import resolve_args

        profile_args = resolve_args("dirsearch", ctx.params or {})
        if not profile_args:
            profile_args = ["-t", "20"]

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            out_path = Path(f.name)

        cmd = [
            binary,
            "-u", url,
            "-w", wordlist,
            "--format=json",
            "-o", str(out_path),
            "--quiet-mode",
            "--no-color",
            *profile_args,
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
                    f"dirsearch exceeded {_TIMEOUT_SEC}s on {url}",
                    raw_output=raw_stderr[:_RAW_CAP_BYTES],
                )

            if not out_path.exists() or out_path.stat().st_size == 0:
                return _tool_error_result(
                    "dirsearch produced no output (target unreachable or no matches)",
                    raw_output=raw_stderr[:_RAW_CAP_BYTES],
                    severity="info",
                )

            try:
                raw_json = out_path.read_text(encoding="utf-8", errors="replace")
            except OSError as e:
                log.warning("dirsearch output read failed: %s", e)
                raw_json = ""

            endpoints, findings = _parse_dirsearch_json(raw_json)

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
            )
        finally:
            out_path.unlink(missing_ok=True)


def _tool_error_result(
    msg: str, *, raw_output: str = "", severity: str = "info"
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
    )


def _parse_dirsearch_json(
    raw_json: str,
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
                title="dirsearch JSON parse error",
                description=str(e),
            )
        ]

    # dirsearch v0.4.3 format: {"results": [...]} or {"<base_url>": [...]}
    results = data.get("results")
    if results is None:
        for v in data.values():
            if isinstance(v, list):
                results = v
                break
    if not results:
        return endpoints, findings

    for hit in results:
        url = hit.get("url") or ""
        if not url:
            continue
        status = hit.get("status")
        length = hit.get("content-length") or hit.get("contentLength")
        ctype = hit.get("content-type") or hit.get("contentType")
        redirect = hit.get("redirect") or hit.get("redirectlocation")
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

        # Collect classifier flags for this row
        kind_flags: list[str] = []
        if _DOTGIT_RE.search(path):
            kind_flags.append("exposed_dotgit")
        if _DOTENV_RE.search(path):
            kind_flags.append("exposed_dotenv")
        if _BACKUP_RE.search(path):
            kind_flags.append("backup_file")
        if _SWAGGER_RE.search(path):
            kind_flags.append("swagger_exposed")
        if (
            status == 200
            and path.endswith("/")
            and isinstance(ctype, str)
            and "text/html" in ctype.lower()
        ):
            kind_flags.append("directory_indexing")
        flags = _classify(path)
        for flag_name, kind in (
            ("is_admin", "admin_panel"),
            ("is_login", "login_form"),
            ("is_api", "api_endpoint"),
            ("is_upload", "upload_form"),
        ):
            if flags.get(flag_name):
                kind_flags.append(kind)

        evidence = {
            "url": url,
            "path": path,
            "status": status,
            "content_type": ctype,
            "content_length": length,
            "redirect": redirect,
            "flags": kind_flags,
        }

        # Emit ONE discovered_endpoint finding per result so plain hits show
        # up in the UI even without classifier matches.
        severity = (
            "high"
            if any(k in {"exposed_dotgit", "exposed_dotenv"} for k in kind_flags)
            else "med"
            if any(
                k in {
                    "backup_file", "swagger_exposed", "directory_indexing",
                    "admin_panel", "upload_form",
                }
                for k in kind_flags
            )
            else "low"
            if kind_flags
            else "info"
        )
        findings.append(
            FindingRecord(
                kind="discovered_endpoint",
                severity=severity,
                title=f"{status if status is not None else '?'} {path}"[:200],
                description=(
                    f"dirsearch discovered {url} (HTTP {status})."
                    + (f" Classifier: {', '.join(kind_flags)}." if kind_flags else "")
                ),
                evidence=evidence,
            )
        )

    return endpoints, findings


def _finding(kind: str, severity: str, path: str, evidence: dict) -> FindingRecord:
    return FindingRecord(
        kind=kind,
        severity=severity,
        title=f"{kind.replace('_', ' ')}: {path}"[:200],
        description=f"dirsearch discovered {path} (HTTP {evidence.get('status')})",
        evidence=evidence,
    )
