"""nmap_deep — per-asset intense nmap scan adapter.

Wraps nmap with `-A -T4 -Pn` (intense scan profile) against a single host
(subdomain FQDN or ipv4). `-A` enables OS detection, version detection, script
scanning, and traceroute. `-T4` uses faster timing template. `-Pn` skips host
discovery so cloud hosts behind ICMP filters still scan.

Emits:

- One `ServiceUpdateRecord` per open port (service_name, product, version,
  banner, cpes) — worker dispatches to `services/service_enrichment.upsert_service_enrichment`.
- `FindingRecord` rows for NSE script hits:
    - `nse_vuln_<sid>` for `vuln`-category scripts (severity from script's own
      VULNERABLE / LIKELY VULNERABLE markers).
    - `service_banner_leak` for `banner` script results (low severity, info disclosure).
    - `nse_<sid>` for other script-class output (low severity).

Honors `params.port` (int) to scan one port instead of `--top-ports 1000`.
Ignores `params.protocol` — nmap is port-based, protocol-agnostic.

Authz-gated (active scan traffic).
"""
from __future__ import annotations

import asyncio
import logging
import shutil
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

from app.pipeline.investigation.stage import (
    FindingRecord,
    InvestigationResult,
    ServiceUpdateRecord,
    TaskContext,
)
from app.workers.sandbox import get_preexec_fn

log = logging.getLogger(__name__)

_BINARY = "nmap"
_TIMEOUT_SEC = 600  # 10 min — fits within investigation worker job_timeout (15 min)
_RAW_CAP_BYTES = 100_000


class NmapDeepAdapter:
    tool = "nmap_deep"

    async def execute(self, ctx: TaskContext) -> InvestigationResult:
        binary = shutil.which(_BINARY)
        if binary is None:
            return InvestigationResult(
                findings=[
                    FindingRecord(
                        kind="tool_error",
                        severity="info",
                        title="nmap binary not found",
                        description=(
                            "nmap not on PATH in investigation worker container."
                        ),
                    )
                ],
                raw_output="nmap binary missing",
            )

        from app.services.net_guard import assert_target_allowed
        from app.services.scan_profiles import resolve_args

        host = ctx.asset_canonical_key
        try:
            assert_target_allowed(host)
        except ValueError as e:
            return InvestigationResult(
                findings=[
                    FindingRecord(
                        kind="tool_error",
                        severity="info",
                        title="target blocked",
                        description=str(e),
                    )
                ],
                raw_output=str(e),
            )
        profile_args = resolve_args("nmap_deep", ctx.params or {})
        if not profile_args:
            # Fallback to aggressive default if profile resolution returned nothing
            profile_args = ["-A", "-T4", "-Pn"]

        with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as f:
            out_path = Path(f.name)

        cmd = [
            binary,
            *profile_args,
            "-oX", str(out_path),
            host,
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
                return InvestigationResult(
                    findings=[
                        FindingRecord(
                            kind="tool_error",
                            severity="info",
                            title="nmap deep scan timed out",
                            description=(
                                f"nmap exceeded {_TIMEOUT_SEC}s on {host}. "
                                "Try a single-port scan (params.port) for faster results."
                            ),
                        )
                    ],
                    raw_output=(
                        f"timeout after {_TIMEOUT_SEC}s\n"
                        f"{raw_stderr[:_RAW_CAP_BYTES]}"
                    ),
                    exit_code=proc.returncode,
                    stderr=raw_stderr,
                )

            if not out_path.exists() or out_path.stat().st_size == 0:
                return InvestigationResult(
                    findings=[
                        FindingRecord(
                            kind="tool_error",
                            severity="info",
                            title="nmap produced no output",
                            description=(
                                "No XML emitted. Target may be unreachable or all "
                                "scanned ports closed."
                            ),
                            evidence={"stderr": raw_stderr[:1000]},
                        )
                    ],
                    raw_output=raw_stderr[:_RAW_CAP_BYTES],
                    exit_code=proc.returncode,
                    stderr=raw_stderr,
                )

            try:
                raw_xml = out_path.read_text(encoding="utf-8", errors="replace")
            except OSError as e:
                log.warning("nmap_deep XML read failed: %s", e)
                raw_xml = ""

            services, findings = _parse_nmap_xml(raw_xml, host=host)

            raw_output = raw_xml
            if len(raw_output) > _RAW_CAP_BYTES:
                raw_output = (
                    raw_output[:_RAW_CAP_BYTES]
                    + f"\n[truncated {len(raw_xml) - _RAW_CAP_BYTES} bytes]"
                )

            return InvestigationResult(
                services=services,
                findings=findings,
                raw_output=raw_output,
                exit_code=proc.returncode,
                stderr=raw_stderr,
            )
        finally:
            out_path.unlink(missing_ok=True)


def _parse_nmap_xml(
    xml_text: str, *, host: str
) -> tuple[list[ServiceUpdateRecord], list[FindingRecord]]:
    services: list[ServiceUpdateRecord] = []
    findings: list[FindingRecord] = []

    if not xml_text.strip():
        return services, findings

    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as e:
        log.warning("nmap_deep XML parse failed: %s", e)
        return [], [
            FindingRecord(
                kind="tool_error",
                severity="info",
                title="nmap XML parse error",
                description=str(e),
            )
        ]

    for port_el in root.findall(".//port"):
        state_el = port_el.find("state")
        if state_el is None or state_el.get("state") != "open":
            continue
        try:
            portid = int(port_el.get("portid", "0"))
        except ValueError:
            continue
        proto = (port_el.get("protocol") or "tcp").lower()

        svc_el = port_el.find("service")
        service_name = svc_el.get("name") if svc_el is not None else None
        product = svc_el.get("product") if svc_el is not None else None
        version = svc_el.get("version") if svc_el is not None else None
        extra = svc_el.get("extrainfo") if svc_el is not None else None

        banner_parts = [p for p in [product, version, extra] if p]
        banner = " ".join(banner_parts) if banner_parts else None

        cpes: list[str] = []
        if svc_el is not None:
            for cpe_el in svc_el.findall("cpe"):
                if cpe_el.text:
                    cpes.append(cpe_el.text)

        services.append(
            ServiceUpdateRecord(
                host=host,
                port=portid,
                proto=proto,
                service_name=service_name,
                product=product,
                version=version,
                banner=banner,
                cpes=cpes,
            )
        )

        for script_el in port_el.findall("script"):
            f = _script_to_finding(script_el, host=host, port=portid, proto=proto)
            if f is not None:
                findings.append(f)

    # Host-level scripts (e.g. smb-vuln-*, ssl-*).
    for script_el in root.findall(".//hostscript/script"):
        f = _script_to_finding(script_el, host=host, port=None, proto=None)
        if f is not None:
            findings.append(f)

    return services, findings


def _script_to_finding(
    script_el: ET.Element,
    *,
    host: str,
    port: int | None,
    proto: str | None,
) -> FindingRecord | None:
    sid = script_el.get("id") or ""
    output = (script_el.get("output") or "").strip()
    if not sid or not output:
        return None

    severity, kind = _classify_nse(sid, output)
    if severity == "skip":
        return None

    port_suffix = f":{port}" if port is not None else ""
    title = (
        f"nmap {sid} on {host}{port_suffix}: {_first_line(output)[:120]}"
    )
    evidence = {
        "host": host,
        "script_id": sid,
        "output": output[:5000],
    }
    if port is not None:
        evidence["port"] = port
    if proto is not None:
        evidence["proto"] = proto

    return FindingRecord(
        kind=kind,
        severity=severity,
        title=title[:200],
        description=output[:1500],
        evidence=evidence,
    )


def _first_line(s: str) -> str:
    for ln in s.splitlines():
        ln = ln.strip()
        if ln:
            return ln
    return ""


def _classify_nse(sid: str, output: str) -> tuple[str, str]:
    """Return (severity, kind) for an NSE script result.

    severity 'skip' → caller drops the finding (e.g. 'not vulnerable').
    """
    low = output.lower()
    sid_low = sid.lower()

    if sid_low == "banner":
        return ("low", "service_banner_leak")

    if "vuln" in sid_low or sid_low.endswith("-check"):
        if "not vulnerable" in low:
            return ("skip", "")
        if "state: vulnerable" in low or "vulnerable:" in low:
            return ("high", f"nse_vuln_{sid_low}")
        if "likely vulnerable" in low:
            return ("med", f"nse_vuln_{sid_low}")
        # Ran but no clear marker — info disclosure of the check itself.
        return ("info", f"nse_vuln_{sid_low}")

    return ("low", f"nse_{sid_low}")
