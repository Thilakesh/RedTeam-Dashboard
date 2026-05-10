"""nmap NSE vuln-category scanner.

Runs nmap with safe NSE script categories (`vuln`, `http-enum`, `ssl-cert`)
against open services from the recon asset graph. Targets are limited to a
small set of common ports per host so we don't fan out into a slow scan.

Output is XML on stdout (`-oX -`); parsed for `<script>` results inside
`<port>` elements that have non-trivial output. Each emitted VulnRecord is
keyed `nse:{script_id}:{service_id}`.

Non-intrusive: NSE `vuln` category contains check-only scripts (no exploit
payloads). The per-port timeout caps blast radius if a script misbehaves.

Fail-soft: optional=True; returns [] on binary missing or parse failure.
"""

from __future__ import annotations

import asyncio
import logging
import shutil
import xml.etree.ElementTree as ET
from collections import defaultdict

from app.pipeline.vuln.stage import VulnEvidenceRecord, VulnRecord, VulnStageContext

log = logging.getLogger(__name__)

_BINARY = "nmap"
_SCRIPTS = "vuln,http-enum,ssl-cert"
_TIMEOUT_SEC = 1200
_TARGET_PORTS = {21, 22, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 8080, 8443}


def _binary_available() -> bool:
    return shutil.which(_BINARY) is not None


def _severity_from_script(output: str) -> str:
    """Heuristic: NSE doesn't emit CVSS. Bump severity if the output mentions
    a CVE or vulnerability state."""
    low = output.lower()
    if "vulnerable: yes" in low or "state: vulnerable" in low:
        return "HIGH"
    if "cve-" in low:
        return "MED"
    return "LOW"


def _extract_cves(output: str) -> list[str]:
    import re
    return list({m.upper() for m in re.findall(r"CVE-\d{4}-\d{4,7}", output, re.I)})


class NmapNseVulnStage:
    name = "nmap_nse_vuln"
    source_tool = "nmap-nse"
    depends_on: list[str] = []
    weight = 80
    optional = True
    intrusive_required = False

    def applies(self, ctx: VulnStageContext) -> bool:
        return bool(ctx.services)

    async def execute_vuln(self, ctx: VulnStageContext) -> list[VulnRecord]:
        if not _binary_available():
            log.warning("nmap_nse_vuln: binary %r not found — skipping", _BINARY)
            return []

        # Group target services by host so we issue one nmap invocation per host.
        host_to_services: dict[str, list] = defaultdict(list)
        for svc in ctx.services:
            if svc.state != "open":
                continue
            if svc.port not in _TARGET_PORTS:
                continue
            host_to_services[svc.host].append(svc)

        if not host_to_services:
            return []

        records: list[VulnRecord] = []
        sem = asyncio.Semaphore(3)

        async def scan_host(host: str, services: list) -> list[VulnRecord]:
            ports = ",".join(str(s.port) for s in services)
            svc_by_port = {s.port: s for s in services}
            cmd = [
                _BINARY,
                "-Pn",
                "-sT",
                "-sV",
                "--script", _SCRIPTS,
                "--script-timeout", "60s",
                "-p", ports,
                "-oX", "-",
                host,
            ]
            async with sem:
                try:
                    proc = await asyncio.create_subprocess_exec(
                        *cmd,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.DEVNULL,
                    )
                    stdout, _ = await asyncio.wait_for(
                        proc.communicate(), timeout=_TIMEOUT_SEC
                    )
                except (asyncio.TimeoutError, FileNotFoundError):
                    return []
                except Exception as exc:
                    log.warning("nmap_nse_vuln: %s failed: %s", host, exc)
                    return []

            try:
                root = ET.fromstring(stdout)
            except ET.ParseError:
                return []

            out: list[VulnRecord] = []
            for port_el in root.iter("port"):
                try:
                    portid = int(port_el.attrib.get("portid", "0"))
                except ValueError:
                    continue
                svc = svc_by_port.get(portid)
                if svc is None:
                    continue
                for script in port_el.findall("script"):
                    sid = script.attrib.get("id", "")
                    output = script.attrib.get("output", "") or ""
                    if not sid or not output.strip():
                        continue
                    # Filter out scripts that ran but found nothing
                    low = output.lower()
                    if "couldn't" in low or "error" in low and "no " in low:
                        continue
                    if "no " in low and "found" in low:
                        continue

                    severity = _severity_from_script(output)
                    cves = _extract_cves(output)
                    canonical_key = f"nse:{sid}:{svc.id}"
                    out.append(
                        VulnRecord(
                            asset_id=svc.asset_id,
                            service_id=svc.id,
                            canonical_key=canonical_key,
                            title=f"NSE {sid} on {host}:{portid}",
                            severity=severity,
                            description=output[:500],
                            template_id=sid,
                            cve_ids=cves,
                            evidence=VulnEvidenceRecord(
                                source_tool="nmap-nse",
                                matcher_name=sid,
                                extracted={"host": host, "port": portid, "output": output[:1000]},
                                confidence=70,
                            ),
                        )
                    )
            return out

        host_results = await asyncio.gather(
            *(scan_host(h, s) for h, s in host_to_services.items()),
            return_exceptions=False,
        )
        for r in host_results:
            records.extend(r)
        return records
