"""testssl.sh adapter — TLS misconfiguration / weak-cipher / cert checks.

Runs testssl.sh per HTTPS http_service URL with `--jsonfile-pretty` output. We
restrict to fast severity-relevant checks (`--protocols --ciphers --vulnerable
--server-defaults`) so a scan against many hosts stays under the per-stage
timeout.

Non-intrusive: testssl negotiates handshakes only; it does not send exploits.
Fail-soft: optional=True, returns [] if binary missing or run fails.
"""

from __future__ import annotations

import asyncio
import json
import logging
import shutil
import tempfile
from pathlib import Path
from urllib.parse import urlparse

from app.pipeline.vuln.stage import VulnEvidenceRecord, VulnRecord, VulnStageContext

log = logging.getLogger(__name__)

_BINARY = "testssl.sh"
_TIMEOUT_SEC = 300       # per-host
_OVERALL_TIMEOUT = 1200  # whole stage

_SEVERITY_BY_TESTSSL = {
    "CRITICAL": "CRITICAL",
    "HIGH": "HIGH",
    "MEDIUM": "MED",
    "LOW": "LOW",
    "WARN": "LOW",
    "INFO": "INFO",
    "OK": "INFO",
    "DEBUG": "INFO",
}
# testssl IDs we never bother emitting (purely informational scan metadata)
_NOISE_IDS = {
    "scanTime", "scanProblem", "service", "engine", "openssl", "scriptVersion",
    "openssl_version", "cipherorder_TLSv1", "cipherorder_TLSv1_1",
}


def _binary_available() -> bool:
    return shutil.which(_BINARY) is not None


async def _run_one(url: str) -> list[dict]:
    """Run testssl against a single URL. Returns list of finding dicts or []."""
    parsed = urlparse(url)
    host_port = parsed.netloc or parsed.path
    if not host_port:
        return []

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
        out_path = Path(tf.name)

    cmd = [
        _BINARY,
        "--quiet",
        "--color", "0",
        "--jsonfile-pretty", str(out_path),
        "--protocols",
        "--server-defaults",
        "--vulnerable",
        host_port,
    ]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            await asyncio.wait_for(proc.wait(), timeout=_TIMEOUT_SEC)
        except asyncio.TimeoutError:
            proc.kill()
            try:
                await proc.wait()
            except Exception:
                pass
            return []

        if not out_path.exists():
            return []
        try:
            data = json.loads(out_path.read_text())
        except (json.JSONDecodeError, OSError):
            return []
        return data if isinstance(data, list) else []
    finally:
        try:
            out_path.unlink(missing_ok=True)
        except Exception:
            pass


class TestsslStage:
    name = "testssl"
    source_tool = "testssl"
    depends_on: list[str] = []
    weight = 50
    optional = True
    intrusive_required = False

    def applies(self, ctx: VulnStageContext) -> bool:
        return any(a.canonical_key.startswith("https://") for a in ctx.http_services)

    async def execute_vuln(self, ctx: VulnStageContext) -> list[VulnRecord]:
        if not _binary_available():
            log.warning("testssl: binary %r not found — skipping", _BINARY)
            return []

        https_assets = [a for a in ctx.http_services if a.canonical_key.startswith("https://")]
        if not https_assets:
            return []

        sem = asyncio.Semaphore(4)

        async def run(asset):
            async with sem:
                try:
                    return asset, await _run_one(asset.canonical_key)
                except Exception as exc:
                    log.warning("testssl: %s failed: %s", asset.canonical_key, exc)
                    return asset, []

        try:
            all_results = await asyncio.wait_for(
                asyncio.gather(*(run(a) for a in https_assets)),
                timeout=_OVERALL_TIMEOUT,
            )
        except asyncio.TimeoutError:
            log.warning("testssl: overall timeout")
            return []

        records: list[VulnRecord] = []
        for asset, findings in all_results:
            for f in findings:
                fid = f.get("id", "")
                if not fid or fid in _NOISE_IDS:
                    continue
                sev_raw = str(f.get("severity", "INFO")).upper()
                severity = _SEVERITY_BY_TESTSSL.get(sev_raw, "INFO")
                if severity == "INFO":
                    # Skip purely informational rows to avoid noise.
                    continue

                finding_text = f.get("finding") or fid
                cve = f.get("cve") or ""
                cve_ids = [c for c in cve.split() if c.startswith("CVE-")]

                canonical_key = f"tls:{fid}:{asset.id}"
                records.append(
                    VulnRecord(
                        asset_id=asset.id,
                        canonical_key=canonical_key,
                        title=f"TLS: {fid}",
                        severity=severity,
                        description=finding_text[:500],
                        template_id=fid,
                        cve_ids=cve_ids,
                        evidence=VulnEvidenceRecord(
                            source_tool="testssl",
                            matcher_name=fid,
                            extracted={
                                "host": asset.canonical_key,
                                "ip": f.get("ip"),
                                "port": f.get("port"),
                                "raw_severity": sev_raw,
                                "finding": finding_text,
                            },
                            confidence=80,
                        ),
                    )
                )
        return records
