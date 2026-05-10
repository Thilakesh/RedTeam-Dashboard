"""katana — passive endpoint discovery.

Runs `katana -passive -silent -jc -d 2` against http_service URLs. Passive
mode pulls endpoints from public sources (web archives, common-crawl) and
makes NO active requests against the target. The discovered endpoints are
written into a single INFO-severity VulnRecord per asset whose evidence
carries the endpoint list — surfacing them in the Endpoints tab without
polluting the vulnerability count.

Fail-soft: optional=True; returns [] if the binary is missing or times out.
"""

from __future__ import annotations

import asyncio
import logging
import shutil

from app.pipeline.vuln.stage import VulnEvidenceRecord, VulnRecord, VulnStageContext

log = logging.getLogger(__name__)

_BINARY = "katana"
_TIMEOUT_SEC = 300
_DEPTH = "2"
_MAX_ENDPOINTS_PER_ASSET = 200


def _binary_available() -> bool:
    return shutil.which(_BINARY) is not None


class KatanaStage:
    name = "katana"
    source_tool = "katana"
    depends_on: list[str] = []
    weight = 30
    optional = True
    intrusive_required = False

    def applies(self, ctx: VulnStageContext) -> bool:
        return bool(ctx.http_services)

    async def execute_vuln(self, ctx: VulnStageContext) -> list[VulnRecord]:
        if not ctx.http_services:
            return []
        if not _binary_available():
            log.warning("katana: binary %r not found — skipping", _BINARY)
            return []

        urls = [a.canonical_key for a in ctx.http_services]
        url_to_asset = {a.canonical_key: a for a in ctx.http_services}
        targets = "\n".join(urls)

        cmd = [
            _BINARY,
            "-passive",
            "-silent",
            "-no-color",
            "-d", _DEPTH,
            "-jc",
        ]
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(
                proc.communicate(input=targets.encode()), timeout=_TIMEOUT_SEC
            )
        except asyncio.TimeoutError:
            proc.kill()
            try:
                await proc.communicate()
            except Exception:
                pass
            log.warning("katana: timed out after %ss", _TIMEOUT_SEC)
            return []
        except FileNotFoundError:
            return []

        # Group endpoints by their root http_service
        endpoints_by_asset: dict = {}
        for raw in stdout.splitlines():
            line = raw.decode(errors="ignore").strip()
            if not line or not line.startswith(("http://", "https://")):
                continue
            for url, asset in url_to_asset.items():
                if line.startswith(url):
                    bucket = endpoints_by_asset.setdefault(asset.id, [])
                    if len(bucket) < _MAX_ENDPOINTS_PER_ASSET and line not in bucket:
                        bucket.append(line)
                    break

        records: list[VulnRecord] = []
        for asset_id, eps in endpoints_by_asset.items():
            if not eps:
                continue
            asset = next(a for a in ctx.http_services if a.id == asset_id)
            records.append(
                VulnRecord(
                    asset_id=asset_id,
                    canonical_key=f"endpoints:{asset_id}",
                    title=f"Discovered endpoints ({len(eps)}) on {asset.canonical_key}",
                    severity="INFO",
                    description=f"katana passive crawl found {len(eps)} URLs.",
                    evidence=VulnEvidenceRecord(
                        source_tool="katana",
                        matcher_name="passive_crawl",
                        extracted={"endpoints": eps, "count": len(eps)},
                        confidence=90,
                    ),
                )
            )
        return records
