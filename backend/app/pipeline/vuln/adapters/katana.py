"""katana — passive endpoint discovery.

Runs `katana -passive -silent -jc -d 2` against http_service URLs. Passive mode
pulls endpoints from public sources (web archives, common-crawl) and makes NO
active requests against the target.

M-Vuln-5: writes to the first-class `endpoints` table via
`services/endpoints.py::upsert_endpoints`. Returns NO VulnRecords — endpoint
discovery is surface enrichment, not a weakness signal. Downstream stages
(nuclei_safe, ffuf, endpoint_classifier) consume the table.

Fail-soft: optional=True; returns [] if the binary is missing or times out.
"""

from __future__ import annotations

import asyncio
import logging
import shutil

from app.core.db import SessionLocal
from app.pipeline.vuln.stage import VulnRecord, VulnStageContext
from app.services.endpoints import EndpointRecord, upsert_endpoints

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

        # Group discovered endpoints by their root http_service asset.
        endpoints_by_asset: dict = {}
        for raw in stdout.splitlines():
            line = raw.decode(errors="ignore").strip()
            if not line or not line.startswith(("http://", "https://")):
                continue
            for url, asset in url_to_asset.items():
                if line.startswith(url):
                    bucket = endpoints_by_asset.setdefault(asset.id, set())
                    if len(bucket) < _MAX_ENDPOINTS_PER_ASSET:
                        bucket.add(line)
                    break

        # Build EndpointRecord list for upsert.
        records: list[EndpointRecord] = []
        for asset_id, ep_set in endpoints_by_asset.items():
            for url in ep_set:
                records.append(EndpointRecord(asset_id=asset_id, url=url, method="GET"))

        if not records:
            return []

        # Write to endpoints table directly. Use a fresh session — the stage runs
        # outside the worker's primary session per the M-Vuln-2 detached-context pattern.
        # Stage_id is not yet known here; pass the scan_id as a sentinel since the
        # observation table requires a stage_id. We retrieve the current ScanStage
        # row id from ctx in the worker's on_done flow — but for this adapter the
        # cleanest approach is to skip observations for now (endpoints alone are
        # the signal). See M-Vuln-6 for adding katana stage_id plumbing.
        # MVP: write endpoints, no observations.
        async with SessionLocal() as db:
            await _upsert_no_obs(db, target_id=ctx.target_id, records=records)
            await db.commit()

        log.info("katana: wrote %d endpoints across %d assets",
                 len(records), len(endpoints_by_asset))
        return []


async def _upsert_no_obs(db, *, target_id, records):
    """Endpoint upsert WITHOUT writing observations.

    The full upsert_endpoints() helper writes per-scan observations, which need a
    stage_id. The katana adapter here doesn't have access to its own stage_id
    inside execute_vuln (the coordinator allocates it but doesn't pass it). Until
    we plumb stage_id through (M-Vuln-6), endpoints are first-class but their
    per-scan history is reconstructed from vulnerability scans against them.
    """
    from sqlalchemy.dialects.postgresql import insert
    from sqlalchemy.sql import func
    from urllib.parse import urlparse
    from app.models.endpoint import Endpoint

    for start in range(0, len(records), 2000):
        chunk = records[start : start + 2000]
        rows = [
            {
                "target_id": target_id,
                "asset_id": r.asset_id,
                "service_id": r.service_id,
                "url": r.url,
                "path": urlparse(r.url).path or "/",
                "method": r.method,
                "source_tool": "katana",
            }
            for r in chunk
        ]
        stmt = insert(Endpoint).values(rows)
        stmt = stmt.on_conflict_do_update(
            constraint="uq_endpoint_identity",
            set_={"last_seen": func.now()},
        )
        await db.execute(stmt)
