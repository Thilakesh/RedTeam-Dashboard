"""Arq worker that runs vulnerability analysis scans end-to-end.

Mirrors the pattern in runner.py but operates on ScanKind.vuln_analysis scans.
Stages return VulnRecord lists; upsert_vulns persists them.
"""

import json
from datetime import datetime, timezone
from uuid import UUID

from arq.connections import RedisSettings
from redis.asyncio import Redis

from app.core.config import get_settings
from app.core.db import SessionLocal
from app.models import Scan, ScanKind, ScanStage, ScanStatus, StageStatus, Target
from app.pipeline.vuln.coordinator import load_vuln_context, run_vuln_dag, total_weight
from app.pipeline.vuln.profiles import vuln_stages_for
from app.services.vulns import upsert_vulns

settings = get_settings()


async def _publish(redis: Redis, scan_id: UUID, event: str, **fields) -> None:
    payload = {"event": event, "scan_id": str(scan_id), **fields}
    await redis.publish(f"scan:{scan_id}", json.dumps(payload, default=str))


async def run_vuln_scan(_ctx: dict, scan_id_str: str) -> None:
    scan_id = UUID(scan_id_str)
    redis = Redis.from_url(settings.redis_url, decode_responses=True)

    try:
        async with SessionLocal() as db:
            scan = await db.get(Scan, scan_id)
            if scan is None:
                raise RuntimeError(f"scan {scan_id} not found")
            if scan.kind != ScanKind.vuln_analysis:
                raise RuntimeError(f"scan {scan_id} is not a vuln_analysis scan")
            if scan.parent_scan_id is None:
                raise RuntimeError(f"scan {scan_id} has no parent_scan_id")

            parent = await db.get(Scan, scan.parent_scan_id)
            if parent is None:
                raise RuntimeError(f"parent scan {scan.parent_scan_id} not found")

            target = await db.get(Target, parent.target_id)
            if target is None:
                raise RuntimeError(f"target {parent.target_id} not found")

            profile = scan.profile
            target_id = target.id
            domain = target.domain
            intrusive = scan.intrusive
            parent_scan_id = scan.parent_scan_id

            scan.status = ScanStatus.running
            scan.started_at = datetime.now(timezone.utc)
            await db.commit()

            # Build the vuln context while the db session is open (needs Service/Tech data)
            ctx = await load_vuln_context(
                db,
                scan_id=scan_id,
                parent_scan_id=parent_scan_id,
                target_id=target_id,
                domain=domain,
                intrusive=intrusive,
            )

        stages = vuln_stages_for(profile)
        weight_total = total_weight(stages)
        completed_weight = 0
        await _publish(redis, scan_id, "scan.started", profile=profile)

        async def on_start(stage) -> UUID:
            async with SessionLocal() as db:
                row = ScanStage(
                    scan_id=scan_id,
                    stage_name=stage.name,
                    status=StageStatus.running,
                    started_at=datetime.now(timezone.utc),
                )
                db.add(row)
                await db.commit()
                await db.refresh(row)
                stage_id = row.id
            await _publish(redis, scan_id, "stage.started", stage=stage.name)
            return stage_id

        async def on_done(stage, records, handle: UUID) -> None:
            nonlocal completed_weight
            async with SessionLocal() as db:
                written = await upsert_vulns(
                    db,
                    target_id=target_id,
                    scan_id=scan_id,
                    stage_id=handle,
                    records=records,
                )
                row = await db.get(ScanStage, handle)
                row.status = StageStatus.completed
                row.finished_at = datetime.now(timezone.utc)
                completed_weight += max(stage.weight, 1)
                progress = min(99, int((completed_weight / weight_total) * 100))
                scan_obj = await db.get(Scan, scan_id)
                scan_obj.progress_pct = progress
                await db.commit()
            await _publish(
                redis,
                scan_id,
                "stage.completed",
                stage=stage.name,
                vulns_found=written,
                progress=progress,
            )

        async def on_fail(stage, exc: Exception, handle: UUID) -> None:
            async with SessionLocal() as db:
                row = await db.get(ScanStage, handle)
                row.status = StageStatus.failed
                row.finished_at = datetime.now(timezone.utc)
                row.error = str(exc)[:1900]
                await db.commit()
            await _publish(
                redis, scan_id, "stage.failed", stage=stage.name, error=str(exc)[:500]
            )

        async def on_skip(stage, reason: str) -> None:
            now = datetime.now(timezone.utc)
            async with SessionLocal() as db:
                row = ScanStage(
                    scan_id=scan_id,
                    stage_name=stage.name,
                    status=StageStatus.skipped,
                    started_at=now,
                    finished_at=now,
                    error=reason[:1900],
                )
                db.add(row)
                await db.commit()
            await _publish(redis, scan_id, "stage.skipped", stage=stage.name, reason=reason)

        await run_vuln_dag(
            stages,
            ctx,
            on_start=on_start,
            on_done=on_done,
            on_fail=on_fail,
            on_skip=on_skip,
        )

        async with SessionLocal() as db:
            final = await db.get(Scan, scan_id)
            if final is not None and final.status != ScanStatus.stopped:
                final.status = ScanStatus.completed
                final.finished_at = datetime.now(timezone.utc)
                final.progress_pct = 100
                await db.commit()
        if final is None or final.status != ScanStatus.stopped:
            await _publish(redis, scan_id, "scan.completed")

    except Exception as exc:
        async with SessionLocal() as db:
            fresh = await db.get(Scan, scan_id)
            if fresh is not None and fresh.status != ScanStatus.stopped:
                fresh.status = ScanStatus.failed
                fresh.finished_at = datetime.now(timezone.utc)
                fresh.error = str(exc)[:1900]
                await db.commit()
        if fresh is None or fresh.status != ScanStatus.stopped:
            await _publish(redis, scan_id, "scan.failed", error=str(exc)[:500])
        raise
    finally:
        await redis.aclose()


class VulnWorkerSettings:
    functions = [run_vuln_scan]
    queue_name = "vuln"
    job_timeout = 60 * 45
    max_jobs = 4
    redis_settings = RedisSettings.from_dsn(get_settings().redis_url)
