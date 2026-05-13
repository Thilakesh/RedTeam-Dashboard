"""Arq worker that runs scans end-to-end via the DAG coordinator.

Persistence, pub/sub, and weighted progress accounting all live here. The coordinator
is a pure orchestrator (`pipeline/coordinator.py`); adapters under `pipeline/adapters/`
are pure subprocess/API wrappers. The three boundaries don't bleed into each other.

SQLAlchemy async sessions are NOT safe to share across concurrent tasks — the
coordinator runs stages in parallel via asyncio.gather, so every callback opens its
own short-lived session.
"""

import json
import os
from datetime import datetime, timezone
from uuid import UUID

from arq.connections import RedisSettings
from redis.asyncio import Redis

from app.core.config import get_settings
from app.core.db import SessionLocal
from app.models import Scan, ScanStage, ScanStatus, StageStatus, Target
from app.pipeline.coordinator import execute_dag, total_weight
from app.pipeline.profiles import stages_for
from app.pipeline.stage import AssetRecord, Stage
from app.services import storage
from app.services.assets import upsert_assets

settings = get_settings()


async def _publish(redis: Redis, scan_id: UUID, event: str, **fields) -> None:
    payload = {"event": event, "scan_id": str(scan_id), **fields}
    await redis.publish(f"scan:{scan_id}", json.dumps(payload, default=str))


async def run_scan(_ctx: dict, scan_id_str: str) -> None:
    scan_id = UUID(scan_id_str)
    redis = Redis.from_url(settings.redis_url, decode_responses=True)
    completed_weight = 0

    try:
        async with SessionLocal() as db:
            scan = await db.get(Scan, scan_id)
            if scan is None:
                raise RuntimeError(f"scan {scan_id} not found")
            target = await db.get(Target, scan.target_id)
            if target is None:
                raise RuntimeError(f"target {scan.target_id} not found")
            authorization_verified = target.authorization_verified_at is not None
            profile = scan.profile
            domain = target.domain
            target_id = target.id
            scan.status = ScanStatus.running
            scan.started_at = datetime.now(timezone.utc)
            await db.commit()

        authz_state = [authorization_verified]
        stages = stages_for(profile, authz_state=authz_state)
        weight_total = total_weight(stages)
        await _publish(redis, scan_id, "scan.started", profile=profile)

        async def on_start(stage: Stage) -> UUID:
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

        async def on_done(stage: Stage, records: list[AssetRecord], handle: UUID) -> None:
            nonlocal completed_weight
            async with SessionLocal() as db:
                written = await upsert_assets(
                    db,
                    target_id=target_id,
                    scan_id=scan_id,
                    stage_id=handle,
                    source_tool=stage.source_tool,
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
                assets_found=written,
                progress=progress,
            )

        async def on_fail(stage: Stage, exc: Exception, handle: UUID) -> None:
            async with SessionLocal() as db:
                row = await db.get(ScanStage, handle)
                row.status = StageStatus.failed
                row.finished_at = datetime.now(timezone.utc)
                row.error = str(exc)[:1900]
                await db.commit()
            await _publish(
                redis, scan_id, "stage.failed", stage=stage.name, error=str(exc)[:500]
            )

        async def on_skip(stage: Stage, reason: str) -> None:
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

        await execute_dag(
            stages,
            domain=domain,
            target_id=target_id,
            scan_id=scan_id,
            on_start=on_start,
            on_done=on_done,
            on_fail=on_fail,
            on_skip=on_skip,
            authorization_verified=authz_state,
        )

        # Respect a stop that happened mid-run — don't override the stopped status
        final = None
        async with SessionLocal() as db:
            final = await db.get(Scan, scan_id)
            if final is not None and final.status != ScanStatus.stopped:
                final.status = ScanStatus.completed
                final.finished_at = datetime.now(timezone.utc)
                final.progress_pct = 100
                await db.commit()
        if final is None or final.status != ScanStatus.stopped:
            await _publish(redis, scan_id, "scan.completed")
        # If stopped, the stop_scan API endpoint already published scan.stopped
    except BaseException as exc:
        fresh_scan = None
        async with SessionLocal() as db:
            fresh_scan = await db.get(Scan, scan_id)
            if fresh_scan is not None and fresh_scan.status != ScanStatus.stopped:
                fresh_scan.status = ScanStatus.failed
                fresh_scan.finished_at = datetime.now(timezone.utc)
                fresh_scan.error = str(exc)[:1900]
                await db.commit()
        if fresh_scan is None or fresh_scan.status != ScanStatus.stopped:
            await _publish(redis, scan_id, "scan.failed", error=str(exc)[:500])
        raise
    finally:
        await redis.aclose()


async def startup(_ctx: dict) -> None:
    """Ensure MinIO bucket exists before processing any jobs."""
    storage.ensure_bucket()


class WorkerSettings:
    functions = [run_scan]
    on_startup = startup
    redis_settings = RedisSettings.from_dsn(get_settings().redis_url)
    queue_name = os.getenv("ARQ_QUEUE_NAME", "default")
    job_timeout = 60 * 30
    max_jobs = 4
