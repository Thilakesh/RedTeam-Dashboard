"""Arq worker that runs per-asset, per-tool investigation tasks.

One job = one InvestigationTask row = one tool against one asset. Adapter
contract is in `pipeline/investigation/stage.py`; registry in `pipeline/investigation/registry.py`.

Authz gate (mirrors deep-recon rule): tools listed in
`investigation_tasks.TOOL_REQUIRES_AUTHZ` need `Target.authorization_verified_at`.
Failing the gate marks the task `failed` with a clear reason — analyst can verify
the target via /targets/{id}/verify and retry.

Pub/sub channel: `investigation:{task_id}`. Workspace SSE filters by Redis SET
`workspace:{workspace_id}:tasks` (membership added at task start, never removed —
SET grows linearly with task count; revisit if workspaces exceed ~10K tasks).
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from uuid import UUID

from arq.connections import RedisSettings
from redis.asyncio import Redis

from app.core.config import get_settings
from app.core.db import SessionLocal
from app.models import (
    Asset,
    InvestigationFinding,
    InvestigationTask,
    InvestigationTaskStatus,
    Target,
    TargetWorkspace,
)
from app.pipeline.investigation.registry import get_adapter
from app.pipeline.investigation.stage import (
    InvestigationResult,
    TaskContext,
)
from app.services import investigation_tasks as task_service
from app.services.endpoint_enrichment import upsert_endpoint_enrichment
from app.services.service_enrichment import upsert_service_enrichment
from app.services.tls import insert_tls_observation

settings = get_settings()


async def _publish(redis: Redis, task_id: UUID, event: str, **fields) -> None:
    payload = {"event": event, "task_id": str(task_id), **fields}
    await redis.publish(
        f"investigation:{task_id}", json.dumps(payload, default=str)
    )


async def _persist_result(
    task_id: UUID,
    workspace_id: UUID,
    target_id: UUID,
    asset_id: UUID,
    tool: str,
    result: InvestigationResult,
) -> None:
    """Write findings + tls observations + service/endpoint enrichment + raw_output."""
    async with SessionLocal() as db:
        for f in result.findings:
            db.add(
                InvestigationFinding(
                    task_id=task_id,
                    asset_id=asset_id,
                    kind=f.kind,
                    severity=f.severity,
                    title=f.title[:200],
                    description=f.description,
                    evidence=f.evidence or {},
                )
            )
        for tls in result.tls_observations:
            await insert_tls_observation(db, target_id=target_id, record=tls)
        for svc in result.services:
            await upsert_service_enrichment(db, target_id=target_id, record=svc)
        for ep in result.endpoints:
            await upsert_endpoint_enrichment(
                db,
                target_id=target_id,
                asset_id=asset_id,
                source_tool=tool,
                record=ep,
            )
        await db.commit()


async def run_investigation_task(_ctx: dict, task_id_str: str) -> None:
    task_id = UUID(task_id_str)
    redis = Redis.from_url(settings.redis_url, decode_responses=True)

    try:
        # Load context + authz gate in one session, then close before adapter execute.
        async with SessionLocal() as db:
            task = await db.get(InvestigationTask, task_id)
            if task is None:
                raise RuntimeError(f"investigation task {task_id} not found")

            workspace = await db.get(TargetWorkspace, task.workspace_id)
            if workspace is None:
                raise RuntimeError(f"workspace {task.workspace_id} not found")

            asset = await db.get(Asset, task.asset_id)
            if asset is None:
                raise RuntimeError(f"asset {task.asset_id} not found")

            target = await db.get(Target, workspace.target_id)
            if target is None:
                raise RuntimeError(f"target {workspace.target_id} not found")

            # Authz gate — active tools require verified ownership.
            requires_authz = task_service.TOOL_REQUIRES_AUTHZ.get(task.tool, True)
            if requires_authz and target.authorization_verified_at is None:
                task_service.mark_task_failed(
                    task, "target not verified for active scanning"
                )
                await db.commit()
                await _publish(
                    redis,
                    task_id,
                    "task.failed",
                    reason="target not verified for active scanning",
                )
                return

            task_service.mark_task_started(task)
            await db.commit()

            ctx = TaskContext(
                task_id=task.id,
                workspace_id=workspace.id,
                target_id=target.id,
                target_domain=target.domain,
                asset_id=asset.id,
                asset_canonical_key=asset.canonical_key,
                asset_type=asset.type,
                params=task.params or {},
            )

        # Register task in workspace SET so SSE knows to forward its events.
        await redis.sadd(f"workspace:{workspace.id}:tasks", str(task.id))

        await _publish(redis, task_id, "task.started", tool=ctx.params)

        adapter = get_adapter(task.tool)
        if adapter is None:
            raise RuntimeError(f"no adapter registered for tool '{task.tool}'")

        result = await adapter.execute(ctx)

        await _persist_result(
            task_id=task.id,
            workspace_id=workspace.id,
            target_id=target.id,
            asset_id=asset.id,
            tool=task.tool,
            result=result,
        )

        async with SessionLocal() as db:
            fresh = await db.get(InvestigationTask, task_id)
            if fresh is None:
                return
            task_service.mark_task_completed(fresh, result.raw_output)
            await db.commit()

        await _publish(
            redis,
            task_id,
            "task.completed",
            findings_count=len(result.findings),
        )

    except Exception as exc:
        async with SessionLocal() as db:
            fresh = await db.get(InvestigationTask, task_id)
            if fresh is not None and fresh.status not in (
                InvestigationTaskStatus.completed,
                InvestigationTaskStatus.failed,
                InvestigationTaskStatus.cancelled,
            ):
                task_service.mark_task_failed(fresh, str(exc))
                await db.commit()
        await _publish(redis, task_id, "task.failed", error=str(exc)[:500])
        raise
    finally:
        await redis.aclose()


class InvestigationWorkerSettings:
    functions = [run_investigation_task]
    queue_name = "investigation"
    job_timeout = 60 * 15  # 15 min — longest tool here (nmap_deep) caps at 600s
    max_jobs = 6
    redis_settings = RedisSettings.from_dsn(get_settings().redis_url)
