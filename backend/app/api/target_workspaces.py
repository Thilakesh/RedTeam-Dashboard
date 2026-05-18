"""Target Workspace API.

Layered above completed recon scans; analyst-driven per-asset investigation.
Tenant isolation via the denormalized TargetWorkspace.org_id column (mirrors
Scan.org_id pattern in app/api/scans.py).
"""
from __future__ import annotations

import asyncio
import json
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from redis.asyncio import Redis
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sse_starlette.sse import EventSourceResponse

from app.api.deps import CurrentUser, get_current_user, get_current_user_sse
from app.core.config import get_settings
from app.core.db import get_db
from app.models import (
    Asset,
    Scan,
    ScanKind,
    ScanStatus,
    Target,
    TargetWorkspace,
    InvestigationTask,
)
from app.schemas.target_workspace import (
    InvestigationFindingOut,
    InvestigationTaskCreateRequest,
    InvestigationTaskDetailOut,
    InvestigationTaskOut,
    InvestigationTasksResponse,
    WorkspaceCreateRequest,
    WorkspaceListRow,
    WorkspaceOut,
    WorkspaceOverview,
    WorkspaceSubdomainRow,
    WorkspaceSubdomainsResponse,
)
from app.services import target_workspace as ws_service
from app.services import investigation_tasks as task_service

router = APIRouter(prefix="/target-workspaces", tags=["target-workspaces"])


@router.get("/scan-profiles")
async def get_scan_profiles() -> dict:
    """Profile catalog used by the Scan Configuration UI.

    Returned shape:
      { "<tool>": { "binary": str, "default": str,
                    "profiles": [{id, label, args[], description}] } }
    """
    from app.services.scan_profiles import PROFILES
    return PROFILES


async def _get_workspace_for_user(
    workspace_id: UUID, db: AsyncSession, user: CurrentUser
) -> tuple[TargetWorkspace, str]:
    """Returns (workspace, target_domain). 404 on miss/foreign-org."""
    row = (
        await db.execute(
            select(TargetWorkspace, Target.domain)
            .join(Target, Target.id == TargetWorkspace.target_id)
            .where(
                TargetWorkspace.id == workspace_id,
                TargetWorkspace.org_id == user.org_id,
            )
        )
    ).first()
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "workspace not found")
    return row.TargetWorkspace, row.domain


def _workspace_out(ws: TargetWorkspace, domain: str) -> WorkspaceOut:
    return WorkspaceOut(
        id=ws.id,
        label=ws.label,
        target_id=ws.target_id,
        target_domain=domain,
        parent_scan_id=ws.parent_scan_id,
        status=ws.status.value if hasattr(ws.status, "value") else str(ws.status),
        created_at=ws.created_at,
    )


@router.post("", response_model=WorkspaceOut, status_code=status.HTTP_201_CREATED)
async def create_workspace(
    req: WorkspaceCreateRequest,
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> WorkspaceOut:
    """Idempotent: returns existing workspace if (target, parent_scan) match."""
    parent_row = (
        await db.execute(
            select(Scan, Target.domain)
            .join(Target, Target.id == Scan.target_id)
            .where(
                Scan.id == req.parent_scan_id,
                Scan.org_id == user.org_id,
                Scan.kind == ScanKind.recon,
            )
        )
    ).first()
    if parent_row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "parent recon scan not found")

    parent_scan, target_domain = parent_row.Scan, parent_row.domain
    if parent_scan.status != ScanStatus.completed:
        raise HTTPException(
            status.HTTP_409_CONFLICT, "parent recon scan not complete"
        )

    ws = await ws_service.create_or_get_workspace(
        db,
        target_id=parent_scan.target_id,
        parent_scan_id=parent_scan.id,
        org_id=user.org_id,
        target_domain=target_domain,
    )
    return _workspace_out(ws, target_domain)


@router.get("", response_model=list[WorkspaceListRow])
async def list_workspaces(
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> list[WorkspaceListRow]:
    rows = await ws_service.list_workspaces_for_org(db, user.org_id)
    return [WorkspaceListRow(**r) for r in rows]


@router.get("/{workspace_id}", response_model=WorkspaceOut)
async def get_workspace(
    workspace_id: UUID,
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> WorkspaceOut:
    ws, domain = await _get_workspace_for_user(workspace_id, db, user)
    return _workspace_out(ws, domain)


@router.get("/{workspace_id}/overview", response_model=WorkspaceOverview)
async def get_workspace_overview(
    workspace_id: UUID,
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> WorkspaceOverview:
    ws, _ = await _get_workspace_for_user(workspace_id, db, user)
    data = await ws_service.build_workspace_overview(db, ws)
    return WorkspaceOverview(**data)


@router.get("/{workspace_id}/subdomains", response_model=WorkspaceSubdomainsResponse)
async def list_workspace_subdomains(
    workspace_id: UUID,
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> WorkspaceSubdomainsResponse:
    ws, _ = await _get_workspace_for_user(workspace_id, db, user)
    rows = await ws_service.build_workspace_subdomain_rows(db, ws)
    return WorkspaceSubdomainsResponse(
        rows=[WorkspaceSubdomainRow(**r) for r in rows]
    )


@router.get("/{workspace_id}/tasks", response_model=InvestigationTasksResponse)
async def list_workspace_tasks(
    workspace_id: UUID,
    status_filter: str | None = Query(None, alias="status"),
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> InvestigationTasksResponse:
    ws, _ = await _get_workspace_for_user(workspace_id, db, user)
    rows = await task_service.list_tasks_for_workspace(
        db, ws.id, status_filter=status_filter
    )
    return InvestigationTasksResponse(
        rows=[InvestigationTaskOut(**r) for r in rows]
    )


@router.post(
    "/{workspace_id}/tasks",
    response_model=InvestigationTaskOut,
    status_code=status.HTTP_201_CREATED,
)
async def create_investigation_task(
    workspace_id: UUID,
    req: InvestigationTaskCreateRequest,
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> InvestigationTaskOut:
    ws, _ = await _get_workspace_for_user(workspace_id, db, user)

    # Asset must belong to the same target as the workspace.
    asset = await db.get(Asset, req.asset_id)
    if asset is None or asset.target_id != ws.target_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "asset not found in workspace")

    if not await task_service.validate_tool_for_asset(db, asset, req.tool):
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            f"tool '{req.tool}' is not applicable to this asset",
        )

    task = await task_service.create_and_enqueue_task(
        db,
        workspace_id=ws.id,
        asset_id=asset.id,
        tool=req.tool,
        params=req.params,
    )
    return InvestigationTaskOut(
        id=task.id,
        workspace_id=task.workspace_id,
        asset_id=task.asset_id,
        asset_label=asset.canonical_key,
        tool=task.tool,
        status=task.status.value if hasattr(task.status, "value") else str(task.status),
        progress_pct=task.progress_pct,
        duration_s=None,
        raw_output_present=task.raw_output is not None,
        error=task.error,
        created_at=task.created_at,
        started_at=task.started_at,
        finished_at=task.finished_at,
    )


@router.get(
    "/{workspace_id}/tasks/{task_id}",
    response_model=InvestigationTaskDetailOut,
)
async def get_investigation_task(
    workspace_id: UUID,
    task_id: UUID,
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> InvestigationTaskDetailOut:
    ws, _ = await _get_workspace_for_user(workspace_id, db, user)

    row = (
        await db.execute(
            select(InvestigationTask, Asset.canonical_key.label("asset_label"))
            .join(Asset, Asset.id == InvestigationTask.asset_id)
            .where(
                InvestigationTask.id == task_id,
                InvestigationTask.workspace_id == ws.id,
            )
        )
    ).first()
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "task not found")

    task, asset_label = row.InvestigationTask, row.asset_label
    findings = await task_service.get_task_findings(db, task.id)

    duration_s = None
    if task.started_at and task.finished_at:
        duration_s = (task.finished_at - task.started_at).total_seconds()

    return InvestigationTaskDetailOut(
        task=InvestigationTaskOut(
            id=task.id,
            workspace_id=task.workspace_id,
            asset_id=task.asset_id,
            asset_label=asset_label,
            tool=task.tool,
            status=task.status.value if hasattr(task.status, "value") else str(task.status),
            progress_pct=task.progress_pct,
            duration_s=duration_s,
            raw_output_present=task.raw_output is not None,
            error=task.error,
            created_at=task.created_at,
            started_at=task.started_at,
            finished_at=task.finished_at,
        ),
        findings=[
            InvestigationFindingOut(
                id=f.id,
                task_id=f.task_id,
                asset_id=f.asset_id,
                kind=f.kind,
                severity=f.severity,
                title=f.title,
                description=f.description,
                evidence=f.evidence or {},
                created_at=f.created_at,
            )
            for f in findings
        ],
        raw_output=task.raw_output,
    )


@router.get("/{workspace_id}/stream")
async def stream_workspace_tasks(
    workspace_id: UUID,
    user: CurrentUser = Depends(get_current_user_sse),
    db: AsyncSession = Depends(get_db),
):
    """SSE: aggregates `investigation:{task_id}` channel events for all
    tasks in this workspace. Uses Redis psubscribe over channel pattern
    `investigation:*` then filters by workspace via Redis SET membership."""
    exists = await db.scalar(
        select(TargetWorkspace.id).where(
            TargetWorkspace.id == workspace_id,
            TargetWorkspace.org_id == user.org_id,
        )
    )
    if exists is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "workspace not found")

    redis = Redis.from_url(get_settings().redis_url, decode_responses=True)
    workspace_set_key = f"workspace:{workspace_id}:tasks"

    async def event_gen():
        pubsub = redis.pubsub()
        await pubsub.psubscribe("investigation:*")
        try:
            while True:
                msg = await pubsub.get_message(
                    ignore_subscribe_messages=True, timeout=15.0
                )
                if msg is None:
                    yield {"event": "ping", "data": "{}"}
                    continue
                channel = msg.get("channel", "")
                task_id = channel.split(":", 1)[1] if ":" in channel else ""
                # Only forward events for tasks belonging to this workspace
                is_member = await redis.sismember(workspace_set_key, task_id)
                if not is_member:
                    continue
                data = msg["data"]
                try:
                    parsed = json.loads(data)
                    event = parsed.get("event", "task.update")
                except (ValueError, TypeError):
                    event = "task.update"
                yield {"event": event, "data": data}
        finally:
            await pubsub.punsubscribe("investigation:*")
            await pubsub.aclose()
            await redis.aclose()

    return EventSourceResponse(event_gen())
