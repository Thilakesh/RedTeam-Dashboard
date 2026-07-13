"""Target Workspace API.

Layered above completed recon scans; analyst-driven per-asset investigation.
Tenant isolation via the denormalized TargetWorkspace.org_id column (404 on
mismatch — hides existence across orgs), plus strict per-owner isolation via
TargetWorkspace.created_by (403 on mismatch within the org). No role gets
blanket org visibility, including admin — mirrors the Scan/Operation IDOR
fix in app/api/scans.py and app/api/operations.py exactly.
"""
from __future__ import annotations

import asyncio
import json
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from redis.asyncio import Redis
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sse_starlette.sse import EventSourceResponse

from app.api.deps import CurrentUser, get_current_user, get_current_user_sse, require_feature
from app.core import features
from app.core.config import get_settings
from app.core.db import get_db
from app.models import (
    Asset,
    InvestigationTaskStatus,
    Scan,
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
from app.services import audit
from app.services import storage
from app.services import target_workspace as ws_service
from app.services import investigation_tasks as task_service
from app.services.net_guard import assert_target_allowed
from app.services.tool_args import validate_custom_args

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
    """Returns (workspace, target_domain). 404 on miss/foreign-org (hides
    cross-tenant existence); 403 if it exists in-org but isn't yours."""
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
    if row.TargetWorkspace.created_by != user.id:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "you do not have access to this workspace")
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
    request: Request,
    user: CurrentUser = Depends(require_feature("target_workspace")),
    db: AsyncSession = Depends(get_db),
) -> WorkspaceOut:
    """Idempotent: returns existing workspace if (target, parent_scan) match."""
    parent_row = (
        await db.execute(
            select(Scan, Target.domain)
            .join(Target, Target.id == Scan.target_id)
            .where(Scan.id == req.parent_scan_id, Scan.org_id == user.org_id)
        )
    ).first()
    if parent_row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "parent recon scan not found")
    if parent_row.Scan.created_by != user.id:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "you do not have access to this scan")

    parent_scan, target_domain = parent_row.Scan, parent_row.domain
    if parent_scan.status != ScanStatus.completed:
        raise HTTPException(
            status.HTTP_409_CONFLICT, "parent recon scan not complete"
        )

    ws, created = await ws_service.create_or_get_workspace(
        db,
        target_id=parent_scan.target_id,
        parent_scan_id=parent_scan.id,
        org_id=user.org_id,
        target_domain=target_domain,
        created_by=user.id,
    )
    if created:
        await audit.log(
            db,
            actor_user_id=user.id,
            action="workspace.created",
            target_type="workspace",
            target_id=ws.id,
            meta={"domain": target_domain, "parent_scan_id": str(parent_scan.id)},
            request=request,
        )
    return _workspace_out(ws, target_domain)


@router.get("", response_model=list[WorkspaceListRow])
async def list_workspaces(
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> list[WorkspaceListRow]:
    rows = await ws_service.list_workspaces_for_org(db, user.org_id, user.id)
    return [WorkspaceListRow(**r) for r in rows]


@router.get("/{workspace_id}", response_model=WorkspaceOut)
async def get_workspace(
    workspace_id: UUID,
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> WorkspaceOut:
    ws, domain = await _get_workspace_for_user(workspace_id, db, user)
    return _workspace_out(ws, domain)


@router.delete("/{workspace_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_workspace(
    workspace_id: UUID,
    request: Request,
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> None:
    """Delete a workspace + all its investigation tasks and findings (cascade).
    Refuses if any child task is still in flight."""
    ws, domain = await _get_workspace_for_user(workspace_id, db, user)

    in_flight = await db.scalar(
        select(func.count(InvestigationTask.id)).where(
            InvestigationTask.workspace_id == ws.id,
            InvestigationTask.status.in_(
                [InvestigationTaskStatus.queued, InvestigationTaskStatus.running]
            ),
        )
    )
    if in_flight:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"{in_flight} task(s) still running — cancel them first",
        )

    await db.delete(ws)
    await audit.log(
        db,
        actor_user_id=user.id,
        action="workspace.deleted",
        target_type="workspace",
        target_id=workspace_id,
        meta={"domain": domain, "label": ws.label},
        request=request,
        commit=False,
    )
    await db.commit()


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
    request: Request,
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> InvestigationTaskOut:
    ws, _ = await _get_workspace_for_user(workspace_id, db, user)

    await features.require(db, user.id, "target_workspace", "investigations")
    if req.tool in features.FEATURES:
        await features.require(db, user.id, req.tool)

    # Asset must belong to the same target as the workspace.
    asset = await db.get(Asset, req.asset_id)
    if asset is None or asset.target_id != ws.target_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "asset not found in workspace")

    if not await task_service.validate_tool_for_asset(db, asset, req.tool):
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            f"tool '{req.tool}' is not applicable to this asset",
        )

    # Assets come from legitimate recon, but a spoofed/malicious DNS response
    # during that recon could still seed one resolving to platform
    # infrastructure or a cloud-metadata address. Guard before enqueueing.
    try:
        assert_target_allowed(asset.canonical_key)
    except ValueError as e:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(e))

    # Unlike Operations, this path previously forwarded req.params straight to
    # the adapter with no validation at all. Restrict to the known-safe keys
    # (drops any "wordlist" override, which let a client point ffuf/dirsearch
    # at an arbitrary local file) and allow-list-validate custom_args — the
    # same check scan_profiles.resolve_args re-applies at execution time.
    safe_params = {
        k: v for k, v in (req.params or {}).items()
        if k in ("profile", "protocol", "port", "custom_args")
    }
    try:
        if safe_params.get("profile") == "custom":
            validate_custom_args(req.tool, safe_params.get("custom_args"))
    except ValueError as e:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(e))

    task = await task_service.create_and_enqueue_task(
        db,
        workspace_id=ws.id,
        asset_id=asset.id,
        tool=req.tool,
        params=safe_params,
    )
    await audit.log(
        db,
        actor_user_id=user.id,
        action="investigation_task.created",
        target_type="investigation_task",
        target_id=task.id,
        meta={"workspace_id": str(ws.id), "tool": req.tool, "asset": asset.canonical_key},
        request=request,
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
        exit_code=task.exit_code,
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
            exit_code=task.exit_code,
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
        stderr=task.stderr,
        stdout_url=storage.object_url(task.stdout_object_key) if task.stdout_object_key else None,
        stderr_url=storage.object_url(task.stderr_object_key) if task.stderr_object_key else None,
    )


@router.delete(
    "/{workspace_id}/tasks/{task_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def delete_investigation_task(
    workspace_id: UUID,
    task_id: UUID,
    request: Request,
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> None:
    """Delete an investigation task + its findings (cascade). Refuses if the
    task is still queued or running."""
    ws, _ = await _get_workspace_for_user(workspace_id, db, user)
    task = await db.scalar(
        select(InvestigationTask).where(
            InvestigationTask.id == task_id,
            InvestigationTask.workspace_id == ws.id,
        )
    )
    if task is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "task not found")
    if task.status in (
        InvestigationTaskStatus.queued,
        InvestigationTaskStatus.running,
    ):
        raise HTTPException(
            status.HTTP_409_CONFLICT, "cancel the task before deleting"
        )

    tool = task.tool
    status_at_delete = task.status.value if hasattr(task.status, "value") else str(task.status)
    await db.delete(task)
    await audit.log(
        db,
        actor_user_id=user.id,
        action="investigation_task.deleted",
        target_type="investigation_task",
        target_id=task_id,
        meta={"workspace_id": str(workspace_id), "tool": tool, "status_at_delete": status_at_delete},
        request=request,
        commit=False,
    )
    await db.commit()


@router.get("/{workspace_id}/stream")
async def stream_workspace_tasks(
    workspace_id: UUID,
    user: CurrentUser = Depends(get_current_user_sse),
    db: AsyncSession = Depends(get_db),
):
    """SSE: aggregates `investigation:{task_id}` channel events for all
    tasks in this workspace. Uses Redis psubscribe over channel pattern
    `investigation:*` then filters by workspace via Redis SET membership."""
    ws = await db.scalar(
        select(TargetWorkspace).where(
            TargetWorkspace.id == workspace_id,
            TargetWorkspace.org_id == user.org_id,
        )
    )
    if ws is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "workspace not found")
    if ws.created_by != user.id:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "you do not have access to this workspace")

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
