"""Admin-only in-app log viewer — Postgres-only, per the observability
roadmap's Phase 5 decision (deep raw-log search lives in Grafana, this just
surfaces what's already in Postgres, tenant-scoped, with no Loki coupling).

Merges Operation, InvestigationTask, and ScanStage rows into one list since
Phase 3 put exit_code/stderr on all three. The audit trail (creation/mutation
events) is a separate concern, already served by /admin/audit — not
duplicated here.
"""
from __future__ import annotations

from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import CurrentUser, require_admin
from app.core.config import get_settings
from app.core.db import get_db
from app.models import Asset, InvestigationTask, Operation, Scan, ScanStage, Target, TargetWorkspace
from app.schemas.admin import ToolExecutionOut
from app.services import storage

router = APIRouter(prefix="/admin/logs", tags=["admin"])


def _is_super_admin(user: CurrentUser) -> bool:
    return user.email.lower() == get_settings().super_admin_email.lower()


def _status_str(value) -> str:
    return value.value if hasattr(value, "value") else value


async def _operations(
    db: AsyncSession, user: CurrentUser, tool, status_, from_, to, limit
) -> list[ToolExecutionOut]:
    stmt = select(Operation).order_by(desc(Operation.created_at)).limit(limit)
    if not _is_super_admin(user):
        stmt = stmt.where(Operation.org_id == user.org_id)
    if tool:
        stmt = stmt.where(Operation.tool == tool)
    if status_:
        stmt = stmt.where(Operation.status == status_)
    if from_:
        stmt = stmt.where(Operation.created_at >= from_)
    if to:
        stmt = stmt.where(Operation.created_at <= to)
    rows = (await db.scalars(stmt)).all()
    return [
        ToolExecutionOut(
            id=r.id,
            source="operation",
            tool=r.tool,
            target=r.target,
            status=r.status,
            exit_code=r.exit_code,
            error=r.error,
            stderr_preview=r.stderr[:500] if r.stderr else None,
            stdout_url=storage.object_url(r.stdout_object_key) if r.stdout_object_key else None,
            stderr_url=storage.object_url(r.stderr_object_key) if r.stderr_object_key else None,
            org_id=r.org_id,
            created_at=r.created_at,
        )
        for r in rows
    ]


async def _investigation_tasks(
    db: AsyncSession, user: CurrentUser, tool, status_, from_, to, limit
) -> list[ToolExecutionOut]:
    stmt = (
        select(InvestigationTask, TargetWorkspace.org_id, Asset.canonical_key)
        .join(TargetWorkspace, TargetWorkspace.id == InvestigationTask.workspace_id)
        .join(Asset, Asset.id == InvestigationTask.asset_id)
        .order_by(desc(InvestigationTask.created_at))
        .limit(limit)
    )
    if not _is_super_admin(user):
        stmt = stmt.where(TargetWorkspace.org_id == user.org_id)
    if tool:
        stmt = stmt.where(InvestigationTask.tool == tool)
    if status_:
        stmt = stmt.where(InvestigationTask.status == status_)
    if from_:
        stmt = stmt.where(InvestigationTask.created_at >= from_)
    if to:
        stmt = stmt.where(InvestigationTask.created_at <= to)
    rows = (await db.execute(stmt)).all()
    return [
        ToolExecutionOut(
            id=t.id,
            source="investigation_task",
            tool=t.tool,
            target=canonical_key,
            status=_status_str(t.status),
            exit_code=t.exit_code,
            error=t.error,
            stderr_preview=t.stderr[:500] if t.stderr else None,
            stdout_url=storage.object_url(t.stdout_object_key) if t.stdout_object_key else None,
            stderr_url=storage.object_url(t.stderr_object_key) if t.stderr_object_key else None,
            org_id=org_id,
            created_at=t.created_at,
        )
        for t, org_id, canonical_key in rows
    ]


async def _scan_stages(
    db: AsyncSession, user: CurrentUser, tool, status_, from_, to, limit
) -> list[ToolExecutionOut]:
    # exit_code is only populated on hard stage failures (see ScanStage model
    # docstring) — most recon adapters swallow non-zero exits, so this list is
    # necessarily a subset of all stage runs, not every stage execution.
    stmt = (
        select(ScanStage, Scan.org_id, Target.domain)
        .join(Scan, Scan.id == ScanStage.scan_id)
        .join(Target, Target.id == Scan.target_id)
        .where(ScanStage.exit_code.isnot(None))
        .order_by(desc(ScanStage.created_at))
        .limit(limit)
    )
    if not _is_super_admin(user):
        stmt = stmt.where(Scan.org_id == user.org_id)
    if tool:
        stmt = stmt.where(ScanStage.stage_name == tool)
    if status_:
        stmt = stmt.where(ScanStage.status == status_)
    if from_:
        stmt = stmt.where(ScanStage.created_at >= from_)
    if to:
        stmt = stmt.where(ScanStage.created_at <= to)
    rows = (await db.execute(stmt)).all()
    return [
        ToolExecutionOut(
            id=s.id,
            source="scan_stage",
            tool=s.stage_name,
            target=domain,
            status=_status_str(s.status),
            exit_code=s.exit_code,
            error=s.error,
            stderr_preview=s.stderr[:500] if s.stderr else None,
            org_id=org_id,
            created_at=s.created_at,
        )
        for s, org_id, domain in rows
    ]


@router.get("/tool-executions", response_model=list[ToolExecutionOut])
async def list_tool_executions(
    tool: str | None = Query(default=None),
    status: str | None = Query(default=None),
    from_: datetime | None = Query(default=None, alias="from"),
    to: datetime | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    user: CurrentUser = Depends(require_admin()),
    db: AsyncSession = Depends(get_db),
) -> list[ToolExecutionOut]:
    ops = await _operations(db, user, tool, status, from_, to, limit)
    tasks = await _investigation_tasks(db, user, tool, status, from_, to, limit)
    stages = await _scan_stages(db, user, tool, status, from_, to, limit)
    merged = sorted(ops + tasks + stages, key=lambda r: r.created_at, reverse=True)
    return merged[:limit]
