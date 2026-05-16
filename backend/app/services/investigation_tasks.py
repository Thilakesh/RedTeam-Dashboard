"""Investigation task service layer.

Per-click execution: one tool, one asset, one task. Validates that the chosen
tool is *applicable* to the asset (server-side mirror of the UI dropdown logic
in build_workspace_subdomain_rows) so a tampered client can't enqueue an
inappropriate tool.
"""
from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import (
    Asset,
    InvestigationFinding,
    InvestigationTask,
    InvestigationTaskStatus,
)
from app.services.queue import enqueue_investigation_task

# Canonical tool list; order is also the display order in dropdowns.
TOOLS: list[str] = ["nmap_deep", "ffuf", "dirsearch", "testssl"]

# Per-tool authz gate: True = active traffic, requires Target.authorization_verified_at.
TOOL_REQUIRES_AUTHZ: dict[str, bool] = {
    "nmap_deep": True,
    "ffuf": True,
    "dirsearch": True,
    "testssl": False,  # TLS handshake only, no attack traffic
}


SCANNABLE_ASSET_TYPES = {"subdomain", "ipv4"}


async def available_tools_for_asset(
    db: AsyncSession, asset: Asset
) -> list[str]:
    """All 4 tools are always offered. Analyst decides applicability; UI
    no longer hides tools for unknown/unenriched assets (per user request).

    The asset-capability heuristics are retained as a hint surface in the
    Subdomain row (`has_http`, `has_https`, `ports`) but no longer gate
    tool selection."""
    return list(TOOLS)


async def validate_tool_for_asset(
    db: AsyncSession, asset: Asset, tool: str
) -> bool:
    if tool not in TOOLS:
        return False
    if asset.type not in SCANNABLE_ASSET_TYPES:
        return False
    return True


async def create_and_enqueue_task(
    db: AsyncSession,
    workspace_id: UUID,
    asset_id: UUID,
    tool: str,
    params: dict | None = None,
) -> InvestigationTask:
    """Insert InvestigationTask row + push to Arq investigation queue."""
    task = InvestigationTask(
        workspace_id=workspace_id,
        asset_id=asset_id,
        tool=tool,
        status=InvestigationTaskStatus.queued,
        params=params or {},
    )
    db.add(task)
    await db.commit()
    await db.refresh(task)
    await enqueue_investigation_task(str(task.id))
    return task


async def list_tasks_for_workspace(
    db: AsyncSession,
    workspace_id: UUID,
    status_filter: str | None = None,
    limit: int = 200,
) -> list[dict]:
    """Rows for the Run Scan Details tab."""
    stmt = (
        select(InvestigationTask, Asset.canonical_key.label("asset_label"))
        .join(Asset, Asset.id == InvestigationTask.asset_id)
        .where(InvestigationTask.workspace_id == workspace_id)
        .order_by(desc(InvestigationTask.created_at))
        .limit(limit)
    )
    if status_filter:
        try:
            stmt = stmt.where(
                InvestigationTask.status == InvestigationTaskStatus(status_filter)
            )
        except ValueError:
            pass
    rows = (await db.execute(stmt)).all()

    out = []
    for task, asset_label in rows:
        duration_s = None
        if task.started_at and task.finished_at:
            duration_s = (task.finished_at - task.started_at).total_seconds()
        out.append({
            "id": task.id,
            "workspace_id": task.workspace_id,
            "asset_id": task.asset_id,
            "asset_label": asset_label,
            "tool": task.tool,
            "status": task.status.value if hasattr(task.status, "value") else str(task.status),
            "progress_pct": task.progress_pct,
            "duration_s": duration_s,
            "raw_output_present": task.raw_output is not None,
            "error": task.error,
            "created_at": task.created_at,
            "started_at": task.started_at,
            "finished_at": task.finished_at,
        })
    return out


async def get_task_findings(
    db: AsyncSession, task_id: UUID
) -> list[InvestigationFinding]:
    rows = (
        await db.execute(
            select(InvestigationFinding)
            .where(InvestigationFinding.task_id == task_id)
            .order_by(InvestigationFinding.severity, InvestigationFinding.kind)
        )
    ).scalars().all()
    return list(rows)


def mark_task_started(task: InvestigationTask) -> None:
    task.status = InvestigationTaskStatus.running
    task.started_at = datetime.now(timezone.utc)


def mark_task_completed(task: InvestigationTask, raw_output: str | None) -> None:
    task.status = InvestigationTaskStatus.completed
    task.progress_pct = 100
    task.finished_at = datetime.now(timezone.utc)
    if raw_output is not None:
        # Cap at 100KB (per plan §Risk + scaling notes)
        task.raw_output = raw_output[:100_000]


def mark_task_failed(task: InvestigationTask, error: str) -> None:
    task.status = InvestigationTaskStatus.failed
    task.finished_at = datetime.now(timezone.utc)
    task.error = error[:2000]
