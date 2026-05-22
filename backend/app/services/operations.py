"""Service layer for standalone Operations.

An Operation is one manually-launched scan (one tool, one typed target), owned
by org_id (tenant) + created_by (user). No workspace/asset linkage. Execution
reuses the investigation adapters via the worker's ``run_operation``.
"""
from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Operation, OperationFinding, OperationStatus
from app.services.operations_command import (
    TOOLS,
    render_command,
    validate_custom_args,
    validate_target,
)
from app.services.queue import enqueue_operation

_ACTIVE = (OperationStatus.queued.value, OperationStatus.running.value)


def build_preview(
    *,
    target_type: str,
    target: str,
    tool: str,
    profile: str | None,
    protocol: str | None,
    custom_args: str | None,
) -> str:
    """Server-authoritative command preview. Raises ValueError on bad input."""
    if tool not in TOOLS:
        raise ValueError(f"tool '{tool}' is not supported")
    host = validate_target(target_type, target)
    validate_custom_args(tool, profile, custom_args)
    return render_command(
        tool, host, profile=profile, protocol=protocol, custom_args=custom_args
    )


async def create_operation(
    db: AsyncSession,
    *,
    org_id: UUID,
    created_by: UUID | None,
    target_type: str,
    target: str,
    tool: str,
    profile: str | None,
    protocol: str | None,
    custom_args: str | None,
) -> Operation:
    """Insert an Operation row + enqueue it. Raises ValueError on bad input."""
    if tool not in TOOLS:
        raise ValueError(f"tool '{tool}' is not supported")
    host = validate_target(target_type, target)
    validate_custom_args(tool, profile, custom_args)
    generated_command = render_command(
        tool, host, profile=profile, protocol=protocol, custom_args=custom_args
    )
    op = Operation(
        org_id=org_id,
        created_by=created_by,
        target=host,
        target_type=target_type,
        tool=tool,
        profile=profile,
        protocol=protocol,
        custom_args=custom_args,
        generated_command=generated_command,
        status=OperationStatus.queued.value,
    )
    db.add(op)
    await db.commit()
    await db.refresh(op)
    await enqueue_operation(str(op.id))
    return op


async def list_operations(db: AsyncSession, org_id: UUID, limit: int = 200) -> list[Operation]:
    rows = (
        await db.execute(
            select(Operation)
            .where(Operation.org_id == org_id)
            .order_by(desc(Operation.created_at))
            .limit(limit)
        )
    ).scalars().all()
    return list(rows)


async def get_operation(
    db: AsyncSession, org_id: UUID, operation_id: UUID
) -> Operation | None:
    return (
        await db.execute(
            select(Operation).where(
                Operation.id == operation_id, Operation.org_id == org_id
            )
        )
    ).scalar_one_or_none()


async def get_operation_findings(
    db: AsyncSession, operation_id: UUID
) -> list[OperationFinding]:
    rows = (
        await db.execute(
            select(OperationFinding)
            .where(OperationFinding.operation_id == operation_id)
            .order_by(OperationFinding.severity, OperationFinding.kind)
        )
    ).scalars().all()
    return list(rows)


async def cancel_operation(db: AsyncSession, op: Operation) -> None:
    """Mark a queued/running operation cancelled. The worker's start +
    completion guards turn this into a real no-op / discard."""
    if op.status not in _ACTIVE:
        raise ValueError("operation is not cancellable")
    op.status = OperationStatus.cancelled.value
    op.completed_at = datetime.now(timezone.utc)
    await db.commit()


async def retry_operation(
    db: AsyncSession, op: Operation, created_by: UUID | None
) -> Operation:
    """Fresh row copying the original config; the original is left untouched."""
    new = Operation(
        org_id=op.org_id,
        created_by=created_by,
        target=op.target,
        target_type=op.target_type,
        tool=op.tool,
        profile=op.profile,
        protocol=op.protocol,
        custom_args=op.custom_args,
        generated_command=op.generated_command,
        status=OperationStatus.queued.value,
    )
    db.add(new)
    await db.commit()
    await db.refresh(new)
    await enqueue_operation(str(new.id))
    return new


def duration_seconds(op: Operation) -> float | None:
    if op.started_at and op.completed_at:
        return (op.completed_at - op.started_at).total_seconds()
    return None


# --- worker-side state transitions -------------------------------------------

def mark_started(op: Operation) -> None:
    op.status = OperationStatus.running.value
    op.started_at = datetime.now(timezone.utc)


def mark_completed(op: Operation, raw_output: str | None) -> None:
    op.status = OperationStatus.completed.value
    op.progress_pct = 100
    op.completed_at = datetime.now(timezone.utc)
    if raw_output is not None:
        op.raw_output = raw_output[:100_000]


def mark_failed(op: Operation, error: str) -> None:
    op.status = OperationStatus.failed.value
    op.completed_at = datetime.now(timezone.utc)
    op.error = error[:2000]
