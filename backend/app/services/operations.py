"""Service layer for standalone Operations.

An Operation is one manually-launched scan (one tool, one typed target), owned
by org_id (tenant) + created_by (user). No workspace/asset linkage. Execution
reuses the investigation adapters via the worker's ``run_operation``.
"""
from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Operation, OperationFinding, OperationStatus
from app.services import storage
from app.services.operations_command import (
    TOOLS,
    render_command,
    validate_custom_args,
    validate_target,
)
from app.services.queue import enqueue_operation

_ACTIVE = (OperationStatus.queued.value, OperationStatus.running.value)

# Caps total concurrent load per user regardless of request pacing — the
# per-minute rate limit alone doesn't stop someone from patiently (or via a
# slow Intruder run) accumulating hundreds of active operations over time and
# exhausting the investigation-worker queue. This is the actual ceiling.
MAX_ACTIVE_OPERATIONS_PER_USER = 10


class DuplicateOperationError(Exception):
    """Raised when an identical operation is already queued or running —
    kept distinct from ValueError so the API layer can map it to 409 instead
    of the 422 used for bad input."""


class TooManyActiveOperationsError(Exception):
    """Raised when the user already has MAX_ACTIVE_OPERATIONS_PER_USER
    operations queued or running — mapped to 429 by the API layer."""
_DB_PREVIEW_CAP = 100_000
_STDERR_PREVIEW_CAP = 20_000


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

    active_count = await db.scalar(
        select(func.count())
        .select_from(Operation)
        .where(
            Operation.org_id == org_id,
            Operation.created_by == created_by,
            Operation.status.in_(_ACTIVE),
        )
    )
    if active_count >= MAX_ACTIVE_OPERATIONS_PER_USER:
        raise TooManyActiveOperationsError(
            f"you already have {MAX_ACTIVE_OPERATIONS_PER_USER} operations queued or "
            "running — wait for one to finish before starting another"
        )

    # Blocks replay of the exact same create-operation request (and
    # double-clicks) — same user, same target+tool, still in flight.
    existing = await db.scalar(
        select(Operation.id).where(
            Operation.org_id == org_id,
            Operation.created_by == created_by,
            Operation.target == host,
            Operation.target_type == target_type,
            Operation.tool == tool,
            Operation.status.in_(_ACTIVE),
        )
    )
    if existing is not None:
        raise DuplicateOperationError(
            "an identical operation for this target and tool is already queued or running"
        )

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


async def list_operations(
    db: AsyncSession, org_id: UUID, created_by: UUID, limit: int = 200
) -> list[Operation]:
    """Own operations only — no role gets blanket org visibility here (matches
    the Scan IDOR fix: analysts and admins alike only see what they created)."""
    rows = (
        await db.execute(
            select(Operation)
            .where(Operation.org_id == org_id, Operation.created_by == created_by)
            .order_by(desc(Operation.created_at))
            .limit(limit)
        )
    ).scalars().all()
    return list(rows)


async def get_operation(
    db: AsyncSession, org_id: UUID, operation_id: UUID
) -> Operation | None:
    """org_id-scoped only — the caller (app/api/operations.py::_get_op_for_user)
    layers the created_by ownership check on top, so cross-tenant misses stay
    404 while same-tenant non-owner hits can be told apart and 403'd."""
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


def mark_completed(
    op: Operation,
    raw_output: str | None,
    *,
    exit_code: int | None = None,
    stderr: str | None = None,
) -> None:
    op.status = OperationStatus.completed.value
    op.progress_pct = 100
    op.completed_at = datetime.now(timezone.utc)
    op.exit_code = exit_code
    if raw_output is not None:
        # DB keeps a capped preview; the untruncated blob goes to MinIO so
        # nothing is lost to the cap (see plan Phase 3 — lift the 100KB cap).
        op.raw_output = raw_output[:_DB_PREVIEW_CAP]
        if len(raw_output) > _DB_PREVIEW_CAP:
            object_name = f"logs/operations/{op.id}/stdout.txt"
            if storage.upload_bytes(object_name, raw_output.encode("utf-8", errors="replace")):
                op.stdout_object_key = object_name
    if stderr:
        op.stderr = stderr[:_STDERR_PREVIEW_CAP]
        if len(stderr) > _STDERR_PREVIEW_CAP:
            object_name = f"logs/operations/{op.id}/stderr.txt"
            if storage.upload_bytes(object_name, stderr.encode("utf-8", errors="replace")):
                op.stderr_object_key = object_name


def mark_failed(op: Operation, error: str) -> None:
    op.status = OperationStatus.failed.value
    op.completed_at = datetime.now(timezone.utc)
    op.error = error[:2000]
