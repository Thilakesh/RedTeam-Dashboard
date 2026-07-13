"""Append-only audit logging.

Every privileged or auth-relevant action calls audit.log(...). Rows are never
updated; the table is truncated only by a future scheduled purge cron.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import UUID

from fastapi import Request
from sqlalchemy import delete, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import User
from app.models.auth import AuditLog


def _client_ip(request: Request | None) -> str | None:
    if request is None:
        return None
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    if request.client is not None:
        return request.client.host
    return None


async def log(
    db: AsyncSession,
    *,
    action: str,
    actor_user_id: UUID | None = None,
    target_type: str | None = None,
    target_id: UUID | None = None,
    meta: dict[str, Any] | None = None,
    request: Request | None = None,
    commit: bool = True,
) -> AuditLog:
    """Insert an audit row. `commit=False` lets callers batch with surrounding work.

    org_id is looked up from actor_user_id rather than threaded through every
    call site — keeps the ~25 existing call sites untouched while still
    denormalizing the tenant boundary onto the row for scoped reads.
    """
    org_id = None
    if actor_user_id is not None:
        org_id = await db.scalar(select(User.org_id).where(User.id == actor_user_id))
    row = AuditLog(
        actor_user_id=actor_user_id,
        actor_ip=_client_ip(request),
        user_agent=(request.headers.get("user-agent") or "")[:255] or None if request else None,
        org_id=org_id,
        action=action,
        target_type=target_type,
        target_id=target_id,
        meta=meta or {},
    )
    db.add(row)
    if commit:
        await db.commit()
    else:
        await db.flush()
    return row


async def purge_expired(db: AsyncSession, retention_days: int) -> int:
    """Delete audit rows older than the retention window. Only path allowed to
    delete from audit_logs — see migration 0022 (append-only trigger) which
    blocks DELETE unless app.allow_audit_purge is set for the transaction."""
    cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)
    await db.execute(text("SET LOCAL app.allow_audit_purge = 'true'"))
    result = await db.execute(delete(AuditLog).where(AuditLog.created_at < cutoff))
    await db.commit()
    return result.rowcount or 0
