"""Append-only audit logging.

Every privileged or auth-relevant action calls audit.log(...). Rows are never
updated; the table is truncated only by a future scheduled purge cron.
"""
from __future__ import annotations

from typing import Any
from uuid import UUID

from fastapi import Request
from sqlalchemy.ext.asyncio import AsyncSession

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
    """Insert an audit row. `commit=False` lets callers batch with surrounding work."""
    row = AuditLog(
        actor_user_id=actor_user_id,
        actor_ip=_client_ip(request),
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
