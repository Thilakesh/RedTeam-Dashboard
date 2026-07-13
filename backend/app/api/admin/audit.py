"""Admin-only audit log query.

Tenant-scoped: an org admin only sees their own org's rows. Only the
configured super admin (settings.super_admin_email) sees across all orgs —
mirrors the super-admin carve-out already used in app/api/users.py.
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
from app.models.auth import AuditLog
from app.schemas.admin import AuditOut

router = APIRouter(prefix="/admin/audit", tags=["admin"])


def _is_super_admin(user: CurrentUser) -> bool:
    return user.email.lower() == get_settings().super_admin_email.lower()


@router.get("", response_model=list[AuditOut])
async def list_audit(
    actor: UUID | None = Query(default=None),
    action: str | None = Query(default=None),
    from_: datetime | None = Query(default=None, alias="from"),
    to: datetime | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=1000),
    user: CurrentUser = Depends(require_admin()),
    db: AsyncSession = Depends(get_db),
) -> list[AuditOut]:
    stmt = select(AuditLog).order_by(desc(AuditLog.created_at)).limit(limit)
    if not _is_super_admin(user):
        stmt = stmt.where(AuditLog.org_id == user.org_id)
    if actor is not None:
        stmt = stmt.where(AuditLog.actor_user_id == actor)
    if action is not None:
        stmt = stmt.where(AuditLog.action == action)
    if from_ is not None:
        stmt = stmt.where(AuditLog.created_at >= from_)
    if to is not None:
        stmt = stmt.where(AuditLog.created_at <= to)
    rows = await db.scalars(stmt)
    return [
        AuditOut(
            id=r.id,
            actor_user_id=r.actor_user_id,
            actor_ip=str(r.actor_ip) if r.actor_ip else None,
            user_agent=r.user_agent,
            org_id=r.org_id,
            action=r.action,
            target_type=r.target_type,
            target_id=r.target_id,
            meta=r.meta,
            created_at=r.created_at,
        )
        for r in rows.all()
    ]
