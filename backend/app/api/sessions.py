"""Session listing + revocation.

- Analyst: list/revoke their own.
- Admin: list/revoke any user's sessions.
"""
from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import CurrentUser, get_current_user, require_admin
from app.core.db import get_db
from app.models import User
from app.models.auth import RefreshSession
from app.schemas.admin import SessionOut
from app.services import audit
from app.services import sessions as session_svc

router = APIRouter(prefix="/sessions", tags=["sessions"])


def _to_out(row: RefreshSession, user_email: str | None) -> SessionOut:
    return SessionOut(
        id=row.id,
        user_id=row.user_id,
        user_email=user_email,
        device_label=row.device_label,
        ip_address=str(row.ip_address) if row.ip_address else None,
        user_agent=row.user_agent,
        expires_at=row.expires_at,
        revoked=row.revoked,
        revoked_reason=row.revoked_reason,
        last_used_at=row.last_used_at,
        created_at=row.created_at,
    )


@router.get("", response_model=list[SessionOut])
async def list_sessions(
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> list[SessionOut]:
    """Admin: all sessions. Analyst: own only."""
    stmt = select(RefreshSession, User.email).join(User, User.id == RefreshSession.user_id)
    if not user.is_admin:
        stmt = stmt.where(RefreshSession.user_id == user.id)
    stmt = stmt.order_by(desc(RefreshSession.created_at)).limit(500)
    rows = await db.execute(stmt)
    return [_to_out(s, email) for s, email in rows.all()]


@router.delete("/{session_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_session(
    session_id: UUID,
    request: Request,
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> None:
    row = await db.get(RefreshSession, session_id)
    # Same 404 for "doesn't exist" and "exists but isn't yours" — a 403 here
    # would let a non-admin enumerate valid session ids by probing UUIDs.
    if row is None or (not user.is_admin and row.user_id != user.id):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "session not found")
    reason = "admin_revoke" if user.is_admin and row.user_id != user.id else "user_revoke"
    await session_svc.revoke_one(db, session_id=session_id, reason=reason)
    await audit.log(
        db,
        actor_user_id=user.id,
        action="session.revoked",
        target_type="session",
        target_id=session_id,
        meta={"target_user_id": str(row.user_id), "reason": reason},
        request=request,
        commit=False,
    )
    await db.commit()


@router.delete("/user/{user_id}", status_code=status.HTTP_204_NO_CONTENT, dependencies=[Depends(require_admin())])
async def revoke_all_for_user(
    user_id: UUID,
    request: Request,
    actor: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> None:
    count = await session_svc.revoke_all_for_user(db, user_id=user_id, reason="admin_revoke")
    await audit.log(
        db,
        actor_user_id=actor.id,
        action="session.revoked_all",
        target_type="user",
        target_id=user_id,
        meta={"count": count},
        request=request,
        commit=False,
    )
    await db.commit()
