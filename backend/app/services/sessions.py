"""Refresh session lifecycle: create, rotate, revoke, reuse-detection.

Refresh tokens are opaque random strings. The server stores only sha256(token).
Each /auth/refresh call:
  1. validates the presented token's hash against an unrevoked row,
  2. marks that row revoked (reason='rotation'),
  3. creates a new session row whose parent_session_id chains to the old one,
  4. issues a new access JWT + new refresh token.

If a hash matches a row that is already revoked, that's reuse-detection: the
whole parent_session_id chain is killed and every still-valid access JWT for
those sessions is blacklisted.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import UUID

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.redis import get_redis
from app.core.tokens import generate_refresh_token, hash_refresh_token
from app.models.auth import BlacklistedJti, RefreshSession


async def _blacklist_session_id(session: RefreshSession) -> None:
    """Add Redis sentinel so any access JWT carrying this sid is rejected.

    TTL matches the access-token lifetime ceiling (refresh expiry) so the key
    cleans itself up once no live access token could still reference it.
    """
    redis = get_redis()
    ttl = int((session.expires_at - datetime.now(timezone.utc)).total_seconds())
    if ttl < 60:
        ttl = 60
    await redis.set(f"blacklist:sid:{session.id}", "1", ex=ttl)
    await redis.delete(f"session:{session.id}")
    await redis.srem(f"session:user:{session.user_id}", str(session.id))


def _device_label(user_agent: str | None) -> str | None:
    if not user_agent:
        return None
    # cheap parse — keep just first 120 chars
    return user_agent[:120]


async def create_session(
    db: AsyncSession,
    *,
    user_id: UUID,
    ip_address: str | None,
    user_agent: str | None,
    parent_session_id: UUID | None = None,
) -> tuple[RefreshSession, str]:
    """Create a fresh refresh session. Returns (session, raw_refresh_token)."""
    settings = get_settings()
    raw = generate_refresh_token()
    session = RefreshSession(
        user_id=user_id,
        refresh_token_hash=hash_refresh_token(raw),
        device_label=_device_label(user_agent),
        ip_address=ip_address,
        user_agent=user_agent,
        expires_at=datetime.now(timezone.utc) + timedelta(days=settings.jwt_refresh_expire_days),
        parent_session_id=parent_session_id,
        last_used_at=datetime.now(timezone.utc),
    )
    db.add(session)
    await db.flush()
    return session, raw


async def find_active(db: AsyncSession, *, raw_token: str) -> RefreshSession | None:
    """Return the matching session if it exists and is not expired (regardless of revoked)."""
    token_hash = hash_refresh_token(raw_token)
    row = await db.scalar(
        select(RefreshSession).where(RefreshSession.refresh_token_hash == token_hash)
    )
    if row is None:
        return None
    if row.expires_at < datetime.now(timezone.utc):
        return None
    return row


async def revoke_chain(
    db: AsyncSession, *, root_session_id: UUID, reason: str
) -> list[RefreshSession]:
    """Revoke every session in the parent_session_id chain rooted at given id.

    Walks both directions (ancestors + descendants) so a stolen refresh token
    can't pivot to a sibling session.
    """
    visited: dict[UUID, RefreshSession] = {}

    async def _walk(sid: UUID) -> None:
        if sid in visited:
            return
        row = await db.get(RefreshSession, sid)
        if row is None:
            return
        visited[sid] = row
        # ancestors
        if row.parent_session_id is not None:
            await _walk(row.parent_session_id)
        # descendants
        children = await db.scalars(
            select(RefreshSession).where(RefreshSession.parent_session_id == sid)
        )
        for child in children.all():
            await _walk(child.id)

    await _walk(root_session_id)

    for row in visited.values():
        if not row.revoked:
            row.revoked = True
            row.revoked_reason = reason
            await _blacklist_session_id(row)
    await db.flush()
    return list(visited.values())


async def revoke_one(db: AsyncSession, *, session_id: UUID, reason: str) -> RefreshSession | None:
    row = await db.get(RefreshSession, session_id)
    if row is None:
        return None
    if not row.revoked:
        row.revoked = True
        row.revoked_reason = reason
        await _blacklist_session_id(row)
        await db.flush()
    return row


async def revoke_all_for_user(db: AsyncSession, *, user_id: UUID, reason: str) -> int:
    """Mass-revoke every active session for a user (used on password change, role change)."""
    active = await db.scalars(
        select(RefreshSession).where(
            RefreshSession.user_id == user_id, RefreshSession.revoked.is_(False)
        )
    )
    rows = list(active.all())
    for row in rows:
        row.revoked = True
        row.revoked_reason = reason
        await _blacklist_session_id(row)
    await db.flush()
    return len(rows)


async def blacklist_jti(
    db: AsyncSession,
    *,
    jti: UUID,
    user_id: UUID,
    expires_at: datetime,
    reason: str,
) -> None:
    """Add a JTI to the blacklist. Idempotent."""
    existing = await db.get(BlacklistedJti, jti)
    if existing is not None:
        return
    db.add(
        BlacklistedJti(
            jti=jti,
            user_id=user_id,
            expires_at=expires_at,
            reason=reason,
        )
    )
    await db.flush()


async def is_jti_blacklisted(db: AsyncSession, *, jti: UUID) -> bool:
    return await db.get(BlacklistedJti, jti) is not None
