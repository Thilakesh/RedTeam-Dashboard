"""Invite token issuance + redemption (copy-link flow).

Admin creates a user with no password; backend mints a 32-byte URL-safe token,
stores sha256(token) on users.invite_token_hash, and returns the raw token to
the admin to share. The user opens /accept-invite?token=... and POSTs to
/auth/invite/accept with a new password — server validates the hash + expiry,
sets password_hash, clears the invite columns.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.security import hash_password
from app.core.tokens import generate_invite_token, hash_invite_token
from app.models import User


async def issue_invite(db: AsyncSession, *, user: User) -> str:
    """Mint a new invite token, store its hash on the user, return the raw token."""
    settings = get_settings()
    raw = generate_invite_token()
    user.invite_token_hash = hash_invite_token(raw)
    user.invite_expires_at = datetime.now(timezone.utc) + timedelta(hours=settings.invite_ttl_hours)
    await db.flush()
    return raw


async def find_user_by_invite(db: AsyncSession, *, raw_token: str) -> User | None:
    token_hash = hash_invite_token(raw_token)
    user = await db.scalar(select(User).where(User.invite_token_hash == token_hash))
    if user is None:
        return None
    if user.invite_expires_at is None or user.invite_expires_at < datetime.now(timezone.utc):
        return None
    return user


async def accept_invite(db: AsyncSession, *, user: User, new_password: str) -> None:
    """Set the password, clear invite columns. Caller commits."""
    user.password_hash = hash_password(new_password)
    user.password_changed_at = datetime.now(timezone.utc)
    user.invite_token_hash = None
    user.invite_expires_at = None


def build_invite_url(*, raw_token: str, frontend_base: str = "http://localhost:3000") -> str:
    """Helper for the admin UI to render a copy-link."""
    return f"{frontend_base.rstrip('/')}/accept-invite?token={raw_token}"


def revoke_invite(user: User) -> None:
    user.invite_token_hash = None
    user.invite_expires_at = None


def has_pending_invite(user: User) -> bool:
    if user.invite_token_hash is None:
        return False
    if user.invite_expires_at is None:
        return False
    return user.invite_expires_at > datetime.now(timezone.utc)


# Convenience: a sentinel for callers that only care about the raw token string.
UUID_ZERO = UUID("00000000-0000-0000-0000-000000000000")
