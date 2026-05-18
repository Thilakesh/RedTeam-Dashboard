"""FastAPI dependencies for cookie-based RS256 auth + RBAC + feature gates."""
from __future__ import annotations

from uuid import UUID

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import features
from app.core.db import get_db
from app.core.redis import get_redis
from app.core.tokens import decode_access_token
from app.models import User, UserRole
from app.models.auth import BlacklistedJti

ACCESS_COOKIE = "rt_access"
REFRESH_COOKIE = "rt_refresh"
CSRF_COOKIE = "rt_csrf"


class CurrentUser:
    """Per-request handle for the authenticated user.

    `org_id` is preserved for backwards compatibility with existing
    tenant-scoped queries (Scan.org_id, etc.). New code should prefer
    `scan_filter()` which encodes the admin-vs-analyst visibility rule.
    """

    def __init__(self, user: User, jti: UUID, session_id: UUID):
        self.id: UUID = user.id
        self.org_id: UUID = user.org_id
        self.email: str = user.email
        self.role: UserRole = user.role
        self.is_admin: bool = user.role == UserRole.admin
        self.jti: UUID = jti
        self.session_id: UUID = session_id
        self._user = user

    def scan_filter(self, model_column) -> bool:
        """Helper for query .where(...). Admin sees all; analyst sees only own."""
        from sqlalchemy import true

        if self.is_admin:
            return true()
        return model_column == self.id


async def _resolve_current_user(request: Request, db: AsyncSession) -> CurrentUser:
    token = request.cookies.get(ACCESS_COOKIE)
    if not token:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "missing access token")

    try:
        payload = decode_access_token(token)
    except ValueError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid access token") from None

    try:
        user_id = UUID(payload["sub"])
        jti = UUID(payload["jti"])
        session_id = UUID(payload["sid"])
    except (KeyError, ValueError):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "malformed token claims") from None

    # Fast-path blacklist check via Redis (per-jti and per-session-id), DB is
    # the authoritative fallback for jti only.
    redis = get_redis()
    if await redis.exists(f"blacklist:jti:{jti}"):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "token revoked")
    if await redis.exists(f"blacklist:sid:{session_id}"):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "session revoked")
    if await db.get(BlacklistedJti, jti) is not None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "token revoked")

    user = await db.scalar(select(User).where(User.id == user_id))
    if user is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "user not found")
    if not user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "user disabled")

    return CurrentUser(user, jti=jti, session_id=session_id)


async def get_current_user(
    request: Request, db: AsyncSession = Depends(get_db)
) -> CurrentUser:
    return await _resolve_current_user(request, db)


# Backwards-compat alias for SSE endpoints. EventSource sends cookies natively,
# so this is functionally identical to get_current_user now.
async def get_current_user_sse(
    request: Request, db: AsyncSession = Depends(get_db)
) -> CurrentUser:
    return await _resolve_current_user(request, db)


def require_role(*roles: UserRole):
    """FastAPI dependency factory: gate the route on caller's role."""
    allowed = {r.value if isinstance(r, UserRole) else r for r in roles}

    async def _dep(user: CurrentUser = Depends(get_current_user)) -> CurrentUser:
        if user.role.value not in allowed:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "forbidden")
        return user

    return _dep


def require_admin():
    return require_role(UserRole.admin)


def require_feature(feature_name: str):
    """Gate the route on whether feature_name is enabled for this user."""

    async def _dep(
        user: CurrentUser = Depends(get_current_user),
        db: AsyncSession = Depends(get_db),
    ) -> CurrentUser:
        if not await features.is_enabled(db, user.id, feature_name):
            raise HTTPException(
                status.HTTP_403_FORBIDDEN, f"feature '{feature_name}' disabled for this user"
            )
        return user

    return _dep
