"""Auth endpoints: login, refresh, logout, me, invite/accept.

Tokens travel in HttpOnly cookies (rt_access, rt_refresh) + a JS-readable
CSRF cookie (rt_csrf). The response bodies surface only the CSRF token and
non-sensitive user metadata. /auth/signup is removed — admin invites only.
"""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import (
    ACCESS_COOKIE,
    CSRF_COOKIE,
    REFRESH_COOKIE,
    CurrentUser,
    get_current_user,
)
from app.core import features
from app.core.config import get_settings
from app.core.db import get_db
from app.core.redis import get_redis
from app.core.security import verify_password
from app.core.tokens import create_access_token, generate_csrf_token
from app.models import User
from app.models.auth import RefreshSession
from app.schemas.auth import (
    InviteAcceptRequest,
    LoginRequest,
    LoginResponse,
    MeResponse,
)
from app.services import audit, invites, sessions

router = APIRouter(prefix="/auth", tags=["auth"])
settings = get_settings()


# ---------------- helpers ----------------


def _client_ip(request: Request) -> str | None:
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else None


def _set_access_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        key=ACCESS_COOKIE,
        value=token,
        max_age=settings.jwt_access_expire_minutes * 60,
        httponly=True,
        secure=settings.cookie_secure,
        samesite="lax",
        path="/",
        domain=settings.cookie_domain or None,
    )


def _set_refresh_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        key=REFRESH_COOKIE,
        value=token,
        max_age=settings.jwt_refresh_expire_days * 24 * 3600,
        httponly=True,
        secure=settings.cookie_secure,
        samesite="strict",
        # Scope to /auth so the refresh token only travels on auth requests.
        path="/auth",
        domain=settings.cookie_domain or None,
    )


def _set_csrf_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        key=CSRF_COOKIE,
        value=token,
        max_age=settings.jwt_refresh_expire_days * 24 * 3600,
        httponly=False,  # JS must read it to echo in X-CSRF-Token
        secure=settings.cookie_secure,
        samesite="strict",
        path="/",
        domain=settings.cookie_domain or None,
    )


def _clear_auth_cookies(response: Response) -> None:
    response.delete_cookie(ACCESS_COOKIE, path="/", domain=settings.cookie_domain or None)
    response.delete_cookie(REFRESH_COOKIE, path="/auth", domain=settings.cookie_domain or None)
    response.delete_cookie(CSRF_COOKIE, path="/", domain=settings.cookie_domain or None)


async def _issue_session_and_cookies(
    db: AsyncSession,
    response: Response,
    *,
    user: User,
    request: Request,
    parent_session_id=None,
) -> tuple[RefreshSession, str]:
    """Create a refresh session row, issue access JWT, set all three cookies.

    Returns (session, csrf_token). Caller commits.
    """
    ip = _client_ip(request)
    ua = request.headers.get("user-agent")

    session, raw_refresh = await sessions.create_session(
        db,
        user_id=user.id,
        ip_address=ip,
        user_agent=ua,
        parent_session_id=parent_session_id,
    )

    access_token, jti, access_expires_at = create_access_token(
        user_id=user.id, role=user.role.value, session_id=session.id
    )
    csrf = generate_csrf_token()

    _set_access_cookie(response, access_token)
    _set_refresh_cookie(response, raw_refresh)
    _set_csrf_cookie(response, csrf)

    # warm session record in redis (best-effort, expires with refresh)
    redis = get_redis()
    await redis.hset(
        f"session:{session.id}",
        mapping={"user_id": str(user.id), "ip": ip or "", "last_seen": str(int(datetime.now(timezone.utc).timestamp()))},
    )
    await redis.expire(f"session:{session.id}", settings.jwt_refresh_expire_days * 24 * 3600)
    await redis.sadd(f"session:user:{user.id}", str(session.id))
    await redis.expire(f"session:user:{user.id}", settings.jwt_refresh_expire_days * 24 * 3600)

    return session, csrf


async def _me_payload(db: AsyncSession, user: User) -> MeResponse:
    enabled = await features.list_enabled(db, user.id)
    return MeResponse(
        id=user.id,
        email=user.email,
        role=user.role.value,
        org_id=user.org_id,
        features=enabled,
    )


# ---------------- endpoints ----------------


@router.post("/login", response_model=LoginResponse)
async def login(
    req: LoginRequest,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
) -> LoginResponse:
    user = await db.scalar(select(User).where(User.email == req.email))
    if user is None or user.password_hash is None or not verify_password(req.password, user.password_hash):
        await audit.log(
            db,
            action="auth.login_failed",
            target_type="user",
            target_id=user.id if user else None,
            meta={"email": req.email},
            request=request,
        )
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid credentials")
    if not user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "user disabled")

    _, csrf = await _issue_session_and_cookies(db, response, user=user, request=request)
    await audit.log(
        db,
        actor_user_id=user.id,
        action="auth.login",
        target_type="user",
        target_id=user.id,
        request=request,
    )
    return LoginResponse(csrf_token=csrf, user=await _me_payload(db, user))


@router.post("/refresh", response_model=LoginResponse)
async def refresh(
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
) -> LoginResponse:
    raw = request.cookies.get(REFRESH_COOKIE)
    if not raw:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "missing refresh token")

    session = await sessions.find_active(db, raw_token=raw)
    if session is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid refresh token")

    # Reuse detection: hash matched a revoked row → kill chain + blacklist.
    if session.revoked:
        revoked = await sessions.revoke_chain(
            db, root_session_id=session.id, reason="reuse_detected"
        )
        # blacklist every jti for these sessions if we know any (best-effort)
        await audit.log(
            db,
            actor_user_id=session.user_id,
            action="auth.refresh_reuse_detected",
            target_type="session",
            target_id=session.id,
            meta={"revoked_sessions": [str(r.id) for r in revoked]},
            request=request,
        )
        _clear_auth_cookies(response)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "refresh token reuse detected")

    user = await db.get(User, session.user_id)
    if user is None or not user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "user unavailable")

    # rotation: revoke old, mint new with parent link
    session.revoked = True
    session.revoked_reason = "rotation"
    session.last_used_at = datetime.now(timezone.utc)
    await sessions._blacklist_session_id(session)

    _, csrf = await _issue_session_and_cookies(
        db, response, user=user, request=request, parent_session_id=session.id
    )
    await audit.log(
        db,
        actor_user_id=user.id,
        action="auth.refresh",
        target_type="session",
        target_id=session.id,
        request=request,
    )
    return LoginResponse(csrf_token=csrf, user=await _me_payload(db, user))


@router.post("/logout")
async def logout(
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
) -> dict:
    raw = request.cookies.get(REFRESH_COOKIE)
    if raw:
        session = await sessions.find_active(db, raw_token=raw)
        if session is not None and not session.revoked:
            await sessions.revoke_one(db, session_id=session.id, reason="logout")
            # remove redis session record
            redis = get_redis()
            await redis.delete(f"session:{session.id}")
            await redis.srem(f"session:user:{session.user_id}", str(session.id))
            await audit.log(
                db,
                actor_user_id=session.user_id,
                action="auth.logout",
                target_type="session",
                target_id=session.id,
                request=request,
            )
    _clear_auth_cookies(response)
    return {"ok": True}


@router.get("/me", response_model=MeResponse)
async def me(
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> MeResponse:
    full = await db.get(User, user.id)
    return await _me_payload(db, full)


@router.post("/invite/accept", response_model=LoginResponse)
async def accept_invite(
    req: InviteAcceptRequest,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
) -> LoginResponse:
    user = await invites.find_user_by_invite(db, raw_token=req.token)
    if user is None:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "invalid or expired invite token")
    if not user.is_active:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "user disabled")

    await invites.accept_invite(db, user=user, new_password=req.password)
    _, csrf = await _issue_session_and_cookies(db, response, user=user, request=request)
    await audit.log(
        db,
        actor_user_id=user.id,
        action="auth.invite_accepted",
        target_type="user",
        target_id=user.id,
        request=request,
    )
    return LoginResponse(csrf_token=csrf, user=await _me_payload(db, user))
