"""Per-user profile + admin system settings.

Profile: user's own email/password.
System: admin-only runtime knobs (subset of Settings)."""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import CurrentUser, get_current_user, require_admin
from app.core.config import get_settings
from app.core.db import get_db
from app.core.security import hash_password, verify_password
from app.models import User
from app.schemas.admin import (
    ProfileUpdateRequest,
    SystemSettingsOut,
    SystemSettingsPatchRequest,
    UserOut,
)
from app.services import audit
from app.services import sessions as session_svc

router = APIRouter(prefix="/settings", tags=["settings"])


def _profile_out(row: User) -> UserOut:
    s = get_settings()
    return UserOut(
        id=row.id,
        email=row.email,
        first_name=row.first_name,
        last_name=row.last_name,
        role=row.role.value,
        is_active=row.is_active,
        is_super_admin=row.email.lower() == s.super_admin_email.lower(),
        created_by=row.created_by,
        created_at=row.created_at,
    )


@router.get("/profile", response_model=UserOut)
async def get_profile(
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> UserOut:
    row = await db.get(User, user.id)
    return _profile_out(row)


@router.patch("/profile", response_model=UserOut)
async def patch_profile(
    req: ProfileUpdateRequest,
    request: Request,
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> UserOut:
    row = await db.get(User, user.id)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "user not found")

    changes: dict[str, str] = {}

    if req.new_password is not None:
        if not req.current_password or row.password_hash is None or not verify_password(
            req.current_password, row.password_hash
        ):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "current_password incorrect")
        row.password_hash = hash_password(req.new_password)
        row.password_changed_at = datetime.now(timezone.utc)
        # Force re-login on other devices.
        await session_svc.revoke_all_for_user(db, user_id=row.id, reason="password_change")
        changes["password"] = "changed"

    if req.email is not None and req.email != row.email:
        row.email = req.email
        changes["email"] = req.email

    if req.first_name is not None and req.first_name != (row.first_name or ""):
        row.first_name = req.first_name or None
        changes["first_name"] = req.first_name

    if req.last_name is not None and req.last_name != (row.last_name or ""):
        row.last_name = req.last_name or None
        changes["last_name"] = req.last_name

    if changes:
        await audit.log(
            db,
            actor_user_id=user.id,
            action="user.profile_updated",
            target_type="user",
            target_id=user.id,
            meta=changes,
            request=request,
            commit=False,
        )
        await db.commit()
        await db.refresh(row)

    return _profile_out(row)


@router.get("/system", response_model=SystemSettingsOut, dependencies=[Depends(require_admin())])
async def get_system_settings() -> SystemSettingsOut:
    s = get_settings()
    return SystemSettingsOut(
        bbot_timeout=s.bbot_timeout,
        jwt_access_expire_minutes=s.jwt_access_expire_minutes,
        jwt_refresh_expire_days=s.jwt_refresh_expire_days,
    )


@router.patch("/system", response_model=SystemSettingsOut)
async def patch_system_settings(
    req: SystemSettingsPatchRequest,
    request: Request,
    actor: CurrentUser = Depends(require_admin()),
    db: AsyncSession = Depends(get_db),
) -> SystemSettingsOut:
    """In-memory patch for the current process. Persisting to durable store
    would require a settings table; out of scope here. Restart resets to env."""
    s = get_settings()
    changes: dict[str, int] = {}
    if req.bbot_timeout is not None:
        s.bbot_timeout = req.bbot_timeout
        changes["bbot_timeout"] = req.bbot_timeout

    if changes:
        await audit.log(
            db,
            actor_user_id=actor.id,
            action="system.settings_patched",
            meta=changes,
            request=request,
        )

    return SystemSettingsOut(
        bbot_timeout=s.bbot_timeout,
        jwt_access_expire_minutes=s.jwt_access_expire_minutes,
        jwt_refresh_expire_days=s.jwt_refresh_expire_days,
    )
