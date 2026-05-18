"""Admin-only user CRUD + invite issuance.

Public signup is gone — admins create users; new user receives a copy-link
invite URL; user POSTs /auth/invite/accept to set their password and log in.
"""
from __future__ import annotations

import os
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import CurrentUser, require_admin
from app.core.config import get_settings
from app.core.db import get_db
from app.core.features import FEATURES, invalidate_user
from app.models import Organization, User, UserRole
from app.models.auth import UserFeature
from app.schemas.admin import (
    FeatureRow,
    FeatureSetRequest,
    UserCreateRequest,
    UserCreateResponse,
    UserOut,
    UserPatchRequest,
)
from app.services import audit, invites, sessions

router = APIRouter(prefix="/users", tags=["users"])
settings = get_settings()


def _frontend_base() -> str:
    return os.environ.get("FRONTEND_URL", "http://localhost:3000")


def _user_out(user: User) -> UserOut:
    return UserOut(
        id=user.id,
        email=user.email,
        role=user.role.value,
        is_active=user.is_active,
        created_by=user.created_by,
        created_at=user.created_at,
        has_pending_invite=invites.has_pending_invite(user),
    )


@router.get("", response_model=list[UserOut])
async def list_users(
    actor: CurrentUser = Depends(require_admin()),
    db: AsyncSession = Depends(get_db),
) -> list[UserOut]:
    rows = await db.scalars(select(User).order_by(desc(User.created_at)))
    return [_user_out(u) for u in rows.all()]


@router.post("", response_model=UserCreateResponse, status_code=status.HTTP_201_CREATED)
async def create_user(
    req: UserCreateRequest,
    request: Request,
    actor: CurrentUser = Depends(require_admin()),
    db: AsyncSession = Depends(get_db),
) -> UserCreateResponse:
    existing = await db.scalar(select(User).where(User.email == req.email))
    if existing is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, "email already registered")

    org = await db.scalar(
        select(Organization).where(Organization.name == settings.default_org_name)
    )
    if org is None:
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "default org missing")

    user = User(
        org_id=org.id,
        email=req.email,
        password_hash=None,
        role=UserRole(req.role),
        is_active=True,
        created_by=actor.id,
    )
    db.add(user)
    await db.flush()

    raw_invite = await invites.issue_invite(db, user=user)
    await audit.log(
        db,
        actor_user_id=actor.id,
        action="user.created",
        target_type="user",
        target_id=user.id,
        meta={"role": user.role.value, "email": user.email},
        request=request,
        commit=False,
    )
    await db.commit()
    await db.refresh(user)

    return UserCreateResponse(
        user=_user_out(user),
        invite_token=raw_invite,
        invite_url=invites.build_invite_url(raw_token=raw_invite, frontend_base=_frontend_base()),
    )


@router.get("/{user_id}", response_model=UserOut)
async def get_user(
    user_id: UUID,
    actor: CurrentUser = Depends(require_admin()),
    db: AsyncSession = Depends(get_db),
) -> UserOut:
    user = await db.get(User, user_id)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "user not found")
    return _user_out(user)


@router.patch("/{user_id}", response_model=UserOut)
async def patch_user(
    user_id: UUID,
    req: UserPatchRequest,
    request: Request,
    actor: CurrentUser = Depends(require_admin()),
    db: AsyncSession = Depends(get_db),
) -> UserOut:
    user = await db.get(User, user_id)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "user not found")

    changes: dict[str, str] = {}
    revoke_sessions = False

    if req.role is not None and req.role != user.role.value:
        new_role = UserRole(req.role)
        # safety: never allow the last admin to demote themselves into oblivion
        if user.role == UserRole.admin and new_role != UserRole.admin:
            remaining = await db.scalar(
                select(User).where(User.role == UserRole.admin, User.id != user.id, User.is_active.is_(True))
            )
            if remaining is None:
                raise HTTPException(status.HTTP_409_CONFLICT, "cannot demote last active admin")
        user.role = new_role
        changes["role"] = new_role.value
        revoke_sessions = True

    if req.is_active is not None and req.is_active != user.is_active:
        if not req.is_active and user.id == actor.id:
            raise HTTPException(status.HTTP_409_CONFLICT, "cannot disable yourself")
        user.is_active = req.is_active
        changes["is_active"] = str(req.is_active)
        revoke_sessions = revoke_sessions or not req.is_active

    if not changes:
        return _user_out(user)

    if revoke_sessions:
        await sessions.revoke_all_for_user(db, user_id=user.id, reason="admin_revoke")

    await audit.log(
        db,
        actor_user_id=actor.id,
        action="user.patched",
        target_type="user",
        target_id=user.id,
        meta=changes,
        request=request,
        commit=False,
    )
    await db.commit()
    await db.refresh(user)
    return _user_out(user)


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(
    user_id: UUID,
    request: Request,
    actor: CurrentUser = Depends(require_admin()),
    db: AsyncSession = Depends(get_db),
) -> None:
    """Soft-delete via is_active=false; preserves audit + FK history."""
    user = await db.get(User, user_id)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "user not found")
    if user.id == actor.id:
        raise HTTPException(status.HTTP_409_CONFLICT, "cannot delete yourself")
    user.is_active = False
    await sessions.revoke_all_for_user(db, user_id=user.id, reason="admin_revoke")
    await audit.log(
        db,
        actor_user_id=actor.id,
        action="user.disabled",
        target_type="user",
        target_id=user.id,
        request=request,
        commit=False,
    )
    await db.commit()


@router.post("/{user_id}/invite/regenerate", response_model=UserCreateResponse)
async def regenerate_invite(
    user_id: UUID,
    request: Request,
    actor: CurrentUser = Depends(require_admin()),
    db: AsyncSession = Depends(get_db),
) -> UserCreateResponse:
    user = await db.get(User, user_id)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "user not found")
    raw_invite = await invites.issue_invite(db, user=user)
    await audit.log(
        db,
        actor_user_id=actor.id,
        action="user.invite_regenerated",
        target_type="user",
        target_id=user.id,
        request=request,
        commit=False,
    )
    await db.commit()
    await db.refresh(user)
    return UserCreateResponse(
        user=_user_out(user),
        invite_token=raw_invite,
        invite_url=invites.build_invite_url(raw_token=raw_invite, frontend_base=_frontend_base()),
    )


@router.get("/{user_id}/features", response_model=list[FeatureRow])
async def list_user_features(
    user_id: UUID,
    actor: CurrentUser = Depends(require_admin()),
    db: AsyncSession = Depends(get_db),
) -> list[FeatureRow]:
    user = await db.get(User, user_id)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "user not found")
    overrides = await db.scalars(select(UserFeature).where(UserFeature.user_id == user_id))
    by_name = {row.feature_name: row.enabled for row in overrides.all()}
    return [
        FeatureRow(feature_name=name, enabled=by_name.get(name, True))
        for name in sorted(FEATURES)
    ]


@router.put("/{user_id}/features/{feature_name}", response_model=FeatureRow)
async def set_user_feature(
    user_id: UUID,
    feature_name: str,
    req: FeatureSetRequest,
    request: Request,
    actor: CurrentUser = Depends(require_admin()),
    db: AsyncSession = Depends(get_db),
) -> FeatureRow:
    if feature_name not in FEATURES:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"unknown feature: {feature_name}")
    user = await db.get(User, user_id)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "user not found")

    row = await db.scalar(
        select(UserFeature).where(
            UserFeature.user_id == user_id, UserFeature.feature_name == feature_name
        )
    )
    if row is None:
        row = UserFeature(
            user_id=user_id, feature_name=feature_name, enabled=req.enabled, updated_by=actor.id
        )
        db.add(row)
    else:
        row.enabled = req.enabled
        row.updated_by = actor.id

    invalidate_user(user_id)
    await audit.log(
        db,
        actor_user_id=actor.id,
        action="feature.toggled",
        target_type="user",
        target_id=user_id,
        meta={"feature": feature_name, "enabled": req.enabled},
        request=request,
        commit=False,
    )
    await db.commit()
    return FeatureRow(feature_name=feature_name, enabled=req.enabled)
