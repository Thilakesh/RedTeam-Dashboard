"""Admin-only Verified Targets management.

Verified targets unlock aggressive scan profiles (deep recon, intrusive
vuln, ffuf/dirsearch/naabu/nmap_deep). Only admins can verify or unverify;
analysts cannot see this section in the UI.
"""
from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import CurrentUser, get_current_user, require_admin
from app.core.config import get_settings
from app.core.db import get_db
from app.models import Organization, Project, Target, User
from app.schemas.target import VerifiedTargetCreateRequest, VerifiedTargetOut
from app.services import audit

# Router is auth-only at the prefix level; mutating endpoints add require_admin.
router = APIRouter(prefix="/verified-targets", tags=["verified-targets"])

settings = get_settings()


async def _default_project_id(db: AsyncSession) -> UUID:
    """Singleton org's default project. Mirrors the helper in scans.py but
    doesn't require a user (admin endpoint operates on the platform's only org).
    """
    org = await db.scalar(
        select(Organization).where(Organization.name == settings.default_org_name)
    )
    if org is None:
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "default org missing")
    project_id = await db.scalar(
        select(Project.id).where(Project.org_id == org.id, Project.name == settings.default_project_name)
    )
    if project_id is None:
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "default project missing")
    return project_id


def _to_out(target: Target, email: str | None) -> VerifiedTargetOut:
    return VerifiedTargetOut(
        id=target.id,
        domain=target.domain,
        is_verified=target.is_verified,
        verified_by=target.verified_by,
        verified_by_email=email,
        verified_at=target.verified_at,
        created_at=target.created_at,
    )


@router.get("", response_model=list[VerifiedTargetOut])
async def list_verified(
    actor: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> list[VerifiedTargetOut]:
    """All verified targets across the platform. Read-open to analysts too."""
    rows = (
        await db.execute(
            select(Target, User.email)
            .outerjoin(User, User.id == Target.verified_by)
            .where(Target.is_verified.is_(True))
            .order_by(desc(Target.verified_at))
        )
    ).all()
    return [_to_out(t, email) for t, email in rows]


@router.post("", response_model=VerifiedTargetOut, status_code=status.HTTP_201_CREATED)
async def add_verified(
    req: VerifiedTargetCreateRequest,
    request: Request,
    actor: CurrentUser = Depends(require_admin()),
    db: AsyncSession = Depends(get_db),
) -> VerifiedTargetOut:
    """Create the Target if absent (under singleton org/default project),
    then mark it verified. Idempotent — re-adding a verified domain just
    refreshes verified_by/verified_at."""
    domain = req.domain.strip().lower()
    if not domain:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "domain required")

    project_id = await _default_project_id(db)
    target = await db.scalar(
        select(Target).where(Target.project_id == project_id, Target.domain == domain)
    )
    if target is None:
        target = Target(project_id=project_id, domain=domain)
        db.add(target)
        await db.flush()

    target.is_verified = True
    target.verified_by = actor.id
    target.verified_at = datetime.now(timezone.utc)

    await audit.log(
        db,
        actor_user_id=actor.id,
        action="target.verified",
        target_type="target",
        target_id=target.id,
        meta={"domain": domain},
        request=request,
        commit=False,
    )
    await db.commit()
    await db.refresh(target)
    return _to_out(target, actor.email)


@router.delete("/{target_id}", status_code=status.HTTP_204_NO_CONTENT)
async def unverify(
    target_id: UUID,
    request: Request,
    actor: CurrentUser = Depends(require_admin()),
    db: AsyncSession = Depends(get_db),
) -> None:
    target = await db.get(Target, target_id)
    if target is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "target not found")
    if not target.is_verified:
        return
    target.is_verified = False
    target.verified_by = None
    target.verified_at = None
    await audit.log(
        db,
        actor_user_id=actor.id,
        action="target.unverified",
        target_type="target",
        target_id=target.id,
        meta={"domain": target.domain},
        request=request,
        commit=False,
    )
    await db.commit()
