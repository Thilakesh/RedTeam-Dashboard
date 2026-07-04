"""Target management endpoints."""
from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import CurrentUser, get_current_user
from app.core.db import get_db
from app.models import Project, Target
from app.schemas.target import TargetOut

router = APIRouter(prefix="/targets", tags=["targets"])


async def _get_target_for_user(
    target_id: UUID, db: AsyncSession, user: CurrentUser
) -> Target:
    target = await db.scalar(
        select(Target)
        .join(Project, Project.id == Target.project_id)
        .where(Target.id == target_id, Project.org_id == user.org_id)
    )
    if target is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "target not found")
    return target


@router.get("", response_model=list[TargetOut])
async def list_targets(
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> list[TargetOut]:
    rows = (
        await db.execute(
            select(Target)
            .join(Project, Project.id == Target.project_id)
            .where(Project.org_id == user.org_id)
            .order_by(Target.domain)
        )
    ).scalars().all()
    return [TargetOut.model_validate(t) for t in rows]
