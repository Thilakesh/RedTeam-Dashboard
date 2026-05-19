"""Target trust / verification helpers.

A Target is "verified" when an admin has flipped is_verified=true via the
admin Verified Targets page. Verified targets unlock aggressive scan
profiles; unverified targets are restricted to passive scans.
"""
from __future__ import annotations

from uuid import UUID

from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Target

# Anything that hits the target hard. Used by target_workspaces.create_task.
AGGRESSIVE_TOOLS: frozenset[str] = frozenset({"nmap_deep", "ffuf", "dirsearch", "naabu"})


async def assert_aggressive_allowed(
    db: AsyncSession, *, target_id: UUID, reason: str
) -> Target:
    """403 if target is not verified; returns the Target row otherwise.

    `reason` is surfaced in the error detail so the UI can explain the gate.
    """
    target = await db.get(Target, target_id)
    if target is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "target not found")
    if not target.is_verified:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            f"target not verified — {reason} requires a verified target",
        )
    return target
