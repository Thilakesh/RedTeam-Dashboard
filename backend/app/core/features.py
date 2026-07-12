"""Per-user feature flags.

Two-tier model:
  SCOPES — whole areas of the product. Disabling one blocks every action in
    that area regardless of the tool-level flags underneath it.
  TOOLS  — individual recon/investigation adapters. Disabling one blocks that
    tool specifically, wherever it's invoked (scan pipeline, investigation
    tasks, Operations console).
FEATURES is the union of both — it's what admin toggles and DB rows key on;
the split only matters for call sites deciding what to check.

Tool names are exactly `Stage.name` / `InvestigationAdapter` tool strings
(see app/pipeline/stage.py, app/pipeline/investigation/stage.py) so a scan's
required tool list can be read straight off `profiles.stages_for(profile)`
without a separate mapping to keep in sync.

Default-enabled semantics: a missing user_features row means the feature is on.
Only explicit `enabled=false` rows are stored. Admin UI toggles call
PUT /users/{id}/features/{name}.

Caching: 30-second TTL in-process LRU keyed by (user_id, feature_name).
Invalidation: writes call invalidate_user(user_id) directly, which also
publishes on Redis pubsub channel `features:invalidate:{user_id}` so other
workers (Arq, investigation) drop their caches too.
"""
from __future__ import annotations

import time
from uuid import UUID

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

SCOPES = frozenset(
    {
        "recon",             # basic recon Scan pipeline (any profile)
        "deep_scan",         # profile=deep specifically, on top of "recon"
        "target_workspace",  # Target Workspace area
        "investigations",    # investigation tasks within a workspace
        "operations",        # standalone Operations console
        "export_reports",    # report export (not wired to a route yet)
    }
)

TOOLS = frozenset(
    {
        # recon pipeline adapters — app/pipeline/adapters/*.py
        "subfinder",
        "assetfinder",
        "amass",
        "bbot",
        "dnsx",
        "httpx",
        "asnmap",
        "geoip",
        "wafw00f",
        "naabu",
        "nmap",
        "gowitness",
        "risk_prioritizer",
        # investigation / Operations console adapters
        "ffuf",
        "dirsearch",
        "nmap_deep",
        "testssl",
    }
)

FEATURES = SCOPES | TOOLS

_CACHE_TTL_SECONDS = 30
_cache: dict[tuple[UUID, str], tuple[float, bool]] = {}


def _cache_get(user_id: UUID, feature: str) -> bool | None:
    entry = _cache.get((user_id, feature))
    if entry is None:
        return None
    expires_at, value = entry
    if time.monotonic() > expires_at:
        _cache.pop((user_id, feature), None)
        return None
    return value


def _cache_set(user_id: UUID, feature: str, value: bool) -> None:
    _cache[(user_id, feature)] = (time.monotonic() + _CACHE_TTL_SECONDS, value)


def invalidate_user(user_id: UUID) -> None:
    for key in [k for k in _cache if k[0] == user_id]:
        _cache.pop(key, None)


async def is_enabled(db: AsyncSession, user_id: UUID, feature: str) -> bool:
    """Return True unless an explicit row sets enabled=false."""
    if feature not in FEATURES:
        # Unknown feature — fail closed so callers can't typo their way past gates.
        return False
    cached = _cache_get(user_id, feature)
    if cached is not None:
        return cached

    # Lazy import to avoid circular: models -> features.
    from app.models.auth import UserFeature

    row = await db.scalar(
        select(UserFeature).where(
            UserFeature.user_id == user_id, UserFeature.feature_name == feature
        )
    )
    value = True if row is None else row.enabled
    _cache_set(user_id, feature, value)
    return value


async def require(db: AsyncSession, user_id: UUID, *feature_names: str) -> None:
    """Raise 403 on the first disabled name. No-op for names outside FEATURES
    (callers that pass user-supplied strings, e.g. a `tool` field, must check
    membership themselves first — an unknown name here would otherwise 403
    with a misleading "restricted" message instead of the caller's own
    "unsupported tool" validation error)."""
    for name in feature_names:
        if name not in FEATURES:
            continue
        if not await is_enabled(db, user_id, name):
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                f"Access restricted: you don't have permission to use '{name}'.",
            )


async def list_enabled(db: AsyncSession, user_id: UUID) -> list[str]:
    """All features enabled for this user (used by /auth/me)."""
    from app.models.auth import UserFeature

    rows = await db.scalars(
        select(UserFeature).where(UserFeature.user_id == user_id, UserFeature.enabled.is_(False))
    )
    disabled = {r.feature_name for r in rows.all()}
    return sorted(f for f in FEATURES if f not in disabled)
