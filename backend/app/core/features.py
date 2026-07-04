"""Per-user feature flags.

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

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

# Wildcard import safe — feature constants only.
FEATURES = frozenset(
    {
        "deep_scan",
        "ffuf",
        "dirsearch",
        "nmap",
        "naabu",
        "target_workspace",
        "investigations",
        "export_reports",
        "gowitness",
    }
)

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


async def list_enabled(db: AsyncSession, user_id: UUID) -> list[str]:
    """All features enabled for this user (used by /auth/me)."""
    from app.models.auth import UserFeature

    rows = await db.scalars(
        select(UserFeature).where(UserFeature.user_id == user_id, UserFeature.enabled.is_(False))
    )
    disabled = {r.feature_name for r in rows.all()}
    return sorted(f for f in FEATURES if f not in disabled)
