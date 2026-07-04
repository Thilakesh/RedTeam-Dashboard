"""Durable system settings (key-value) + OpenRouter config resolution.

Generic get/set by key over the `system_settings` table. OpenRouter config is
resolved DB-first with env / default fallback so a saved admin config drives the
live AI pipeline without a restart.
"""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.models import SystemSetting

KEY_OPENROUTER_API_KEY = "openrouter_api_key"
KEY_OPENROUTER_MODEL = "openrouter_default_model"

DEFAULT_MODEL = "openai/gpt-oss-20b:free"
PRESET_MODELS = [
    "openai/gpt-4o",
    "anthropic/claude-3.7-sonnet",
    "google/gemini-2.5-pro",
]


async def get_setting(db: AsyncSession, key: str) -> str | None:
    return await db.scalar(select(SystemSetting.value).where(SystemSetting.key == key))


async def set_setting(db: AsyncSession, key: str, value: str) -> None:
    """Upsert a setting by key. Caller commits."""
    row = await db.scalar(select(SystemSetting).where(SystemSetting.key == key))
    if row is None:
        db.add(SystemSetting(key=key, value=value))
    else:
        row.value = value
        row.updated_at = datetime.now(timezone.utc)


async def get_openrouter_config(db: AsyncSession) -> tuple[str | None, str]:
    """(api_key, model). DB value first, else env key / default model."""
    api_key = await get_setting(db, KEY_OPENROUTER_API_KEY)
    if not api_key:
        api_key = get_settings().openrouter_api_key or None
    model = await get_setting(db, KEY_OPENROUTER_MODEL)
    if not model:
        model = DEFAULT_MODEL
    return api_key, model
