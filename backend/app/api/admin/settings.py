"""Admin-only system settings persisted in the DB (OpenRouter config).

The raw API key is never returned or logged — responses expose only whether a
key is set plus a last-4 hint.
"""
from __future__ import annotations

import httpx
from fastapi import APIRouter, Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import CurrentUser, require_admin
from app.core.db import get_db
from app.schemas.admin import (
    OpenRouterSettingsOut,
    OpenRouterSettingsUpdateRequest,
    OpenRouterTestRequest,
    OpenRouterTestResponse,
)
from app.services import audit
from app.services import system_settings as ss

router = APIRouter(
    prefix="/admin/settings",
    tags=["admin"],
    dependencies=[Depends(require_admin())],
)

_MODELS_URL = "https://openrouter.ai/api/v1/models"


def _hint(key: str | None) -> str | None:
    if not key:
        return None
    return "…" + key[-4:] if len(key) >= 4 else "…"


async def _openrouter_out(db: AsyncSession) -> OpenRouterSettingsOut:
    key = await ss.get_setting(db, ss.KEY_OPENROUTER_API_KEY)
    model = await ss.get_setting(db, ss.KEY_OPENROUTER_MODEL) or ss.DEFAULT_MODEL
    return OpenRouterSettingsOut(
        api_key_set=bool(key),
        api_key_hint=_hint(key),
        default_model=model,
    )


@router.get("/openrouter", response_model=OpenRouterSettingsOut)
async def get_openrouter_settings(
    db: AsyncSession = Depends(get_db),
) -> OpenRouterSettingsOut:
    return await _openrouter_out(db)


@router.post("/openrouter", response_model=OpenRouterSettingsOut)
async def update_openrouter_settings(
    req: OpenRouterSettingsUpdateRequest,
    request: Request,
    actor: CurrentUser = Depends(require_admin()),
    db: AsyncSession = Depends(get_db),
) -> OpenRouterSettingsOut:
    meta: dict[str, str] = {}
    key_changed = req.api_key is not None and req.api_key.strip() != ""
    if key_changed:
        await ss.set_setting(db, ss.KEY_OPENROUTER_API_KEY, req.api_key.strip())
        meta["api_key"] = "changed"  # never store the value
    if req.default_model is not None and req.default_model.strip():
        await ss.set_setting(db, ss.KEY_OPENROUTER_MODEL, req.default_model.strip())
        meta["default_model"] = req.default_model.strip()

    if meta:
        # commit=True flushes the set_setting writes in this session too.
        await audit.log(
            db,
            actor_user_id=actor.id,
            action="system.openrouter_updated",
            meta=meta,
            request=request,
        )
    return await _openrouter_out(db)


@router.post("/openrouter/test", response_model=OpenRouterTestResponse)
async def test_openrouter_connection(
    req: OpenRouterTestRequest,
    db: AsyncSession = Depends(get_db),
) -> OpenRouterTestResponse:
    # Use the typed key if supplied (testing before save), else the stored/env key.
    key = (req.api_key or "").strip()
    if not key:
        key = await ss.get_setting(db, ss.KEY_OPENROUTER_API_KEY) or ""
    if not key:
        from app.core.config import get_settings

        key = get_settings().openrouter_api_key or ""
    if not key:
        return OpenRouterTestResponse(
            status="invalid_key", detail="No API key configured."
        )

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(
                _MODELS_URL, headers={"Authorization": f"Bearer {key}"}
            )
    except httpx.HTTPError:
        return OpenRouterTestResponse(
            status="connection_failed", detail="Could not reach OpenRouter."
        )

    if resp.status_code == 200:
        return OpenRouterTestResponse(status="connected")
    if resp.status_code in (401, 403):
        return OpenRouterTestResponse(status="invalid_key", detail="Key rejected.")
    return OpenRouterTestResponse(
        status="connection_failed", detail=f"OpenRouter returned {resp.status_code}."
    )
