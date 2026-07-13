import logging
import secrets

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import select

from app.api import (
    auth,
    dashboard as dashboard_api,
    operations as operations_api,
    scans,
    sessions as sessions_api,
    settings as settings_api,
    target_workspaces,
    targets,
    users as users_api,
)
from app.api.admin import audit as admin_audit
from app.api.admin import settings as admin_settings
from app.api.middleware.csrf import CSRFMiddleware
from app.core.config import get_settings
from app.core.db import SessionLocal
from app.core.keys import ensure_keypair
from app.core.security import hash_password
from app.models import Organization, Project, User, UserRole

settings = get_settings()
log = logging.getLogger("uvicorn.error")

app = FastAPI(title="Red Team Recon Dashboard", version="0.1.0")

app.add_middleware(CSRFMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    # An empty string here must mean "no regex" (None) — Starlette compiles
    # allow_origin_regex with re.compile() and an empty pattern matches every
    # origin, which is the opposite of disabling it. Setting
    # CORS_ORIGIN_REGEX="" in prod is how the localhost-dev default gets
    # turned off without touching allow_origins.
    allow_origin_regex=settings.cors_origin_regex or None,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*", "X-CSRF-Token"],
    expose_headers=["*"],
)

app.include_router(auth.router)
app.include_router(dashboard_api.router)
app.include_router(users_api.router)
app.include_router(sessions_api.router)
app.include_router(settings_api.router)
app.include_router(admin_audit.router)
app.include_router(admin_settings.router)
app.include_router(scans.router)
app.include_router(targets.router)
app.include_router(target_workspaces.router)
app.include_router(operations_api.router)


@app.get("/health")
async def health() -> dict:
    return {"status": "ok"}


async def _ensure_default_org() -> Organization:
    """Singleton Default Organization; created if absent."""
    async with SessionLocal() as db:
        org = await db.scalar(select(Organization).where(Organization.name == settings.default_org_name))
        if org is not None:
            return org
        org = Organization(name=settings.default_org_name)
        db.add(org)
        await db.flush()
        db.add(Project(org_id=org.id, name=settings.default_project_name))
        await db.commit()
        await db.refresh(org)
        log.info("bootstrap: created default org %s", org.id)
        return org


async def _ensure_bootstrap_admin() -> None:
    """If no admin user exists, create one from ADMIN_EMAIL/ADMIN_PASSWORD env.

    Never falls back to a known/hardcoded credential (config.py defaults are
    blank). If ADMIN_EMAIL is unset, bootstrap is skipped — the operator must
    set it and restart. If ADMIN_PASSWORD is unset, a random one is generated
    and logged once at boot; it is never stored anywhere else, so this is the
    only place to recover it.
    """
    async with SessionLocal() as db:
        existing = await db.scalar(select(User).where(User.role == UserRole.admin))
        if existing is not None:
            return
        if not settings.admin_email:
            log.warning(
                "bootstrap: ADMIN_EMAIL is not set — skipping admin creation. "
                "Set ADMIN_EMAIL (and optionally ADMIN_PASSWORD) and restart."
            )
            return
        org = await _ensure_default_org()
        password = settings.admin_password
        if not password:
            password = secrets.token_urlsafe(18)
            log.warning(
                "bootstrap: ADMIN_PASSWORD is not set — generated a random "
                "password for %s (shown once, not stored anywhere else): %s",
                settings.admin_email,
                password,
            )
        admin = User(
            org_id=org.id,
            email=settings.admin_email,
            password_hash=hash_password(password),
            role=UserRole.admin,
            is_active=True,
        )
        db.add(admin)
        await db.commit()
        log.info("bootstrap: created admin %s", settings.admin_email)


@app.on_event("startup")
async def _startup() -> None:
    ensure_keypair()
    await _ensure_bootstrap_admin()
