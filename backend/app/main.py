import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import select

from app.api import (
    auth,
    scans,
    sessions as sessions_api,
    settings as settings_api,
    target_workspaces,
    targets,
    users as users_api,
    vuln_scans,
    vulns,
)
from app.api.admin import audit as admin_audit
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
    allow_origin_regex=settings.cors_origin_regex,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*", "X-CSRF-Token"],
    expose_headers=["*"],
)

app.include_router(auth.router)
app.include_router(users_api.router)
app.include_router(sessions_api.router)
app.include_router(settings_api.router)
app.include_router(admin_audit.router)
app.include_router(scans.router)
app.include_router(targets.router)
app.include_router(vuln_scans.router)
app.include_router(vulns.router)
app.include_router(target_workspaces.router)


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
    """If no admin user exists, create one from ADMIN_EMAIL/ADMIN_PASSWORD env."""
    async with SessionLocal() as db:
        existing = await db.scalar(select(User).where(User.role == UserRole.admin))
        if existing is not None:
            return
        org = await _ensure_default_org()
        admin = User(
            org_id=org.id,
            email=settings.admin_email,
            password_hash=hash_password(settings.admin_password),
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
