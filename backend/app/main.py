from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api import auth, scans, target_workspaces, targets, vuln_scans, vulns
from app.core.config import get_settings

settings = get_settings()
app = FastAPI(title="Red Team Recon Dashboard", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_origin_regex=settings.cors_origin_regex,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"],
)

app.include_router(auth.router)
app.include_router(scans.router)
app.include_router(targets.router)
app.include_router(vuln_scans.router)
app.include_router(vulns.router)
app.include_router(target_workspaces.router)


@app.get("/health")
async def health() -> dict:
    return {"status": "ok"}
