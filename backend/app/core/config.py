from functools import lru_cache

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str = Field(
        default="postgresql+asyncpg://recon:recon@postgres:5432/recon"
    )
    redis_url: str = Field(default="redis://redis:6379/0")

    # RS256 access + opaque rotating refresh.
    jwt_private_key_path: str = Field(default="/secrets/jwt/private.pem")
    jwt_public_key_path: str = Field(default="/secrets/jwt/public.pem")
    jwt_issuer: str = "redteam-dashboard"
    jwt_audience: str = "redteam-dashboard-web"
    jwt_access_expire_minutes: int = 10
    jwt_refresh_expire_days: int = 14

    # Cookie config — secure must be true in prod, off for local http://localhost.
    # Defaults secure (fail-safe): local dev's docker-compose.yml explicitly
    # sets COOKIE_SECURE=false, so this only changes behavior for a
    # deployment that forgets to set it at all.
    cookie_secure: bool = True
    cookie_domain: str = ""  # empty → host-only (correct for localhost)

    # Admin bootstrap (run on backend startup if no admin exists).
    # No hardcoded credential defaults: if ADMIN_EMAIL is unset, bootstrap is
    # skipped (see main._ensure_bootstrap_admin); if ADMIN_PASSWORD is unset,
    # a random one is generated and logged once at boot rather than falling
    # back to a known password.
    admin_email: str = ""
    admin_password: str = ""

    # Super-admin: cannot be disabled, demoted, or deleted by other admins.
    # Falls back to admin_email (below) when unset — see _resolve_super_admin.
    super_admin_email: str = ""

    # Singleton org under which every user lives now that org signup is gone.
    default_org_name: str = "Default Organization"
    default_project_name: str = "default"

    # Invite tokens — copy-link delivery, single-use, short TTL.
    invite_ttl_hours: int = 24

    cors_origins: list[str] = Field(default=["http://localhost:3000"])
    cors_origin_regex: str = Field(
        default=r"^http://(localhost|127\.0\.0\.1)(:\d+)?$"
    )
    minio_url: str = ""
    minio_access_key: str = "minioadmin"
    minio_secret_key: str = "minioadmin"
    minio_bucket: str = "recon"
    openrouter_api_key: str = ""          # required for deep scans; set via OPENROUTER_API_KEY env
    bbot_timeout: int = 1800

    # audit_logs rows (and their actor_ip PII) older than this are purged by
    # the nightly retention cron — see workers/runner.py::purge_audit_logs_job.
    audit_retention_days: int = 180

    @model_validator(mode="after")
    def _resolve_super_admin(self) -> "Settings":
        if not self.super_admin_email:
            self.super_admin_email = self.admin_email
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
