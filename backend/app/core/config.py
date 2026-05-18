from functools import lru_cache

from pydantic import Field
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
    cookie_secure: bool = False
    cookie_domain: str = ""  # empty → host-only (correct for localhost)

    # Admin bootstrap (run on backend startup if no admin exists).
    admin_email: str = "alpha@gmail.com"
    admin_password: str = "Testing123@"

    # Singleton org under which every user lives now that org signup is gone.
    default_org_name: str = "Default Organization"
    default_project_name: str = "default"

    # Invite tokens — copy-link delivery, single-use, short TTL.
    invite_ttl_hours: int = 24

    # Rate limiting (Redis-backed counters).
    rl_login_per_15min: int = 5
    rl_refresh_per_min: int = 10

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


@lru_cache
def get_settings() -> Settings:
    return Settings()
