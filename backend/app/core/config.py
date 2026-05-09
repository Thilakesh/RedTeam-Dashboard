from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str = Field(
        default="postgresql+asyncpg://recon:recon@postgres:5432/recon"
    )
    redis_url: str = Field(default="redis://redis:6379/0")
    jwt_secret: str = Field(default="dev-secret-change-me")
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 60 * 24
    cors_origins: list[str] = Field(default=["http://localhost:3000"])
    cors_origin_regex: str = Field(
        default=r"^http://(localhost|127\.0\.0\.1)(:\d+)?$"
    )
    minio_url: str = ""
    minio_access_key: str = "minioadmin"
    minio_secret_key: str = "minioadmin"
    minio_bucket: str = "recon"
    openrouter_api_key: str = ""          # required for deep scans; set via OPENROUTER_API_KEY env
    censys_api_id: str = ""
    censys_api_secret: str = ""
    shodan_api_key: str = ""
    bbot_timeout: int = 1800


@lru_cache
def get_settings() -> Settings:
    return Settings()
