import re
from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field, field_validator

from app.models.scan import ScanStatus, StageStatus
from app.schemas.base import StrictRequest

_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
)


class ScanCreateRequest(StrictRequest):
    # Format-only check here; reachability (loopback, metadata, this
    # platform's own services) is checked server-side in create_scan via
    # app.services.net_guard, which needs a DNS resolution a Pydantic
    # validator shouldn't perform.
    domain: str = Field(min_length=3, max_length=255)
    profile: str = Field(default="quick", pattern="^(quick|standard|deep)$")
    autostart: bool = True  # False → create as queued, no immediate enqueue

    @field_validator("domain")
    @classmethod
    def _normalize_and_validate_domain(cls, v: str) -> str:
        normalized = v.strip().lower()
        if not _DOMAIN_RE.match(normalized):
            raise ValueError("invalid domain")
        return normalized


class ScanUpdateRequest(StrictRequest):
    profile: str = Field(pattern="^(quick|standard|deep)$")


class StageOut(BaseModel):
    id: UUID
    stage_name: str
    status: StageStatus
    started_at: datetime | None
    finished_at: datetime | None
    error: str | None

    class Config:
        from_attributes = True


class ScanOut(BaseModel):
    id: UUID
    domain: str
    profile: str
    status: ScanStatus
    progress_pct: int
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    error: str | None

    class Config:
        from_attributes = True


class ScanDetailOut(ScanOut):
    stages: list[StageOut]


class AssetOut(BaseModel):
    id: UUID
    type: str
    canonical_key: str
    attributes: dict
    first_seen: datetime
    last_seen: datetime

    class Config:
        from_attributes = True
