from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field

from app.models.scan import ScanStatus, StageStatus


class ScanCreateRequest(BaseModel):
    domain: str = Field(min_length=3, max_length=255)
    profile: str = Field(default="quick", pattern="^(quick|standard|deep)$")
    autostart: bool = True  # False → create as queued, no immediate enqueue


class ScanUpdateRequest(BaseModel):
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
    target_authz_verified: bool = False  # True when target.authorization_verified_at is not None

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
