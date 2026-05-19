"""Pydantic schemas for Target API endpoints (M2)."""
from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel


class TargetOut(BaseModel):
    id: UUID
    domain: str
    kind: str
    monitoring_enabled: bool
    authorization_token: str | None = None
    authorization_verified_at: datetime | None = None
    authorization_proof: str | None = None
    is_verified: bool = False
    verified_by: UUID | None = None
    verified_at: datetime | None = None
    created_at: datetime

    model_config = {"from_attributes": True}


class VerifiedTargetCreateRequest(BaseModel):
    domain: str


class VerifiedTargetOut(BaseModel):
    id: UUID
    domain: str
    is_verified: bool
    verified_by: UUID | None
    verified_by_email: str | None = None
    verified_at: datetime | None
    created_at: datetime

    model_config = {"from_attributes": True}


class GenerateTokenResponse(BaseModel):
    token: str
    dns_txt_record: str
    http_file_path: str
    instructions: str


class VerifyRequest(BaseModel):
    method: str  # "dns_txt" or "http_file"
