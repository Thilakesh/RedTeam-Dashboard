"""Pydantic schemas for Target API endpoints."""
from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel


class TargetOut(BaseModel):
    id: UUID
    domain: str
    kind: str
    monitoring_enabled: bool
    created_at: datetime

    model_config = {"from_attributes": True}
