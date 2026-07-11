"""Pydantic v2 schemas for the standalone Operations Console API."""
from __future__ import annotations

from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, Field

from app.schemas.base import StrictRequest

TargetType = Literal["domain", "ipv4"]
Protocol = Literal["http", "https"]


class OperationPreviewRequest(StrictRequest):
    target_type: TargetType
    target: str
    tool: str
    profile: str | None = None
    protocol: Protocol | None = None
    custom_args: str | None = None


class OperationCreateRequest(OperationPreviewRequest):
    pass


class CommandPreviewResponse(BaseModel):
    generated_command: str


class OperationOut(BaseModel):
    id: UUID
    target: str
    target_type: str
    tool: str
    profile: str | None = None
    protocol: str | None = None
    custom_args: str | None = None
    generated_command: str | None = None
    status: str
    progress_pct: int
    duration_s: float | None = None
    raw_output_present: bool
    error: str | None = None
    created_at: datetime
    started_at: datetime | None = None
    completed_at: datetime | None = None


class OperationsResponse(BaseModel):
    rows: list[OperationOut]


class OperationFindingOut(BaseModel):
    id: UUID
    operation_id: UUID
    kind: str
    severity: str
    title: str
    description: str | None = None
    evidence: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime


class OperationDetailOut(BaseModel):
    operation: OperationOut
    findings: list[OperationFindingOut]
    raw_output: str | None = None
