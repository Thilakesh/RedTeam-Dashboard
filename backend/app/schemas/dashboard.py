"""Pydantic v2 schemas for the Dashboard overview endpoint."""
from __future__ import annotations

from datetime import date, datetime
from uuid import UUID

from pydantic import BaseModel


class ScanActivityDay(BaseModel):
    day: date
    completed: int


class RecentScanRow(BaseModel):
    id: UUID
    domain: str
    profile: str
    status: str
    progress_pct: int
    created_at: datetime


class TopFindingRow(BaseModel):
    scan_id: UUID
    fqdn: str
    severity: str
    risk_score: float
    rationale: str


class DashboardSummary(BaseModel):
    active_scans: int
    assets_tracked: int
    open_findings: int
    workspaces: int
    severity_counts: dict[str, int]
    scan_activity: list[ScanActivityDay]
    recent_scans: list[RecentScanRow]
    top_findings: list[TopFindingRow]
