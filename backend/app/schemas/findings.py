"""Response schemas for GET /scans/{id}/findings."""
from __future__ import annotations

from uuid import UUID

from pydantic import BaseModel


class FindingRow(BaseModel):
    finding_id: UUID
    asset_id: UUID | None
    fqdn: str
    severity: str           # HIGH | MED | LOW | INFO
    priority_rank: int      # 1 = highest risk
    risk_score: float       # 0.0–1.0
    rationale: str
    signals: list[str]
    recommended_action: str
    source: str             # "llm" | "fallback"


class FindingsPage(BaseModel):
    total: int
    items: list[FindingRow]
