from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field

from app.schemas.scan import StageOut


class VulnScanCreateRequest(BaseModel):
    parent_scan_id: UUID
    profile: str = Field(default="vuln_quick", pattern="^(vuln_quick|vuln_standard|vuln_deep)$")
    intrusive: bool = False


class VulnScanOut(BaseModel):
    id: UUID
    target_domain: str
    parent_scan_id: UUID | None
    profile: str
    status: str
    progress_pct: int
    intrusive: bool
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    error: str | None

    class Config:
        from_attributes = True


class VulnScanDetailOut(VulnScanOut):
    stages: list[StageOut]


class VulnOverview(BaseModel):
    total: int
    critical: int
    high: int
    med: int
    low: int
    info: int
    kev_count: int
    cve_count: int


class VulnOut(BaseModel):
    id: UUID
    canonical_key: str
    title: str
    severity: str
    cvss_v3: float | None
    cve_ids: list[str]
    cwe_ids: list[str]
    status: str
    asset_id: UUID
    asset_label: str
    template_id: str | None
    kev: bool
    first_seen: datetime
    last_seen: datetime

    class Config:
        from_attributes = True


class VulnsPage(BaseModel):
    total: int
    items: list[VulnOut]


class VulnStatusUpdateRequest(BaseModel):
    status: str = Field(
        pattern="^(triaged|false_positive|fixed|wont_fix|open|reopened)$"
    )
