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
    # M-Vuln-8 additions
    hvt_count: int = 0
    public_service_count: int = 0
    top_risk_vulns: list[dict] = []


class VulnOut(BaseModel):
    id: UUID
    canonical_key: str
    title: str
    severity: str
    cvss_v3: float | None
    epss: float | None = None       # M-Vuln-8: added
    risk_score: float | None = None  # M-Vuln-8: added
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


class VulnDiffOut(BaseModel):
    counts: dict
    new: list[VulnOut]
    seen: list[VulnOut]
    fixed: list[VulnOut]
    has_prior: bool


# ── M-Vuln-8: By Service ──────────────────────────────────────────────────────

class ByServiceRow(BaseModel):
    service_id: UUID | None
    service_key: str          # host:port/proto  or "No service"
    host: str | None
    port: int | None
    classification: str
    product: str | None
    version: str | None
    vuln_count: int
    severities: dict          # {"CRITICAL": 1, "HIGH": 3, ...}
    max_risk_score: float | None


class ByServiceResponse(BaseModel):
    rows: list[ByServiceRow]


# ── M-Vuln-8: By Technology ───────────────────────────────────────────────────

class ByTechRow(BaseModel):
    technology_id: UUID | None
    name: str
    version: str | None
    cpe: str | None
    category: str | None
    vuln_count: int
    severities: dict
    max_risk_score: float | None


class ByTechResponse(BaseModel):
    rows: list[ByTechRow]


# ── M-Vuln-8: Endpoints ───────────────────────────────────────────────────────

class EndpointRow(BaseModel):
    id: UUID
    url: str
    path: str
    method: str
    status_code: int | None
    content_type: str | None
    title: str | None
    is_login: bool
    is_signup: bool
    is_upload: bool
    is_api: bool
    is_admin: bool
    source_tool: str
    first_seen: datetime
    last_seen: datetime


class EndpointsPage(BaseModel):
    total: int
    items: list[EndpointRow]


class EndpointDetail(EndpointRow):
    """Same shape as EndpointRow — returned by the endpoint-detail page."""
    pass


# ── M-Vuln-8: TLS ─────────────────────────────────────────────────────────────

class TlsRow(BaseModel):
    service_id: UUID
    service_key: str            # host:port
    cert_subject: str | None
    cert_issuer: str | None
    cert_not_after: datetime | None
    days_until_expiry: int | None   # None if cert_not_after missing; negative = expired
    is_expired: bool
    grade: str | None
    weak_ciphers: list[str]
    deprecated_protocols: list[str]  # TLSv1.0, TLSv1.1 when enabled
    observed_at: datetime


class TlsResponse(BaseModel):
    rows: list[TlsRow]


# ── M-Vuln-8: HVTs ────────────────────────────────────────────────────────────

class HvtSignalItem(BaseModel):
    signal_type: str
    score: float
    confidence: int
    evidence: dict


class HvtRow(BaseModel):
    asset_id: UUID
    asset_label: str
    hvt_score: float
    signals: list[HvtSignalItem]


class HvtResponse(BaseModel):
    rows: list[HvtRow]


# ── M-Vuln-8: Triage ──────────────────────────────────────────────────────────

class TriageVulnRow(BaseModel):
    id: UUID
    title: str
    severity: str
    risk_score: float | None
    cvss_v3: float | None
    epss: float | None
    kev: bool
    cve_ids: list[str]
    asset_label: str
    description: str
    remediation: str | None


class TriageResponse(BaseModel):
    rows: list[TriageVulnRow]
    total_with_risk_score: int    # how many vulns in this scan have risk_score set


# ── M-Vuln-8: Target Risk Rollup ─────────────────────────────────────────────

class TargetRiskVulnRow(BaseModel):
    id: UUID
    title: str
    severity: str
    risk_score: float | None
    kev: bool
    asset_label: str
    status: str


class TargetRiskView(BaseModel):
    target_id: UUID
    target_domain: str
    open_counts: dict             # {"critical": N, "high": N, ...}
    top_risk_vulns: list[TargetRiskVulnRow]
    hvt_count: int
    hvt_signal_summary: dict      # {"admin_panel": 3, "git_repo": 1, ...}
    endpoint_count: int
    latest_vuln_scan_id: UUID | None
    latest_vuln_scan_status: str | None
    latest_vuln_scan_created_at: datetime | None
