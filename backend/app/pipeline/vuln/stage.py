from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol
from uuid import UUID


@dataclass
class VulnEvidenceRecord:
    source_tool: str
    request: str | None = None
    response_excerpt: str | None = None
    matcher_name: str | None = None
    extracted: dict = field(default_factory=dict)
    confidence: int = 80


@dataclass
class VulnRecord:
    asset_id: UUID
    canonical_key: str   # dedup identity: e.g. "nuclei:{template}:{asset_id}:{url}"
    title: str
    severity: str        # "CRITICAL"|"HIGH"|"MED"|"LOW"|"INFO"
    description: str
    evidence: VulnEvidenceRecord
    service_id: UUID | None = None
    technology_id: UUID | None = None
    template_id: str | None = None
    cve_ids: list[str] = field(default_factory=list)
    cwe_ids: list[str] = field(default_factory=list)
    cvss_v3: float | None = None
    remediation: str | None = None


@dataclass
class VulnStageContext:
    scan_id: UUID
    target_id: UUID
    parent_scan_id: UUID
    domain: str
    intrusive: bool
    # Pre-loaded frozen views from recon — READ ONLY
    services: list  # list[Service] - avoid circular import, type as list
    technologies: list  # list[Technology]
    http_services: list  # list[Asset] (type=http_service)
    # Convenience lookups
    service_by_id: dict   # UUID -> Service
    tech_by_asset_id: dict  # UUID -> list[Technology]
    http_service_urls: list[str]  # canonical_key (URLs) from http_services
    # M-Vuln-5: pre-loaded endpoint + HVT views from prior vuln scans
    endpoints: list = None              # list[Endpoint]
    hvt_signals: list = None            # list[HvtSignal]
    endpoints_by_asset: dict = None     # UUID -> list[Endpoint]
    hvt_signals_by_asset: dict = None   # UUID -> list[HvtSignal]

    def __post_init__(self) -> None:
        # Normalize None → empty so adapters can iterate without guards.
        if self.endpoints is None:
            self.endpoints = []
        if self.hvt_signals is None:
            self.hvt_signals = []
        if self.endpoints_by_asset is None:
            self.endpoints_by_asset = {}
        if self.hvt_signals_by_asset is None:
            self.hvt_signals_by_asset = {}


class VulnStage(Protocol):
    name: str
    source_tool: str
    depends_on: list[str]
    weight: int
    optional: bool
    intrusive_required: bool  # if True, skip when ctx.intrusive=False
    required_signals: list[str]

    async def execute_vuln(self, ctx: VulnStageContext) -> list[VulnRecord]: ...
    # Optional: def applies(self, ctx: VulnStageContext) -> bool: ...
