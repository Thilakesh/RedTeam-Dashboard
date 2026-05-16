"""Investigation adapter contract.

Per-asset, per-tool runs. Each adapter wraps one binary (or one HTTP probe),
executes it against a single asset, and returns a normalized result that the
worker hands to the appropriate upsert services.

Adapters NEVER touch the DB directly — same boundary rule as recon/vuln stages.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol
from uuid import UUID


@dataclass
class TaskContext:
    task_id: UUID
    workspace_id: UUID
    target_id: UUID
    target_domain: str
    asset_id: UUID
    asset_canonical_key: str
    asset_type: str
    params: dict


@dataclass
class FindingRecord:
    kind: str
    severity: str  # 'critical' | 'high' | 'med' | 'low' | 'info'
    title: str
    description: str | None = None
    evidence: dict = field(default_factory=dict)


@dataclass
class ServiceUpdateRecord:
    """Optional service enrichment emitted by nmap_deep."""
    host: str
    port: int
    proto: str
    service_name: str | None = None
    product: str | None = None
    version: str | None = None
    banner: str | None = None
    cpes: list[str] = field(default_factory=list)


@dataclass
class EndpointRecord:
    """Endpoint emitted by ffuf / dirsearch."""
    url: str
    path: str
    method: str = "GET"
    status_code: int | None = None
    content_type: str | None = None
    content_length: int | None = None
    title: str | None = None


@dataclass
class TlsObservationRecord:
    """TLS posture emitted by testssl."""
    host: str
    port: int
    cert_subject: str | None = None
    cert_issuer: str | None = None
    cert_not_before: str | None = None  # ISO string; worker parses
    cert_not_after: str | None = None
    cert_san: list[str] = field(default_factory=list)
    protocols: dict = field(default_factory=dict)
    weak_ciphers: list[str] = field(default_factory=list)
    grade: str | None = None


@dataclass
class InvestigationResult:
    findings: list[FindingRecord] = field(default_factory=list)
    services: list[ServiceUpdateRecord] = field(default_factory=list)
    endpoints: list[EndpointRecord] = field(default_factory=list)
    tls_observations: list[TlsObservationRecord] = field(default_factory=list)
    raw_output: str = ""


class InvestigationAdapter(Protocol):
    tool: str

    async def execute(self, ctx: TaskContext) -> InvestigationResult: ...
