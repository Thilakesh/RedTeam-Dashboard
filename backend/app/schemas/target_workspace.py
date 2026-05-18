"""Pydantic v2 schemas for Target Workspace API."""
from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field


class WorkspaceCreateRequest(BaseModel):
    parent_scan_id: UUID


class WorkspaceOut(BaseModel):
    id: UUID
    label: str
    target_id: UUID
    target_domain: str
    parent_scan_id: UUID | None
    status: str
    created_at: datetime


class WorkspaceListRow(BaseModel):
    id: UUID
    label: str
    target_id: UUID
    target_domain: str
    parent_scan_id: UUID | None
    asset_count: int
    task_count: int
    status: str
    created_at: datetime


class WorkspaceOverview(BaseModel):
    total_subdomains: int
    alive_hosts: int
    ports_identified: int
    running_tasks: int
    findings_count: int
    hvt_count: int
    hvt_signal_summary: dict[str, int] = Field(default_factory=dict)


class WorkspaceScanEntry(BaseModel):
    task_id: UUID
    tool: str
    status: str
    created_at: datetime
    started_at: datetime | None = None
    finished_at: datetime | None = None
    duration_s: float | None = None


class WorkspaceSubdomainIpRow(BaseModel):
    asset_id: UUID
    ip: str
    scans: list[WorkspaceScanEntry] = Field(default_factory=list)


class WorkspaceSubdomainRow(BaseModel):
    asset_id: UUID
    fqdn: str
    alive: bool
    ports: list[int] = Field(default_factory=list)
    technologies: list[str] = Field(default_factory=list)
    has_http: bool
    has_https: bool
    available_tools: list[str] = Field(default_factory=list)
    tools_run: list[str] = Field(default_factory=list)
    hvt_signals: list[str] = Field(default_factory=list)
    ips: list[WorkspaceSubdomainIpRow] = Field(default_factory=list)
    scans: list[WorkspaceScanEntry] = Field(default_factory=list)


class WorkspaceSubdomainsResponse(BaseModel):
    rows: list[WorkspaceSubdomainRow]


class InvestigationTaskCreateRequest(BaseModel):
    asset_id: UUID
    tool: str
    params: dict[str, Any] = Field(default_factory=dict)


class InvestigationTaskOut(BaseModel):
    id: UUID
    workspace_id: UUID
    asset_id: UUID
    asset_label: str
    tool: str
    status: str
    progress_pct: int
    duration_s: float | None = None
    raw_output_present: bool
    error: str | None = None
    created_at: datetime
    started_at: datetime | None = None
    finished_at: datetime | None = None


class InvestigationTasksResponse(BaseModel):
    rows: list[InvestigationTaskOut]


class InvestigationFindingOut(BaseModel):
    id: UUID
    task_id: UUID
    asset_id: UUID
    kind: str
    severity: str
    title: str
    description: str | None = None
    evidence: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime


class InvestigationTaskDetailOut(BaseModel):
    task: InvestigationTaskOut
    findings: list[InvestigationFindingOut]
    raw_output: str | None = None
