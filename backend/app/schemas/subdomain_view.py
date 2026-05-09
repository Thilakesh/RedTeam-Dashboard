"""Read-side schemas for the M1.5 Subdomains tab and its sibling tabs.

These pydantic models are the stable contract the frontend reads against.
The shape is denormalized — one row per subdomain, every column from the
mockup populated in a single payload — even though the underlying data
lives across `subdomain` and `ipv4` Asset rows + their observations.
"""
from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel


class SubdomainRow(BaseModel):
    asset_id: UUID
    subdomain: str
    http_status: int | None = None
    title: str | None = None
    redirect: bool = False
    final_url: str | None = None
    location: str | None = None
    ip_tag: str | None = None  # "Direct IP" / "CDN IP" / "Cloudflare IP"
    primary_ip: str | None = None
    all_ips: list[str] = []
    cdn: bool = False
    cdn_name: str | None = None
    cname: str | None = None
    cnames: list[str] = []
    waf: str | None = None
    waf_conf: str | None = None  # NONE / LOW / MED / HIGH
    asn: str | None = None
    org: str | None = None
    country: str | None = None
    country_name: str | None = None
    city: str | None = None
    server: str | None = None
    tech: list[str] = []
    open_ports: list[str] = []       # e.g. ["80/tcp", "443/tcp"]
    sources: list[str] = []          # tools that discovered this subdomain, e.g. ["subfinder", "shodan"]
    screenshot_url: str | None = None
    url: str | None = None
    first_seen: datetime
    last_seen: datetime


class SubdomainsPage(BaseModel):
    rows: list[SubdomainRow]
    total: int
    page: int
    limit: int


class IpRow(BaseModel):
    asset_id: UUID
    ip: str
    subdomain_count: int
    asn: str | None = None
    org: str | None = None
    country: str | None = None
    city: str | None = None
    resolves: list[str] = []


class CountBucket(BaseModel):
    label: str
    count: int


class TechBucket(BaseModel):
    label: str
    count: int
    subdomains: list[str] = []


class ScanOverview(BaseModel):
    subdomain_count: int
    ip_count: int
    cdn_count: int
    waf_count: int
    tech_count: int
    http_status_buckets: list[CountBucket]
    top_tech: list[CountBucket]
    top_asn: list[CountBucket]
    top_cdn: list[CountBucket]


class CdnWafSummary(BaseModel):
    behind_cdn_pct: float
    behind_waf_pct: float
    cdn_breakdown: list[CountBucket]
    waf_breakdown: list[CountBucket]
    unprotected_origins: list[str]  # subdomains with no CDN AND no WAF


class PortRow(BaseModel):
    asset_id: UUID
    host: str
    port: int
    proto: str
    state: str
    service_name: str | None = None
    product: str | None = None
    version: str | None = None


class PortsPage(BaseModel):
    rows: list[PortRow]
    total: int
    page: int
    limit: int
