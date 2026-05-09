"""Aggregation that produces the M1.5 denormalized read models.

Each subdomain row is built from observations across multiple source_tools and
joined to its primary IP's enrichment (asnmap + geoip). We do this in Python
because the join shape is irregular and the result-set is small (thousands of
rows max per scan). If this ever becomes a hot path, materialize a view.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Any
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Asset, AssetObservation
from app.models.finding import Finding
from app.models.service import Service
from app.models.technology import Technology
from app.services import storage
from app.schemas.findings import FindingRow
from app.schemas.subdomain_view import (
    CdnWafSummary,
    CountBucket,
    IpRow,
    PortRow,
    PortsPage,
    ScanOverview,
    SubdomainRow,
    TechBucket,
)


# Tool → which payload keys it contributes. Documenting it here keeps the
# adapters as the source of truth for *what* and the join as the source for *where*.
_HOST_TOOLS = {"subfinder", "assetfinder", "dnsx", "httpx", "wafw00f"}
_IP_TOOLS = {"asnmap", "geoip", "dnsx"}
_SERVICE_TOOLS = {"naabu", "nmap"}
_SCREENSHOT_TOOLS = {"gowitness"}


async def _load_observations_for_scan(
    db: AsyncSession, scan_id: UUID, asset_type: str
) -> dict[UUID, dict[str, dict]]:
    """Return {asset_id: {source_tool: merged_payload}} for the given scan + type."""
    rows = (
        await db.execute(
            select(Asset.id, AssetObservation.source_tool, AssetObservation.payload)
            .join(AssetObservation, AssetObservation.asset_id == Asset.id)
            .where(AssetObservation.scan_id == scan_id, Asset.type == asset_type)
        )
    ).all()
    by_asset: dict[UUID, dict[str, dict]] = defaultdict(dict)
    for asset_id, source_tool, payload in rows:
        if source_tool not in by_asset[asset_id]:
            by_asset[asset_id][source_tool] = {}
        # Multiple observations from the same source merge — last wins on key conflict.
        # This handles wafw00f re-runs etc; for now a single observation is the norm.
        by_asset[asset_id][source_tool].update(payload or {})
    return by_asset


async def _load_assets(
    db: AsyncSession, scan_id: UUID, asset_type: str
) -> list[Asset]:
    """Distinct assets of a type observed in this scan."""
    rows = (
        await db.execute(
            select(Asset)
            .join(AssetObservation, AssetObservation.asset_id == Asset.id)
            .where(AssetObservation.scan_id == scan_id, Asset.type == asset_type)
            .distinct()
        )
    ).scalars().all()
    return list(rows)


def _resolve_screenshot_url(payload: dict) -> str | None:
    """Return the appropriate screenshot URL.

    Tries to regenerate from `screenshot_object_name` (needed for presigned URLs which
    expire). If storage is not configured on this process (e.g. the API container has no
    MINIO_URL) the regeneration returns None and we fall back to the URL stored by the
    worker, which was generated with the correct MINIO_PUBLIC_URL at upload time.
    """
    object_name = payload.get("screenshot_object_name")
    if object_name:
        url = storage.screenshot_url(object_name)
        if url:
            return url
    return payload.get("screenshot_url")


def _ip_tag(payloads: dict[str, dict]) -> str | None:
    """Derive the IP Tag chip — CDN IP / Cloudflare IP / Direct IP."""
    httpx = payloads.get("httpx", {})
    if httpx.get("cdn"):
        name = (httpx.get("cdn_name") or "").lower()
        if "cloudflare" in name:
            return "Cloudflare IP"
        return "CDN IP"
    asnmap = payloads.get("asnmap", {})
    org = (asnmap.get("org") or "").lower()
    if any(needle in org for needle in ("cloudflare", "cloudfront", "akamai", "fastly")):
        return "CDN IP"
    if httpx or asnmap:
        return "Direct IP"
    return None


def _merge_ip_attrs(
    primary_ip: str | None, ip_payloads: dict[str, dict[str, dict]]
) -> dict[str, Any]:
    """Pull asnmap+geoip enrichment for a given IP. ip_payloads keyed by canonical_key."""
    if not primary_ip:
        return {}
    return ip_payloads.get(primary_ip, {})


async def build_port_rows(db: AsyncSession, scan_id: UUID) -> list[PortRow]:
    """Build port/service rows from the first-class `services` table.

    Scoped to this scan via asset_observations — only services first detected in (or
    re-observed during) this scan are included. Replaces the old JSONB-walking path.
    """
    # Subquery: asset_ids for service-type assets observed in this scan
    svc_asset_ids_sq = (
        select(AssetObservation.asset_id)
        .join(Asset, Asset.id == AssetObservation.asset_id)
        .where(AssetObservation.scan_id == scan_id, Asset.type == "service")
        .distinct()
        .scalar_subquery()
    )

    services = (
        await db.scalars(select(Service).where(Service.asset_id.in_(svc_asset_ids_sq)))
    ).all()

    rows: list[PortRow] = []
    for svc in services:
        rows.append(
            PortRow(
                asset_id=svc.asset_id,
                host=svc.host,
                port=svc.port,
                proto=svc.proto,
                state=svc.state,
                service_name=svc.service_name,
                product=svc.product,
                version=svc.version,
            )
        )
    return sorted(rows, key=lambda r: (r.host, r.port))


async def build_subdomain_rows(db: AsyncSession, scan_id: UUID) -> list[SubdomainRow]:
    sub_assets = await _load_assets(db, scan_id, "subdomain")
    sub_payloads = await _load_observations_for_scan(db, scan_id, "subdomain")

    # IP enrichment lookup: canonical_key (the IP) → merged payload across asnmap+geoip+dnsx
    ip_assets = await _load_assets(db, scan_id, "ipv4")
    ip_obs = await _load_observations_for_scan(db, scan_id, "ipv4")
    ip_lookup: dict[str, dict[str, Any]] = {}
    for asset in ip_assets:
        merged: dict[str, Any] = {}
        for tool in _IP_TOOLS:
            merged.update(ip_obs.get(asset.id, {}).get(tool, {}))
        ip_lookup[asset.canonical_key] = merged

    # HTTP enrichment lookup: the httpx adapter writes type="http_service" assets
    # (canonical_key = full URL, e.g. "https://api.example.com"), not subdomain assets.
    # We build a host-keyed dict here so the subdomain join can find HTTP data.
    # Prefer https observations over http when both exist for the same FQDN.
    http_assets = await _load_assets(db, scan_id, "http_service")
    http_obs = await _load_observations_for_scan(db, scan_id, "http_service")
    http_lookup: dict[str, dict[str, Any]] = {}  # FQDN → merged httpx payload
    for http_asset in http_assets:
        obs = http_obs.get(http_asset.id, {})
        payload = obs.get("httpx", {})
        # "host" / "input" in the payload is the FQDN we passed to httpx
        host = payload.get("host") or payload.get("input") or ""
        if not host:
            # Fall back to parsing the URL canonical_key
            try:
                from urllib.parse import urlparse  # stdlib, already available
                host = urlparse(http_asset.canonical_key).hostname or ""
            except Exception:
                pass
        if not host:
            continue
        is_https = http_asset.canonical_key.startswith("https://")
        if host not in http_lookup or is_https:
            http_lookup[host] = payload

    # Service (port) enrichment: group by host FQDN → list of "port/proto" strings
    service_assets = await _load_assets(db, scan_id, "service")
    port_lookup: dict[str, list[str]] = {}
    for svc_asset in service_assets:
        try:
            host_part, rest = svc_asset.canonical_key.rsplit(":", 1)
            port_str, proto = rest.split("/", 1)
        except (ValueError, IndexError):
            continue
        port_lookup.setdefault(host_part, []).append(f"{port_str}/{proto}")

    # Screenshot enrichment: FQDN → screenshot_url
    screenshot_assets = await _load_assets(db, scan_id, "screenshot")
    screenshot_obs = await _load_observations_for_scan(db, scan_id, "screenshot")
    screenshot_lookup: dict[str, str] = {}
    for ss_asset in screenshot_assets:
        obs = screenshot_obs.get(ss_asset.id, {})
        for tool in _SCREENSHOT_TOOLS:
            tool_payload = obs.get(tool, {})
            ss_url = _resolve_screenshot_url(tool_payload)
            if ss_url:
                screenshot_lookup[ss_asset.canonical_key] = ss_url
                break

    rows: list[SubdomainRow] = []
    for asset in sub_assets:
        payloads = sub_payloads.get(asset.id, {})
        dnsx = payloads.get("dnsx", {})
        # httpx data lives on http_service assets, not subdomain assets — use the lookup
        httpx = http_lookup.get(asset.canonical_key, {})
        wafw00f = payloads.get("wafw00f", {})

        all_ips = list(dnsx.get("ips") or [])
        primary_ip = dnsx.get("primary_ip") or (all_ips[0] if all_ips else None)
        cnames = list(dnsx.get("cnames") or httpx.get("cnames") or [])

        ip_data = _merge_ip_attrs(primary_ip, {primary_ip: ip_lookup.get(primary_ip, {})} if primary_ip else {})

        # _ip_tag needs httpx data, but httpx data lives in http_lookup, not payloads.
        # Merge it in so _ip_tag can derive CDN/Cloudflare/Direct classification.
        payloads_for_ip_tag = {**payloads, "httpx": httpx}

        rows.append(
            SubdomainRow(
                asset_id=asset.id,
                subdomain=asset.canonical_key,
                http_status=httpx.get("status_code"),
                title=httpx.get("title"),
                redirect=bool(httpx.get("redirect")),
                final_url=httpx.get("final_url") or None,
                location=httpx.get("location") or None,
                ip_tag=_ip_tag(payloads_for_ip_tag),
                primary_ip=primary_ip,
                all_ips=all_ips,
                cdn=bool(httpx.get("cdn")),
                cdn_name=httpx.get("cdn_name") or None,
                cname=(cnames[0] if cnames else None),
                cnames=cnames,
                waf=wafw00f.get("waf") or None,
                waf_conf=wafw00f.get("waf_conf") or None,
                asn=ip_data.get("asn") or None,
                org=ip_data.get("org") or None,
                country=ip_data.get("country") or None,
                country_name=ip_data.get("country_name") or None,
                city=ip_data.get("city") or None,
                server=httpx.get("server") or None,
                tech=list(httpx.get("tech") or []),
                open_ports=sorted(port_lookup.get(asset.canonical_key, [])),
                sources=sorted(payloads.keys()),
                screenshot_url=screenshot_lookup.get(asset.canonical_key),
                url=httpx.get("input") and httpx.get("scheme") and f"{httpx['scheme']}://{httpx['input']}" or None,
                first_seen=asset.first_seen,
                last_seen=asset.last_seen,
            )
        )
    return rows


def filter_and_sort(
    rows: list[SubdomainRow],
    *,
    search: str | None,
    status: list[int] | None,
    ip_tags: list[str] | None,
    cdns: list[str] | None,
    wafs: list[str] | None,
    sort: str | None,
) -> list[SubdomainRow]:
    out = rows
    if search:
        s = search.lower()
        out = [r for r in out if s in r.subdomain.lower()]
    if status:
        sset = set(status)
        out = [r for r in out if r.http_status in sset]
    if ip_tags:
        tset = set(ip_tags)
        out = [r for r in out if r.ip_tag in tset]
    if cdns:
        cset = {c.lower() for c in cdns}
        out = [r for r in out if (r.cdn_name or "").lower() in cset]
    if wafs:
        wset = {w.lower() for w in wafs}
        out = [r for r in out if (r.waf or "").lower() in wset]

    if sort:
        desc = sort.startswith("-")
        key = sort.lstrip("-")
        out = sorted(
            out,
            key=lambda r: (getattr(r, key, None) is None, getattr(r, key, None) or ""),
            reverse=desc,
        )
    else:
        out = sorted(out, key=lambda r: r.subdomain)
    return out


async def build_ip_rows(db: AsyncSession, scan_id: UUID) -> list[IpRow]:
    ip_assets = await _load_assets(db, scan_id, "ipv4")
    ip_obs = await _load_observations_for_scan(db, scan_id, "ipv4")
    out: list[IpRow] = []
    for asset in ip_assets:
        merged: dict[str, Any] = {}
        for tool in _IP_TOOLS:
            merged.update(ip_obs.get(asset.id, {}).get(tool, {}))
        resolves = list(merged.get("resolves") or [])
        out.append(
            IpRow(
                asset_id=asset.id,
                ip=asset.canonical_key,
                subdomain_count=len(resolves),
                asn=merged.get("asn") or None,
                org=merged.get("org") or None,
                country=merged.get("country") or None,
                city=merged.get("city") or None,
                resolves=resolves,
            )
        )
    return sorted(out, key=lambda r: -r.subdomain_count)


async def build_overview(db: AsyncSession, scan_id: UUID) -> ScanOverview:
    rows = await build_subdomain_rows(db, scan_id)
    ips = await build_ip_rows(db, scan_id)

    status_counter: dict[str, int] = defaultdict(int)
    tech_counter: dict[str, int] = defaultdict(int)
    asn_counter: dict[str, int] = defaultdict(int)
    cdn_counter: dict[str, int] = defaultdict(int)
    waf_count = 0
    cdn_count = 0
    tech_set: set[str] = set()
    for r in rows:
        bucket = _status_bucket(r.http_status)
        status_counter[bucket] += 1
        for t in r.tech:
            tech_counter[t] += 1
            tech_set.add(t)
        if r.cdn:
            cdn_count += 1
            if r.cdn_name:
                cdn_counter[r.cdn_name] += 1
        if r.waf:
            waf_count += 1
    for ip in ips:
        if ip.asn:
            label = f"{ip.asn} {ip.org}".strip() if ip.org else ip.asn
            asn_counter[label] += ip.subdomain_count

    return ScanOverview(
        subdomain_count=len(rows),
        ip_count=len(ips),
        cdn_count=cdn_count,
        waf_count=waf_count,
        tech_count=len(tech_set),
        http_status_buckets=_top_buckets(status_counter, n=8),
        top_tech=_top_buckets(tech_counter, n=10),
        top_asn=_top_buckets(asn_counter, n=10),
        top_cdn=_top_buckets(cdn_counter, n=10),
    )


async def build_cdn_waf_summary(db: AsyncSession, scan_id: UUID) -> CdnWafSummary:
    rows = await build_subdomain_rows(db, scan_id)
    live = [r for r in rows if r.http_status is not None]
    total = max(len(live), 1)
    behind_cdn = sum(1 for r in live if r.cdn)
    behind_waf = sum(1 for r in live if r.waf)
    cdn_buckets: dict[str, int] = defaultdict(int)
    waf_buckets: dict[str, int] = defaultdict(int)
    unprotected: list[str] = []
    for r in live:
        if r.cdn_name:
            cdn_buckets[r.cdn_name] += 1
        if r.waf:
            waf_buckets[r.waf] += 1
        if not r.cdn and not r.waf:
            unprotected.append(r.subdomain)
    return CdnWafSummary(
        behind_cdn_pct=round(100.0 * behind_cdn / total, 1),
        behind_waf_pct=round(100.0 * behind_waf / total, 1),
        cdn_breakdown=_top_buckets(cdn_buckets, n=20),
        waf_breakdown=_top_buckets(waf_buckets, n=20),
        unprotected_origins=sorted(unprotected)[:200],
    )


async def build_technologies(db: AsyncSession, scan_id: UUID) -> list[TechBucket]:
    """Build technology buckets from the first-class `technologies` table.

    Scoped to http_service assets observed in this scan. Groups by tech name and
    attaches the list of URLs (canonical_key) that carry the tech.
    """
    http_asset_ids_sq = (
        select(AssetObservation.asset_id)
        .join(Asset, Asset.id == AssetObservation.asset_id)
        .where(AssetObservation.scan_id == scan_id, Asset.type == "http_service")
        .distinct()
        .scalar_subquery()
    )

    # Join Technology to Asset so we can return the URL (canonical_key) per tech
    tech_rows = (
        await db.execute(
            select(Technology.name, Asset.canonical_key)
            .join(Asset, Asset.id == Technology.asset_id)
            .where(Technology.asset_id.in_(http_asset_ids_sq))
            .order_by(Technology.name)
        )
    ).all()

    counter: dict[str, int] = defaultdict(int)
    tech_urls: dict[str, list[str]] = defaultdict(list)
    for name, url in tech_rows:
        counter[name] += 1
        tech_urls[name].append(url)

    return [
        TechBucket(label=k, count=v, subdomains=sorted(tech_urls[k]))
        for k, v in sorted(counter.items(), key=lambda kv: -kv[1])[:200]
    ]


def _status_bucket(status: int | None) -> str:
    if status is None:
        return "no probe"
    if 200 <= status < 300:
        return "2xx"
    if 300 <= status < 400:
        return "3xx"
    if 400 <= status < 500:
        return "4xx"
    if 500 <= status < 600:
        return "5xx"
    return "other"


def _top_buckets(counter: dict[str, int], *, n: int) -> list[CountBucket]:
    items = sorted(counter.items(), key=lambda kv: -kv[1])[:n]
    return [CountBucket(label=k, count=v) for k, v in items]


async def build_findings(
    db: AsyncSession,
    scan_id: UUID,
    severity: str | None = None,
    offset: int = 0,
    limit: int = 50,
) -> tuple[int, list[FindingRow]]:
    """Return paginated findings ordered by priority_rank ASC (1 = highest risk)."""
    count_q = select(func.count()).select_from(Finding).where(Finding.scan_id == scan_id)
    if severity:
        count_q = count_q.where(Finding.severity == severity)
    total: int = await db.scalar(count_q) or 0

    data_q = (
        select(Finding, Asset.canonical_key)
        .join(Asset, Asset.id == Finding.asset_id, isouter=True)
        .where(Finding.scan_id == scan_id)
    )
    if severity:
        data_q = data_q.where(Finding.severity == severity)
    data_q = data_q.order_by(Finding.priority_rank).offset(offset).limit(limit)

    rows = (await db.execute(data_q)).all()
    items = [
        FindingRow(
            finding_id=finding.id,
            asset_id=finding.asset_id,
            fqdn=fqdn or "",
            severity=finding.severity.value,
            priority_rank=finding.priority_rank,
            risk_score=finding.risk_score,
            rationale=finding.rationale,
            signals=list(finding.signals or []),
            recommended_action=finding.recommended_action,
            source=finding.source,
        )
        for finding, fqdn in rows
    ]
    return total, items
