"""Target Workspace service layer.

Workspaces are analyst-driven investigation containers built on top of a
completed recon scan. They do NOT own assets — the asset graph belongs to the
target. The workspace adds: investigation_tasks (per-tool, per-asset jobs),
investigation_findings (normalized tool-specific signals), and the analyst's
operational context (which tools have been run on which subdomain).

Creation is idempotent on (target_id, parent_scan_id) — re-clicking
"Target Investigation" on the same recon scan returns the existing workspace.
"""
from __future__ import annotations

from collections import defaultdict
from uuid import UUID

from sqlalchemy import desc, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import (
    Asset,
    AssetObservation,
    HvtSignal,
    InvestigationFinding,
    InvestigationTask,
    InvestigationTaskStatus,
    Service,
    Target,
    TargetWorkspace,
)


def _workspace_label(parent_scan_id: UUID | None, target_domain: str) -> str:
    """Format: 'TW-<short-scan-id>-<domain>'. Used as display name on list page."""
    if parent_scan_id is None:
        return f"TW-{target_domain}"
    short = str(parent_scan_id)[:8]
    return f"TW-{short}-{target_domain}"


async def create_or_get_workspace(
    db: AsyncSession,
    target_id: UUID,
    parent_scan_id: UUID,
    org_id: UUID,
    target_domain: str,
) -> TargetWorkspace:
    """Idempotent: returns existing workspace if (target_id, parent_scan_id) row exists."""
    existing = await db.scalar(
        select(TargetWorkspace).where(
            TargetWorkspace.target_id == target_id,
            TargetWorkspace.parent_scan_id == parent_scan_id,
        )
    )
    if existing is not None:
        return existing

    ws = TargetWorkspace(
        org_id=org_id,
        target_id=target_id,
        parent_scan_id=parent_scan_id,
        label=_workspace_label(parent_scan_id, target_domain),
    )
    db.add(ws)
    try:
        await db.commit()
    except IntegrityError:
        # Race: another request created the same workspace. Re-read.
        await db.rollback()
        existing = await db.scalar(
            select(TargetWorkspace).where(
                TargetWorkspace.target_id == target_id,
                TargetWorkspace.parent_scan_id == parent_scan_id,
            )
        )
        if existing is None:
            raise
        return existing
    await db.refresh(ws)
    return ws


async def list_workspaces_for_org(
    db: AsyncSession, org_id: UUID
) -> list[dict]:
    """Return list rows for the /target-workspaces index page."""
    rows = (
        await db.execute(
            select(TargetWorkspace, Target.domain)
            .join(Target, Target.id == TargetWorkspace.target_id)
            .where(TargetWorkspace.org_id == org_id)
            .order_by(desc(TargetWorkspace.created_at))
            .limit(200)
        )
    ).all()
    if not rows:
        return []

    workspace_ids = [r.TargetWorkspace.id for r in rows]
    target_ids = list({r.TargetWorkspace.target_id for r in rows})

    # Subdomain asset count per target (live-ref, not per-workspace)
    asset_counts: dict[UUID, int] = {}
    asset_rows = (
        await db.execute(
            select(Asset.target_id, func.count(Asset.id))
            .where(Asset.target_id.in_(target_ids), Asset.type == "subdomain")
            .group_by(Asset.target_id)
        )
    ).all()
    for tid, cnt in asset_rows:
        asset_counts[tid] = cnt

    # Task counts per workspace
    task_counts: dict[UUID, int] = {}
    task_rows = (
        await db.execute(
            select(InvestigationTask.workspace_id, func.count(InvestigationTask.id))
            .where(InvestigationTask.workspace_id.in_(workspace_ids))
            .group_by(InvestigationTask.workspace_id)
        )
    ).all()
    for wid, cnt in task_rows:
        task_counts[wid] = cnt

    out = []
    for r in rows:
        ws = r.TargetWorkspace
        out.append({
            "id": ws.id,
            "label": ws.label,
            "target_id": ws.target_id,
            "target_domain": r.domain,
            "parent_scan_id": ws.parent_scan_id,
            "asset_count": asset_counts.get(ws.target_id, 0),
            "task_count": task_counts.get(ws.id, 0),
            "status": ws.status.value if hasattr(ws.status, "value") else str(ws.status),
            "created_at": ws.created_at,
        })
    return out


async def build_workspace_overview(
    db: AsyncSession, workspace: TargetWorkspace
) -> dict:
    """Counts for the Overview tab. Pulls live from target-scoped tables."""
    target_id = workspace.target_id

    total_subdomains = (
        await db.scalar(
            select(func.count(Asset.id)).where(
                Asset.target_id == target_id, Asset.type == "subdomain"
            )
        )
    ) or 0

    alive_hosts = (
        await db.scalar(
            select(func.count(Asset.id.distinct())).where(
                Asset.target_id == target_id, Asset.type == "http_service"
            )
        )
    ) or 0

    ports_identified = (
        await db.scalar(
            select(func.count(Service.id)).where(
                Service.target_id == target_id, Service.state == "open"
            )
        )
    ) or 0

    running_tasks = (
        await db.scalar(
            select(func.count(InvestigationTask.id)).where(
                InvestigationTask.workspace_id == workspace.id,
                InvestigationTask.status.in_(
                    [InvestigationTaskStatus.queued, InvestigationTaskStatus.running]
                ),
            )
        )
    ) or 0

    findings_count = (
        await db.scalar(
            select(func.count(InvestigationFinding.id))
            .join(
                InvestigationTask,
                InvestigationTask.id == InvestigationFinding.task_id,
            )
            .where(InvestigationTask.workspace_id == workspace.id)
        )
    ) or 0

    hvt_count = (
        await db.scalar(
            select(func.count(HvtSignal.id)).where(HvtSignal.target_id == target_id)
        )
    ) or 0

    hvt_rows = (
        await db.execute(
            select(HvtSignal.signal_type, func.count(HvtSignal.id))
            .where(HvtSignal.target_id == target_id)
            .group_by(HvtSignal.signal_type)
        )
    ).all()
    hvt_signal_summary = {
        (st.value if hasattr(st, "value") else str(st)): cnt for st, cnt in hvt_rows
    }

    return {
        "total_subdomains": total_subdomains,
        "alive_hosts": alive_hosts,
        "ports_identified": ports_identified,
        "running_tasks": running_tasks,
        "findings_count": findings_count,
        "hvt_count": hvt_count,
        "hvt_signal_summary": hvt_signal_summary,
    }


async def build_workspace_subdomain_rows(
    db: AsyncSession, workspace: TargetWorkspace
) -> list[dict]:
    """Operational table for the Subdomains tab.

    Per subdomain asset, derive:
      - alive (boolean from http_service presence OR open ports)
      - ports[] (from Service.host == fqdn AND state == open)
      - technologies[] (from Service.product)
      - has_http / has_https (hint only — all 4 tools always offered)
      - ips[] — list of {asset_id, ip} pairs for IPs the subdomain resolves to
                (sourced from dnsx AssetObservation payloads, joined to
                Asset(type=ipv4) for the scannable asset_id)
      - tools_run[] (distinct completed tools across THIS asset + its IPs)
      - hvt_signals[] (from HvtSignal table)
    """
    from app.services.investigation_tasks import TOOLS  # local to avoid cycle

    target_id = workspace.target_id

    subdomains = (
        await db.execute(
            select(Asset).where(
                Asset.target_id == target_id, Asset.type == "subdomain"
            )
        )
    ).scalars().all()
    if not subdomains:
        return []

    fqdns = [a.canonical_key for a in subdomains]
    asset_by_fqdn: dict[str, Asset] = {a.canonical_key: a for a in subdomains}
    asset_ids = [a.id for a in subdomains]

    # Open ports + products per host
    svc_rows = (
        await db.execute(
            select(Service.host, Service.port, Service.product)
            .where(
                Service.target_id == target_id,
                Service.host.in_(fqdns),
                Service.state == "open",
            )
        )
    ).all()
    ports_by_fqdn: dict[str, list[int]] = defaultdict(list)
    techs_by_fqdn: dict[str, set[str]] = defaultdict(set)
    for host, port, product in svc_rows:
        ports_by_fqdn[host].append(port)
        if product:
            techs_by_fqdn[host].add(product)

    # http_service assets — hint surface only, no longer gates tool dropdown.
    http_rows = (
        await db.execute(
            select(Asset.canonical_key).where(
                Asset.target_id == target_id, Asset.type == "http_service"
            )
        )
    ).all()
    http_for: dict[str, bool] = defaultdict(bool)
    https_for: dict[str, bool] = defaultdict(bool)
    for (ck,) in http_rows:
        if not isinstance(ck, str):
            continue
        if ck.startswith("https://"):
            host = ck[len("https://") :].split("/", 1)[0].split(":", 1)[0]
            https_for[host] = True
        elif ck.startswith("http://"):
            host = ck[len("http://") :].split("/", 1)[0].split(":", 1)[0]
            http_for[host] = True

    # IPs per subdomain — read dnsx observation payloads; map IP -> ipv4 Asset.id
    ip_assets = (
        await db.execute(
            select(Asset.id, Asset.canonical_key).where(
                Asset.target_id == target_id, Asset.type == "ipv4"
            )
        )
    ).all()
    ip_asset_by_ip: dict[str, UUID] = {ck: aid for aid, ck in ip_assets}

    dnsx_rows = (
        await db.execute(
            select(AssetObservation.asset_id, AssetObservation.payload).where(
                AssetObservation.asset_id.in_(asset_ids),
                AssetObservation.source_tool == "dnsx",
            )
        )
    ).all()
    # Only the primary IP per subdomain (first A record dnsx returned).
    primary_ip_by_asset: dict[UUID, str] = {}
    for asset_id, payload in dnsx_rows:
        if asset_id in primary_ip_by_asset:
            continue
        p = payload or {}
        primary = p.get("primary_ip")
        if not primary:
            ips_list = p.get("ips") or []
            primary = ips_list[0] if ips_list else None
        if primary:
            primary_ip_by_asset[asset_id] = primary

    # tools_run aggregation — include tasks run against the subdomain
    # AND its primary IP asset, so "View Nmap Scan" surfaces results regardless
    # of whether the analyst ran on the FQDN or on its backing IP.
    all_related_ids: set[UUID] = set(asset_ids)
    for asset_id, ip in primary_ip_by_asset.items():
        related_asset_id = ip_asset_by_ip.get(ip)
        if related_asset_id is not None:
            all_related_ids.add(related_asset_id)

    tools_run_rows = (
        await db.execute(
            select(InvestigationTask.asset_id, InvestigationTask.tool)
            .where(
                InvestigationTask.asset_id.in_(all_related_ids),
                InvestigationTask.workspace_id == workspace.id,
                InvestigationTask.status == InvestigationTaskStatus.completed,
            )
            .distinct()
        )
    ).all()
    tools_run_by_asset: dict[UUID, set[str]] = defaultdict(set)
    for asset_id, tool in tools_run_rows:
        tools_run_by_asset[asset_id].add(tool)

    # HVT signals per asset
    hvt_rows = (
        await db.execute(
            select(HvtSignal.asset_id, HvtSignal.signal_type).where(
                HvtSignal.asset_id.in_(asset_ids)
            )
        )
    ).all()
    hvts_by_asset: dict[UUID, set[str]] = defaultdict(set)
    for asset_id, signal_type in hvt_rows:
        st = signal_type.value if hasattr(signal_type, "value") else str(signal_type)
        hvts_by_asset[asset_id].add(st)

    rows: list[dict] = []
    for fqdn in sorted(fqdns):
        asset = asset_by_fqdn[fqdn]
        ports = sorted(set(ports_by_fqdn.get(fqdn, [])))
        techs = sorted(techs_by_fqdn.get(fqdn, set()))
        has_http = http_for.get(fqdn, False)
        has_https = https_for.get(fqdn, False)
        alive = has_http or has_https or bool(ports)

        primary_ip = primary_ip_by_asset.get(asset.id)
        ip_rows = []
        ip_tools_run: set[str] = set()
        if primary_ip:
            ip_asset_id = ip_asset_by_ip.get(primary_ip)
            if ip_asset_id is not None:
                ip_rows.append({"asset_id": ip_asset_id, "ip": primary_ip})
                ip_tools_run = set(tools_run_by_asset.get(ip_asset_id, set()))

        # Subdomain row tools_run = own tools_run ∪ tools_run on its primary IP
        combined_tools_run = set(tools_run_by_asset.get(asset.id, set())) | ip_tools_run

        rows.append({
            "asset_id": asset.id,
            "fqdn": fqdn,
            "alive": alive,
            "ports": ports,
            "technologies": techs,
            "has_http": has_http,
            "has_https": has_https,
            "available_tools": list(TOOLS),  # always all 4
            "tools_run": sorted(combined_tools_run),
            "hvt_signals": sorted(hvts_by_asset.get(asset.id, set())),
            "ips": ip_rows,
        })
    return rows
