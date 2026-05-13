"""Target management and authorization verification endpoints (M2)."""
from __future__ import annotations

import secrets
from datetime import datetime, timezone
from uuid import UUID

import httpx
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import CurrentUser, get_current_user
from app.core.db import get_db
from app.models import Project, Scan, ScanKind, Target
from app.models.asset import Asset
from app.models.endpoint import Endpoint
from app.models.hvt_signal import HvtSignal
from app.models.vulnerability import Vulnerability
from app.schemas.target import GenerateTokenResponse, TargetOut, VerifyRequest
from app.schemas.vuln import TargetRiskView, TargetRiskVulnRow

router = APIRouter(prefix="/targets", tags=["targets"])


async def _get_target_for_user(
    target_id: UUID, db: AsyncSession, user: CurrentUser
) -> Target:
    target = await db.scalar(
        select(Target)
        .join(Project, Project.id == Target.project_id)
        .where(Target.id == target_id, Project.org_id == user.org_id)
    )
    if target is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "target not found")
    return target


@router.get("", response_model=list[TargetOut])
async def list_targets(
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> list[TargetOut]:
    rows = (
        await db.execute(
            select(Target)
            .join(Project, Project.id == Target.project_id)
            .where(Project.org_id == user.org_id)
            .order_by(Target.domain)
        )
    ).scalars().all()
    return [TargetOut.model_validate(t) for t in rows]


@router.post("/{target_id}/generate-token", response_model=GenerateTokenResponse)
async def generate_auth_token(
    target_id: UUID,
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> GenerateTokenResponse:
    """Generate (or return existing) authorization token for target ownership proof."""
    target = await _get_target_for_user(target_id, db, user)
    if not target.authorization_token:
        target.authorization_token = secrets.token_hex(16)
        await db.commit()
        await db.refresh(target)
    token = target.authorization_token
    return GenerateTokenResponse(
        token=token,
        dns_txt_record=f'_recon-auth.{target.domain} TXT "{token}"',
        http_file_path="/.well-known/recon-auth.txt",
        instructions=(
            f"Verify ownership of {target.domain} using one of:\n"
            f"1. DNS TXT: Add TXT record '_recon-auth.{target.domain}' = '{token}'\n"
            f"2. HTTP file: Serve '{token}' at "
            f"http://{target.domain}/.well-known/recon-auth.txt"
        ),
    )


@router.post("/{target_id}/verify", response_model=TargetOut)
async def verify_target(
    target_id: UUID,
    req: VerifyRequest,
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> TargetOut:
    """Verify target ownership via DNS TXT record or HTTP well-known file."""
    target = await _get_target_for_user(target_id, db, user)
    if not target.authorization_token:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "generate a token first via /generate-token")

    token = target.authorization_token
    verified = False
    method = req.method.lower()

    if method == "http_file":
        url = f"http://{target.domain}/.well-known/recon-auth.txt"
        try:
            async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
                resp = await client.get(url)
            verified = resp.status_code == 200 and token in resp.text
        except Exception:
            pass

    elif method == "dns_txt":
        dns_name = f"_recon-auth.{target.domain}"
        doh_url = f"https://cloudflare-dns.com/dns-query?name={dns_name}&type=TXT"
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(doh_url, headers={"accept": "application/dns-json"})
            if resp.status_code == 200:
                for ans in resp.json().get("Answer", []):
                    if token in (ans.get("data") or ""):
                        verified = True
                        break
        except Exception:
            pass
    else:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "method must be 'dns_txt' or 'http_file'",
        )

    if not verified:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            f"Verification failed for method '{method}'. Ensure the token is correctly placed.",
        )

    target.authorization_verified_at = datetime.now(timezone.utc)
    target.authorization_proof = method
    await db.commit()
    await db.refresh(target)
    return TargetOut.model_validate(target)


@router.get("/{target_id}/risk", response_model=TargetRiskView)
async def get_target_risk(
    target_id: UUID,
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> TargetRiskView:
    """Cross-scan vulnerability + HVT rollup for a target."""
    # Tenant gate
    target = await db.scalar(
        select(Target)
        .join(Project, Project.id == Target.project_id)
        .where(Target.id == target_id, Project.org_id == user.org_id)
    )
    if target is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "target not found")

    # Open vuln counts by severity across all scans for this target
    sev_rows = (
        await db.execute(
            select(Vulnerability.severity, func.count(Vulnerability.id).label("cnt"))
            .where(
                Vulnerability.target_id == target_id,
                Vulnerability.status.in_(["open", "triaged"]),
            )
            .group_by(Vulnerability.severity)
        )
    ).all()
    open_counts: dict = {"critical": 0, "high": 0, "med": 0, "low": 0, "info": 0}
    for sev, cnt in sev_rows:
        key = (sev.value if hasattr(sev, "value") else str(sev)).lower()
        open_counts[key] = cnt

    # Top 10 open vulns by risk_score
    top_rows = (
        await db.execute(
            select(Vulnerability, Asset.canonical_key.label("asset_label"))
            .join(Asset, Asset.id == Vulnerability.asset_id)
            .where(
                Vulnerability.target_id == target_id,
                Vulnerability.status.in_(["open", "triaged"]),
            )
            .order_by(desc(Vulnerability.risk_score).nullslast())
            .limit(10)
        )
    ).all()
    top_risk_vulns = [
        TargetRiskVulnRow(
            id=v.id,
            title=v.title,
            severity=v.severity.value if hasattr(v.severity, "value") else str(v.severity),
            risk_score=v.risk_score,
            kev=v.kev,
            asset_label=asset_label,
            status=v.status.value if hasattr(v.status, "value") else str(v.status),
        )
        for v, asset_label in top_rows
    ]

    # HVT inventory
    hvt_count = (
        await db.scalar(
            select(func.count(HvtSignal.id)).where(HvtSignal.target_id == target_id)
        )
    ) or 0

    signal_rows = (
        await db.execute(
            select(HvtSignal.signal_type, func.count(HvtSignal.id).label("cnt"))
            .where(HvtSignal.target_id == target_id)
            .group_by(HvtSignal.signal_type)
        )
    ).all()
    hvt_signal_summary = {
        (st.value if hasattr(st, "value") else str(st)): cnt
        for st, cnt in signal_rows
    }

    # Endpoint count
    endpoint_count = (
        await db.scalar(
            select(func.count(Endpoint.id)).where(Endpoint.target_id == target_id)
        )
    ) or 0

    # Latest vuln scan
    latest_scan = await db.scalar(
        select(Scan)
        .where(Scan.target_id == target_id, Scan.kind == ScanKind.vuln_analysis)
        .order_by(desc(Scan.created_at))
        .limit(1)
    )

    return TargetRiskView(
        target_id=target_id,
        target_domain=target.domain,
        open_counts=open_counts,
        top_risk_vulns=top_risk_vulns,
        hvt_count=hvt_count,
        hvt_signal_summary=hvt_signal_summary,
        endpoint_count=endpoint_count,
        latest_vuln_scan_id=latest_scan.id if latest_scan else None,
        latest_vuln_scan_status=latest_scan.status.value if latest_scan else None,
        latest_vuln_scan_created_at=latest_scan.created_at if latest_scan else None,
    )
