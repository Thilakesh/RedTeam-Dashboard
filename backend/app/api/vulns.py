from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import CurrentUser, get_current_user
from app.core.db import get_db
from app.models.asset import Asset
from app.models.org import Project, Target
from app.models.vulnerability import VulnStatus, Vulnerability
from app.schemas.vuln import VulnOut, VulnStatusUpdateRequest

router = APIRouter(prefix="/vulns", tags=["vulns"])


async def _get_vuln_scoped(
    db: AsyncSession, vuln_id: UUID, org_id: UUID
) -> tuple[Vulnerability, str]:
    """Load a Vulnerability and verify tenant scope via target → project → org.

    Returns (vulnerability, asset_label). Raises 404 if not found or wrong org.
    """
    row = (
        await db.execute(
            select(Vulnerability, Asset.canonical_key.label("asset_label"))
            .join(Asset, Asset.id == Vulnerability.asset_id)
            .join(Target, Target.id == Vulnerability.target_id)
            .join(Project, Project.id == Target.project_id)
            .where(
                Vulnerability.id == vuln_id,
                Project.org_id == org_id,
            )
        )
    ).first()
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "vulnerability not found")
    return row.Vulnerability, row.asset_label


@router.patch("/{vuln_id}", response_model=VulnOut)
async def update_vuln_status(
    vuln_id: UUID,
    req: VulnStatusUpdateRequest,
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> VulnOut:
    vuln, asset_label = await _get_vuln_scoped(db, vuln_id, user.org_id)
    vuln.status = VulnStatus(req.status)
    await db.commit()
    await db.refresh(vuln)
    return VulnOut(
        id=vuln.id,
        canonical_key=vuln.canonical_key,
        title=vuln.title,
        severity=vuln.severity.value,
        cvss_v3=vuln.cvss_v3,
        cve_ids=vuln.cve_ids or [],
        cwe_ids=vuln.cwe_ids or [],
        status=vuln.status.value,
        asset_id=vuln.asset_id,
        asset_label=asset_label,
        template_id=vuln.template_id,
        kev=vuln.kev,
        first_seen=vuln.first_seen,
        last_seen=vuln.last_seen,
    )
