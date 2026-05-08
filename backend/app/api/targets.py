"""Target management and authorization verification endpoints (M2)."""
from __future__ import annotations

import secrets
from datetime import datetime, timezone
from uuid import UUID

import httpx
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import CurrentUser, get_current_user
from app.core.db import get_db
from app.models import Project, Target
from app.schemas.target import GenerateTokenResponse, TargetOut, VerifyRequest

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
