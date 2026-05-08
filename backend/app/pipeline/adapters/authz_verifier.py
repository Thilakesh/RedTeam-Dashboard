"""AuthzVerifierStage — automated target authorization check.

Runs as an early stage (L0, no deps) in the deep profile. Tries HTTP well-known
and DNS TXT verification in sequence. On success: updates the target's
authorization_verified_at in DB and sets authz_state[0] = True so the coordinator
allows authz_required stages (naabu/nmap/gowitness) to run in the same scan.

Documented exception to "adapters never touch DB": this stage MUST write
authorization_verified_at to gate active scanning. Follows RiskPrioritizerStage
pattern of injecting SessionLocal at construction time.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

import httpx

from app.core.db import SessionLocal
from app.models import Target
from app.pipeline.stage import AssetRecord, StageContext

log = logging.getLogger(__name__)


class AuthzVerifierStage:
    name = "authz_verifier"
    source_tool = "authz_verifier"
    inputs: list[str] = []
    outputs: list[str] = []
    depends_on: list[str] = []
    weight = 5
    optional = True
    authz_required = False  # This stage can always run — it's what grants authz

    def __init__(self, authz_state: list[bool]) -> None:
        self._authz_state = authz_state

    async def execute(self, ctx: StageContext) -> list[AssetRecord]:
        async with SessionLocal() as db:
            target = await db.get(Target, ctx.target_id)
            if target is None:
                log.warning("authz_verifier: target %s not found", ctx.target_id)
                return []

            # Already verified — nothing to do.
            if target.authorization_verified_at is not None:
                self._authz_state[0] = True
                return []

            token = target.authorization_token
            if not token:
                log.info("authz_verifier: no token for %s — skipping", ctx.domain)
                return []

        verified = await self._try_http(ctx.domain, token)
        if not verified:
            verified = await self._try_dns(ctx.domain, token)

        if not verified:
            log.info("authz_verifier: could not verify %s", ctx.domain)
            return []

        # Write verification to DB
        async with SessionLocal() as db:
            target = await db.get(Target, ctx.target_id)
            if target is not None:
                target.authorization_verified_at = datetime.now(timezone.utc)
                target.authorization_proof = "auto_verified"
                await db.commit()

        self._authz_state[0] = True
        log.info("authz_verifier: verified %s", ctx.domain)
        return []

    async def _try_http(self, domain: str, token: str) -> bool:
        url = f"http://{domain}/.well-known/recon-auth.txt"
        try:
            async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
                resp = await client.get(url)
            return resp.status_code == 200 and token in resp.text
        except Exception:
            return False

    async def _try_dns(self, domain: str, token: str) -> bool:
        dns_name = f"_recon-auth.{domain}"
        doh_url = f"https://cloudflare-dns.com/dns-query?name={dns_name}&type=TXT"
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(doh_url, headers={"accept": "application/dns-json"})
            if resp.status_code == 200:
                for ans in resp.json().get("Answer", []):
                    if token in (ans.get("data") or ""):
                        return True
        except Exception:
            pass
        return False
