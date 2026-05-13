"""gitlab_probe — GitLab admin access + open registration detection.

Fires when hvt_signal:gitlab is present. Checks:
  1. /-/admin accessible unauthenticated -> CRITICAL (admin panel exposed)
  2. /users/sign_in with registration visible -> MED (open registration)
  3. /explore/projects visible unauthenticated -> LOW (project listing public)

Non-intrusive: read-only GETs. optional=True.
"""

from __future__ import annotations

import asyncio
import logging
from urllib.parse import urlparse, urlunparse

import httpx as _httpx

from app.pipeline.vuln.stage import VulnEvidenceRecord, VulnRecord, VulnStageContext

log = logging.getLogger(__name__)

_TIMEOUT = 8.0

_CHECKS = [
    {
        "path": "/-/admin",
        "indicators": ["admin area", "dashboard", "gitlab admin"],
        "title": "GitLab Admin Area Accessible Unauthenticated",
        "severity": "CRITICAL",
        "description": (
            "The GitLab admin area (/-/admin) is accessible without authentication. "
            "This allows complete administrative control over the GitLab instance, "
            "including user management, repository access, and system configuration."
        ),
        "remediation": (
            "Enable authentication requirements for the admin area. Ensure that "
            "GitLab is configured with `config.middleware.use OmniAuth::Builder` "
            "and that the admin panel is protected by the authentication layer. "
            "Review GitLab's 'Require authentication for admin area' setting."
        ),
        "canonical_suffix": "admin_unauth",
        "confidence": 90,
    },
    {
        "path": "/users/sign_in",
        "indicators": ["register", "sign up", "create account"],
        "title": "GitLab Open User Registration Enabled",
        "severity": "MED",
        "description": (
            "GitLab allows open user registration without administrator approval. "
            "Unauthenticated users can create accounts and potentially access "
            "internal repositories if they are set to 'Internal' visibility."
        ),
        "remediation": (
            "In GitLab Admin Area -> Settings -> General -> Sign-up restrictions, "
            "disable 'Sign-up enabled' or enable 'Require admin approval for new sign-ups'. "
            "Consider restricting sign-ups to specific email domains."
        ),
        "canonical_suffix": "open_registration",
        "confidence": 75,
    },
    {
        "path": "/explore/projects",
        "indicators": ["explore", "projects", "trending"],
        "title": "GitLab Public Project Listing Accessible",
        "severity": "LOW",
        "description": (
            "The GitLab project explore page is accessible without authentication, "
            "allowing enumeration of public and internal projects. "
            "Internal projects may be visible to unauthenticated users depending on configuration."
        ),
        "remediation": (
            "In GitLab Admin Area -> Settings -> General -> Visibility and access controls, "
            "set 'Default project visibility' to 'Private' and restrict the 'Explore' "
            "page to authenticated users."
        ),
        "canonical_suffix": "public_explore",
        "confidence": 70,
    },
]


def _build_url(base_url: str, path: str) -> str:
    parsed = urlparse(base_url)
    return urlunparse(parsed._replace(path=path, query="", fragment=""))


class GitlabProbeStage:
    name = "gitlab_probe"
    source_tool = "gitlab_probe"
    depends_on: list[str] = []
    required_signals: list[str] = ["hvt_signal:gitlab"]
    weight = 15
    optional = True
    intrusive_required = False

    def applies(self, ctx: VulnStageContext) -> bool:
        return bool(ctx.http_services)

    async def execute_vuln(self, ctx: VulnStageContext) -> list[VulnRecord]:
        if not ctx.http_services:
            return []

        records: list[VulnRecord] = []

        async def check_asset(asset) -> list[VulnRecord]:
            asset_records = []
            for chk in _CHECKS:
                url = _build_url(asset.canonical_key, chk["path"])
                try:
                    async with _httpx.AsyncClient(
                        timeout=_TIMEOUT, follow_redirects=True, verify=False
                    ) as client:
                        resp = await client.get(url)
                except Exception:
                    continue

                if resp.status_code != 200:
                    continue

                body_lower = resp.text.lower() if resp.text else ""
                indicators = chk.get("indicators", [])
                if indicators and not any(ind in body_lower for ind in indicators):
                    continue

                asset_records.append(VulnRecord(
                    asset_id=asset.id,
                    canonical_key=f"gitlab:{chk['canonical_suffix']}:{asset.id}",
                    title=chk["title"],
                    severity=chk["severity"],
                    description=chk["description"],
                    remediation=chk["remediation"],
                    evidence=VulnEvidenceRecord(
                        source_tool="gitlab_probe",
                        request=f"GET {url}",
                        response_excerpt=resp.text[:500] if resp.text else None,
                        matcher_name=chk["canonical_suffix"],
                        extracted={"url": url, "status_code": resp.status_code},
                        confidence=chk["confidence"],
                    ),
                ))
            return asset_records

        results = await asyncio.gather(*(check_asset(a) for a in ctx.http_services))
        for batch in results:
            records.extend(batch)

        return records
