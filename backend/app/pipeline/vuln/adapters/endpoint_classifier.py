"""endpoint_classifier — heuristic flagging on already-discovered endpoints.

Pure-python pass: walks the endpoints table for the target and sets the
is_login / is_signup / is_upload / is_api / is_admin flags from URL path
pattern matching. No subprocess, no network calls.

Runs after katana / swagger_discoverer at Level 1. The flags drive UI filters
and the conditional execution router (e.g. nuclei stages can declare
required_signals=["endpoint:is_admin"]).
"""

from __future__ import annotations

import logging
import re
from urllib.parse import urlparse

from sqlalchemy import select, update

from app.core.db import SessionLocal
from app.models.endpoint import Endpoint
from app.pipeline.vuln.stage import VulnRecord, VulnStageContext

log = logging.getLogger(__name__)

# Path-pattern → flag-name. Patterns are case-insensitive substring/regex matches.
_LOGIN_PATTERNS = [
    re.compile(r"/(login|signin|sign-in|auth/login|sso|oauth)\b", re.I),
    re.compile(r"/wp-login\.php", re.I),
]
_SIGNUP_PATTERNS = [
    re.compile(r"/(signup|sign-up|register|registration|create-?account)\b", re.I),
]
_UPLOAD_PATTERNS = [
    re.compile(r"/(upload|fileupload|file-upload|media/upload)\b", re.I),
]
_API_PATTERNS = [
    re.compile(r"/(api|v1|v2|v3|graphql|rest)/", re.I),
    re.compile(r"/(openapi\.json|swagger\.json|api-docs|swagger-ui|swagger\.yaml)", re.I),
]
_ADMIN_PATTERNS = [
    re.compile(r"/(admin|manage|management|dashboard|console|control)\b", re.I),
    re.compile(r"/(wp-admin|administrator|phpmyadmin)\b", re.I),
]


def _classify(path: str) -> dict[str, bool]:
    flags = {
        "is_login": any(p.search(path) for p in _LOGIN_PATTERNS),
        "is_signup": any(p.search(path) for p in _SIGNUP_PATTERNS),
        "is_upload": any(p.search(path) for p in _UPLOAD_PATTERNS),
        "is_api": any(p.search(path) for p in _API_PATTERNS),
        "is_admin": any(p.search(path) for p in _ADMIN_PATTERNS),
    }
    return flags


class EndpointClassifierStage:
    name = "endpoint_classifier"
    source_tool = "endpoint_classifier"
    depends_on = ["katana"]
    weight = 5
    optional = True
    intrusive_required = False

    def applies(self, ctx: VulnStageContext) -> bool:
        # The katana stage may have just written endpoints in this run; we rely
        # on a fresh DB query rather than ctx (which is the pre-scan snapshot).
        return True

    async def execute_vuln(self, ctx: VulnStageContext) -> list[VulnRecord]:
        async with SessionLocal() as db:
            rows = (await db.execute(
                select(Endpoint.id, Endpoint.path, Endpoint.url).where(
                    Endpoint.target_id == ctx.target_id,
                )
            )).all()
            updated = 0
            for eid, path, url in rows:
                # Use path if set, fall back to URL parse
                p = path or urlparse(url).path or "/"
                flags = _classify(p)
                if not any(flags.values()):
                    continue
                # Update only when at least one flag fires (cheap idempotent OR).
                await db.execute(
                    update(Endpoint)
                    .where(Endpoint.id == eid)
                    .values(**flags)
                )
                updated += 1
            await db.commit()
            log.info("endpoint_classifier: flagged %d endpoints", updated)
        return []
