"""RiskPrioritizerStage — ranks recon assets by attack-surface risk using an LLM.

Design notes:
- Two separate `async with SessionLocal() as db:` blocks are used intentionally.
  The first block reads scan data (subdomain/port rows). It is closed before the
  LLM call so we don't hold a DB connection open during the network round-trip
  (which can take up to 120 seconds). The second block writes findings after the
  LLM responds, keeping the write transaction as short as possible.
- BoundedCompletionError is NOT caught here. The stage is registered as
  optional=True; the DAG coordinator handles optional-stage failures. Swallowing
  the error in the stage would hide configuration problems (missing API key etc.)
  from the coordinator's logging.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from sqlalchemy import delete

from app.agents.bounded_completion import BoundedCompletionError, bounded_completion  # noqa: F401  (re-exported for patch target)
from app.core.db import SessionLocal
from app.models.ai_usage import AiUsage
from app.models.finding import Finding, FindingSeverity
from app.pipeline.stage import AssetRecord, StageContext
from app.services.scan_view import build_port_rows, build_subdomain_rows

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# LLM system prompt — static, never user-controllable.
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = """You are a security analyst ranking reconnaissance findings by attack-surface risk.

Given a JSON list of assets from a deep scan, return a JSON object with key
"findings" containing ALL assets ranked from highest to lowest risk.

For each asset output exactly these fields:
  fqdn              string   (copy from input, unchanged)
  severity          string   HIGH | MED | LOW | INFO
  risk_score        float    0.0-1.0 (higher = more critical)
  priority_rank     integer  1=highest risk, contiguous integers, no gaps or duplicates
  rationale         string   1-2 sentences explaining the specific risk
  signals           array    short snake_case tags e.g. ["no_waf","open_admin_port"]
  recommended_action string  one imperative sentence

Ranking criteria (highest weight first):
  - Exposed admin or login interfaces (path or subdomain contains admin, login, dashboard)
  - Missing WAF on a live HTTP service (waf field is null or empty)
  - Outdated or known-vulnerable server software (server field contains version numbers)
  - Open non-standard ports (ports other than 80, 443)
  - Recently appeared assets (first_seen_days_ago < 7)
  - No CDN fronting on a direct-IP asset (cdn is false and no cdn_name)

Every asset in the input MUST appear in the output exactly once.
Severity should reflect genuine risk: not everything is HIGH or MED."""

# Model to call via OpenRouter.
_MODEL = "openai/gpt-oss-20b:free"


class RiskPrioritizerStage:
    """Ranks all subdomain assets for a scan by attack-surface risk."""

    name = "risk_prioritizer"
    source_tool = "risk_prioritizer"
    depends_on = ["gowitness"]
    inputs: list[str] = []
    outputs: list[str] = []
    weight = 15
    optional = True
    authz_required = False

    async def execute(self, ctx: StageContext) -> list[AssetRecord]:
        # ------------------------------------------------------------------
        # Block 1: Read scan data. Connection closed before the LLM call.
        # ------------------------------------------------------------------
        async with SessionLocal() as db:
            subdomain_rows = await build_subdomain_rows(db, ctx.scan_id)
            port_rows = await build_port_rows(db, ctx.scan_id)

        if not subdomain_rows:
            logger.info("risk_prioritizer: no subdomain rows for scan %s — skipping", ctx.scan_id)
            return []

        # Build hallucination guard: fqdn → row (keyed lowercase for case-insensitive guard)
        asset_index: dict[str, Any] = {row.subdomain.lower(): row for row in subdomain_rows}

        # Build port lookup: host fqdn → ["80/tcp", "443/tcp", ...]
        port_lookup: dict[str, list[str]] = {}
        for pr in port_rows:
            port_lookup.setdefault(pr.host, []).append(f"{pr.port}/{pr.proto}")

        # Serialize assets for LLM
        now = datetime.now(timezone.utc)
        asset_list = []
        for row in subdomain_rows:
            first_seen_days: int | None = None
            if row.first_seen:
                first_seen_days = (now - row.first_seen).days if row.first_seen.tzinfo else (now - row.first_seen.replace(tzinfo=timezone.utc)).days
            asset_list.append({
                "fqdn": row.subdomain,
                "http_status": row.http_status,
                "waf": row.waf,
                "waf_conf": row.waf_conf,
                "cdn": row.cdn,
                "cdn_name": row.cdn_name,
                "tech": row.tech,
                "server": row.server,
                "screenshot_url": row.screenshot_url,
                "open_ports": port_lookup.get(row.subdomain, []),
                "first_seen_days_ago": first_seen_days,
            })

        # ------------------------------------------------------------------
        # LLM call — BoundedCompletionError propagates to the coordinator.
        # ------------------------------------------------------------------
        result = await bounded_completion(
            system=SYSTEM_PROMPT,
            user=json.dumps(asset_list),
            model=_MODEL,
            max_input_chars=40_000,
            timeout=120.0,
        )

        # ------------------------------------------------------------------
        # Parse and validate LLM response
        # ------------------------------------------------------------------
        raw_content = result.content
        if not isinstance(raw_content, dict):
            logger.warning("risk_prioritizer: unexpected non-dict content from LLM, skipping")
            return []
        raw_findings: list[dict] = raw_content.get("findings") or []

        valid: list[dict] = []
        for item in raw_findings:
            fqdn = (item.get("fqdn") or "").lower()
            if not fqdn:
                continue
            if fqdn not in asset_index:
                logger.warning(
                    "risk_prioritizer: LLM returned hallucinated fqdn %r for scan %s — dropping",
                    fqdn,
                    ctx.scan_id,
                )
                continue
            # Store the normalized fqdn back so the write block uses the correct key
            item["fqdn"] = fqdn
            valid.append(item)

        # Sort by risk_score DESC and re-assign contiguous priority ranks
        valid.sort(key=lambda x: float(x.get("risk_score") or 0.0), reverse=True)
        for rank, item in enumerate(valid, start=1):
            item["priority_rank"] = rank

        # ------------------------------------------------------------------
        # Block 2: Write findings. Short transaction, no LLM wait inside.
        # ------------------------------------------------------------------
        async with SessionLocal() as db:
            # Idempotent — delete previous findings for this scan before writing
            await db.execute(delete(Finding).where(Finding.scan_id == ctx.scan_id))

            for item in valid:
                fqdn = item["fqdn"]
                row = asset_index[fqdn]

                severity_str = str(item.get("severity", "INFO")).upper()
                try:
                    severity = FindingSeverity[severity_str]
                except KeyError:
                    severity = FindingSeverity.INFO

                db.add(
                    Finding(
                        id=uuid4(),
                        scan_id=ctx.scan_id,
                        asset_id=row.asset_id,
                        severity=severity,
                        priority_rank=item["priority_rank"],
                        risk_score=float(item.get("risk_score") or 0.0),
                        rationale=str(item.get("rationale", "")),
                        signals=list(item.get("signals", [])),
                        recommended_action=str(item.get("recommended_action", "")),
                        source="llm",
                    )
                )

            db.add(
                AiUsage(
                    id=uuid4(),
                    scan_id=ctx.scan_id,
                    model=_MODEL,
                    prompt_tokens=result.prompt_tokens,
                    completion_tokens=result.completion_tokens,
                )
            )

            await db.commit()

        return []
