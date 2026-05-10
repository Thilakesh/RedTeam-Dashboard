"""ai_triage — LLM rationale + remediation for newly detected vulns.

Reads the top-N "new" vulnerabilities from the current scan's run-matches and
asks an LLM to write a one-paragraph rationale and a one-sentence remediation
per vuln. Updates Vulnerability.remediation in place and writes an ai_usage
row for cost accounting.

Reuses the bounded_completion wrapper for timeout/JSON-mode/error handling.
Stage is optional=True; coordinator handles BoundedCompletionError. Writes
directly to the DB (documented exception, same as RiskPrioritizerStage).
"""

from __future__ import annotations

import json
import logging
from uuid import uuid4

from sqlalchemy import select

from app.agents.bounded_completion import bounded_completion
from app.core.db import SessionLocal
from app.models.ai_usage import AiUsage
from app.models.vulnerability import Vulnerability
from app.models.vuln_run_match import VulnRunMatch
from app.pipeline.vuln.stage import VulnRecord, VulnStageContext

log = logging.getLogger(__name__)

_MODEL = "openai/gpt-oss-20b:free"
_MAX_VULNS = 30  # cap per scan for token budget

SYSTEM_PROMPT = """You are a vulnerability triage analyst. For each input vulnerability
return a JSON object with key "items", a list where each item has:
  id            string  (echo back unchanged)
  rationale     string  one paragraph: why this matters in the asset's context
  remediation   string  one imperative sentence with a concrete fix

Be concrete. Cite the affected component/version when given. Do not invent CVEs."""


class AiTriageStage:
    name = "ai_triage"
    source_tool = "ai_triage"
    depends_on = ["correlator"]
    weight = 15
    optional = True
    intrusive_required = False

    async def execute_vuln(self, ctx: VulnStageContext) -> list[VulnRecord]:
        async with SessionLocal() as db:
            # Pull "new" vulns from this scan's run matches
            rows = (await db.execute(
                select(Vulnerability)
                .join(VulnRunMatch, VulnRunMatch.vulnerability_id == Vulnerability.id)
                .where(
                    VulnRunMatch.scan_id == ctx.scan_id,
                    VulnRunMatch.state == "new",
                )
                .limit(_MAX_VULNS)
            )).scalars().all()

            if not rows:
                return []

            payload = [
                {
                    "id": str(v.id),
                    "title": v.title,
                    "severity": str(v.severity.value if hasattr(v.severity, "value") else v.severity),
                    "description": v.description[:600],
                    "cve_ids": list(v.cve_ids or []),
                    "template_id": v.template_id,
                }
                for v in rows
            ]
            id_to_vuln = {str(v.id): v for v in rows}

        try:
            result = await bounded_completion(
                system=SYSTEM_PROMPT,
                user=json.dumps(payload),
                model=_MODEL,
                max_input_chars=30_000,
                timeout=120.0,
            )
        except Exception as exc:
            log.warning("ai_triage: bounded_completion failed: %s", exc)
            return []

        items = (result.content or {}).get("items") or []
        if not isinstance(items, list):
            return []

        async with SessionLocal() as db:
            updated = 0
            for it in items:
                vid = str(it.get("id") or "")
                if vid not in id_to_vuln:
                    continue
                rationale = str(it.get("rationale", "")).strip()
                remediation = str(it.get("remediation", "")).strip()
                # Compose remediation field (rationale + one-line fix)
                merged = remediation
                if rationale:
                    merged = f"{rationale}\n\nFix: {remediation}" if remediation else rationale
                if not merged:
                    continue
                v = await db.get(Vulnerability, id_to_vuln[vid].id)
                if v is not None:
                    v.remediation = merged[:4000]
                    updated += 1

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
            log.info("ai_triage: updated remediation on %d vulns", updated)

        return []
