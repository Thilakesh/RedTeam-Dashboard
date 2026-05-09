"""Offline CPE -> CVE matcher.

Reads service.cpes (list of CPE strings) and technology.cpe (single CPE string)
from the VulnStageContext and matches them against bundled JSON rules using
substring matching. Returns one VulnRecord per unique (asset_id, cve_id) match.

Non-intrusive: no network calls.
"""

from __future__ import annotations

import json
import pathlib
from uuid import UUID

from app.pipeline.vuln.stage import VulnEvidenceRecord, VulnRecord, VulnStageContext

_RULES_PATH = pathlib.Path(__file__).parent.parent / "data" / "cpe_rules.json"


def _load_rules() -> list[dict]:
    with _RULES_PATH.open() as fh:
        return json.load(fh)


class CpeMatcherStage:
    name = "cpe_matcher"
    source_tool = "cpe_matcher"
    depends_on: list[str] = []
    weight = 10
    optional = True
    intrusive_required = False

    def applies(self, ctx: VulnStageContext) -> bool:
        return bool(ctx.services or ctx.technologies)

    async def execute_vuln(self, ctx: VulnStageContext) -> list[VulnRecord]:
        if not ctx.services and not ctx.technologies:
            return []

        rules = _load_rules()
        seen: set[tuple[UUID, str]] = set()
        records: list[VulnRecord] = []

        def _match_cpe(cpe_str: str, asset_id: UUID, service_id: UUID | None, tech_id: UUID | None) -> None:
            for rule in rules:
                if rule["cpe_contains"] not in cpe_str:
                    continue
                dedup_key = (asset_id, rule["cve_id"])
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)
                canonical_key = f"cve:{rule['cve_id']}:{asset_id}"
                records.append(
                    VulnRecord(
                        asset_id=asset_id,
                        canonical_key=canonical_key,
                        title=rule["title"],
                        severity=rule["severity"],
                        description=rule["description"],
                        evidence=VulnEvidenceRecord(
                            source_tool="cpe_matcher",
                            matcher_name="cpe_substring",
                            extracted={"cpe": cpe_str, "cpe_contains": rule["cpe_contains"]},
                            confidence=70,
                        ),
                        service_id=service_id,
                        technology_id=tech_id,
                        cve_ids=[rule["cve_id"]],
                        cwe_ids=rule.get("cwe_ids", []),
                        cvss_v3=rule.get("cvss_v3"),
                        remediation=rule.get("remediation"),
                    )
                )

        for svc in ctx.services:
            for cpe_str in (svc.cpes or []):
                _match_cpe(cpe_str, svc.asset_id, svc.id, None)

        for tech in ctx.technologies:
            if tech.cpe:
                _match_cpe(tech.cpe, tech.asset_id, None, tech.id)

        return records
