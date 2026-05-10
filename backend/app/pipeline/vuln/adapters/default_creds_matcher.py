"""default_creds_matcher — flags services/tech known to ship with default creds.

Pure offline matcher. Reads service.product / technology.name from the
VulnStageContext and matches against bundled rules in
`data/default_creds_rules.json`. Emits one VulnRecord per (asset, rule) match.

Hard rule: this stage NEVER attempts authentication. It only reports the risk
that a default credential might exist. That is well-defined surface signal,
distinct from active credential testing (which would be intrusive).
"""

from __future__ import annotations

import json
import pathlib

from app.pipeline.vuln.stage import VulnEvidenceRecord, VulnRecord, VulnStageContext

_RULES_PATH = pathlib.Path(__file__).parent.parent / "data" / "default_creds_rules.json"


def _load_rules() -> list[dict]:
    with _RULES_PATH.open() as fh:
        return json.load(fh)


class DefaultCredsMatcherStage:
    name = "default_creds_matcher"
    source_tool = "default_creds_matcher"
    depends_on: list[str] = []
    weight = 5
    optional = True
    intrusive_required = False

    def applies(self, ctx: VulnStageContext) -> bool:
        return bool(ctx.services or ctx.technologies)

    async def execute_vuln(self, ctx: VulnStageContext) -> list[VulnRecord]:
        rules = _load_rules()
        records: list[VulnRecord] = []
        seen: set[tuple] = set()

        for rule in rules:
            if rule["match_type"] == "service":
                field = rule["match_field"]
                needle = rule["match_contains"].lower()
                for svc in ctx.services:
                    val = (getattr(svc, field, None) or "").lower()
                    if not val or needle not in val:
                        continue
                    key = (svc.asset_id, rule["title"])
                    if key in seen:
                        continue
                    seen.add(key)
                    canonical_key = f"defcreds:{needle}:{svc.id}"
                    records.append(
                        VulnRecord(
                            asset_id=svc.asset_id,
                            service_id=svc.id,
                            canonical_key=canonical_key,
                            title=rule["title"],
                            severity=rule["severity"],
                            description=rule["description"],
                            remediation=rule.get("remediation"),
                            evidence=VulnEvidenceRecord(
                                source_tool="default_creds_matcher",
                                matcher_name=f"service.{field}_contains",
                                extracted={"matched": val, "needle": needle},
                                confidence=60,
                            ),
                        )
                    )
            elif rule["match_type"] == "tech":
                field = rule["match_field"]
                needle = rule["match_contains"].lower()
                for tech in ctx.technologies:
                    val = (getattr(tech, field, None) or "").lower()
                    if not val or needle not in val:
                        continue
                    key = (tech.asset_id, rule["title"])
                    if key in seen:
                        continue
                    seen.add(key)
                    canonical_key = f"defcreds:{needle}:{tech.id}"
                    records.append(
                        VulnRecord(
                            asset_id=tech.asset_id,
                            technology_id=tech.id,
                            canonical_key=canonical_key,
                            title=rule["title"],
                            severity=rule["severity"],
                            description=rule["description"],
                            remediation=rule.get("remediation"),
                            evidence=VulnEvidenceRecord(
                                source_tool="default_creds_matcher",
                                matcher_name=f"tech.{field}_contains",
                                extracted={"matched": val, "needle": needle},
                                confidence=60,
                            ),
                        )
                    )

        return records
