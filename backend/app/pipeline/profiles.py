from app.agents.risk_prioritizer import RiskPrioritizerStage
from app.pipeline.adapters.amass import AmassStage
from app.pipeline.adapters.asnmap import AsnmapStage
from app.pipeline.adapters.assetfinder import AssetfinderStage
from app.pipeline.adapters.bbot import BBOTStage
from app.pipeline.adapters.censys import CensysStage
from app.pipeline.adapters.dnsx import DnsxStage
from app.pipeline.adapters.geoip import GeoipStage
from app.pipeline.adapters.gowitness import GoWitnessStage
from app.pipeline.adapters.httpx import HttpxStage
from app.pipeline.adapters.naabu import NaabuStage
from app.pipeline.adapters.nmap import NmapStage
from app.pipeline.adapters.shodan import ShodanStage
from app.pipeline.adapters.subfinder import SubfinderStage
from app.pipeline.adapters.wafw00f import Wafw00fStage
from app.pipeline.stage import Stage

# DAG topology is implicit in each stage's `depends_on`. The coordinator computes
# execution levels:
#   L0: subfinder + assetfinder + censys + shodan (parallel passive enum)
#   L0: bbot (deep only, heavy-queue, parallel with L0)
#   L1: dnsx                    (resolves the deduped subdomain set)
#   L2: httpx + asnmap + geoip  (parallel — httpx hits hosts, asnmap+geoip enrich IPs)
#   L3: wafw00f                 (after httpx so we only fingerprint live services)
PROFILES: dict[str, list[Stage]] = {
    "quick": [SubfinderStage()],
    "standard": [
        SubfinderStage(),
        AssetfinderStage(),
        AmassStage(),
        CensysStage(),
        ShodanStage(),
        DnsxStage(),
        HttpxStage(),
        AsnmapStage(),
        GeoipStage(),
        Wafw00fStage(),
    ],
    "deep": [
        SubfinderStage(),
        AssetfinderStage(),
        AmassStage(),
        CensysStage(),
        ShodanStage(),
        BBOTStage(),
        DnsxStage(),
        HttpxStage(),
        AsnmapStage(),
        GeoipStage(),
        Wafw00fStage(),
        NaabuStage(),
        NmapStage(),
        GoWitnessStage(),
        RiskPrioritizerStage(),  # L7 — AI analysis, runs after all enrichment
    ],
}


def stages_for(profile: str, authz_state: list[bool] | None = None) -> list[Stage]:
    if profile not in PROFILES:
        raise ValueError(f"unknown profile: {profile}")
    stages = list(PROFILES[profile])
    if profile == "deep" and authz_state is not None:
        # Import here to avoid circular imports and keep module-level PROFILES dict clean.
        from app.pipeline.adapters.authz_verifier import AuthzVerifierStage  # noqa: PLC0415

        # Prepend authz verifier at L0 (no deps, runs alongside subfinder/assetfinder).
        stages = [AuthzVerifierStage(authz_state)] + stages
    return stages
