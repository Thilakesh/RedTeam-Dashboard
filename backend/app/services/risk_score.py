"""Composite risk score for a Vulnerability.

Pure functions — no DB, no async. The correlator_engine calls these for each
vulnerability after loading service and HVT context from VulnStageContext.
"""
from __future__ import annotations

# Ports that indicate a publicly-facing web service
_WEB_PORTS = frozenset({80, 443, 8080, 8443, 8000, 8888, 3000})
# Ports that indicate an internal/backend service (lower exposure)
_INTERNAL_PORTS = frozenset({
    3306, 5432, 1433, 1521, 27017, 6379, 9042, 5984, 7474,  # databases
    5672, 15672, 9092, 1883, 61616,                          # messaging
    11211,                                                   # cache
})


def compute_exposure_score(services_for_asset: list) -> float:
    """Return 0.0–1.0 exposure score for an asset.

    services_for_asset: list[Service] — services whose asset_id matches the vuln's asset_id.
    """
    if not services_for_asset:
        return 0.5   # unknown exposure
    ports = {svc.port for svc in services_for_asset}
    if ports & _WEB_PORTS:
        return 1.0
    if ports & _INTERNAL_PORTS:
        return 0.2
    return 0.5


def compute_blast_radius_score(services_for_asset: list) -> float:
    """Return 0.0–1.0 blast radius score.

    Simple proxy: number of services on the same asset / 5, capped at 1.0.
    An asset with 5+ services is maximally exposed; a single-service asset scores 0.2.
    """
    return min(1.0, len(services_for_asset) / 5.0)


def compute_risk(
    *,
    cvss_v3: float | None,
    epss: float | None,
    kev: bool,
    exposure_score: float,
    hvt_score: float,
    blast_radius_score: float,
) -> dict[str, float]:
    """Compute composite risk score from pre-computed component values.

    Returns a dict with risk_score, exposure_score, exploitability_score,
    blast_radius_score — keys matching Vulnerability ORM column names.

    Formula (weights sum to 1.0):
        0.30 * cvss_normalized
        0.20 * epss
        0.15 * kev_bump
        0.15 * exposure_score
        0.10 * hvt_score
        0.10 * blast_radius_score
    """
    cvss_norm = (cvss_v3 or 0.0) / 10.0
    epss_val = epss or 0.0
    kev_bump = 1.0 if kev else 0.0

    risk = (
        0.30 * cvss_norm
        + 0.20 * epss_val
        + 0.15 * kev_bump
        + 0.15 * exposure_score
        + 0.10 * hvt_score
        + 0.10 * blast_radius_score
    )
    # exploitability_score combines cvss + epss as a proxy for ease-of-exploit
    exploitability = min(1.0, 0.60 * cvss_norm + 0.40 * epss_val)

    return {
        "risk_score": min(1.0, max(0.0, risk)),
        "exposure_score": exposure_score,
        "exploitability_score": exploitability,
        "blast_radius_score": blast_radius_score,
    }
