import pytest


def test_all_zero_inputs_returns_zero():
    from app.services.risk_score import compute_risk
    scores = compute_risk(
        cvss_v3=None, epss=None, kev=False,
        exposure_score=0.0, hvt_score=0.0, blast_radius_score=0.0,
    )
    assert scores["risk_score"] == 0.0


def test_perfect_inputs_returns_one():
    from app.services.risk_score import compute_risk
    scores = compute_risk(
        cvss_v3=10.0, epss=1.0, kev=True,
        exposure_score=1.0, hvt_score=1.0, blast_radius_score=1.0,
    )
    assert abs(scores["risk_score"] - 1.0) < 1e-6


def test_kev_bump_adds_015():
    from app.services.risk_score import compute_risk
    without_kev = compute_risk(
        cvss_v3=7.0, epss=0.5, kev=False,
        exposure_score=0.5, hvt_score=0.5, blast_radius_score=0.5,
    )
    with_kev = compute_risk(
        cvss_v3=7.0, epss=0.5, kev=True,
        exposure_score=0.5, hvt_score=0.5, blast_radius_score=0.5,
    )
    diff = with_kev["risk_score"] - without_kev["risk_score"]
    assert abs(diff - 0.15) < 1e-6


def test_result_keys_present():
    from app.services.risk_score import compute_risk
    scores = compute_risk(
        cvss_v3=5.0, epss=0.1, kev=False,
        exposure_score=0.5, hvt_score=0.3, blast_radius_score=0.2,
    )
    assert "risk_score" in scores
    assert "exposure_score" in scores
    assert "exploitability_score" in scores
    assert "blast_radius_score" in scores


def test_compute_exposure_score_web_port():
    from app.services.risk_score import compute_exposure_score
    svc = type("S", (), {"port": 443})()
    assert compute_exposure_score([svc]) == 1.0


def test_compute_exposure_score_db_port():
    from app.services.risk_score import compute_exposure_score
    svc = type("S", (), {"port": 5432})()
    assert compute_exposure_score([svc]) == 0.2


def test_compute_exposure_score_empty():
    from app.services.risk_score import compute_exposure_score
    assert compute_exposure_score([]) == 0.5


def test_compute_blast_radius_score_five_services():
    from app.services.risk_score import compute_blast_radius_score
    svcs = [object() for _ in range(5)]
    assert compute_blast_radius_score(svcs) == 1.0


def test_compute_blast_radius_score_one_service():
    from app.services.risk_score import compute_blast_radius_score
    assert abs(compute_blast_radius_score([object()]) - 0.2) < 1e-6
