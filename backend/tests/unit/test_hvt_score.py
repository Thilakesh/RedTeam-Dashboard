from unittest.mock import MagicMock
import pytest


def _sig(signal_type: str, score=0.5, confidence: int = 80) -> MagicMock:
    s = MagicMock()
    s.signal_type = signal_type  # plain string
    s.score = score
    s.confidence = confidence
    return s


def test_empty_signals_returns_zero():
    from app.services.hvt_score import compute_hvt_score
    assert compute_hvt_score([]) == 0.0


def test_known_signal_type_applies_weight():
    from app.services.hvt_score import compute_hvt_score, SIGNAL_WEIGHTS
    sig = _sig("jenkins", score=1.0, confidence=100)
    result = compute_hvt_score([sig])
    assert abs(result - SIGNAL_WEIGHTS["jenkins"]) < 1e-6


def test_capped_at_one():
    from app.services.hvt_score import compute_hvt_score
    sigs = [_sig("jenkins", 1.0), _sig("git_repo", 1.0), _sig("env_file", 1.0)]
    assert compute_hvt_score(sigs) == 1.0


def test_unknown_signal_type_uses_default_weight():
    from app.services.hvt_score import compute_hvt_score
    sig = _sig("totally_unknown_type", score=1.0)
    result = compute_hvt_score([sig])
    assert 0.0 < result <= 0.35


def test_null_score_treated_as_half():
    from app.services.hvt_score import compute_hvt_score, SIGNAL_WEIGHTS
    sig = _sig("admin_panel", score=None)
    result = compute_hvt_score([sig])
    expected = SIGNAL_WEIGHTS["admin_panel"] * 0.5
    assert abs(result - expected) < 1e-6
