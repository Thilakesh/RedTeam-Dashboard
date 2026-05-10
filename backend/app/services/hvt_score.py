from __future__ import annotations

SIGNAL_WEIGHTS: dict[str, float] = {
    "admin_panel":    0.85,
    "login_form":     0.40,
    "signup_form":    0.20,
    "upload_form":    0.50,
    "api_doc":        0.50,
    "dev_portal":     0.55,
    "jenkins":        0.95,
    "wordpress":      0.60,
    "gitlab":         0.85,
    "k8s_dashboard":  0.95,
    "exposed_index":  0.70,
    "swagger":        0.50,
    "graphql":        0.55,
    "git_repo":       0.90,
    "env_file":       0.95,
    "other":          0.30,
}

_DEFAULT_WEIGHT = 0.30


def compute_hvt_score(hvt_signals: list) -> float:
    """Return composite HVT score for an asset (0.0–1.0).

    hvt_signals: list[HvtSignal] (or any objects with .signal_type and .score).
    """
    if not hvt_signals:
        return 0.0
    total = 0.0
    for sig in hvt_signals:
        # Handle both str and HvtSignalType enum
        st = sig.signal_type.value if hasattr(sig.signal_type, "value") else str(sig.signal_type)
        weight = SIGNAL_WEIGHTS.get(st, _DEFAULT_WEIGHT)
        raw_score = sig.score if sig.score is not None else 0.5
        total += weight * max(0.0, min(1.0, raw_score))
    return min(1.0, total)
