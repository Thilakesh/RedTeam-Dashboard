"""pipeline/vuln/router.py — required_signals gate for vuln stages.

Evaluates a stage's `required_signals` list against a VulnStageContext.
Each token is a typed predicate; ALL must pass (AND logic). If the stage
has no `required_signals` attribute, the gate passes.

Called by run_vuln_dag instead of stage.applies() so the structured skip
reason is surfaced in SSE events as "no_matching_signals: <token>".
"""

from __future__ import annotations

import logging
import re
from typing import Any

from app.pipeline.vuln.stage import VulnStageContext

log = logging.getLogger(__name__)


def _eval_technology(ctx: VulnStageContext, name: str, version_op: str | None, version_val: str | None) -> bool:
    for tech in ctx.technologies:
        tech_name = (tech.name or "").lower()
        if tech_name != name.lower():
            continue
        if version_op is None:
            return True
        # Version comparison: only >= supported for now
        if version_op == ">=" and tech.version:
            try:
                from packaging.version import Version
                return Version(tech.version) >= Version(version_val)
            except Exception:
                return False
        log.warning("router: unsupported version operator %r in token — skipping", version_op)
        return False
    return False


def _eval_hvt_signal(ctx: VulnStageContext, signal_type: str, score_op: str | None, score_val: float | None) -> bool:
    for sig in ctx.hvt_signals:
        if str(sig.signal_type.value if hasattr(sig.signal_type, 'value') else sig.signal_type) != signal_type:
            continue
        if score_op is None:
            return True
        if score_op == ">=" and sig.score is not None and sig.score >= score_val:
            return True
    return False


def _eval_service_classification(ctx: VulnStageContext, cls: str) -> bool:
    for svc in ctx.services:
        svc_cls = str(svc.classification.value if hasattr(svc.classification, 'value') else svc.classification)
        if svc_cls == cls:
            return True
    return False


def _eval_service_product(ctx: VulnStageContext, product: str) -> bool:
    for svc in ctx.services:
        if svc.product and product.lower() in svc.product.lower():
            return True
    return False


def _eval_endpoint_flag(ctx: VulnStageContext, flag: str) -> bool:
    for ep in ctx.endpoints:
        if getattr(ep, flag, False):
            return True
    return False


def _eval_endpoint_path_regex(ctx: VulnStageContext, pattern: str) -> bool:
    try:
        rx = re.compile(pattern, re.I)
    except re.error:
        log.warning("router: invalid endpoint.path regex %r", pattern)
        return False
    for ep in ctx.endpoints:
        if ep.path and rx.search(ep.path):
            return True
    return False


def _eval_token(token: str, ctx: VulnStageContext) -> bool:
    """Evaluate a single required_signals token. Returns True if satisfied."""
    token = token.strip()

    # technology:{name}  or  technology:{name}:version>={ver}
    if token.startswith("technology:"):
        rest = token[len("technology:"):]
        parts = rest.split(":version>=", 1)
        name = parts[0]
        version_op, version_val = (">=", parts[1]) if len(parts) == 2 else (None, None)
        return _eval_technology(ctx, name, version_op, version_val)

    # hvt_signal:{type}  or  hvt_signal:{type}:score>={n}
    if token.startswith("hvt_signal:"):
        rest = token[len("hvt_signal:"):]
        parts = rest.split(":score>=", 1)
        signal_type = parts[0]
        score_op, score_val = (">=", float(parts[1])) if len(parts) == 2 else (None, None)
        return _eval_hvt_signal(ctx, signal_type, score_op, score_val)

    # service.classification:{cls}
    if token.startswith("service.classification:"):
        cls = token[len("service.classification:"):]
        return _eval_service_classification(ctx, cls)

    # service.product:{product}
    if token.startswith("service.product:"):
        product = token[len("service.product:"):]
        return _eval_service_product(ctx, product)

    # endpoint:is_api / endpoint:is_admin / endpoint:is_login etc.
    if token.startswith("endpoint:is_"):
        flag = token[len("endpoint:"):]  # e.g. "is_api"
        return _eval_endpoint_flag(ctx, flag)

    # endpoint.path~={regex}
    if token.startswith("endpoint.path~="):
        pattern = token[len("endpoint.path~="):]
        return _eval_endpoint_path_regex(ctx, pattern)

    log.warning("router: unrecognised token %r — treating as False", token)
    return False


def stage_applies(stage: Any, ctx: VulnStageContext) -> tuple[bool, str]:
    """Return (applies, reason).

    Checks:
      1. `stage.required_signals` — ALL tokens must pass.
      2. `stage.applies(ctx)` — legacy predicate, if present.

    Returns (False, reason_string) on first failure so the coordinator
    can surface the structured reason in the SSE 'stage.skipped' event.
    """
    required = getattr(stage, "required_signals", [])
    for token in required:
        if not _eval_token(token, ctx):
            return False, f"no_matching_signals: {token}"

    applies_fn = getattr(stage, "applies", None)
    if applies_fn is not None and not applies_fn(ctx):
        return False, "no_matching_inputs"

    return True, ""
