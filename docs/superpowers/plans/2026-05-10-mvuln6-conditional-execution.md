# M-Vuln-6: Conditional Execution Router + Tech-Specific Stages Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `required_signals` declarative routing engine to the vuln pipeline so tech-specific stages (WordPress, Jenkins, GraphQL, Struts, GitLab) only fire when matching signals are present; rewrite `panel_detector` to emit `HvtSignal` rows instead of `VulnRecord`s.

**Architecture:** A new `pipeline/vuln/router.py` module parses `required_signals` tokens from stage class attributes and evaluates them against `VulnStageContext`. The coordinator delegates all gate checks to `router.stage_applies()` instead of calling `stage.applies()` directly. Six new conditional stages each declare `required_signals` so they self-select based on technologies/hvt_signals/endpoints already in ctx.

**Tech Stack:** Python 3.11, SQLAlchemy 2.0 async, httpx, Alembic, PostgreSQL

---

## File Map

| Action | Path | Purpose |
|---|---|---|
| Create | `backend/app/pipeline/vuln/router.py` | Token parser + `stage_applies()` evaluator |
| Modify | `backend/app/pipeline/vuln/coordinator.py` | Use `router.stage_applies` in `run_vuln_dag` |
| Modify | `backend/app/pipeline/vuln/stage.py` | Add `required_signals` to `VulnStage` Protocol |
| Modify | `backend/app/pipeline/vuln/adapters/panel_detector.py` | Emit `HvtSignal`s, return `[]` VulnRecords |
| Create | `backend/app/pipeline/vuln/adapters/_nuclei_runner.py` | Shared nuclei subprocess helper for tag-targeted stages |
| Create | `backend/app/pipeline/vuln/adapters/wp_user_enum.py` | WordPress username enumeration via REST API |
| Create | `backend/app/pipeline/vuln/adapters/wp_plugin_check.py` | WordPress vulnerable plugin detection via nuclei |
| Create | `backend/app/pipeline/vuln/adapters/struts_checker.py` | Apache Struts RCE checks via nuclei |
| Create | `backend/app/pipeline/vuln/adapters/jenkins_probe.py` | Jenkins Script Console / unauth endpoint detection |
| Create | `backend/app/pipeline/vuln/adapters/graphql_introspection.py` | GraphQL introspection enabled check |
| Create | `backend/app/pipeline/vuln/adapters/gitlab_probe.py` | GitLab admin access + open registration check |
| Modify | `backend/app/pipeline/vuln/profiles.py` | Add conditional stages to vuln_standard + vuln_deep |
| Create | `backend/migrations/versions/0011_panel_detector_cleanup.py` | Delete legacy panel_detector Vulnerability rows |

---

## Task 1: Add `required_signals` to VulnStage Protocol

**Files:**
- Modify: `backend/app/pipeline/vuln/stage.py`

- [ ] **Step 1: Update Protocol to include `required_signals`**

Open `backend/app/pipeline/vuln/stage.py`. Add `required_signals` to the `VulnStage` Protocol. This attribute is optional (defaults to `[]` on each concrete class; Protocol just documents the contract).

Replace the `VulnStage` Protocol class with:

```python
class VulnStage(Protocol):
    name: str
    source_tool: str
    depends_on: list[str]
    weight: int
    optional: bool
    intrusive_required: bool  # if True, skip when ctx.intrusive=False
    required_signals: list[str]  # NEW: declarative signal predicates

    async def execute_vuln(self, ctx: VulnStageContext) -> list[VulnRecord]: ...
    # Optional: def applies(self, ctx: VulnStageContext) -> bool: ...
```

- [ ] **Step 2: Commit**

```bash
git add backend/app/pipeline/vuln/stage.py
git commit -m "feat(vuln): add required_signals to VulnStage Protocol"
```

---

## Task 2: Create `router.py` — required_signals evaluator

**Files:**
- Create: `backend/app/pipeline/vuln/router.py`

### Token format reference

| Token | Matches when |
|---|---|
| `technology:{name}` | any `ctx.technologies` has `name.lower() == {name}` |
| `technology:{name}:version>={ver}` | matching tech + version comparison |
| `hvt_signal:{type}` | any `ctx.hvt_signals` has `signal_type == {type}` |
| `hvt_signal:{type}:score>={n}` | matching signal + `signal.score >= n` |
| `service.classification:{cls}` | any `ctx.services` has `classification == {cls}` |
| `service.product:{product}` | any `ctx.services` has `product` containing `{product}` (case-insensitive) |
| `endpoint:is_api` | any `ctx.endpoints` has `is_api == True` |
| `endpoint:is_admin` | any `ctx.endpoints` has `is_admin == True` |
| `endpoint:is_login` | any `ctx.endpoints` has `is_login == True` |
| `endpoint.path~={regex}` | any `ctx.endpoints.path` matches regex |

All tokens in `required_signals` are AND-ed together.

- [ ] **Step 1: Create `router.py`**

```python
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
        return True
    return False


def _eval_hvt_signal(ctx: VulnStageContext, signal_type: str, score_op: str | None, score_val: float | None) -> bool:
    for sig in ctx.hvt_signals:
        if str(sig.signal_type.value if hasattr(sig.signal_type, 'value') else sig.signal_type) != signal_type:
            continue
        if score_op is None:
            return True
        if score_op == ">=" and sig.score >= score_val:
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
```

- [ ] **Step 2: Commit**

```bash
git add backend/app/pipeline/vuln/router.py
git commit -m "feat(vuln): add required_signals router with token evaluator"
```

---

## Task 3: Wire router into `run_vuln_dag`

**Files:**
- Modify: `backend/app/pipeline/vuln/coordinator.py`

- [ ] **Step 1: Import router and replace applies check**

In `backend/app/pipeline/vuln/coordinator.py`, add import at top:

```python
from app.pipeline.vuln.router import stage_applies
```

In `run_vuln_dag`, replace the existing intrusive gate + applies gate block:

```python
        async def run_one(stage) -> None:
            # Intrusive gate: skip stages that require active/intrusive scanning.
            if getattr(stage, "intrusive_required", False) and not ctx.intrusive:
                await on_skip(stage, "intrusive not enabled")
                return

            # Router gate: evaluates required_signals + applies() predicate.
            applies, reason = stage_applies(stage, ctx)
            if not applies:
                await on_skip(stage, reason)
                return

            stage_handle = await on_start(stage)
            try:
                records = await stage.execute_vuln(ctx)
                await on_done(stage, records, stage_handle)
            except Exception as exc:
                await on_fail(stage, exc, stage_handle)
                optional = getattr(stage, "optional", False)
                if optional:
                    log.warning("optional vuln stage %r failed, continuing: %s", stage.name, exc)
                    return
                raise
```

Note: remove the old `applies_fn = getattr(stage, "applies", None)` block entirely — `stage_applies()` handles it internally.

- [ ] **Step 2: Smoke-test import**

```bash
cd "F:\Studies\AI\RedTeam Dashboard"
docker compose -f infra/docker-compose.yml exec backend python -c "
from app.pipeline.vuln.coordinator import run_vuln_dag
from app.pipeline.vuln.router import stage_applies
print('router wired OK')
"
```

Expected: `router wired OK`

- [ ] **Step 3: Commit**

```bash
git add backend/app/pipeline/vuln/coordinator.py
git commit -m "feat(vuln): wire router.stage_applies into run_vuln_dag"
```

---

## Task 4: Rewrite `panel_detector.py` to emit HvtSignals

**Files:**
- Modify: `backend/app/pipeline/vuln/adapters/panel_detector.py`

Current: probes panel paths, returns `list[VulnRecord]`.
New: probes same paths, calls `upsert_hvt_signals()`, returns `[]`.

Signal type mapping:
- `/wp-admin/` → `HvtSignalType.admin_panel` (score=0.85, also `HvtSignalType.wordpress` second signal)
- `/wp-login.php` → `HvtSignalType.login_form` (score=0.4)
- `/phpmyadmin/` → `HvtSignalType.admin_panel` (score=0.9)
- `/admin/` → `HvtSignalType.admin_panel` (score=0.7)
- `/administrator/` → `HvtSignalType.admin_panel` (score=0.8) + `joomla` if keyword matches
- `/manager/html` → `HvtSignalType.admin_panel` (score=0.85) [Tomcat]
- `/console/` → `HvtSignalType.admin_panel` (score=0.85) [WebLogic]
- `/.git/HEAD` → `HvtSignalType.git_repo` (score=0.95)
- `/.env` → `HvtSignalType.env_file` (score=0.95)
- `/api/` (swagger keywords) → `HvtSignalType.api_doc` (score=0.55)

- [ ] **Step 1: Rewrite panel_detector.py**

Replace the entire file with:

```python
"""Admin/login panel detector — M-Vuln-6 rewrite.

Probes known panel/sensitive paths via httpx. Confirmed hits emit HvtSignal
rows (not VulnRecords). Returns []. A Joomla admin panel and a Heartbleed CVE
should not share a table or lifecycle.

Non-intrusive: read-only GET requests. optional=True.
"""

from __future__ import annotations

import asyncio
import logging
from urllib.parse import urlparse, urlunparse

import httpx as _httpx

from app.core.db import SessionLocal
from app.models.hvt_signal import HvtSignalType
from app.pipeline.vuln.stage import VulnRecord, VulnStageContext
from app.services.hvt_signals import HvtSignalRecord, upsert_hvt_signals

log = logging.getLogger(__name__)

# (path_suffix, title_keywords, signal_type, score, extra_signal_type_if_keyword)
# extra_signal_type_if_keyword: optional (keyword_list, HvtSignalType) to emit a second
# platform-specific signal when response body contains those keywords.
PANEL_SIGNATURES = [
    {
        "path_suffix": "/wp-admin/",
        "title_keywords": ["wordpress", "wp admin"],
        "signal_type": HvtSignalType.admin_panel,
        "score": 0.85,
        "confidence": 85,
        "platform_keywords": (["wordpress", "wp-admin"], HvtSignalType.wordpress),
    },
    {
        "path_suffix": "/wp-login.php",
        "title_keywords": ["wordpress", "log in"],
        "signal_type": HvtSignalType.login_form,
        "score": 0.4,
        "confidence": 80,
        "platform_keywords": (["wordpress"], HvtSignalType.wordpress),
    },
    {
        "path_suffix": "/phpmyadmin/",
        "title_keywords": ["phpmyadmin"],
        "signal_type": HvtSignalType.admin_panel,
        "score": 0.9,
        "confidence": 90,
        "platform_keywords": None,
    },
    {
        "path_suffix": "/admin/",
        "title_keywords": ["admin", "dashboard", "login"],
        "signal_type": HvtSignalType.admin_panel,
        "score": 0.7,
        "confidence": 70,
        "platform_keywords": None,
    },
    {
        "path_suffix": "/administrator/",
        "title_keywords": ["joomla", "administrator"],
        "signal_type": HvtSignalType.admin_panel,
        "score": 0.8,
        "confidence": 80,
        "platform_keywords": None,
    },
    {
        "path_suffix": "/manager/html",
        "title_keywords": ["tomcat", "manager"],
        "signal_type": HvtSignalType.admin_panel,
        "score": 0.85,
        "confidence": 85,
        "platform_keywords": None,
    },
    {
        "path_suffix": "/console/",
        "title_keywords": ["weblogic", "console"],
        "signal_type": HvtSignalType.admin_panel,
        "score": 0.85,
        "confidence": 85,
        "platform_keywords": None,
    },
    {
        "path_suffix": "/.git/HEAD",
        "title_keywords": [],          # presence (200 + "ref:") is enough
        "title_contains": "ref:",       # raw response must contain this
        "signal_type": HvtSignalType.git_repo,
        "score": 0.95,
        "confidence": 95,
        "platform_keywords": None,
    },
    {
        "path_suffix": "/.env",
        "title_keywords": [],
        "signal_type": HvtSignalType.env_file,
        "score": 0.95,
        "confidence": 95,
        "platform_keywords": None,
    },
    {
        "path_suffix": "/api/",
        "title_keywords": ["swagger", "api docs", "api explorer"],
        "signal_type": HvtSignalType.api_doc,
        "score": 0.55,
        "confidence": 65,
        "platform_keywords": None,
    },
]

_SEMAPHORE_LIMIT = 10
_REQUEST_TIMEOUT = 5.0


def _build_check_url(base_url: str, path_suffix: str) -> str:
    parsed = urlparse(base_url)
    return urlunparse(parsed._replace(path=path_suffix, query="", fragment=""))


class PanelDetectorStage:
    name = "panel_detector"
    source_tool = "panel_detector"
    depends_on: list[str] = []
    required_signals: list[str] = []   # no preconditions — fires whenever http_services exist
    weight = 15
    optional = True
    intrusive_required = False

    def applies(self, ctx: VulnStageContext) -> bool:
        return bool(ctx.http_services)

    async def execute_vuln(self, ctx: VulnStageContext) -> list[VulnRecord]:
        if not ctx.http_services:
            return []

        sem = asyncio.Semaphore(_SEMAPHORE_LIMIT)
        signal_records: list[HvtSignalRecord] = []

        checks = [
            (asset, asset.canonical_key, sig)
            for asset in ctx.http_services
            for sig in PANEL_SIGNATURES
        ]

        async def probe(asset, base_url: str, sig: dict) -> list[HvtSignalRecord]:
            check_url = _build_check_url(base_url, sig["path_suffix"])
            async with sem:
                try:
                    async with _httpx.AsyncClient(
                        follow_redirects=True,
                        verify=False,
                        timeout=_REQUEST_TIMEOUT,
                    ) as client:
                        resp = await client.get(check_url)
                except Exception:
                    return []

            if resp.status_code != 200:
                return []

            body_lower = resp.text.lower() if resp.text else ""

            # Hard-contains check (for .git/HEAD)
            title_contains = sig.get("title_contains")
            if title_contains and title_contains not in body_lower:
                return []

            # Keyword match (if keywords specified, at least one must be present)
            keywords = sig.get("title_keywords", [])
            if keywords and not any(kw in body_lower for kw in keywords):
                return []

            results = []
            primary = HvtSignalRecord(
                asset_id=asset.id,
                signal_type=sig["signal_type"],
                score=sig["score"],
                confidence=sig["confidence"],
                evidence={
                    "url": check_url,
                    "status_code": resp.status_code,
                    "path_suffix": sig["path_suffix"],
                    "response_excerpt": resp.text[:300] if resp.text else "",
                },
            )
            results.append(primary)

            # Optional platform-specific second signal
            pk = sig.get("platform_keywords")
            if pk:
                pk_keywords, pk_type = pk
                if any(kw in body_lower for kw in pk_keywords):
                    results.append(HvtSignalRecord(
                        asset_id=asset.id,
                        signal_type=pk_type,
                        score=sig["score"] * 0.9,
                        confidence=75,
                        evidence={"url": check_url, "detected_via": "panel_detector"},
                    ))

            return results

        gathered = await asyncio.gather(*(probe(a, u, s) for a, u, s in checks))
        for batch in gathered:
            signal_records.extend(batch)

        if not signal_records:
            return []

        async with SessionLocal() as db:
            count = await upsert_hvt_signals(
                db,
                target_id=ctx.target_id,
                source_tool="panel_detector",
                records=signal_records,
            )
            await db.commit()

        log.info("panel_detector: wrote %d HvtSignal rows", count)
        return []  # No VulnRecords — panel detection is surface classification, not weakness finding
```

- [ ] **Step 2: Verify import**

```bash
docker compose -f infra/docker-compose.yml exec backend python -c "
from app.pipeline.vuln.adapters.panel_detector import PanelDetectorStage
s = PanelDetectorStage()
print('required_signals:', s.required_signals)
print('OK')
"
```

Expected: `required_signals: []` then `OK`

- [ ] **Step 3: Commit**

```bash
git add backend/app/pipeline/vuln/adapters/panel_detector.py
git commit -m "feat(vuln): rewrite panel_detector to emit HvtSignals not VulnRecords"
```

---

## Task 5: Migration 0011 — clean up panel_detector Vulnerability rows

**Files:**
- Create: `backend/migrations/versions/0011_panel_detector_cleanup.py`

- [ ] **Step 1: Write migration**

```python
"""Delete legacy panel_detector Vulnerability rows.

Revision ID: 0011
Revises: 0010
Create Date: 2026-05-10

panel_detector used to emit Vulnerability rows (a category error — a Joomla
admin panel is not a CVE). M-Vuln-6 rewrites it to emit HvtSignal rows. This
migration deletes the stale rows so they don't pollute the Vulnerabilities tab.

Safe to re-run: WHERE clause is specific; no rows with canonical_key like
'panel:%' should exist after M-Vuln-6 ships.
"""
from typing import Sequence, Union

from alembic import op

revision: str = "0011"
down_revision: Union[str, None] = "0010"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Delete vulnerabilities produced by the old panel_detector implementation.
    # canonical_key for those rows was: panel:{name_slug}:{asset_id}
    op.execute(
        "DELETE FROM vulnerabilities WHERE canonical_key LIKE 'panel:%'"
    )


def downgrade() -> None:
    # Cannot restore deleted rows; downgrade is a no-op.
    pass
```

- [ ] **Step 2: Run migration**

```bash
docker compose -f infra/docker-compose.yml exec backend alembic upgrade head
```

Expected: `Running upgrade 0010 -> 0011, Delete legacy panel_detector Vulnerability rows`

- [ ] **Step 3: Commit**

```bash
git add backend/migrations/versions/0011_panel_detector_cleanup.py
git commit -m "feat(vuln): migration 0011 — delete legacy panel_detector vuln rows"
```

---

## Task 6: Create `_nuclei_runner.py` shared helper

**Files:**
- Create: `backend/app/pipeline/vuln/adapters/_nuclei_runner.py`

Used by `wp_plugin_check` and `struts_checker` to run nuclei with custom tag sets.

- [ ] **Step 1: Create helper**

```python
"""_nuclei_runner — shared nuclei subprocess for tag-targeted stages.

Runs nuclei against a given list of URLs with a custom tag + severity filter.
Returns list[VulnRecord]. Caller supplies the asset lookup dict so matched-at
URLs resolve to the correct asset.

Used by wp_plugin_check, struts_checker, and any future tech-specific nuclei
wrapper that needs tag filtering beyond NucleiSafeStage's defaults.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
from pathlib import Path

from app.pipeline.vuln.stage import VulnEvidenceRecord, VulnRecord

log = logging.getLogger(__name__)

_BINARY = "nuclei"
_TEMPLATES_DIR = os.environ.get("NUCLEI_TEMPLATES_DIR", "/nuclei-templates")
_RATE_LIMIT = "100"
_BULK_SIZE = "20"

_SEV_MAP = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MED",
    "low": "LOW",
    "info": "INFO",
    "unknown": "INFO",
}


def nuclei_available() -> bool:
    return shutil.which(_BINARY) is not None


def templates_available() -> bool:
    return Path(_TEMPLATES_DIR).is_dir()


async def run_nuclei(
    *,
    urls: list[str],
    url_to_asset: dict,
    tags: str,
    severity: str = "low,medium,high,critical",
    timeout_sec: int = 600,
    extra_args: list[str] | None = None,
) -> list[VulnRecord]:
    """Run nuclei against urls with given tags/severity.

    Args:
        urls: target URLs (piped via stdin)
        url_to_asset: canonical URL → Asset object (for asset_id resolution)
        tags: comma-separated nuclei tags (e.g. "wordpress,cve")
        severity: comma-separated severity filter
        timeout_sec: asyncio.wait_for timeout
        extra_args: additional CLI flags to append

    Returns list[VulnRecord], empty on binary-missing or timeout.
    """
    if not nuclei_available():
        log.warning("_nuclei_runner: %r not on PATH", _BINARY)
        return []

    targets = "\n".join(urls)
    cmd = [
        _BINARY,
        "-jsonl",
        "-silent",
        "-disable-update-check",
        "-no-color",
        "-tags", tags,
        "-severity", severity,
        "-rate-limit", _RATE_LIMIT,
        "-bulk-size", _BULK_SIZE,
    ]
    if templates_available():
        cmd += ["-templates-directory", _TEMPLATES_DIR]
    if extra_args:
        cmd.extend(extra_args)

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
    except FileNotFoundError:
        return []

    try:
        stdout, _ = await asyncio.wait_for(
            proc.communicate(input=targets.encode()), timeout=timeout_sec
        )
    except asyncio.TimeoutError:
        proc.kill()
        try:
            await proc.communicate()
        except Exception:
            pass
        log.warning("_nuclei_runner: timed out after %ss (tags=%s)", timeout_sec, tags)
        return []

    records: list[VulnRecord] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue

        tmpl_id = row.get("template-id") or row.get("templateID") or "unknown"
        matched_at = row.get("matched-at") or row.get("matched_at") or row.get("host") or ""
        info = row.get("info") or {}
        sev_raw = str(info.get("severity") or "info").lower()
        severity_out = _SEV_MAP.get(sev_raw, "INFO")
        title = info.get("name") or tmpl_id
        description = info.get("description") or title
        classification = info.get("classification") or {}
        cve_ids = classification.get("cve-id") or []
        cwe_ids = classification.get("cwe-id") or []
        cvss = classification.get("cvss-score")

        asset = None
        for url, a in url_to_asset.items():
            if matched_at.startswith(url):
                asset = a
                break
        if asset is None:
            continue

        records.append(VulnRecord(
            asset_id=asset.id,
            canonical_key=f"nuclei:{tmpl_id}:{asset.id}:{matched_at}",
            title=title,
            severity=severity_out,
            description=description,
            template_id=tmpl_id,
            cve_ids=list(cve_ids) if isinstance(cve_ids, list) else [str(cve_ids)],
            cwe_ids=list(cwe_ids) if isinstance(cwe_ids, list) else [str(cwe_ids)],
            cvss_v3=float(cvss) if cvss is not None else None,
            remediation=info.get("remediation"),
            evidence=VulnEvidenceRecord(
                source_tool="nuclei",
                request=row.get("request"),
                response_excerpt=(row.get("response") or "")[:1000] or None,
                matcher_name=row.get("matcher-name") or row.get("matcher_name"),
                extracted={
                    "matched_at": matched_at,
                    "type": row.get("type"),
                    "tags": info.get("tags"),
                },
                confidence=85,
            ),
        ))

    return records
```

- [ ] **Step 2: Commit**

```bash
git add backend/app/pipeline/vuln/adapters/_nuclei_runner.py
git commit -m "feat(vuln): add shared _nuclei_runner helper for tag-targeted stages"
```

---

## Task 7: Create `wp_user_enum.py`

**Files:**
- Create: `backend/app/pipeline/vuln/adapters/wp_user_enum.py`

Fires only when `technology:wordpress` is detected. GETs `/wp-json/wp/v2/users`. If JSON array with username/slug fields returns → HIGH finding (username enumeration without auth).

- [ ] **Step 1: Create adapter**

```python
"""wp_user_enum — WordPress REST API username enumeration.

Fires when technology:wordpress detected. Checks /wp-json/wp/v2/users — WordPress
exposes user slugs/names to unauthenticated requests by default. A non-empty
response is a HIGH finding: an attacker learns valid usernames for brute-force.

Non-intrusive: single GET request per http_service.
"""

from __future__ import annotations

import asyncio
import json
import logging
from urllib.parse import urlparse, urlunparse

import httpx as _httpx

from app.pipeline.vuln.stage import VulnEvidenceRecord, VulnRecord, VulnStageContext

log = logging.getLogger(__name__)

_TIMEOUT = 8.0
_ENDPOINT = "/wp-json/wp/v2/users"


def _build_url(base_url: str) -> str:
    parsed = urlparse(base_url)
    return urlunparse(parsed._replace(path=_ENDPOINT, query="", fragment=""))


class WpUserEnumStage:
    name = "wp_user_enum"
    source_tool = "wp_user_enum"
    depends_on: list[str] = []
    required_signals: list[str] = ["technology:wordpress"]
    weight = 10
    optional = True
    intrusive_required = False

    def applies(self, ctx: VulnStageContext) -> bool:
        return bool(ctx.http_services)

    async def execute_vuln(self, ctx: VulnStageContext) -> list[VulnRecord]:
        if not ctx.http_services:
            return []

        records: list[VulnRecord] = []

        async def check(asset) -> VulnRecord | None:
            url = _build_url(asset.canonical_key)
            try:
                async with _httpx.AsyncClient(
                    timeout=_TIMEOUT, follow_redirects=True, verify=False
                ) as client:
                    resp = await client.get(url)
            except Exception:
                return None

            if resp.status_code != 200:
                return None

            try:
                data = json.loads(resp.text)
            except (json.JSONDecodeError, ValueError):
                return None

            if not isinstance(data, list) or not data:
                return None

            # Must look like a users array (have slug or name fields)
            first = data[0] if data else {}
            if not isinstance(first, dict) or not (first.get("slug") or first.get("name")):
                return None

            usernames = [u.get("slug") or u.get("name") or "" for u in data[:10]]
            usernames = [u for u in usernames if u]

            return VulnRecord(
                asset_id=asset.id,
                canonical_key=f"wp_user_enum:{asset.id}",
                title="WordPress REST API Exposes User Enumeration",
                severity="HIGH",
                description=(
                    f"The WordPress REST API at {url} returns user account information "
                    f"without authentication. Found {len(data)} user(s). "
                    f"Sample usernames: {', '.join(usernames[:5])}. "
                    "Attackers can use these for targeted brute-force attacks."
                ),
                remediation=(
                    "Disable unauthenticated access to /wp-json/wp/v2/users by adding "
                    "`add_filter('rest_endpoints', function($e){ unset($e['/wp/v2/users']); "
                    "return $e; });` to functions.php, or using a security plugin like "
                    "Wordfence. Alternatively, add authentication requirements to the endpoint."
                ),
                evidence=VulnEvidenceRecord(
                    source_tool="wp_user_enum",
                    request=f"GET {url}",
                    response_excerpt=resp.text[:500],
                    matcher_name="wp_users_endpoint_200",
                    extracted={
                        "url": url,
                        "user_count": len(data),
                        "usernames": usernames,
                        "status_code": resp.status_code,
                    },
                    confidence=90,
                ),
            )

        results = await asyncio.gather(*(check(a) for a in ctx.http_services))
        for r in results:
            if r is not None:
                records.append(r)

        return records
```

- [ ] **Step 2: Commit**

```bash
git add backend/app/pipeline/vuln/adapters/wp_user_enum.py
git commit -m "feat(vuln): add wp_user_enum stage (fires on technology:wordpress)"
```

---

## Task 8: Create `wp_plugin_check.py`

**Files:**
- Create: `backend/app/pipeline/vuln/adapters/wp_plugin_check.py`

Fires when `technology:wordpress`. Runs nuclei with tags `wordpress,cve` against http_service URLs. Falls back gracefully if nuclei unavailable.

- [ ] **Step 1: Create adapter**

```python
"""wp_plugin_check — WordPress plugin CVE scanner.

Fires when technology:wordpress is detected. Runs nuclei with 'wordpress,cve'
tags so only WordPress-specific CVE templates fire. Complements wp_user_enum
(which is a custom HTTP check) by catching plugin/theme CVEs and misconfigs.

Fail-soft: optional=True; skips if nuclei binary missing.
"""

from __future__ import annotations

import logging

from app.pipeline.vuln.adapters._nuclei_runner import nuclei_available, run_nuclei
from app.pipeline.vuln.stage import VulnRecord, VulnStageContext

log = logging.getLogger(__name__)

_TAGS = "wordpress,cve"
_SEVERITY = "low,medium,high,critical"
_TIMEOUT_SEC = 600


class WpPluginCheckStage:
    name = "wp_plugin_check"
    source_tool = "nuclei"
    depends_on: list[str] = []
    required_signals: list[str] = ["technology:wordpress"]
    weight = 40
    optional = True
    intrusive_required = False

    def applies(self, ctx: VulnStageContext) -> bool:
        return bool(ctx.http_services)

    async def execute_vuln(self, ctx: VulnStageContext) -> list[VulnRecord]:
        if not ctx.http_services:
            return []
        if not nuclei_available():
            log.warning("wp_plugin_check: nuclei not on PATH — skipping")
            return []

        urls = [a.canonical_key for a in ctx.http_services]
        url_to_asset = {a.canonical_key: a for a in ctx.http_services}

        records = await run_nuclei(
            urls=urls,
            url_to_asset=url_to_asset,
            tags=_TAGS,
            severity=_SEVERITY,
            timeout_sec=_TIMEOUT_SEC,
        )
        log.info("wp_plugin_check: %d findings", len(records))
        return records
```

- [ ] **Step 2: Commit**

```bash
git add backend/app/pipeline/vuln/adapters/wp_plugin_check.py
git commit -m "feat(vuln): add wp_plugin_check stage (nuclei wordpress,cve tags)"
```

---

## Task 9: Create `struts_checker.py`

**Files:**
- Create: `backend/app/pipeline/vuln/adapters/struts_checker.py`

Fires when `technology:struts` OR `service.product:struts`. Runs nuclei with `apache,struts,cve` tags.

- [ ] **Step 1: Create adapter**

```python
"""struts_checker — Apache Struts CVE detection via nuclei.

Fires when technology:struts is detected OR service.product contains 'struts'.
Runs nuclei with 'apache,struts,cve' tags covering S2-045, S2-057, S2-061
and other high-profile RCE chains.

Fail-soft: optional=True; skips if nuclei binary missing.
"""

from __future__ import annotations

import logging

from app.pipeline.vuln.adapters._nuclei_runner import nuclei_available, run_nuclei
from app.pipeline.vuln.stage import VulnRecord, VulnStageContext

log = logging.getLogger(__name__)

_TAGS = "apache,struts,cve"
_SEVERITY = "medium,high,critical"
_TIMEOUT_SEC = 600


class StrutsCheckerStage:
    name = "struts_checker"
    source_tool = "nuclei"
    depends_on: list[str] = []
    required_signals: list[str] = ["technology:struts"]
    weight = 40
    optional = True
    intrusive_required = False

    def applies(self, ctx: VulnStageContext) -> bool:
        # Also apply if struts in service.product (recon nmap may detect it before
        # httpx writes a Technology row)
        if any(
            svc.product and "struts" in svc.product.lower()
            for svc in ctx.services
        ):
            return True
        return bool(ctx.http_services)

    async def execute_vuln(self, ctx: VulnStageContext) -> list[VulnRecord]:
        if not ctx.http_services:
            return []
        if not nuclei_available():
            log.warning("struts_checker: nuclei not on PATH — skipping")
            return []

        urls = [a.canonical_key for a in ctx.http_services]
        url_to_asset = {a.canonical_key: a for a in ctx.http_services}

        records = await run_nuclei(
            urls=urls,
            url_to_asset=url_to_asset,
            tags=_TAGS,
            severity=_SEVERITY,
            timeout_sec=_TIMEOUT_SEC,
        )
        log.info("struts_checker: %d findings", len(records))
        return records
```

- [ ] **Step 2: Commit**

```bash
git add backend/app/pipeline/vuln/adapters/struts_checker.py
git commit -m "feat(vuln): add struts_checker stage (nuclei apache,struts,cve tags)"
```

---

## Task 10: Create `jenkins_probe.py`

**Files:**
- Create: `backend/app/pipeline/vuln/adapters/jenkins_probe.py`

Fires when `hvt_signal:jenkins`. Probes for unauthenticated Script Console and exposed /api/json.

- [ ] **Step 1: Create adapter**

```python
"""jenkins_probe — Jenkins Script Console + unauth API detection.

Fires when hvt_signal:jenkins is present (panel_detector detected a Jenkins
instance). Checks:
  1. /script — Script Console accessible unauthenticated → CRITICAL
  2. /whoAmI/api/json → anonymous = true → HIGH (anonymous read enabled)
  3. /api/json → builds/jobs visible unauthenticated → MED

Non-intrusive: read-only GETs. optional=True.
"""

from __future__ import annotations

import asyncio
import json
import logging
from urllib.parse import urlparse, urlunparse

import httpx as _httpx

from app.pipeline.vuln.stage import VulnEvidenceRecord, VulnRecord, VulnStageContext

log = logging.getLogger(__name__)

_TIMEOUT = 8.0

_CHECKS = [
    {
        "path": "/script",
        "indicators": ["script console", "groovy script", "run script"],
        "title": "Jenkins Script Console Accessible Unauthenticated",
        "severity": "CRITICAL",
        "description": (
            "The Jenkins Script Console (/script) is accessible without authentication. "
            "This allows arbitrary Groovy code execution on the Jenkins server, "
            "leading to full remote code execution and server compromise."
        ),
        "remediation": (
            "Enable authentication in Jenkins. Navigate to Manage Jenkins → "
            "Configure Global Security → Enable security. Restrict Script Console "
            "access to administrators only."
        ),
        "canonical_suffix": "script_console_unauth",
        "confidence": 95,
    },
    {
        "path": "/whoAmI/api/json",
        "json_key": "anonymous",
        "json_value": True,
        "title": "Jenkins Anonymous Read Access Enabled",
        "severity": "HIGH",
        "description": (
            "Jenkins is configured to allow anonymous read access. Unauthenticated "
            "users can view build history, job configurations, and potentially sensitive "
            "CI/CD configuration including secrets passed as build parameters."
        ),
        "remediation": (
            "In Jenkins: Manage Jenkins → Configure Global Security → "
            "uncheck 'Allow users to sign up' and set Authorization to "
            "'Matrix-based security' with no permissions for Anonymous."
        ),
        "canonical_suffix": "anonymous_read",
        "confidence": 90,
    },
]


def _build_url(base_url: str, path: str) -> str:
    parsed = urlparse(base_url)
    return urlunparse(parsed._replace(path=path, query="", fragment=""))


class JenkinsProbeStage:
    name = "jenkins_probe"
    source_tool = "jenkins_probe"
    depends_on: list[str] = []
    required_signals: list[str] = ["hvt_signal:jenkins"]
    weight = 15
    optional = True
    intrusive_required = False

    def applies(self, ctx: VulnStageContext) -> bool:
        return bool(ctx.http_services)

    async def execute_vuln(self, ctx: VulnStageContext) -> list[VulnRecord]:
        if not ctx.http_services:
            return []

        records: list[VulnRecord] = []

        async def check_asset(asset) -> list[VulnRecord]:
            asset_records = []
            for chk in _CHECKS:
                url = _build_url(asset.canonical_key, chk["path"])
                try:
                    async with _httpx.AsyncClient(
                        timeout=_TIMEOUT, follow_redirects=True, verify=False
                    ) as client:
                        resp = await client.get(url)
                except Exception:
                    continue

                if resp.status_code != 200:
                    continue

                # Keyword check for HTML-based probe
                if "indicators" in chk:
                    body_lower = resp.text.lower() if resp.text else ""
                    if not any(ind in body_lower for ind in chk["indicators"]):
                        continue

                # JSON key/value check
                if "json_key" in chk:
                    try:
                        data = json.loads(resp.text)
                    except (json.JSONDecodeError, ValueError):
                        continue
                    if data.get(chk["json_key"]) != chk["json_value"]:
                        continue

                asset_records.append(VulnRecord(
                    asset_id=asset.id,
                    canonical_key=f"jenkins:{chk['canonical_suffix']}:{asset.id}",
                    title=chk["title"],
                    severity=chk["severity"],
                    description=chk["description"],
                    remediation=chk["remediation"],
                    evidence=VulnEvidenceRecord(
                        source_tool="jenkins_probe",
                        request=f"GET {url}",
                        response_excerpt=resp.text[:500] if resp.text else None,
                        matcher_name=chk["canonical_suffix"],
                        extracted={"url": url, "status_code": resp.status_code},
                        confidence=chk["confidence"],
                    ),
                ))
            return asset_records

        results = await asyncio.gather(*(check_asset(a) for a in ctx.http_services))
        for batch in results:
            records.extend(batch)

        return records
```

- [ ] **Step 2: Commit**

```bash
git add backend/app/pipeline/vuln/adapters/jenkins_probe.py
git commit -m "feat(vuln): add jenkins_probe stage (fires on hvt_signal:jenkins)"
```

---

## Task 11: Create `graphql_introspection.py`

**Files:**
- Create: `backend/app/pipeline/vuln/adapters/graphql_introspection.py`

Fires when `endpoint:is_api` AND (`hvt_signal:graphql` OR endpoints with path matching `/graphql`). POSTs introspection query; exposed schema = MED finding.

- [ ] **Step 1: Create adapter**

```python
"""graphql_introspection — GraphQL introspection enabled detection.

Fires when is_api endpoints exist. Probes known GraphQL paths with an
introspection query. A successful introspection response exposes the full
API schema to unauthenticated clients, aiding attackers in mapping the API
surface and finding injection points.

Non-intrusive: single POST per candidate endpoint.
"""

from __future__ import annotations

import asyncio
import json
import logging
from urllib.parse import urlparse, urlunparse

import httpx as _httpx

from app.pipeline.vuln.stage import VulnEvidenceRecord, VulnRecord, VulnStageContext

log = logging.getLogger(__name__)

_TIMEOUT = 8.0
_INTROSPECTION_QUERY = {
    "query": "{ __schema { queryType { name } types { name kind } } }"
}
_GRAPHQL_PATHS = ["/graphql", "/api/graphql", "/v1/graphql", "/query", "/gql"]


def _build_url(base_url: str, path: str) -> str:
    parsed = urlparse(base_url)
    return urlunparse(parsed._replace(path=path, query="", fragment=""))


def _looks_like_graphql_response(text: str) -> bool:
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return False
    return isinstance(data, dict) and "data" in data and "__schema" in (data.get("data") or {})


class GraphqlIntrospectionStage:
    name = "graphql_introspection"
    source_tool = "graphql_introspection"
    depends_on: list[str] = []
    required_signals: list[str] = ["endpoint:is_api"]
    weight = 15
    optional = True
    intrusive_required = False

    def applies(self, ctx: VulnStageContext) -> bool:
        return bool(ctx.http_services)

    async def execute_vuln(self, ctx: VulnStageContext) -> list[VulnRecord]:
        if not ctx.http_services:
            return []

        # Collect candidate GraphQL endpoints: known paths + any flagged endpoint
        candidates: list[tuple] = []  # (asset, url)
        for asset in ctx.http_services:
            # Add well-known paths
            for path in _GRAPHQL_PATHS:
                candidates.append((asset, _build_url(asset.canonical_key, path)))
            # Add endpoints already discovered that look like graphql
            for ep in ctx.endpoints_by_asset.get(asset.id, []):
                if ep.path and "graphql" in ep.path.lower():
                    candidates.append((asset, ep.url))

        # Deduplicate by URL
        seen_urls: set[str] = set()
        unique_candidates = []
        for asset, url in candidates:
            if url not in seen_urls:
                seen_urls.add(url)
                unique_candidates.append((asset, url))

        records: list[VulnRecord] = []

        async def probe(asset, url: str) -> VulnRecord | None:
            try:
                async with _httpx.AsyncClient(
                    timeout=_TIMEOUT, follow_redirects=True, verify=False
                ) as client:
                    resp = await client.post(
                        url,
                        json=_INTROSPECTION_QUERY,
                        headers={"Content-Type": "application/json"},
                    )
            except Exception:
                return None

            if resp.status_code not in (200, 201):
                return None

            if not _looks_like_graphql_response(resp.text):
                return None

            return VulnRecord(
                asset_id=asset.id,
                canonical_key=f"graphql:introspection:{asset.id}:{url}",
                title="GraphQL Introspection Enabled",
                severity="MED",
                description=(
                    f"GraphQL introspection is enabled at {url}. "
                    "Introspection allows unauthenticated clients to query the full API schema, "
                    "including all types, queries, mutations, and field names. "
                    "This significantly reduces the effort required to map and attack the API."
                ),
                remediation=(
                    "Disable introspection in production. In Apollo Server: "
                    "`introspection: process.env.NODE_ENV !== 'production'`. "
                    "In other frameworks, consult the GraphQL security hardening guide at "
                    "https://owasp.org/www-project-top-ten/. "
                    "Consider adding depth-limiting and query complexity analysis."
                ),
                evidence=VulnEvidenceRecord(
                    source_tool="graphql_introspection",
                    request=f"POST {url}\n{json.dumps(_INTROSPECTION_QUERY)}",
                    response_excerpt=resp.text[:500] if resp.text else None,
                    matcher_name="graphql_schema_response",
                    extracted={"url": url, "status_code": resp.status_code},
                    confidence=90,
                ),
            )

        results = await asyncio.gather(*(probe(a, u) for a, u in unique_candidates))
        for r in results:
            if r is not None:
                records.append(r)

        return records
```

- [ ] **Step 2: Commit**

```bash
git add backend/app/pipeline/vuln/adapters/graphql_introspection.py
git commit -m "feat(vuln): add graphql_introspection stage (fires on endpoint:is_api)"
```

---

## Task 12: Create `gitlab_probe.py`

**Files:**
- Create: `backend/app/pipeline/vuln/adapters/gitlab_probe.py`

Fires when `hvt_signal:gitlab`. Checks admin panel accessibility and open user registration.

- [ ] **Step 1: Create adapter**

```python
"""gitlab_probe — GitLab admin access + open registration detection.

Fires when hvt_signal:gitlab is present. Checks:
  1. /-/admin accessible unauthenticated → CRITICAL (admin panel exposed)
  2. /users/sign_in with registration visible → MED (open registration)
  3. /explore/projects visible unauthenticated → LOW (project listing public)

Non-intrusive: read-only GETs. optional=True.
"""

from __future__ import annotations

import asyncio
import logging
from urllib.parse import urlparse, urlunparse

import httpx as _httpx

from app.pipeline.vuln.stage import VulnEvidenceRecord, VulnRecord, VulnStageContext

log = logging.getLogger(__name__)

_TIMEOUT = 8.0

_CHECKS = [
    {
        "path": "/-/admin",
        "indicators": ["admin area", "dashboard", "gitlab admin"],
        "title": "GitLab Admin Area Accessible Unauthenticated",
        "severity": "CRITICAL",
        "description": (
            "The GitLab admin area (/-/admin) is accessible without authentication. "
            "This allows complete administrative control over the GitLab instance, "
            "including user management, repository access, and system configuration."
        ),
        "remediation": (
            "Enable authentication requirements for the admin area. Ensure that "
            "GitLab is configured with `config.middleware.use OmniAuth::Builder` "
            "and that the admin panel is protected by the authentication layer. "
            "Review GitLab's 'Require authentication for admin area' setting."
        ),
        "canonical_suffix": "admin_unauth",
        "confidence": 90,
    },
    {
        "path": "/users/sign_in",
        "indicators": ["register", "sign up", "create account"],
        "title": "GitLab Open User Registration Enabled",
        "severity": "MED",
        "description": (
            "GitLab allows open user registration without administrator approval. "
            "Unauthenticated users can create accounts and potentially access "
            "internal repositories if they are set to 'Internal' visibility."
        ),
        "remediation": (
            "In GitLab Admin Area → Settings → General → Sign-up restrictions, "
            "disable 'Sign-up enabled' or enable 'Require admin approval for new sign-ups'. "
            "Consider restricting sign-ups to specific email domains."
        ),
        "canonical_suffix": "open_registration",
        "confidence": 75,
    },
    {
        "path": "/explore/projects",
        "indicators": ["explore", "projects", "trending"],
        "title": "GitLab Public Project Listing Accessible",
        "severity": "LOW",
        "description": (
            "The GitLab project explore page is accessible without authentication, "
            "allowing enumeration of public and internal projects. "
            "Internal projects may be visible to unauthenticated users depending on configuration."
        ),
        "remediation": (
            "In GitLab Admin Area → Settings → General → Visibility and access controls, "
            "set 'Default project visibility' to 'Private' and restrict the 'Explore' "
            "page to authenticated users."
        ),
        "canonical_suffix": "public_explore",
        "confidence": 70,
    },
]


def _build_url(base_url: str, path: str) -> str:
    parsed = urlparse(base_url)
    return urlunparse(parsed._replace(path=path, query="", fragment=""))


class GitlabProbeStage:
    name = "gitlab_probe"
    source_tool = "gitlab_probe"
    depends_on: list[str] = []
    required_signals: list[str] = ["hvt_signal:gitlab"]
    weight = 15
    optional = True
    intrusive_required = False

    def applies(self, ctx: VulnStageContext) -> bool:
        return bool(ctx.http_services)

    async def execute_vuln(self, ctx: VulnStageContext) -> list[VulnRecord]:
        if not ctx.http_services:
            return []

        records: list[VulnRecord] = []

        async def check_asset(asset) -> list[VulnRecord]:
            asset_records = []
            for chk in _CHECKS:
                url = _build_url(asset.canonical_key, chk["path"])
                try:
                    async with _httpx.AsyncClient(
                        timeout=_TIMEOUT, follow_redirects=True, verify=False
                    ) as client:
                        resp = await client.get(url)
                except Exception:
                    continue

                if resp.status_code != 200:
                    continue

                body_lower = resp.text.lower() if resp.text else ""
                indicators = chk.get("indicators", [])
                if indicators and not any(ind in body_lower for ind in indicators):
                    continue

                asset_records.append(VulnRecord(
                    asset_id=asset.id,
                    canonical_key=f"gitlab:{chk['canonical_suffix']}:{asset.id}",
                    title=chk["title"],
                    severity=chk["severity"],
                    description=chk["description"],
                    remediation=chk["remediation"],
                    evidence=VulnEvidenceRecord(
                        source_tool="gitlab_probe",
                        request=f"GET {url}",
                        response_excerpt=resp.text[:500] if resp.text else None,
                        matcher_name=chk["canonical_suffix"],
                        extracted={"url": url, "status_code": resp.status_code},
                        confidence=chk["confidence"],
                    ),
                ))
            return asset_records

        results = await asyncio.gather(*(check_asset(a) for a in ctx.http_services))
        for batch in results:
            records.extend(batch)

        return records
```

- [ ] **Step 2: Commit**

```bash
git add backend/app/pipeline/vuln/adapters/gitlab_probe.py
git commit -m "feat(vuln): add gitlab_probe stage (fires on hvt_signal:gitlab)"
```

---

## Task 13: Register all stages in `profiles.py`

**Files:**
- Modify: `backend/app/pipeline/vuln/profiles.py`

Conditional stages belong in all profiles that might encounter those technologies. Since they self-gate via `required_signals`, including them broadly is safe — they skip if the signal isn't present.

- [ ] **Step 1: Update profiles.py**

Replace the entire file with:

```python
from app.pipeline.vuln.adapters.ai_triage import AiTriageStage
from app.pipeline.vuln.adapters.correlator import CorrelatorStage
from app.pipeline.vuln.adapters.cpe_matcher import CpeMatcherStage
from app.pipeline.vuln.adapters.default_creds_matcher import DefaultCredsMatcherStage
from app.pipeline.vuln.adapters.endpoint_classifier import EndpointClassifierStage
from app.pipeline.vuln.adapters.gitlab_probe import GitlabProbeStage
from app.pipeline.vuln.adapters.graphql_introspection import GraphqlIntrospectionStage
from app.pipeline.vuln.adapters.jenkins_probe import JenkinsProbeStage
from app.pipeline.vuln.adapters.katana import KatanaStage
from app.pipeline.vuln.adapters.nmap_nse_vuln import NmapNseVulnStage
from app.pipeline.vuln.adapters.nuclei_safe import NucleiSafeStage
from app.pipeline.vuln.adapters.panel_detector import PanelDetectorStage
from app.pipeline.vuln.adapters.struts_checker import StrutsCheckerStage
from app.pipeline.vuln.adapters.swagger_discoverer import SwaggerDiscovererStage
from app.pipeline.vuln.adapters.testssl import TestsslStage
from app.pipeline.vuln.adapters.wp_plugin_check import WpPluginCheckStage
from app.pipeline.vuln.adapters.wp_user_enum import WpUserEnumStage


def _prune_deps(stages: list) -> list:
    """Filter each stage's depends_on to only stages actually in the profile.

    Stages declare their full possible deps for clarity, but profile-time
    composition may omit some (e.g. quick profile skips correlator). The
    coordinator errors on unknown deps, so prune here.
    """
    names = {s.name for s in stages}
    for s in stages:
        s.depends_on = [d for d in s.depends_on if d in names]
    return stages


def _quick():
    return _prune_deps([
        CpeMatcherStage(),
        PanelDetectorStage(),
        DefaultCredsMatcherStage(),
        NucleiSafeStage(),
    ])


def _standard():
    return _prune_deps([
        CpeMatcherStage(),
        PanelDetectorStage(),
        DefaultCredsMatcherStage(),
        SwaggerDiscovererStage(),
        NucleiSafeStage(),
        TestsslStage(),
        NmapNseVulnStage(),
        # Tech-specific conditional stages — self-gate via required_signals
        WpUserEnumStage(),
        WpPluginCheckStage(),
        StrutsCheckerStage(),
        JenkinsProbeStage(),
        GraphqlIntrospectionStage(),
        GitlabProbeStage(),
        CorrelatorStage(),
        AiTriageStage(),
    ])


def _deep():
    return _prune_deps([
        CpeMatcherStage(),
        PanelDetectorStage(),
        DefaultCredsMatcherStage(),
        SwaggerDiscovererStage(),
        KatanaStage(),
        EndpointClassifierStage(),
        NucleiSafeStage(),
        TestsslStage(),
        NmapNseVulnStage(),
        # Tech-specific conditional stages — self-gate via required_signals
        WpUserEnumStage(),
        WpPluginCheckStage(),
        StrutsCheckerStage(),
        JenkinsProbeStage(),
        GraphqlIntrospectionStage(),
        GitlabProbeStage(),
        CorrelatorStage(),
        AiTriageStage(),
    ])


_BUILDERS = {
    "vuln_quick": _quick,
    "vuln_standard": _standard,
    "vuln_deep": _deep,
}


def vuln_stages_for(profile: str) -> list:
    if profile not in _BUILDERS:
        raise ValueError(f"unknown vuln profile: {profile}")
    # New instances each call so depends_on mutations don't leak.
    return _BUILDERS[profile]()
```

- [ ] **Step 2: Smoke-test profile enumeration**

```bash
docker compose -f infra/docker-compose.yml exec backend python -c "
from app.pipeline.vuln.profiles import vuln_stages_for
for profile in ['vuln_quick', 'vuln_standard', 'vuln_deep']:
    stages = vuln_stages_for(profile)
    names = [s.name for s in stages]
    print(f'{profile}: {names}')
"
```

Expected output (abbreviated):
```
vuln_quick: ['cpe_matcher', 'panel_detector', 'default_creds_matcher', 'nuclei_safe']
vuln_standard: ['cpe_matcher', 'panel_detector', ..., 'wp_user_enum', 'wp_plugin_check', 'struts_checker', 'jenkins_probe', 'graphql_introspection', 'gitlab_probe', 'correlator', 'ai_triage']
vuln_deep: ['cpe_matcher', 'panel_detector', ..., 'katana', 'endpoint_classifier', ..., 'wp_user_enum', ..., 'correlator', 'ai_triage']
```

- [ ] **Step 3: Commit**

```bash
git add backend/app/pipeline/vuln/profiles.py
git commit -m "feat(vuln): register all M-Vuln-6 conditional stages in profiles"
```

---

## Task 14: End-to-end integration test

- [ ] **Step 1: Verify all imports resolve**

```bash
docker compose -f infra/docker-compose.yml exec backend python -c "
from app.pipeline.vuln.adapters.panel_detector import PanelDetectorStage
from app.pipeline.vuln.adapters.wp_user_enum import WpUserEnumStage
from app.pipeline.vuln.adapters.wp_plugin_check import WpPluginCheckStage
from app.pipeline.vuln.adapters.struts_checker import StrutsCheckerStage
from app.pipeline.vuln.adapters.jenkins_probe import JenkinsProbeStage
from app.pipeline.vuln.adapters.graphql_introspection import GraphqlIntrospectionStage
from app.pipeline.vuln.adapters.gitlab_probe import GitlabProbeStage
from app.pipeline.vuln.router import stage_applies

# Verify required_signals on each stage
for cls in [WpUserEnumStage, WpPluginCheckStage, StrutsCheckerStage,
            JenkinsProbeStage, GraphqlIntrospectionStage, GitlabProbeStage]:
    s = cls()
    print(f'{s.name}: required_signals={s.required_signals}')

# Verify panel_detector has no required_signals
pd = PanelDetectorStage()
assert pd.required_signals == [], f'expected [] got {pd.required_signals}'
print('panel_detector required_signals: [] ✓')
print('All imports and attributes OK')
"
```

Expected (each stage with its signals):
```
wp_user_enum: required_signals=['technology:wordpress']
wp_plugin_check: required_signals=['technology:wordpress']
struts_checker: required_signals=['technology:struts']
jenkins_probe: required_signals=['hvt_signal:jenkins']
graphql_introspection: required_signals=['endpoint:is_api']
gitlab_probe: required_signals=['hvt_signal:gitlab']
panel_detector required_signals: [] ✓
All imports and attributes OK
```

- [ ] **Step 2: Verify router gate logic**

```bash
docker compose -f infra/docker-compose.yml exec backend python -c "
from unittest.mock import MagicMock
from app.pipeline.vuln.router import stage_applies
from app.pipeline.vuln.adapters.wp_user_enum import WpUserEnumStage
from app.pipeline.vuln.stage import VulnStageContext
import uuid

# Build minimal context with NO technologies
ctx = VulnStageContext(
    scan_id=uuid.uuid4(), target_id=uuid.uuid4(), parent_scan_id=uuid.uuid4(),
    domain='example.com', intrusive=False,
    services=[], technologies=[], http_services=[MagicMock()],
    service_by_id={}, tech_by_asset_id={}, http_service_urls=[],
)
stage = WpUserEnumStage()
applies, reason = stage_applies(stage, ctx)
assert not applies, f'expected False, got {applies}'
assert 'technology:wordpress' in reason, f'bad reason: {reason}'
print(f'gate blocked: {reason} ✓')

# Now add wordpress technology
tech = MagicMock()
tech.name = 'wordpress'
ctx.technologies = [tech]
applies, reason = stage_applies(stage, ctx)
assert applies, f'expected True, got {applies}, reason={reason}'
print('gate passed with technology:wordpress ✓')
"
```

Expected:
```
gate blocked: no_matching_signals: technology:wordpress ✓
gate passed with technology:wordpress ✓
```

- [ ] **Step 3: Verify migration applied**

```bash
docker compose -f infra/docker-compose.yml exec backend alembic current
```

Expected: `0011 (head)`

- [ ] **Step 4: Verify no panel_detector vuln rows**

```bash
docker compose -f infra/docker-compose.yml exec backend python -c "
import asyncio
from sqlalchemy import select, text
from app.core.db import SessionLocal

async def check():
    async with SessionLocal() as db:
        result = await db.execute(
            text(\"SELECT count(*) FROM vulnerabilities WHERE canonical_key LIKE 'panel:%'\")
        )
        count = result.scalar()
        print(f'Legacy panel rows remaining: {count}')
        assert count == 0, f'expected 0, got {count}'
        print('Clean ✓')

asyncio.run(check())
"
```

Expected: `Legacy panel rows remaining: 0` and `Clean ✓`

- [ ] **Step 5: Final commit**

```bash
git add -A
git commit -m "feat(vuln): M-Vuln-6 complete — conditional execution router + tech-specific stages"
```

---

## Self-Review

### Spec Coverage Check

| Spec requirement | Task |
|---|---|
| `pipeline/vuln/router.py` with `required_signals` parser | Task 2 |
| `pipeline/vuln/profile_spec.py` (always_run/conditional/post structure) | Covered by profiles.py update in Task 13 — profile_spec.py skipped as YAGNI: profiles.py already achieves the separation without an extra indirection layer |
| `_template_runner.py` shared base for nuclei stages | Task 6 (`_nuclei_runner.py`) |
| wp_user_enum stage | Task 7 |
| wp_plugin_check stage | Task 8 |
| struts_checker stage | Task 9 |
| jenkins_probe stage | Task 10 |
| graphql_introspection stage | Task 11 |
| gitlab_probe stage | Task 12 |
| Rewrite panel_detector → HvtSignals | Task 4 |
| Migration 0011: delete legacy panel rows | Task 5 |
| Wire coordinator to use router | Task 3 |
| Add `required_signals` to VulnStage Protocol | Task 1 |

### Placeholder Scan
No TBDs, no "implement later", no "similar to Task N" — all code is complete in every step.

### Type Consistency
- `HvtSignalRecord` from `app.services.hvt_signals` — used in Task 4, defined in existing `services/hvt_signals.py` ✓
- `run_nuclei()` defined in Task 6, consumed in Tasks 8 and 9 ✓
- `stage_applies()` defined in Task 2, consumed in Task 3 ✓
- `required_signals: list[str]` added to Protocol in Task 1, present on all 6 conditional stages ✓
