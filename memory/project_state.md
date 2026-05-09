# Project State

## Milestones

### M0 — Skeleton
✅ Completed

### M1 — Pipeline Framework
✅ Completed

### M1.5 — Subdomain-centric UI + Passive Enrichment
✅ Completed

### M2 — Active Scanning + Isolation
✅ Fully complete (backend + frontend) — 2026-05-08

### M3 — AI Risk Prioritization
✅ Fully complete — 2026-05-07

### M4 — Workflow-Oriented Dashboard Redesign
✅ Fully complete — 2026-05-08

### M5 — Enrichment (BBOT only)
✅ Fully complete — 2026-05-09

### M-Vuln-1 — Vulnerability Schema + Scan-kind Plumbing
✅ Complete (committed + pushed to `dev_vuln_dash`)

**Schema:**
- Migrations 0005 (services + technologies promotion), 0006 (vuln tables), 0007 (scan kind/parent/intrusive)
- New ORM models: `Service`, `Technology`, `Vulnerability`, `VulnEvidence`, `VulnRunMatch`
- `Scan.kind` (recon|vuln_analysis), `Scan.parent_scan_id` (self-FK SET NULL), `Scan.intrusive`
- `FindingSeverity` extended: added CRITICAL
- Postgres ENUM types created explicitly: `vuln_severity`, `vuln_status`, `scan_kind`
- Partial unique index: prevent concurrent vuln scans per target

**Behavioral:**
- `Stage.applies(ctx)` optional predicate; coordinator skips with reason="no_matching_inputs"
- `upsert_assets()` dual-writes Service rows (type=service) + Technology rows (httpx tech list)
- `scan_view.build_port_rows()` + `build_technologies()` rewritten to query first-class tables (scan-scoped via `asset_observations.scan_id` subquery)

### M-Vuln-2 — Vuln Pipeline + Worker + API + UI
✅ Complete (commit `9c07d34` on `dev_vuln_dash`, pushed) — 2026-05-09

**Pipeline layer (`backend/app/pipeline/vuln/`):**
- `VulnStage` Protocol: `name`, `source_tool`, `depends_on`, `weight`, `optional`, `intrusive_required`, async `execute_vuln(ctx) -> list[VulnRecord]`
- `VulnStageContext` dataclass: pre-loaded frozen recon view (services, technologies, http_services, lookups by id) — READ ONLY
- `VulnRecord` + `VulnEvidenceRecord` dataclasses
- `coordinator.py`: `_levels()` topo sort, `load_vuln_context()`, `run_vuln_dag()` with `intrusive_required` + `applies()` gates, `total_weight()` for progress
- `profiles.py`: `vuln_quick`/`vuln_standard`/`vuln_deep` (all use cpe_matcher + panel_detector + nuclei_safe stub for now)
- Adapters: `cpe_matcher` (offline CPE→CVE via bundled `data/cpe_rules.json` — 5 rules: Log4Shell, Struts2, Heartbleed, WP SQLi, PHP-FPM), `panel_detector` (async httpx admin/login probe with Semaphore(10), 9 signatures), `nuclei_safe` (STUB returning [], real binary in M-Vuln-3)

**Services:**
- `services/vulns.py::upsert_vulns()` mirrors `upsert_assets`: ON CONFLICT `uq_vuln_identity`, appends VulnEvidence, upserts VulnRunMatch (new vs seen via prior-scan check), batch 2000
- `services/vuln_view.py`: `build_vuln_overview()` (severity counts, KEV/CVE counts), `build_vuln_rows()` (paginated, scan-scoped via vuln_run_matches join, severity/status filters)

**API (`backend/app/api/`):**
- `vuln_scans.py` prefix=`/vuln-scans`: POST (validates parent recon completed + same org), GET list (kind=vuln_analysis filter), GET detail (selectinload stages), GET stream (Redis SSE), GET overview, GET vulnerabilities (paginated)
- `vulns.py` prefix=`/vulns`: PATCH `/{id}` status update; tenant scope via `vulnerability.target_id → Target → Project.org_id`
- Both routers wired into `main.py`

**Worker (`backend/app/workers/vuln_runner.py`):**
- `run_vuln_scan()` Arq function: validates scan kind/parent, loads `VulnStageContext` (within db session), then runs DAG outside session (detached SQLAlchemy objects with loaded columns)
- on_done: `upsert_vulns()` + updates `scan.progress_pct` per stage weight (matches recon runner pattern)
- `VulnWorkerSettings`: queue_name="vuln", job_timeout=45min, max_jobs=4
- `services/queue.py::enqueue_vuln_scan()` routes to "vuln" queue

**Infra:**
- `infra/Dockerfile.vuln_worker` — python:3.11-slim, nuclei v3.2.4 + nmap, no chromium, CMD `arq vuln_runner.VulnWorkerSettings`
- `infra/docker-compose.yml` — new `vuln-worker` service (DATABASE_URL/REDIS_URL/OPENROUTER_API_KEY env, `restart: unless-stopped`)

**Frontend:**
- `frontend/lib/api.ts` — added `VulnScanOut`, `VulnScanDetail`, `VulnOverview`, `VulnOut`, `VulnsPage` types
- `frontend/app/vuln-scans/page.tsx` — list view with 4s polling on running, status badges, target/profile/status/progress columns, empty state, links
- `frontend/app/vuln-scans/[id]/page.tsx` — detail view, SSE subscription on Redis channel, Overview tab (severity cards + KEV/CVE summary), Vulnerabilities tab (paginated table with severity/status filters, inline status change PATCH), Suspense wrapper for useSearchParams, ?tab= URL param
- `frontend/app/scans/[id]/page.tsx` — "Run Vulnerability Analysis" CTA on completed recon scans (POST /vuln-scans, navigate to /vuln-scans/{id})

### M-Vuln-3 — Real Nuclei + More Safe Stages
⏳ Not started

### M-Vuln-4 — Intrusive Stages
⏳ Not started

## Current Architecture Decisions
- Docker Compose monolith (no k8s yet)
- Arq + Redis: `default` queue (recon non-deep), `heavy` queue (recon deep + bbot), `vuln` queue (vuln_analysis)
- PostgreSQL asset graph (`Asset` + `AssetObservation` + `Finding`) + first-class `Service`/`Technology` (M-Vuln-1) + `Vulnerability`/`VulnEvidence`/`VulnRunMatch` (M-Vuln-1)
- MinIO for screenshots
- SSE for real-time scan progress (Redis pub/sub `scan:{scan_id}`, same shape for recon + vuln)
- AI: OpenRouter `openai/gpt-oss-20b:free` JSON mode
- `RiskPrioritizerStage`, `AuthzVerifierStage` are documented exceptions to "adapters never touch DB"
- Tenant isolation: `Scan.org_id` denormalized; vulns scoped via target→project chain
- Tab state via `?tab=` URL param + VALID_TABS allowlist
- Scan kind separation: vuln_analysis scans require completed parent recon scan, run on `vuln` queue, get separate frontend route `/vuln-scans/[id]`
- Vuln dedup identity: `(target_id, canonical_key)` unique; `canonical_key` formula varies by source (e.g. `cve:{cve_id}:{asset_id}`)
- VulnEvidence is append-only; VulnRunMatch tracks per-scan new/seen state for diff view
- VulnStageContext is detached SQLAlchemy objects (column attrs loaded, no lazy relationships) — frozen view, prevents recon re-runs

## Carry-forward Rules (stable)
- **Sandbox**: NEVER use `RLIMIT_AS` for Go binaries — SIGABRT at startup; use `RLIMIT_NOFILE`
- **Naabu**: always use `-s c` (connect scan); SYN blocked by Cloudflare
- **Screenshot**: backend API has no MinIO env vars — `_resolve_screenshot_url()` falls back to stored URL
- **Env**: `infra/.env` is secret source of truth; `${VAR:-}` in compose overrides Pydantic `.env`
- **arq reload**: `docker compose restart worker heavy-worker vuln-worker` after Python module changes — bind mount alone does not reload
- **Bind mount**: all worker services need `volumes: - ../backend:/app` for dev hot-swap
- **Vuln module boundary**: vuln adapters NEVER write to `assets`/`services`/`technologies` — they consume the frozen `VulnStageContext` only

## Current Focus
M-Vuln-1 + M-Vuln-2 done. `dev_vuln_dash` branch pushed. PR creation pending (gh CLI missing). Next: **M-Vuln-3** — wire real nuclei binary, add testssl/nmap_nse_vuln/default_creds_matcher/katana/correlator/ai_triage stages, Diff tab in UI.
