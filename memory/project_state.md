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

**What's in M2:**
- Active adapters: naabu, nmap, gowitness (`authz_required=True`)
- MinIO screenshot storage with presigned URL support (`MINIO_USE_SIGNED_URLS` toggle)
- Worker subprocess sandbox (`backend/app/workers/sandbox.py`): RLIMIT_NOFILE=4096 only
- AuthzVerifierStage: L0, auto-verifies target via HTTP well-known + DNS TXT, flips `authz_state[0]=True`
- `target_authz_verified` exposed on `ScanOut` — UI shows ⚠️ for deep scans on unverified targets

**Critical bug fixed (2026-05-08):**
- `RLIMIT_AS=768MB` in sandbox.py was killing Go binaries (naabu, gowitness) via SIGABRT at startup
- Fix: removed `RLIMIT_AS` entirely, raised `RLIMIT_NOFILE` from 512 → 4096

### M3 — AI Risk Prioritization
✅ Fully complete (backend + frontend) — 2026-05-07

### M4 — Workflow-Oriented Dashboard Redesign
✅ Fully complete (backend + frontend) — 2026-05-08

**Backend changes:**
- `queued` and `stopped` statuses added to `ScanStatus` ENUM (Alembic migration applied)
- `autostart: bool = True` on `POST /scans`; `False` creates scan as `queued` without enqueuing
- New lifecycle endpoints: `POST /scans/{id}/start`, `POST /scans/{id}/stop`, `PATCH /scans/{id}`, `DELETE /scans/{id}`
- Worker guards completion/failure paths against overriding `stopped` status
- SSE stream terminates on `scan.stopped` event

**Frontend changes:**
- `frontend/lib/api.ts` — Scan.status extended to 6 values; lifecycle helpers; `TechBucket` type added
- `frontend/components/AppShell.tsx` — Dashboard nav item (`/home`); breadcrumbs fixed for all routes
- `frontend/app/dashboard/layout.tsx` — bare AppShell wrapper only (no stats bar)
- `frontend/app/dashboard/page.tsx` — "Add Scan" title + description heading
- `frontend/app/dashboard/recon-jobs/page.tsx` — "Recon Jobs" title + 4-column stats grid
- `frontend/app/home/page.tsx` — new empty Dashboard placeholder page at `/home`
- `frontend/components/tabs/OverviewTab.tsx` — Top Risks card for completed deep scans
- `frontend/components/tabs/TechnologiesTab.tsx` — expandable rows showing subdomains per tech

**M4 bug fixes (2026-05-08 session):**
- Screenshot URL fallback: `_resolve_screenshot_url()` now falls back to stored `screenshot_url` when backend has no MinIO env vars
- Technologies tab: `TechBucket` schema with `subdomains: list[str]`; `build_technologies()` collects FQDN list per tech

### M5 — Enrichment (Censys + Shodan + BBOT)
✅ Backend complete — 2026-05-09

**What's in M5:**
- `CensysStage` + `ShodanStage`: passive L0 adapters with daily Redis cache, optional, skip gracefully if unconfigured
- `BBOTStage`: deep-profile-only, runs on `heavy` queue, 30-min timeout, domain-scoped filter
- `heavy-worker` Docker service: identical to worker + bbot, listens on `ARQ_QUEUE_NAME=heavy`
- Queue routing: `enqueue_scan(id, profile)` → `heavy` queue for deep, `default` for all others
- 17 unit tests passing (censys ×4, shodan ×4, bbot ×5, queue ×4)
- SDK imports deferred inside `execute()` so container starts even if censys/shodan not installed yet

**New files:**
- `backend/app/pipeline/adapters/_cache.py` — Redis daily cache helpers (cache_get/cache_set)
- `backend/app/pipeline/adapters/censys.py`
- `backend/app/pipeline/adapters/shodan.py`
- `backend/app/pipeline/adapters/bbot.py`
- `infra/Dockerfile.heavy-worker`
- `backend/tests/unit/test_censys.py`, `test_shodan.py`, `test_bbot.py`, `test_queue.py`

**Modified files:**
- `backend/app/core/config.py` — added censys_api_id, censys_api_secret, shodan_api_key, bbot_timeout
- `backend/app/pipeline/profiles.py` — CensysStage+ShodanStage in standard+deep; BBOTStage in deep only
- `backend/app/services/queue.py` — profile-based queue routing
- `backend/app/workers/runner.py` — WorkerSettings.queue_name from ARQ_QUEUE_NAME env
- `backend/app/api/scans.py` — both enqueue_scan calls pass profile=scan.profile
- `backend/pyproject.toml` — added censys>=2.2, shodan>=1.31
- `infra/Dockerfile.worker` — pip install censys+shodan
- `infra/docker-compose.yml` — env vars on worker + new heavy-worker service

**OpenSearch deferred** to future milestone (removed from M5 scope).

### M6
⏳ Not started

## Current Architecture Decisions
- Docker Compose monolith (no k8s until outgrows single host)
- Arq + Redis for async job queue
- PostgreSQL asset graph (`Asset` + `AssetObservation` + `Finding`)
- MinIO (S3-compatible) for screenshots/binary blobs
- SSE for real-time scan progress (not WebSockets)
- AI: OpenRouter `openai/gpt-oss-20b:free` for JSON-mode LLM (no parse retries)
- `RiskPrioritizerStage` and `AuthzVerifierStage` are documented exceptions to "adapters never touch DB" rule
- Tenant isolation on findings: enforced via `scan_id → scans.org_id`
- Tab state in Scan Detail driven by `?tab=` URL param (VALID_TABS allowlist guard)
- Dashboard nav: "Dashboard" (`/home`) + "Basic Recon" (collapsed group: "Add Scan", "Recon Jobs")
- `layout.tsx` provides AppShell for entire `/dashboard` subtree; child pages manage their own title+stats
- Scan lifecycle: `queued → created → running → completed/failed/stopped`
- `bounded_completion.py` null-content guard: null content from OpenRouter raises `BoundedCompletionError` with `finish_reason` context
- **Sandbox rule**: NEVER use `RLIMIT_AS` for Go-based recon tools — use `RLIMIT_NOFILE` instead
- **Screenshot URL rule**: backend API has NO MinIO env vars; `_resolve_screenshot_url()` must fall back to stored URL when regen returns None

## Current Focus
All M0–M4 complete. Next: M5 — Enrichment + Search (Censys/Shodan/BBOT/OpenSearch).
