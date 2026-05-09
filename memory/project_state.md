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

### M5 — Enrichment (BBOT only)
✅ Fully complete (backend + frontend) — 2026-05-09

**What's in M5 (final state after Censys/Shodan removal):**
- `BBOTStage`: deep-profile-only, runs on `heavy` queue, 30-min timeout, domain-scoped filter
- `heavy-worker` Docker service: worker image + bbot, listens on `ARQ_QUEUE_NAME=heavy`
- Queue routing: `enqueue_scan(id, profile)` → `heavy` queue for deep, `default` for all others
- `sources: list[str]` on SubdomainRow — which tools found each subdomain (purple badges in UI)
- 13 unit tests passing (bbot ×5, queue ×4, bounded_completion ×4)

**Final file state:**
- `backend/app/pipeline/adapters/bbot.py` — BBOTStage
- `infra/Dockerfile.heavy-worker` — worker + bbot binary
- `infra/docker-compose.yml` — heavy-worker service; `volumes: - ../backend:/app` on BOTH worker + heavy-worker
- `backend/app/core/config.py` — bbot_timeout: int = 1800
- `backend/app/pipeline/profiles.py` — BBOTStage in deep only; no censys/shodan
- `backend/app/services/queue.py` — profile-based queue routing
- `backend/app/workers/runner.py` — WorkerSettings.queue_name from ARQ_QUEUE_NAME env
- `backend/app/schemas/subdomain_view.py` — `sources: list[str] = []` on SubdomainRow
- `backend/app/services/scan_view.py` — sources populated from observation source_tool keys

**Censys + Shodan removed (2026-05-09):**
- Deleted: `censys.py`, `shodan.py`, `_cache.py`, `test_censys.py`, `test_shodan.py`
- Removed from: profiles.py, config.py, pyproject.toml, Dockerfile.worker, docker-compose.yml

**Key bug fixes (2026-05-09):**
- naabu connect scan: `-s c` flag — SYN scan blocked by Cloudflare, connect scan finds all ports
- heavy-worker bind mount: added `volumes: - ../backend:/app` — was using stale baked image
- arq module reload: must `docker compose restart worker heavy-worker` after any Python module changes

**OpenSearch deferred** to future milestone.

**Pipeline verified end-to-end (2026-05-09):**
- Quick (subfinder only): ✅ 22s
- Standard (8 stages, no censys/shodan): ✅ 213s
- Deep (bbot + active stages): ✅ running on heavy-worker, clean stage list confirmed

### Vulnerability Analysis
⏳ Not started — next milestone (user confirmed, start with brainstorming skill)

## Current Architecture Decisions
- Docker Compose monolith (no k8s until outgrows single host)
- Arq + Redis for async job queue; `heavy` queue for deep-profile scans (BBOTStage)
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
- **Naabu rule**: always use `-s c` (connect scan) — SYN scan is silently blocked by Cloudflare and returns 0–4 ports
- **Env var rule**: `docker-compose.yml` `${VAR:-}` takes priority over Pydantic `.env`; add real secrets to `infra/.env` (gitignored)
- **arq reload rule**: after any Python module change, must `docker compose restart worker heavy-worker` — arq loads modules at startup, bind mount alone does not trigger reload
- **heavy-worker bind mount rule**: both `worker` and `heavy-worker` must have `volumes: - ../backend:/app` in docker-compose.yml for dev hot-swap

## Current Focus
M5 complete + verified. Pipeline clean (all 3 profiles confirmed working). PR at https://github.com/Thilakesh/RedTeam-Dashboard/compare/main...dev_BlackPie (create manually — gh CLI not installed). Next: **Vulnerability Analysis** feature — start with brainstorming skill.
