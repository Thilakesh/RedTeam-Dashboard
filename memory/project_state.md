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

### M5–M6
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
