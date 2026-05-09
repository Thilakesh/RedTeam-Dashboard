# Active Tasks

## Completed This Session (2026-05-09) — M-Vuln-1 + M-Vuln-2

### M-Vuln-1 — Schema + Scan-kind Plumbing
- [x] Migrations: `0005_promote_services_tech.py`, `0006_vuln_tables.py`, `0007_scan_kind_and_parent.py`
- [x] ORM models: `Service`, `Technology`, `Vulnerability` (+ `VulnSeverity`, `VulnStatus`), `VulnEvidence`, `VulnRunMatch`
- [x] `Scan` extended: `kind` (recon|vuln_analysis), `parent_scan_id` (self-FK), `intrusive` bool
- [x] `FindingSeverity` extended: CRITICAL added (autocommit_block in 0007)
- [x] `Stage.applies(ctx)` optional predicate; coordinator skips with reason="no_matching_inputs"
- [x] `upsert_assets()` dual-writes Service + Technology rows
- [x] `scan_view.build_port_rows()` + `build_technologies()` rewritten to query first-class tables (scan-scoped)
- [x] Backfill migrations from existing JSONB attributes (LATERAL join pattern)

### M-Vuln-2 — Vuln Pipeline + Worker + API + UI (4 parallel agents)
- [x] **Pipeline**: `VulnStage` Protocol, `VulnStageContext`, `coordinator.py` (`_levels`, `load_vuln_context`, `run_vuln_dag`, `total_weight`), `profiles.py`
- [x] **Adapters**: `cpe_matcher.py` (offline CPE→CVE, 5 bundled rules), `panel_detector.py` (async httpx, 9 sigs), `nuclei_safe.py` (STUB → real binary in M-Vuln-3)
- [x] **Services**: `vulns.py::upsert_vulns` (ON CONFLICT + evidence append + run_match), `vuln_view.py` (overview + paginated rows)
- [x] **API**: `vuln_scans.py` (CRUD + SSE + overview + vulnerabilities), `vulns.py` (PATCH status with target→project→org tenant scope)
- [x] **Worker**: `vuln_runner.py` (`run_vuln_scan`, `VulnWorkerSettings` queue=vuln, 45min timeout, max_jobs=4)
- [x] Progress tracking added: `total_weight()` + on_done updates `scan.progress_pct` per stage
- [x] `services/queue.py::enqueue_vuln_scan` routes to "vuln" queue
- [x] `main.py` includes vuln_scans + vulns routers
- [x] **Infra**: `Dockerfile.vuln_worker` (nuclei v3.2.4 + nmap), `docker-compose.yml` vuln-worker service
- [x] **Frontend**: `lib/api.ts` types, `/vuln-scans` list page, `/vuln-scans/[id]` detail (Overview + Vulnerabilities tabs, SSE, inline status), `/scans/[id]` "Run Vulnerability Analysis" CTA

### Git
- [x] M-Vuln-1 committed + pushed (`dev_vuln_dash`)
- [x] M-Vuln-2 commit `9c07d34` pushed to `dev_vuln_dash`
- [x] 23 files changed, 2301 insertions

## Pending / Needs User Action

### PR not created (gh CLI missing on host)
- Open manually: https://github.com/Thilakesh/RedTeam-Dashboard/compare/main...dev_vuln_dash
- Branch: `dev_vuln_dash`, base: `main`
- Includes M-Vuln-1 + M-Vuln-2

### Verification (recommended before M-Vuln-3)
- `docker compose up --build` (build vuln-worker image)
- `docker compose exec backend alembic current` → expect `0007`
- Run a recon scan against verified target → completed
- Click "Run Vulnerability Analysis" CTA → vuln scan created
- Watch `docker compose logs vuln-worker -f` → confirm queue=vuln pickup
- Check `/vuln-scans/{id}` → Overview tab shows severity counts, Vulnerabilities tab paginates
- Re-run vuln scan against same parent → confirm dedup (no duplicate vuln rows; new VulnEvidence rows appended)

## Next Milestone: M-Vuln-3 — Real Nuclei + More Stages
- Wire real `nuclei` binary into `nuclei_safe.py` (currently stub)
- Add stages: `testssl`, `nmap_nse_vuln`, `default_creds_matcher`, `katana` (passive), `correlator`, `ai_triage`
- Add Diff tab in UI (uses `VulnRunMatch.state`)
- AI triage uses existing `bounded_completion` wrapper + `ai_usage` accounting

## M-Vuln-4 (later)
- Intrusive stages: `ffuf`, `nikto`, `nuclei_intrusive`
- Per-target rate limiter (Redis token bucket: `vuln:rate:{target_id}`)
- Per-target consent UX in frontend
