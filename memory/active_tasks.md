# Active Tasks

## Completed This Session (2026-05-10) — UI Fixes + Bug Fixes

### Subfinder Fix (committed `efb4f6b` on `dev_vuln_dash`)
- [x] Rewrote `subfinder.py` to stream stdout line-by-line (mirrors amass pattern)
- [x] Raised `asyncio.wait_for` timeout to 300s; added `-timeout 30` per-source HTTP flag
- [x] Kill-on-timeout returns partial results (was: scan failed entirely)
- [x] Verified: new scan `732c510d` against boman.ai completed 14 stages, found 16 subdomains

### Vuln Runner Progress Fix (same commit)
- [x] Added `total_weight()` to `vuln/coordinator.py`
- [x] `vuln_runner.py::on_done` now tracks `nonlocal completed_weight`, computes `progress_pct`, updates `Scan.progress_pct`, publishes `progress=` in SSE events
- [x] Fixed double `db.commit()` in `on_done`

### Navigation + UX Fixes (2026-05-10, uncommitted)
- [x] `AppShell.tsx`: Added "Vulnerability Scans" nav entry (`/vuln-scans`, ShieldAlert icon) between "Basic Recon" and "Targets"
- [x] `AppShell.tsx`: Added breadcrumb cases for `/vuln-scans` and `/vuln-scans/*`
- [x] `dashboard/recon-jobs/page.tsx`: Added "Run Vuln Analysis" button per completed scan row (POSTs to `/vuln-scans`, navigates to `/vuln-scans/{id}`, spinner while in-flight)
- [x] `backend/app/api/scans.py`: Fixed `GET /scans` — now filters `Scan.kind == ScanKind.recon`; vuln_analysis scans no longer leak into recon jobs list

## Previously Completed — M-Vuln-1 + M-Vuln-2 (2026-05-09)

### M-Vuln-1 — Schema + Scan-kind Plumbing
- [x] Migrations: `0005_promote_services_tech.py`, `0006_vuln_tables.py`, `0007_scan_kind_and_parent.py`
- [x] ORM models: `Service`, `Technology`, `Vulnerability` (+ `VulnSeverity`, `VulnStatus`), `VulnEvidence`, `VulnRunMatch`
- [x] `Scan` extended: `kind` (recon|vuln_analysis), `parent_scan_id` (self-FK), `intrusive` bool
- [x] `FindingSeverity` extended: CRITICAL added
- [x] `Stage.applies(ctx)` optional predicate; coordinator skips with reason="no_matching_inputs"
- [x] `upsert_assets()` dual-writes Service + Technology rows
- [x] `scan_view.build_port_rows()` + `build_technologies()` rewritten to query first-class tables

### M-Vuln-2 — Vuln Pipeline + Worker + API + UI
- [x] Pipeline: `VulnStage` Protocol, `VulnStageContext`, `coordinator.py`, `profiles.py`
- [x] Adapters: `cpe_matcher` (5 bundled rules), `panel_detector` (9 sigs), `nuclei_safe` (STUB)
- [x] Services: `vulns.py::upsert_vulns`, `vuln_view.py` (overview + paginated rows)
- [x] API: `vuln_scans.py`, `vulns.py` (PATCH status)
- [x] Worker: `vuln_runner.py` (queue=vuln, 45min timeout, max_jobs=4)
- [x] Infra: `Dockerfile.vuln_worker`, docker-compose.yml vuln-worker service
- [x] Frontend: api.ts types, `/vuln-scans` list, `/vuln-scans/[id]` detail, `/scans/[id]` CTA

## Pending / Needs User Action

### Uncommitted Changes (2026-05-10)
Three files modified locally, not yet committed to `dev_vuln_dash`:
- `frontend/components/AppShell.tsx` — nav + breadcrumbs
- `frontend/app/dashboard/recon-jobs/page.tsx` — Run Vuln Analysis button
- `backend/app/api/scans.py` — kind=recon filter fix

Commit when ready:
```bash
git add frontend/components/AppShell.tsx \
        frontend/app/dashboard/recon-jobs/page.tsx \
        backend/app/api/scans.py
git commit -m "fix: filter recon-only scans in list API; add vuln nav + run-vuln button in recon jobs"
git push origin dev_vuln_dash
```

### PR not created (gh CLI missing on host)
- Open manually: https://github.com/Thilakesh/RedTeam-Dashboard/compare/main...dev_vuln_dash

## Next Milestone: M-Vuln-3 — Real Nuclei + More Stages
- Wire real `nuclei` binary into `nuclei_safe.py` (currently stub returning [])
- Add stages: `testssl`, `nmap_nse_vuln`, `default_creds_matcher`, `katana` (passive), `correlator`, `ai_triage`
- Add Diff tab in UI (uses `VulnRunMatch.state`)
- AI triage uses existing `bounded_completion` wrapper + `ai_usage` accounting

## M-Vuln-4 (later)
- Intrusive stages: `ffuf`, `nikto`, `nuclei_intrusive`
- Per-target rate limiter (Redis token bucket: `vuln:rate:{target_id}`)
- Per-target consent UX in frontend
