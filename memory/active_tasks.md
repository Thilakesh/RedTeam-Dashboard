# Active Tasks

## Completed This Session (2026-05-13) — M-Vuln-8 UI Evolution

14 commits on `dev_vuln_dash` branch. All tasks passed spec review + code quality review.

### Backend
- [x] `backend/app/schemas/vuln.py` — 8 new Pydantic response types; extended VulnOut (epss, risk_score) + VulnOverview (hvt_count, public_service_count, top_risk_vulns)
- [x] `backend/app/services/vuln_view.py` — Added: build_by_service, build_by_technology, build_endpoint_rows, build_tls_view, build_hvt_rows, build_triage_view. Updated: build_vuln_overview (HVT/exposure/top-risk), build_vuln_rows (risk_score sort + kev/hvt filters), VulnRow dataclass (epss + risk_score fields)
- [x] `backend/app/api/vuln_scans.py` — 7 new GET endpoints (by-service, by-technology, endpoints, endpoints/{id}, tls, hvts, triage). Updated /vulnerabilities (kev_only + hvt_only query params)
- [x] `backend/app/api/targets.py` — New GET /targets/{id}/risk cross-scan rollup

### Frontend
- [x] `frontend/lib/api.ts` — All new TS types (ByServiceRow, ByTechRow, EndpointRow, TlsRow, HvtRow, TriageVulnRow, TargetRiskView + response wrappers)
- [x] `frontend/app/vuln-scans/[id]/page.tsx` — 6 new tab components; updated OverviewTab + VulnerabilitiesTab; wired 9-tab shell
- [x] `frontend/app/vuln-scans/[id]/endpoints/[endpoint_id]/page.tsx` — NEW endpoint detail page
- [x] `frontend/app/targets/[id]/risk/page.tsx` — NEW target risk rollup page
- [x] `frontend/components/AppShell.tsx` — Breadcrumbs for new routes

## Previously Completed (M-Vuln-1 through M-Vuln-7)
See project_state.md for full history.

## Pending / Needs User Action

### Push + PR
Branch `dev_vuln_dash` has 14 new commits not yet pushed this session:
```bash
git push origin dev_vuln_dash
```
Then create PR: https://github.com/Thilakesh/RedTeam-Dashboard/compare/main...dev_vuln_dash

### UI smoke test (no automated tests for frontend)
- Start `docker compose up` in `infra/`
- Navigate to `/vuln-scans/<id>` — verify all 9 tabs render, empty states show for tabs without data
- Check Vulnerabilities tab: KEV-only + HVT-only toggle buttons visible; Risk column present
- Check Overview tab: HVT count card + public services card (conditional on data)
- Navigate to `/vuln-scans/<id>/endpoints/<ep_id>` from Endpoints tab — endpoint detail renders
- Navigate to `/targets/<id>/risk` — severity cards render

## Next Milestone Options

### M-Vuln-4 — Intrusive Stages
- `ffuf` (dir/path fuzz), `nikto`, `nuclei_intrusive` (severity high+, tagged rce/sqli/fuzz)
- Rate limiter: Redis token bucket `vuln:rate:{target_id}` + `vuln:rate:{org_id}:intrusive`
- Per-target consent UX: intrusive opt-in checkbox + warning modal

### PR + Branch Merge
- Dev branch has M-Vuln-1 through M-Vuln-8 complete
- Could merge to main and start fresh branch for M-Vuln-4
