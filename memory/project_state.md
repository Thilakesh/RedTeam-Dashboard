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

Migrations 0005–0007. ORM models: Service, Technology, Vulnerability, VulnEvidence, VulnRunMatch. Scan.kind/parent_scan_id/intrusive. Stage.applies() predicate. upsert_assets() dual-writes Service+Technology. scan_view rewritten for first-class tables.

### M-Vuln-2 — Vuln Pipeline + Worker + API + UI
✅ Complete (commit `9c07d34` on `dev_vuln_dash`) — 2026-05-09

VulnStage Protocol + VulnStageContext + coordinator.py + profiles.py. Adapters: cpe_matcher, panel_detector, nuclei_safe (stub). Services: upsert_vulns, vuln_view. API: /vuln-scans + /vulns. Worker: vuln_runner.py (queue=vuln). Infra: Dockerfile.vuln_worker. Frontend: vuln-scans list + detail + CTA.

### M-Vuln-3 — Real Nuclei + More Safe Stages
✅ Complete (2026-05-10 commits on `dev_vuln_dash`)

Real nuclei subprocess. Added: testssl, nmap_nse_vuln, default_creds_matcher, katana, correlator (merge_by_cve + enrich_epss_kev + write_risk_scores), ai_triage. Diff tab in UI. EPSS/KEV daily refresher worker. Risk score formula: 0.30·CVSS + 0.20·EPSS + 0.15·KEV + 0.15·exposure + 0.10·hvt + 0.10·blast_radius.

### M-Vuln-4 — Intrusive Stages
⏳ Not started

### M-Vuln-5 — HVT Signals + Endpoint Discovery
✅ Complete (committed on `dev_vuln_dash` before this session)

HvtSignal model + hvt_scorer. Endpoint model + endpoint_discoverer (katana/ffuf/swagger). TlsObservation model. panel_detector + swagger_discoverer adapters. VulnStageContext extended with hvt_signals + endpoints.

### M-Vuln-6 — Conditional Execution Router
✅ Complete (committed on `dev_vuln_dash`)

Tech-specific stages gated by VulnStageContext.technologies. Conditional execution profiles. Stage.applies() extended.

### M-Vuln-7 — Correlation Engine + Risk Scoring
✅ Complete (committed on `dev_vuln_dash`)

correlator_engine.py: merge_by_cve + enrich_epss_kev + write_risk_scores. services/risk_score.py with composite formula + unit tests. feeds_refresher.py (EPSS/KEV daily refresh). ai_triage selects by risk_score DESC.

### M-Vuln-8 — UI Evolution
✅ Complete (14 commits on `dev_vuln_dash`) — 2026-05-13

**Backend:**
- `backend/app/schemas/vuln.py`: 8 new Pydantic response types (ByServiceResponse, ByTechResponse, EndpointsPage, TlsResponse, HvtResponse, TriageResponse, TargetRiskView + row types). Extended VulnOut (epss, risk_score) + VulnOverview (hvt_count, public_service_count, top_risk_vulns).
- `backend/app/services/vuln_view.py`: Added build_by_service, build_by_technology, build_endpoint_rows, build_tls_view, build_hvt_rows, build_triage_view. Updated build_vuln_overview (HVT/exposure/top-risk) + build_vuln_rows (risk_score DESC NULLS LAST sort, kev_only + hvt_only filters). VulnRow dataclass extended with epss + risk_score.
- `backend/app/api/vuln_scans.py`: 7 new endpoints (by-service, by-technology, endpoints list, endpoints/{id} detail, tls, hvts, triage). Updated /vulnerabilities (kev_only/hvt_only params). Tenant isolation on endpoint detail via scan.target_id.
- `backend/app/api/targets.py`: New GET /targets/{id}/risk cross-scan rollup (open counts, top 10 vulns, HVT inventory, endpoint count, latest vuln scan).

**Frontend:**
- `frontend/lib/api.ts`: All new TypeScript types exported (ByServiceRow, ByTechRow, EndpointRow, TlsRow, HvtRow, TriageVulnRow, TargetRiskVulnRow, TargetRiskView + response wrappers).
- `frontend/app/vuln-scans/[id]/page.tsx`: 6 new tab components (ByServiceTab, ByTechTab, EndpointsTab, TlsTab, HvtsTab, TriageTab). Updated OverviewTab (HVT count card, public services card, top-risk vulns block). Updated VulnerabilitiesTab (kevOnly/hvtOnly state + filter buttons + Risk column). Wired 9-tab shell (VALID_TABS expanded, TabsList with icons, TabsContent for all 6 new tabs).
- `frontend/app/vuln-scans/[id]/endpoints/[endpoint_id]/page.tsx`: NEW — endpoint detail page with method/status/content-type/source/flags/timestamps. Back link to `?tab=endpoints`.
- `frontend/app/targets/[id]/risk/page.tsx`: NEW — cross-scan target risk rollup page. Severity cards, HVT signal badges, endpoint count, top-10 risk table, latest vuln scan link.
- `frontend/components/AppShell.tsx`: Breadcrumbs for `/vuln-scans/*/endpoints/*` and `/targets/*/risk`.

## Current Architecture Decisions
- Docker Compose monolith (no k8s yet)
- Arq + Redis: `default` queue (recon non-deep), `heavy` queue (recon deep + bbot), `vuln` queue (vuln_analysis)
- PostgreSQL asset graph + first-class Service/Technology + Vulnerability/VulnEvidence/VulnRunMatch + HvtSignal + Endpoint + TlsObservation
- MinIO for screenshots
- SSE for real-time scan progress (Redis pub/sub `scan:{scan_id}`)
- AI: OpenRouter `openai/gpt-oss-20b:free` JSON mode
- Tenant isolation: Scan.org_id denormalized; vulns scoped via target→project chain; endpoint detail scoped by scan.target_id
- Tab state via `?tab=` URL param + VALID_TABS allowlist
- Scan kind separation: vuln_analysis scans require completed parent recon, run on `vuln` queue
- `GET /scans` filters `kind=recon` only
- Vuln dedup identity: `(target_id, canonical_key)`
- VulnRunMatch tracks per-scan new/seen/fixed state for diff view
- Risk score: 0.30·CVSS + 0.20·EPSS + 0.15·KEV + 0.15·exposure + 0.10·hvt + 0.10·blast_radius

## Carry-forward Rules (stable)
- **Sandbox**: NEVER use `RLIMIT_AS` for Go binaries — SIGABRT at startup; use `RLIMIT_NOFILE`
- **Naabu**: always use `-s c` (connect scan); SYN blocked by Cloudflare
- **Screenshot**: backend API has no MinIO env vars — `_resolve_screenshot_url()` falls back to stored URL
- **Env**: `infra/.env` is secret source of truth; `${VAR:-}` in compose overrides Pydantic `.env`
- **arq reload**: `docker compose restart worker heavy-worker vuln-worker` after Python module changes
- **Bind mount**: all worker services need `volumes: - ../backend:/app` for dev hot-swap
- **Vuln module boundary**: vuln adapters NEVER write to `assets`/`services`/`technologies` — they consume the frozen `VulnStageContext` only
- **Subfinder**: use streaming async for (not `proc.communicate()`), 300s wait_for, `-timeout 30` per-source; kill on timeout returns partial results

### M-TW-1 — Target Workspace (analyst per-asset investigation)
⏳ In progress (2026-05-16) — scaffold + TestSSL adapter live; nmap_deep/ffuf/dirsearch still placeholder

**Backend (uncommitted on `dev_vuln_dash`):**
- Migration `0012_target_workspace.py`: 3 tables (`target_workspaces`, `investigation_tasks`, `investigation_findings`) + 2 enums (`workspace_status`, `investigation_task_status`)
- Models: `TargetWorkspace`, `WorkspaceStatus`, `InvestigationTask`, `InvestigationTaskStatus`, `InvestigationFinding` — registered in `models/__init__.py`
- Services:
  - `services/target_workspace.py` — idempotent create_or_get_workspace, build_workspace_overview, build_workspace_subdomain_rows (returns `ips: [{asset_id, ip}]` for **primary IP only** via dnsx observation `primary_ip` field; tools_run unions own + primary IP tasks)
  - `services/investigation_tasks.py` — TOOLS = [nmap_deep, ffuf, dirsearch, testssl]. TOOL_REQUIRES_AUTHZ: nmap_deep/ffuf/dirsearch=True, testssl=False. `available_tools_for_asset` returns all 4 unconditionally (no capability gating). `validate_tool_for_asset` checks `tool ∈ TOOLS` and `asset.type ∈ {subdomain, ipv4}` only.
  - `services/tls.py::insert_tls_observation` — appends TlsObservation row; resolves Service by (target_id, host, port); drops silently if no matching service.
- Queue: `services/queue.py::enqueue_investigation_task` → Arq queue `investigation`
- API: `app/api/target_workspaces.py` registered in `main.py` — 8 routes (POST/GET workspaces, /overview, /subdomains, /tasks, /tasks/{id}, POST /tasks, /stream SSE)
- Schemas: `schemas/target_workspace.py` (11 Pydantic models including `WorkspaceSubdomainIpRow`)
- Worker:
  - `pipeline/investigation/stage.py` — TaskContext, FindingRecord, ServiceUpdateRecord, EndpointRecord, TlsObservationRecord, InvestigationResult, InvestigationAdapter Protocol
  - `pipeline/investigation/registry.py` — ADAPTERS dict (nmap_deep/ffuf/dirsearch = PlaceholderAdapter; testssl = TestSslAdapter)
  - `pipeline/investigation/adapters/testssl.py` — REAL. Subprocess `testssl.sh --quiet --jsonfile-pretty --protocols --server-defaults --vulnerable {fqdn|ip}:{port}`, 600s timeout, parses JSON, classifies into kinds (weak_cipher/insecure_protocol/expired_cert/self_signed_cert/tls_vuln/tls_misconfig). Honors `params.port` (default 443); HTTPS implicit.
  - `pipeline/investigation/adapters/placeholder.py` — sleeps 1s + emits one INFO finding echoing params
  - `workers/investigation_runner.py` — authz gate, pub/sub `investigation:{task_id}`, Redis SET `workspace:{ws_id}:tasks` for SSE filter, `_persist_result` dispatches findings + tls_observations (services/endpoints dispatch TODO for nmap/ffuf/dirsearch)
- Infra: `Dockerfile.investigation_worker` (nmap + ffuf 2.1.0 + dirsearch 0.4.3 + testssl 3.2 + SecLists `/wordlists/common.txt`); compose service `investigation-worker`

**Frontend (uncommitted):**
- `lib/api.ts` extended: WorkspaceOut, WorkspaceListRow, WorkspaceOverview, WorkspaceSubdomainRow (with `ips: WorkspaceSubdomainIpRow[]`), InvestigationTaskOut, InvestigationFindingOut, InvestigationTaskDetailOut, TOOL_LABELS, 7 helpers
- `app/targets/page.tsx` — workspace list
- `app/targets/[id]/workspace/page.tsx` — 3 tabs (Overview, Subdomains, Run Scan Details). Subdomains tab:
  - **Expandable rows**: click chevron to reveal `ScanTargetPanel` for FQDN + one per primary IP (currently capped at one per user request)
  - **Per-target panel**: Protocol toggle (HTTP/HTTPS segmented), Tool dropdown (all 4 always), Run Scan button. POST `/tasks` with `params: {protocol, port}`.
  - **Column-header sort**: clickable headers with `↕ / ↑ / ↓` icons (lucide ArrowUpDown/ArrowUp/ArrowDown). Sortable: Subdomain (asc default), Status (desc), Ports (desc), IPs (desc), Tools Run (desc). Click same header to flip direction.
  - IPs column shows primary IP only.
  - `tools_run` chips on row; expanded section shows "View X results →" links to ?tab=tasks.
- CTAs: "Target Investigation" button on `app/scans/[id]/page.tsx` and `app/dashboard/recon-jobs/page.tsx`
- AppShell nav: "Target Workspace" entry with Crosshair icon + child "Assets". Breadcrumbs for `/targets/[id]/workspace`, `/targets/[id]/workspace/tasks/[task_id]`, `/targets/[id]/risk`.
- SSE wired on workspace stream invalidates overview/subdomains/tasks queries.

**Pending:**
- Step 7: Nmap Deep adapter — `-sV -sC --script vuln,banner -p- --top-ports 1000`; emit ServiceUpdateRecord rows + nse_vuln_* / service_banner_leak findings
- Step 8: FFUF adapter — `ffuf -u {protocol}://{host}/FUZZ -w $INVESTIGATION_WORDLIST -mc 200,204,301,302,307,401,403 -of json`; upsert Endpoint + classify admin/login/api/upload
- Step 9: Dirsearch adapter — `dirsearch -u {protocol}://{host} -w $INVESTIGATION_WORDLIST --format=json`; upsert Endpoint + detect .git/.env/backup/swagger
- Step 10: `/targets/[id]/workspace/tasks/[task_id]/page.tsx` per-task result page + 4 tool-result components + RawOutputCollapsible
- Step 11: SSE verification with real adapters
- Step 12: Dynamic "View X Scan" deep links to most-recent task per (asset, tool)
- Worker `_persist_result` wiring for `result.services` (Service upsert) + `result.endpoints` (Endpoint upsert) — needed before step 7/8/9 land

**Locked design decisions (user, 2026-05-16):**
1. New `TargetWorkspace` + `InvestigationTask` tables, NOT a ScanKind
2. Idempotent on (target_id, parent_scan_id)
3. Live asset reference (no snapshot)
4. Results enrich existing tables (Service/Endpoint/TlsObservation) + new InvestigationFinding for tool-specific signals
5. Authz gate: nmap_deep/ffuf/dirsearch require `Target.authorization_verified_at`; testssl exempt
6. Dedicated `investigation` Arq queue + worker
7. **All 4 tools shown for every asset** (no capability gating in UI or backend); analyst decides applicability
8. **Primary IP only** per subdomain (not all IPs)
9. **Per-target protocol selector** (HTTP/HTTPS) on each expanded scan panel; tools receive `params.protocol` + `params.port`
10. **Column-header sort** in Subdomains table (not separate sort dropdown)

## Current Focus
M-TW-1 scaffold live with TestSSL real adapter; nmap_deep/ffuf/dirsearch placeholder. Next: Nmap Deep adapter (Step 7) + worker dispatch for Service upsert. Plan file: `C:\Users\Admin\.claude\plans\target-workspace-gleaming-clarke.md`.
