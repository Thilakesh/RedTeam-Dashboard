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
⏳ In progress (2026-05-17) — all 4 adapters real (TestSSL, Nmap Deep, FFUF, Dirsearch); per-task UI live; Steps 11-12 pending

**Backend (on `dev_Tar_workspace`, scaffold pushed; Step 7 pending push):**
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
  - `pipeline/investigation/adapters/nmap_deep.py` — REAL (Step 7, 2026-05-17). Cmd `nmap -sV -sC --script vuln,banner --open -Pn {port_args} -oX {tmp} {host}`. Port args: `-p {params.port}` if explicit, else `--top-ports 1000`. Ignores `params.protocol` (port-based). Timeout 600s. Parses XML, emits `ServiceUpdateRecord` per open port + `FindingRecord` per NSE hit (vuln-category → `nse_vuln_<sid>` graded by VULNERABLE/LIKELY VULNERABLE markers; banner → `service_banner_leak`; other → `nse_<sid>`).
  - `pipeline/investigation/adapters/ffuf.py` — REAL (Step 8, 2026-05-17). Cmd `ffuf -u {protocol}://{host}[:{port}]/FUZZ -w $INVESTIGATION_WORDLIST -mc 200,204,301,302,307,401,403 -of json -t 40 -timeout 10 -noninteractive`. Honors `params.protocol` (default https) + `params.port`. Parses JSON, emits `EndpointRecord` per hit + classifier findings (admin_panel/login_form/api_endpoint/upload_form/signup_form).
  - `pipeline/investigation/adapters/dirsearch.py` — REAL (Step 9, 2026-05-17). Cmd `dirsearch -u {protocol}://{host}[:{port}] -w $INVESTIGATION_WORDLIST --format=json --quiet-mode --no-color -t 20`. High-signal kinds via regex: `exposed_dotgit` (high) / `exposed_dotenv` (high) / `backup_file` (med) / `swagger_exposed` (med) / `directory_indexing` (med, 200+html+trailing-slash heuristic).
  - `pipeline/investigation/adapters/placeholder.py` — unused (all 4 tools real) but kept for future additions.
  - `services/service_enrichment.py::upsert_service_enrichment` — Service upsert from investigation ServiceUpdateRecord. Upsert by (target_id, canonical_key); coalesce non-null fields; `cpes` uses `case+cardinality` to avoid wiping prior CPEs.
  - `services/endpoint_enrichment.py::upsert_endpoint_enrichment` — Endpoint upsert from investigation EndpointRecord. Binds asset_id from TaskContext. Applies classifier flags via shared `_classify`. Coalesce non-null on conflict; bool flags monotonically promote.
  - `workers/investigation_runner.py` — authz gate, pub/sub `investigation:{task_id}`, Redis SET `workspace:{ws_id}:tasks` for SSE filter. `_persist_result(tool=...)` dispatches findings + tls_observations + services + endpoints; passes `task.tool` through for `endpoints.source_tool` column.
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
- `app/targets/[id]/workspace/tasks/[task_id]/page.tsx` — per-task detail page (Step 10). Polls every 3s while queued/running. Dispatches to per-tool renderer.
- `components/workspace/tool-results/{NmapResult,FfufResult,DirsearchResult,TestSslResult,RawOutputCollapsible,shared}.tsx` — per-tool result renderers + shared helpers (SeverityBadge, statusVariant). NmapResult shows NSE-keyed port summary + grouped findings (vuln/banner/other). FfufResult: classifier filter buttons + endpoint table. DirsearchResult: high-signal callout + bucketed paths. TestSslResult: CVE chips + 5 grouped sections. RawOutputCollapsible: `<details>` + copy button.
- CTAs: "Target Investigation" button on `app/scans/[id]/page.tsx` and `app/dashboard/recon-jobs/page.tsx`
- AppShell nav: "Target Workspace" entry with Crosshair icon + child "Assets". Breadcrumbs for `/targets/[id]/workspace`, `/targets/[id]/workspace/tasks/[task_id]`, `/targets/[id]/risk`.
- SSE wired on workspace stream invalidates overview/subdomains/tasks queries.

**Pending:**
- Step 11: SSE verification with real adapters (smoke test full task lifecycle, ensure query invalidation fires)
- Step 12: Dynamic "View X Scan" deep links on Subdomains tab — query most-recent task per (asset, tool) and link to detail page

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
M-TW-1 all 4 investigation adapters real (TestSSL/Nmap Deep/FFUF/Dirsearch). Per-task detail page + 4 tool-result components shipped. Next: Step 11 SSE smoke test with real adapters + Step 12 dynamic "View X Scan" deep links. Plan file: `C:\Users\Admin\.claude\plans\target-workspace-gleaming-clarke.md`.
