# Application Flow

## Scan Lifecycle

```
User submits scan (POST /scans)
  → autostart=true (default): Arq job enqueued (services/queue.py), status=created
  → autostart=false: status=queued, no enqueue (user-deferred)

  Queue routing (services/queue.py):
  → profile="deep" → _queue_name="heavy" (heavy-worker picks up)
  → profile="quick"|"standard" → _queue_name="default" (worker picks up)

  Queued scan management:
  → POST /scans/{id}/start  → status=created, enqueued
  → PATCH /scans/{id}       → update profile (queued only)
  → DELETE /scans/{id}      → hard delete (queued only)

  Running scan management:
  → POST /scans/{id}/stop   → status=stopped, finished_at set, publishes scan.stopped to Redis

  runner.py picks up job (status=created)
    → loads Target, checks authorization_verified_at
    → authorization_verified = (target.authorization_verified_at is not None)
    → builds stage list from profile (pipeline/profiles.py)
    → execute_dag() (pipeline/coordinator.py)
      → topological sort → parallel execution levels
      → L0: subfinder + assetfinder (parallel, passive)
      → L1: amass, dnsx (after L0)
      → L2: httpx + asnmap + geoip (parallel, after dnsx)
      → L3: wafw00f (after httpx)
      → [deep only, authz_required=True] L4: naabu → L5: nmap → L6: gowitness
      → [deep only] L7: risk_prioritizer (optional=True, depends_on=["gowitness"])
      → [deep only, heavy queue] BBOTStage runs concurrently with passive stages
      → if stage.authz_required=True and not authorization_verified → skip (not fail)
      → if stage.optional=True and stage raises → mark failed, scan continues
    → each stage: on_start() → execute() → on_done()/on_fail()/on_skip()
    → upsert_assets() → Asset + AssetObservation rows  [tool adapter stages]
    → RiskPrioritizerStage writes directly to findings + ai_usage [AI analysis stage exception]
    → Redis pub/sub: scan:{scan_id} channel
    → On completion: check if status==stopped before writing completed/failed
      → If stopped: skip status update, do NOT publish scan.completed
      → If not stopped: write completed/failed, publish terminal event
  → scan.completed / scan.failed / scan.stopped event → SSE stream closes
```

## Scan Status Lifecycle

```
queued    → created (via POST /start or autostart=true on creation)
created   → running (worker picks up job)
running   → completed (DAG finishes, worker writes)
running   → failed (DAG raises, worker writes)
running   → stopped (POST /stop sets DB + publishes scan.stopped; worker skips overwrite)
```

## Authorization Gate

- `Target.authorization_verified_at` (nullable DateTime) controls whether active stages run
- When NULL: naabu/nmap/gowitness are skipped with reason "target not verified for active scanning"
- `ScanOut.target_authz_verified: bool` — exposed on all scan API responses so UI can warn
- UI: orange ⚠️ in Recon Jobs table for `profile=deep` AND `target_authz_verified=false`
- Manual verification: `POST /targets/{id}/generate-token` → `POST /targets/{id}/verify`
  - Verify checks DNS TXT `recon-auth=<token>` via Cloudflare DoH or `/.well-known/recon-auth.txt`
- Dev shortcut: directly set `authorization_verified_at = NOW()` in DB for local test targets
- **Automated `AuthzVerifierStage`** (built in M2): runs at L0 in deep profile
  - Tries HTTP `/.well-known/recon-auth.txt` then DNS TXT via Cloudflare DoH
  - On success: writes `authorization_verified_at` + `authorization_proof="auto_verified"` to DB
  - Flips `authz_state[0] = True` so naabu/nmap/gowitness run in SAME scan
  - If target already verified in DB: sets authz_state immediately and returns []

## Data Flow: Asset Deduplication

```
Stage returns list[AssetRecord]
  → upsert_assets() (services/assets.py)
    → INSERT INTO assets ... ON CONFLICT (target_id, type, canonical_key) DO UPDATE
    → INSERT INTO asset_observations (asset_id, scan_id, stage_id, source_tool, payload)
```

- `canonical_key` per type: subdomain=FQDN, ipv4=dotted-quad, service=host:port/proto, screenshot=FQDN
- One Asset row per unique (target_id, type, canonical_key) — accumulates across scans
- One AssetObservation per (asset, scan) — provides per-scan history for diff (future)
- `upsert_assets()` calls `flush()` not `commit()` — caller must `await db.commit()` explicitly

## Data Flow: Risk Findings

```
RiskPrioritizerStage.execute(ctx):
  Session 1 (read):
    → build_subdomain_rows(db, scan_id)   → SubdomainRow[]
    → build_port_rows(db, scan_id)         → PortRow[]
  → serialize to compact JSON asset_list
  → bounded_completion(system=SYSTEM_PROMPT, user=json.dumps(asset_list))
      → POST https://openrouter.ai/api/v1/chat/completions
      → model: openai/gpt-oss-20b:free, response_format={"type": "json_object"}
      → null content guard: if choices[0].message.content is None → BoundedCompletionError
        (includes finish_reason + model in error message for diagnostics)
      → returns CompletionResult(content, prompt_tokens, completion_tokens)
  → hallucination guard: drop FQDNs not in scan (normalized to lowercase)
  → sort by risk_score DESC, re-assign priority_rank 1..N
  Session 2 (write):
    → DELETE FROM findings WHERE scan_id = ...  (idempotent)
    → INSERT Finding rows (one per asset)
    → INSERT AiUsage row (model, prompt_tokens, completion_tokens)
    → commit
  → return []
```

**Known failure modes of gpt-oss-20b:free (both handled as BoundedCompletionError):**
- `content: null` — model rate-limited or unavailable; stage fails with clear message
- Truncated/invalid JSON — model hit output token limit; stage fails with JSONDecodeError message
Both are transient — re-running the scan will usually succeed.

## Screenshot Storage (MinIO)

```
gowitness adapter:
  → captures screenshot → uploads to MinIO bucket "recon"
  → object name: scans/<scan_id>/<fqdn>.png
  → storage.public_url() → uses MINIO_PUBLIC_URL (http://localhost:9000) not MINIO_URL (http://minio:9000)
  → URL stored in asset_observations.payload["screenshot_url"]
  → object name stored in asset_observations.payload["screenshot_object_name"]
  → bucket has public-read S3 policy (set by ensure_bucket() at worker startup)

_resolve_screenshot_url() (called from backend API, NOT worker context):
  → backend has NO MinIO env vars → storage.screenshot_url() returns None
  → falls back to stored payload["screenshot_url"] (set correctly by worker at upload time)
  → NEVER returns None if screenshot was captured — stored URL is the reliable source
```

Key env vars (worker service):
- `MINIO_URL=http://minio:9000` — internal Docker URL for SDK connections
- `MINIO_PUBLIC_URL=http://localhost:9000` — browser-accessible URL for generated links
- `OPENROUTER_API_KEY=sk-or-v1-...` — required for deep scans; `BoundedCompletionError` raised at call time if empty
**Backend API container has NO MinIO env vars** — intentional. All MinIO work happens in the worker.

**Secret resolution order** (highest priority wins):
1. Shell environment variables (e.g., CI secrets)
2. `infra/.env` (read by docker-compose, gitignored)
3. `backend/.env` (read by Pydantic Settings, gitignored)
`infra/.env` is the effective source for Docker services; `backend/.env` is only used when running backend directly (e.g., tests outside Docker).

## Enrichment Adapters (M5)

```
BBOTStage (optional=True, deep only, heavy queue, 30-min timeout):
  → asyncio subprocess: bbot -t {domain} -m subdomain-enum -o json
  → parses DNS_NAME + IP_ADDRESS events from stdout
  → domain filter: FQDN must end with .{domain} or == domain
  → returns AssetRecord[] (type=subdomain + ipv4)
```

## Subfinder Streaming Pattern (fixed 2026-05-10)

```
SubfinderStage.execute(ctx):
  → asyncio.create_subprocess_exec(binary, "-d", domain, "-silent", "-all", "-timeout", "30")
  → _collect(): async for raw in proc.stdout → parse + filter → seen.add(host)
  → asyncio.wait_for(_collect(), timeout=300)
  → TimeoutError: proc.kill() → wait up to 5s → return partial results (seen set)
  → Non-zero exit code: ignored (normal when some passive sources fail)
```
Key: `-timeout 30` caps per-source HTTP probes; `asyncio.wait_for(300)` caps total process. Partial results always returned.

## Read Model (denormalized views)

```
GET /scans/{id}/subdomains   → SubdomainRow[] (joined: http, ip, waf, cdn, tech, server, sources)
GET /scans/{id}/overview     → ScanOverview (counts, distributions)
GET /scans/{id}/ips          → IpRow[]
GET /scans/{id}/cdn-waf      → CdnWafSummary
GET /scans/{id}/technologies → TechBucket[] (label, count, subdomains: list[str])
GET /scans/{id}/ports        → PortsPage (PortRow[])
GET /scans/{id}/findings     → FindingsPage (FindingRow[], ordered by priority_rank ASC)
                               query params: severity=HIGH|MED|LOW|INFO, page, limit (1–200)
                               returns {"total": 0, "items": []} (not 404) when no findings
                               tenant-scoped via _ensure_scan_visible()
```

SubdomainRow.sources: `list[str]` — sorted list of source_tool values from asset_observations for this subdomain+scan. Purple badges in UI for enrichment tools (bbot, amass); grey for passive (subfinder, assetfinder).

## Worker Subprocess Sandbox

`backend/app/workers/sandbox.py` — applied via `preexec_fn=get_preexec_fn()` to naabu, nmap, gowitness subprocesses (Unix only; skipped on win32).

**Current limits:**
- `RLIMIT_NOFILE = 4096` — naabu opens many concurrent probe sockets

**CRITICAL: Never use `RLIMIT_AS` for Go binaries.** Go runtime reserves several GB of virtual address space for GC arenas at startup. Setting `RLIMIT_AS=768MB` causes immediate `pthread_create failed` → `SIGABRT`. The process exits in <300ms with empty stdout and no error record in the DB (stage shows "completed" with 0 assets). This is a silent failure.

## Profiles

### Recon profiles (`Scan.kind = recon`)

| Profile  | Stages                                                                                             | authz needed | Queue   |
|----------|----------------------------------------------------------------------------------------------------|-------------|---------|
| quick    | subfinder                                                                                          | No          | default |
| standard | subfinder, assetfinder, amass, dnsx, httpx, asnmap, geoip, wafw00f                               | No          | default |
| deep     | authz_verifier (L0) + standard + bbot + naabu, nmap, gowitness, risk_prioritizer                  | Yes (active)| heavy   |

### Vuln profiles (`Scan.kind = vuln_analysis`, M-Vuln-2)

| Profile        | Stages                                              | Intrusive | Queue |
|----------------|-----------------------------------------------------|-----------|-------|
| vuln_quick     | cpe_matcher, panel_detector, nuclei_safe (stub)     | No        | vuln  |
| vuln_standard  | (same as quick currently, expanded in M-Vuln-3)     | No        | vuln  |
| vuln_deep      | (same as quick currently, expanded in M-Vuln-3/4)   | Optional  | vuln  |

Vuln scans require parent recon `status=completed` (enforced at API). They consume frozen `VulnStageContext` (services + technologies + http_services from parent recon target) — adapters never re-run recon tools.

**naabu must always use `-s c` (connect scan)**: default SYN scan is silently blocked by Cloudflare and returns 0–4 ports. Connect scan finds all open ports.

## Real-time Updates

- Worker publishes to Redis channel `scan:{scan_id}`
- Events: `scan.started`, `stage.started`, `stage.completed`, `stage.failed`, `stage.skipped`, `scan.completed`, `scan.failed`, `scan.stopped`
- API: `GET /scans/{id}/stream` — SSE, closes on terminal event (`completed`, `failed`, `stopped`)
- Frontend: SSE with TanStack Query invalidation on each event
  - `scan-findings` query invalidated only on `scan.completed` (not intermediate events)

## Frontend Routing

```
/ → redirect to /dashboard
/login, /signup → (auth) layout (no AppShell)
/home → Dashboard placeholder (AppShell, empty — future widgets)
/dashboard → layout.tsx (bare AppShell wrapper) wraps:
  /dashboard          → Add Scan form ([Add] queued, [Start Scan] immediate) + "Add Scan" title
  /dashboard/recon-jobs → Recon Jobs table + 4-column stats grid (Total/Running/Completed/Failed)
                          Actions per row:
                            queued: [Start] [Delete]
                            running: [Stop]
                            completed/failed/stopped: [View Results] [Run Vuln Analysis]  ← added 2026-05-10
/scans/[id] → tabbed Scan Detail (recon)
  URL tab: ?tab= (VALID_TABS: overview|subdomains|ips|cdnwaf|tech|ports|risks|history)
  tabs: Overview | Subdomains | IP Summary | CDN/WAF | Technologies | Ports | Risks | History
  Overview: Top Risks card for completed deep scans only
  CTA on completed scans: "Run Vulnerability Analysis" → POST /vuln-scans → /vuln-scans/{new_id}
/vuln-scans → vuln scan list page (4s polling on running) (M-Vuln-2)
              accessible via sidebar nav "Vulnerability Scans" ← added 2026-05-10
/vuln-scans/[id] → vuln scan detail (M-Vuln-2, extended M-Vuln-8)
  URL tab: ?tab= (VALID_TABS: overview|vulnerabilities|by-service|by-tech|endpoints|tls|hvts|triage|diff)
  tabs:
    Overview — severity cards + KEV/CVE summary + HVT count card + public services card + top-3 risk vulns
    Vulnerabilities — paginated table, severity/status/kev-only/hvt-only filters, Risk column, inline status PATCH
    By Service — vuln grouped by service (host:port/proto), severity breakdown badges
    By Tech — vuln grouped by technology, table with CPE/category/max-risk
    Endpoints — paginated endpoint table, flag filters (all/admin/login/api/upload), links to endpoint detail
    TLS — per-service TLS observations, cert expiry, grade, deprecated protocols, weak ciphers
    HVTs — high-value target signals grouped by asset, HVT score, signal type badges
    Triage — top-20 by risk_score with CVSS/EPSS/KEV, description, remediation
    Diff — new/seen/fixed_in_this_run sections (VulnRunMatch.state)
  SSE subscription on Redis channel scan:{id} while running
/vuln-scans/[id]/endpoints/[endpoint_id] → endpoint detail page (M-Vuln-8)
  Shows: url, method, status_code, content_type, source_tool, flags (admin/login/api/upload/signup), timestamps
  Back link to ?tab=endpoints
/targets/[id]/risk → cross-scan target risk rollup (M-Vuln-8)
  Shows: open vuln severity cards, HVT signal summary, endpoint count, top-10 vulns by risk_score, latest vuln scan link
/targets → target management
```

### Sidebar Nav (AppShell.tsx) — updated 2026-05-10

```
Dashboard          → /home
Basic Recon ▼
  Add Scan         → /dashboard
  Recon Jobs       → /dashboard/recon-jobs
Vulnerability Scans → /vuln-scans   ← added
Targets            → /targets
Reports            → /reports
Settings           → /settings
```

## Vuln Scan Flow (M-Vuln-2)

```
Entry point 1: User clicks "Run Vulnerability Analysis" on completed recon scan detail (/scans/{id})
Entry point 2: User clicks "Run Vuln Analysis" on completed scan row in /dashboard/recon-jobs  ← added 2026-05-10
  → POST /vuln-scans { parent_scan_id, profile: "vuln_quick", intrusive: false }
  → API validates: parent recon scan exists in user's org, status=completed
  → Inserts Scan(kind=vuln_analysis, parent_scan_id, target_id, intrusive)
  → enqueue_vuln_scan(scan_id) → Arq queue "vuln"
  → Frontend navigates to /vuln-scans/{new_id}

vuln-worker picks up job (workers/vuln_runner.py::run_vuln_scan):
  Session 1 (read):
    → load Scan, validate kind=vuln_analysis + parent_scan_id present
    → load parent Scan + Target
    → Mark scan.status=running, started_at=now
    → load_vuln_context(): query Service, Technology, Asset(type=http_service) → VulnStageContext
    → commit + close session
  → run_vuln_dag(stages, ctx):
    → for each level (topo sort by depends_on):
      → for each stage in parallel:
        → if intrusive_required and not ctx.intrusive: on_skip(reason="intrusive not enabled")
        → if applies(ctx) and predicate is False: on_skip(reason="no_matching_inputs")
        → on_start() → records = stage.execute_vuln(ctx) → on_done(records)
        → on_done: upsert_vulns + update scan.progress_pct (weight-based)
        → if optional and raises: on_fail + log + continue; else re-raise
  → On terminal: scan.status=completed, finished_at, progress_pct=100
  → Redis publishes: scan.started, stage.started/completed/failed/skipped, scan.completed/failed
```

## Vuln Dedup + Lifecycle

```
upsert_vulns() (services/vulns.py):
  → For each VulnRecord:
    → INSERT INTO vulnerabilities ... ON CONFLICT (target_id, canonical_key) DO UPDATE
       SET last_seen=NOW(), last_verified_at=NOW(), <merge_fields>
    → INSERT INTO vuln_evidence (vulnerability_id, scan_id, stage_id, source_tool, ...)
    → Determine VulnRunMatch state:
      → if vuln existed in any prior scan → state="seen"
      → else → state="new"
    → INSERT INTO vuln_run_matches (scan_id, vulnerability_id, state) ON CONFLICT DO UPDATE

Status transitions (Vulnerability.status):
  open → triaged | false_positive (manual via PATCH /vulns/{id})
  open → fixed (auto by correlator stage in M-Vuln-3 when prior scan had vuln, current does not)
  fixed → reopened (auto when re-detected after fixed)
  * → wont_fix (manual)
```

## Scan API Kind Separation (fixed 2026-05-10)

```
GET /scans          → kind=recon only (WHERE Scan.kind == ScanKind.recon)
GET /vuln-scans     → kind=vuln_analysis only (WHERE Scan.kind == ScanKind.vuln_analysis)
```
These two lists are strictly separated. Recon jobs page only ever shows recon scans. Vuln scans page only shows vuln_analysis scans. No mixing.

## Frontend TanStack Query Keys

| Key pattern | Endpoint | Invalidated on |
|-------------|----------|----------------|
| `["scans"]` | `GET /scans` | scan create/start/stop/delete, all SSE events |
| `["scan", id]` | `GET /scans/{id}` | all SSE events |
| `["scan-subdomains", id]` | `GET /scans/{id}/subdomains` | all SSE events |
| `["scan-overview", id]` | `GET /scans/{id}/overview` | all SSE events |
| `["scan-overview-light", id]` | `GET /scans/{id}/overview` | all SSE events |
| `["scan-ips", id]` | `GET /scans/{id}/ips` | all SSE events |
| `["scan-cdn-waf", id]` | `GET /scans/{id}/cdn-waf` | all SSE events |
| `["scan-tech", id]` | `GET /scans/{id}/technologies` | all SSE events |
| `["scan-ports", id]` | `GET /scans/{id}/ports` | all SSE events |
| `["scan-findings", id, severity, page]` | `GET /scans/{id}/findings` | `scan.completed` only |
| `["scan-findings", id, "HIGH", 1]` | `GET /scans/{id}/findings?severity=HIGH&limit=5` | `scan.completed` only |
| `["vuln-scans"]` | `GET /vuln-scans` | 4s polling while running |

## Key Module Boundaries

| Module | Responsibility | Must NOT |
|--------|----------------|----------|
| pipeline/adapters/* | Invoke tool, parse output, return AssetRecord[] | Touch DB |
| pipeline/vuln/adapters/* | Consume frozen VulnStageContext, return VulnRecord[] | Touch assets/services/technologies; rerun recon tools |
| agents/risk_prioritizer.py | Read asset graph, call LLM, write findings | Return AssetRecord[] |
| agents/bounded_completion.py | HTTP call to OpenRouter, parse JSON | Know about DB or stage context |
| services/assets.py | Upsert Asset + AssetObservation; dual-write Service + Technology (flush only) | Run subprocesses |
| services/vulns.py | Upsert Vulnerability + VulnEvidence + VulnRunMatch (flush only) | Touch assets/services/technologies |
| workers/runner.py | Recon scan lifecycle, pub/sub, progress | Business logic |
| workers/vuln_runner.py | Vuln scan lifecycle, pub/sub, progress | Re-run recon stages |
| pipeline/coordinator.py | Recon DAG scheduling | Know about Redis |
| pipeline/vuln/coordinator.py | Vuln DAG scheduling, intrusive + applies gates, total_weight | Know about Redis |
| services/scan_view.py | Read-model aggregation + build_findings() | Write to DB |
| services/vuln_view.py | Vuln overview + paginated rows (scan-scoped) | Write to DB |
| services/storage.py | MinIO upload + URL generation | Use minio:9000 for public URLs |
| app/api/scans.py | Recon scan CRUD + lifecycle (kind=recon filter on list) | Business logic beyond status transitions |
| app/api/vuln_scans.py | Vuln scan CRUD + SSE + overview/vulns | Business logic beyond status transitions |
| app/api/vulns.py | PATCH vuln status (tenant-scoped via target→project→org) | Touch assets |
