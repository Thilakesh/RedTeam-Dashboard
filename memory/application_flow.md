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

| Profile  | Stages                                                                                             | authz needed | Queue   |
|----------|----------------------------------------------------------------------------------------------------|-------------|---------|
| quick    | subfinder                                                                                          | No          | default |
| standard | subfinder, assetfinder, amass, dnsx, httpx, asnmap, geoip, wafw00f                               | No          | default |
| deep     | authz_verifier (L0) + standard + bbot + naabu, nmap, gowitness, risk_prioritizer                  | Yes (active)| heavy   |

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
  /dashboard/recon-jobs → Recon Jobs table + "Recon Jobs" title + 4-column stats grid (Total/Running/Completed/Failed)
/scans/[id] → tabbed Scan Detail
  URL tab selection: ?tab=<value> (VALID_TABS: overview|subdomains|ips|cdnwaf|tech|ports|risks|history)
  tabs: Overview | Subdomains | IP Summary | CDN/WAF | Technologies | Ports | Risks | History (stub)
  Overview tab: Top Risks card for completed deep scans only
/targets → target management
```

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

## Key Module Boundaries

| Module | Responsibility | Must NOT |
|--------|----------------|----------|
| pipeline/adapters/* | Invoke tool, parse output, return AssetRecord[] | Touch DB |
| agents/risk_prioritizer.py | Read asset graph, call LLM, write findings | Return AssetRecord[] |
| agents/bounded_completion.py | HTTP call to OpenRouter, parse JSON | Know about DB or stage context |
| services/assets.py | Upsert Asset + AssetObservation (flush only — caller commits) | Run subprocesses |
| workers/runner.py | Lifecycle, pub/sub, progress | Business logic |
| pipeline/coordinator.py | DAG scheduling, parallel execution | Know about Redis |
| services/scan_view.py | Read-model aggregation + build_findings() | Write to DB |
| services/storage.py | MinIO upload + URL generation | Use minio:9000 for public URLs |
| app/api/scans.py | Scan CRUD + lifecycle endpoints | Business logic beyond status transitions |
