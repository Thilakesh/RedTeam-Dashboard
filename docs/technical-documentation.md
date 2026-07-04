# Technical Documentation

---

## Application Workflow (End-to-End)

The platform supports three distinct workflows that build on each other:

1. **Recon Scan** — an admin or analyst submits a domain, chooses a scan profile (quick / standard / deep), and a background worker runs a DAG of reconnaissance tools. Normalized assets stream back to the UI in real time.
2. **Vulnerability Analysis** — once a recon scan completes, the analyst triggers a vuln scan against the same target. A dedicated worker runs matcher and active-check tools against the known services, correlates CVEs, scores risk, and surfaces findings in a 9-tab UI.
3. **Target Workspace Investigation** — for any completed recon target, the analyst opens the workspace and runs per-asset deep tools (nmap intensive scan, FFUF directory brute-force, Dirsearch path enumeration, TestSSL TLS audit) against specific subdomains or IPs.

All three workflows are scoped per organization and per user (admin vs analyst), share a PostgreSQL asset graph, and stream progress to the browser via Server-Sent Events over Redis pub/sub.

---

## Authentication Flow

### Onboarding (invite-only)
There is no public signup. An admin user is bootstrapped from `ADMIN_EMAIL` / `ADMIN_PASSWORD` environment variables on the first backend startup (`_ensure_bootstrap_admin()` in `main.py`). The admin invites additional users via `POST /users` which generates a single-use token (24h TTL) and delivers a link. The invited user sets their password via `POST /auth/invite/accept`.

### Cookie-based RS256 auth
Three cookies are set on login and each refresh:

| Cookie | Name | Storage | TTL | Path | Purpose |
|---|---|---|---|---|---|
| Access token | `rt_access` | HttpOnly | 10 min | `/` | RS256 JWT, verified on every request |
| Refresh token | `rt_refresh` | HttpOnly, SameSite=Strict | 14 days | `/auth` | Opaque token for session rotation |
| CSRF token | `rt_csrf` | JS-readable, SameSite=Strict | 14 days | `/` | Echoed as `X-CSRF-Token` header |

The access token is short-lived. The frontend transparently refreshes it: when the API returns 401, `lib/api.ts::tryRefresh()` sends a single `POST /auth/refresh` (deduped with a singleton promise), then retries the original request. If refresh fails, the user is redirected to `/login`.

### Rotating refresh + reuse detection
Each `/auth/refresh` call rotates the refresh token: the old session row is marked `revoked=true` + `revoked_reason="rotation"`, and a new `RefreshSession` row is created with a `parent_session_id` link. If a revoked token is presented again, the entire chain is revoked and an `auth.refresh_reuse_detected` audit event is logged — indicating a stolen token scenario.

### Token validation (per request)
`backend/app/api/deps.py::_resolve_current_user()`:
1. Read `rt_access` cookie → decode RS256 JWT → extract `sub` (user_id), `jti`, `sid`
2. Redis fast-path: `EXISTS blacklist:jti:{jti}` + `EXISTS blacklist:sid:{sid}`
3. DB fallback: query `BlacklistedJti` table
4. Load `User` row, check `is_active`

### RBAC
Two roles: `admin` and `analyst`. `CurrentUser.scan_filter(model_column)` returns `true()` for admins (see all org scans) or `model_column == user.id` for analysts (own scans only). Feature flags per user via `UserFeature` rows, checked via `features.is_enabled()`.

### CSRF protection
`backend/app/api/middleware/csrf.py` — all mutating requests (POST/PUT/PATCH/DELETE) must include the `X-CSRF-Token` header matching the `rt_csrf` cookie value. `lib/api.ts::doFetch()` reads the cookie and injects the header automatically for all non-GET requests.

### Password hashing
`bcrypt` directly (no passlib). `app/core/security.py` truncates passwords to bcrypt's 72-byte limit explicitly. Passlib breaks with `bcrypt>=4.1` — do not reintroduce it.

---

## Module Descriptions

### `backend/app/api/`
FastAPI routers. Each router owns its own auth dependency injection, input validation (Pydantic schemas), and tenant scoping. The `deps.py` module provides `get_current_user`, `require_role()`, and `require_feature()` FastAPI dependencies. CSRF middleware wraps the entire app.

### `backend/app/pipeline/` — Recon pipeline
Core abstractions for running recon tools. `stage.py` defines the `Stage` protocol: `name`, `source_tool`, `authz_required`, `optional`, `depends_on`, and `async execute(ctx) -> list[AssetRecord]`. `coordinator.py` topologically sorts stages by `depends_on`, groups them into parallel execution levels, and runs levels sequentially. Each level runs its stages concurrently.

### `backend/app/pipeline/adapters/`
One file per recon tool. Each adapter invokes its CLI binary via `asyncio.create_subprocess_exec` (never `shell=True`), parses stdout, and returns `AssetRecord[]`. Adapters never touch the DB. Currently: subfinder, assetfinder, amass, dnsx, httpx, naabu, nmap, gowitness, wafw00f, asnmap, geoip, bbot.

### `backend/app/pipeline/vuln/`
Parallel to the recon pipeline but for vulnerability analysis. `stage.py` defines `VulnStage` protocol with `execute_vuln(ctx: VulnStageContext) -> list[VulnRecord]` and `applies(ctx) -> bool` for conditional execution. `coordinator.py` runs the vuln DAG. `profiles.py` maps profile names to stage lists. Adapters consume a frozen `VulnStageContext` (services + technologies + http_services from the parent recon scan) — they never re-run recon tools.

### `backend/app/pipeline/investigation/`
Investigation adapters for the Target Workspace. `stage.py` defines `InvestigationAdapter` protocol with `execute(ctx: TaskContext) -> InvestigationResult`. Each adapter returns `FindingRecord[]`, `ServiceUpdateRecord[]`, `EndpointRecord[]`, and `TlsObservationRecord[]`. `registry.py` maps tool names to adapter instances. `scan_profiles.py` defines per-tool profile arg presets.

### `backend/app/services/`
Business logic layer. Key services:
- `assets.py` — `upsert_assets()`: deduplicated INSERT … ON CONFLICT for Asset + AssetObservation rows; also dual-writes Service and Technology from httpx output
- `vulns.py` — `upsert_vulns()`: similar dedup pattern for Vulnerability + VulnEvidence + VulnRunMatch
- `scan_view.py` — read-model aggregation: subdomains, IPs, CDN/WAF, tech buckets, ports, findings
- `vuln_view.py` — vuln read-model: overview, paginated vuln rows, by-service, by-tech, endpoints, TLS, HVTs, triage
- `queue.py` — `enqueue_scan()`, `enqueue_vuln_scan()`, `enqueue_investigation_task()` — opens and closes a Redis connection per enqueue (acceptable at current load)
- `scan_profiles.py` — `PROFILES` dict mapping tool names to profile bundles (`id`, `label`, `args`, `description`); `resolve_args()` applies profile to scan params

### `backend/app/workers/`
Arq worker entrypoints. Each worker function handles the scan lifecycle: load scan, set status=running, execute the pipeline, write terminal status, publish pub/sub events. Workers never contain business logic — they delegate to pipeline coordinators and service functions.

### `backend/app/agents/`
LLM integration. `bounded_completion.py` wraps OpenRouter API calls with null-content guard and token counting. `risk_prioritizer.py` reads the asset graph (subdomains + ports), serializes to JSON, calls the LLM, applies a hallucination guard (drops FQDNs not in the scan), and writes `Finding` rows sorted by `risk_score DESC`.

### `backend/app/models/`
SQLAlchemy ORM. All models re-exported from `__init__.py` — required for Alembic autogenerate to see them. Models use `Mapped[]` type annotations (SQLAlchemy 2.0 style). Every new model must be added to `__init__.py`.

### `backend/app/schemas/`
Pydantic v2 request/response models. ORM-derived response models use `model_config = ConfigDict(from_attributes=True)`. Field validators are inline (no separate validator files).

---

## Recon Pipeline Execution

### Profiles

| Profile | Queue | Stages | Authz required |
|---|---|---|---|
| `quick` | default | subfinder | No |
| `standard` | default | subfinder, assetfinder, amass, dnsx, httpx, asnmap, geoip, wafw00f | No |
| `deep` | heavy | all standard + bbot + naabu, nmap, gowitness, risk_prioritizer | No (authz gating removed) |

**Note:** Authorization gating (DNS/HTTP ownership proof) was removed in migration `0017_drop_target_verification.py`. All stages run regardless of target ownership. The platform is now a trusted-operator model — access control is RBAC only.

### DAG levels (deep profile)

| Level | Stages | Runs after |
|---|---|---|
| L0 | subfinder, assetfinder | — |
| L1 | amass, dnsx | L0 |
| L2 | httpx, asnmap, geoip | L1 (dnsx) |
| L3 | wafw00f | L2 (httpx) |
| L4 | naabu | L3 |
| L5 | nmap | L4 |
| L6 | gowitness | L5 |
| L7 | risk_prioritizer (optional=True) | L6 (gowitness) |

BBOT runs in the heavy worker concurrently with L0+ as a separate Arq job.

### Stage lifecycle events (Redis pub/sub `scan:{scan_id}`)

`scan.started`, `stage.started`, `stage.completed`, `stage.failed`, `stage.skipped`, `scan.completed`, `scan.failed`, `scan.stopped`

Terminal events: `scan.completed`, `scan.failed`, `scan.stopped` → SSE generator closes.

### Asset deduplication

```
Stage returns list[AssetRecord]
→ upsert_assets() (services/assets.py)
  → INSERT INTO assets ... ON CONFLICT (target_id, type, canonical_key) DO UPDATE
  → INSERT INTO asset_observations (asset_id, scan_id, stage_id, source_tool, payload)
```

`canonical_key` per type: `subdomain` = lowercased FQDN, `ipv4` = dotted-quad, `service` = `host:port/proto`, `screenshot` = FQDN. Do not change `canonical_key` values — changing them requires a data migration.

---

## Vulnerability Scan Flow

### Trigger
`POST /vuln-scans { parent_scan_id, profile, intrusive }` — validates parent recon `status=completed` and same org. Creates `Scan(kind=vuln_analysis, parent_scan_id, intrusive)` and enqueues to `vuln` queue.

### Worker execution (`workers/vuln_runner.py`)
1. Load Scan + parent Scan + Target
2. Set `status=running`
3. `load_vuln_context()` — query Service, Technology, Asset(type=http_service) → build frozen `VulnStageContext` (no lazy relationships)
4. `run_vuln_dag(stages, ctx)` — for each topo level, for each stage in parallel:
   - if `intrusive_required` and not `ctx.intrusive` → skip
   - if `applies(ctx)` returns False → skip (conditional execution by tech match)
   - `execute_vuln(ctx)` → `upsert_vulns()` → update `scan.progress_pct`
5. Terminal: `status=completed/failed`, `progress_pct=100`, publish `scan.completed/failed`

### Correlator + risk scoring
`correlator_engine.py` runs as a final vuln stage:
1. `merge_by_cve` — deduplicate findings across adapters by CVE ID
2. `enrich_epss_kev` — look up EPSS scores and KEV status from `CveIntel` table
3. `write_risk_scores` — compute composite score and persist

**Risk formula:** `0.30·CVSS + 0.20·EPSS + 0.15·KEV + 0.15·exposure + 0.10·hvt + 0.10·blast_radius`

### EPSS/KEV refresh
`workers/feeds_refresher.py` — scheduled daily Arq job. Fetches EPSS CSV + CISA KEV JSON, upserts `CveIntel` rows.

### Vulnerability dedup and lifecycle

```
upsert_vulns():
  → INSERT INTO vulnerabilities ON CONFLICT (target_id, canonical_key) DO UPDATE
  → INSERT INTO vuln_evidence (vulnerability_id, scan_id, source_tool)
  → VulnRunMatch.state = "new" (first detection) or "seen" (subsequent)
```

Status workflow: `open → triaged | false_positive` (manual PATCH), `open → fixed` (correlator: present in prior scan, absent in current), `fixed → reopened` (re-detected after fix), `* → wont_fix` (manual).

---

## Target Workspace / Investigation

### Workspace creation
`POST /target-workspaces` → idempotent: `create_or_get_workspace(target_id, parent_scan_id)`. One workspace per (target, parent scan). Returns existing row if already created.

### Investigation task creation
`POST /target-workspaces/{ws}/tasks { asset_id, tool, params }` → `create_and_enqueue_task()`:
- `params` carries `{ protocol, port, profile, custom_args }`
- Tool validated against `TOOLS = [nmap_deep, ffuf, dirsearch, testssl]`
- Asset type must be `subdomain` or `ipv4`
- No authz gating — any analyst with workspace access can run any tool

**Important:** `asset_id` is currently `NOT NULL`. The logical-otter plan (pending) adds a manual-target path that makes it nullable.

### Scan profiles
`services/scan_profiles.py::PROFILES` — per-tool profile bundles exposed via `GET /target-workspaces/scan-profiles`. Frontend `ScanConfigurationCard` fetches this and populates the profile dropdown. Custom profile: `params.profile="custom"` + `params.custom_args` (shlex-split, never `shell=True`).

### Command preview
`POST /target-workspaces/{ws}/operations/preview { asset_id, tool, params }` → `build_command_preview()` → server-side rendered command string. Frontend shows this in the preview box before running.

### Worker execution (`workers/investigation_runner.py`)
1. Load task, asset, workspace
2. Set `status=running`
3. Get adapter from `pipeline/investigation/registry.ADAPTERS[tool]`
4. `adapter.execute(ctx)` → `InvestigationResult`
5. Persist results:
   - `result.findings` → `InvestigationFinding` rows (always written)
   - `result.services` → `upsert_service_enrichment()` (only if `asset_id is not None`)
   - `result.endpoints` → `upsert_endpoint_enrichment()` (only if `asset_id is not None`)
   - `result.tls_observations` → `insert_tls_observation()` (only if `asset_id is not None`)
6. Publish to Redis `investigation:{task_id}`, write `workspace:{ws_id}:tasks` SSE filter key

### Investigation adapters

| Tool | Adapter | Command | Timeout |
|---|---|---|---|
| `nmap_deep` | `NmapDeepAdapter` | `nmap -sV -sC --script vuln,banner --open -Pn {ports} {host}` | 600s |
| `ffuf` | `FfufAdapter` | `ffuf -u {protocol}://{host}/FUZZ -w $INVESTIGATION_WORDLIST -mc 200,204,301,302,307,401,403` | 600s |
| `dirsearch` | `DirsearchAdapter` | `dirsearch -u {protocol}://{host} -w $INVESTIGATION_WORDLIST --format=json` | 600s |
| `testssl` | `TestSslAdapter` | `testssl.sh --quiet --jsonfile-pretty --protocols --server-defaults --vulnerable {host}:{port}` | 600s |

**FFUF wordlist:** `$INVESTIGATION_WORDLIST` env var → `/wordlists/common.txt` (SecLists) bundled in `Dockerfile.investigation_worker`.

---

## Database Interactions

### SQLAlchemy 2.0 async style
```python
# correct
result = await db.scalar(select(Scan).where(Scan.id == scan_id))
rows = (await db.scalars(select(Asset).where(Asset.target_id == tid))).all()

# wrong (legacy)
db.query(Scan).filter(...)
```

### Upsert pattern (assets + vulns)
```python
# ON CONFLICT (target_id, type, canonical_key) DO UPDATE SET last_seen = now()
stmt = insert(Asset).values(**data).on_conflict_do_update(
    index_elements=["target_id", "type", "canonical_key"],
    set_={"last_seen": func.now(), ...}
)
await db.execute(stmt)
await db.flush()  # caller must commit
```

`flush()` writes to the DB transaction but does not commit — the calling worker must `await db.commit()`. This allows callers to bundle multiple upserts into a single transaction.

### Alembic ENUM gotcha
```python
# CORRECT — one instance, one .create() call, reuse the same object
status_enum = postgresql.ENUM("queued", "running", "completed", name="scan_status", create_type=False)
status_enum.create(op.get_bind(), checkfirst=True)

op.create_table("scans",
    sa.Column("status", status_enum, nullable=False),
    ...
)
```
Never use `sa.Enum(name=..., create_type=False)` in column definitions — SQLAlchemy treats it as a new type with `create_type=True` and fires a second `CREATE TYPE` which crashes.

---

## API Request Lifecycle

All frontend HTTP goes through `frontend/lib/api.ts::api<T>(path, init)`:

1. Build headers — add `Content-Type: application/json` if body present
2. If mutating method (not GET/HEAD/OPTIONS) — read `rt_csrf` cookie, inject `X-CSRF-Token` header
3. `fetch(API_URL + path, { credentials: "include", ...headers })`
4. If response is `401` and not already a refresh attempt:
   - Call `tryRefresh()` (singleton promise — parallel calls wait on the same refresh)
   - If refresh succeeds → retry original request
   - If refresh fails → `window.location.assign("/login")`
5. If `!res.ok` → throw `ApiError(status, detail)` (handles Pydantic 422 arrays)
6. If `204` → return `undefined`
7. Otherwise → `res.json()`

`ApiError` vs `TypeError`: auth layout pages distinguish these cases. `TypeError` means the API is unreachable (CORS or network) and surfaces a "cannot reach API" message instead of a generic error.

---

## State Management

### TanStack Query key conventions

| Key pattern | Endpoint | Invalidated on |
|---|---|---|
| `["scans"]` | GET /scans | scan create/start/stop/delete + all SSE events |
| `["scan", id]` | GET /scans/{id} | all SSE events |
| `["scan-subdomains", id]` | GET /scans/{id}/subdomains | all SSE events |
| `["scan-overview", id]` | GET /scans/{id}/overview | all SSE events |
| `["scan-ports", id]` | GET /scans/{id}/ports | all SSE events |
| `["scan-findings", id, severity, page]` | GET /scans/{id}/findings | `scan.completed` only |
| `["vuln-scans"]` | GET /vuln-scans | 4s polling while running |
| `["workspace-tasks", wsId]` | GET /target-workspaces/{ws}/tasks | SSE task events |
| `["workspace-overview", wsId]` | GET /target-workspaces/{ws}/overview | SSE task events |

### Tab state
All tabbed pages use `?tab=` URL param + `VALID_TABS` allowlist. Invalid tab values silently fall back to the default tab. This makes tabs deep-linkable and browser-back-navigable.

### localStorage usage
Only for saved scan profiles in `ScanConfigurationCard` — key pattern `tw:saved-profiles:{tool}`. Auth tokens are NOT in localStorage (HttpOnly cookies).

---

## Real-time Updates

### Flow
Worker → `await redis.publish(f"scan:{scan_id}", json.dumps({event, ...}))` → API SSE endpoint subscribes → `EventSource` in browser → TanStack Query `invalidateQueries`.

### SSE endpoints

| Endpoint | Channel | Closes on |
|---|---|---|
| `GET /scans/{id}/stream` | `scan:{id}` | `scan.completed`, `scan.failed`, `scan.stopped` |
| `GET /vuln-scans/{id}/stream` | `scan:{id}` | `scan.completed`, `scan.failed` |
| `GET /target-workspaces/{ws}/stream` | `investigation:{task_id}` for tasks in workspace | client disconnect |

### Cross-origin requirement
Frontend runs on `:3000`, API on `:8000`. `EventSource` is cross-origin and drops cookies by default. All SSE clients must pass `{ withCredentials: true }`:
```typescript
const es = new EventSource(sseUrl(`/scans/${id}/stream`), { withCredentials: true });
```
The backend already has `allow_credentials=True` in CORS config. Without `withCredentials`, the `rt_access` cookie is not sent and the SSE endpoint returns 401.

---

## Screenshot Storage (MinIO)

```
gowitness adapter (runs in heavy-worker):
  → capture screenshot → upload to MinIO bucket "recon"
  → object name: scans/{scan_id}/{fqdn}.png
  → storage.public_url() uses MINIO_PUBLIC_URL (http://localhost:9000) — browser-accessible
  → URL stored in asset_observations.payload["screenshot_url"]

API (backend container, NO MinIO env vars):
  → _resolve_screenshot_url() → storage.screenshot_url() returns None (no env)
  → falls back to stored payload["screenshot_url"] — always set correctly by worker
```

Never serve `minio:9000` URLs to the browser — that hostname only resolves inside Docker. `MINIO_PUBLIC_URL` must be the browser-accessible URL.

---

## AI Integration

`backend/app/agents/bounded_completion.py`:
- Provider: OpenRouter → `openai/gpt-oss-20b:free`
- `response_format={"type": "json_object"}` (JSON mode)
- Null-content guard: if `choices[0].message.content is None` → raise `BoundedCompletionError` (includes `finish_reason` + model for diagnostics)
- Returns `CompletionResult(content, prompt_tokens, completion_tokens)`

`backend/app/agents/risk_prioritizer.py`:
- Builds compact JSON from `SubdomainRow[]` + `PortRow[]`
- Hallucination guard: drops any FQDN in LLM output not present in the scan's asset set
- Writes `Finding` rows sorted by `risk_score DESC`, re-assigns `priority_rank 1..N`
- Writes `AiUsage` row (model, token counts) for cost tracking
- Token failures: both `content: null` and truncated JSON are `BoundedCompletionError` — transient, re-running the scan usually succeeds

`OPENROUTER_API_KEY` is required for deep scans. If not set, `BoundedCompletionError` is raised at call time. The `risk_prioritizer` stage is `optional=True` so a missing key makes the stage fail gracefully without failing the entire scan.

---

## Security Considerations

| Area | Implementation | Notes |
|---|---|---|
| Password hashing | `bcrypt` direct, 72-byte input truncation | Never use passlib — breaks with bcrypt≥4.1 |
| Access tokens | RS256 asymmetric JWT, 10-min TTL, HttpOnly cookie | Private key in Docker volume `jwt_secrets`, auto-generated on first boot |
| Refresh tokens | Opaque bcrypt-hashed, rotating, reuse detection | Chain revocation on reuse — entire session tree invalidated |
| CSRF | Double-submit cookie pattern, `X-CSRF-Token` header required on mutations | `SameSite=Strict` on refresh + CSRF cookies |
| CORS | `cors_origin_regex` matches any localhost port; `cors_origins` for explicit prod origins | API returns 200 on preflight but no `Allow-Origin` header if origin doesn't match — request fails in browser |
| Worker subprocesses | `asyncio.create_subprocess_exec` (never `shell=True`) | All tool args passed as list — argument injection not possible from parsed inputs |
| Worker sandbox | `sandbox.py`: `RLIMIT_NOFILE=4096` | Never use `RLIMIT_AS` — kills Go binaries (SIGABRT at startup) |
| Command builder | `shlex.split` on custom_args, denylist for dangerous flags | `validate_custom_args()` in `scan_profiles.py` |
| Tenant isolation | `Scan.org_id` denormalized, `CurrentUser.scan_filter()` applied on all queries | Admin sees all org data; analyst sees own only |
| Audit log | `services/audit.py::log()` called on login/logout/invite/refresh events | Actor, action, target_type, target_id, IP, UA stored |

---

## Known Limitations

| Limitation | Impact | Plan |
|---|---|---|
| DAG stages execute sequentially per level, not true parallel in a single worker | Slower scans | Arq can run multiple workers; parallel levels already run with asyncio.gather |
| No frontend test suite | Regressions catch manually | M1+ checklist: pytest + testcontainers for backend; frontend testing TBD |
| Worker subprocess: no disk quota per scan | A runaway scan could fill worker disk | M2 hardening (deferred) |
| MinIO public URLs are unsigned (no expiry) | Screenshot URLs never expire | Implement signed URL generation with TTL |
| `gpt-oss-20b:free` null-content failures | Deep scan Risks tab shows empty on transient LLM failure | Retry logic or model fallback not yet implemented |
| `services/queue.py` opens/closes Redis connection per enqueue | Minor overhead at low scan volume | Pool when submission frequency justifies it |
| Investigation `asset_id` is NOT NULL | Blocks standalone manual target operations | logical-otter plan (pending) adds migration 0019 |
