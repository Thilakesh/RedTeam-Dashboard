# Developer Handover

Getting productive on this codebase from scratch. Assumes Docker Desktop,
Python 3.11+, Node 20+ installed. For architecture see
[`architecture.md`](architecture.md); for API/model detail see
[`technical-documentation.md`](technical-documentation.md).

---

## 1. First boot (10 minutes)

```
cd infra
docker compose up --build          # first run; downloads images + builds workers
```

What you get:
- `backend` runs `alembic upgrade head` (currently → `0020`), bootstraps a
  Default Organization + Default Project + admin user from
  `ADMIN_EMAIL` / `ADMIN_PASSWORD` (in `infra/.env`).
- 3 workers register their Arq queues: `default`, `heavy`, `investigation`.
- `frontend` starts Next.js dev server with HMR.

Open:
- Frontend: <http://localhost:3000> — log in with the admin creds from
  `infra/.env`.
- Swagger: <http://localhost:8000/docs>.

Subsequent runs: `docker compose up` (no rebuild). Rebuild only when
`pyproject.toml` / `package.json` / a Dockerfile changes.

Common commands:

| Task                                    | Command                                                              |
|-----------------------------------------|----------------------------------------------------------------------|
| Tail backend logs                        | `docker compose logs -f backend`                                     |
| Tail a worker                            | `docker compose logs -f investigation-worker`                        |
| Restart a worker after Python edits      | `docker compose restart worker heavy-worker investigation-worker`    |
| Rebuild backend image (deps changed)     | `docker compose up -d --build backend`                               |
| Reset the DB (destructive)               | `docker compose down -v && docker compose up --build`                |
| Run alembic                              | `docker compose exec backend alembic <cmd>`                          |
| Open psql                                | `docker compose exec postgres psql -U recon -d recon`                |
| Frontend typecheck                       | `cd frontend && npx tsc --noEmit`                                    |

---

## 2. Repo layout (short)

- `backend/app/api/` — FastAPI routers.
- `backend/app/services/` — business logic (tenant scoping, upserts).
- `backend/app/pipeline/` — recon DAG + investigation adapters.
- `backend/app/workers/` — Arq entrypoints.
- `backend/app/models/` — ORM. Update `__init__.py` when you add one.
- `backend/migrations/versions/` — alembic. Current head = `0020`.
- `frontend/app/` — Next.js App Router routes.
- `frontend/components/` — UI + shared tool-result renderers.
- `frontend/lib/api.ts` — API client. Every fetch goes through here.
- `infra/docker-compose.yml` + `infra/Dockerfile.*` — deploy.
- `docs/` — architecture / handover / technical / diagrams (this folder).
- `APPLICATION_GUIDE.md` — end-user feature guide.

---

## 3. Mental model

Three distinct scan workflows share primitives:

| Workflow                | Entry point (UI)                     | Backend surface           | Queue          | Adapter home                                                      |
|-------------------------|--------------------------------------|---------------------------|----------------|-------------------------------------------------------------------|
| **Basic Recon**         | `/dashboard` → Add Scan               | `/scans`                  | `default` / `heavy` | `backend/app/pipeline/adapters/*`                                |
| **Investigation**       | `/targets/{id}/workspace` (Assets)   | `/target-workspaces`      | `investigation` | `backend/app/pipeline/investigation/adapters/*` (nmap_deep, ffuf, dirsearch, testssl) |
| **Operations**          | `/operations/launch`                  | `/operations`             | `investigation` | Reuses the 4 investigation adapters via a synthesized `TaskContext`. |

All three publish live progress to Redis (`scan:`, `investigation:`,
`operation:`). Recon + Investigation stream via SSE; Operations polls.

The **asset graph** is authoritative. Recon writes/updates
`assets` + `asset_observations`. Investigation reuses assets from a completed
recon parent (idempotent workspace). Operations does NOT touch the asset graph
— its findings live in a separate `operation_findings` table so a manual scan
of a random target never pollutes a customer's inventory.

---

## 4. Recipe: add a new recon stage

1. **Implement** `Stage` protocol in a new file
   `backend/app/pipeline/adapters/mytool.py`:
   ```
   class MyToolStage:
       name = "mytool"
       source_tool = "mytool"
       depends_on: list[str] = ["httpx"]  # optional
       inputs: list[str] = []
       outputs: list[str] = []
       weight = 5
       optional = False

       async def execute(self, ctx: StageContext) -> list[AssetRecord]:
           ...
   ```
2. **Register** it in `backend/app/pipeline/profiles.py` under `quick` /
   `standard` / `deep` (whichever profile should run it).
3. **Install the binary** in `infra/Dockerfile.worker` (pin the version,
   `RUN mytool --version` at build time).
4. **Rebuild**: `docker compose up -d --build worker heavy-worker`.
5. Verify: submit a scan, tail the worker, watch for your stage's SSE events.

**Persistence boundary**: adapters return `AssetRecord`s and never write to
the DB directly. The worker calls `services/assets.upsert_assets` for you.
Preserve this — it's the anti-coupling rule.

---

## 5. Recipe: add a new investigation tool

1. **Adapter**: `backend/app/pipeline/investigation/adapters/mytool.py`
   implementing `InvestigationAdapter`:
   ```
   class MyToolAdapter:
       tool = "mytool"

       async def execute(self, ctx: TaskContext) -> InvestigationResult:
           binary = shutil.which("mytool") or raise
           host = ctx.asset_canonical_key
           profile_args = resolve_args("mytool", ctx.params or {}) or _DEFAULT
           cmd = [binary, *profile_args, "-o", tmp, host]
           # asyncio.create_subprocess_exec + sandbox + timeout + parse
           return InvestigationResult(findings=[...], raw_output=...)
   ```
2. **Register** in `pipeline/investigation/registry.py::ADAPTERS`.
3. **Profile bundle** in `backend/app/services/scan_profiles.py::PROFILES`:
   ```
   "mytool": {
       "binary": "mytool",
       "default": "quick",
       "profiles": [
           {"id": "quick", "label": "Quick", "args": [...], "description": ...},
           {"id": "custom", "label": "Custom", "args": [], "description": ...},
       ],
   }
   ```
   The frontend picks this up automatically via `/target-workspaces/scan-profiles`.
4. **Install the binary** in `infra/Dockerfile.investigation_worker`. Rebuild
   with `docker compose up -d --build investigation-worker`.
5. **Result renderer**:
   `frontend/components/workspace/tool-results/MyToolResult.tsx` — read
   `findings.evidence` for structured data. Dispatch on it from
   `frontend/app/targets/[id]/workspace/tasks/[task_id]/page.tsx` and (if it
   should surface in Operations too) `frontend/app/operations/[operation_id]/page.tsx`.

---

## 6. Recipe: expose the tool in Operations

Operations reuse the investigation adapters, but they own their own command
preview. In `backend/app/services/operations_command.py`:

1. Add `"mytool"` to `TOOLS`.
2. Add its fallback args to `_DEFAULT_ARGS`.
3. Add the argv shape to `render_command()` — it must exactly mirror what the
   adapter builds (that's the "preview equals execution" guarantee).
4. Add a per-tool output/file denylist to `_DENYLIST` so custom args can't
   redirect output.

No frontend change needed if the tool already has a result renderer.

---

## 7. Recipe: write a migration

```
docker compose exec backend alembic revision --autogenerate -m "add mytable"
```

Rules of thumb:
- Autogenerate reads
  `backend/app/models/__init__.py`. If your model isn't imported there, the
  diff will be empty.
- Enums: use the single-instance pattern from `0001_initial.py`. Prefer
  `VARCHAR(N)` for new status columns (avoid the ENUM gotcha).
- Forward-only removals: see `0020_drop_vuln_feature.py` — drop rows before
  columns, drop indices before enums, `DROP TYPE IF EXISTS` at the end.
- If the DB gets stamped at a rev whose file was deleted, boot dies with
  `Can't locate revision identified by 'NNNN'`. Fix:
  ```
  docker compose exec postgres psql -U recon -d recon \
    -c "UPDATE alembic_version SET version_num='<last-good>';"
  ```
  Then drop any leftover columns/tables the deleted migration added.

---

## 8. Recipe: add an API route

1. Router in `backend/app/api/<area>.py`. Include admin gate where needed:
   `dependencies=[Depends(require_admin())]`.
2. Schemas in `backend/app/schemas/<area>.py` (Pydantic v2, `ConfigDict(from_attributes=True)`
   when mirroring ORM).
3. Register in `backend/app/main.py` — `app.include_router(<area>.router)`.
4. Add a client helper + type in `frontend/lib/api.ts`. Route the call
   through the shared `api<T>()` wrapper (do NOT bypass with raw `fetch` — it
   handles CSRF + 401 refresh + Pydantic error formatting).
5. Verify with `curl http://localhost:8000/openapi.json | jq '.paths."<path>"'`.

---

## 9. Debugging

### Backend won't boot
`docker compose logs backend --tail=80`. Usually one of:
- Alembic can't find a revision → see §7 recipe.
- Import error → run `docker compose exec backend python -c "import app.main"`
  to see the traceback.

### Task stuck in `queued`
Its worker isn't running or wasn't restarted after Python edits. Investigation
+ operations tasks need `investigation-worker`; recon needs `worker` or
`heavy-worker`. `docker compose ps` to confirm, `docker compose restart <name>`
to reload code.

### OpenRouter call fails
Check `/admin/settings/openrouter` — the card shows `api_key_set: true`
and a hint if a key is saved. Otherwise the env fallback is used. Use the
**Test Connection** button to verify.

### Frontend returns 500 on every page
Next.js `.next` cache is corrupted (typical after a bind-mounted file
disappears from host). Fix: `docker compose restart frontend`.

### CORS / connection refused
The backend crashed silently. See "Backend won't boot" above.

---

## 10. Where to look for what (cheat sheet)

| Question                                                    | File                                                               |
|-------------------------------------------------------------|--------------------------------------------------------------------|
| How does the DAG order stages?                              | `backend/app/pipeline/coordinator.py`                              |
| Which stages run for a profile?                             | `backend/app/pipeline/profiles.py`                                 |
| What does upsert_assets do?                                 | `backend/app/services/assets.py`                                   |
| How is progress published?                                  | `backend/app/workers/runner.py` + `investigation_runner.py` (Redis `publish`) |
| How does SSE work end to end?                               | `api/scans.py::stream_scan` + `api/target_workspaces.py::stream_workspace` |
| Where's the admin auth gate?                                | `backend/app/api/deps.py::require_admin`                           |
| Where's the CSRF middleware?                                | `backend/app/api/middleware/csrf.py`                               |
| Which fields does the OpenRouter card mask?                  | `backend/app/api/admin/settings.py::_openrouter_out`               |
| How are operations validated (argument-injection)?          | `backend/app/services/operations_command.py::validate_target`      |
| Where do tool-result components live?                       | `frontend/components/workspace/tool-results/*.tsx`                 |
| How does the frontend know which nav to show?               | `frontend/components/AppShell.tsx::NAV_MAIN` + `NAV_ADMIN`         |

---

## 11. Historical context

- `docs/superpowers/` — dated plans + specs from earlier milestones
  (M3 risk prioritizer, M5 BBOT / Censys / Shodan, several M-Vuln drops). Kept
  as a design log — read for rationale, not current state.
- `memory/project_state.md` — running project log; the Vulnerability Scans
  removal is documented there.
- Removed pieces: the entire vuln analysis module (M-Vuln-1..8), the old
  scan-authorization gate, and the associated frontend routes
  (`/vuln-scans`, `/targets/[id]/risk`). See migration `0020_drop_vuln_feature.py`
  for the exact schema removals.
