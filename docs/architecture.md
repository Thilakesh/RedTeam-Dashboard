# Architecture

Multi-tenant Attack Surface Management (ASM) platform. This document describes
the layered runtime, module boundaries, and data flow of the current codebase
(post migration `0020` — Vulnerability Analysis feature removed).

For usage recipes, see [`APPLICATION_GUIDE.md`](../APPLICATION_GUIDE.md).
For diagrams, see [`docs/diagrams.md`](diagrams.md).

---

## 1. Layered monolith (5 planes)

```
Presentation   Next.js App Router                            frontend/
     │
     │  JSON + CSRF-guarded fetch                            frontend/lib/api.ts
     ▼
API            FastAPI routers (auth, tenant scope)          backend/app/api/
     │
     ▼
Orchestration  Recon DAG + Investigation runner +            backend/app/pipeline/
               Operations runner                             backend/app/workers/
     │
     ▼  Arq / Redis
Execution      Adapters wrap CLI tools & HTTP probes         backend/app/pipeline/**/adapters/
     │
     ▼
Data           Postgres asset graph + observations           backend/app/models/
               MinIO for screenshots
```

The 5 planes are **module boundaries within a single repo**, not separate
services. Do not split into microservices — that decision is explicitly
deferred.

---

## 2. Runtime components

| Container              | Image                                      | Queue(s)         | Purpose                                                                 |
|------------------------|--------------------------------------------|------------------|-------------------------------------------------------------------------|
| `postgres`             | `postgres:16-alpine`                        | —                | Primary data store (asset graph + observations + auth + settings).      |
| `redis`                | `redis:7-alpine`                            | —                | Arq broker + pub/sub for live progress events + CSRF blacklist.         |
| `minio`                | `minio/minio`                               | —                | Object store for screenshots produced by `gowitness`.                   |
| `backend`              | `infra/Dockerfile.backend`                  | —                | FastAPI + Uvicorn on `:8000`. Runs `alembic upgrade head` at boot.      |
| `frontend`             | `node:20-alpine`                            | —                | Next.js 14 dev server on `:3000`.                                       |
| `worker`               | `infra/Dockerfile.worker`                   | `default`        | Recon quick/standard profiles.                                          |
| `heavy-worker`         | `infra/Dockerfile.worker`                   | `heavy`          | Recon deep profile + BBOT enrichment.                                   |
| `investigation-worker` | `infra/Dockerfile.investigation_worker`     | `investigation`  | Per-asset Investigation tasks **and** standalone Operations.            |

Removed from earlier revisions: `vuln-worker` (queue `vuln`) — deleted in the
Vulnerability Scans removal.

---

## 3. Key modules

| Concern              | File                                                                 |
|----------------------|----------------------------------------------------------------------|
| API routers          | `backend/app/api/*.py` + `backend/app/api/admin/*.py`                |
| Auth deps + RBAC     | `backend/app/api/deps.py`                                            |
| Tenant scoping       | Every service uses `where(org_id == user.org_id)` + `user.scan_filter(created_by)` |
| Recon DAG            | `backend/app/pipeline/coordinator.py` + `backend/app/pipeline/adapters/*` |
| Investigation        | `backend/app/pipeline/investigation/adapters/*` + `backend/app/workers/investigation_runner.py` |
| Operations           | `backend/app/services/operations_command.py` + `backend/app/services/operations.py` + `backend/app/workers/investigation_runner.py::run_operation` |
| AI risk ranking      | `backend/app/agents/risk_prioritizer.py` + `backend/app/agents/bounded_completion.py` |
| Queue enqueues       | `backend/app/services/queue.py`                                      |
| Scan profiles        | `backend/app/services/scan_profiles.py`                              |
| System settings (DB) | `backend/app/services/system_settings.py`                            |
| Audit log            | `backend/app/services/audit.py`                                      |
| API client           | `frontend/lib/api.ts`                                                |
| Nav + breadcrumbs    | `frontend/components/AppShell.tsx`                                   |

---

## 4. Locked architectural decisions

1. **SaaS-first, multi-tenant.** Every scan-relevant row carries `org_id`;
   every query filters on it.
2. **Layered monolith, not microservices.** All 5 planes live in one repo,
   one image (per role). No k8s.
3. **Docker Compose is the deployment target.** Each container is one process.
4. **Arq + Redis.** Three queues: `default` (recon light), `heavy` (recon
   deep + bbot), `investigation` (per-asset tasks + standalone operations).
5. **Postgres asset graph.** `assets` is deduped by
   `(target_id, type, canonical_key)`; per-run history lives in
   `asset_observations`. Do not add a "results" table that duplicates data
   per-scan.
6. **Structured findings**, never raw terminal output as the user surface.
   Adapters return dataclasses that services normalize into DB rows; per-tool
   result components render structured views; the raw output lives in a
   collapsible panel only.
7. **Argv, never `shell=True`.** All CLI wrapping goes through
   `asyncio.create_subprocess_exec` with an argv list; user-supplied strings
   never flow into a shell. Manual Operation targets pass strict domain /
   IPv4 validation before reaching argv (argument-injection guard).
8. **Preview equals execution.** For Operations, the server-side
   `render_command` mirrors the exact argv the adapter builds — the preview
   an analyst sees is what runs.
9. **Investigation adapters are shared execution code.** Operations reuse
   them by synthesizing a `TaskContext`; adapters never know which entry
   point invoked them.
10. **No live feed calls from stages.** Stages read the DB; background jobs
    (if any) write feeds. Historically enforced by CI in the removed vuln
    module.

---

## 5. Auth model

- **RS256 JWT** with rotating refresh sessions. Access token in `rt_access`
  HTTP-only cookie; refresh token in `rt_refresh`. Bootstrap admin created
  from `ADMIN_EMAIL` / `ADMIN_PASSWORD` env on first boot.
- **CSRF**: double-submit cookie `rt_csrf` + `X-CSRF-Token` header. The
  frontend `api()` client attaches this automatically for POST/PATCH/DELETE.
- **Roles**: `admin` sees the whole org; `analyst` sees only their own scans
  (enforced via `CurrentUser.scan_filter()`).
- **Feature flags** (`backend/app/core/features.py`) — per-user opt-outs of
  specific tools/features. Missing row = enabled.

---

## 6. Data model (current tables)

Kept after migration `0020`:

| Group            | Tables                                                                              |
|------------------|-------------------------------------------------------------------------------------|
| Identity         | `organizations`, `projects`, `users`, `refresh_sessions`, `user_features`, `blacklisted_jti`, `audit_logs` |
| Targets          | `targets`, `assets`, `asset_observations`                                           |
| Recon scans      | `scans`, `scan_stages`, `services`, `technologies`, `findings`, `ai_usage`          |
| Investigation    | `target_workspaces`, `investigation_tasks`, `investigation_findings`                |
| Shared enrich    | `endpoints`, `endpoint_observations`, `tls_observations`                            |
| Operations       | `operations`, `operation_findings`                                                   |
| Settings         | `system_settings`                                                                    |

Dropped in `0020`: `vulnerabilities`, `vuln_evidence`, `vuln_run_matches`,
`cve_intel`, `hvt_signals` + Scan columns `kind` / `parent_scan_id` /
`intrusive` + 4 enums (`scan_kind`, `vuln_severity`, `vuln_status`,
`hvt_signal_type`).

### Asset graph invariants

- `Asset(target_id, type, canonical_key)` is unique.
- `canonical_key` is the dedup identity — lowercased FQDN for `subdomain`,
  dotted-quad for `ipv4`, `host:port/proto` for a `service`. Changing a
  canonical_key requires a migration.
- `AssetObservation` is append-only per-scan; a repeat sighting updates
  `Asset.last_seen` and adds a new observation.

---

## 7. Live progress channels

| Producer                                        | Redis channel               | Consumer                                                                  |
|-------------------------------------------------|-----------------------------|---------------------------------------------------------------------------|
| Recon `runner.py`                               | `scan:{scan_id}`            | API `GET /scans/{id}/stream` (SSE) → UI updates tabs.                     |
| Investigation `investigation_runner.py`         | `investigation:{task_id}`   | Workspace SSE stream (filtered by `workspace:{ws}:tasks` Redis SET).       |
| Operations `investigation_runner.py::run_operation` | `operation:{operation_id}` | Currently polled by the UI (4s `refetchInterval`); SSE is a future task.   |

Terminal events always fire (`scan.completed` / `scan.failed` / `scan.stopped`
/ `task.cancelled` / `operation.cancelled` etc.) so the SSE generator closes
cleanly.

---

## 8. Extension points (see `docs/developer-handover.md` for recipes)

- **New recon stage** — implement the `Stage` protocol in
  `backend/app/pipeline/stage.py`, add it to a profile in
  `backend/app/pipeline/profiles.py`, install any binary in
  `infra/Dockerfile.worker`, rebuild `worker`.
- **New investigation tool** — implement `InvestigationAdapter` in
  `pipeline/investigation/adapters/`, register it in `registry.py`, add a
  bundle to `services/scan_profiles.py::PROFILES`, install the binary in
  `Dockerfile.investigation_worker`, add a result renderer in
  `frontend/components/workspace/tool-results/`.
- **New Operations tool** — add it to `TOOLS`, `_DEFAULT_ARGS`, and
  `render_command()` in `services/operations_command.py`.
- **New table** — write the model, add it to `backend/app/models/__init__.py`
  (autogenerate depends on this), then
  `alembic revision --autogenerate -m "..."`.

---

## 9. What is **not** in the codebase

The Vulnerability Scans feature (M-Vuln-1 … M-Vuln-8) was removed:
- CVE-tagged Vulnerability rows, nuclei / correlator / AI-triage stages,
  EPSS/KEV feeds, HVT signal scoring, `/vuln-scans` UI, `/targets/{id}/risk`
  rollup — all deleted.
- The old scan-authorization gate (verified-target-only) — replaced by
  role-based access + per-user feature flags.

See `memory/project_state.md` for the removal inventory and rationale.
