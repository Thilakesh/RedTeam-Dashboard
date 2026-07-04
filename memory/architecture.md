# Architecture Snapshot

## Five-Plane Layered Monolith

| Plane | Technology | Path |
|---|---|---|
| Presentation | Next.js 14 App Router, TanStack Query, Tailwind, Radix UI | `frontend/` |
| API | FastAPI, Pydantic v2, SQLAlchemy 2.0 async | `backend/app/api/` |
| Orchestration | DAG executor (recon), vuln coordinator, investigation runner | `backend/app/pipeline/` |
| Execution | Arq workers (4 queues) | `backend/app/workers/` |
| Data | PostgreSQL 16, Redis 7, MinIO | `infra/docker-compose.yml` |

Do NOT split into microservices — explicitly deferred.

## Worker Queue Map

| Queue | Container | Dockerfile | Handles |
|---|---|---|---|
| `default` | worker | Dockerfile.worker | quick/standard recon scans |
| `heavy` | heavy-worker | Dockerfile.heavy-worker | deep recon (bbot, naabu, nmap, gowitness) |
| `vuln` | vuln-worker | Dockerfile.vuln_worker | vulnerability analysis scans |
| `investigation` | investigation-worker | Dockerfile.investigation_worker | target workspace tasks (nmap_deep/ffuf/dirsearch/testssl) |

## DB Model Groups

- **Org/Auth**: Organization, Project, Target, User, UserRole, UserFeature
- **Session/Audit**: RefreshSession, BlacklistedJti, AuditLog
- **Recon assets**: Asset, AssetObservation, Service, Technology, HvtSignal, Endpoint, TlsObservation
- **Recon scan**: Scan (kind=recon), ScanStage, ScanStatus, Finding, AiUsage
- **Vuln analysis**: Scan (kind=vuln_analysis), Vulnerability, VulnEvidence, VulnRunMatch, CveIntel
- **Investigation**: TargetWorkspace, InvestigationTask, InvestigationFinding

`asset_id` on InvestigationTask/InvestigationFinding is NOT NULL (blocks logical-otter; migration 0019 pending).

## Key Module Boundaries

- **Pipeline adapters** (`pipeline/adapters/*`): invoke CLI tool, parse output, return `AssetRecord[]`. NEVER touch DB.
- **Vuln adapters** (`pipeline/vuln/adapters/*`): consume frozen `VulnStageContext`, return `VulnRecord[]`. NEVER touch assets/services/technologies.
- **Investigation adapters** (`pipeline/investigation/adapters/*`): return `FindingRecord[]`, `ServiceUpdateRecord[]`, `EndpointRecord[]`, `TlsObservationRecord[]`. NEVER write directly.
- **services/assets.py**: upsert Asset + AssetObservation (flush only, caller commits).
- **services/vulns.py**: upsert Vulnerability + VulnEvidence + VulnRunMatch (flush only).
- Workers call services; adapters never call services.

## Tenant Isolation

`Scan.org_id` denormalized from Target→Project→Organization. Every list/detail query filters by `org_id`. `CurrentUser.scan_filter()` extends this: admin sees all org scans, analyst sees only own (`Scan.created_by == user.id`).

## Authentication

- **Access token**: RS256 JWT, 10-min TTL, HttpOnly cookie `rt_access` (path=/).
- **Refresh token**: opaque rotating token, 14-day TTL, HttpOnly `rt_refresh` (path=/auth, SameSite=Strict). Rotation on each use; reuse detection triggers chain revocation.
- **CSRF**: `rt_csrf` cookie (JS-readable, SameSite=Strict); echoed as `X-CSRF-Token` header on mutating requests.
- **Blacklist**: Redis `blacklist:jti:{jti}` + `blacklist:sid:{sid}` (fast path); `BlacklistedJti` table (authoritative fallback).
- **RBAC**: admin (sees all scans, manages users/features) | analyst (sees own scans only).
- **Onboarding**: invite-only — no public signup. Admin bootstrapped via `ADMIN_EMAIL`/`ADMIN_PASSWORD` env on first startup.

## Real-time

Workers publish to Redis pub/sub `scan:{scan_id}` (recon/vuln) or `investigation:{task_id}`. API SSE endpoints at `/scans/{id}/stream`, `/vuln-scans/{id}/stream`, `/target-workspaces/{ws}/stream`. Frontend EventSource requires `withCredentials: true` (cross-origin).

## Pending Plan

`you-are-a-principal-logical-otter.md` — manual standalone operations (no recon asset linkage). Blocked until: (1) migration 0019 makes `asset_id` nullable, (2) frontend route restructure creates `(workspace)` group or adapts to current `/workspace/` tab structure.
