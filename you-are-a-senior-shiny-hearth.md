# Implementation Status (as of 2026-05-08)

> Snapshot of where the project currently stands relative to the architectural plan below. Updated at handoff to keep planning artifacts aligned with reality.

## ✅ Completed Milestones

### M0 — Skeleton
- FastAPI + Postgres + Arq + Next.js scaffolds
- Auth (email + password + JWT), Org/Project/Target CRUD with multi-tenant scoping
- Single-stage end-to-end (subfinder → asset graph → UI)

### M1 — Pipeline Framework
- `Stage` protocol, DAG executor with parallel execution levels (L0–L7)
- Adapters: subfinder, assetfinder, amass, dnsx, httpx
- Asset model + AssetObservation upserts via `services/assets.upsert_assets`
- SSE live progress via Redis pub/sub on channel `scan:{scan_id}`
- Per-stage `on_start` / `on_done` / `on_fail` / `on_skip` lifecycle hooks

### M1.5 — Subdomain-Centric UI + Passive Enrichment
- New adapters: wafw00f, asnmap, geoip (IP2Location LITE bundled, no API cost)
- httpx extended: `-cdn`, `-cname`, `-server`, `-follow-redirects`, `-ip`, `-location`
- Subdomain-centric UI: virtualized TanStack Table v8, every mockup column populated
- AppShell with persistent sidebar + breadcrumbs + light/dark theme (next-themes)
- Read endpoints: `/scans/{id}/subdomains`, `/overview`, `/ips`, `/cdn-waf`, `/technologies`
- Overview / IP Summary / CDN-WAF / Technologies tabs

### M2 — Active Scanning (backend complete, frontend partial)
- Adapters: naabu (port discovery), nmap (service detection), gowitness (screenshots)
- `Target.authorization_verified_at` gate skips active stages when NULL (does not fail)
- MinIO storage for screenshots (`recon` bucket, public-read S3 policy)
- Public URLs use `MINIO_PUBLIC_URL` env (host-accessible) vs `MINIO_URL` (internal SDK)
- Real deep scan of audit360.in verified (16 subdomains, 20 services, 4 screenshots, 12 IPs)

### M3 — AI Risk Prioritization
- `RiskPrioritizerStage` runs as final stage of deep DAG (`optional=True`)
- OpenRouter `openai/gpt-oss-20b:free` with JSON mode, hallucination guard, full coverage
- `findings` table + `ai_usage` ledger (prompt + completion token counts)
- `bounded_completion` wrapper with null-content guard (raises `BoundedCompletionError`)
- Frontend RisksTab + Top Risks card on Overview tab for completed deep scans

### M4 — Workflow-Oriented Dashboard Redesign
- New scan statuses: `queued` (added but not enqueued) and `stopped` (manually stopped)
- Lifecycle endpoints: `POST /scans/{id}/start|stop`, `PATCH /scans/{id}`, `DELETE /scans/{id}`
- Worker guards completion/failure paths against overriding `stopped`
- Dashboard split: `/dashboard` (Add Scan) and `/dashboard/recon-jobs` (jobs table)
- Shared `/dashboard/layout.tsx` provides AppShell + stats bar to both sub-pages
- Recon Jobs table: per-row lifecycle actions, profile dropdown editable for queued scans

### Bug Fixes (2026-05-07 session)
- **CardDescription** missing from `frontend/components/ui/card.tsx` — caused full dashboard crash, now exported
- **Authorization gate visibility** — `target_authz_verified: bool` threaded through `ScanOut` on every endpoint; orange ⚠️ icon in Recon Jobs table for unverified deep scans
- **risk_prioritizer TypeError** — `json.loads(None)` was uncaught when OpenRouter returned `content: null`; now explicit null guard with `finish_reason` in error message
- TypeScript: invalid Badge variant `"secondary"` → `"outline"`; `STATUS_VARIANT` extended with `queued` / `stopped`

---

## ⏳ Pending Work

### M2 Frontend (highest priority remaining)
- [ ] **PortsTab** — `frontend/components/tabs/PortsTab.tsx` already imported in `app/scans/[id]/page.tsx:15` but file does not yet exist
  - Fetch `GET /scans/{id}/ports` (returns `PortsPage` → `PortRow[]`)
  - Columns: host, port, proto, service_name, product, version
  - Empty state if `scan.profile !== "deep"` or no ports found
- [ ] **Screenshot column** in `frontend/components/SubdomainsTable.tsx`
  - Visible only when `scan.profile === "deep"`
  - Thumbnail `<img src={screenshot_url} className="h-8 w-14 object-cover rounded cursor-pointer" />`
  - Click opens modal with full-size image
  - Fallback: dash when no screenshot URL

### M2 Backend Hardening (pre-production only)
- [ ] Worker subprocess sandbox (`backend/app/workers/sandbox.py` — file does not exist yet)
  - Resource limits for naabu / nmap / gowitness
  - Per-scan working directory with disk quota
  - Egress rate-limit through outbound proxy
- [ ] `AuthzVerifierStage` automated stage (manual `POST /targets/{id}/verify` already works)
- [ ] MinIO signed URL expiry (currently public unsigned)

### One-Time Ops
- [ ] SQL fix for screenshot URLs stored before MinIO public-URL fix:
  ```sql
  UPDATE asset_observations
  SET payload = jsonb_set(
    payload,
    '{screenshot_url}',
    to_jsonb(replace(payload->>'screenshot_url', 'http://minio:9000', 'http://localhost:9000'))
  )
  WHERE payload ? 'screenshot_url'
    AND payload->>'screenshot_url' LIKE 'http://minio:9000%';
  ```

### M5 — Enrichment + Search (not started)
- Censys + Shodan integrations (rate-limited, cached)
- BBOT integration (deep profile only, isolated worker pool)
- OpenSearch index for full-text asset search

### M6 — Scheduling + Alerts (not started)
- Recurring scans (cron per target)
- Alert delivery (email, webhook, Slack)
- Per-tenant rate limits + billing hooks

### Deferred Indefinitely
- Asset-graph diff + history features (data layer ready; UI not prioritized)
- Per-scan natural-language summaries / weekly diff narration
- Microservices split, Kubernetes
- Real-time collaboration
- Vulnerability scanning (nuclei)

---

## ▶ Next Action

**Start M2 frontend — PortsTab implementation first** (it is already wired into the tab strip at `app/scans/[id]/page.tsx:15`, so the missing file is currently the only thing breaking that import path's promise). Then add the Screenshot column to `SubdomainsTable.tsx` so deep scans surface their full output. After both, M2 can be marked frontend-complete and the project moves to either M2 backend hardening or jumps to M5.

---

# Workflow-Oriented Dashboard Redesign — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the generic dashboard layout with a workflow-oriented "Basic Recon" module containing an "Add Scan" view and a "Recon Jobs" table, add queued/stopped scan lifecycle, and move Prioritized Risks into the scan detail.

**Architecture:**
- New `queued` and `stopped` scan statuses (Postgres ENUM migration + new API endpoints) enable deferred scan creation and manual stop.
- `POST /scans` gains an `autostart` flag; new `/start`, `/stop`, `PATCH`, and `DELETE` endpoints cover the full lifecycle.
- Frontend splits into `dashboard/page.tsx` (Add Scan) and `dashboard/recon-jobs/page.tsx` (jobs table), wrapped by a shared `dashboard/layout.tsx` stats bar.

**Tech Stack:** FastAPI + SQLAlchemy 2 async + Alembic, Next.js 14 App Router, TanStack Query v5, shadcn/ui, lucide-react.

---

## Context (Redesign)

The current dashboard mixes scan creation, a Prioritized Risks summary card, and a running/completed tab list in one page. The goal is a workflow-oriented model: a dedicated "Add Scan" view where jobs can be queued or started immediately, and a "Recon Jobs" table as the primary scan management surface. Prioritized Risks moves to the scan detail view where results live.

---

## File Map

**New files:**
- `backend/migrations/versions/XXXX_add_queued_stopped_scan_status.py`
- `frontend/app/dashboard/layout.tsx`
- `frontend/app/dashboard/recon-jobs/page.tsx`

**Modified files:**
- `backend/app/models/scan.py` — add `queued`, `stopped` to `ScanStatus`
- `backend/app/schemas/scan.py` — add `autostart` to `ScanCreateRequest`, add `ScanUpdateRequest`
- `backend/app/api/scans.py` — conditionally enqueue on POST; add start/stop/patch/delete endpoints
- `backend/app/workers/runner.py` — respect `stopped` status at scan completion
- `frontend/lib/api.ts` — add `queued`/`stopped` to type union; add API helper fns
- `frontend/components/AppShell.tsx` — rename nav item, restructure children
- `frontend/app/dashboard/page.tsx` — Add Scan form with [Add] + [Start Scan] buttons; remove Prioritized Risks card
- `frontend/components/tabs/OverviewTab.tsx` — add Top Risks card for deep completed scans

---

## Task 1: Backend — Add `queued` and `stopped` enum values + migration

**Files:**
- Modify: `backend/app/models/scan.py`
- Create: `backend/migrations/versions/XXXX_add_queued_stopped_scan_status.py`

- [ ] **Step 1: Add new enum values to ScanStatus**

Edit `backend/app/models/scan.py`, change:
```python
class ScanStatus(str, enum.Enum):
    created = "created"
    running = "running"
    completed = "completed"
    failed = "failed"
```
to:
```python
class ScanStatus(str, enum.Enum):
    queued = "queued"      # created but not yet enqueued (Add button)
    created = "created"    # enqueued, waiting for worker
    running = "running"
    completed = "completed"
    failed = "failed"
    stopped = "stopped"    # manually stopped by user
```

- [ ] **Step 2: Generate and write migration**

Run inside the container to get the revision ID:
```bash
docker compose exec backend alembic revision --autogenerate -m "add_queued_stopped_scan_status"
```
Then open the generated file and **replace** its `upgrade`/`downgrade` with:
```python
from alembic import op

def upgrade() -> None:
    # PostgreSQL 12+ allows ALTER TYPE ADD VALUE inside a transaction
    op.execute("ALTER TYPE scan_status ADD VALUE IF NOT EXISTS 'queued' BEFORE 'created'")
    op.execute("ALTER TYPE scan_status ADD VALUE IF NOT EXISTS 'stopped' AFTER 'failed'")

def downgrade() -> None:
    # PostgreSQL does not support removing enum values — manual intervention needed
    pass
```

- [ ] **Step 3: Apply migration and verify**

```bash
docker compose exec backend alembic upgrade head
```
Expected: no errors. Verify:
```bash
docker compose exec backend python -c "
from app.models.scan import ScanStatus
print([s.value for s in ScanStatus])
"
```
Expected output: `['queued', 'created', 'running', 'completed', 'failed', 'stopped']`

- [ ] **Step 4: Commit**

```bash
git add backend/app/models/scan.py backend/migrations/
git commit -m "feat: add queued and stopped scan statuses"
```

---

## Task 2: Backend — Extend scan API with lifecycle endpoints

**Files:**
- Modify: `backend/app/schemas/scan.py`
- Modify: `backend/app/api/scans.py`

- [ ] **Step 1: Update `ScanCreateRequest` and add `ScanUpdateRequest`**

In `backend/app/schemas/scan.py`, change `ScanCreateRequest` and add update schema:
```python
class ScanCreateRequest(BaseModel):
    domain: str = Field(min_length=3, max_length=255)
    profile: str = Field(default="quick", pattern="^(quick|standard|deep)$")
    autostart: bool = True   # False → create as queued, no immediate enqueue


class ScanUpdateRequest(BaseModel):
    profile: str = Field(pattern="^(quick|standard|deep)$")
```

- [ ] **Step 2: Modify `POST /scans` to conditionally enqueue**

In `backend/app/api/scans.py`, replace the `create_scan` function body:
```python
@router.post("", response_model=ScanOut, status_code=status.HTTP_201_CREATED)
async def create_scan(
    req: ScanCreateRequest,
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> ScanOut:
    project_id = await _default_project_id(db, user.org_id)
    target = await db.scalar(
        select(Target).where(Target.project_id == project_id, Target.domain == req.domain)
    )
    if target is None:
        target = Target(project_id=project_id, domain=req.domain)
        db.add(target)
        await db.flush()

    initial_status = ScanStatus.created if req.autostart else ScanStatus.queued
    scan = Scan(target_id=target.id, org_id=user.org_id, profile=req.profile, status=initial_status)
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    if req.autostart:
        await enqueue_scan(str(scan.id))

    return _to_scan_out(scan, target.domain)
```
Add `from app.models.scan import ScanStatus` import if not already present.

- [ ] **Step 3: Add `_get_scan_and_domain` helper (add after `_to_scan_out`)**

```python
async def _get_scan_and_domain(
    db: AsyncSession, scan_id: UUID, org_id: UUID
) -> tuple[Scan, str]:
    row = (
        await db.execute(
            select(Scan, Target.domain)
            .join(Target, Target.id == Scan.target_id)
            .where(Scan.id == scan_id, Scan.org_id == org_id)
        )
    ).first()
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Scan not found")
    return row.Scan, row.domain
```

- [ ] **Step 4: Add `POST /scans/{scan_id}/start`**

Append to `backend/app/api/scans.py`:
```python
@router.post("/{scan_id}/start", response_model=ScanOut)
async def start_scan(
    scan_id: UUID,
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> ScanOut:
    scan, domain = await _get_scan_and_domain(db, scan_id, user.org_id)
    if scan.status != ScanStatus.queued:
        raise HTTPException(status.HTTP_409_CONFLICT, "Scan is not in queued state")
    scan.status = ScanStatus.created
    await db.commit()
    await enqueue_scan(str(scan.id))
    return _to_scan_out(scan, domain)
```

- [ ] **Step 5: Add `POST /scans/{scan_id}/stop`**

```python
@router.post("/{scan_id}/stop", response_model=ScanOut)
async def stop_scan(
    scan_id: UUID,
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> ScanOut:
    scan, domain = await _get_scan_and_domain(db, scan_id, user.org_id)
    if scan.status not in (ScanStatus.created, ScanStatus.running):
        raise HTTPException(status.HTTP_409_CONFLICT, "Scan is not running")
    from datetime import datetime, timezone
    scan.status = ScanStatus.stopped
    scan.finished_at = datetime.now(timezone.utc)
    await db.commit()
    return _to_scan_out(scan, domain)
```

- [ ] **Step 6: Add `PATCH /scans/{scan_id}` (update profile for queued scans)**

```python
@router.patch("/{scan_id}", response_model=ScanOut)
async def update_scan(
    scan_id: UUID,
    req: ScanUpdateRequest,
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> ScanOut:
    scan, domain = await _get_scan_and_domain(db, scan_id, user.org_id)
    if scan.status != ScanStatus.queued:
        raise HTTPException(status.HTTP_409_CONFLICT, "Only queued scans can be edited")
    scan.profile = req.profile
    await db.commit()
    return _to_scan_out(scan, domain)
```

- [ ] **Step 7: Add `DELETE /scans/{scan_id}`**

```python
@router.delete("/{scan_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_scan(
    scan_id: UUID,
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> None:
    scan, _ = await _get_scan_and_domain(db, scan_id, user.org_id)
    if scan.status != ScanStatus.queued:
        raise HTTPException(status.HTTP_409_CONFLICT, "Only queued scans can be deleted")
    await db.delete(scan)
    await db.commit()
```

- [ ] **Step 8: Update `ScanUpdateRequest` import in scans.py**

Make sure the import line reads:
```python
from app.schemas.scan import AssetOut, ScanCreateRequest, ScanDetailOut, ScanOut, ScanUpdateRequest
```

- [ ] **Step 9: Manual endpoint smoke test**

```bash
# Create a queued scan (autostart=false)
curl -X POST http://localhost:8000/scans \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"domain":"example.com","profile":"quick","autostart":false}'
# Expect: {"status":"queued", ...}

# Start it
curl -X POST http://localhost:8000/scans/$SCAN_ID/start -H "Authorization: Bearer $TOKEN"
# Expect: {"status":"created", ...}

# Create and immediately start (default)
curl -X POST http://localhost:8000/scans \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"domain":"example.com","profile":"quick"}'
# Expect: {"status":"created", ...}
```

- [ ] **Step 10: Commit**

```bash
git add backend/app/schemas/scan.py backend/app/api/scans.py
git commit -m "feat: add scan lifecycle endpoints (start/stop/patch/delete) and autostart flag"
```

---

## Task 3: Backend — Worker respects `stopped` status

**Files:**
- Modify: `backend/app/workers/runner.py`

The stop endpoint marks the DB as `stopped`. The worker must not override this with `completed` or `failed` after the DAG finishes.

- [ ] **Step 1: Guard the completion path**

In `runner.py`, find and replace the block that marks `completed` (currently lines ~142–148):
```python
        # After execute_dag: respect a stop that happened mid-run
        async with SessionLocal() as db:
            final = await db.get(Scan, scan_id)
            if final is not None and final.status != ScanStatus.stopped:
                final.status = ScanStatus.completed
                final.finished_at = datetime.now(timezone.utc)
                final.progress_pct = 100
                await db.commit()
        if final is None or final.status != ScanStatus.stopped:
            await _publish(redis, scan_id, "scan.completed")
        else:
            await _publish(redis, scan_id, "scan.stopped")
```

- [ ] **Step 2: Guard the failure path**

Replace the `except Exception` block (currently lines ~149–158) with:
```python
    except Exception as exc:
        async with SessionLocal() as db:
            scan = await db.get(Scan, scan_id)
            if scan is not None and scan.status != ScanStatus.stopped:
                scan.status = ScanStatus.failed
                scan.finished_at = datetime.now(timezone.utc)
                scan.error = str(exc)[:1900]
                await db.commit()
        if scan is None or scan.status != ScanStatus.stopped:
            await _publish(redis, scan_id, "scan.failed", error=str(exc)[:500])
        raise
```

- [ ] **Step 3: Rebuild worker and run a quick scan to verify no regressions**

```bash
docker compose up --build -d worker
docker compose logs -f worker --tail=30
```

- [ ] **Step 4: Commit**

```bash
git add backend/app/workers/runner.py
git commit -m "fix: worker respects stopped status at scan completion"
```

---

## Task 4: Frontend — API types + client helper functions

**Files:**
- Modify: `frontend/lib/api.ts`

- [ ] **Step 1: Extend Scan status union**

Find the `Scan` type and change `status`:
```typescript
export type Scan = {
  id: string;
  domain: string;
  profile: string;
  status: "queued" | "created" | "running" | "completed" | "failed" | "stopped";
  progress_pct: number;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
  error: string | null;
};
```

- [ ] **Step 2: Add scan lifecycle API functions (append to end of file)**

```typescript
export async function startScan(scanId: string): Promise<Scan> {
  return api<Scan>(`/scans/${scanId}/start`, { method: "POST" });
}

export async function stopScan(scanId: string): Promise<Scan> {
  return api<Scan>(`/scans/${scanId}/stop`, { method: "POST" });
}

export async function patchScan(scanId: string, profile: string): Promise<Scan> {
  return api<Scan>(`/scans/${scanId}`, {
    method: "PATCH",
    body: JSON.stringify({ profile }),
  });
}

export async function deleteScan(scanId: string): Promise<void> {
  await api<void>(`/scans/${scanId}`, { method: "DELETE" });
}
```

- [ ] **Step 3: Verify TypeScript compiles**

```bash
docker compose exec frontend npx tsc --noEmit
```
Expected: zero errors.

- [ ] **Step 4: Commit**

```bash
git add frontend/lib/api.ts
git commit -m "feat: extend Scan type with queued/stopped statuses and add lifecycle API helpers"
```

---

## Task 5: Frontend — AppShell navigation restructure

**Files:**
- Modify: `frontend/components/AppShell.tsx`

- [ ] **Step 1: Update NAV array**

Replace the existing `NAV` array (currently lines 38–53):
```typescript
const NAV: NavItem[] = [
  {
    href: "/dashboard",
    label: "Basic Recon",
    icon: ScanSearch,
    children: [
      { href: "/dashboard", label: "Add Scan" },
      { href: "/dashboard/recon-jobs", label: "Recon Jobs" },
    ],
  },
  { href: "/targets", label: "Targets", icon: Target },
  { href: "/reports", label: "Reports", icon: FileBarChart2 },
  { href: "/settings", label: "Settings", icon: Settings },
];
```
Remove `LayoutDashboard` from the lucide-react import (no longer used).

- [ ] **Step 2: Fix active state for nested `/dashboard` routes**

In the `NavRow` component, change the `active` computation from:
```typescript
const active =
  pathname === item.href ||
  (item.href !== "/dashboard" && pathname.startsWith(item.href));
```
to:
```typescript
const active =
  pathname === item.href ||
  (item.href !== "/" && pathname.startsWith(item.href));
```
This correctly highlights "Basic Recon" when at `/dashboard/recon-jobs`.

- [ ] **Step 3: Update `buildBreadcrumb`**

Replace the function:
```typescript
function buildBreadcrumb(pathname: string): string[] {
  if (pathname === "/dashboard") return ["Basic Recon", "Add Scan"];
  if (pathname === "/dashboard/recon-jobs") return ["Basic Recon", "Recon Jobs"];
  if (pathname.startsWith("/scans/")) return ["Basic Recon", "Scan Detail"];
  if (pathname === "/targets") return ["Targets"];
  if (pathname === "/reports") return ["Reports"];
  if (pathname === "/settings") return ["Settings"];
  const parts = pathname.split("/").filter(Boolean);
  return parts.map((p) => p.charAt(0).toUpperCase() + p.slice(1));
}
```

- [ ] **Step 4: Update TopBar "New Scan" quick link**

Change the TopBar quick-link from `/dashboard?compose=1` to `/dashboard`:
```typescript
<Link href="/dashboard" className="hidden md:inline-flex items-center gap-1.5 h-9 px-3 rounded-md bg-primary text-primary-foreground text-sm font-medium hover:bg-primary/90">
  <Plus className="h-4 w-4" /> New Scan
</Link>
```

- [ ] **Step 5: Verify sidebar in browser**

Navigate to `http://localhost:3000/dashboard`. Expected: "Basic Recon" with "Add Scan" and "Recon Jobs" children visible; no standalone "Dashboard" or "Scans" nav items.

- [ ] **Step 6: Commit**

```bash
git add frontend/components/AppShell.tsx
git commit -m "feat: rename Dashboard to Basic Recon, restructure nav with Add Scan / Recon Jobs"
```

---

## Task 6: Frontend — Dashboard layout with stats bar

**Files:**
- Create: `frontend/app/dashboard/layout.tsx`

This layout wraps both `dashboard/page.tsx` and `dashboard/recon-jobs/page.tsx`. **Important:** Both child pages must NOT render their own `<AppShell>` — the layout provides it.

- [ ] **Step 1: Create `frontend/app/dashboard/layout.tsx`**

```typescript
"use client";

import { useQuery } from "@tanstack/react-query";
import { Activity, AlertCircle, CheckCircle2, Database } from "lucide-react";
import { AppShell } from "@/components/AppShell";
import { api, type Scan } from "@/lib/api";

function StatPill({
  icon: Icon,
  label,
  value,
  colorClass,
}: {
  icon: React.ComponentType<{ className?: string }>;
  label: string;
  value: number;
  colorClass: string;
}) {
  return (
    <div className="flex items-center gap-2 rounded-lg border border-border bg-card px-4 py-2.5">
      <Icon className={`h-4 w-4 ${colorClass}`} />
      <div>
        <div className="text-xs text-muted-foreground">{label}</div>
        <div className="text-lg font-semibold tabular-nums leading-none">{value}</div>
      </div>
    </div>
  );
}

export default function DashboardLayout({ children }: { children: React.ReactNode }) {
  const scans = useQuery({
    queryKey: ["scans"],
    queryFn: () => api<Scan[]>("/scans"),
    refetchInterval: (q) => {
      const data = q.state.data as Scan[] | undefined;
      return data?.some((s) => s.status === "running" || s.status === "created") ? 3000 : false;
    },
  });

  const all = scans.data ?? [];
  const totalCount = all.length;
  const runningCount = all.filter((s) => s.status === "running" || s.status === "created").length;
  const completedCount = all.filter((s) => s.status === "completed").length;
  const failedCount = all.filter((s) => s.status === "failed" || s.status === "stopped").length;

  return (
    <AppShell>
      <div className="mb-6">
        <h1 className="text-2xl font-semibold tracking-tight">Basic Recon</h1>
        <p className="text-sm text-muted-foreground mt-1">
          Queue and run reconnaissance scans against your targets.
        </p>
      </div>

      {/* Stats bar */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-8">
        <StatPill icon={Database} label="Total Scans" value={totalCount} colorClass="text-muted-foreground" />
        <StatPill icon={Activity} label="Running" value={runningCount} colorClass="text-warning" />
        <StatPill icon={CheckCircle2} label="Completed" value={completedCount} colorClass="text-success" />
        <StatPill icon={AlertCircle} label="Failed / Stopped" value={failedCount} colorClass="text-destructive" />
      </div>

      {children}
    </AppShell>
  );
}
```

- [ ] **Step 2: Remove `<AppShell>` from `dashboard/page.tsx`**

The current dashboard page wraps everything in `<AppShell>`. Once the layout is in place, remove that wrapper — the layout provides it. The page should return its content directly (a `<Card>` element at the top level).

- [ ] **Step 3: Verify both routes show stats bar**

Navigate to `/dashboard` and `/dashboard/recon-jobs` — both should show the "Basic Recon" header and stats bar.

- [ ] **Step 4: Commit**

```bash
git add frontend/app/dashboard/layout.tsx
git commit -m "feat: add dashboard layout with Basic Recon header and stats bar"
```

---

## Task 7: Frontend — Simplified "Add Scan" page

**Files:**
- Modify: `frontend/app/dashboard/page.tsx`

Remove the Prioritized Risks card, Running/Completed tabs, and scan list. Replace with a clean form with [Add] and [Start Scan] buttons. Note: `<AppShell>` is now provided by `layout.tsx` — do NOT include it here.

- [ ] **Step 1: Rewrite `dashboard/page.tsx`**

```typescript
"use client";

import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { Plus, Zap } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { ApiError, api, type Scan } from "@/lib/api";

export default function AddScanPage() {
  const qc = useQueryClient();
  const router = useRouter();
  const [domain, setDomain] = useState("");
  const [profile, setProfile] = useState("standard");
  const [err, setErr] = useState<string | null>(null);
  const [addedDomain, setAddedDomain] = useState<string | null>(null);

  const create = useMutation({
    mutationFn: (body: { domain: string; profile: string; autostart: boolean }) =>
      api<Scan>("/scans", { method: "POST", body: JSON.stringify(body) }),
    onSuccess: (scan, variables) => {
      qc.invalidateQueries({ queryKey: ["scans"] });
      setErr(null);
      if (variables.autostart) {
        router.push(`/scans/${scan.id}`);
      } else {
        setAddedDomain(scan.domain);
        setDomain("");
      }
    },
    onError: (e) => setErr(e instanceof ApiError ? e.message : "Failed to create scan"),
  });

  const handleAdd = () => {
    if (!domain.trim()) return;
    setErr(null);
    setAddedDomain(null);
    create.mutate({ domain: domain.trim(), profile, autostart: false });
  };

  const handleStartScan = () => {
    if (!domain.trim()) return;
    setErr(null);
    setAddedDomain(null);
    create.mutate({ domain: domain.trim(), profile, autostart: true });
  };

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center gap-2">
          <Plus className="h-4 w-4 text-primary" />
          <CardTitle>New Scan</CardTitle>
        </div>
        <CardDescription>
          Enter a target domain and choose a profile. <strong>Add</strong> queues it for later;{" "}
          <strong>Start Scan</strong> runs it immediately.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <div className="flex flex-wrap gap-2">
          <Input
            placeholder="example.com"
            value={domain}
            onChange={(e) => { setDomain(e.target.value); setAddedDomain(null); }}
            className="flex-1 min-w-[16rem]"
            onKeyDown={(e) => { if (e.key === "Enter") handleStartScan(); }}
          />
          <Select value={profile} onValueChange={setProfile}>
            <SelectTrigger className="w-36">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="quick">quick</SelectItem>
              <SelectItem value="standard">standard</SelectItem>
              <SelectItem value="deep">deep</SelectItem>
            </SelectContent>
          </Select>
          <Button
            variant="outline"
            onClick={handleAdd}
            disabled={create.isPending || !domain.trim()}
          >
            Add
          </Button>
          <Button
            onClick={handleStartScan}
            disabled={create.isPending || !domain.trim()}
          >
            <Zap className="h-4 w-4" />
            {create.isPending ? "Starting…" : "Start Scan"}
          </Button>
        </div>
        {err && <p className="text-sm text-destructive mt-3">{err}</p>}
        {addedDomain && (
          <p className="text-sm text-success mt-3">
            <strong>{addedDomain}</strong> queued — find it in{" "}
            <a href="/dashboard/recon-jobs" className="underline">Recon Jobs</a>.
          </p>
        )}
      </CardContent>
    </Card>
  );
}
```

- [ ] **Step 2: Verify page renders and buttons work**

- `http://localhost:3000/dashboard` shows only the New Scan card (no risks, no scan list)
- [Add] button creates queued scan, shows success message, clears the domain field
- [Start Scan] creates and starts scan, redirects to detail page
- Stats bar updates count

- [ ] **Step 3: Commit**

```bash
git add frontend/app/dashboard/page.tsx
git commit -m "feat: simplify Add Scan page with Add + Start Scan buttons, remove old dashboard content"
```

---

## Task 8: Frontend — Recon Jobs table page

**Files:**
- Create: `frontend/app/dashboard/recon-jobs/page.tsx`

Note: `<AppShell>` is provided by `layout.tsx` — this page returns content directly.

- [ ] **Step 1: Create `frontend/app/dashboard/recon-jobs/page.tsx`**

```typescript
"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useRouter } from "next/navigation";
import { ExternalLink, Play, Square, Trash2 } from "lucide-react";
import Link from "next/link";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { api, deleteScan, patchScan, startScan, stopScan, type Scan } from "@/lib/api";

const STATUS_CONFIG: Record<
  Scan["status"],
  { label: string; variant: "default" | "warning" | "success" | "destructive" | "secondary" }
> = {
  queued:    { label: "Not Started", variant: "secondary" },
  created:   { label: "Queued",      variant: "warning"   },
  running:   { label: "Running",     variant: "warning"   },
  completed: { label: "Completed",   variant: "success"   },
  failed:    { label: "Failed",      variant: "destructive" },
  stopped:   { label: "Stopped",     variant: "default"   },
};

function RunningProgress({ scan }: { scan: Scan }) {
  return (
    <div className="min-w-[120px]">
      <div className="h-1.5 bg-muted rounded overflow-hidden mb-1">
        <div
          className="h-full bg-primary transition-all"
          style={{ width: `${scan.progress_pct}%` }}
        />
      </div>
      <div className="text-xs text-muted-foreground">{scan.progress_pct}%</div>
    </div>
  );
}

function ScanTableRow({ scan }: { scan: Scan }) {
  const router = useRouter();
  const qc = useQueryClient();
  const invalidate = () => qc.invalidateQueries({ queryKey: ["scans"] });

  const doStart = useMutation({ mutationFn: () => startScan(scan.id), onSuccess: (s) => { invalidate(); router.push(`/scans/${s.id}`); } });
  const doStop  = useMutation({ mutationFn: () => stopScan(scan.id),  onSuccess: invalidate });
  const doDelete = useMutation({ mutationFn: () => deleteScan(scan.id), onSuccess: invalidate });
  const doPatch  = useMutation({ mutationFn: (p: string) => patchScan(scan.id, p), onSuccess: invalidate });

  const cfg = STATUS_CONFIG[scan.status] ?? { label: scan.status, variant: "default" as const };
  const isActive = scan.status === "running" || scan.status === "created";

  return (
    <tr className="border-b border-border hover:bg-muted/30 transition-colors">
      {/* Domain */}
      <td className="px-4 py-3">
        <Link href={`/scans/${scan.id}`} className="font-medium hover:underline text-foreground">
          {scan.domain}
        </Link>
        <div className="text-xs text-muted-foreground mt-0.5">
          {new Date(scan.created_at).toLocaleString()}
        </div>
      </td>

      {/* Profile — editable only when queued */}
      <td className="px-4 py-3">
        {scan.status === "queued" ? (
          <Select value={scan.profile} onValueChange={(p) => doPatch.mutate(p)}>
            <SelectTrigger className="h-7 w-28 text-xs">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="quick">quick</SelectItem>
              <SelectItem value="standard">standard</SelectItem>
              <SelectItem value="deep">deep</SelectItem>
            </SelectContent>
          </Select>
        ) : (
          <span className="text-sm font-mono">{scan.profile}</span>
        )}
      </td>

      {/* Status */}
      <td className="px-4 py-3">
        <Badge variant={cfg.variant}>{cfg.label}</Badge>
      </td>

      {/* Progress */}
      <td className="px-4 py-3">
        {isActive ? <RunningProgress scan={scan} /> :
         scan.status === "completed" ? <span className="text-xs text-muted-foreground">100%</span> :
         <span className="text-xs text-muted-foreground">—</span>}
      </td>

      {/* Actions */}
      <td className="px-4 py-3">
        <div className="flex items-center gap-1.5">
          {scan.status === "queued" && (
            <>
              <Button size="sm" variant="outline" className="h-7 gap-1 text-xs"
                onClick={() => doStart.mutate()} disabled={doStart.isPending}>
                <Play className="h-3 w-3" /> Start
              </Button>
              <Button size="sm" variant="ghost" className="h-7 w-7 p-0 text-destructive hover:text-destructive"
                onClick={() => doDelete.mutate()} disabled={doDelete.isPending} title="Delete">
                <Trash2 className="h-3.5 w-3.5" />
              </Button>
            </>
          )}
          {isActive && (
            <Button size="sm" variant="outline" className="h-7 gap-1 text-xs"
              onClick={() => doStop.mutate()} disabled={doStop.isPending}>
              <Square className="h-3 w-3" /> Stop
            </Button>
          )}
          {(scan.status === "completed" || scan.status === "failed" || scan.status === "stopped") && (
            <Button size="sm" variant="outline" className="h-7 gap-1 text-xs" asChild>
              <Link href={`/scans/${scan.id}`}>
                <ExternalLink className="h-3 w-3" /> View Results
              </Link>
            </Button>
          )}
        </div>
      </td>
    </tr>
  );
}

export default function ReconJobsPage() {
  const scans = useQuery({
    queryKey: ["scans"],
    queryFn: () => api<Scan[]>("/scans"),
    refetchInterval: (q) => {
      const data = q.state.data as Scan[] | undefined;
      return data?.some((s) => s.status === "running" || s.status === "created") ? 3000 : false;
    },
  });

  if (scans.isLoading) return <p className="text-sm text-muted-foreground">Loading jobs…</p>;

  const all = scans.data ?? [];

  if (all.length === 0) {
    return (
      <div className="rounded-lg border border-dashed border-border p-8 text-center">
        <p className="text-sm text-muted-foreground">No scans yet — add one on the Add Scan page.</p>
      </div>
    );
  }

  return (
    <div className="rounded-lg border border-border overflow-hidden">
      <table className="w-full text-sm">
        <thead className="bg-muted/50 border-b border-border">
          <tr>
            {["Target Domain", "Profile", "Status", "Progress", "Actions"].map((h) => (
              <th key={h} className="px-4 py-2.5 text-left font-medium text-xs uppercase tracking-wide text-muted-foreground">
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {all.map((scan) => <ScanTableRow key={scan.id} scan={scan} />)}
        </tbody>
      </table>
    </div>
  );
}
```

- [ ] **Step 2: Verify Recon Jobs page**

Navigate to `http://localhost:3000/dashboard/recon-jobs`:
- All scans appear in rows
- Queued scans: profile dropdown (changes save), Start button, Trash button
- Running scans: progress bar + Stop button
- Completed/Stopped/Failed: View Results button

- [ ] **Step 3: Commit**

```bash
git add frontend/app/dashboard/recon-jobs/page.tsx
git commit -m "feat: add Recon Jobs table with lifecycle actions and status badges"
```

---

## Task 9: Frontend — Prioritized Risks card in OverviewTab

**Files:**
- Modify: `frontend/components/tabs/OverviewTab.tsx`

The Prioritized Risks card was removed from the dashboard in Task 7. It now lives in the scan detail's Overview tab, shown only for completed deep scans.

- [ ] **Step 1: Add imports to OverviewTab.tsx**

Add to existing imports:
```typescript
import { ShieldAlert } from "lucide-react";
import Link from "next/link";
import { api, type FindingsPage, type ScanDetail, type ScanOverview } from "@/lib/api";
```
(Replace the existing `api, type ScanDetail, type ScanOverview` import)

- [ ] **Step 2: Add findings query inside `OverviewTab`**

Inside the function body, after the existing `data` query:
```typescript
  const risksQuery = useQuery({
    queryKey: ["scan-findings", scanId, "HIGH", 1],
    queryFn: () => api<FindingsPage>(`/scans/${scanId}/findings?severity=HIGH&limit=5`),
    enabled: scan?.profile === "deep" && scan?.status === "completed",
  });
```

- [ ] **Step 3: Insert Top Risks card into the JSX**

After the 5-stat count grid and before the 3-column charts grid, add:
```typescript
      {/* Top Risks — only for completed deep scans */}
      {scan?.profile === "deep" && scan?.status === "completed" && (
        <Card>
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <div className="flex items-center gap-2">
              <ShieldAlert className="h-4 w-4 text-destructive" />
              <CardTitle>Top Risks</CardTitle>
            </div>
            <Link href={`/scans/${scanId}?tab=risks`} className="text-xs text-primary hover:underline">
              View all →
            </Link>
          </CardHeader>
          <CardContent>
            {risksQuery.isLoading ? (
              <p className="text-sm text-muted-foreground">Loading risks…</p>
            ) : !risksQuery.data?.items.length ? (
              <p className="text-sm text-muted-foreground">No HIGH severity findings.</p>
            ) : (
              <div className="space-y-2">
                {risksQuery.data.items.map((finding) => (
                  <div key={finding.finding_id}
                    className="flex items-start gap-3 rounded-md border border-border bg-card/50 px-3 py-2">
                    <span className="w-6 shrink-0 text-xs font-semibold tabular-nums text-muted-foreground">
                      #{finding.priority_rank}
                    </span>
                    <div className="min-w-0">
                      <div className="truncate font-mono text-xs font-medium" title={finding.fqdn}>
                        {finding.fqdn}
                      </div>
                      <div className="mt-0.5 line-clamp-1 text-xs text-muted-foreground">
                        {finding.rationale}
                      </div>
                    </div>
                    <span className="shrink-0 rounded px-1.5 py-0.5 text-xs font-medium bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-300">
                      HIGH
                    </span>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      )}
```

- [ ] **Step 4: Verify TypeScript and visual output**

```bash
docker compose exec frontend npx tsc --noEmit
```
Then open a completed deep scan's Overview tab — "Top Risks" card should appear. On a non-deep or incomplete scan, the card should be absent.

- [ ] **Step 5: Commit**

```bash
git add frontend/components/tabs/OverviewTab.tsx
git commit -m "feat: add Top Risks card to OverviewTab for completed deep scans"
```

---

## Verification Checklist

1. **Sidebar** — "Basic Recon" with "Add Scan" + "Recon Jobs" children; no standalone "Dashboard" or "Scans" items
2. **Stats bar** — Total / Running / Completed / Failed+Stopped visible at both `/dashboard` and `/dashboard/recon-jobs`
3. **Add Scan** — [Add] creates `queued` scan with success message, no redirect; [Start Scan] creates, starts, and redirects to detail
4. **Recon Jobs table** — all statuses display correctly; queued rows have editable profile dropdown, Start + Delete buttons; running rows have progress bar + Stop; terminal rows have View Results
5. **Stop** — Stop button marks scan `stopped`; worker does not override to `completed`
6. **Top Risks card** — visible in Overview tab for completed deep scans only; absent otherwise
7. **TypeScript** — `docker compose exec frontend npx tsc --noEmit` → zero errors

---

# Red Team Recon Dashboard — Architectural Plan

## Context

You're building a **domain-driven Attack Surface Management (ASM) platform** that automates reconnaissance pipelines, normalizes intelligence into a queryable model, and surfaces it through a real-time dashboard. The MVP spec in `project_spec.md` is sound for a learning prototype but is structurally insufficient for what you actually want — a system that can grow into a Censys/Shodan/ProjectDiscovery-class product.

The core problems this plan solves:

1. **The MVP design is monolithic and stage-sequential.** It cannot scale to BBOT-style 100+ module recon, parallel tool fan-out, or large target sets without being rewritten.
2. **The data model is flat.** It treats results as rows, not as a graph of *assets* (domains, IPs, certs, services, technologies, organizations) that ASM products live or die by.
3. **The pipeline has no abstraction.** Each tool is implicitly hardcoded into stages, which couples scan logic to specific binaries — exactly what you said you want to avoid.
4. **There is no plan for the AI layer.** The multi-agent council needs a concrete charter, communication protocol, and integration points with the recon pipeline, not a vibes-based "agents collaborate" hand-wave.

This plan replaces the milestone roadmap with a layered architecture, a DAG-based pipeline, a normalized asset graph, and a defined multi-agent council that participates in both *building* the system (design-time) and *operating* it (runtime).

---

## 1. Product Positioning & Wedge

Before architecture: **what is the wedge?** Censys/Shodan own internet-wide passive data. ProjectDiscovery owns the OSS toolchain. BBOT owns recursive recon. You will not out-data any of them.

Your wedge is **opinionated orchestration + AI-driven risk prioritization + clean UX over the OSS toolchain you already listed**. Think: "the Linear of recon" — you don't invent the work, you make running and reviewing it pleasant. Specifically:

- **Run-mode tiers**: `quick` (passive only, ~30s), `standard` (passive + active probe, ~5min), `deep` (full BBOT + ports + endpoints, ~30min+).
- **AI prioritization on every scan** — instead of dumping 800 assets on the user, every asset is severity-bucketed and ranked, with high-priority items surfaced first. That's the headline feature, not a chatbot.
- **Tool-agnostic asset graph** — the user never sees raw subfinder output; they see assets with provenance.
- **Multi-tenant from day one**, even if tenant count = 1, because retrofitting tenancy is the most expensive refactor in SaaS.

*Diff scans were originally part of the wedge; they're deferred until after enrichment + search ships. The asset graph still records `first_seen`/`last_seen` so the data is there when we're ready to expose it.*

This positioning shapes every architectural choice below.

---

## 2. System Architecture (Layered)

Five logical planes, deployable as one process at MVP and split as load grows. **Do not start with microservices.** Start with a modular monolith + worker pool; the module boundaries below are the seams along which you'll later split.

```
┌─────────────────────────────────────────────────────────────┐
│  PRESENTATION   Next.js 14 (App Router) + TanStack Query    │
│                 SSE for live progress, REST for queries     │
├─────────────────────────────────────────────────────────────┤
│  API GATEWAY    FastAPI (async) — auth, scan CRUD, query    │
│                 Read models served from materialized views  │
├─────────────────────────────────────────────────────────────┤
│  ORCHESTRATION  Scan Coordinator (DAG executor)             │
│                 Stage Scheduler, retry/backoff, timeouts    │
├─────────────────────────────────────────────────────────────┤
│  EXECUTION      Worker Pool (Celery/Arq) — Tool Adapters    │
│                 Sandboxed subprocess runners per tool       │
├─────────────────────────────────────────────────────────────┤
│  DATA           Postgres (asset graph) + Redis (queue/cache)│
│                 OpenSearch (full-text/asset search)         │
│                 S3/MinIO (raw tool output, screenshots)     │
└─────────────────────────────────────────────────────────────┘
```

**Why these choices:**
- **FastAPI** over Express: native async, Pydantic models double as API contracts and DB DTOs, ecosystem fit with Python recon tooling.
- **Arq** over Celery for MVP (lighter, async-native, Redis-only). Migrate to Celery+RabbitMQ when you need priority queues and per-tenant fairness.
- **Postgres** with `JSONB` columns for tool-specific metadata, but **normalized columns for queryable fields** (status, IP, ASN, etc.). Don't store everything as JSON — that's a graveyard.
- **OpenSearch** is deferred to Milestone 3, but design the asset model with full-text in mind from day one.
- **S3/MinIO** for screenshots (gowitness), raw HTTP responses, and cold archives — never put binary blobs in Postgres.

---

## 3. The Recon Pipeline as a DAG (Not a Chain)

The MVP spec describes a linear chain (Subdomain → HTTP → IP). This is wrong as soon as you add a fourth tool. **Model the pipeline as a Directed Acyclic Graph of stages with typed inputs/outputs.**

### Stage Abstraction

```python
class Stage(Protocol):
    name: str
    inputs: list[AssetType]   # e.g. [Domain]
    outputs: list[AssetType]  # e.g. [Subdomain, DNSRecord]
    depends_on: list[str]     # stage names
    timeout: int
    retry_policy: RetryPolicy
    
    async def execute(ctx: ScanContext, inputs: AssetSet) -> AssetSet: ...
```

Every tool integration is a `Stage`. The Scan Coordinator builds a DAG from the requested run-mode profile, topologically sorts it, fans out parallel branches, and streams asset deltas back to the data layer as each stage completes.

### Concrete DAG (Standard mode)

```
              ┌──> subfinder ──┐
   [Domain] ──┤                ├──> dedupe ──> dnsx ──> httpx ──> wafw00f
              └──> assetfinder ┘                  │
                                                  └──> naabu (top 1000)
                                                           │
                                                           └──> nmap -sV (on open ports)
   [Domain] ──> Censys API ──┐
                             ├──> dedupe ──> enrich (ASN, geo)
   [Domain] ──> Shodan API ──┘
   
   [HTTPx live hosts] ──> gau / katana ──> URL bucket
   [HTTPx live hosts] ──> gowitness ──> S3
```

### Run-mode Profiles

| Profile  | Stages                                                | SLA      |
|----------|-------------------------------------------------------|----------|
| quick    | subfinder + assetfinder + dnsx + httpx                | < 60s    |
| standard | + Censys/Shodan + wafw00f + naabu top-1k + gowitness  | < 5 min  |
| deep     | + BBOT recursive + nmap -sV + katana + CloudFlair     | bounded* |

*Deep scans get a hard wall-clock cap (e.g., 30 min) with checkpointed partial results — never let a scan run forever.

### Tool Adapter Layer

Each tool gets an adapter that:
1. Accepts normalized `AssetSet` input.
2. Renders the tool's CLI invocation (or API call).
3. Runs the subprocess in a **sandboxed environment** (separate uid, cgroup memory cap, network egress allowed but rate-limited).
4. Parses tool output into the normalized asset model.
5. Records provenance (which tool found which asset, with what confidence).

This is the **anti-coupling boundary** the spec correctly identified — formalize it as a protocol.

---

## 4. Data Model — The Asset Graph

This is the most undervalued part of the original spec. Treat assets as first-class entities with deduplication identity, not as scan-scoped rows.

### Core entities

- **Organization** — top-level tenant.
- **Project** — a logical grouping under an organization (e.g., "production", "acquisition-target-X").
- **Target** — a domain or IP range registered for monitoring.
- **Scan** — a single execution of a pipeline against a Target.
- **Asset** — the deduplicated unit: `Subdomain`, `IPAddress`, `Service`, `Certificate`, `Technology`, `Endpoint`. Identified by a stable canonical key.
- **AssetObservation** — every time a scan sees an asset, it writes an observation (with timestamp, source tool, confidence, raw payload). Assets accumulate observations over time → diffs become trivial.
- **ScanStage** — execution record per DAG node, with status/timing/error.
- **Finding** — derived rows surfaced in the UI. In M3 these are exclusively `kind=risk_priority` entries from the Risk Prioritization Agent (one per scanned asset). Diff-driven `kind=new_subdomain`/`new_port` rows are deferred along with the diff feature itself.

### Why this matters

- **Multi-source confidence** — if Censys, subfinder, and BBOT all report `api.example.com`, that's a high-confidence asset; if only one source did, mark it accordingly. The Risk Prioritization Agent (M3) reads this signal directly.
- **Asset history is free** — `first_seen`/`last_seen` and per-scan observations accumulate from day one. The diff/explorer surface that consumes them is deferred, but the data layer underneath does not change when we're ready to ship it.
- **Diff scans become a database query when we eventually expose them** — `SELECT assets WHERE first_seen >= last_scan_time` is the whole feature. We're choosing not to build the UI for that yet (see "Defer indefinitely"), but the schema is already correct for the day we do.

### Schema sketch (Postgres)

```
organizations(id, name, plan, created_at)
users(id, org_id, email, password_hash, role)
projects(id, org_id, name)
targets(id, project_id, domain, kind, monitoring_enabled)
scans(id, target_id, profile, status, progress_pct, started_at, finished_at, triggered_by)
scan_stages(id, scan_id, stage_name, status, started_at, finished_at, error, output_uri)

assets(id, target_id, type, canonical_key, first_seen, last_seen, attributes JSONB)
  UNIQUE(target_id, type, canonical_key)
asset_observations(id, asset_id, scan_id, stage_id, source_tool, observed_at, payload JSONB, confidence)
asset_relationships(id, src_asset_id, dst_asset_id, relation_type)  -- e.g. subdomain→ip, ip→asn

findings(id, scan_id, asset_id, kind, severity, title, details JSONB, acknowledged)
```

Critical indexes: `(target_id, type, canonical_key)` for asset upsert, `(scan_id, stage_name)` for progress queries, `(asset_id, observed_at DESC)` for history views.

---

## 5. Async Execution & Real-Time Updates

### Queue topology

- **Default queue** — standard scans.
- **Priority queue** — paid-tier / interactive scans.
- **Heavy queue** — deep scans, isolated worker pool with higher memory limits.
- **Per-tenant token bucket** — prevents one user from starving the queue. Implement with a Redis Lua script.

### Worker isolation

- Each tool subprocess runs under a **per-scan working directory** with bounded disk quota.
- Egress from naabu/nmap goes through an **outbound proxy with per-tenant rate limits** — critical for both being a polite internet citizen and avoiding upstream blocks.
- **Authorization gate**: before any active scanning stage (naabu, nmap, katana with crawl, CloudFlair), require an `authorization_token` on the Target proving the user owns/has-permission. Skipping this is a legal liability and a future-you problem.

### Real-time progress

- Workers publish stage events to a **Redis pub/sub channel** keyed by `scan:{scan_id}`.
- API exposes **Server-Sent Events** at `/scans/{id}/stream` — simpler than WebSockets, works through every proxy, perfect for one-way updates.
- Frontend subscribes on the scan detail page; the dashboard list polls `/scans?status=running` every 5s.
- **Progress calculation**: not `completed/total` (that lies — a 30-min nmap stage and a 2s dnsx stage are not equal). Weight stages by historical p50 duration. Recompute weights nightly.

---

## 6. Frontend Architecture

The reference visual target is `docs/screenshots/scan-results-mockup.png` (razorpay.com style). The placeholder `type | canonical_key | first_seen` table from M0/M1 is explicitly *not* the product — the product is a subdomain-centric inventory with rich, sortable, filterable columns and a multi-tab scan workspace.

### Stack

- **Next.js 14** (App Router). Server components for static chrome; client components for interactive tables, charts, theme.
- **TanStack Query** for server state, **Zustand** for ephemeral UI state. No Redux.
- **shadcn/ui** (Radix + Tailwind) for primitives — tables, badges, tabs, dropdowns, dialogs, toasts. Don't hand-roll these; the mockup's badge/pill/filter language is exactly what shadcn ships.
- **TanStack Table v8** + **@tanstack/react-virtual** for the headline tables. Recon explodes past 10k rows fast; non-virtualized tables brick the browser.
- **lucide-react** icons. **next-themes** for light/dark with `prefers-color-scheme` fallback, persisted to `localStorage`.
- **Recharts** (or **visx**) for the Overview-tab donuts/bars. One chart lib, not two.

### App shell

- **Persistent left sidebar**, grouped: `Dashboard`, `Scans` (sub-items: `Add Scan`, `Recent Scans`, `Completed Scans`), `Targets`, `Reports`, `Settings`. Collapses to icons on narrow viewports. Active item highlighted with the brand accent.
- **Top bar**: breadcrumb left (`Scans / Scan Details`), then theme toggle, notification bell, avatar with org/role popover.
- **Light theme is the default** (matches the mockup), dark theme available via the toggle. Build component primitives against the shadcn token system so both themes get the same palette discipline.

### Three primary screens

1. **Dashboard** — recent scans card, running scans (live progress), Prioritized Risks card (from M3).
2. **Scan Detail** — see "Scan Detail spec" below. This is the screen the user sees most.
3. **Asset Explorer** (M4+) — search across all historical assets for a target, filter by tech/ASN/status. (Asset history timeline depends on the deferred diff feature; ship search-only first.)

### Scan Detail spec

- **Header card**: target domain (h1), status badge, a meta row (`started`, `duration`, `total subdomains`, `status` chip), and right-aligned actions: **Export** (CSV/JSON dropdown) + **Share Report**.
- **Tab bar** (left-aligned, underline-on-active):
  - **Overview** — counts grid (subdomains, IPs, CDNs, WAFs, technologies); HTTP-status distribution donut; top-N tech bar; top-N ASN bar; **stage timeline** showing the DAG with per-stage status and elapsed time.
  - **Subdomains** — the headline table from the mockup. See "Subdomains table" below.
  - **IP Summary** — table of IPs → subdomain count, ASN/Org, Country/City. Row click drills to all subdomains on that IP.
  - **CDN / WAF** — coverage charts: % behind a CDN, breakdown by provider, WAF coverage with confidence buckets, list of *unprotected* origins (no CDN, no WAF) — that's the actionable view.
  - **Technologies** — tech inventory with counts and click-to-filter back into the Subdomains tab.
  - **Risks** — Prioritized Risks list (M3): every asset ranked, high-severity first, with rationale. Also reachable from the dashboard "Prioritized Risks" card.
- *Deferred:* History tab + Diff modal (was M3, now indefinitely deferred — see "Defer indefinitely").

### Subdomains table (the headline view)

Match the mockup. Columns, in order:

| Col | Source | Notes |
|-----|--------|-------|
| `#` | row index | not sortable |
| `Subdomain` | subfinder/assetfinder | sortable; click → asset detail drawer |
| `HTTP Status` | httpx | colored badge: green 2xx, amber 3xx, red 4xx/5xx, neutral if no probe |
| `Title` | httpx | truncated, full on hover |
| `Redir` | httpx `-follow-redirects` | `YES` pill + final URL on hover |
| `IP Tag` | derived from CDN detection | `CDN IP` / `Direct IP` / `Cloudflare IP` chip |
| `Primary IP` | dnsx (first A) | monospace |
| `All IPs` | dnsx | comma-joined, truncated; tooltip with full list |
| `CDN` | httpx `-cdn` | provider name + small logo |
| `CNAME` | dnsx `-cname` | monospace |
| `WAF` | wafw00f | "AWS WAF possible" / "Cloudflare WAF" / blank |
| `WAF Conf` | wafw00f confidence | `LOW` / `MED` / `HIGH` badge |
| `ASN` | asnmap | `AS16509` |
| `Org` | asnmap | `Amazon.com, Inc.` |
| `Country` | geoip | flag emoji + 2-letter |
| `City` | geoip | text |
| `Server` | httpx response header | `nginx/1.21.4`, `cloudflare`, etc |

Above the table: search box (subdomain substring), and dropdown filters for `Status Codes`, `IP Types`, `CDNs`, `WAFs`. Right side: **Columns** toggle (show/hide), CSV download. Sticky header, virtualized rows, server-side pagination at 15 / 50 / 100 / page.

### API contract changes this implies

- Replace flat `/scans/{id}/assets` with `/scans/{id}/subdomains?page=&limit=&sort=&filter[status]=&filter[cdn]=` returning denormalized rows joined across the asset graph.
- Add `/scans/{id}/overview` returning the counts and distributions the Overview tab needs (one round-trip, not five).
- Add `/scans/{id}/ips`, `/scans/{id}/cdn-waf`, `/scans/{id}/technologies` for the other tabs.

---

## 7. Multi-Agent AI Council

This is where most projects ship a chatbot and call it a day. Your platform should treat agents as **specialized internal contributors** with charters, not as a single LLM call dressed up. Two operating modes:

### Mode A — Design-time council (helps you build)

A roundtable that runs against architectural decisions, PRs, and roadmap proposals. You feed it a question; agents respond with their domain lens; an orchestrator synthesizes. Implemented via the Anthropic SDK with prompt caching on the shared system context (the architecture doc) so each round is cheap.

### Mode B — Runtime agents (help the user)

Actual product features that run on user data. These are the ones that justify charging money.

### The 8 Agents

| # | Agent                       | Domain                                | Mode | Outputs                                                           |
|---|-----------------------------|---------------------------------------|------|-------------------------------------------------------------------|
| 1 | **Architect Agent**         | System design, scaling, tradeoffs     | A    | Design critiques, alternative patterns, ADR drafts                |
| 2 | **Pipeline Optimizer**      | Recon DAG efficiency, tool selection  | A    | Suggests dropping redundant tools, profile tuning per target type |
| 3 | **Infrastructure Agent**    | Cost, scaling, deployment             | A    | Capacity estimates, infra cost ceilings, resource planning        |
| 4 | **Data Modeler Agent**      | Schema, indexing, query patterns      | A    | Migration plans, index suggestions from query logs                |
| 5 | **UX Agent**                | Frontend flows, information density   | A    | Wireframe critique, copy review, accessibility audit              |
| 6 | **Security Agent**          | Authz, sandbox, abuse, legal          | A    | Threat model per feature, abuse-case enumeration                  |
| 7 | **Risk Prioritization Agent** | Scoring assets by attack-surface risk | B    | Per-scan top-N "concentrate here" list with reasoning             |
| 8 | **Attack-Path Reasoner**    | Connecting assets into exploit chains | B    | Hypothesis chains: "this exposed admin panel + that subdomain..." |

**Expandable (future)** — Recon Analyst Summaries, Diff Narrator, Bug-bounty Strategy, Tech Stack reasoning all slot in via the same protocol when you want them.

### Mode B — what runtime agents actually do (revised focus)

The product's AI surface is **risk concentration, not narration**. Users don't want a paragraph summarizing what the scan found — they can read the table. They want: *"Of these 847 assets, here is every asset ranked by priority, with the high-severity items at the top and the reason for each."*

**Ranking contract:** every asset that flowed through the scan must appear in the output exactly once with a `priority_rank` (1 = highest). Severity buckets (`HIGH` / `MED` / `LOW` / `INFO`) sort first; within a bucket, `risk_score` (descending) breaks ties. The UI surfaces high-severity items first, then the ordered tail — no truncation, no "top 5 only" cliff. Test coverage must assert the agent emits a row for every asset, not just the leaders.

**Risk Prioritization Agent — output contract:**
```json
{
  "scan_id": "...",
  "generated_at": "...",
  "prioritized_assets": [
    {
      "asset_id": "...",
      "asset": "admin.staging.example.com",
      "priority_rank": 1,
      "severity": "HIGH",
      "risk_score": 0.92,
      "rationale": "Admin interface exposed on staging subdomain; nginx 1.18 (known CVEs); no WAF detected; recently appeared (first seen 3 days ago).",
      "signals": ["exposed_admin_panel", "outdated_software", "no_waf", "recent_appearance"],
      "recommended_action": "Restrict to VPN or add auth proxy."
    },
    {
      "asset_id": "...",
      "asset": "www.example.com",
      "priority_rank": 47,
      "severity": "INFO",
      "risk_score": 0.08,
      "rationale": "Public marketing site behind Cloudflare WAF; no exposed admin paths; current TLS.",
      "signals": ["waf_present", "cdn_fronted"],
      "recommended_action": "No action."
    }
  ]
}
```

**Attack-Path Reasoner** correlates *across* assets — e.g., "subdomain X has exposed `.git`, and host Y on the same ASN runs a CI server; combined this looks like a supply-chain foothold." Lower frequency (runs only on deep scans).

Both agents read from the asset graph, not from raw tool output — clean separation.

### Council protocol

```
question → Router (classifies domain) → relevant agents (parallel)
        → each agent returns {position, rationale, confidence, disagreements}
        → Synthesizer (Opus) produces decision + dissent log
        → Decision written to ADR file with agent-attributed rationale
```

Use **Claude Opus** for Synthesizer and Architect, **Sonnet** for the rest. Cache the architecture doc + asset schema as a shared system prompt — every council round becomes ~$0.01 instead of $0.50.

### Runtime agent integration

- Risk Prioritization Agent runs as the final stage of the DAG (depends on all other stages) and writes one `findings` row per scanned asset with `kind=risk_priority`, `priority_rank`, and `severity`.
- Attack-Path Reasoner runs only on `deep` profile scans, after Risk Prioritization, and writes `kind=attack_path` rows referencing 2+ assets each.
- Outputs land in the `findings` table → surfaced in the UI as the **Prioritized Risks** card (dashboard) and the **Risks tab** (Scan Detail).
- *Diff Narrator and Recon Analyst Summaries are deferred along with the diff feature — both rely on cross-scan history we're not exposing yet.*

---

## 8. Improved Milestone Roadmap

Replacing the v1/v2/v3 in the spec with execution-ordered milestones. Each is shippable.

### M0 — Skeleton (week 1)
- FastAPI + Postgres + Arq + Next.js scaffolds
- Auth (email + password + JWT), Org/Project/Target CRUD
- One stage end-to-end: subfinder only, results table renders
- **Done when**: can submit domain, see subfinder output in UI

### M1 — Pipeline framework (weeks 2–3)
- `Stage` protocol, DAG executor, tool adapter abstraction
- Adapters: subfinder, assetfinder, dnsx, httpx
- Per-stage status/progress, SSE live updates
- Asset model + observation upserts
- **Done when**: standard profile runs, results stream live, refreshing the page during a scan shows accurate progress

### M1.5 — Subdomain-centric UI overhaul + passive enrichment (weeks 3.5–4.5)

The current detail page is a flat `type | key | first_seen` table — unreadable as a product. This milestone makes the **Subdomains tab** the headline view *before* M2 lands active scanning, so future enrichment has a UI that can actually display it. Reference visual: `docs/screenshots/scan-results-mockup.png`.

**Backend — pull these stages forward from later milestones (all still passive, no authz gate needed):**
- **`wafw00f` adapter** (was M2). HEAD/GET with crafted payloads — passive enough to ship without the active-scanning gate.
- **`asnmap` adapter** (ProjectDiscovery, free CLI). IP → ASN, Org. Runs after dnsx, weight 10.
- **`geoip` enrichment**. Bundle IP2Location LITE DB (CC-BY) into the worker image. Pure-Python lookup, no API rate limit, no per-call cost. IP → Country, City. Weight 5.
- **Expand `httpx` adapter**: add `-follow-redirects`, `-cdn`, `-cname`, `-server`, `-ip`, `-location`. Capture `final_url`, `redirect`, `cdn_name`, `cnames`, `server`, `webserver` into the `http_service` payload.
- **Asset model decision** (defer to a Mode-A council mini-round): either add `cname` / `asn` / `cdn` / `waf` as new asset types, or denormalize onto the subdomain Asset's `attributes` JSONB and let the new endpoint do the join. Lean toward **the latter** for M1.5 — graph cleanliness can be revisited if/when the diff feature is reinstated.
- **New endpoint** `GET /scans/{id}/subdomains?page=&limit=&sort=&filter[...]` returning denormalized rows shaped exactly to the table columns. Server-side pagination, sorting, filtering. Plus `/overview`, `/ips`, `/cdn-waf`, `/technologies` to back the other tabs.

**Frontend — the design refresh:**
- Replace the placeholder shell with the **persistent-sidebar AppShell** described in Section 6.
- Install **shadcn/ui**, **TanStack Table v8**, **@tanstack/react-virtual**, **lucide-react**, **next-themes**, **recharts**.
- Light theme as default; dark via toggle, persisted.
- Build the **tabbed Scan Detail layout** (Overview, Subdomains, IP Summary, CDN/WAF, Technologies — Risks tab added in M3, History tab deferred indefinitely).
- Implement the **Subdomains table** to match the mockup column-for-column: sortable headers, virtualized rows, multi-filter row, column visibility toggle, CSV export, paginator with page-size dropdown.

**Done when**: a `standard` scan of `razorpay.com` (or any moderately-sized target) produces a Subdomains table that visually matches the mockup — every column populated for at least the rows where the data exists, filters working, theme toggle persists across reloads, table renders 1k+ rows without jank.

### M2 — Active scanning + isolation (weeks 4–5)
- Worker sandbox (subprocess limits, working dir, egress rate-limit)
- Authorization-token gate on targets
- naabu + nmap + gowitness adapters (wafw00f moved up to M1.5)
- Screenshots stored to MinIO, served via signed URLs
- New columns surface in the Subdomains table: `Open Ports`, `Screenshot` (thumbnail → modal); add a **Ports** tab.
- **Done when**: deep profile produces port + screenshot data, no scan can blow up the host, the new fields render in the existing table without a redesign

### M3 — AI risk prioritization (weeks 6–7)
- Risk Prioritization Agent runs as the final stage of every scan
- **All scanned assets are scored and ranked** — not a truncated top-N. Output lands in `findings` table with `kind=risk_priority`, `severity`, `priority_rank`, and structured rationale per asset.
- Dashboard surfaces a **"Prioritized Risks"** card per scan: priority items (HIGH severity) listed first, followed by the remaining assets in rank order. The full list is browsable/paginated, not capped at five.
- Bounded-completion wrapper + `ai_usage` ledger
- Mode A council infra used internally for ADRs (cheap to add — same SDK, same caching)
- **Done when**: every completed scan shows a Prioritized Risks card where (a) every asset that passed through the scan has a priority rank, (b) priority items render before the ordered tail, (c) tests assert coverage over the full asset set, not just the top entries; clicking an item jumps to the asset's detail page

*Deferred to a later milestone (was previously here):* per-scan natural-language summaries, weekly diff digests. They're cheap to add on top of the asset graph + agent infra, but they're not the wedge. Risk concentration is.

### M4 — Enrichment + search (weeks 8–9)
- Censys + Shodan integrations (rate-limited, cached)
- BBOT integration (deep profile only, isolated worker pool)
- OpenSearch index for asset full-text search
- **Done when**: search "tech:nginx AND status:200" across all targets returns in <500ms

### M5 — Scheduling + alerts (week 10+)
- Recurring scans (cron per target)
- Alert delivery (email, webhook, Slack)
- Per-tenant rate limits + billing hooks
- **Done when**: a scheduled scan that finds a new finding pages the user

### Defer indefinitely (and be ruthless)
- Microservices split — only when one module is the actual bottleneck
- **Kubernetes / orchestration upgrades** — Docker Compose on local hardware is the deployment target for the foreseeable future. Revisit only when you actually outgrow a single host. Don't pre-design for k8s; it warps every other choice.
- **Asset-graph diff + history features** (was M3) — diff scans, asset explorer, Findings rows of `kind=new_subdomain`/`new_port`, Scan-Detail History tab. The asset graph itself (`Asset` + `AssetObservation`) already exists and continues accumulating data, so diff is a future query-layer addition. Revisit after M5 if users actually ask "what changed."
- Per-scan natural-language summaries / weekly diff narration (moved out of M3 — add post-MVP if users ask)
- Real-time collaboration — nobody asked for this
- Vulnerability scanning (nuclei) — adjacent product, don't dilute the wedge

---

## 9. Critical Files to Create (when implementation begins)

```
backend/
  app/
    api/                     # FastAPI routers (auth, scans, assets, findings)
    core/                    # config, security, db session
    models/                  # SQLAlchemy ORM + Pydantic schemas
    pipeline/
      coordinator.py         # DAG executor
      stage.py               # Stage protocol
      profiles.py            # quick/standard/deep DAG definitions
      adapters/              # one file per tool
        subfinder.py
        assetfinder.py
        dnsx.py
        httpx.py              # extended in M1.5: -cdn -cname -server -follow-redirects -ip
        wafw00f.py            # M1.5
        asnmap.py             # M1.5
        geoip.py              # M1.5 — IP2Location LITE local lookup
        naabu.py              # M2
        nmap.py               # M2
        gowitness.py          # M2
        ...
    workers/
      runner.py              # Arq worker entrypoint
      sandbox.py             # subprocess isolation
    agents/
      council.py             # Mode A orchestrator (design-time)
      risk_prioritizer.py    # Mode B — top-N risk concentration
      attack_path.py         # Mode B — cross-asset exploit chain hypotheses
      bounded_completion.py  # token-capped wrapper + ai_usage ledger
    services/
      assets.py              # asset upsert + dedup logic
      # diff.py deferred — was M3, see "Defer indefinitely"
  migrations/                # Alembic
  tests/
    unit/
    integration/             # spin up real Postgres + Redis via testcontainers
frontend/
  app/
    (auth)/
    dashboard/
    scans/[id]/
      page.tsx               # tabbed shell (Overview / Subdomains / IPs / CDN-WAF / Tech / Risks)
      tabs/
        OverviewTab.tsx
        SubdomainsTab.tsx    # the headline table from the mockup
        IpSummaryTab.tsx
        CdnWafTab.tsx
        TechnologiesTab.tsx
        RisksTab.tsx          # M3 — prioritized full ranking
        # HistoryTab.tsx deferred (was M3) — see "Defer indefinitely"
    targets/
    reports/
    settings/
    assets/
  components/
    AppShell.tsx             # sidebar + topbar layout
    Sidebar.tsx
    TopBar.tsx               # breadcrumb, theme toggle, notifications, avatar
    ThemeProvider.tsx        # next-themes wrapper
    DAGViewer.tsx            # used in OverviewTab stage timeline
    SubdomainsTable.tsx      # virtualized TanStack Table v8
    StatusBadge.tsx
    IpTagChip.tsx
    WafConfBadge.tsx
    PrioritizedRisksList.tsx # M3 — full ranked list, severity-bucketed
    # DiffModal.tsx deferred (was M3) — see "Defer indefinitely"
    charts/
      StatusDistribution.tsx
      TopTechBar.tsx
      TopAsnBar.tsx
  lib/
    api.ts                   # existing — add subdomains/overview/ips/cdn-waf/technologies endpoints
infra/
  docker-compose.yml         # postgres, redis, minio, opensearch, app, worker
  Dockerfile.app
  Dockerfile.worker          # includes recon tools (subfinder, httpx, naabu, etc.)
docs/
  adrs/                      # architecture decision records (council outputs)
  agents/                    # agent charter files
```

---

## 10. Verification Strategy

Per milestone, verify with:

1. **Unit tests** on stage adapters using golden output fixtures (capture real tool output once, replay in tests).
2. **Integration test**: docker-compose up, hit `/scans` POST with a known test domain (`example.com`, `scanme.nmap.org`), assert assets land in DB and SSE stream emits expected events.
3. **Load test** at M4: 100 concurrent scans of standard profile against a fixture domain, p95 stage latency must stay within budget.
4. **Sandbox escape test**: malicious tool output (e.g., a subdomain like `; rm -rf /`) must not break the parser or escape the worker.
5. **UI smoke**: Playwright run that submits a scan, watches progress to 100%, asserts the Subdomains table and the Prioritized Risks card both render.
6. **Risk-prio coverage test (M3)**: for a fixture scan that produces N assets, assert `prioritized_assets` length == N, every `priority_rank` is unique and contiguous (1..N), HIGH-severity items precede MED/LOW/INFO, and no asset is silently dropped from the ranking.
7. **Council dogfooding**: run Mode A council against this very plan, capture dissent, refine. (Meta-verification: if your own agents can't critique your design, they won't help users either.)

---

## 11. Locked Decisions

These shape every milestone below; revisit only with explicit cause.

1. **SaaS-first, multi-tenant cloud.** Org/Project/Target hierarchy is mandatory from M0. Auth, per-tenant rate limits, signed URLs for screenshots, row-level scoping on every query — all baked in, not retrofitted.
2. **Hard authorization gate on active scanning.** Before any naabu / nmap / katana-crawl / CloudFlair stage runs, the Target must have a verified `authorization_proof` (one of: DNS TXT record `recon-auth=<token>`, `/.well-known/recon-auth.txt` file, or — for owned domains — registrar-verified ownership). Verifier runs as a separate stage with its own retry. Quick + standard *passive* profiles run without it; anything that touches the target's infra requires it. Coordinator refuses to schedule a gated stage if the proof is missing or expired (>30 days).
3. **Solo, no hard deadline — sequencing is for learning depth, not speed.** Treat each milestone as a chance to deeply understand one subsystem. Order is unchanged but explicitly *unhurried* — M2's sandbox work in particular is worth doing right rather than fast. Cloud cost stays near zero by running everything in Docker Compose locally until M4.
4. **AI Risk Prioritization runs free on every scan, with a hard per-scan token cap.** Risk Prioritization Agent gets a budget of ~10K input + 2K output tokens (Sonnet); Attack-Path Reasoner (deep scans only) gets ~20K + 3K (Opus). Implement both as `bounded_completion(model, prompt, max_input_tokens, max_output_tokens)` — over-budget triggers a "summarize the asset set first, then prioritize" pass instead of a retry. Track per-org spend in an `ai_usage` table; surface as a bar in the dashboard so cost stays visible. If cost ever becomes a real problem, this table makes the paid-tier migration trivial.

### Implications baked into the milestones
- **M0** now includes Org/Project schema and a tenant-scoped session middleware, not just User auth.
- **M2** now includes the `authorization_proof` verifier stage and the gating check in the DAG coordinator.
- **M3** (renumbered from old M4 after the diff milestone was removed) now includes the `ai_usage` ledger and the bounded-completion wrapper, plus the full-coverage ranking contract for the Risk Prioritization Agent.
- **M5's billing hooks** (renumbered from old M6) are demoted — no billing needed while solo, but the multi-tenant data model means it's a one-week add whenever you want it.
