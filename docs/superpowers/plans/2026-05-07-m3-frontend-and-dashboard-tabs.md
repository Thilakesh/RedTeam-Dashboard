# M3 Frontend — RisksTab, Dashboard Risks Card, and Dashboard Scan Tabs

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Surface AI risk findings in the UI via a Risks tab in Scan Detail, a Prioritized Risks card on the Dashboard, and replace the Dashboard's stacked Running/Completed cards with a clean tabbed interface.

**Architecture:** Five self-contained changes: (1) add `FindingRow`/`FindingsPage` API types, (2) new `RisksTab` component fetching `GET /scans/{id}/findings`, (3) patch the scan detail page to add the Risks tab and read an optional `?tab=` URL param so the Dashboard's "View all →" link deep-links directly to the Risks tab, (4) replace the Dashboard's two stacked cards with a single Tabs component (Running | Completed), (5) add a Prioritized Risks card that fetches HIGH-severity findings from the most recent completed deep scan. No backend changes required — all endpoints are already live and verified.

**Tech Stack:** Next.js 14 App Router, TypeScript strict, TanStack Query v5, shadcn/ui (Tabs, Card, Select, Button, Badge), lucide-react, Tailwind CSS

---

## File Map

| Action | Path | What changes |
|--------|------|-------------|
| Modify | `frontend/lib/api.ts` | Add `FindingRow` and `FindingsPage` types |
| Create | `frontend/components/tabs/RisksTab.tsx` | New tab: paginated findings table + severity filter |
| Modify | `frontend/app/scans/[id]/page.tsx` | Add Risks tab, wrap in Suspense for `useSearchParams`, read `?tab=` param |
| Modify | `frontend/app/dashboard/page.tsx` | Replace Running/Completed cards with Tabs, add Prioritized Risks card |

---

## Context for implementer

### Backend API (already live, no changes needed)

`GET /scans/{scan_id}/findings`
- Query params: `severity=HIGH|MED|LOW|INFO` (optional), `page=1` (1-based), `limit=50` (1–200)
- Returns `{"total": 0, "items": []}` — never 404
- Items ordered by `priority_rank ASC`

Each `FindingRow` from the API has:
```json
{
  "finding_id": "uuid",
  "asset_id": "uuid",
  "fqdn": "api.example.com",
  "severity": "HIGH",
  "priority_rank": 1,
  "risk_score": 0.92,
  "rationale": "Admin interface exposed...",
  "signals": ["exposed_admin_panel"],
  "recommended_action": "Restrict to VPN.",
  "source": "risk_prioritizer"
}
```

### Severity badge colours
- HIGH → red (`bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400`)
- MED  → amber (`bg-amber-100 text-amber-800 dark:bg-amber-900/30 dark:text-amber-400`)
- LOW  → blue (`bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-400`)
- INFO → muted (`bg-muted text-muted-foreground`)

### Key existing types in `frontend/lib/api.ts`
```typescript
export type Scan = {
  id: string; domain: string; profile: string;
  status: "created" | "running" | "completed" | "failed";
  progress_pct: number; created_at: string;
  started_at: string | null; finished_at: string | null; error: string | null;
};
```

### Existing tab structure in scan detail page
The scan detail page (`frontend/app/scans/[id]/page.tsx`) already has tabs for: overview, subdomains, ips, cdnwaf, tech, ports, history. The new **risks** tab is added here. `defaultValue` currently hardcoded to `"subdomains"` — Task 3 changes it to read from `?tab=` URL param.

### `useSearchParams` needs Suspense (Next.js 14 rule)
Any client component using `useSearchParams()` must be wrapped in `<Suspense>`. Task 3 splits the scan detail page into an inner component (`ScanDetailContent`) that uses `useSearchParams`, wrapped by the exported page component in `<Suspense>`. This is the only structural change to the scan detail page.

### Where to run type checks
```bash
cd infra
docker compose exec frontend npx tsc --noEmit
```
Run this after each task to catch type errors before visually verifying in the browser.

---

## Task 1: Add FindingRow and FindingsPage types to api.ts

**Files:**
- Modify: `frontend/lib/api.ts` (append after `PortsPage` type, around line 182)

- [ ] **Step 1: Open `frontend/lib/api.ts` and append the two types at the end of the file**

Add after the `PortsPage` block (which ends around line 182):

```typescript
export type FindingRow = {
  finding_id: string;
  asset_id: string;
  fqdn: string;
  severity: "HIGH" | "MED" | "LOW" | "INFO";
  priority_rank: number;
  risk_score: number;
  rationale: string;
  signals: string[];
  recommended_action: string;
  source: string;
};

export type FindingsPage = {
  total: number;
  items: FindingRow[];
};
```

- [ ] **Step 2: Run type check to confirm no errors**

```bash
cd infra
docker compose exec frontend npx tsc --noEmit 2>&1 | head -30
```

Expected: no output (zero errors). If there are errors they will be printed; fix before continuing.

- [ ] **Step 3: Commit**

```bash
cd "F:/Studies/AI/RedTeam Dashboard"
git add frontend/lib/api.ts
git commit -m "feat(frontend): add FindingRow and FindingsPage API types"
```

---

## Task 2: Create RisksTab component

**Files:**
- Create: `frontend/components/tabs/RisksTab.tsx`

- [ ] **Step 1: Create the file with full contents**

Write the complete file to `frontend/components/tabs/RisksTab.tsx`:

```tsx
"use client";

import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { ChevronLeft, ChevronRight, ShieldAlert } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { api, type FindingsPage } from "@/lib/api";

const SEVERITY_COLORS: Record<string, string> = {
  HIGH: "bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400",
  MED: "bg-amber-100 text-amber-800 dark:bg-amber-900/30 dark:text-amber-400",
  LOW: "bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-400",
  INFO: "bg-muted text-muted-foreground",
};

interface RisksTabProps {
  scanId: string;
  scanProfile: string;
}

export function RisksTab({ scanId, scanProfile }: RisksTabProps) {
  const [severity, setSeverity] = useState<string>("ALL");
  const [page, setPage] = useState(1);
  const limit = 25;

  const query = useQuery({
    queryKey: ["scan-findings", scanId, severity, page],
    queryFn: () => {
      const params = new URLSearchParams();
      if (severity !== "ALL") params.set("severity", severity);
      params.set("page", String(page));
      params.set("limit", String(limit));
      return api<FindingsPage>(`/scans/${scanId}/findings?${params.toString()}`);
    },
    enabled: scanProfile === "deep",
  });

  if (scanProfile !== "deep") {
    return (
      <div className="flex flex-col items-center gap-3 py-12 text-center text-muted-foreground">
        <ShieldAlert className="h-8 w-8 opacity-40" />
        <p className="text-sm">Risk analysis is only available for deep scans.</p>
        <p className="text-xs max-w-sm">
          Run a <strong>deep</strong> scan on a verified target to generate AI-prioritised findings.
        </p>
      </div>
    );
  }

  if (query.isLoading) {
    return <p className="text-sm text-muted-foreground py-6">Loading findings…</p>;
  }

  const { total = 0, items = [] } = query.data ?? {};
  const totalPages = Math.max(1, Math.ceil(total / limit));

  return (
    <div className="space-y-4">
      {/* Filter bar */}
      <div className="flex items-center gap-3">
        <span className="text-sm text-muted-foreground">Severity:</span>
        <Select
          value={severity}
          onValueChange={(v) => {
            setSeverity(v);
            setPage(1);
          }}
        >
          <SelectTrigger className="w-32">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="ALL">All</SelectItem>
            <SelectItem value="HIGH">HIGH</SelectItem>
            <SelectItem value="MED">MED</SelectItem>
            <SelectItem value="LOW">LOW</SelectItem>
            <SelectItem value="INFO">INFO</SelectItem>
          </SelectContent>
        </Select>
        <span className="text-xs text-muted-foreground ml-auto">
          {total} finding{total !== 1 ? "s" : ""}
        </span>
      </div>

      {items.length === 0 ? (
        <div className="flex flex-col items-center gap-3 py-12 text-center text-muted-foreground">
          <ShieldAlert className="h-8 w-8 opacity-40" />
          <p className="text-sm">No risk findings yet.</p>
          <p className="text-xs max-w-sm">
            Findings are generated by the AI risk prioritiser at the end of a deep scan.
            They appear here once the scan is complete.
          </p>
        </div>
      ) : (
        <>
          <div className="overflow-auto rounded-md border border-border">
            <table className="w-full text-sm border-collapse">
              <thead className="bg-muted/50 sticky top-0 z-10">
                <tr>
                  {["#", "FQDN", "Severity", "Risk Score", "Rationale", "Recommended Action"].map(
                    (h) => (
                      <th
                        key={h}
                        className="px-3 py-2 text-left font-medium text-muted-foreground whitespace-nowrap border-b border-border"
                      >
                        {h}
                      </th>
                    ),
                  )}
                </tr>
              </thead>
              <tbody>
                {items.map((row) => (
                  <tr
                    key={row.finding_id}
                    className="border-b border-border hover:bg-muted/30 transition-colors"
                  >
                    <td className="px-3 py-2 text-xs text-muted-foreground tabular-nums w-8">
                      {row.priority_rank}
                    </td>
                    <td className="px-3 py-2 font-mono text-xs font-medium">{row.fqdn}</td>
                    <td className="px-3 py-2">
                      <span
                        className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ${
                          SEVERITY_COLORS[row.severity] ?? SEVERITY_COLORS.INFO
                        }`}
                      >
                        {row.severity}
                      </span>
                    </td>
                    <td className="px-3 py-2 text-xs tabular-nums">{row.risk_score.toFixed(2)}</td>
                    <td className="px-3 py-2 text-xs max-w-xs text-muted-foreground">
                      {row.rationale}
                    </td>
                    <td className="px-3 py-2 text-xs max-w-xs">{row.recommended_action}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* Pagination */}
          <div className="flex items-center justify-between text-xs text-muted-foreground">
            <span>
              Page {page} of {totalPages}
            </span>
            <div className="flex items-center gap-1">
              <Button
                variant="outline"
                size="sm"
                onClick={() => setPage((p) => p - 1)}
                disabled={page <= 1}
              >
                <ChevronLeft className="h-3.5 w-3.5" />
                Prev
              </Button>
              <Button
                variant="outline"
                size="sm"
                onClick={() => setPage((p) => p + 1)}
                disabled={page >= totalPages}
              >
                Next
                <ChevronRight className="h-3.5 w-3.5" />
              </Button>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
```

- [ ] **Step 2: Run type check**

```bash
cd infra
docker compose exec frontend npx tsc --noEmit 2>&1 | head -30
```

Expected: no output. Fix any errors before continuing.

- [ ] **Step 3: Commit**

```bash
cd "F:/Studies/AI/RedTeam Dashboard"
git add frontend/components/tabs/RisksTab.tsx
git commit -m "feat(frontend): add RisksTab component with severity filter and pagination"
```

---

## Task 3: Add Risks tab + URL-driven tab selection to scan detail page

**Files:**
- Modify: `frontend/app/scans/[id]/page.tsx` (full replacement)

The changes are:
1. Import `Suspense` from `react` and `useSearchParams` from `next/navigation`
2. Import `RisksTab` from `@/components/tabs/RisksTab`
3. Rename the existing default export function to `ScanDetailContent` and add `useSearchParams` inside it
4. Change `<Tabs defaultValue="subdomains">` to `<Tabs defaultValue={defaultTab}>`
5. Add `<TabsTrigger value="risks">Risks</TabsTrigger>` and its `<TabsContent>` with `<RisksTab>`
6. Add a new thin `ScanDetailPage` default export that wraps `ScanDetailContent` in `<Suspense>`

- [ ] **Step 1: Replace the full contents of `frontend/app/scans/[id]/page.tsx`**

```tsx
"use client";

import { Suspense, useEffect } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useSearchParams } from "next/navigation";
import { Calendar, Clock, Download, Globe, Share2 } from "lucide-react";
import { AppShell } from "@/components/AppShell";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { OverviewTab } from "@/components/tabs/OverviewTab";
import { IpSummaryTab } from "@/components/tabs/IpSummaryTab";
import { CdnWafTab } from "@/components/tabs/CdnWafTab";
import { TechnologiesTab } from "@/components/tabs/TechnologiesTab";
import { PortsTab } from "@/components/tabs/PortsTab";
import { RisksTab } from "@/components/tabs/RisksTab";
import { SubdomainsTable } from "@/components/SubdomainsTable";
import { api, sseUrl, type ScanDetail, type ScanOverview } from "@/lib/api";

const SSE_EVENTS = [
  "stage.started",
  "stage.completed",
  "stage.failed",
  "scan.completed",
  "scan.failed",
];

const STATUS_VARIANT: Record<string, "success" | "warning" | "destructive" | "default"> = {
  completed: "success",
  running: "warning",
  failed: "destructive",
  created: "default",
};

// Inner component — uses useSearchParams, must be wrapped in Suspense by the page
function ScanDetailContent({ params }: { params: { id: string } }) {
  const qc = useQueryClient();
  const searchParams = useSearchParams();
  const defaultTab = searchParams.get("tab") ?? "subdomains";

  const scan = useQuery({
    queryKey: ["scan", params.id],
    queryFn: () => api<ScanDetail>(`/scans/${params.id}`),
  });

  const overview = useQuery({
    queryKey: ["scan-overview-light", params.id],
    queryFn: () => api<ScanOverview>(`/scans/${params.id}/overview`),
    enabled: !!scan.data,
  });

  useEffect(() => {
    const status = scan.data?.status;
    if (!status || status === "completed" || status === "failed") return;

    const es = new EventSource(sseUrl(`/scans/${params.id}/stream`));
    const refetch = () => {
      qc.invalidateQueries({ queryKey: ["scan", params.id] });
      qc.invalidateQueries({ queryKey: ["scan-subdomains", params.id] });
      qc.invalidateQueries({ queryKey: ["scan-overview", params.id] });
      qc.invalidateQueries({ queryKey: ["scan-overview-light", params.id] });
      qc.invalidateQueries({ queryKey: ["scan-ips", params.id] });
      qc.invalidateQueries({ queryKey: ["scan-cdn-waf", params.id] });
      qc.invalidateQueries({ queryKey: ["scan-tech", params.id] });
      qc.invalidateQueries({ queryKey: ["scan-ports", params.id] });
    };
    SSE_EVENTS.forEach((ev) => es.addEventListener(ev, refetch));
    es.onerror = () => {
      if (es.readyState === EventSource.CLOSED) es.close();
    };
    return () => es.close();
  }, [scan.data?.status, params.id, qc]);

  if (scan.isLoading || !scan.data) {
    return (
      <AppShell>
        <p className="text-sm text-muted-foreground">Loading scan…</p>
      </AppShell>
    );
  }

  const s = scan.data;
  const started = s.started_at ? new Date(s.started_at) : null;
  const finished = s.finished_at ? new Date(s.finished_at) : null;
  const durationMs = started && finished ? finished.getTime() - started.getTime() : null;
  const subCount = overview.data?.subdomain_count ?? 0;

  return (
    <AppShell>
      {/* Header */}
      <div className="mb-6 flex flex-wrap items-start justify-between gap-4">
        <div>
          <div className="text-xs text-muted-foreground mb-1">Scan Results</div>
          <div className="flex items-center gap-3">
            <Globe className="h-5 w-5 text-primary" />
            <h1 className="text-2xl font-semibold tracking-tight">{s.domain}</h1>
            <Badge variant={STATUS_VARIANT[s.status] ?? "default"}>{s.status}</Badge>
          </div>
          <div className="mt-2 flex flex-wrap items-center gap-x-5 gap-y-1 text-xs text-muted-foreground">
            {started && (
              <span className="inline-flex items-center gap-1.5">
                <Calendar className="h-3.5 w-3.5" /> {started.toLocaleString()}
              </span>
            )}
            {durationMs != null && (
              <span className="inline-flex items-center gap-1.5">
                <Clock className="h-3.5 w-3.5" /> Duration: {formatDuration(durationMs)}
              </span>
            )}
            <span>
              Profile: <span className="text-foreground font-medium">{s.profile}</span>
            </span>
            <span>
              Total Subdomains:{" "}
              <span className="text-foreground font-medium">{subCount}</span>
            </span>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" size="sm">
            <Download className="h-4 w-4" /> Export
          </Button>
          <Button size="sm">
            <Share2 className="h-4 w-4" /> Share Report
          </Button>
        </div>
      </div>

      {/* Progress bar (only while running) */}
      {s.status !== "completed" && (
        <div className="mb-6">
          <div className="flex justify-between text-xs mb-1.5 text-muted-foreground">
            <span>Progress</span>
            <span>{s.progress_pct}%</span>
          </div>
          <div className="h-2 bg-muted rounded overflow-hidden">
            <div
              className="h-full bg-primary transition-all"
              style={{ width: `${s.progress_pct}%` }}
            />
          </div>
          {s.error && (
            <p className="mt-2 text-xs text-destructive break-words">Error: {s.error}</p>
          )}
        </div>
      )}

      {/* Tabs */}
      <Tabs defaultValue={defaultTab}>
        <TabsList>
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="subdomains">Subdomains</TabsTrigger>
          <TabsTrigger value="ips">IP Summary</TabsTrigger>
          <TabsTrigger value="cdnwaf">CDN / WAF</TabsTrigger>
          <TabsTrigger value="tech">Technologies</TabsTrigger>
          <TabsTrigger value="ports">Ports</TabsTrigger>
          <TabsTrigger value="risks">Risks</TabsTrigger>
          <TabsTrigger value="history">History</TabsTrigger>
        </TabsList>

        <TabsContent value="overview">
          <OverviewTab scanId={params.id} scan={s} />
        </TabsContent>
        <TabsContent value="subdomains">
          <SubdomainsTable scanId={params.id} />
        </TabsContent>
        <TabsContent value="ips">
          <IpSummaryTab scanId={params.id} />
        </TabsContent>
        <TabsContent value="cdnwaf">
          <CdnWafTab scanId={params.id} />
        </TabsContent>
        <TabsContent value="tech">
          <TechnologiesTab scanId={params.id} />
        </TabsContent>
        <TabsContent value="ports">
          <PortsTab scanId={params.id} />
        </TabsContent>
        <TabsContent value="risks">
          <RisksTab scanId={params.id} scanProfile={s.profile} />
        </TabsContent>
        <TabsContent value="history">
          <p className="text-sm text-muted-foreground">
            Historical scan diffing arrives in a future milestone — re-running this target will
            populate added/removed/changed cards here.
          </p>
        </TabsContent>
      </Tabs>
    </AppShell>
  );
}

function formatDuration(ms: number): string {
  const totalSec = Math.round(ms / 1000);
  const m = Math.floor(totalSec / 60);
  const s = totalSec % 60;
  return `${String(m).padStart(2, "0")}:${String(s).padStart(2, "0")}`;
}

// Page export — wraps the inner component in Suspense (required by Next.js for useSearchParams)
export default function ScanDetailPage({ params }: { params: { id: string } }) {
  return (
    <Suspense
      fallback={
        <AppShell>
          <p className="text-sm text-muted-foreground">Loading scan…</p>
        </AppShell>
      }
    >
      <ScanDetailContent params={params} />
    </Suspense>
  );
}
```

- [ ] **Step 2: Run type check**

```bash
cd infra
docker compose exec frontend npx tsc --noEmit 2>&1 | head -30
```

Expected: no output. Fix any errors before continuing.

- [ ] **Step 3: Verify in browser**

Navigate to `http://localhost:3000/scans/<any-scan-id>`.

Checklist:
- [ ] "Risks" tab appears in the tab bar between "Ports" and "History"
- [ ] Clicking "Risks" on a non-deep scan shows the "only available for deep scans" empty state
- [ ] Clicking "Risks" on a completed deep scan shows the findings table (or "No risk findings yet" if none)
- [ ] Navigate to `http://localhost:3000/scans/<deep-scan-id>?tab=risks` — the Risks tab opens directly (no flash of Subdomains tab first)

- [ ] **Step 4: Commit**

```bash
cd "F:/Studies/AI/RedTeam Dashboard"
git add "frontend/app/scans/[id]/page.tsx"
git commit -m "feat(frontend): add Risks tab to scan detail + URL-driven tab selection"
```

---

## Task 4: Refactor Dashboard scan list to tabbed interface

**Files:**
- Modify: `frontend/app/dashboard/page.tsx`

Replace the two separate `<Card>` components (Running + Completed) with a single `<Tabs>` component containing two `<TabsContent>` panels. The default tab is "running" when any scans are running, otherwise "completed".

Note: This task only changes the scan list section. The Prioritized Risks card is added in Task 5 (on top of these changes). Tasks 4 and 5 both modify `dashboard/page.tsx` — complete Task 4 fully before starting Task 5.

- [ ] **Step 1: Replace the full contents of `frontend/app/dashboard/page.tsx` with the version below (Tasks 4 only — no Risks card yet)**

```tsx
"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { Activity, CheckCircle2, Plus } from "lucide-react";
import { AppShell } from "@/components/AppShell";
import { ScanRow } from "@/components/ScanRow";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ApiError, api, type Scan } from "@/lib/api";

export default function DashboardPage() {
  const qc = useQueryClient();
  const router = useRouter();
  const [domain, setDomain] = useState("");
  const [profile, setProfile] = useState("standard");
  const [err, setErr] = useState<string | null>(null);

  const scans = useQuery({
    queryKey: ["scans"],
    queryFn: () => api<Scan[]>("/scans"),
    refetchInterval: (q) => {
      const data = q.state.data as Scan[] | undefined;
      return data?.some((s) => s.status === "running" || s.status === "created") ? 3000 : false;
    },
  });

  const create = useMutation({
    mutationFn: (body: { domain: string; profile: string }) =>
      api<Scan>("/scans", { method: "POST", body: JSON.stringify(body) }),
    onSuccess: (scan) => {
      qc.invalidateQueries({ queryKey: ["scans"] });
      setDomain("");
      router.push(`/scans/${scan.id}`);
    },
    onError: (e) => setErr(e instanceof ApiError ? e.message : "Failed to create scan"),
  });

  const running = scans.data?.filter((s) => s.status === "running" || s.status === "created") ?? [];
  const completed = scans.data?.filter((s) => s.status === "completed" || s.status === "failed") ?? [];

  // Auto-select "running" tab when scans are active; fall back to "completed"
  const defaultScanTab = running.length > 0 ? "running" : "completed";

  return (
    <AppShell>
      <div className="mb-6">
        <h1 className="text-2xl font-semibold tracking-tight">Dashboard</h1>
        <p className="text-sm text-muted-foreground mt-1">
          Run a recon scan or jump back into one already running.
        </p>
      </div>

      {/* New Scan */}
      <Card className="mb-8">
        <CardHeader className="flex flex-row items-center gap-2">
          <Plus className="h-4 w-4 text-primary" />
          <CardTitle>New scan</CardTitle>
        </CardHeader>
        <CardContent>
          <form
            onSubmit={(e) => {
              e.preventDefault();
              setErr(null);
              create.mutate({ domain, profile });
            }}
            className="flex flex-wrap gap-2"
          >
            <Input
              required
              placeholder="example.com"
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
              className="flex-1 min-w-[16rem]"
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
            <Button type="submit" disabled={create.isPending}>
              {create.isPending ? "Starting…" : "Start scan"}
            </Button>
          </form>
          {err && <p className="text-sm text-destructive mt-2">{err}</p>}
        </CardContent>
      </Card>

      {/* Scans list — tabbed Running | Completed */}
      <Tabs defaultValue={defaultScanTab}>
        <TabsList>
          <TabsTrigger value="running" className="gap-1.5">
            <Activity className="h-3.5 w-3.5 text-warning" />
            Running
            {running.length > 0 && (
              <span className="rounded-full bg-warning/20 text-warning px-1.5 text-xs font-medium">
                {running.length}
              </span>
            )}
          </TabsTrigger>
          <TabsTrigger value="completed" className="gap-1.5">
            <CheckCircle2 className="h-3.5 w-3.5 text-success" />
            Completed
            {completed.length > 0 && (
              <span className="rounded-full bg-muted text-muted-foreground px-1.5 text-xs font-medium">
                {completed.length}
              </span>
            )}
          </TabsTrigger>
        </TabsList>

        <TabsContent value="running" className="mt-4">
          {running.length === 0 ? (
            <div className="flex items-center gap-2 rounded-md border border-border bg-card p-4 text-sm text-muted-foreground">
              <Activity className="h-4 w-4 shrink-0" />
              No scans currently running.
            </div>
          ) : (
            <div className="space-y-2">
              {running.map((s) => (
                <ScanRow key={s.id} scan={s} />
              ))}
            </div>
          )}
        </TabsContent>

        <TabsContent value="completed" className="mt-4">
          {completed.length === 0 ? (
            <div className="flex items-center gap-2 rounded-md border border-border bg-card p-4 text-sm text-muted-foreground">
              <CheckCircle2 className="h-4 w-4 shrink-0" />
              Nothing here yet — start a scan above.
            </div>
          ) : (
            <div className="space-y-2">
              {completed.map((s) => (
                <ScanRow key={s.id} scan={s} />
              ))}
            </div>
          )}
        </TabsContent>
      </Tabs>
    </AppShell>
  );
}
```

- [ ] **Step 2: Run type check**

```bash
cd infra
docker compose exec frontend npx tsc --noEmit 2>&1 | head -30
```

Expected: no output.

- [ ] **Step 3: Verify in browser**

Navigate to `http://localhost:3000/dashboard`.

Checklist:
- [ ] The two separate Running / Completed cards are gone
- [ ] A tab bar with "Running" and "Completed" tabs appears below the New scan card
- [ ] When running scans exist, "Running" tab is active by default with a count badge
- [ ] When no running scans exist, "Completed" tab is active by default
- [ ] Completed tab shows all completed/failed scans, each clickable (links to `/scans/{id}`)
- [ ] Count badges disappear when a section is empty

- [ ] **Step 4: Commit**

```bash
cd "F:/Studies/AI/RedTeam Dashboard"
git add frontend/app/dashboard/page.tsx
git commit -m "feat(frontend): replace dashboard scan cards with tabbed Running/Completed interface"
```

---

## Task 5: Add Prioritized Risks card to Dashboard

**Files:**
- Modify: `frontend/app/dashboard/page.tsx` (extend from Task 4)

This adds the Prioritized Risks card between the New Scan card and the Scans tabs. It fetches HIGH-severity findings from the most recent completed deep scan.

- [ ] **Step 1: Replace the full contents of `frontend/app/dashboard/page.tsx` with the final version**

This is the complete file including both the Task 4 tabs and the new Risks card:

```tsx
"use client";

import Link from "next/link";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { Activity, CheckCircle2, Plus, ShieldAlert } from "lucide-react";
import { AppShell } from "@/components/AppShell";
import { ScanRow } from "@/components/ScanRow";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ApiError, api, type FindingsPage, type Scan } from "@/lib/api";

export default function DashboardPage() {
  const qc = useQueryClient();
  const router = useRouter();
  const [domain, setDomain] = useState("");
  const [profile, setProfile] = useState("standard");
  const [err, setErr] = useState<string | null>(null);

  const scans = useQuery({
    queryKey: ["scans"],
    queryFn: () => api<Scan[]>("/scans"),
    refetchInterval: (q) => {
      const data = q.state.data as Scan[] | undefined;
      return data?.some((s) => s.status === "running" || s.status === "created") ? 3000 : false;
    },
  });

  const create = useMutation({
    mutationFn: (body: { domain: string; profile: string }) =>
      api<Scan>("/scans", { method: "POST", body: JSON.stringify(body) }),
    onSuccess: (scan) => {
      qc.invalidateQueries({ queryKey: ["scans"] });
      setDomain("");
      router.push(`/scans/${scan.id}`);
    },
    onError: (e) => setErr(e instanceof ApiError ? e.message : "Failed to create scan"),
  });

  const running = scans.data?.filter((s) => s.status === "running" || s.status === "created") ?? [];
  const completed = scans.data?.filter((s) => s.status === "completed" || s.status === "failed") ?? [];

  // Most recent completed deep scan — the API returns newest-first, so .find() gets the latest
  const latestDeepScan = scans.data?.find(
    (s) => s.profile === "deep" && s.status === "completed",
  );

  // Fetch top-5 HIGH findings for the latest deep scan
  const risksQuery = useQuery({
    queryKey: ["dashboard-risks", latestDeepScan?.id],
    queryFn: () =>
      api<FindingsPage>(
        `/scans/${latestDeepScan!.id}/findings?severity=HIGH&limit=5`,
      ),
    enabled: !!latestDeepScan,
  });

  const defaultScanTab = running.length > 0 ? "running" : "completed";

  return (
    <AppShell>
      <div className="mb-6">
        <h1 className="text-2xl font-semibold tracking-tight">Dashboard</h1>
        <p className="text-sm text-muted-foreground mt-1">
          Run a recon scan or jump back into one already running.
        </p>
      </div>

      {/* ── New Scan ── */}
      <Card className="mb-8">
        <CardHeader className="flex flex-row items-center gap-2">
          <Plus className="h-4 w-4 text-primary" />
          <CardTitle>New scan</CardTitle>
        </CardHeader>
        <CardContent>
          <form
            onSubmit={(e) => {
              e.preventDefault();
              setErr(null);
              create.mutate({ domain, profile });
            }}
            className="flex flex-wrap gap-2"
          >
            <Input
              required
              placeholder="example.com"
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
              className="flex-1 min-w-[16rem]"
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
            <Button type="submit" disabled={create.isPending}>
              {create.isPending ? "Starting…" : "Start scan"}
            </Button>
          </form>
          {err && <p className="text-sm text-destructive mt-2">{err}</p>}
        </CardContent>
      </Card>

      {/* ── Prioritized Risks — only when a completed deep scan exists ── */}
      {latestDeepScan && (
        <Card className="mb-8">
          <CardHeader className="flex flex-row items-center justify-between">
            <div className="flex items-center gap-2">
              <ShieldAlert className="h-4 w-4 text-destructive" />
              <CardTitle>Prioritized Risks</CardTitle>
              <span className="text-xs text-muted-foreground">— {latestDeepScan.domain}</span>
            </div>
            <Link
              href={`/scans/${latestDeepScan.id}?tab=risks`}
              className="text-xs text-primary hover:underline"
            >
              View all →
            </Link>
          </CardHeader>
          <CardContent>
            {risksQuery.isLoading ? (
              <p className="text-sm text-muted-foreground">Loading risks…</p>
            ) : !risksQuery.data?.items.length ? (
              <p className="text-sm text-muted-foreground">
                No HIGH severity findings for this scan.
              </p>
            ) : (
              <div className="space-y-2">
                {risksQuery.data.items.map((finding) => (
                  <div
                    key={finding.finding_id}
                    className="flex items-start gap-3 rounded-md border border-border bg-card/50 px-3 py-2"
                  >
                    <span className="w-6 shrink-0 text-xs font-semibold tabular-nums text-muted-foreground">
                      #{finding.priority_rank}
                    </span>
                    <div className="min-w-0">
                      <div className="truncate font-mono text-xs font-medium">{finding.fqdn}</div>
                      <div className="mt-0.5 line-clamp-1 text-xs text-muted-foreground">
                        {finding.rationale}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {/* ── Scans list — tabbed Running | Completed ── */}
      <Tabs defaultValue={defaultScanTab}>
        <TabsList>
          <TabsTrigger value="running" className="gap-1.5">
            <Activity className="h-3.5 w-3.5 text-warning" />
            Running
            {running.length > 0 && (
              <span className="rounded-full bg-warning/20 px-1.5 text-xs font-medium text-warning">
                {running.length}
              </span>
            )}
          </TabsTrigger>
          <TabsTrigger value="completed" className="gap-1.5">
            <CheckCircle2 className="h-3.5 w-3.5 text-success" />
            Completed
            {completed.length > 0 && (
              <span className="rounded-full bg-muted px-1.5 text-xs font-medium text-muted-foreground">
                {completed.length}
              </span>
            )}
          </TabsTrigger>
        </TabsList>

        <TabsContent value="running" className="mt-4">
          {running.length === 0 ? (
            <div className="flex items-center gap-2 rounded-md border border-border bg-card p-4 text-sm text-muted-foreground">
              <Activity className="h-4 w-4 shrink-0" />
              No scans currently running.
            </div>
          ) : (
            <div className="space-y-2">
              {running.map((s) => (
                <ScanRow key={s.id} scan={s} />
              ))}
            </div>
          )}
        </TabsContent>

        <TabsContent value="completed" className="mt-4">
          {completed.length === 0 ? (
            <div className="flex items-center gap-2 rounded-md border border-border bg-card p-4 text-sm text-muted-foreground">
              <CheckCircle2 className="h-4 w-4 shrink-0" />
              Nothing here yet — start a scan above.
            </div>
          ) : (
            <div className="space-y-2">
              {completed.map((s) => (
                <ScanRow key={s.id} scan={s} />
              ))}
            </div>
          )}
        </TabsContent>
      </Tabs>
    </AppShell>
  );
}
```

- [ ] **Step 2: Run type check**

```bash
cd infra
docker compose exec frontend npx tsc --noEmit 2>&1 | head -30
```

Expected: no output.

- [ ] **Step 3: Verify in browser**

Navigate to `http://localhost:3000/dashboard`.

Checklist:
- [ ] Prioritized Risks card appears **only when at least one completed deep scan exists**; it does not appear when there are only quick/standard scans or no completed scans
- [ ] The card header shows the domain name of the most recent completed deep scan
- [ ] "View all →" link is present in the card header; clicking it navigates to `/scans/{id}?tab=risks` and the Risks tab opens directly
- [ ] Up to 5 HIGH-severity findings are listed; each shows `#rank`, FQDN (truncated), and a one-line rationale snippet
- [ ] If the deep scan has no HIGH findings, "No HIGH severity findings for this scan." is shown (not an error)
- [ ] The card is **not** shown when there are no completed deep scans (e.g., first-time user)

- [ ] **Step 4: Commit**

```bash
cd "F:/Studies/AI/RedTeam Dashboard"
git add frontend/app/dashboard/page.tsx
git commit -m "feat(frontend): add Prioritized Risks card to dashboard with deep-link to Risks tab"
```

---

## Self-Review

### Spec coverage

| Requirement | Task |
|-------------|------|
| RisksTab — fetch `GET /scans/{id}/findings?limit=50` (paginated) | Task 2 |
| RisksTab — empty state if `scan.profile !== "deep"` | Task 2 |
| RisksTab — empty state if `total === 0` | Task 2 |
| RisksTab — columns: priority_rank, fqdn, severity badge, risk_score, rationale, recommended_action | Task 2 |
| RisksTab — severity filter dropdown (ALL / HIGH / MED / LOW / INFO) | Task 2 |
| RisksTab — pagination | Task 2 |
| Add "Risks" tab to tab bar in scan detail page | Task 3 |
| "View all →" link deep-links to Risks tab via `?tab=risks` | Task 3 + Task 5 |
| Dashboard Prioritized Risks card — fetch HIGH findings from most recent deep scan | Task 5 |
| Dashboard Prioritized Risks card — show rank + fqdn + rationale snippet (up to 5) | Task 5 |
| Dashboard Prioritized Risks card — only shown when completed deep scan exists | Task 5 |
| Dashboard scan list — tabbed Running / Completed instead of stacked cards | Task 4 |
| Severity badge colours: HIGH=red, MED=amber, LOW=blue, INFO=grey | Task 2 |
| API types for FindingRow / FindingsPage | Task 1 |

### Placeholder scan

No "TBD", "TODO", or vague steps found. Every step shows complete code.

### Type consistency

- `FindingRow.finding_id` used as `key` in both RisksTab (Task 2) and Dashboard card (Task 5) ✓
- `RisksTab` props: `{ scanId: string, scanProfile: string }` — matches usage in Task 3 (`scanProfile={s.profile}`) ✓
- `FindingsPage` import added to dashboard in Task 5 ✓
- `useSearchParams` in `ScanDetailContent` (not `ScanDetailPage`) — correctly inside Suspense boundary ✓
- `api<FindingsPage>` with non-null assertion `latestDeepScan!.id` protected by `enabled: !!latestDeepScan` ✓
