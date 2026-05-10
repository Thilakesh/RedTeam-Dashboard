"use client";

import { Suspense, useEffect, useState } from "react";
import { useQuery, useQueryClient, useMutation } from "@tanstack/react-query";
import { useRouter, useSearchParams } from "next/navigation";
import { Globe, Calendar, Clock, ExternalLink } from "lucide-react";
import Link from "next/link";
import { AppShell } from "@/components/AppShell";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  api,
  sseUrl,
  type VulnDiff,
  type VulnScanDetail,
  type VulnOverview,
  type VulnOut,
  type VulnsPage,
} from "@/lib/api";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

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
  queued: "default",
};

const SEVERITY_COLOR: Record<string, string> = {
  CRITICAL: "text-red-600 bg-red-100 border-red-300",
  HIGH: "text-orange-500 bg-orange-100 border-orange-300",
  MED: "text-yellow-600 bg-yellow-100 border-yellow-300",
  LOW: "text-blue-500 bg-blue-100 border-blue-300",
  INFO: "text-gray-500 bg-gray-100 border-gray-300",
};

const VULN_STATUS_VARIANT: Record<string, "success" | "warning" | "destructive" | "default" | "info"> = {
  open: "info",
  triaged: "warning",
  false_positive: "default",
  fixed: "success",
  wont_fix: "default",
  reopened: "warning",
};

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

function formatDuration(ms: number): string {
  const totalSec = Math.round(ms / 1000);
  const m = Math.floor(totalSec / 60);
  const s = totalSec % 60;
  return `${String(m).padStart(2, "0")}:${String(s).padStart(2, "0")}`;
}

function SeverityBadge({ severity }: { severity: string }) {
  const cls = SEVERITY_COLOR[severity] ?? "text-gray-500 bg-gray-100 border-gray-300";
  return (
    <span
      className={`inline-flex items-center rounded-md border px-2 py-0.5 text-xs font-semibold ${cls}`}
    >
      {severity}
    </span>
  );
}

function CveBadges({ ids }: { ids: string[] }) {
  if (!ids.length) return <span className="text-muted-foreground text-xs">—</span>;
  const shown = ids.slice(0, 3);
  const extra = ids.length - shown.length;
  return (
    <span className="flex flex-wrap gap-1">
      {shown.map((id) => (
        <span
          key={id}
          className="inline-flex items-center rounded bg-muted px-1.5 py-0.5 text-xs font-mono text-muted-foreground"
        >
          {id}
        </span>
      ))}
      {extra > 0 && (
        <span className="text-xs text-muted-foreground">+{extra} more</span>
      )}
    </span>
  );
}

// ---------------------------------------------------------------------------
// Overview tab
// ---------------------------------------------------------------------------

function OverviewTab({
  scanId,
  scanStatus,
  progressPct,
}: {
  scanId: string;
  scanStatus: string;
  progressPct: number;
}) {
  const ov = useQuery({
    queryKey: ["vuln-overview", scanId],
    queryFn: () => api<VulnOverview>(`/vuln-scans/${scanId}/overview`),
    enabled: scanStatus !== "created" && scanStatus !== "queued",
  });

  if (scanStatus === "running" || scanStatus === "created" || scanStatus === "queued") {
    return (
      <div className="mt-4 space-y-3">
        <p className="text-sm text-muted-foreground">
          Scan is in progress — results will appear here once complete.
        </p>
        <div className="max-w-sm">
          <div className="flex justify-between text-xs mb-1.5 text-muted-foreground">
            <span>Progress</span>
            <span>{progressPct}%</span>
          </div>
          <div className="h-2 bg-muted rounded overflow-hidden">
            <div
              className="h-full bg-primary transition-all"
              style={{ width: `${progressPct}%` }}
            />
          </div>
        </div>
      </div>
    );
  }

  if (ov.isLoading) {
    return <p className="mt-4 text-sm text-muted-foreground">Loading overview…</p>;
  }

  if (ov.isError || !ov.data) {
    return (
      <p className="mt-4 text-sm text-destructive">Failed to load overview data.</p>
    );
  }

  const d = ov.data;

  if (d.total === 0 && scanStatus === "completed") {
    return (
      <div className="mt-6 rounded-lg border border-border p-8 text-center">
        <p className="text-sm font-medium text-success">No vulnerabilities found — great news!</p>
        <p className="text-xs text-muted-foreground mt-1">
          The scan completed with a clean bill of health.
        </p>
      </div>
    );
  }

  const severities = [
    { label: "CRITICAL", count: d.critical, color: "text-red-600", bg: "bg-red-50 border-red-200 dark:bg-red-950/30 dark:border-red-800" },
    { label: "HIGH",     count: d.high,     color: "text-orange-500", bg: "bg-orange-50 border-orange-200 dark:bg-orange-950/30 dark:border-orange-800" },
    { label: "MED",      count: d.med,      color: "text-yellow-600", bg: "bg-yellow-50 border-yellow-200 dark:bg-yellow-950/30 dark:border-yellow-800" },
    { label: "LOW",      count: d.low,      color: "text-blue-500", bg: "bg-blue-50 border-blue-200 dark:bg-blue-950/30 dark:border-blue-800" },
    { label: "INFO",     count: d.info,     color: "text-gray-500", bg: "bg-gray-50 border-gray-200 dark:bg-gray-900/30 dark:border-gray-700" },
  ];

  return (
    <div className="mt-4 space-y-6">
      {/* Severity cards */}
      <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
        {severities.map(({ label, count, color, bg }) => (
          <div
            key={label}
            className={`rounded-lg border px-4 py-3 flex flex-col gap-1 ${bg}`}
          >
            <div className={`text-xs font-semibold uppercase tracking-wide ${color}`}>
              {label}
            </div>
            <div className={`text-2xl font-bold tabular-nums leading-none ${color}`}>
              {count}
            </div>
          </div>
        ))}
      </div>

      {/* KEV / CVE summary */}
      <div className="flex flex-wrap gap-3">
        <div className="inline-flex items-center gap-2 rounded-md border border-border bg-card px-3 py-2">
          <span className="text-xs text-muted-foreground">KEV findings</span>
          <span className="text-sm font-semibold tabular-nums">{d.kev_count}</span>
        </div>
        <div className="inline-flex items-center gap-2 rounded-md border border-border bg-card px-3 py-2">
          <span className="text-xs text-muted-foreground">With CVE IDs</span>
          <span className="text-sm font-semibold tabular-nums">{d.cve_count}</span>
        </div>
        <div className="inline-flex items-center gap-2 rounded-md border border-border bg-card px-3 py-2">
          <span className="text-xs text-muted-foreground">Total</span>
          <span className="text-sm font-semibold tabular-nums">{d.total}</span>
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Status inline changer cell
// ---------------------------------------------------------------------------

const VULN_STATUSES = [
  "open",
  "triaged",
  "false_positive",
  "fixed",
  "wont_fix",
  "reopened",
] as const;

function VulnStatusCell({
  vulnId,
  current,
  onChanged,
}: {
  vulnId: string;
  current: string;
  onChanged: () => void;
}) {
  const mut = useMutation({
    mutationFn: (status: string) =>
      api<VulnOut>(`/vulns/${vulnId}`, {
        method: "PATCH",
        body: JSON.stringify({ status }),
      }),
    onSuccess: onChanged,
  });

  return (
    <Select
      value={current}
      onValueChange={(v) => mut.mutate(v)}
      disabled={mut.isPending}
    >
      <SelectTrigger className="h-7 w-36 text-xs">
        <SelectValue />
      </SelectTrigger>
      <SelectContent>
        {VULN_STATUSES.map((s) => (
          <SelectItem key={s} value={s}>
            {s.replace(/_/g, " ")}
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  );
}

// ---------------------------------------------------------------------------
// Vulnerabilities tab
// ---------------------------------------------------------------------------

const SEVERITY_OPTIONS = ["All", "CRITICAL", "HIGH", "MED", "LOW", "INFO"];
const STATUS_OPTIONS = [
  "All",
  "open",
  "triaged",
  "false_positive",
  "fixed",
  "wont_fix",
  "reopened",
];
const PAGE_SIZE = 50;

function VulnerabilitiesTab({ scanId }: { scanId: string }) {
  const qc = useQueryClient();
  const [severity, setSeverity] = useState("All");
  const [status, setStatus] = useState("All");
  const [offset, setOffset] = useState(0);

  // Reset offset when filters change
  useEffect(() => setOffset(0), [severity, status]);

  const params = new URLSearchParams({
    offset: String(offset),
    limit: String(PAGE_SIZE),
  });
  if (severity !== "All") params.set("severity", severity);
  if (status !== "All") params.set("status", status);

  const query = useQuery({
    queryKey: ["vuln-list", scanId, severity, status, offset],
    queryFn: () =>
      api<VulnsPage>(`/vuln-scans/${scanId}/vulnerabilities?${params.toString()}`),
  });

  const invalidate = () => {
    qc.invalidateQueries({ queryKey: ["vuln-list", scanId] });
  };

  const data = query.data;
  const items = data?.items ?? [];
  const total = data?.total ?? 0;
  const hasMore = offset + PAGE_SIZE < total;

  return (
    <div className="mt-4 space-y-4">
      {/* Filters */}
      <div className="flex flex-wrap items-center gap-3">
        <div className="flex items-center gap-2">
          <span className="text-xs text-muted-foreground">Severity</span>
          <Select value={severity} onValueChange={setSeverity}>
            <SelectTrigger className="h-8 w-32 text-xs">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {SEVERITY_OPTIONS.map((s) => (
                <SelectItem key={s} value={s}>
                  {s}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-xs text-muted-foreground">Status</span>
          <Select value={status} onValueChange={setStatus}>
            <SelectTrigger className="h-8 w-36 text-xs">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {STATUS_OPTIONS.map((s) => (
                <SelectItem key={s} value={s}>
                  {s.replace(/_/g, " ")}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        {total > 0 && (
          <span className="text-xs text-muted-foreground ml-auto">
            {total} result{total !== 1 ? "s" : ""}
          </span>
        )}
      </div>

      {/* Table */}
      {query.isLoading ? (
        <p className="text-sm text-muted-foreground">Loading vulnerabilities…</p>
      ) : query.isError ? (
        <p className="text-sm text-destructive">Failed to load vulnerabilities.</p>
      ) : items.length === 0 ? (
        <div className="rounded-lg border border-dashed border-border p-8 text-center">
          <p className="text-sm text-muted-foreground">
            No vulnerabilities match the current filters.
          </p>
        </div>
      ) : (
        <div className="rounded-lg border border-border overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="bg-muted/50 border-b border-border">
              <tr>
                {[
                  "Severity",
                  "Title",
                  "CVE IDs",
                  "CVSS",
                  "Asset",
                  "Status",
                  "First Seen",
                ].map((h) => (
                  <th
                    key={h}
                    className="px-3 py-2.5 text-left font-medium text-xs uppercase tracking-wide text-muted-foreground whitespace-nowrap"
                  >
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {items.map((v) => (
                <tr
                  key={v.id}
                  className="border-b border-border hover:bg-muted/30 transition-colors"
                >
                  <td className="px-3 py-2.5">
                    <SeverityBadge severity={v.severity} />
                  </td>
                  <td className="px-3 py-2.5 max-w-[260px]">
                    <span
                      className="font-medium truncate block"
                      title={v.title}
                    >
                      {v.title}
                    </span>
                    {v.kev && (
                      <span className="text-xs text-red-600 font-semibold">
                        KEV
                      </span>
                    )}
                  </td>
                  <td className="px-3 py-2.5">
                    <CveBadges ids={v.cve_ids} />
                  </td>
                  <td className="px-3 py-2.5 tabular-nums text-xs">
                    {v.cvss_v3 != null ? v.cvss_v3.toFixed(1) : "—"}
                  </td>
                  <td className="px-3 py-2.5 text-xs font-mono text-muted-foreground max-w-[160px] truncate">
                    {v.asset_label}
                  </td>
                  <td className="px-3 py-2.5">
                    <VulnStatusCell
                      vulnId={v.id}
                      current={v.status}
                      onChanged={invalidate}
                    />
                  </td>
                  <td className="px-3 py-2.5 text-xs text-muted-foreground whitespace-nowrap">
                    {new Date(v.first_seen).toLocaleDateString()}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Pagination */}
      {(offset > 0 || hasMore) && (
        <div className="flex items-center gap-2 text-xs text-muted-foreground">
          {offset > 0 && (
            <button
              onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}
              className="px-3 py-1.5 rounded border border-border hover:bg-muted transition-colors"
            >
              Previous
            </button>
          )}
          <span>
            {offset + 1}–{Math.min(offset + PAGE_SIZE, total)} of {total}
          </span>
          {hasMore && (
            <button
              onClick={() => setOffset(offset + PAGE_SIZE)}
              className="px-3 py-1.5 rounded border border-border hover:bg-muted transition-colors"
            >
              Load more
            </button>
          )}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Diff tab
// ---------------------------------------------------------------------------

function DiffSection({ title, items, tone }: { title: string; items: VulnOut[]; tone: "new" | "seen" | "fixed" }) {
  const toneClass =
    tone === "new"
      ? "border-orange-300 bg-orange-50 dark:bg-orange-950/20"
      : tone === "fixed"
      ? "border-green-300 bg-green-50 dark:bg-green-950/20"
      : "border-border bg-card";
  return (
    <div className={`rounded-lg border p-4 ${toneClass}`}>
      <div className="flex items-center justify-between mb-3">
        <h3 className="text-sm font-semibold">{title}</h3>
        <span className="text-xs text-muted-foreground tabular-nums">{items.length}</span>
      </div>
      {items.length === 0 ? (
        <p className="text-xs text-muted-foreground">None.</p>
      ) : (
        <ul className="space-y-1.5">
          {items.slice(0, 50).map((v) => (
            <li key={v.id} className="flex items-center gap-2 text-xs">
              <SeverityBadge severity={v.severity} />
              <span className="font-medium truncate" title={v.title}>{v.title}</span>
              <span className="ml-auto font-mono text-muted-foreground truncate max-w-[200px]" title={v.asset_label}>
                {v.asset_label}
              </span>
            </li>
          ))}
          {items.length > 50 && (
            <li className="text-xs text-muted-foreground">…and {items.length - 50} more.</li>
          )}
        </ul>
      )}
    </div>
  );
}

function DiffTab({ scanId }: { scanId: string }) {
  const q = useQuery({
    queryKey: ["vuln-diff", scanId],
    queryFn: () => api<VulnDiff>(`/vuln-scans/${scanId}/diff`),
  });

  if (q.isLoading) return <p className="mt-4 text-sm text-muted-foreground">Loading diff…</p>;
  if (q.isError || !q.data) return <p className="mt-4 text-sm text-destructive">Failed to load diff.</p>;

  const d = q.data;

  return (
    <div className="mt-4 space-y-4">
      {!d.has_prior && (
        <div className="rounded-md border border-border bg-muted/40 p-3 text-xs text-muted-foreground">
          No prior completed vuln scan against this target — every detection here is necessarily new.
          Run another vuln scan later to compare.
        </div>
      )}
      <div className="flex flex-wrap gap-3">
        <div className="rounded-md border border-orange-300 bg-orange-50 dark:bg-orange-950/20 px-3 py-2">
          <div className="text-xs uppercase tracking-wide text-orange-600 font-semibold">New</div>
          <div className="text-xl font-bold tabular-nums">{d.counts.new}</div>
        </div>
        <div className="rounded-md border border-border bg-card px-3 py-2">
          <div className="text-xs uppercase tracking-wide text-muted-foreground font-semibold">Seen</div>
          <div className="text-xl font-bold tabular-nums">{d.counts.seen}</div>
        </div>
        <div className="rounded-md border border-green-300 bg-green-50 dark:bg-green-950/20 px-3 py-2">
          <div className="text-xs uppercase tracking-wide text-green-600 font-semibold">Fixed in this run</div>
          <div className="text-xl font-bold tabular-nums">{d.counts.fixed}</div>
        </div>
      </div>
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <DiffSection title="New" items={d.new} tone="new" />
        <DiffSection title="Seen" items={d.seen} tone="seen" />
        <DiffSection title="Fixed in this run" items={d.fixed} tone="fixed" />
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main content (uses useSearchParams → wrapped in Suspense below)
// ---------------------------------------------------------------------------

function VulnScanDetailContent({ params }: { params: { id: string } }) {
  const qc = useQueryClient();
  const router = useRouter();
  const searchParams = useSearchParams();

  const VALID_TABS = ["overview", "vulnerabilities", "diff"];
  const rawTab = searchParams.get("tab");
  const defaultTab = rawTab && VALID_TABS.includes(rawTab) ? rawTab : "overview";

  const scan = useQuery({
    queryKey: ["vuln-scan", params.id],
    queryFn: () => api<VulnScanDetail>(`/vuln-scans/${params.id}`),
  });

  // SSE subscription while scan is running
  useEffect(() => {
    const status = scan.data?.status;
    if (!status || status === "completed" || status === "failed") return;

    const es = new EventSource(sseUrl(`/vuln-scans/${params.id}/stream`));
    const refetch = () => {
      qc.invalidateQueries({ queryKey: ["vuln-scan", params.id] });
      qc.invalidateQueries({ queryKey: ["vuln-overview", params.id] });
      qc.invalidateQueries({ queryKey: ["vuln-list", params.id] });
      qc.invalidateQueries({ queryKey: ["vuln-diff", params.id] });
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
  const durationMs =
    started && finished ? finished.getTime() - started.getTime() : null;

  return (
    <AppShell>
      {/* Header */}
      <div className="mb-6 flex flex-wrap items-start justify-between gap-4">
        <div>
          <div className="text-xs text-muted-foreground mb-1">Vulnerability Analysis</div>
          <div className="flex items-center gap-3">
            <Globe className="h-5 w-5 text-primary" />
            <h1 className="text-2xl font-semibold tracking-tight">
              {s.target_domain}
            </h1>
            <Badge variant={STATUS_VARIANT[s.status] ?? "default"}>
              {s.status}
            </Badge>
          </div>
          <div className="mt-2 flex flex-wrap items-center gap-x-5 gap-y-1 text-xs text-muted-foreground">
            {started && (
              <span className="inline-flex items-center gap-1.5">
                <Calendar className="h-3.5 w-3.5" />
                {started.toLocaleString()}
              </span>
            )}
            {durationMs != null && (
              <span className="inline-flex items-center gap-1.5">
                <Clock className="h-3.5 w-3.5" />
                Duration: {formatDuration(durationMs)}
              </span>
            )}
            <span>
              Profile:{" "}
              <span className="text-foreground font-medium">{s.profile}</span>
            </span>
            {s.intrusive && (
              <span className="text-warning font-medium">Intrusive mode</span>
            )}
            {s.parent_scan_id && (
              <span className="inline-flex items-center gap-1">
                Recon scan:{" "}
                <Link
                  href={`/scans/${s.parent_scan_id}`}
                  className="inline-flex items-center gap-0.5 text-primary hover:underline"
                >
                  {s.parent_scan_id.slice(0, 8)}…
                  <ExternalLink className="h-3 w-3" />
                </Link>
              </span>
            )}
          </div>
        </div>
      </div>

      {/* Progress bar while running */}
      {(s.status === "running" || s.status === "created") && (
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
        </div>
      )}

      {s.error && (
        <p className="mb-6 text-xs text-destructive break-words">
          Error: {s.error}
        </p>
      )}

      {/* Tabs */}
      <Tabs
        value={defaultTab}
        onValueChange={(t) => router.replace(`?tab=${t}`, { scroll: false })}
      >
        <TabsList>
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="vulnerabilities">Vulnerabilities</TabsTrigger>
          <TabsTrigger value="diff">Diff</TabsTrigger>
        </TabsList>

        <TabsContent value="overview">
          <OverviewTab
            scanId={params.id}
            scanStatus={s.status}
            progressPct={s.progress_pct}
          />
        </TabsContent>
        <TabsContent value="vulnerabilities">
          <VulnerabilitiesTab scanId={params.id} />
        </TabsContent>
        <TabsContent value="diff">
          <DiffTab scanId={params.id} />
        </TabsContent>
      </Tabs>
    </AppShell>
  );
}

// ---------------------------------------------------------------------------
// Page export — wraps in Suspense (required for useSearchParams)
// ---------------------------------------------------------------------------

export default function VulnScanDetailPage({
  params,
}: {
  params: { id: string };
}) {
  return (
    <Suspense
      fallback={
        <AppShell>
          <p className="text-sm text-muted-foreground">Loading scan…</p>
        </AppShell>
      }
    >
      <VulnScanDetailContent params={params} />
    </Suspense>
  );
}
