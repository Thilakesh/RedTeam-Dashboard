"use client";

import Link from "next/link";
import { useQuery } from "@tanstack/react-query";
import { Activity, AlertTriangle, Crosshair, Layers } from "lucide-react";
import { AppShell } from "@/components/AppShell";
import { useAuth } from "@/lib/auth-context";
import { getDashboardSummary, type DashboardSummary } from "@/lib/api";

const SEVERITY_ORDER = ["HIGH", "MED", "LOW", "INFO"] as const;

const SEVERITY_DOT: Record<string, string> = {
  HIGH: "bg-red-500",
  MED: "bg-amber-500",
  LOW: "bg-blue-500",
  INFO: "bg-muted-foreground/50",
};

const SEVERITY_STROKE: Record<string, string> = {
  HIGH: "hsl(0 72% 51%)",
  MED: "hsl(38 92% 50%)",
  LOW: "hsl(217 91% 60%)",
  INFO: "hsl(var(--muted-foreground) / 0.5)",
};

const SEVERITY_TEXT: Record<string, string> = {
  HIGH: "text-red-600 dark:text-red-400",
  MED: "text-amber-600 dark:text-amber-400",
  LOW: "text-blue-600 dark:text-blue-400",
  INFO: "text-muted-foreground",
};

// Matches components/tabs/RisksTab.tsx's SEVERITY_COLORS convention exactly.
const SEVERITY_BADGE: Record<string, string> = {
  HIGH: "bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400",
  MED: "bg-amber-100 text-amber-800 dark:bg-amber-900/30 dark:text-amber-400",
  LOW: "bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-400",
  INFO: "bg-muted text-muted-foreground",
};

const STATUS_BADGE: Record<string, string> = {
  completed: "bg-success/15 text-success",
  running: "bg-info/15 text-info",
  created: "bg-info/15 text-info",
  queued: "bg-muted text-muted-foreground",
  failed: "bg-destructive/15 text-destructive",
  stopped: "bg-warning/15 text-warning",
};

function timeAgo(iso: string): string {
  const diffMs = Date.now() - new Date(iso).getTime();
  const mins = Math.floor(diffMs / 60_000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
}

export default function DashboardHomePage() {
  const { hasFeature } = useAuth();
  const q = useQuery({ queryKey: ["dashboard-summary"], queryFn: getDashboardSummary });

  return (
    <AppShell>
      <div className="flex items-start justify-between gap-4 mb-6 flex-wrap">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Dashboard</h1>
          <p className="text-sm text-muted-foreground mt-1">
            Your scans, findings, and workspaces at a glance.
          </p>
        </div>
        <div className="flex gap-2">
          {hasFeature("operations") && (
            <Link
              href="/operations/launch"
              className="h-9 px-4 inline-flex items-center rounded-md border border-border text-sm font-medium hover:bg-accent"
            >
              Launch Operation
            </Link>
          )}
          {hasFeature("recon") && (
            <Link
              href="/dashboard"
              className="h-9 px-4 inline-flex items-center rounded-md bg-primary text-primary-foreground text-sm font-medium hover:bg-primary/90"
            >
              + New Scan
            </Link>
          )}
        </div>
      </div>

      {q.isLoading && <p className="text-sm text-muted-foreground">Loading overview…</p>}
      {q.isError && (
        <p className="text-sm text-destructive">Couldn't load the dashboard overview.</p>
      )}

      {q.data && (
        <div className="space-y-4">
          <KpiRow data={q.data} />
          <div className="grid grid-cols-1 lg:grid-cols-[1fr_1.3fr] gap-4">
            <SeverityCard data={q.data} />
            <ActivityCard data={q.data} />
          </div>
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <RecentScansCard data={q.data} />
            <TopFindingsCard data={q.data} />
          </div>
        </div>
      )}
    </AppShell>
  );
}

function KpiRow({ data }: { data: DashboardSummary }) {
  const tiles = [
    { label: "Active scans", value: data.active_scans, icon: Activity, tone: "text-primary bg-primary/10" },
    { label: "Assets tracked", value: data.assets_tracked, icon: Layers, tone: "text-success bg-success/10" },
    { label: "Open findings", value: data.open_findings, icon: AlertTriangle, tone: "text-destructive bg-destructive/10" },
    { label: "Target workspaces", value: data.workspaces, icon: Crosshair, tone: "text-warning bg-warning/10" },
  ];
  return (
    <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
      {tiles.map((t) => (
        <div key={t.label} className="rounded-lg border border-border bg-card p-4">
          <div className={`h-8 w-8 rounded-md flex items-center justify-center mb-3 ${t.tone}`}>
            <t.icon className="h-4 w-4" />
          </div>
          <div className="text-2xl font-semibold tabular-nums tracking-tight">{t.value}</div>
          <div className="text-xs text-muted-foreground mt-0.5">{t.label}</div>
        </div>
      ))}
    </div>
  );
}

function SeverityCard({ data }: { data: DashboardSummary }) {
  const total = data.open_findings;
  const r = 52;
  const circumference = 2 * Math.PI * r;
  let acc = 0;
  const segments = SEVERITY_ORDER.map((sev) => {
    const count = data.severity_counts[sev] ?? 0;
    const frac = total > 0 ? count / total : 0;
    const length = frac * circumference;
    const dashoffset = -acc;
    acc += length;
    return { sev, count, length, dashoffset, pct: total > 0 ? Math.round(frac * 100) : 0 };
  });

  return (
    <div className="rounded-lg border border-border bg-card p-5">
      <div className="text-sm font-semibold">Findings by severity</div>
      <div className="text-xs text-muted-foreground mb-4">
        {total > 0 ? `${total} total across your scans` : "No findings yet"}
      </div>
      <div className="flex items-center gap-6">
        <div className="relative w-[132px] h-[132px] shrink-0">
          <svg width="132" height="132" viewBox="0 0 132 132">
            <circle cx="66" cy="66" r={r} fill="none" stroke="hsl(var(--muted))" strokeWidth="16" />
            {total > 0 &&
              segments.map((s) =>
                s.length > 0 ? (
                  <circle
                    key={s.sev}
                    cx="66"
                    cy="66"
                    r={r}
                    fill="none"
                    stroke={SEVERITY_STROKE[s.sev]}
                    strokeWidth="16"
                    strokeLinecap="round"
                    strokeDasharray={`${s.length} ${circumference - s.length}`}
                    strokeDashoffset={s.dashoffset}
                    transform="rotate(-90 66 66)"
                  />
                ) : null,
              )}
          </svg>
          <div className="absolute inset-0 flex flex-col items-center justify-center">
            <div className="text-xl font-semibold tabular-nums">{total}</div>
            <div className="text-[10px] text-muted-foreground">findings</div>
          </div>
        </div>
        <div className="flex-1 space-y-2.5">
          {segments.map((s) => (
            <div key={s.sev} className="flex items-center justify-between text-sm">
              <span className="flex items-center gap-2">
                <i className={`h-2.5 w-2.5 rounded-sm ${SEVERITY_DOT[s.sev]}`} />
                <span className={SEVERITY_TEXT[s.sev]}>{s.sev}</span>
              </span>
              <span>
                <span className="font-semibold tabular-nums">{s.count}</span>
                <span className="text-muted-foreground text-xs ml-1.5">{s.pct}%</span>
              </span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function ActivityCard({ data }: { data: DashboardSummary }) {
  const days = data.scan_activity;
  const max = Math.max(1, ...days.map((d) => d.completed));
  const w = 560;
  const h = 120;
  const stepX = days.length > 1 ? w / (days.length - 1) : 0;
  const points = days.map((d, i) => ({
    x: i * stepX,
    y: 100 - (d.completed / max) * 80,
    v: d.completed,
    day: d.day,
  }));
  const linePath = points.map((p, i) => `${i === 0 ? "M" : "L"}${p.x},${p.y}`).join(" ");
  const areaPath = `${linePath} L${w},120 L0,120 Z`;
  const today = new Date().toISOString().slice(0, 10);

  return (
    <div className="rounded-lg border border-border bg-card p-5">
      <div className="text-sm font-semibold">Scan activity</div>
      <div className="text-xs text-muted-foreground mb-4">Completed scans per day, last 7 days</div>
      <svg width="100%" height="120" viewBox={`0 0 ${w} ${h}`} preserveAspectRatio="none" style={{ overflow: "visible" }}>
        <defs>
          <linearGradient id="dashSparkFill" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="hsl(var(--primary))" stopOpacity="0.28" />
            <stop offset="100%" stopColor="hsl(var(--primary))" stopOpacity="0" />
          </linearGradient>
        </defs>
        <line x1="0" y1="30" x2={w} y2="30" stroke="hsl(var(--border))" strokeWidth="1" />
        <line x1="0" y1="60" x2={w} y2="60" stroke="hsl(var(--border))" strokeWidth="1" />
        <line x1="0" y1="90" x2={w} y2="90" stroke="hsl(var(--border))" strokeWidth="1" />
        <path d={areaPath} fill="url(#dashSparkFill)" stroke="none" />
        <path d={linePath} fill="none" stroke="hsl(var(--primary))" strokeWidth="2.5" strokeLinejoin="round" strokeLinecap="round" />
        {points.map((p) => (
          <circle
            key={p.day}
            cx={p.x}
            cy={p.y}
            r={p.day === today ? 4.5 : 3.5}
            fill={p.day === today ? "hsl(var(--primary))" : "hsl(var(--card))"}
            stroke="hsl(var(--primary))"
            strokeWidth="2"
          >
            <title>
              {new Date(`${p.day}T00:00:00`).toLocaleDateString(undefined, { weekday: "short", month: "short", day: "numeric" })}
              : {p.v} completed
            </title>
          </circle>
        ))}
      </svg>
      <div className="flex justify-between text-xs text-muted-foreground mt-1.5">
        {days.map((d) => (
          <span key={d.day}>
            {d.day === today
              ? "Today"
              : new Date(`${d.day}T00:00:00`).toLocaleDateString(undefined, { weekday: "short" })}
          </span>
        ))}
      </div>
    </div>
  );
}

function RecentScansCard({ data }: { data: DashboardSummary }) {
  return (
    <div className="rounded-lg border border-border bg-card p-5">
      <div className="text-sm font-semibold">Recent scans</div>
      <div className="text-xs text-muted-foreground mb-3">Your last {data.recent_scans.length || 0} scans</div>
      {data.recent_scans.length === 0 && (
        <p className="text-sm text-muted-foreground py-6 text-center">No scans yet.</p>
      )}
      {data.recent_scans.map((s) => (
        <Link
          key={s.id}
          href={`/scans/${s.id}`}
          className="flex items-center justify-between gap-3 py-3 border-t border-border first:border-t-0 hover:bg-accent/40 -mx-1 px-1 rounded"
        >
          <div className="min-w-0">
            <div className="text-sm font-medium truncate">{s.domain}</div>
            <div className="text-xs text-muted-foreground">
              {s.profile} · {timeAgo(s.created_at)}
            </div>
          </div>
          <span className={`text-xs font-semibold px-2.5 py-1 rounded-full whitespace-nowrap ${STATUS_BADGE[s.status] ?? "bg-muted text-muted-foreground"}`}>
            {s.status}
          </span>
        </Link>
      ))}
      {data.recent_scans.length > 0 && (
        <Link href="/dashboard/recon-jobs" className="block text-center text-xs font-medium text-primary mt-3 hover:underline">
          View all scans →
        </Link>
      )}
    </div>
  );
}

function TopFindingsCard({ data }: { data: DashboardSummary }) {
  return (
    <div className="rounded-lg border border-border bg-card p-5">
      <div className="text-sm font-semibold">Top findings</div>
      <div className="text-xs text-muted-foreground mb-3">Ranked by risk score, across your scans</div>
      {data.top_findings.length === 0 && (
        <p className="text-sm text-muted-foreground py-6 text-center">No findings yet — run a deep scan to populate this.</p>
      )}
      {data.top_findings.map((f, i) => (
        <Link
          key={`${f.scan_id}-${i}`}
          href={`/scans/${f.scan_id}?tab=risks`}
          className="flex items-center justify-between gap-3 py-3 border-t border-border first:border-t-0 hover:bg-accent/40 -mx-1 px-1 rounded"
        >
          <div className="min-w-0">
            <div className="text-sm font-medium truncate">{f.fqdn}</div>
            <div className="text-xs text-muted-foreground truncate">{f.rationale}</div>
          </div>
          <span className={`text-xs font-semibold px-2.5 py-1 rounded-full whitespace-nowrap ${SEVERITY_BADGE[f.severity] ?? SEVERITY_BADGE.INFO}`}>
            {f.severity}
          </span>
        </Link>
      ))}
      {data.top_findings.length > 0 && (
        <Link href="/dashboard/recon-jobs" className="block text-center text-xs font-medium text-primary mt-3 hover:underline">
          View all findings →
        </Link>
      )}
    </div>
  );
}
