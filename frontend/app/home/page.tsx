"use client";

import Link from "next/link";
import { useQuery } from "@tanstack/react-query";
import { Activity, AlertTriangle, Crosshair, Layers, Rocket, Search } from "lucide-react";
import { AppShell } from "@/components/AppShell";
import { useAuth } from "@/lib/auth-context";
import { getDashboardSummary, type DashboardSummary } from "@/lib/api";

const SEVERITY_ORDER = ["HIGH", "MED", "LOW", "INFO"] as const;

const SEVERITY_DOT: Record<string, string> = {
  HIGH: "bg-sev-high",
  MED: "bg-sev-med",
  LOW: "bg-sev-low",
  INFO: "bg-divider",
};

const SEVERITY_STROKE: Record<string, string> = {
  HIGH: "hsl(var(--sev-high))",
  MED: "hsl(var(--sev-med))",
  LOW: "hsl(var(--sev-low))",
  INFO: "hsl(var(--divider))",
};

const SEVERITY_TEXT: Record<string, string> = {
  HIGH: "text-sev-high-fg",
  MED: "text-sev-med-fg",
  LOW: "text-sev-low-fg",
  INFO: "text-muted-foreground",
};

const SEVERITY_PILL: Record<string, string> = {
  HIGH: "pill pill-hi",
  MED: "pill pill-med",
  LOW: "pill pill-low",
  INFO: "pill pill-info",
};

const STATUS_PILL: Record<string, string> = {
  completed: "pill pill-ok",
  running: "pill pill-run",
  created: "pill pill-run",
  queued: "pill pill-info",
  failed: "pill pill-err",
  stopped: "pill pill-warn",
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

function greeting(): string {
  const h = new Date().getHours();
  if (h < 5) return "Good night";
  if (h < 12) return "Good morning";
  if (h < 18) return "Good afternoon";
  return "Good evening";
}

export default function DashboardHomePage() {
  const { user, hasFeature } = useAuth();
  const q = useQuery({ queryKey: ["dashboard-summary"], queryFn: getDashboardSummary });
  const name = (user?.email || "").split("@")[0] || "there";

  return (
    <AppShell>
      <div className="flex items-end justify-between gap-6 mb-6 flex-wrap">
        <div>
          <div className="kicker mb-2">Console · Recon Dashboard</div>
          <h1 className="page-h1">
            {greeting()}, {name}.
          </h1>
          <p className="text-sm text-muted-foreground mt-1">
            Your scans, findings, and workspaces at a glance.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <div className="hidden md:flex cmd-box w-[280px] xl:w-[320px] text-muted-foreground">
            <Search className="h-3.5 w-3.5 text-primary shrink-0" />
            <span className="flex-1 text-[13px] truncate">Search domains, IPs, findings…</span>
            <span className="kbd">⌘K</span>
          </div>
          {hasFeature("operations") && (
            <Link
              href="/operations/launch"
              className="h-9 px-4 inline-flex items-center gap-1.5 rounded-md border border-border text-sm font-medium hover:bg-accent whitespace-nowrap"
            >
              <Rocket className="h-3.5 w-3.5" /> Launch Operation
            </Link>
          )}
          {hasFeature("recon") && (
            <Link
              href="/dashboard"
              className="h-9 px-4 inline-flex items-center rounded-md bg-primary text-primary-foreground text-sm font-medium hover:bg-primary/90 whitespace-nowrap"
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
          <div className="grid grid-cols-1 lg:grid-cols-[1.6fr_1fr] gap-4">
            <ActivityCard data={q.data} />
            <SeverityCard data={q.data} />
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
    { label: "Active scans", value: data.active_scans, icon: Activity, valueClass: "text-primary-tint" },
    { label: "Assets tracked", value: data.assets_tracked, icon: Layers, valueClass: "" },
    { label: "Open findings", value: data.open_findings, icon: AlertTriangle, valueClass: "text-sev-high-fg" },
    { label: "Target workspaces", value: data.workspaces, icon: Crosshair, valueClass: "" },
  ];
  return (
    <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
      {tiles.map((t) => (
        <div key={t.label} className="stat-tile">
          <div className="text-[10px] tracking-[0.1em] uppercase text-muted-foreground-2 flex items-center gap-1.5">
            <t.icon className="h-3 w-3" />
            {t.label}
          </div>
          <div className={`text-[30px] font-medium tabular-nums tracking-[-0.02em] ${t.valueClass}`}>
            {t.value}
          </div>
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
    <div className="card-panel">
      <div className="panel-title">Findings by severity</div>
      <div className="panel-sub mb-4">
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
    <div className="card-panel">
      <div className="panel-title">Scan activity</div>
      <div className="panel-sub mb-4">Completed scans per day, last 7 days</div>
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
    <div className="card-panel">
      <div className="flex items-center justify-between mb-1">
        <div>
          <div className="panel-title">Recent scans</div>
          <div className="panel-sub">Your last {data.recent_scans.length || 0} scans</div>
        </div>
        {data.recent_scans.length > 0 && (
          <Link href="/dashboard/recon-jobs" className="text-[11px] text-primary hover:underline">
            View all →
          </Link>
        )}
      </div>
      {data.recent_scans.length === 0 && (
        <p className="text-sm text-muted-foreground py-6 text-center">No scans yet.</p>
      )}
      {data.recent_scans.map((s) => (
        <Link
          key={s.id}
          href={`/scans/${s.id}`}
          className="row-strip flex items-center justify-between gap-3 py-3 hover:bg-accent/40 -mx-1 px-1 rounded"
        >
          <div className="min-w-0">
            <div className="text-[13px] font-medium truncate">{s.domain}</div>
            <div className="text-[11px] text-muted-foreground-2">
              {s.profile} · {timeAgo(s.created_at)}
            </div>
          </div>
          <span className={STATUS_PILL[s.status] ?? "pill pill-info"}>{s.status}</span>
        </Link>
      ))}
    </div>
  );
}

function TopFindingsCard({ data }: { data: DashboardSummary }) {
  return (
    <div className="card-panel">
      <div className="flex items-center justify-between mb-1">
        <div>
          <div className="panel-title">Top findings</div>
          <div className="panel-sub">Ranked by risk score, across your scans</div>
        </div>
        {data.top_findings.length > 0 && (
          <Link href="/dashboard/recon-jobs" className="text-[11px] text-primary hover:underline">
            View all →
          </Link>
        )}
      </div>
      {data.top_findings.length === 0 && (
        <p className="text-sm text-muted-foreground py-6 text-center">No findings yet — run a deep scan to populate this.</p>
      )}
      {data.top_findings.map((f, i) => (
        <Link
          key={`${f.scan_id}-${i}`}
          href={`/scans/${f.scan_id}?tab=risks`}
          className="row-strip flex items-center justify-between gap-3 py-3 hover:bg-accent/40 -mx-1 px-1 rounded"
        >
          <div className="min-w-0">
            <div className="text-[13px] font-medium truncate">{f.fqdn}</div>
            <div className="text-[11px] text-muted-foreground-2 truncate">{f.rationale}</div>
          </div>
          <span className={SEVERITY_PILL[f.severity] ?? SEVERITY_PILL.INFO}>{f.severity}</span>
        </Link>
      ))}
    </div>
  );
}
