"use client";

import { Suspense, useEffect, useState } from "react";
import { useQuery, useQueryClient, useMutation } from "@tanstack/react-query";
import { useRouter, useSearchParams } from "next/navigation";
import { Globe, Calendar, Clock, ExternalLink, Server, Cpu, Network, Lock, Shield, Brain, Trash2 } from "lucide-react";
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
import { Button } from "@/components/ui/button";
import {
  api,
  canDeleteScan,
  deleteVulnScan,
  sseUrl,
  type ByServiceResponse,
  type ByTechResponse,
  type EndpointsPage,
  type EndpointRow,
  type HvtResponse,
  type TlsResponse,
  type TriageResponse,
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
// ByService tab
// ---------------------------------------------------------------------------

function ByServiceTab({ scanId }: { scanId: string }) {
  const q = useQuery({
    queryKey: ["vuln-by-service", scanId],
    queryFn: () => api<ByServiceResponse>(`/vuln-scans/${scanId}/by-service`),
  });

  if (q.isLoading) return <p className="mt-4 text-sm text-muted-foreground">Loading…</p>;
  if (q.isError || !q.data) return <p className="mt-4 text-sm text-destructive">Failed to load.</p>;

  const rows = q.data.rows;
  if (rows.length === 0)
    return (
      <div className="mt-6 rounded-lg border border-dashed border-border p-8 text-center">
        <p className="text-sm text-muted-foreground">No service-linked vulnerabilities found.</p>
      </div>
    );

  const SEV_ORDER = ["CRITICAL", "HIGH", "MED", "LOW", "INFO"];
  const SEV_COLOR: Record<string, string> = {
    CRITICAL: "bg-red-500",
    HIGH: "bg-orange-500",
    MED: "bg-yellow-500",
    LOW: "bg-blue-400",
    INFO: "bg-gray-400",
  };

  return (
    <div className="mt-4 space-y-3">
      {rows.map((row, i) => (
        <div key={row.service_id ?? `none-${i}`} className="rounded-lg border border-border bg-card p-4">
          <div className="flex items-start justify-between gap-4 flex-wrap">
            <div>
              <div className="flex items-center gap-2">
                <Server className="h-4 w-4 text-muted-foreground" />
                <span className="font-mono text-sm font-medium">{row.service_key}</span>
                {row.classification !== "unknown" && (
                  <span className="rounded-full border border-border bg-muted px-2 py-0.5 text-xs">
                    {row.classification}
                  </span>
                )}
              </div>
              {(row.product || row.version) && (
                <p className="mt-1 text-xs text-muted-foreground">
                  {[row.product, row.version].filter(Boolean).join(" ")}
                </p>
              )}
            </div>
            <div className="flex items-center gap-3">
              <span className="text-xs text-muted-foreground">{row.vuln_count} vulns</span>
              {row.max_risk_score != null && (
                <span className="text-xs font-semibold tabular-nums">
                  Risk: {row.max_risk_score.toFixed(2)}
                </span>
              )}
            </div>
          </div>
          <div className="mt-2 flex flex-wrap gap-1">
            {SEV_ORDER.filter((s) => (row.severities[s] ?? 0) > 0).map((s) => (
              <span
                key={s}
                className={`inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-xs font-semibold text-white ${SEV_COLOR[s]}`}
              >
                {s} {row.severities[s]}
              </span>
            ))}
          </div>
        </div>
      ))}
    </div>
  );
}

// ---------------------------------------------------------------------------
// ByTech tab
// ---------------------------------------------------------------------------

function ByTechTab({ scanId }: { scanId: string }) {
  const q = useQuery({
    queryKey: ["vuln-by-tech", scanId],
    queryFn: () => api<ByTechResponse>(`/vuln-scans/${scanId}/by-technology`),
  });

  if (q.isLoading) return <p className="mt-4 text-sm text-muted-foreground">Loading…</p>;
  if (q.isError || !q.data) return <p className="mt-4 text-sm text-destructive">Failed to load.</p>;

  const rows = q.data.rows;
  if (rows.length === 0)
    return (
      <div className="mt-6 rounded-lg border border-dashed border-border p-8 text-center">
        <p className="text-sm text-muted-foreground">No technology-linked vulnerabilities found.</p>
      </div>
    );

  const SEV_ORDER = ["CRITICAL", "HIGH", "MED", "LOW", "INFO"];
  const SEV_COLOR: Record<string, string> = {
    CRITICAL: "bg-red-500", HIGH: "bg-orange-500",
    MED: "bg-yellow-500", LOW: "bg-blue-400", INFO: "bg-gray-400",
  };

  return (
    <div className="mt-4 rounded-lg border border-border overflow-x-auto">
      <table className="w-full text-sm">
        <thead className="bg-muted/50 border-b border-border">
          <tr>
            {["Technology", "Category", "CPE", "Vulns", "Severity breakdown", "Max Risk"].map((h) => (
              <th key={h} className="px-3 py-2.5 text-left text-xs font-medium uppercase tracking-wide text-muted-foreground whitespace-nowrap">
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row, i) => (
            <tr key={row.technology_id ?? i} className="border-b border-border hover:bg-muted/30">
              <td className="px-3 py-2.5 font-medium">
                {row.name}
                {row.version && <span className="ml-1 text-xs text-muted-foreground">{row.version}</span>}
              </td>
              <td className="px-3 py-2.5 text-xs text-muted-foreground">{row.category ?? "—"}</td>
              <td className="px-3 py-2.5 text-xs font-mono text-muted-foreground max-w-[200px] truncate">{row.cpe ?? "—"}</td>
              <td className="px-3 py-2.5 tabular-nums font-semibold">{row.vuln_count}</td>
              <td className="px-3 py-2.5">
                <div className="flex flex-wrap gap-1">
                  {SEV_ORDER.filter((s) => (row.severities[s] ?? 0) > 0).map((s) => (
                    <span key={s} className={`inline-flex items-center rounded-full px-1.5 py-0.5 text-xs font-semibold text-white ${SEV_COLOR[s]}`}>
                      {s[0]}{row.severities[s]}
                    </span>
                  ))}
                </div>
              </td>
              <td className="px-3 py-2.5 tabular-nums text-xs">
                {row.max_risk_score != null ? row.max_risk_score.toFixed(2) : "—"}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Endpoints tab
// ---------------------------------------------------------------------------

const ENDPOINT_FLAG_OPTIONS = [
  { label: "All", value: "all" },
  { label: "Admin", value: "is_admin" },
  { label: "Login", value: "is_login" },
  { label: "API", value: "is_api" },
  { label: "Upload", value: "is_upload" },
];

function EndpointsTab({ scanId }: { scanId: string }) {
  const [filter, setFilter] = useState("all");
  const [offset, setOffset] = useState(0);
  const PAGE_SIZE = 50;

  useEffect(() => setOffset(0), [filter]);

  const params = new URLSearchParams({ offset: String(offset), limit: String(PAGE_SIZE) });
  if (filter === "is_admin") params.set("is_admin", "true");
  else if (filter === "is_login") params.set("is_login", "true");
  else if (filter === "is_api") params.set("is_api", "true");
  else if (filter === "is_upload") params.set("is_upload", "true");

  const q = useQuery({
    queryKey: ["vuln-endpoints", scanId, filter, offset],
    queryFn: () => api<EndpointsPage>(`/vuln-scans/${scanId}/endpoints?${params}`),
  });

  const items = q.data?.items ?? [];
  const total = q.data?.total ?? 0;
  const hasMore = offset + PAGE_SIZE < total;

  return (
    <div className="mt-4 space-y-4">
      <div className="flex flex-wrap items-center gap-2">
        {ENDPOINT_FLAG_OPTIONS.map((opt) => (
          <button
            key={opt.value}
            onClick={() => setFilter(opt.value)}
            className={`rounded-full border px-3 py-1 text-xs font-medium transition-colors ${
              filter === opt.value
                ? "border-primary bg-primary text-primary-foreground"
                : "border-border hover:bg-muted"
            }`}
          >
            {opt.label}
          </button>
        ))}
        {total > 0 && (
          <span className="ml-auto text-xs text-muted-foreground">{total} endpoint{total !== 1 ? "s" : ""}</span>
        )}
      </div>

      {q.isLoading ? (
        <p className="text-sm text-muted-foreground">Loading…</p>
      ) : q.isError ? (
        <p className="text-sm text-destructive">Failed to load endpoints.</p>
      ) : items.length === 0 ? (
        <div className="rounded-lg border border-dashed border-border p-8 text-center">
          <p className="text-sm text-muted-foreground">No endpoints discovered yet.</p>
        </div>
      ) : (
        <div className="rounded-lg border border-border overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="bg-muted/50 border-b border-border">
              <tr>
                {["Method", "URL", "Status", "Title", "Flags", "Source"].map((h) => (
                  <th key={h} className="px-3 py-2.5 text-left text-xs font-medium uppercase tracking-wide text-muted-foreground whitespace-nowrap">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {items.map((ep: EndpointRow) => (
                <tr key={ep.id} className="border-b border-border hover:bg-muted/30">
                  <td className="px-3 py-2 text-xs font-mono font-semibold">{ep.method}</td>
                  <td className="px-3 py-2 max-w-[300px]">
                    <Link
                      href={`/vuln-scans/${scanId}/endpoints/${ep.id}`}
                      className="text-xs font-mono text-primary hover:underline truncate block"
                      title={ep.url}
                    >
                      {ep.path}
                    </Link>
                  </td>
                  <td className="px-3 py-2 text-xs tabular-nums">
                    {ep.status_code ?? "—"}
                  </td>
                  <td className="px-3 py-2 text-xs text-muted-foreground max-w-[180px] truncate">
                    {ep.title ?? "—"}
                  </td>
                  <td className="px-3 py-2">
                    <div className="flex flex-wrap gap-1">
                      {ep.is_admin && <span className="rounded bg-red-100 text-red-700 px-1.5 py-0.5 text-xs font-semibold">admin</span>}
                      {ep.is_login && <span className="rounded bg-yellow-100 text-yellow-700 px-1.5 py-0.5 text-xs font-semibold">login</span>}
                      {ep.is_api && <span className="rounded bg-blue-100 text-blue-700 px-1.5 py-0.5 text-xs font-semibold">api</span>}
                      {ep.is_upload && <span className="rounded bg-purple-100 text-purple-700 px-1.5 py-0.5 text-xs font-semibold">upload</span>}
                    </div>
                  </td>
                  <td className="px-3 py-2 text-xs text-muted-foreground">{ep.source_tool}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {(offset > 0 || hasMore) && (
        <div className="flex items-center gap-2 text-xs text-muted-foreground">
          {offset > 0 && (
            <button onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))} className="px-3 py-1.5 rounded border border-border hover:bg-muted">
              Previous
            </button>
          )}
          <span>{offset + 1}–{Math.min(offset + PAGE_SIZE, total)} of {total}</span>
          {hasMore && (
            <button onClick={() => setOffset(offset + PAGE_SIZE)} className="px-3 py-1.5 rounded border border-border hover:bg-muted">
              Load more
            </button>
          )}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// TLS tab
// ---------------------------------------------------------------------------

function TlsTab({ scanId }: { scanId: string }) {
  const q = useQuery({
    queryKey: ["vuln-tls", scanId],
    queryFn: () => api<TlsResponse>(`/vuln-scans/${scanId}/tls`),
  });

  if (q.isLoading) return <p className="mt-4 text-sm text-muted-foreground">Loading…</p>;
  if (q.isError || !q.data) return <p className="mt-4 text-sm text-destructive">Failed to load TLS data.</p>;

  const rows = q.data.rows;
  if (rows.length === 0)
    return (
      <div className="mt-6 rounded-lg border border-dashed border-border p-8 text-center">
        <p className="text-sm text-muted-foreground">No TLS observations found. Run testssl in the vuln profile to populate this tab.</p>
      </div>
    );

  const gradeColor = (grade: string | null) => {
    if (!grade) return "text-muted-foreground";
    if (grade.startsWith("A")) return "text-green-600";
    if (grade.startsWith("B")) return "text-yellow-600";
    return "text-red-600";
  };

  return (
    <div className="mt-4 space-y-3">
      {rows.map((row) => (
        <div key={row.service_id} className={`rounded-lg border p-4 ${row.is_expired ? "border-red-300 bg-red-50 dark:bg-red-950/20" : "border-border bg-card"}`}>
          <div className="flex items-start justify-between gap-4 flex-wrap">
            <div className="flex items-center gap-2">
              <Lock className="h-4 w-4 text-muted-foreground" />
              <span className="font-mono text-sm font-medium">{row.service_key}</span>
              {row.grade && (
                <span className={`text-lg font-bold ${gradeColor(row.grade)}`}>{row.grade}</span>
              )}
            </div>
            {row.cert_not_after && (
              <div className="text-xs">
                {row.is_expired ? (
                  <span className="font-semibold text-red-600">Certificate expired {Math.abs(row.days_until_expiry!)} days ago</span>
                ) : (
                  <span className={row.days_until_expiry! < 30 ? "text-orange-600 font-semibold" : "text-muted-foreground"}>
                    Expires in {row.days_until_expiry} days
                  </span>
                )}
              </div>
            )}
          </div>
          {row.cert_subject && (
            <p className="mt-2 text-xs text-muted-foreground truncate">
              Subject: {row.cert_subject}
            </p>
          )}
          {row.deprecated_protocols.length > 0 && (
            <div className="mt-2 flex flex-wrap gap-1">
              {row.deprecated_protocols.map((p) => (
                <span key={p} className="rounded bg-orange-100 text-orange-700 px-2 py-0.5 text-xs font-semibold">
                  {p} enabled
                </span>
              ))}
            </div>
          )}
          {row.weak_ciphers.length > 0 && (
            <div className="mt-2">
              <span className="text-xs text-muted-foreground">Weak ciphers: </span>
              <span className="text-xs text-orange-600">{row.weak_ciphers.join(", ")}</span>
            </div>
          )}
        </div>
      ))}
    </div>
  );
}

// ---------------------------------------------------------------------------
// HVTs tab
// ---------------------------------------------------------------------------

const HVT_SIGNAL_LABELS: Record<string, string> = {
  admin_panel: "Admin Panel",
  login_form: "Login Form",
  signup_form: "Sign-up Form",
  upload_form: "Upload Form",
  api_doc: "API Docs",
  dev_portal: "Dev Portal",
  jenkins: "Jenkins",
  wordpress: "WordPress",
  gitlab: "GitLab",
  k8s_dashboard: "K8s Dashboard",
  exposed_index: "Exposed Index",
  swagger: "Swagger",
  graphql: "GraphQL",
  git_repo: "Git Repo",
  env_file: ".env File",
  other: "Other",
};

const HVT_SIGNAL_COLOR: Record<string, string> = {
  admin_panel: "bg-red-100 text-red-700",
  jenkins: "bg-red-100 text-red-700",
  git_repo: "bg-red-100 text-red-700",
  env_file: "bg-red-100 text-red-700",
  k8s_dashboard: "bg-red-100 text-red-700",
  login_form: "bg-orange-100 text-orange-700",
  upload_form: "bg-orange-100 text-orange-700",
  wordpress: "bg-blue-100 text-blue-700",
  gitlab: "bg-purple-100 text-purple-700",
  api_doc: "bg-blue-100 text-blue-700",
  swagger: "bg-blue-100 text-blue-700",
  graphql: "bg-blue-100 text-blue-700",
};

function HvtsTab({ scanId }: { scanId: string }) {
  const q = useQuery({
    queryKey: ["vuln-hvts", scanId],
    queryFn: () => api<HvtResponse>(`/vuln-scans/${scanId}/hvts`),
  });

  if (q.isLoading) return <p className="mt-4 text-sm text-muted-foreground">Loading…</p>;
  if (q.isError || !q.data) return <p className="mt-4 text-sm text-destructive">Failed to load HVT data.</p>;

  const rows = q.data.rows;
  if (rows.length === 0)
    return (
      <div className="mt-6 rounded-lg border border-dashed border-border p-8 text-center">
        <p className="text-sm text-muted-foreground">No high-value target signals detected. Run panel_detector or swagger_discoverer to populate this tab.</p>
      </div>
    );

  return (
    <div className="mt-4 space-y-3">
      {rows.map((row) => (
        <div key={row.asset_id} className="rounded-lg border border-border bg-card p-4">
          <div className="flex items-start justify-between gap-4 flex-wrap">
            <div className="flex items-center gap-2">
              <Shield className="h-4 w-4 text-muted-foreground" />
              <span className="font-mono text-sm font-medium">{row.asset_label}</span>
            </div>
            <div className="flex items-center gap-2">
              <div className="text-xs text-muted-foreground">HVT score</div>
              <div
                className={`text-sm font-bold tabular-nums ${
                  row.hvt_score > 0.7 ? "text-red-600" : row.hvt_score > 0.4 ? "text-orange-500" : "text-muted-foreground"
                }`}
              >
                {row.hvt_score.toFixed(2)}
              </div>
            </div>
          </div>
          <div className="mt-2 flex flex-wrap gap-1.5">
            {row.signals.map((sig, i) => {
              const colorClass = HVT_SIGNAL_COLOR[sig.signal_type] ?? "bg-gray-100 text-gray-700";
              const label = HVT_SIGNAL_LABELS[sig.signal_type] ?? sig.signal_type;
              return (
                <span
                  key={i}
                  className={`inline-flex items-center rounded-full px-2.5 py-1 text-xs font-semibold ${colorClass}`}
                  title={`Score: ${sig.score.toFixed(2)}, Confidence: ${sig.confidence}%`}
                >
                  {label}
                </span>
              );
            })}
          </div>
        </div>
      ))}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Triage tab
// ---------------------------------------------------------------------------

function TriageTab({ scanId }: { scanId: string }) {
  const q = useQuery({
    queryKey: ["vuln-triage", scanId],
    queryFn: () => api<TriageResponse>(`/vuln-scans/${scanId}/triage`),
  });

  if (q.isLoading) return <p className="mt-4 text-sm text-muted-foreground">Loading triage data…</p>;
  if (q.isError || !q.data) return <p className="mt-4 text-sm text-destructive">Failed to load triage data.</p>;

  const { rows, total_with_risk_score } = q.data;

  if (rows.length === 0)
    return (
      <div className="mt-6 rounded-lg border border-dashed border-border p-8 text-center">
        <p className="text-sm text-muted-foreground">No triage data yet. Risk scores are populated by the correlator stage.</p>
      </div>
    );

  return (
    <div className="mt-4 space-y-4">
      <p className="text-xs text-muted-foreground">
        Top {rows.length} vulnerabilities by composite risk score. {total_with_risk_score} total have been scored.
      </p>
      {rows.map((row, i) => (
        <div key={row.id} className="rounded-lg border border-border bg-card p-4 space-y-2">
          <div className="flex items-start justify-between gap-3 flex-wrap">
            <div className="flex items-center gap-2">
              <span className="text-xs font-mono text-muted-foreground tabular-nums w-5">#{i + 1}</span>
              <SeverityBadge severity={row.severity} />
              <span className="font-medium text-sm">{row.title}</span>
              {row.kev && (
                <span className="rounded bg-red-100 text-red-700 px-1.5 py-0.5 text-xs font-bold">KEV</span>
              )}
            </div>
            <div className="flex items-center gap-3 text-xs text-muted-foreground">
              {row.risk_score != null && (
                <span className="font-semibold text-foreground">Risk: {row.risk_score.toFixed(2)}</span>
              )}
              {row.cvss_v3 != null && <span>CVSS: {row.cvss_v3.toFixed(1)}</span>}
              {row.epss != null && <span>EPSS: {(row.epss * 100).toFixed(1)}%</span>}
              <span className="font-mono">{row.asset_label}</span>
            </div>
          </div>
          {row.cve_ids.length > 0 && <CveBadges ids={row.cve_ids} />}
          {row.description && (
            <p className="text-xs text-muted-foreground leading-relaxed line-clamp-3">
              {row.description}
            </p>
          )}
          {row.remediation && (
            <div className="rounded-md border border-border bg-muted/40 p-3">
              <p className="text-xs font-semibold mb-1">Remediation</p>
              <p className="text-xs text-muted-foreground leading-relaxed">{row.remediation}</p>
            </div>
          )}
        </div>
      ))}
    </div>
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

      {/* HVT + exposure summary */}
      {(d.hvt_count > 0 || d.public_service_count > 0) && (
        <div className="flex flex-wrap gap-3">
          {d.hvt_count > 0 && (
            <div className="inline-flex items-center gap-2 rounded-md border border-orange-300 bg-orange-50 dark:bg-orange-950/20 px-3 py-2">
              <Shield className="h-3.5 w-3.5 text-orange-600" />
              <span className="text-xs text-muted-foreground">HVT signals</span>
              <span className="text-sm font-semibold tabular-nums text-orange-600">{d.hvt_count}</span>
            </div>
          )}
          {d.public_service_count > 0 && (
            <div className="inline-flex items-center gap-2 rounded-md border border-border bg-card px-3 py-2">
              <span className="text-xs text-muted-foreground">Public web services</span>
              <span className="text-sm font-semibold tabular-nums">{d.public_service_count}</span>
            </div>
          )}
        </div>
      )}

      {/* Top 3 risk-scored vulns */}
      {d.top_risk_vulns.length > 0 && (
        <div>
          <h3 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground mb-2">
            Highest Risk
          </h3>
          <div className="space-y-1.5">
            {d.top_risk_vulns.map((v) => (
              <div key={v.id} className="flex items-center gap-2 rounded border border-border bg-card px-3 py-2">
                <SeverityBadge severity={v.severity} />
                <span className="text-sm font-medium flex-1 truncate">{v.title}</span>
                {v.kev && <span className="text-xs font-bold text-red-600">KEV</span>}
                {v.risk_score != null && (
                  <span className="text-xs font-semibold tabular-nums text-muted-foreground">
                    {v.risk_score.toFixed(2)}
                  </span>
                )}
              </div>
            ))}
          </div>
        </div>
      )}
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
  const [kevOnly, setKevOnly] = useState(false);
  const [hvtOnly, setHvtOnly] = useState(false);
  const [offset, setOffset] = useState(0);

  // Reset offset when filters change
  useEffect(() => setOffset(0), [severity, status, kevOnly, hvtOnly]);

  const params = new URLSearchParams({
    offset: String(offset),
    limit: String(PAGE_SIZE),
  });
  if (severity !== "All") params.set("severity", severity);
  if (status !== "All") params.set("status", status);
  if (kevOnly) params.set("kev_only", "true");
  if (hvtOnly) params.set("hvt_only", "true");

  const query = useQuery({
    queryKey: ["vuln-list", scanId, severity, status, kevOnly, hvtOnly, offset],
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
        <button
          onClick={() => setKevOnly(!kevOnly)}
          className={`inline-flex items-center gap-1 rounded-full border px-3 py-1 text-xs font-medium transition-colors ${
            kevOnly
              ? "border-red-400 bg-red-100 text-red-700"
              : "border-border hover:bg-muted"
          }`}
        >
          KEV only
        </button>
        <button
          onClick={() => setHvtOnly(!hvtOnly)}
          className={`inline-flex items-center gap-1 rounded-full border px-3 py-1 text-xs font-medium transition-colors ${
            hvtOnly
              ? "border-orange-400 bg-orange-100 text-orange-700"
              : "border-border hover:bg-muted"
          }`}
        >
          HVT assets only
        </button>
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
                  "Risk",
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
                  <td className="px-3 py-2.5 tabular-nums text-xs">
                    {v.risk_score != null ? v.risk_score.toFixed(2) : "—"}
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

  const VALID_TABS = [
    "overview", "vulnerabilities", "by-service", "by-tech",
    "endpoints", "tls", "hvts", "triage", "diff",
  ];
  const rawTab = searchParams.get("tab");
  const defaultTab = rawTab && VALID_TABS.includes(rawTab) ? rawTab : "overview";

  const scan = useQuery({
    queryKey: ["vuln-scan", params.id],
    queryFn: () => api<VulnScanDetail>(`/vuln-scans/${params.id}`),
  });

  const doDelete = useMutation({
    mutationFn: () => deleteVulnScan(params.id),
    onSuccess: () => router.push("/vuln-scans"),
    onError: (e) => alert((e as Error).message),
  });

  // SSE subscription while scan is running
  useEffect(() => {
    const status = scan.data?.status;
    if (!status || status === "completed" || status === "failed") return;

    const es = new EventSource(sseUrl(`/vuln-scans/${params.id}/stream`), { withCredentials: true });
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
        <div className="flex items-center gap-2">
          {canDeleteScan(s.status) && (
            <Button
              variant="outline"
              size="sm"
              className="text-destructive hover:text-destructive"
              onClick={() => {
                if (
                  confirm(
                    `Delete vuln scan for ${s.target_domain}? Removes all stages, vuln evidence, and matches.`,
                  )
                ) {
                  doDelete.mutate();
                }
              }}
              disabled={doDelete.isPending}
            >
              <Trash2 className="h-4 w-4" /> Delete vuln scan
            </Button>
          )}
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
        <TabsList className="flex-wrap h-auto">
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="vulnerabilities">Vulnerabilities</TabsTrigger>
          <TabsTrigger value="by-service">
            <Server className="h-3.5 w-3.5 mr-1.5" />
            By Service
          </TabsTrigger>
          <TabsTrigger value="by-tech">
            <Cpu className="h-3.5 w-3.5 mr-1.5" />
            By Tech
          </TabsTrigger>
          <TabsTrigger value="endpoints">
            <Network className="h-3.5 w-3.5 mr-1.5" />
            Endpoints
          </TabsTrigger>
          <TabsTrigger value="tls">
            <Lock className="h-3.5 w-3.5 mr-1.5" />
            TLS
          </TabsTrigger>
          <TabsTrigger value="hvts">
            <Shield className="h-3.5 w-3.5 mr-1.5" />
            HVTs
          </TabsTrigger>
          <TabsTrigger value="triage">
            <Brain className="h-3.5 w-3.5 mr-1.5" />
            Triage
          </TabsTrigger>
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
        <TabsContent value="by-service">
          <ByServiceTab scanId={params.id} />
        </TabsContent>
        <TabsContent value="by-tech">
          <ByTechTab scanId={params.id} />
        </TabsContent>
        <TabsContent value="endpoints">
          <EndpointsTab scanId={params.id} />
        </TabsContent>
        <TabsContent value="tls">
          <TlsTab scanId={params.id} />
        </TabsContent>
        <TabsContent value="hvts">
          <HvtsTab scanId={params.id} />
        </TabsContent>
        <TabsContent value="triage">
          <TriageTab scanId={params.id} />
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
