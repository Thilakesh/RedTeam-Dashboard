"use client";

import { useQuery } from "@tanstack/react-query";
import {
  Bar,
  BarChart,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip as RTooltip,
  XAxis,
  YAxis,
} from "recharts";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Cloud, Globe2, Layers, ShieldAlert, ShieldCheck, Wrench } from "lucide-react";
import Link from "next/link";
import { api, type FindingsPage, type ScanDetail, type ScanOverview } from "@/lib/api";

const STATUS_COLORS: Record<string, string> = {
  "2xx": "hsl(var(--success))",
  "3xx": "hsl(var(--warning))",
  "4xx": "hsl(var(--destructive))",
  "5xx": "#a21caf",
  "no probe": "hsl(var(--muted-foreground))",
  other: "hsl(var(--info))",
};

export function OverviewTab({ scanId, scan }: { scanId: string; scan?: ScanDetail }) {
  const { data, isLoading } = useQuery({
    queryKey: ["scan-overview", scanId],
    queryFn: () => api<ScanOverview>(`/scans/${scanId}/overview`),
  });

  const risksQuery = useQuery({
    queryKey: ["scan-findings", scanId, "HIGH", 1],
    queryFn: () =>
      api<FindingsPage>(`/scans/${scanId}/findings?severity=HIGH&limit=5`),
    enabled: scan?.profile === "deep" && scan?.status === "completed",
  });

  if (isLoading || !data) {
    return <p className="text-sm text-muted-foreground">Loading overview…</p>;
  }

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        <CountCard label="Subdomains" value={data.subdomain_count} icon={Layers} tone="text-primary bg-primary/10" />
        <CountCard label="IPs" value={data.ip_count} icon={Globe2} tone="text-info bg-info/10" />
        <CountCard label="Behind CDN" value={data.cdn_count} icon={Cloud} tone="text-info bg-info/10" />
        <CountCard label="With WAF" value={data.waf_count} icon={ShieldCheck} tone="text-success bg-success/10" />
        <CountCard label="Technologies" value={data.tech_count} icon={Wrench} tone="text-warning bg-warning/10" />
      </div>

      {/* Top Risks — only for completed deep scans */}
      {scan?.profile === "deep" && scan?.status === "completed" && (
        <Card>
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <div className="flex items-center gap-2">
              <ShieldAlert className="h-4 w-4 text-destructive" />
              <CardTitle>Top Risks</CardTitle>
            </div>
            <Link
              href={`/scans/${scanId}?tab=risks`}
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
                No HIGH severity findings.
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
                      <div
                        className="truncate font-mono text-xs font-medium"
                        title={finding.fqdn}
                      >
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

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <Card>
          <CardHeader><CardTitle>HTTP status distribution</CardTitle></CardHeader>
          <CardContent>
            <div style={{ width: "100%", height: 220 }}>
              <ResponsiveContainer>
                <PieChart>
                  <Pie
                    data={data.http_status_buckets}
                    dataKey="count"
                    nameKey="label"
                    innerRadius={50}
                    outerRadius={80}
                    paddingAngle={2}
                  >
                    {data.http_status_buckets.map((b) => (
                      <Cell key={b.label} fill={STATUS_COLORS[b.label] ?? "hsl(var(--info))"} />
                    ))}
                  </Pie>
                  <RTooltip contentStyle={{ background: "hsl(var(--card))", border: "1px solid hsl(var(--border))" }} />
                </PieChart>
              </ResponsiveContainer>
              <div className="flex flex-wrap gap-3 justify-center text-xs mt-2">
                {data.http_status_buckets.map((b) => (
                  <span key={b.label} className="flex items-center gap-1.5">
                    <span className="h-2 w-2 rounded-sm" style={{ background: STATUS_COLORS[b.label] }} />
                    {b.label}: <span className="font-medium">{b.count}</span>
                  </span>
                ))}
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader><CardTitle>Top technologies</CardTitle></CardHeader>
          <CardContent>
            <BarList data={data.top_tech} />
          </CardContent>
        </Card>

        <Card>
          <CardHeader><CardTitle>Top ASNs</CardTitle></CardHeader>
          <CardContent>
            <BarList data={data.top_asn} />
          </CardContent>
        </Card>
      </div>

      {scan?.stages?.length ? (
        <Card>
          <CardHeader><CardTitle>Stage timeline</CardTitle></CardHeader>
          <CardContent>
            <ul className="space-y-2 text-sm">
              {scan.stages.map((s) => {
                const ms = s.started_at && s.finished_at
                  ? new Date(s.finished_at).getTime() - new Date(s.started_at).getTime()
                  : null;
                return (
                  <li key={s.id} className="flex items-center justify-between border border-border rounded-md px-3 py-2">
                    <span className="font-mono text-xs">{s.stage_name}</span>
                    <span className={
                      s.status === "completed" ? "text-success" :
                      s.status === "failed" ? "text-destructive" :
                      s.status === "running" ? "text-warning" : "text-muted-foreground"
                    }>
                      {s.status}{ms != null ? ` · ${(ms / 1000).toFixed(1)}s` : ""}
                    </span>
                  </li>
                );
              })}
            </ul>
          </CardContent>
        </Card>
      ) : null}
    </div>
  );
}

function CountCard({
  label,
  value,
  icon: Icon,
  tone,
}: {
  label: string;
  value: number;
  icon: React.ComponentType<{ className?: string }>;
  tone: string;
}) {
  return (
    <div className="rounded-lg border border-border bg-card px-4 py-3">
      <div className={`h-8 w-8 rounded-md flex items-center justify-center mb-2.5 ${tone}`}>
        <Icon className="h-4 w-4" />
      </div>
      <div className="text-2xl font-semibold tabular-nums">{value}</div>
      <div className="text-xs text-muted-foreground mt-0.5">{label}</div>
    </div>
  );
}

function BarList({ data }: { data: { label: string; count: number }[] }) {
  if (!data.length) return <p className="text-xs text-muted-foreground">No data.</p>;
  return (
    <div style={{ width: "100%", height: 220 }}>
      <ResponsiveContainer>
        <BarChart data={data.slice(0, 8)} layout="vertical" margin={{ left: 8, right: 8 }}>
          <XAxis type="number" hide />
          <YAxis dataKey="label" type="category" width={120} tick={{ fontSize: 11, fill: "hsl(var(--muted-foreground))" }} />
          <RTooltip contentStyle={{ background: "hsl(var(--card))", border: "1px solid hsl(var(--border))" }} />
          <Bar dataKey="count" fill="hsl(var(--primary))" radius={[0, 4, 4, 0]} />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}
