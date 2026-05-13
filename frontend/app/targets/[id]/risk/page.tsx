"use client";

import { useQuery } from "@tanstack/react-query";
import Link from "next/link";
import { ArrowLeft, Shield, Globe, ExternalLink } from "lucide-react";
import { AppShell } from "@/components/AppShell";
import { api, type TargetRiskView } from "@/lib/api";

const SEVERITY_COLOR: Record<string, string> = {
  critical: "text-red-600 bg-red-50 border-red-200",
  high: "text-orange-500 bg-orange-50 border-orange-200",
  med: "text-yellow-600 bg-yellow-50 border-yellow-200",
  low: "text-blue-500 bg-blue-50 border-blue-200",
  info: "text-gray-500 bg-gray-50 border-gray-200",
};

const SEVERITY_LABEL: Record<string, string> = {
  critical: "CRITICAL", high: "HIGH", med: "MED", low: "LOW", info: "INFO",
};

export default function TargetRiskPage({
  params,
}: {
  params: { id: string };
}) {
  const q = useQuery({
    queryKey: ["target-risk", params.id],
    queryFn: () => api<TargetRiskView>(`/targets/${params.id}/risk`),
  });

  if (q.isLoading || !q.data) {
    return (
      <AppShell>
        <p className="text-sm text-muted-foreground">Loading risk view…</p>
      </AppShell>
    );
  }

  const d = q.data;
  const totalOpen = Object.values(d.open_counts).reduce((a, b) => a + b, 0);

  return (
    <AppShell>
      <div className="mb-6">
        <Link
          href="/targets"
          className="inline-flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground mb-4"
        >
          <ArrowLeft className="h-3.5 w-3.5" />
          Back to Targets
        </Link>
        <div className="flex items-center gap-3">
          <Globe className="h-5 w-5 text-primary" />
          <h1 className="text-2xl font-semibold tracking-tight">{d.target_domain}</h1>
        </div>
        <p className="mt-1 text-sm text-muted-foreground">Risk Rollup — continuous monitoring view</p>
      </div>

      {/* Open vuln severity cards */}
      <section className="mb-8">
        <h2 className="text-sm font-semibold uppercase tracking-wide text-muted-foreground mb-3">
          Open Vulnerabilities ({totalOpen})
        </h2>
        <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
          {["critical", "high", "med", "low", "info"].map((sev) => (
            <div
              key={sev}
              className={`rounded-lg border px-4 py-3 flex flex-col gap-1 ${SEVERITY_COLOR[sev]}`}
            >
              <div className="text-xs font-semibold uppercase tracking-wide">
                {SEVERITY_LABEL[sev]}
              </div>
              <div className="text-2xl font-bold tabular-nums leading-none">
                {d.open_counts[sev] ?? 0}
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* HVT inventory */}
      {d.hvt_count > 0 && (
        <section className="mb-8">
          <h2 className="text-sm font-semibold uppercase tracking-wide text-muted-foreground mb-3">
            HVT Signals ({d.hvt_count})
          </h2>
          <div className="flex flex-wrap gap-2">
            {Object.entries(d.hvt_signal_summary)
              .sort(([, a], [, b]) => b - a)
              .map(([type, count]) => (
                <div
                  key={type}
                  className="inline-flex items-center gap-1.5 rounded-full border border-orange-300 bg-orange-50 dark:bg-orange-950/20 px-3 py-1"
                >
                  <Shield className="h-3 w-3 text-orange-600" />
                  <span className="text-xs font-medium">{type.replace(/_/g, " ")}</span>
                  <span className="text-xs font-bold text-orange-700">{count}</span>
                </div>
              ))}
          </div>
        </section>
      )}

      {/* Endpoint surface */}
      <section className="mb-8">
        <div className="inline-flex items-center gap-2 rounded-md border border-border bg-card px-4 py-3">
          <span className="text-xs text-muted-foreground">Discovered endpoints</span>
          <span className="text-lg font-bold tabular-nums">{d.endpoint_count}</span>
        </div>
      </section>

      {/* Top 10 by risk score */}
      {d.top_risk_vulns.length > 0 && (
        <section className="mb-8">
          <h2 className="text-sm font-semibold uppercase tracking-wide text-muted-foreground mb-3">
            Highest Risk Findings
          </h2>
          <div className="rounded-lg border border-border overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="bg-muted/50 border-b border-border">
                <tr>
                  {["Severity", "Title", "Asset", "Risk Score", "Status"].map((h) => (
                    <th
                      key={h}
                      className="px-3 py-2.5 text-left text-xs font-medium uppercase tracking-wide text-muted-foreground whitespace-nowrap"
                    >
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {d.top_risk_vulns.map((v) => (
                  <tr key={v.id} className="border-b border-border hover:bg-muted/30">
                    <td className="px-3 py-2.5">
                      <span
                        className={`inline-flex items-center rounded-md border px-2 py-0.5 text-xs font-semibold ${
                          SEVERITY_COLOR[v.severity.toLowerCase()] ?? "text-gray-500 bg-gray-100 border-gray-300"
                        }`}
                      >
                        {v.severity}
                      </span>
                    </td>
                    <td className="px-3 py-2.5 font-medium max-w-[260px]">
                      <span className="truncate block" title={v.title}>
                        {v.title}
                      </span>
                      {v.kev && (
                        <span className="text-xs text-red-600 font-semibold">KEV</span>
                      )}
                    </td>
                    <td className="px-3 py-2.5 text-xs font-mono text-muted-foreground max-w-[160px] truncate">
                      {v.asset_label}
                    </td>
                    <td className="px-3 py-2.5 tabular-nums text-xs font-semibold">
                      {v.risk_score != null ? v.risk_score.toFixed(2) : "—"}
                    </td>
                    <td className="px-3 py-2.5 text-xs text-muted-foreground">
                      {v.status.replace(/_/g, " ")}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}

      {/* Latest vuln scan link */}
      {d.latest_vuln_scan_id && (
        <section>
          <div className="inline-flex items-center gap-2 text-sm">
            <span className="text-muted-foreground">Latest vuln scan:</span>
            <Link
              href={`/vuln-scans/${d.latest_vuln_scan_id}`}
              className="inline-flex items-center gap-1 text-primary hover:underline"
            >
              {d.latest_vuln_scan_status}
              <ExternalLink className="h-3 w-3" />
            </Link>
            {d.latest_vuln_scan_created_at && (
              <span className="text-xs text-muted-foreground">
                {new Date(d.latest_vuln_scan_created_at).toLocaleDateString()}
              </span>
            )}
          </div>
        </section>
      )}
    </AppShell>
  );
}
