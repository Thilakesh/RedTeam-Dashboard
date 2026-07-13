"use client";

import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { ChevronLeft, ChevronRight, ShieldAlert } from "lucide-react";
import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip as RTooltip } from "recharts";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { ApiError, api, type FindingRow, type FindingsPage } from "@/lib/api";

const SEVERITY_ORDER = ["HIGH", "MED", "LOW", "INFO"] as const;

const SEVERITY_COLORS: Record<string, string> = {
  HIGH: "bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400",
  MED: "bg-amber-100 text-amber-800 dark:bg-amber-900/30 dark:text-amber-400",
  LOW: "bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-400",
  INFO: "bg-muted text-muted-foreground",
};

const SEVERITY_DOT: Record<string, string> = {
  HIGH: "bg-red-500",
  MED: "bg-amber-500",
  LOW: "bg-blue-500",
  INFO: "bg-muted-foreground/50",
};

const SEVERITY_CHART_COLOR: Record<string, string> = {
  HIGH: "hsl(var(--destructive))",
  MED: "hsl(var(--warning))",
  LOW: "hsl(var(--info))",
  INFO: "hsl(var(--muted-foreground) / 0.5)",
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

  if (query.isError) {
    return (
      <p className="text-sm text-destructive py-6">
        {query.error instanceof ApiError
          ? `Failed to load findings (${query.error.status}).`
          : "Failed to load findings. Please try refreshing."}
      </p>
    );
  }

  const { total = 0, items = [], severity_counts = {} } = query.data ?? {};
  const totalPages = Math.max(1, Math.ceil(total / limit));
  const totalFindings = Object.values(severity_counts).reduce((a, b) => a + b, 0);

  return (
    <div className="space-y-4">
      {totalFindings > 0 && (
        <Card>
          <CardHeader><CardTitle>Findings by severity</CardTitle></CardHeader>
          <CardContent>
            <div className="flex items-center gap-6">
              <div style={{ width: 132, height: 132 }} className="shrink-0 relative">
                <ResponsiveContainer>
                  <PieChart>
                    <Pie
                      data={SEVERITY_ORDER.map((sev) => ({ sev, count: severity_counts[sev] ?? 0 }))}
                      dataKey="count"
                      nameKey="sev"
                      innerRadius={44}
                      outerRadius={62}
                      paddingAngle={2}
                    >
                      {SEVERITY_ORDER.map((sev) => (
                        <Cell key={sev} fill={SEVERITY_CHART_COLOR[sev]} />
                      ))}
                    </Pie>
                    <RTooltip contentStyle={{ background: "hsl(var(--card))", border: "1px solid hsl(var(--border))" }} />
                  </PieChart>
                </ResponsiveContainer>
                <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
                  <span className="text-xl font-semibold tabular-nums">{totalFindings}</span>
                  <span className="text-[10px] text-muted-foreground">findings</span>
                </div>
              </div>
              <div className="flex-1 space-y-2.5">
                {SEVERITY_ORDER.map((sev) => {
                  const count = severity_counts[sev] ?? 0;
                  const pct = totalFindings > 0 ? Math.round((count / totalFindings) * 100) : 0;
                  return (
                    <div key={sev} className="flex items-center justify-between text-sm">
                      <span className="flex items-center gap-2">
                        <i className={`h-2.5 w-2.5 rounded-sm inline-block ${SEVERITY_DOT[sev]}`} />
                        {sev}
                      </span>
                      <span>
                        <span className="font-semibold tabular-nums">{count}</span>
                        <span className="text-muted-foreground text-xs ml-1.5">{pct}%</span>
                      </span>
                    </div>
                  );
                })}
              </div>
            </div>
          </CardContent>
        </Card>
      )}

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
                    <td className="px-3 py-2 text-xs tabular-nums">{row.risk_score?.toFixed(2) ?? "—"}</td>
                    <td
                      className="px-3 py-2 text-xs max-w-xs truncate text-muted-foreground"
                      title={row.rationale}
                    >
                      {row.rationale}
                    </td>
                    <td
                      className="px-3 py-2 text-xs max-w-xs truncate"
                      title={row.recommended_action}
                    >
                      {row.recommended_action}
                    </td>
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
