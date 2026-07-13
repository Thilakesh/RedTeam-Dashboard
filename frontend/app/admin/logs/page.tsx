"use client";

import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { ExternalLink } from "lucide-react";
import { AppShell } from "@/components/AppShell";
import { listToolExecutions, type ToolExecutionOut } from "@/lib/api";

const inputClass =
  "bg-background border border-border rounded px-3 py-2 text-sm text-foreground placeholder:text-muted-foreground";

const SOURCE_LABELS: Record<ToolExecutionOut["source"], string> = {
  operation: "Operation",
  investigation_task: "Investigation",
  scan_stage: "Recon Stage",
};

function statusClass(status: string): string {
  if (status === "failed") return "bg-red-500/10 text-red-500";
  if (status === "completed") return "bg-emerald-500/10 text-emerald-500";
  if (status === "running") return "bg-blue-500/10 text-blue-500";
  return "bg-muted text-muted-foreground";
}

export default function AdminLogsPage() {
  const [tool, setTool] = useState("");
  const [status, setStatus] = useState("");
  const [from, setFrom] = useState("");
  const [to, setTo] = useState("");

  const grafanaUrl = process.env.NEXT_PUBLIC_GRAFANA_URL;

  const logs = useQuery({
    queryKey: ["admin", "tool-executions", tool, status, from, to],
    queryFn: () =>
      listToolExecutions({
        tool: tool || undefined,
        status: status || undefined,
        from: from ? new Date(from).toISOString() : undefined,
        to: to ? new Date(to).toISOString() : undefined,
      }),
    refetchInterval: 10_000,
  });

  return (
    <AppShell>
      <div className="space-y-6">
        <header className="flex items-start justify-between gap-4">
          <div>
            <h1 className="text-2xl font-semibold tracking-tight">Tool Executions</h1>
            <p className="text-sm text-muted-foreground mt-1">
              Recon stages, investigation tasks, and operations — org-scoped, from Postgres.
            </p>
          </div>
          {grafanaUrl && (
            <a
              href={grafanaUrl}
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-center gap-1.5 text-sm text-primary hover:underline shrink-0 mt-1"
            >
              Deep search in Grafana <ExternalLink className="h-3.5 w-3.5" />
            </a>
          )}
        </header>

        <div className="flex flex-wrap items-center gap-3">
          <input
            value={tool}
            onChange={(e) => setTool(e.target.value)}
            placeholder="filter tool (e.g. nmap_deep)"
            className={`${inputClass} w-64`}
          />
          <input
            value={status}
            onChange={(e) => setStatus(e.target.value)}
            placeholder="filter status (e.g. failed)"
            className={`${inputClass} w-64`}
          />
          <label className="flex items-center gap-1.5 text-xs text-muted-foreground">
            From
            <input
              type="datetime-local"
              value={from}
              onChange={(e) => setFrom(e.target.value)}
              className={inputClass}
            />
          </label>
          <label className="flex items-center gap-1.5 text-xs text-muted-foreground">
            To
            <input
              type="datetime-local"
              value={to}
              onChange={(e) => setTo(e.target.value)}
              className={inputClass}
            />
          </label>
        </div>

        <div className="rounded-lg border border-border bg-card overflow-auto">
          <table className="w-full text-sm">
            <thead className="bg-muted/40 text-xs uppercase text-muted-foreground">
              <tr>
                <th className="text-left px-3 py-2">When</th>
                <th className="text-left px-3 py-2">Source</th>
                <th className="text-left px-3 py-2">Tool</th>
                <th className="text-left px-3 py-2">Target</th>
                <th className="text-left px-3 py-2">Status</th>
                <th className="text-left px-3 py-2">Exit</th>
                <th className="text-left px-3 py-2">Error / stderr</th>
                <th className="text-left px-3 py-2">Full output</th>
              </tr>
            </thead>
            <tbody>
              {logs.data?.map((r) => (
                <tr key={`${r.source}-${r.id}`} className="border-t border-border align-top">
                  <td className="px-3 py-2 whitespace-nowrap text-xs">
                    {new Date(r.created_at).toLocaleString()}
                  </td>
                  <td className="px-3 py-2 text-xs text-muted-foreground">
                    {SOURCE_LABELS[r.source]}
                  </td>
                  <td className="px-3 py-2 font-medium text-xs">{r.tool}</td>
                  <td className="px-3 py-2 font-mono text-xs">{r.target || "—"}</td>
                  <td className="px-3 py-2">
                    <span className={`px-1.5 py-0.5 rounded text-xs font-medium ${statusClass(r.status)}`}>
                      {r.status}
                    </span>
                  </td>
                  <td className="px-3 py-2 font-mono text-xs">{r.exit_code ?? "—"}</td>
                  <td className="px-3 py-2 font-mono text-xs text-muted-foreground max-w-md truncate" title={r.error || r.stderr_preview || undefined}>
                    {r.error || r.stderr_preview || "—"}
                  </td>
                  <td className="px-3 py-2 text-xs">
                    <div className="flex gap-2">
                      {r.stdout_url && (
                        <a href={r.stdout_url} target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">
                          stdout
                        </a>
                      )}
                      {r.stderr_url && (
                        <a href={r.stderr_url} target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">
                          stderr
                        </a>
                      )}
                      {!r.stdout_url && !r.stderr_url && "—"}
                    </div>
                  </td>
                </tr>
              ))}
              {logs.data?.length === 0 && (
                <tr>
                  <td colSpan={8} className="px-3 py-8 text-center text-sm text-muted-foreground">
                    No tool executions match these filters.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </AppShell>
  );
}
