"use client";

import { Suspense, useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import Link from "next/link";
import { ArrowLeft, Crosshair } from "lucide-react";
import { AppShell } from "@/components/AppShell";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { NmapResult } from "@/components/workspace/tool-results/NmapResult";
import { FfufResult } from "@/components/workspace/tool-results/FfufResult";
import { DirsearchResult } from "@/components/workspace/tool-results/DirsearchResult";
import { TestSslResult } from "@/components/workspace/tool-results/TestSslResult";
import { RawOutputCollapsible } from "@/components/workspace/tool-results/RawOutputCollapsible";
import {
  TOOL_LABELS,
  getInvestigationTask,
  listWorkspaces,
  type InvestigationTaskOut,
} from "@/lib/api";

const TASK_STATUS_VARIANT: Record<
  InvestigationTaskOut["status"],
  "success" | "warning" | "destructive" | "default"
> = {
  queued: "default",
  running: "warning",
  completed: "success",
  failed: "destructive",
  cancelled: "default",
};

function formatDuration(seconds: number | null): string {
  if (seconds === null) return "—";
  if (seconds < 1) return "<1s";
  if (seconds < 60) return `${seconds.toFixed(0)}s`;
  const m = Math.floor(seconds / 60);
  const s = Math.round(seconds % 60);
  return `${m}m ${s}s`;
}

function TaskContent({
  params,
}: {
  params: { id: string; task_id: string };
}) {
  // Resolve workspace_id from target_id via /target-workspaces listing.
  const wsQ = useQuery({
    queryKey: ["workspaces"],
    queryFn: listWorkspaces,
  });
  const workspace = useMemo(
    () => (wsQ.data ?? []).find((w) => w.target_id === params.id),
    [wsQ.data, params.id],
  );
  const wsId = workspace?.id;

  const taskQ = useQuery({
    enabled: !!wsId,
    queryKey: ["investigation-task", wsId, params.task_id],
    queryFn: () => getInvestigationTask(wsId!, params.task_id),
    refetchInterval: (q) => {
      const data = q.state.data;
      if (!data) return 3000;
      return data.task.status === "queued" || data.task.status === "running"
        ? 3000
        : false;
    },
  });

  if (wsQ.isLoading || (taskQ.isLoading && !taskQ.data)) {
    return <div className="p-6 text-sm text-muted-foreground">Loading…</div>;
  }
  if (!workspace) {
    return (
      <div className="p-6 text-sm text-destructive">
        No workspace found for this target.
      </div>
    );
  }
  if (taskQ.isError || !taskQ.data) {
    return (
      <div className="p-6 text-sm text-destructive">
        Failed to load investigation task.
      </div>
    );
  }

  const { task, findings, raw_output } = taskQ.data;
  const toolLabel = TOOL_LABELS[task.tool] ?? task.tool;

  return (
    <div className="container mx-auto max-w-5xl p-6 space-y-5">
      <div>
        <Link
          href={`/targets/${params.id}/workspace?tab=tasks&w=${wsId}`}
          className="inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground"
        >
          <ArrowLeft className="h-4 w-4" />
          Back to workspace
        </Link>
      </div>

      <header className="rounded-lg border border-border bg-card p-4 space-y-3">
        <div className="flex items-start justify-between gap-3">
          <div className="space-y-1">
            <div className="flex items-center gap-2 text-xs text-muted-foreground">
              <Crosshair className="h-3.5 w-3.5" />
              {workspace.label}
            </div>
            <h1 className="text-xl font-semibold flex items-center gap-2">
              {toolLabel}
              <Badge variant="outline" className="font-mono">
                {task.asset_label}
              </Badge>
            </h1>
          </div>
          <Badge variant={TASK_STATUS_VARIANT[task.status]}>{task.status}</Badge>
        </div>

        <dl className="grid grid-cols-2 md:grid-cols-4 gap-3 text-sm">
          <Metric label="Findings" value={findings.length.toString()} />
          <Metric label="Duration" value={formatDuration(task.duration_s)} />
          <Metric label="Progress" value={`${task.progress_pct}%`} />
          <Metric
            label="Started"
            value={
              task.started_at
                ? new Date(task.started_at).toLocaleString()
                : "—"
            }
          />
        </dl>

        {task.error && (
          <div className="rounded-md border border-destructive/40 bg-destructive/5 p-3 text-sm">
            <strong>Error:</strong> {task.error}
          </div>
        )}
      </header>

      <section>
        {task.status === "queued" || task.status === "running" ? (
          <div className="rounded-md border border-border bg-muted/30 p-4 text-sm text-muted-foreground">
            Task is {task.status}. Results will appear once it completes (page
            polls every 3s).
          </div>
        ) : task.tool === "nmap_deep" ? (
          <NmapResult findings={findings} />
        ) : task.tool === "ffuf" ? (
          <FfufResult findings={findings} />
        ) : task.tool === "dirsearch" ? (
          <DirsearchResult findings={findings} />
        ) : task.tool === "testssl" ? (
          <TestSslResult findings={findings} />
        ) : (
          <div className="rounded-md border border-border p-4 text-sm">
            No result renderer for tool '{task.tool}'.
          </div>
        )}
      </section>

      <RawOutputCollapsible content={raw_output} />
    </div>
  );
}

function Metric({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <dt className="text-xs uppercase text-muted-foreground">{label}</dt>
      <dd className="font-medium">{value}</dd>
    </div>
  );
}

export default function TaskPage({
  params,
}: {
  params: { id: string; task_id: string };
}) {
  return (
    <AppShell>
      <Suspense fallback={<div className="p-6">Loading…</div>}>
        <TaskContent params={params} />
      </Suspense>
    </AppShell>
  );
}
