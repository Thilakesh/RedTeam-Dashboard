"use client";

import { useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import Link from "next/link";
import { ArrowLeft, Rocket } from "lucide-react";
import { AppShell } from "@/components/AppShell";
import { Badge } from "@/components/ui/badge";
import { NmapResult } from "@/components/workspace/tool-results/NmapResult";
import { EndpointsResult } from "@/components/workspace/tool-results/EndpointsResult";
import { TestSslResult } from "@/components/workspace/tool-results/TestSslResult";
import { RawOutputCollapsible } from "@/components/workspace/tool-results/RawOutputCollapsible";
import {
  TOOL_LABELS,
  getOperation,
  type InvestigationFindingOut,
  type OperationFinding,
  type OperationStatus,
} from "@/lib/api";

const STATUS_VARIANT: Record<
  OperationStatus,
  "default" | "warning" | "success" | "destructive" | "outline"
> = {
  queued: "outline",
  running: "warning",
  completed: "success",
  failed: "destructive",
  cancelled: "default",
};

function fmtDuration(s: number | null): string {
  if (s === null) return "—";
  if (s < 1) return "<1s";
  if (s < 60) return `${s.toFixed(0)}s`;
  return `${Math.floor(s / 60)}m ${Math.round(s % 60)}s`;
}

// The per-tool result components are typed against InvestigationFindingOut.
// Operation findings carry the same fields minus task_id/asset_id.
function asFindings(rows: OperationFinding[]): InvestigationFindingOut[] {
  return rows.map((f) => ({
    id: f.id,
    task_id: f.operation_id,
    asset_id: "",
    kind: f.kind,
    severity: f.severity,
    title: f.title,
    description: f.description,
    evidence: f.evidence,
    created_at: f.created_at,
  }));
}

function ResultContent({ params }: { params: { operation_id: string } }) {
  const q = useQuery({
    queryKey: ["operation", params.operation_id],
    queryFn: () => getOperation(params.operation_id),
    refetchInterval: (query) => {
      const s = query.state.data?.operation.status;
      return s === "queued" || s === "running" ? 4000 : false;
    },
  });

  const findings = useMemo(
    () => asFindings(q.data?.findings ?? []),
    [q.data?.findings],
  );

  if (q.isLoading) {
    return <div className="p-6 text-sm text-muted-foreground">Loading…</div>;
  }
  if (q.isError || !q.data) {
    return <div className="p-6 text-sm text-destructive">Failed to load operation.</div>;
  }

  const { operation, raw_output } = q.data;
  const toolLabel = TOOL_LABELS[operation.tool] ?? operation.tool;
  const active = operation.status === "queued" || operation.status === "running";

  return (
    <div className="container mx-auto max-w-5xl space-y-5">
      <Link
        href="/operations"
        className="inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground"
      >
        <ArrowLeft className="h-4 w-4" />
        Back to Operation History
      </Link>

      <header className="rounded-lg border border-border bg-card p-4 space-y-3">
        <div className="flex items-start justify-between gap-3">
          <div className="space-y-1">
            <div className="flex items-center gap-2 text-xs text-muted-foreground">
              <Rocket className="h-3.5 w-3.5" />
              Operation
            </div>
            <h1 className="text-xl font-semibold flex items-center gap-2">
              {toolLabel}
              <Badge variant="outline" className="font-mono">
                {operation.target}
              </Badge>
            </h1>
          </div>
          <Badge variant={STATUS_VARIANT[operation.status]}>{operation.status}</Badge>
        </div>

        <dl className="grid grid-cols-2 md:grid-cols-4 gap-3 text-sm">
          <Metric label="Profile" value={operation.profile ?? "—"} />
          <Metric label="Findings" value={(q.data.findings.length).toString()} />
          <Metric label="Duration" value={fmtDuration(operation.duration_s)} />
          <Metric
            label="Started"
            value={operation.started_at ? new Date(operation.started_at).toLocaleString() : "—"}
          />
        </dl>

        {operation.generated_command && (
          <div>
            <div className="text-xxs uppercase text-muted-foreground mb-1">Command</div>
            <pre className="rounded-md border border-border bg-muted/30 px-3 py-2 text-xs font-mono whitespace-pre-wrap break-all">
              {operation.generated_command}
            </pre>
          </div>
        )}

        {operation.error && (
          <div className="rounded-md border border-destructive/40 bg-destructive/5 p-3 text-sm">
            <strong>Error:</strong> {operation.error}
          </div>
        )}
      </header>

      <section>
        {active ? (
          <div className="rounded-md border border-border bg-muted/30 p-4 text-sm text-muted-foreground">
            Operation is {operation.status}. Results appear once it completes (page
            polls every 4s).
          </div>
        ) : operation.tool === "nmap_deep" ? (
          <NmapResult findings={findings} />
        ) : operation.tool === "ffuf" || operation.tool === "dirsearch" ? (
          <EndpointsResult findings={findings} tool={operation.tool} />
        ) : operation.tool === "testssl" ? (
          <TestSslResult findings={findings} />
        ) : (
          <div className="rounded-md border border-border p-4 text-sm">
            No result renderer for tool '{operation.tool}'.
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

export default function OperationResultPage({
  params,
}: {
  params: { operation_id: string };
}) {
  return (
    <AppShell>
      <ResultContent params={params} />
    </AppShell>
  );
}
