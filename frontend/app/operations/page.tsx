"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import Link from "next/link";
import { Ban, Eye, Plus, RotateCcw } from "lucide-react";
import { AppShell } from "@/components/AppShell";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  TOOL_LABELS,
  cancelOperation,
  listOperations,
  retryOperation,
  type Operation,
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

function OperationsTable() {
  const qc = useQueryClient();
  const q = useQuery({
    queryKey: ["operations"],
    queryFn: listOperations,
    refetchInterval: (query) => {
      const rows = query.state.data?.rows ?? [];
      return rows.some((o) => o.status === "queued" || o.status === "running")
        ? 4000
        : false;
    },
  });

  const invalidate = () => qc.invalidateQueries({ queryKey: ["operations"] });
  const cancelMut = useMutation({
    mutationFn: cancelOperation,
    onSuccess: invalidate,
  });
  const retryMut = useMutation({
    mutationFn: retryOperation,
    onSuccess: invalidate,
  });

  const rows = q.data?.rows ?? [];

  return (
    <div className="container mx-auto max-w-6xl space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold">Operation History</h1>
          <p className="text-sm text-muted-foreground">
            Centralized history of standalone manual operations.
          </p>
        </div>
        <Link
          href="/operations/launch"
          className="inline-flex items-center gap-1.5 h-9 px-3 rounded-md bg-primary text-primary-foreground text-sm font-medium hover:bg-primary/90"
        >
          <Plus className="h-4 w-4" /> Launch Operation
        </Link>
      </div>

      <div className="rounded-md border border-border overflow-hidden">
        <table className="w-full text-sm">
          <thead className="bg-muted/40 text-xs uppercase text-muted-foreground">
            <tr>
              <th className="text-left px-3 py-2 font-medium">Operation ID</th>
              <th className="text-left px-3 py-2 font-medium">Target</th>
              <th className="text-left px-3 py-2 font-medium">Tool</th>
              <th className="text-left px-3 py-2 font-medium">Profile</th>
              <th className="text-left px-3 py-2 font-medium">Status</th>
              <th className="text-left px-3 py-2 font-medium">Duration</th>
              <th className="text-left px-3 py-2 font-medium">Started</th>
              <th className="text-right px-3 py-2 font-medium">Actions</th>
            </tr>
          </thead>
          <tbody>
            {q.isLoading && (
              <tr>
                <td colSpan={8} className="px-3 py-6 text-center text-muted-foreground">
                  Loading…
                </td>
              </tr>
            )}
            {!q.isLoading && rows.length === 0 && (
              <tr>
                <td colSpan={8} className="px-3 py-6 text-center text-muted-foreground">
                  No operations yet.{" "}
                  <Link href="/operations/launch" className="underline">
                    Launch one
                  </Link>
                  .
                </td>
              </tr>
            )}
            {rows.map((o: Operation) => {
              const active = o.status === "queued" || o.status === "running";
              return (
                <tr key={o.id} className="border-t border-border hover:bg-muted/20">
                  <td className="px-3 py-2 font-mono text-xs">{o.id.slice(0, 8)}…</td>
                  <td className="px-3 py-2 font-mono">{o.target}</td>
                  <td className="px-3 py-2">{TOOL_LABELS[o.tool] ?? o.tool}</td>
                  <td className="px-3 py-2">{o.profile ?? "—"}</td>
                  <td className="px-3 py-2">
                    <Badge variant={STATUS_VARIANT[o.status]}>{o.status}</Badge>
                  </td>
                  <td className="px-3 py-2">{fmtDuration(o.duration_s)}</td>
                  <td className="px-3 py-2 text-xs">
                    {o.started_at ? new Date(o.started_at).toLocaleString() : "—"}
                  </td>
                  <td className="px-3 py-2">
                    <div className="flex items-center justify-end gap-1">
                      <Button asChild variant="ghost" size="sm">
                        <Link href={`/operations/${o.id}`}>
                          <Eye className="h-3.5 w-3.5 mr-1" /> View
                        </Link>
                      </Button>
                      {active ? (
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => cancelMut.mutate(o.id)}
                          disabled={cancelMut.isPending}
                        >
                          <Ban className="h-3.5 w-3.5 mr-1" /> Cancel
                        </Button>
                      ) : (
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => retryMut.mutate(o.id)}
                          disabled={retryMut.isPending}
                        >
                          <RotateCcw className="h-3.5 w-3.5 mr-1" /> Retry
                        </Button>
                      )}
                    </div>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export default function OperationsPage() {
  return (
    <AppShell>
      <OperationsTable />
    </AppShell>
  );
}
