"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import Link from "next/link";
import { Crosshair, Trash2 } from "lucide-react";
import { AppShell } from "@/components/AppShell";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { deleteWorkspace, listWorkspaces } from "@/lib/api";

const STATUS_VARIANT: Record<
  string,
  "success" | "warning" | "destructive" | "default"
> = {
  active: "success",
  archived: "default",
};

export default function TargetWorkspacesPage() {
  const qc = useQueryClient();
  const q = useQuery({
    queryKey: ["workspaces"],
    queryFn: listWorkspaces,
  });

  const doDelete = useMutation({
    mutationFn: (id: string) => deleteWorkspace(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["workspaces"] }),
    onError: (e) => alert((e as Error).message),
  });

  if (q.isLoading) {
    return (
      <AppShell>
        <p className="text-sm text-muted-foreground">Loading workspaces…</p>
      </AppShell>
    );
  }

  if (q.isError) {
    return (
      <AppShell>
        <p className="text-sm text-destructive">Failed to load workspaces.</p>
      </AppShell>
    );
  }

  const rows = q.data ?? [];

  return (
    <AppShell>
      <div className="space-y-6">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <h1 className="text-2xl font-semibold tracking-tight">Target Workspace</h1>
            <p className="text-sm text-muted-foreground mt-1">
              Analyst investigation environments built on completed recon scans.
            </p>
          </div>
        </div>

        {rows.length === 0 ? (
          <div className="rounded-lg border border-dashed border-border p-10 text-center">
            <Crosshair className="mx-auto h-8 w-8 text-muted-foreground mb-3" />
            <p className="text-sm text-muted-foreground">
              No workspaces yet. Open{" "}
              <Link href="/dashboard/recon-jobs" className="underline">
                a completed recon scan
              </Link>{" "}
              and click <span className="font-medium">Target Investigation</span>.
            </p>
          </div>
        ) : (
          <div className="rounded-lg border border-border overflow-hidden">
            <table className="w-full text-sm">
              <thead className="bg-muted/50 border-b border-border">
                <tr>
                  {[
                    "Workspace",
                    "Source Scan",
                    "Assets",
                    "Tasks",
                    "Status",
                    "Created",
                    "Actions",
                  ].map((h) => (
                    <th
                      key={h}
                      className="px-4 py-2.5 text-left font-medium text-xs uppercase tracking-wide text-muted-foreground"
                    >
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {rows.map((r) => (
                  <tr
                    key={r.id}
                    className="border-b border-border hover:bg-muted/30 transition-colors"
                  >
                    <td className="px-4 py-3">
                      <Link
                        href={`/targets/${r.target_id}/workspace`}
                        className="font-medium hover:underline text-foreground"
                      >
                        {r.label}
                      </Link>
                      <div className="text-xs text-muted-foreground mt-0.5">
                        {r.target_domain}
                      </div>
                    </td>
                    <td className="px-4 py-3 text-xs text-muted-foreground">
                      {r.parent_scan_id ? (
                        <Link
                          href={`/scans/${r.parent_scan_id}`}
                          className="hover:underline"
                        >
                          {r.parent_scan_id.slice(0, 8)}…
                        </Link>
                      ) : (
                        "—"
                      )}
                    </td>
                    <td className="px-4 py-3">{r.asset_count}</td>
                    <td className="px-4 py-3">{r.task_count}</td>
                    <td className="px-4 py-3">
                      <Badge variant={STATUS_VARIANT[r.status] ?? "default"}>
                        {r.status}
                      </Badge>
                    </td>
                    <td className="px-4 py-3 text-xs text-muted-foreground whitespace-nowrap">
                      {new Date(r.created_at).toLocaleString()}
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <Link
                          href={`/targets/${r.target_id}/workspace`}
                          className="text-xs underline hover:text-foreground"
                        >
                          Open
                        </Link>
                        <Button
                          size="sm"
                          variant="ghost"
                          className="h-7 w-7 p-0 text-destructive hover:text-destructive"
                          onClick={() => {
                            if (
                              confirm(
                                `Delete workspace "${r.label}"? Removes all investigation tasks and findings.`,
                              )
                            ) {
                              doDelete.mutate(r.id);
                            }
                          }}
                          disabled={doDelete.isPending}
                          title="Delete workspace"
                        >
                          <Trash2 className="h-3.5 w-3.5" />
                        </Button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </AppShell>
  );
}
