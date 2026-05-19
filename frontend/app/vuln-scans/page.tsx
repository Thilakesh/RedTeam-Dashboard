"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import Link from "next/link";
import { ShieldAlert, Trash2 } from "lucide-react";
import { AppShell } from "@/components/AppShell";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { api, canDeleteScan, deleteVulnScan, type VulnScanOut } from "@/lib/api";

const STATUS_VARIANT: Record<
  string,
  "success" | "warning" | "destructive" | "default"
> = {
  completed: "success",
  running: "warning",
  failed: "destructive",
  created: "default",
  queued: "default",
};

function ProgressBar({ pct }: { pct: number }) {
  return (
    <div className="min-w-[100px]">
      <div className="h-1.5 bg-muted rounded overflow-hidden mb-1">
        <div
          className="h-full bg-primary transition-all"
          style={{ width: `${pct}%` }}
        />
      </div>
      <div className="text-xs text-muted-foreground">{pct}%</div>
    </div>
  );
}

export default function VulnScansPage() {
  const qc = useQueryClient();
  const scans = useQuery({
    queryKey: ["vuln-scans"],
    queryFn: () => api<VulnScanOut[]>("/vuln-scans"),
    refetchInterval: (q) => {
      const data = q.state.data as VulnScanOut[] | undefined;
      return data?.some(
        (s) => s.status === "running" || s.status === "created" || s.status === "queued"
      )
        ? 4000
        : false;
    },
  });

  const doDelete = useMutation({
    mutationFn: (id: string) => deleteVulnScan(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["vuln-scans"] }),
    onError: (e) => alert((e as Error).message),
  });

  if (scans.isLoading) {
    return (
      <AppShell>
        <p className="text-sm text-muted-foreground">Loading vulnerability scans…</p>
      </AppShell>
    );
  }

  if (scans.isError) {
    return (
      <AppShell>
        <p className="text-sm text-destructive">Failed to load vulnerability scans. Please refresh.</p>
      </AppShell>
    );
  }

  const all = scans.data ?? [];

  return (
    <AppShell>
      <div className="space-y-6">
        {/* Page header */}
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <h1 className="text-2xl font-semibold tracking-tight">Vulnerability Scans</h1>
            <p className="text-sm text-muted-foreground mt-1">
              View and manage vulnerability analysis runs across your targets.
            </p>
          </div>
          <Button
            variant="outline"
            size="sm"
            title="Start a vuln scan from a completed recon scan's detail page"
            onClick={() =>
              alert(
                "Start a vuln scan from a completed recon scan's detail page."
              )
            }
          >
            <ShieldAlert className="h-4 w-4" /> New Vulnerability Scan
          </Button>
        </div>

        {/* Empty state */}
        {all.length === 0 ? (
          <div className="rounded-lg border border-dashed border-border p-10 text-center">
            <ShieldAlert className="mx-auto h-8 w-8 text-muted-foreground mb-3" />
            <p className="text-sm text-muted-foreground">
              No vulnerability scans yet. Run one from a{" "}
              <Link href="/dashboard/recon-jobs" className="underline">
                completed recon scan
              </Link>
              .
            </p>
          </div>
        ) : (
          <div className="rounded-lg border border-border overflow-hidden">
            <table className="w-full text-sm">
              <thead className="bg-muted/50 border-b border-border">
                <tr>
                  {["Target Domain", "Profile", "Status", "Progress", "Created", ""].map(
                    (h, i) => (
                      <th
                        key={h || `actions-${i}`}
                        className="px-4 py-2.5 text-left font-medium text-xs uppercase tracking-wide text-muted-foreground"
                      >
                        {h}
                      </th>
                    )
                  )}
                </tr>
              </thead>
              <tbody>
                {all.map((scan) => {
                  const variant =
                    STATUS_VARIANT[scan.status] ?? "default";
                  const isActive =
                    scan.status === "running" || scan.status === "created";

                  return (
                    <tr
                      key={scan.id}
                      className="border-b border-border hover:bg-muted/30 transition-colors"
                    >
                      {/* Target Domain */}
                      <td className="px-4 py-3">
                        <Link
                          href={`/vuln-scans/${scan.id}`}
                          className="font-medium hover:underline text-foreground"
                        >
                          {scan.target_domain}
                        </Link>
                        {scan.parent_scan_id && (
                          <div className="text-xs text-muted-foreground mt-0.5">
                            Recon:{" "}
                            <Link
                              href={`/scans/${scan.parent_scan_id}`}
                              className="hover:underline"
                            >
                              {scan.parent_scan_id.slice(0, 8)}…
                            </Link>
                          </div>
                        )}
                      </td>

                      {/* Profile */}
                      <td className="px-4 py-3">
                        <span className="text-sm font-mono">{scan.profile}</span>
                        {scan.intrusive && (
                          <span className="ml-1.5 text-xs text-warning">(intrusive)</span>
                        )}
                      </td>

                      {/* Status */}
                      <td className="px-4 py-3">
                        <Badge variant={variant}>{scan.status}</Badge>
                      </td>

                      {/* Progress */}
                      <td className="px-4 py-3">
                        {isActive ? (
                          <ProgressBar pct={scan.progress_pct} />
                        ) : scan.status === "completed" ? (
                          <span className="text-xs text-muted-foreground">100%</span>
                        ) : (
                          <span className="text-xs text-muted-foreground">—</span>
                        )}
                      </td>

                      {/* Created */}
                      <td className="px-4 py-3 text-xs text-muted-foreground whitespace-nowrap">
                        {new Date(scan.created_at).toLocaleString()}
                      </td>

                      {/* Delete */}
                      <td className="px-4 py-3 text-right">
                        {canDeleteScan(scan.status) && (
                          <Button
                            size="sm"
                            variant="ghost"
                            className="h-7 w-7 p-0 text-destructive hover:text-destructive"
                            onClick={() => {
                              if (
                                confirm(
                                  `Delete vuln scan for ${scan.target_domain}? Removes all stages, vuln evidence, and matches.`,
                                )
                              ) {
                                doDelete.mutate(scan.id);
                              }
                            }}
                            disabled={doDelete.isPending}
                            title="Delete vuln scan"
                          >
                            <Trash2 className="h-3.5 w-3.5" />
                          </Button>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </AppShell>
  );
}
