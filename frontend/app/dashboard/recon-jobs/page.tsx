"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useRouter } from "next/navigation";
import { Activity, AlertCircle, AlertTriangle, CheckCircle2, Database, ExternalLink, Play, Square, Trash2 } from "lucide-react";
import Link from "next/link";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { api, deleteScan, patchScan, startScan, stopScan, type Scan } from "@/lib/api";

const STATUS_CONFIG: Record<
  Scan["status"],
  { label: string; variant: "default" | "warning" | "success" | "destructive" | "outline" }
> = {
  queued:    { label: "Not Started", variant: "outline"      },
  created:   { label: "Queued",      variant: "warning"      },
  running:   { label: "Running",     variant: "warning"      },
  completed: { label: "Completed",   variant: "success"      },
  failed:    { label: "Failed",      variant: "destructive"  },
  stopped:   { label: "Stopped",     variant: "default"      },
};

function RunningProgress({ scan }: { scan: Scan }) {
  return (
    <div className="min-w-[120px]">
      <div className="h-1.5 bg-muted rounded overflow-hidden mb-1">
        <div
          className="h-full bg-primary transition-all"
          style={{ width: `${scan.progress_pct}%` }}
        />
      </div>
      <div className="text-xs text-muted-foreground">{scan.progress_pct}%</div>
    </div>
  );
}

function ScanTableRow({ scan }: { scan: Scan }) {
  const router = useRouter();
  const qc = useQueryClient();
  const invalidate = () => qc.invalidateQueries({ queryKey: ["scans"] });

  const doStart = useMutation({
    mutationFn: () => startScan(scan.id),
    onSuccess: (s) => {
      invalidate();
      router.push(`/scans/${s.id}`);
    },
  });
  const doStop = useMutation({
    mutationFn: () => stopScan(scan.id),
    onSuccess: invalidate,
  });
  const doDelete = useMutation({
    mutationFn: () => deleteScan(scan.id),
    onSuccess: invalidate,
  });
  const doPatch = useMutation({
    mutationFn: (p: string) => patchScan(scan.id, p),
    onSuccess: invalidate,
  });

  const cfg = STATUS_CONFIG[scan.status] ?? { label: scan.status, variant: "default" as const };
  const isActive = scan.status === "running" || scan.status === "created";
  // Deep scans on unverified targets silently skip naabu/nmap/gowitness
  const needsAuthzWarning = scan.profile === "deep" && !scan.target_authz_verified;

  return (
    <tr className="border-b border-border hover:bg-muted/30 transition-colors">
      {/* Domain */}
      <td className="px-4 py-3">
        <Link
          href={`/scans/${scan.id}`}
          className="font-medium hover:underline text-foreground"
        >
          {scan.domain}
        </Link>
        <div className="text-xs text-muted-foreground mt-0.5">
          {new Date(scan.created_at).toLocaleString()}
        </div>
      </td>

      {/* Profile — editable only when queued */}
      <td className="px-4 py-3">
        {scan.status === "queued" ? (
          <div className="flex items-center gap-1.5">
            <Select value={scan.profile} onValueChange={(p) => doPatch.mutate(p)}>
              <SelectTrigger className="h-7 w-28 text-xs">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="quick">quick</SelectItem>
                <SelectItem value="standard">standard</SelectItem>
                <SelectItem value="deep">deep</SelectItem>
              </SelectContent>
            </Select>
            {needsAuthzWarning && (
              <span
                title="Target not authorized for active scanning — naabu, nmap, and gowitness will be skipped. Go to Targets to verify ownership."
                className="cursor-help"
              >
                <AlertTriangle className="h-4 w-4 text-warning" />
              </span>
            )}
          </div>
        ) : (
          <div className="flex items-center gap-1.5">
            <span className="text-sm font-mono">{scan.profile}</span>
            {needsAuthzWarning && (
              <span
                title="Target not authorized for active scanning — naabu, nmap, and gowitness were skipped. Go to Targets to verify ownership."
                className="cursor-help"
              >
                <AlertTriangle className="h-4 w-4 text-warning" />
              </span>
            )}
          </div>
        )}
      </td>

      {/* Status */}
      <td className="px-4 py-3">
        <Badge variant={cfg.variant}>{cfg.label}</Badge>
      </td>

      {/* Progress */}
      <td className="px-4 py-3">
        {isActive ? (
          <RunningProgress scan={scan} />
        ) : scan.status === "completed" ? (
          <span className="text-xs text-muted-foreground">100%</span>
        ) : (
          <span className="text-xs text-muted-foreground">—</span>
        )}
      </td>

      {/* Actions */}
      <td className="px-4 py-3">
        <div className="flex items-center gap-1.5">
          {scan.status === "queued" && (
            <>
              <Button
                size="sm"
                variant="outline"
                className="h-7 gap-1 text-xs"
                onClick={() => doStart.mutate()}
                disabled={doStart.isPending}
              >
                <Play className="h-3 w-3" /> Start
              </Button>
              <Button
                size="sm"
                variant="ghost"
                className="h-7 w-7 p-0 text-destructive hover:text-destructive"
                onClick={() => doDelete.mutate()}
                disabled={doDelete.isPending}
                title="Delete"
              >
                <Trash2 className="h-3.5 w-3.5" />
              </Button>
            </>
          )}
          {isActive && (
            <Button
              size="sm"
              variant="outline"
              className="h-7 gap-1 text-xs"
              onClick={() => doStop.mutate()}
              disabled={doStop.isPending}
            >
              <Square className="h-3 w-3" /> Stop
            </Button>
          )}
          {(scan.status === "completed" ||
            scan.status === "failed" ||
            scan.status === "stopped") && (
            <Button size="sm" variant="outline" className="h-7 gap-1 text-xs" asChild>
              <Link href={`/scans/${scan.id}`}>
                <ExternalLink className="h-3 w-3" /> View Results
              </Link>
            </Button>
          )}
        </div>
      </td>
    </tr>
  );
}

export default function ReconJobsPage() {
  const scans = useQuery({
    queryKey: ["scans"],
    queryFn: () => api<Scan[]>("/scans"),
    refetchInterval: (q) => {
      const data = q.state.data as Scan[] | undefined;
      return data?.some(
        (s) => s.status === "running" || s.status === "created" || s.status === "queued"
      ) ? 3000 : false;
    },
  });

  if (scans.isLoading) {
    return <p className="text-sm text-muted-foreground">Loading jobs…</p>;
  }

  if (scans.isError) {
    return <p className="text-sm text-destructive">Failed to load jobs. Please refresh.</p>;
  }

  const all = scans.data ?? [];

  if (all.length === 0) {
    return (
      <div className="space-y-6">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Recon Jobs</h1>
          <p className="text-sm text-muted-foreground mt-1">
            Manage and monitor your reconnaissance scans.
          </p>
        </div>
        <div className="rounded-lg border border-dashed border-border p-8 text-center">
          <p className="text-sm text-muted-foreground">
            No scans yet — add one on the{" "}
            <Link href="/dashboard" className="underline">
              Add Scan
            </Link>{" "}
            page.
          </p>
        </div>
      </div>
    );
  }

  const totalCount = all.length;
  const runningCount = all.filter((s) => s.status === "running" || s.status === "created").length;
  const completedCount = all.filter((s) => s.status === "completed").length;
  const failedCount = all.filter((s) => s.status === "failed" || s.status === "stopped").length;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Recon Jobs</h1>
        <p className="text-sm text-muted-foreground mt-1">
          Manage and monitor your reconnaissance scans.
        </p>
      </div>
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <div className="flex items-center gap-2 rounded-lg border border-border bg-card px-4 py-2.5">
          <Database className="h-4 w-4 text-muted-foreground" />
          <div>
            <div className="text-xs text-muted-foreground">Total Scans</div>
            <div className="text-lg font-semibold tabular-nums leading-none">{totalCount}</div>
          </div>
        </div>
        <div className="flex items-center gap-2 rounded-lg border border-border bg-card px-4 py-2.5">
          <Activity className="h-4 w-4 text-warning" />
          <div>
            <div className="text-xs text-muted-foreground">Running</div>
            <div className="text-lg font-semibold tabular-nums leading-none">{runningCount}</div>
          </div>
        </div>
        <div className="flex items-center gap-2 rounded-lg border border-border bg-card px-4 py-2.5">
          <CheckCircle2 className="h-4 w-4 text-success" />
          <div>
            <div className="text-xs text-muted-foreground">Completed</div>
            <div className="text-lg font-semibold tabular-nums leading-none">{completedCount}</div>
          </div>
        </div>
        <div className="flex items-center gap-2 rounded-lg border border-border bg-card px-4 py-2.5">
          <AlertCircle className="h-4 w-4 text-destructive" />
          <div>
            <div className="text-xs text-muted-foreground">Failed / Stopped</div>
            <div className="text-lg font-semibold tabular-nums leading-none">{failedCount}</div>
          </div>
        </div>
      </div>
      <div className="rounded-lg border border-border overflow-hidden">
        <table className="w-full text-sm">
          <thead className="bg-muted/50 border-b border-border">
            <tr>
              {["Target Domain", "Profile", "Status", "Progress", "Actions"].map((h) => (
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
            {all.map((scan) => (
              <ScanTableRow key={scan.id} scan={scan} />
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
