"use client";

import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useRouter } from "next/navigation";
import { Activity, AlertCircle, CheckCircle2, Crosshair, Database, ExternalLink, Play, Square, Trash2 } from "lucide-react";
import Link from "next/link";
import { Button } from "@/components/ui/button";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { api, canDeleteScan, createWorkspace, deleteScan, patchScan, startScan, stopScan, type Scan } from "@/lib/api";

const STATUS_CONFIG: Record<Scan["status"], { label: string; pill: string }> = {
  queued:    { label: "Not Started", pill: "pill pill-out"  },
  created:   { label: "Queued",      pill: "pill pill-run"  },
  running:   { label: "Running",     pill: "pill pill-run"  },
  completed: { label: "Completed",   pill: "pill pill-ok"   },
  failed:    { label: "Failed",      pill: "pill pill-err"  },
  stopped:   { label: "Stopped",     pill: "pill pill-info" },
};

function RunningProgress({ scan }: { scan: Scan }) {
  return (
    <div className="min-w-[120px]">
      <div className="progress mb-1">
        <i style={{ width: `${scan.progress_pct}%` }} />
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
  const [wsLaunching, setWsLaunching] = useState(false);

  const cfg = STATUS_CONFIG[scan.status] ?? { label: scan.status, pill: "pill pill-info" };
  const isActive = scan.status === "running" || scan.status === "created";

  return (
    <tr className="row-strip hover:bg-accent/40 transition-colors">
      {/* Domain */}
      <td className="px-4 py-3">
        <Link
          href={`/scans/${scan.id}`}
          className="font-medium hover:underline text-foreground"
        >
          {scan.domain}
        </Link>
        <div className="text-xs text-muted-foreground-2 mt-0.5">
          {new Date(scan.created_at).toLocaleString()}
        </div>
      </td>

      {/* Profile — editable only when queued */}
      <td className="px-4 py-3">
        {scan.status === "queued" ? (
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
        ) : (
          <span className="text-sm font-mono">{scan.profile}</span>
        )}
      </td>

      {/* Status */}
      <td className="px-4 py-3">
        <span className={cfg.pill}>{cfg.label}</span>
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
            <Button
              size="sm"
              variant="outline"
              className="h-7 gap-1 text-xs"
              onClick={() => doStart.mutate()}
              disabled={doStart.isPending}
            >
              <Play className="h-3 w-3" /> Start
            </Button>
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
          {scan.status === "completed" && (
            <Button
              size="sm"
              variant="outline"
              className="h-7 gap-1 text-xs"
              disabled={wsLaunching}
              onClick={async () => {
                setWsLaunching(true);
                try {
                  const ws = await createWorkspace(scan.id);
                  router.push(`/targets/${ws.target_id}/workspace`);
                } catch (err) {
                  console.error("Failed to open target workspace:", err);
                  setWsLaunching(false);
                }
              }}
            >
              {wsLaunching ? (
                <span className="h-3.5 w-3.5 animate-spin rounded-full border-2 border-current border-t-transparent" />
              ) : (
                <Crosshair className="h-3 w-3" />
              )}
              {wsLaunching ? "Opening…" : "Target Investigation"}
            </Button>
          )}
          {canDeleteScan(scan.status) && (
            <Button
              size="sm"
              variant="ghost"
              className="h-7 w-7 p-0 text-destructive hover:text-destructive"
              onClick={() => {
                if (confirm(`Delete scan for ${scan.domain}? Removes all stages and assets observed by this scan.`)) {
                  doDelete.mutate();
                }
              }}
              disabled={doDelete.isPending}
              title="Delete scan"
            >
              <Trash2 className="h-3.5 w-3.5" />
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
          <div className="kicker mb-2">Basic Recon</div>
          <h1 className="page-h1">Recon Jobs</h1>
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
        <div className="kicker mb-2">Basic Recon</div>
        <h1 className="page-h1">Recon Jobs</h1>
        <p className="text-sm text-muted-foreground mt-1">
          Manage and monitor your reconnaissance scans.
        </p>
      </div>
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <div className="stat-tile flex-row items-center gap-3">
          <Database className="h-4 w-4 text-muted-foreground shrink-0" />
          <div>
            <div className="text-[10px] uppercase tracking-[0.1em] text-muted-foreground-2">Total Scans</div>
            <div className="text-lg font-medium tabular-nums leading-none">{totalCount}</div>
          </div>
        </div>
        <div className="stat-tile flex-row items-center gap-3">
          <Activity className="h-4 w-4 text-primary-tint shrink-0" />
          <div>
            <div className="text-[10px] uppercase tracking-[0.1em] text-muted-foreground-2">Running</div>
            <div className="text-lg font-medium tabular-nums leading-none">{runningCount}</div>
          </div>
        </div>
        <div className="stat-tile flex-row items-center gap-3">
          <CheckCircle2 className="h-4 w-4 text-success shrink-0" />
          <div>
            <div className="text-[10px] uppercase tracking-[0.1em] text-muted-foreground-2">Completed</div>
            <div className="text-lg font-medium tabular-nums leading-none">{completedCount}</div>
          </div>
        </div>
        <div className="stat-tile flex-row items-center gap-3">
          <AlertCircle className="h-4 w-4 text-sev-high-fg shrink-0" />
          <div>
            <div className="text-[10px] uppercase tracking-[0.1em] text-muted-foreground-2">Failed / Stopped</div>
            <div className="text-lg font-medium tabular-nums leading-none">{failedCount}</div>
          </div>
        </div>
      </div>
      <div className="rounded-lg overflow-hidden shadow-[0_0_0_1px_hsl(var(--border))]">
        <table className="w-full text-sm">
          <thead className="bg-foreground/[0.03]">
            <tr>
              {["Target Domain", "Profile", "Status", "Progress", "Actions"].map((h) => (
                <th
                  key={h}
                  className="px-4 py-2.5 text-left font-medium text-[10px] uppercase tracking-[0.1em] text-muted-foreground-2"
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
