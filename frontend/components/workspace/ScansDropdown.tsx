"use client";

import { useState } from "react";
import Link from "next/link";
import { History } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from "@/components/ui/dialog";
import {
  TOOL_LABELS,
  type WorkspaceScanEntry,
  type WorkspaceSubdomainIpRow,
} from "@/lib/api";

const STATUS_VARIANT: Record<
  WorkspaceScanEntry["status"],
  "success" | "warning" | "destructive" | "default"
> = {
  queued: "default",
  running: "warning",
  completed: "success",
  failed: "destructive",
  cancelled: "default",
};

function formatRelative(iso: string): string {
  const d = new Date(iso);
  const diffMs = Date.now() - d.getTime();
  const s = Math.round(diffMs / 1000);
  if (s < 60) return `${s}s ago`;
  const m = Math.round(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.round(m / 60);
  if (h < 24) return `${h}h ago`;
  const days = Math.round(h / 24);
  return `${days}d ago`;
}

function formatAbsolute(iso: string): string {
  return new Date(iso).toLocaleString();
}

function formatDuration(seconds: number | null): string {
  if (seconds === null) return "—";
  if (seconds < 1) return "<1s";
  if (seconds < 60) return `${seconds.toFixed(0)}s`;
  const m = Math.floor(seconds / 60);
  const s = Math.round(seconds % 60);
  return `${m}m ${s}s`;
}

type Group = {
  label: string;
  scope: "domain" | "ip";
  scans: WorkspaceScanEntry[];
};

export function ScansDropdown({
  fqdn,
  domainScans,
  ipRows,
  targetId,
  /**
   * Kept for compat with existing callsite — when true the modal opens on
   * mount. Used by the expanded-row inline dropdown variant.
   */
  defaultOpen = false,
  compact: _compact = false,
}: {
  fqdn: string;
  domainScans: WorkspaceScanEntry[];
  ipRows: WorkspaceSubdomainIpRow[];
  targetId: string;
  defaultOpen?: boolean;
  compact?: boolean;
}) {
  const [open, setOpen] = useState(defaultOpen);

  const groups: Group[] = [
    { label: `Domain · ${fqdn}`, scope: "domain", scans: domainScans },
    ...ipRows.map((ip) => ({
      label: `IP · ${ip.ip}`,
      scope: "ip" as const,
      scans: ip.scans,
    })),
  ];
  const total = groups.reduce((acc, g) => acc + g.scans.length, 0);

  if (total === 0) {
    return <span className="text-xs text-muted-foreground">—</span>;
  }

  return (
    <>
      <button
        type="button"
        onClick={(e) => {
          e.stopPropagation();
          setOpen(true);
        }}
        className="inline-flex items-center gap-1 rounded-md border border-border px-2 py-1 text-xs hover:bg-muted/40"
      >
        <History className="h-3.5 w-3.5" />
        Scans ({total})
      </button>
      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent className="max-w-2xl max-h-[80vh] flex flex-col p-0">
          <DialogHeader className="border-b border-border px-5 py-4">
            <DialogTitle>Scan history · {fqdn}</DialogTitle>
            <DialogDescription>
              {total} total scan{total === 1 ? "" : "s"} across domain + primary IP.
              Click any entry to open its result page.
            </DialogDescription>
          </DialogHeader>
          <div className="flex-1 overflow-y-auto px-5 py-4 space-y-4">
            {groups
              .filter((g) => g.scans.length > 0)
              .map((g) => (
                <section key={g.label}>
                  <div className="flex items-center gap-2 mb-2">
                    <h3 className="text-sm font-semibold">{g.label}</h3>
                    <Badge variant="outline">{g.scans.length}</Badge>
                  </div>
                  <ol className="rounded-md border border-border divide-y divide-border/60">
                    {g.scans.map((s, idx) => (
                      <li key={s.task_id}>
                        <Link
                          href={`/targets/${targetId}/workspace/tasks/${s.task_id}`}
                          className="flex items-center gap-3 px-3 py-2 hover:bg-muted/40 text-sm"
                          onClick={() => setOpen(false)}
                        >
                          <span className="font-mono text-xs text-muted-foreground w-8 text-right">
                            #{idx + 1}
                          </span>
                          <span className="flex-1 font-medium truncate">
                            {TOOL_LABELS[s.tool] ?? s.tool}
                          </span>
                          <Badge variant={STATUS_VARIANT[s.status]}>
                            {s.status}
                          </Badge>
                          <span
                            className="text-xs text-muted-foreground tabular-nums w-20 text-right"
                            title="Execution duration"
                          >
                            {formatDuration(s.duration_s)}
                          </span>
                          <span
                            className="text-xs text-muted-foreground tabular-nums w-24 text-right"
                            title={formatAbsolute(s.created_at)}
                          >
                            {formatRelative(s.created_at)}
                          </span>
                        </Link>
                      </li>
                    ))}
                  </ol>
                </section>
              ))}
          </div>
        </DialogContent>
      </Dialog>
    </>
  );
}
