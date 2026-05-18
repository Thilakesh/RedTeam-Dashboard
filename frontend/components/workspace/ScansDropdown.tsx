"use client";

import { useState } from "react";
import Link from "next/link";
import { ChevronDown, ChevronRight } from "lucide-react";
import { Badge } from "@/components/ui/badge";
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
  return d.toLocaleDateString();
}

function formatDuration(seconds: number | null): string {
  if (seconds === null) return "";
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
  defaultOpen = false,
  compact = false,
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
    <div className={compact ? "text-xs" : "text-sm"}>
      <button
        type="button"
        onClick={(e) => {
          e.stopPropagation();
          setOpen((v) => !v);
        }}
        className="inline-flex items-center gap-1 rounded-md border border-border px-2 py-1 hover:bg-muted/40"
      >
        {open ? (
          <ChevronDown className="h-3.5 w-3.5" />
        ) : (
          <ChevronRight className="h-3.5 w-3.5" />
        )}
        Scans ({total})
      </button>
      {open && (
        <div className="mt-1 rounded-md border border-border bg-background shadow-sm p-2 space-y-2 min-w-[280px]">
          {groups
            .filter((g) => g.scans.length > 0)
            .map((g) => (
              <div key={g.label}>
                <div className="text-xxs uppercase text-muted-foreground px-1 py-0.5">
                  {g.label} ({g.scans.length})
                </div>
                <ol className="space-y-0.5">
                  {g.scans.map((s, idx) => (
                    <li key={s.task_id}>
                      <Link
                        href={`/targets/${targetId}/workspace/tasks/${s.task_id}`}
                        className="flex items-center gap-2 rounded px-1.5 py-1 hover:bg-muted/40 text-xs"
                        title={new Date(s.created_at).toLocaleString()}
                      >
                        <span className="font-mono text-muted-foreground w-6 text-right">
                          #{idx + 1}
                        </span>
                        <span className="flex-1 truncate">
                          {TOOL_LABELS[s.tool] ?? s.tool}
                        </span>
                        <Badge
                          variant={STATUS_VARIANT[s.status]}
                          className="text-xxs"
                        >
                          {s.status}
                        </Badge>
                        <span className="text-xxs text-muted-foreground tabular-nums">
                          {formatRelative(s.created_at)}
                          {s.duration_s !== null
                            ? ` · ${formatDuration(s.duration_s)}`
                            : ""}
                        </span>
                      </Link>
                    </li>
                  ))}
                </ol>
              </div>
            ))}
        </div>
      )}
    </div>
  );
}
