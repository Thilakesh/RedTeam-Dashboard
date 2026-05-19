"use client";

import { Suspense, useEffect, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useRouter, useSearchParams } from "next/navigation";
import {
  ArrowDown,
  ArrowUp,
  ArrowUpDown,
  ChevronDown,
  ChevronRight,
  Crosshair,
  Globe,
  Play,
  Server,
  Trash2,
} from "lucide-react";
import Link from "next/link";
import { AppShell } from "@/components/AppShell";
import { ScansDropdown } from "@/components/workspace/ScansDropdown";
import { ScanConfigurationCard } from "@/components/workspace/ScanConfigurationCard";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  TOOL_LABELS,
  createInvestigationTask,
  deleteInvestigationTask,
  deleteWorkspace,
  getWorkspaceOverview,
  getWorkspaceSubdomains,
  listWorkspaceTasks,
  listWorkspaces,
  sseUrl,
  type InvestigationTaskOut,
  type WorkspaceListRow,
  type WorkspaceOverview,
  type WorkspaceSubdomainRow,
} from "@/lib/api";

const VALID_TABS = ["overview", "subdomains", "tasks"] as const;
type Tab = (typeof VALID_TABS)[number];

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

function WorkspaceContent({ params }: { params: { id: string } }) {
  const router = useRouter();
  const qc = useQueryClient();
  const searchParams = useSearchParams();
  const rawTab = searchParams.get("tab");
  const wQuery = searchParams.get("w");
  const tab: Tab =
    rawTab && (VALID_TABS as readonly string[]).includes(rawTab)
      ? (rawTab as Tab)
      : "overview";

  // Resolve workspace_id from target_id (or from ?w= override)
  const wsListQ = useQuery({
    queryKey: ["workspaces"],
    queryFn: listWorkspaces,
  });

  const workspace: WorkspaceListRow | undefined = useMemo(() => {
    const rows = wsListQ.data ?? [];
    if (wQuery) return rows.find((r) => r.id === wQuery);
    return rows.find((r) => r.target_id === params.id);
  }, [wsListQ.data, params.id, wQuery]);

  const wsId = workspace?.id;

  const overviewQ = useQuery({
    queryKey: ["workspace-overview", wsId],
    queryFn: () => getWorkspaceOverview(wsId!),
    enabled: !!wsId,
  });
  const subsQ = useQuery({
    queryKey: ["workspace-subdomains", wsId],
    queryFn: () => getWorkspaceSubdomains(wsId!),
    enabled: !!wsId,
  });
  const tasksQ = useQuery({
    queryKey: ["workspace-tasks", wsId],
    queryFn: () => listWorkspaceTasks(wsId!),
    enabled: !!wsId,
    refetchInterval: (q) => {
      const data = q.state.data?.rows ?? [];
      return data.some((t) => t.status === "queued" || t.status === "running")
        ? 4000
        : false;
    },
  });

  const doDeleteWs = useMutation({
    mutationFn: (id: string) => deleteWorkspace(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["workspaces"] });
      router.push("/targets");
    },
    onError: (e) => alert((e as Error).message),
  });

  // SSE: refresh tasks + overview + subdomains on any task.* event
  useEffect(() => {
    if (!wsId) return;
    const es = new EventSource(sseUrl(`/target-workspaces/${wsId}/stream`));
    const refetch = () => {
      qc.invalidateQueries({ queryKey: ["workspace-tasks", wsId] });
      qc.invalidateQueries({ queryKey: ["workspace-overview", wsId] });
      qc.invalidateQueries({ queryKey: ["workspace-subdomains", wsId] });
    };
    ["task.started", "task.completed", "task.failed", "task.update"].forEach((ev) =>
      es.addEventListener(ev, refetch),
    );
    es.onerror = () => {
      if (es.readyState === EventSource.CLOSED) es.close();
    };
    return () => es.close();
  }, [wsId, qc]);

  if (wsListQ.isLoading) {
    return (
      <AppShell>
        <p className="text-sm text-muted-foreground">Loading workspace…</p>
      </AppShell>
    );
  }

  if (!workspace) {
    return (
      <AppShell>
        <div className="rounded-lg border border-dashed border-border p-10 text-center">
          <Crosshair className="mx-auto h-8 w-8 text-muted-foreground mb-3" />
          <p className="text-sm text-muted-foreground">
            No workspace found for this target.{" "}
            <Link href="/dashboard/recon-jobs" className="underline">
              Open a completed recon scan
            </Link>{" "}
            and click <span className="font-medium">Target Investigation</span> to create one.
          </p>
        </div>
      </AppShell>
    );
  }

  const setTab = (t: Tab) => {
    const sp = new URLSearchParams(searchParams);
    sp.set("tab", t);
    router.replace(`?${sp.toString()}`, { scroll: false });
  };

  return (
    <AppShell>
      <div className="mb-6 flex flex-wrap items-start justify-between gap-4">
        <div>
          <div className="text-xs text-muted-foreground mb-1">Target Workspace</div>
          <div className="flex items-center gap-3">
            <Globe className="h-5 w-5 text-primary" />
            <h1 className="text-2xl font-semibold tracking-tight">
              {workspace.label}
            </h1>
            <Badge variant="success">{workspace.status}</Badge>
          </div>
          <div className="mt-2 text-xs text-muted-foreground">
            Target: <span className="text-foreground">{workspace.target_domain}</span>
            {workspace.parent_scan_id && (
              <>
                {" · Source recon: "}
                <Link
                  href={`/scans/${workspace.parent_scan_id}`}
                  className="text-foreground hover:underline"
                >
                  {workspace.parent_scan_id.slice(0, 8)}…
                </Link>
              </>
            )}
          </div>
        </div>
        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            className="text-destructive hover:text-destructive"
            onClick={() => {
              if (
                confirm(
                  `Delete workspace "${workspace.label}"? Removes all investigation tasks and findings.`,
                )
              ) {
                doDeleteWs.mutate(workspace.id);
              }
            }}
            disabled={doDeleteWs.isPending}
          >
            <Trash2 className="h-4 w-4" /> Delete workspace
          </Button>
        </div>
      </div>

      <Tabs value={tab} onValueChange={(v) => setTab(v as Tab)}>
        <TabsList>
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="subdomains">Subdomains</TabsTrigger>
          <TabsTrigger value="tasks">Run Scan Details</TabsTrigger>
        </TabsList>

        <TabsContent value="overview">
          <OverviewTab data={overviewQ.data} loading={overviewQ.isLoading} />
        </TabsContent>

        <TabsContent value="subdomains">
          <SubdomainsTab
            rows={subsQ.data?.rows ?? []}
            loading={subsQ.isLoading}
            workspaceId={workspace.id}
            targetId={workspace.target_id}
            onTaskCreated={() => {
              qc.invalidateQueries({ queryKey: ["workspace-tasks", workspace.id] });
              setTab("tasks");
            }}
          />
        </TabsContent>

        <TabsContent value="tasks">
          <TasksTab
            rows={tasksQ.data?.rows ?? []}
            loading={tasksQ.isLoading}
            workspaceId={workspace.id}
            targetId={workspace.target_id}
          />
        </TabsContent>
      </Tabs>
    </AppShell>
  );
}

function OverviewTab({
  data,
  loading,
}: {
  data: WorkspaceOverview | undefined;
  loading: boolean;
}) {
  if (loading || !data) {
    return <p className="text-sm text-muted-foreground py-6">Loading overview…</p>;
  }
  const cards = [
    { label: "Total Subdomains", value: data.total_subdomains },
    { label: "Alive Hosts", value: data.alive_hosts },
    { label: "Ports Identified", value: data.ports_identified },
    { label: "Running Investigations", value: data.running_tasks },
    { label: "Findings", value: data.findings_count },
    { label: "High Value Targets", value: data.hvt_count },
  ];
  const hvtRows = Object.entries(data.hvt_signal_summary || {}).sort(
    (a, b) => b[1] - a[1],
  );

  return (
    <div className="space-y-6 py-4">
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
        {cards.map((c) => (
          <div
            key={c.label}
            className="rounded-lg border border-border bg-card p-4"
          >
            <div className="text-xs uppercase tracking-wide text-muted-foreground">
              {c.label}
            </div>
            <div className="mt-1 text-2xl font-semibold">{c.value}</div>
          </div>
        ))}
      </div>

      <div className="rounded-lg border border-border bg-card p-4">
        <div className="text-sm font-medium mb-2">High Value Targets</div>
        {hvtRows.length === 0 ? (
          <p className="text-xs text-muted-foreground">
            No HVT signals detected yet. Recon-side panel detection + vuln-side
            HVT scoring populate this.
          </p>
        ) : (
          <div className="flex flex-wrap gap-2">
            {hvtRows.map(([type, count]) => (
              <Badge key={type} variant="warning">
                {type} · {count}
              </Badge>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

type SortKey = "fqdn" | "alive" | "ports" | "ips" | "tools_run";

function SortHeader({
  label,
  sortKey,
  activeKey,
  desc,
  onToggle,
}: {
  label: string;
  sortKey: SortKey;
  activeKey: SortKey;
  desc: boolean;
  onToggle: (k: SortKey) => void;
}) {
  const active = activeKey === sortKey;
  const Icon = !active ? ArrowUpDown : desc ? ArrowDown : ArrowUp;
  return (
    <th className="px-4 py-2.5 text-left font-medium text-xs uppercase tracking-wide text-muted-foreground">
      <button
        type="button"
        onClick={() => onToggle(sortKey)}
        className={
          "inline-flex items-center gap-1 hover:text-foreground transition-colors " +
          (active ? "text-foreground" : "")
        }
      >
        {label}
        <Icon className="h-3 w-3" />
      </button>
    </th>
  );
}

function SubdomainsTab({
  rows,
  loading,
  workspaceId,
  targetId,
  onTaskCreated,
}: {
  rows: WorkspaceSubdomainRow[];
  loading: boolean;
  workspaceId: string;
  targetId: string;
  onTaskCreated: () => void;
}) {
  const [sortKey, setSortKey] = useState<SortKey>("fqdn");
  const [sortDesc, setSortDesc] = useState(false);

  const toggleSort = (k: SortKey) => {
    if (k === sortKey) {
      setSortDesc((v) => !v);
    } else {
      setSortKey(k);
      // Sensible default direction per column: string asc, counts desc.
      setSortDesc(k !== "fqdn");
    }
  };

  const sorted = useMemo(() => {
    const copy = [...rows];
    copy.sort((a, b) => {
      let cmp = 0;
      switch (sortKey) {
        case "fqdn":
          cmp = a.fqdn.localeCompare(b.fqdn);
          break;
        case "alive":
          cmp = Number(a.alive) - Number(b.alive);
          break;
        case "ports":
          cmp = a.ports.length - b.ports.length;
          break;
        case "ips":
          cmp = a.ips.length - b.ips.length;
          break;
        case "tools_run":
          cmp = a.tools_run.length - b.tools_run.length;
          break;
      }
      return sortDesc ? -cmp : cmp;
    });
    return copy;
  }, [rows, sortKey, sortDesc]);

  if (loading) {
    return <p className="text-sm text-muted-foreground py-6">Loading subdomains…</p>;
  }
  if (rows.length === 0) {
    return (
      <p className="text-sm text-muted-foreground py-6">
        No subdomains in the asset graph for this target.
      </p>
    );
  }

  return (
    <div className="py-4 space-y-2">
      <div className="text-xs text-muted-foreground">
        {sorted.length} subdomain{sorted.length === 1 ? "" : "s"}
      </div>

      <div className="rounded-lg border border-border overflow-hidden">
        <table className="w-full text-sm">
          <thead className="bg-muted/50 border-b border-border">
            <tr>
              <th className="px-4 py-2.5 w-8" />
              <SortHeader
                label="Subdomain"
                sortKey="fqdn"
                activeKey={sortKey}
                desc={sortDesc}
                onToggle={toggleSort}
              />
              <SortHeader
                label="Status"
                sortKey="alive"
                activeKey={sortKey}
                desc={sortDesc}
                onToggle={toggleSort}
              />
              <SortHeader
                label="Ports"
                sortKey="ports"
                activeKey={sortKey}
                desc={sortDesc}
                onToggle={toggleSort}
              />
              <th className="px-4 py-2.5 text-left font-medium text-xs uppercase tracking-wide text-muted-foreground">
                Technologies
              </th>
              <SortHeader
                label="IPs"
                sortKey="ips"
                activeKey={sortKey}
                desc={sortDesc}
                onToggle={toggleSort}
              />
              <SortHeader
                label="Tools Run"
                sortKey="tools_run"
                activeKey={sortKey}
                desc={sortDesc}
                onToggle={toggleSort}
              />
            </tr>
          </thead>
          <tbody>
            {sorted.map((r) => (
              <SubdomainRow
                key={r.asset_id}
                row={r}
                workspaceId={workspaceId}
                targetId={targetId}
                onTaskCreated={onTaskCreated}
              />
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

const TOOL_DEFAULT_PROTOCOL: Record<string, "http" | "https"> = {
  nmap_deep: "https",
  ffuf: "https",
  dirsearch: "https",
  testssl: "https",
};

function ScanTargetPanel({
  workspaceId,
  assetId,
  label,
  isIp,
  defaultProtocol,
  onTaskCreated,
}: {
  workspaceId: string;
  assetId: string;
  label: string;
  isIp: boolean;
  defaultProtocol: "http" | "https";
  onTaskCreated: () => void;
}) {
  const [protocol, setProtocol] = useState<"http" | "https">(defaultProtocol);
  const [tool, setTool] = useState<string>("nmap_deep");

  const run = useMutation({
    mutationFn: () =>
      createInvestigationTask(workspaceId, {
        asset_id: assetId,
        tool,
        params: { protocol, port: protocol === "https" ? 443 : 80 },
      }),
    onSuccess: () => onTaskCreated(),
  });

  return (
    <div className="rounded-md border border-border bg-muted/20 px-3 py-2.5 flex flex-wrap items-center gap-3">
      <div className="flex items-center gap-2 min-w-[200px]">
        {isIp ? (
          <Server className="h-3.5 w-3.5 text-muted-foreground" />
        ) : (
          <Globe className="h-3.5 w-3.5 text-muted-foreground" />
        )}
        <span className="text-xs font-mono">{label}</span>
      </div>

      <div className="flex items-center gap-1.5">
        <span className="text-xxs uppercase text-muted-foreground">Protocol</span>
        <div className="inline-flex rounded-md border border-border overflow-hidden">
          {(["http", "https"] as const).map((p) => (
            <button
              key={p}
              onClick={() => setProtocol(p)}
              className={
                "h-6 px-2 text-xxs uppercase " +
                (protocol === p
                  ? "bg-primary text-primary-foreground"
                  : "bg-background text-muted-foreground hover:text-foreground")
              }
            >
              {p}
            </button>
          ))}
        </div>
      </div>

      <div className="flex items-center gap-1.5">
        <span className="text-xxs uppercase text-muted-foreground">Tool</span>
        <Select value={tool} onValueChange={setTool}>
          <SelectTrigger className="h-7 w-36 text-xs">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {Object.entries(TOOL_LABELS).map(([t, lbl]) => (
              <SelectItem key={t} value={t}>
                {lbl}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      <Button
        size="sm"
        variant="outline"
        className="h-7 gap-1 text-xs ml-auto"
        disabled={run.isPending}
        onClick={() => run.mutate()}
      >
        {run.isPending ? (
          <span className="h-3.5 w-3.5 animate-spin rounded-full border-2 border-current border-t-transparent" />
        ) : (
          <Play className="h-3 w-3" />
        )}
        Run Scan
      </Button>
    </div>
  );
}

function SubdomainRow({
  row,
  workspaceId,
  targetId,
  onTaskCreated,
}: {
  row: WorkspaceSubdomainRow;
  workspaceId: string;
  targetId: string;
  onTaskCreated: () => void;
}) {
  const [expanded, setExpanded] = useState(false);
  const defaultProto: "http" | "https" = row.has_https || !row.has_http ? "https" : "http";

  return (
    <>
      <tr
        className="border-b border-border hover:bg-muted/30 transition-colors cursor-pointer"
        onClick={() => setExpanded((v) => !v)}
      >
        <td className="px-4 py-3 w-8">
          {expanded ? (
            <ChevronDown className="h-3.5 w-3.5 text-muted-foreground" />
          ) : (
            <ChevronRight className="h-3.5 w-3.5 text-muted-foreground" />
          )}
        </td>
        <td className="px-4 py-3">
          <div className="font-medium">{row.fqdn}</div>
          {row.hvt_signals.length > 0 && (
            <div className="mt-1 flex flex-wrap gap-1">
              {row.hvt_signals.map((s) => (
                <Badge key={s} variant="warning" className="text-xxs">
                  {s}
                </Badge>
              ))}
            </div>
          )}
        </td>
        <td className="px-4 py-3">
          <Badge variant={row.alive ? "success" : "default"}>
            {row.alive ? "Alive" : "Unknown"}
          </Badge>
        </td>
        <td className="px-4 py-3 text-xs">
          {row.ports.length ? row.ports.join(", ") : "—"}
        </td>
        <td className="px-4 py-3 text-xs">
          {row.technologies.length ? row.technologies.join(", ") : "—"}
        </td>
        <td className="px-4 py-3 text-xs">
          {row.ips.length ? row.ips.map((i) => i.ip).join(", ") : "—"}
        </td>
        <td className="px-4 py-3">
          <ScansDropdown
            fqdn={row.fqdn}
            domainScans={row.scans ?? []}
            ipRows={row.ips}
            targetId={targetId}
            compact
          />
        </td>
      </tr>
      {expanded && (
        <tr className="border-b border-border bg-muted/10">
          <td colSpan={7} className="px-4 py-3">
            <ScanConfigurationCard
              workspaceId={workspaceId}
              fqdn={row.fqdn}
              domainAssetId={row.asset_id}
              ipRows={row.ips}
              domainScans={row.scans ?? []}
              targetId={targetId}
              onTaskCreated={onTaskCreated}
            />
          </td>
        </tr>
      )}
    </>
  );
}

function TasksTab({
  rows,
  loading,
  workspaceId,
  targetId,
}: {
  rows: InvestigationTaskOut[];
  loading: boolean;
  workspaceId: string;
  targetId: string;
}) {
  const qc = useQueryClient();
  const doDelete = useMutation({
    mutationFn: (taskId: string) => deleteInvestigationTask(workspaceId, taskId),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["workspace-tasks", workspaceId] });
      qc.invalidateQueries({ queryKey: ["workspace-overview", workspaceId] });
    },
    onError: (e) => alert((e as Error).message),
  });

  if (loading) {
    return <p className="text-sm text-muted-foreground py-6">Loading tasks…</p>;
  }
  if (rows.length === 0) {
    return (
      <p className="text-sm text-muted-foreground py-6">
        No investigation tasks yet. Run a tool from the Subdomains tab.
      </p>
    );
  }
  return (
    <div className="py-4 rounded-lg border border-border overflow-hidden">
      <table className="w-full text-sm">
        <thead className="bg-muted/50 border-b border-border">
          <tr>
            {["Task", "Asset", "Tool", "Status", "Progress", "Duration", "Actions"].map(
              (h) => (
                <th
                  key={h}
                  className="px-4 py-2.5 text-left font-medium text-xs uppercase tracking-wide text-muted-foreground"
                >
                  {h}
                </th>
              ),
            )}
          </tr>
        </thead>
        <tbody>
          {rows.map((t) => {
            const deletable =
              t.status !== "queued" && t.status !== "running";
            return (
              <tr
                key={t.id}
                className="border-b border-border hover:bg-muted/30 transition-colors"
              >
                <td className="px-4 py-3 font-mono text-xs">{t.id.slice(0, 8)}…</td>
                <td className="px-4 py-3">{t.asset_label}</td>
                <td className="px-4 py-3 text-xs">{TOOL_LABELS[t.tool] ?? t.tool}</td>
                <td className="px-4 py-3">
                  <Badge variant={TASK_STATUS_VARIANT[t.status] ?? "default"}>
                    {t.status}
                  </Badge>
                </td>
                <td className="px-4 py-3 text-xs">
                  {t.status === "running"
                    ? `${t.progress_pct}%`
                    : t.status === "completed"
                      ? "100%"
                      : "—"}
                </td>
                <td className="px-4 py-3 text-xs text-muted-foreground">
                  {t.duration_s != null ? `${Math.round(t.duration_s)}s` : "—"}
                </td>
                <td className="px-4 py-3">
                  <div className="flex items-center gap-2">
                    <Link
                      href={`/targets/${targetId}/workspace/tasks/${t.id}`}
                      className="text-xs underline hover:text-foreground"
                    >
                      View
                    </Link>
                    {deletable && (
                      <Button
                        size="sm"
                        variant="ghost"
                        className="h-6 w-6 p-0 text-destructive hover:text-destructive"
                        onClick={() => {
                          if (
                            confirm(
                              `Delete this ${TOOL_LABELS[t.tool] ?? t.tool} task? Removes its findings.`,
                            )
                          ) {
                            doDelete.mutate(t.id);
                          }
                        }}
                        disabled={doDelete.isPending}
                        title="Delete task"
                      >
                        <Trash2 className="h-3 w-3" />
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
  );
}

export default function TargetWorkspacePage({
  params,
}: {
  params: { id: string };
}) {
  return (
    <Suspense fallback={<div className="p-6 text-sm">Loading…</div>}>
      <WorkspaceContent params={params} />
    </Suspense>
  );
}
