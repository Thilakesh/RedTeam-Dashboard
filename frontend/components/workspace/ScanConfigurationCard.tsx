"use client";

import { useEffect, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { History, Play, RotateCcw, Save } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  TOOL_LABELS,
  createInvestigationTask,
  getScanProfiles,
  type ScanProfileSpec,
  type ToolProfileBundle,
  type WorkspaceScanEntry,
  type WorkspaceSubdomainIpRow,
} from "@/lib/api";
import { ScansDropdown } from "./ScansDropdown";

type TargetType = "domain" | "ip";
type Protocol = "http" | "https";

const TOOL_ORDER = ["nmap_deep", "ffuf", "dirsearch", "testssl"] as const;
const PROTOCOL_DEFAULT_PORT: Record<Protocol, number> = { http: 80, https: 443 };

function savedProfileKey(tool: string): string {
  return `tw:saved-profiles:${tool}`;
}

type SavedProfile = { id: string; label: string; args: string[] };

function loadSavedProfiles(tool: string): SavedProfile[] {
  if (typeof window === "undefined") return [];
  try {
    const raw = window.localStorage.getItem(savedProfileKey(tool));
    return raw ? (JSON.parse(raw) as SavedProfile[]) : [];
  } catch {
    return [];
  }
}

function persistSavedProfiles(tool: string, profiles: SavedProfile[]): void {
  if (typeof window === "undefined") return;
  window.localStorage.setItem(savedProfileKey(tool), JSON.stringify(profiles));
}

function buildPreview(
  tool: string,
  bundle: ToolProfileBundle | undefined,
  args: string[],
  target: string,
  protocol: Protocol,
  port: number,
): string {
  if (!bundle) return "";
  const binary = bundle.binary;
  if (tool === "ffuf") {
    const url = `${protocol}://${target}${port === PROTOCOL_DEFAULT_PORT[protocol] ? "" : `:${port}`}/FUZZ`;
    return [
      binary,
      "-u", url,
      "-w", "$INVESTIGATION_WORDLIST",
      ...args,
      "-of", "json",
      "-o", "<tmp>",
      "-noninteractive",
    ].join(" ");
  }
  if (tool === "dirsearch") {
    const url = `${protocol}://${target}${port === PROTOCOL_DEFAULT_PORT[protocol] ? "" : `:${port}`}`;
    return [
      binary,
      "-u", url,
      "-w", "$INVESTIGATION_WORDLIST",
      "--format=json",
      "-o", "<tmp>",
      "--quiet-mode",
      "--no-color",
      ...args,
    ].join(" ");
  }
  if (tool === "testssl") {
    return [
      binary,
      "--quiet",
      "--color", "0",
      "--jsonfile", "<tmp>",
      ...args,
      `${target}:${port}`,
    ].join(" ");
  }
  // nmap_deep — protocol/port not relevant to nmap
  return [binary, ...args, "-oX", "<tmp>", target].join(" ");
}

export function ScanConfigurationCard({
  workspaceId,
  fqdn,
  domainAssetId,
  ipRows,
  domainScans,
  targetId,
  onTaskCreated,
}: {
  workspaceId: string;
  fqdn: string;
  domainAssetId: string;
  ipRows: WorkspaceSubdomainIpRow[];
  domainScans: WorkspaceScanEntry[];
  targetId: string;
  onTaskCreated: () => void;
}) {
  const qc = useQueryClient();
  const profilesQ = useQuery({
    queryKey: ["scan-profiles"],
    queryFn: getScanProfiles,
    staleTime: 5 * 60 * 1000,
  });

  const [targetType, setTargetType] = useState<TargetType>("domain");
  const [protocol, setProtocol] = useState<Protocol>("https");
  const [tool, setTool] = useState<string>("nmap_deep");
  const [profileId, setProfileId] = useState<string>("");
  const [customArgs, setCustomArgs] = useState<string>("");
  const [error, setError] = useState<string | null>(null);

  const bundle = profilesQ.data?.[tool];
  const profiles: ScanProfileSpec[] = bundle?.profiles ?? [];
  const savedProfiles = useMemo(() => loadSavedProfiles(tool), [tool, profileId]);
  const [savedRev, setSavedRev] = useState(0);

  useEffect(() => {
    if (!bundle) return;
    // Reset profile selection when tool changes
    const def = bundle.default;
    setProfileId(def);
    const defSpec = bundle.profiles.find((p) => p.id === def);
    setCustomArgs(defSpec ? defSpec.args.join(" ") : "");
  }, [bundle]);

  const isCustom = profileId === "custom";
  const activeProfile = profiles.find((p) => p.id === profileId);
  const activeSaved = savedProfiles.find((p) => p.id === profileId);

  const argsForPreview: string[] = useMemo(() => {
    if (isCustom) {
      const trimmed = customArgs.trim();
      return trimmed ? trimmed.split(/\s+/) : [];
    }
    if (activeProfile) return activeProfile.args;
    if (activeSaved) return activeSaved.args;
    return [];
  }, [isCustom, customArgs, activeProfile, activeSaved]);

  const targetLabel = useMemo(() => {
    if (targetType === "domain") return fqdn;
    return ipRows[0]?.ip ?? fqdn;
  }, [targetType, fqdn, ipRows]);

  const targetAssetId = useMemo(() => {
    if (targetType === "domain") return domainAssetId;
    return ipRows[0]?.asset_id ?? domainAssetId;
  }, [targetType, domainAssetId, ipRows]);

  const port = PROTOCOL_DEFAULT_PORT[protocol];
  const preview = buildPreview(tool, bundle, argsForPreview, targetLabel, protocol, port);

  const runMut = useMutation({
    mutationFn: async () => {
      const params: Record<string, unknown> = {
        protocol,
        port,
        profile: profileId,
      };
      if (isCustom) params.custom_args = customArgs;
      return createInvestigationTask(workspaceId, {
        asset_id: targetAssetId,
        tool,
        params,
      });
    },
    onSuccess: () => {
      setError(null);
      qc.invalidateQueries({ queryKey: ["workspace-subdomains", workspaceId] });
      qc.invalidateQueries({ queryKey: ["workspace-tasks", workspaceId] });
      onTaskCreated();
    },
    onError: (e: Error) => setError(e.message),
  });

  const handleReset = () => {
    if (!bundle) return;
    setProfileId(bundle.default);
    const defSpec = bundle.profiles.find((p) => p.id === bundle.default);
    setCustomArgs(defSpec ? defSpec.args.join(" ") : "");
    setError(null);
  };

  const handleSaveProfile = () => {
    if (!isCustom) return;
    const name = window.prompt("Profile name (saved per-tool in browser):");
    if (!name) return;
    const trimmed = customArgs.trim();
    if (!trimmed) return;
    const id = `saved:${Date.now().toString(36)}`;
    const next = [
      ...savedProfiles,
      { id, label: name, args: trimmed.split(/\s+/) },
    ];
    persistSavedProfiles(tool, next);
    setSavedRev((r) => r + 1);
    setProfileId(id);
  };

  const handleProfileChange = (id: string) => {
    setProfileId(id);
    const builtin = profiles.find((p) => p.id === id);
    if (builtin && id !== "custom") {
      setCustomArgs(builtin.args.join(" "));
      return;
    }
    const saved = loadSavedProfiles(tool).find((p) => p.id === id);
    if (saved) {
      setCustomArgs(saved.args.join(" "));
    }
  };

  return (
    <div className="rounded-md border border-border bg-card p-4 space-y-3">
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-semibold">Scan Configuration · {fqdn}</h3>
        <ScansDropdown
          fqdn={fqdn}
          domainScans={domainScans}
          ipRows={ipRows}
          targetId={targetId}
        />
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        {ipRows.length > 0 && (
          <Field label="Target Type">
            <div className="flex gap-2">
              <label className="inline-flex items-center gap-1.5 text-sm">
                <input
                  type="radio"
                  checked={targetType === "domain"}
                  onChange={() => setTargetType("domain")}
                />
                Domain
              </label>
              <label className="inline-flex items-center gap-1.5 text-sm">
                <input
                  type="radio"
                  checked={targetType === "ip"}
                  onChange={() => setTargetType("ip")}
                />
                IP ({ipRows[0].ip})
              </label>
            </div>
          </Field>
        )}

        <Field label="Protocol">
          <div className="inline-flex rounded-md border border-border overflow-hidden">
            {(["http", "https"] as Protocol[]).map((p) => (
              <button
                key={p}
                type="button"
                onClick={() => setProtocol(p)}
                className={`px-3 py-1 text-xs ${
                  protocol === p
                    ? "bg-primary text-primary-foreground"
                    : "bg-background hover:bg-muted/50"
                }`}
              >
                {p.toUpperCase()}
              </button>
            ))}
          </div>
        </Field>

        <Field label="Tool">
          <Select value={tool} onValueChange={setTool}>
            <SelectTrigger className="h-8 text-sm">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {TOOL_ORDER.map((t) => (
                <SelectItem key={t} value={t}>
                  {TOOL_LABELS[t] ?? t}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </Field>

        <Field label="Scan Profile">
          <Select value={profileId} onValueChange={handleProfileChange}>
            <SelectTrigger className="h-8 text-sm">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {profiles.map((p) => (
                <SelectItem key={p.id} value={p.id}>
                  {p.label}
                </SelectItem>
              ))}
              {savedProfiles.length > 0 && (
                <>
                  <div className="px-2 py-1 text-xxs uppercase text-muted-foreground">
                    Saved
                  </div>
                  {savedProfiles.map((p) => (
                    <SelectItem key={p.id} value={p.id}>
                      {p.label}
                    </SelectItem>
                  ))}
                </>
              )}
            </SelectContent>
          </Select>
        </Field>
      </div>

      {activeProfile?.description && (
        <p className="text-xs text-muted-foreground">{activeProfile.description}</p>
      )}

      <div>
        <div className="text-xxs uppercase text-muted-foreground mb-1">
          Command Preview
        </div>
        <pre className="rounded-md border border-border bg-muted/30 px-3 py-2 text-xs font-mono whitespace-pre-wrap break-all">
          {preview || "—"}
        </pre>
      </div>

      <div>
        <div className="text-xxs uppercase text-muted-foreground mb-1 flex items-center justify-between">
          <span>{isCustom ? "Custom Args" : "Editable Args (switch to Custom to use)"}</span>
          {!isCustom && (
            <button
              type="button"
              onClick={() => setProfileId("custom")}
              className="text-xs underline text-muted-foreground hover:text-foreground"
            >
              edit
            </button>
          )}
        </div>
        <input
          type="text"
          value={customArgs}
          onChange={(e) => setCustomArgs(e.target.value)}
          disabled={!isCustom}
          className="w-full rounded-md border border-border bg-background px-3 py-1.5 text-xs font-mono disabled:opacity-60"
          placeholder="-A -T4 -Pn"
        />
      </div>

      {error && (
        <div className="rounded-md border border-destructive/40 bg-destructive/5 px-3 py-2 text-xs text-destructive">
          {error}
        </div>
      )}

      <div className="flex items-center justify-between gap-2 pt-1">
        <div className="flex gap-2">
          <Button variant="outline" size="sm" onClick={handleReset}>
            <RotateCcw className="h-3.5 w-3.5 mr-1" />
            Reset
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={handleSaveProfile}
            disabled={!isCustom || !customArgs.trim()}
          >
            <Save className="h-3.5 w-3.5 mr-1" />
            Save Profile
          </Button>
        </div>
        <Button
          size="sm"
          onClick={() => runMut.mutate()}
          disabled={runMut.isPending || !preview}
        >
          <Play className="h-3.5 w-3.5 mr-1" />
          {runMut.isPending ? "Queuing…" : "Run Scan"}
        </Button>
      </div>
    </div>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <div className="text-xxs uppercase text-muted-foreground mb-1">{label}</div>
      {children}
    </div>
  );
}
