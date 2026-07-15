"use client";

import { useEffect, useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { useRouter } from "next/navigation";
import { Check, Copy, Globe, Play, Search, Server, ShieldCheck } from "lucide-react";
import { AppShell } from "@/components/AppShell";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/cn";
import {
  TOOL_LABELS,
  createOperation,
  getScanProfiles,
  previewOperation,
  type ScanProfileSpec,
} from "@/lib/api";

type TargetType = "domain" | "ipv4";
type Protocol = "http" | "https";

const TOOL_ORDER = ["nmap_deep", "ffuf", "dirsearch", "testssl"] as const;

const TOOL_ICON: Record<string, React.ComponentType<{ className?: string }>> = {
  nmap_deep: Server,
  ffuf: Search,
  dirsearch: Search,
  testssl: ShieldCheck,
};

const TOOL_DESC: Record<string, string> = {
  nmap_deep: "Port + service scan",
  ffuf: "Directory + file fuzzing",
  dirsearch: "Endpoint enumeration",
  testssl: "TLS configuration audit",
};

function LaunchForm() {
  const router = useRouter();
  const profilesQ = useQuery({
    queryKey: ["scan-profiles"],
    queryFn: getScanProfiles,
    staleTime: 5 * 60 * 1000,
  });

  const [targetType, setTargetType] = useState<TargetType>("domain");
  const [target, setTarget] = useState("");
  const [tool, setTool] = useState<string>("nmap_deep");
  const [protocol, setProtocol] = useState<Protocol>("https");
  const [profileId, setProfileId] = useState<string>("");
  const [customArgs, setCustomArgs] = useState<string>("");
  const [copied, setCopied] = useState(false);

  const bundle = profilesQ.data?.[tool];
  const profiles: ScanProfileSpec[] = bundle?.profiles ?? [];
  const isCustom = profileId === "custom";
  const activeProfile = profiles.find((p) => p.id === profileId);

  // Reset profile + editable args when tool changes.
  useEffect(() => {
    if (!bundle) return;
    setProfileId(bundle.default);
    const def = bundle.profiles.find((p) => p.id === bundle.default);
    setCustomArgs(def ? def.args.join(" ") : "");
  }, [bundle]);

  const handleProfileChange = (id: string) => {
    setProfileId(id);
    const builtin = profiles.find((p) => p.id === id);
    if (builtin && id !== "custom") setCustomArgs(builtin.args.join(" "));
  };

  // Server-authoritative command preview (debounced).
  const [preview, setPreview] = useState("");
  const [previewErr, setPreviewErr] = useState<string | null>(null);
  useEffect(() => {
    if (!tool || !profileId || !target.trim()) {
      setPreview("");
      setPreviewErr(null);
      return;
    }
    const handle = setTimeout(() => {
      previewOperation({
        target_type: targetType,
        target: target.trim(),
        tool,
        profile: profileId,
        protocol,
        custom_args: isCustom ? customArgs : null,
      })
        .then((r) => {
          setPreview(r.generated_command);
          setPreviewErr(null);
        })
        .catch((e: Error) => {
          setPreview("");
          setPreviewErr(e.message);
        });
    }, 400);
    return () => clearTimeout(handle);
  }, [targetType, target, tool, protocol, profileId, isCustom, customArgs]);

  const runMut = useMutation({
    mutationFn: () =>
      createOperation({
        target_type: targetType,
        target: target.trim(),
        tool,
        profile: profileId,
        protocol,
        custom_args: isCustom ? customArgs : null,
      }),
    onSuccess: () => router.push("/operations"),
  });

  const handleCopy = () => {
    if (!preview) return;
    navigator.clipboard.writeText(preview).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    });
  };

  return (
    <div className="max-w-[1100px] mx-auto space-y-5">
      <div>
        <div className="kicker mb-2">Operations</div>
        <h1 className="page-h1">Launch Operation</h1>
        <p className="text-sm text-muted-foreground mt-1">
          Run a one-off scan against a manually entered domain or IP. Standalone —
          not linked to recon assets.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-[1.2fr_1fr] gap-4 items-start">
        {/* Left: tool + target */}
        <div className="card-panel space-y-4">
          <div>
            <div className="text-[10px] uppercase tracking-[0.1em] text-muted-foreground-2 mb-2.5">
              1. Pick your tool
            </div>
            <div className="grid grid-cols-2 gap-2">
              {TOOL_ORDER.map((t) => {
                const Icon = TOOL_ICON[t] ?? Server;
                const active = tool === t;
                return (
                  <button
                    key={t}
                    type="button"
                    onClick={() => setTool(t)}
                    className={cn(
                      "text-left rounded-lg border px-3.5 py-3 transition-colors",
                      active ? "border-primary bg-primary/10" : "border-border hover:bg-accent/40",
                    )}
                  >
                    <div className="flex items-center gap-2 mb-1">
                      <Icon className={cn("h-3.5 w-3.5", active ? "text-primary" : "text-muted-foreground")} />
                      <span className={cn("font-medium text-sm", active && "text-primary")}>
                        {TOOL_LABELS[t] ?? t}
                      </span>
                    </div>
                    <div className="text-[10px] text-muted-foreground-2">{TOOL_DESC[t]}</div>
                  </button>
                );
              })}
            </div>
          </div>

          <hr className="rule-fade" />

          <div>
            <div className="text-[10px] uppercase tracking-[0.1em] text-muted-foreground-2 mb-2.5">
              2. Target
            </div>
            <div className="flex gap-3">
              <div className="seg shrink-0">
                {(["domain", "ipv4"] as TargetType[]).map((t) => (
                  <label key={t} className="seg-opt">
                    <input type="radio" checked={targetType === t} onChange={() => setTargetType(t)} />
                    <span className="flex items-center gap-1.5">
                      {t === "domain" ? <Globe className="h-3 w-3" /> : <Server className="h-3 w-3" />}
                      {t === "domain" ? "Domain" : "IP"}
                    </span>
                  </label>
                ))}
              </div>
              <input
                type="text"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                placeholder={targetType === "domain" ? "example.com" : "192.0.2.1"}
                className="flex-1 rounded-md border border-border bg-foreground/[0.03] px-3 py-1.5 text-sm font-mono h-9 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
              />
            </div>
          </div>
        </div>

        {/* Right: options */}
        <div className="card-panel space-y-4">
          <div className="text-[10px] uppercase tracking-[0.1em] text-muted-foreground-2">
            3. Options
          </div>

          <Field label="Scan profile">
            <div className="seg w-full">
              {profiles.map((p) => (
                <label key={p.id} className="seg-opt flex-1 justify-center">
                  <input
                    type="radio"
                    checked={profileId === p.id}
                    onChange={() => handleProfileChange(p.id)}
                  />
                  <span>{p.label}</span>
                </label>
              ))}
            </div>
            {activeProfile?.description && (
              <p className="text-xs text-muted-foreground mt-1.5">{activeProfile.description}</p>
            )}
          </Field>

          <Field label="Protocol">
            <div className="seg">
              {(["http", "https"] as Protocol[]).map((p) => (
                <label key={p} className="seg-opt">
                  <input type="radio" checked={protocol === p} onChange={() => setProtocol(p)} />
                  <span>{p.toUpperCase()}</span>
                </label>
              ))}
            </div>
          </Field>

          <Field label={isCustom ? "Custom args" : "Editable args (switch to Custom)"}>
            <div className="flex gap-2">
              <input
                type="text"
                value={customArgs}
                onChange={(e) => setCustomArgs(e.target.value)}
                disabled={!isCustom}
                placeholder="-A -T4 -Pn"
                className="flex-1 rounded-md border border-border bg-foreground/[0.03] px-3 py-1.5 text-xs font-mono h-9 disabled:opacity-60"
              />
              {!isCustom && (
                <Button variant="outline" size="sm" onClick={() => setProfileId("custom")}>
                  Edit
                </Button>
              )}
            </div>
          </Field>

          <div className="rounded-lg overflow-hidden border border-border">
            <div className="flex items-center justify-between px-3 py-2 bg-foreground/[0.04] border-b border-border">
              <div className="flex items-center gap-2">
                <div className="flex gap-1">
                  <span className="h-2 w-2 rounded-full bg-divider" />
                  <span className="h-2 w-2 rounded-full bg-divider" />
                  <span className="h-2 w-2 rounded-full bg-divider" />
                </div>
                <span className="text-[10px] text-muted-foreground-2 tracking-[0.06em] uppercase ml-1">
                  Command preview
                </span>
              </div>
              <button
                type="button"
                onClick={handleCopy}
                disabled={!preview}
                className="inline-flex items-center gap-1 text-[11px] text-muted-foreground hover:text-foreground disabled:opacity-40"
              >
                {copied ? <Check className="h-3 w-3" /> : <Copy className="h-3 w-3" />}
                {copied ? "Copied" : "Copy"}
              </button>
            </div>
            <pre className="bg-surface-deep px-3 py-2.5 text-xs font-mono whitespace-pre-wrap break-all min-h-[2.5rem] text-foreground/90">
              {preview || "—"}
            </pre>
            {previewErr && <p className="px-3 pb-2 text-xs text-destructive">{previewErr}</p>}
          </div>

          {runMut.isError && (
            <div className="rounded-md border border-destructive/40 bg-destructive/5 px-3 py-2 text-xs text-destructive">
              {(runMut.error as Error).message}
            </div>
          )}

          <Button
            className="w-full h-11"
            onClick={() => runMut.mutate()}
            disabled={runMut.isPending || !preview}
          >
            <Play className="h-4 w-4" />
            {runMut.isPending ? "Starting…" : "Launch"}
          </Button>
        </div>
      </div>
    </div>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <div className="text-xs text-muted-foreground mb-1.5">{label}</div>
      {children}
    </div>
  );
}

export default function LaunchOperationPage() {
  return (
    <AppShell>
      <LaunchForm />
    </AppShell>
  );
}
