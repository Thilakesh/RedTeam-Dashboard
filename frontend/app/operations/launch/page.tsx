"use client";

import { useEffect, useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { useRouter } from "next/navigation";
import { Play } from "lucide-react";
import { AppShell } from "@/components/AppShell";
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
  createOperation,
  getScanProfiles,
  previewOperation,
  type ScanProfileSpec,
} from "@/lib/api";

type TargetType = "domain" | "ipv4";
type Protocol = "http" | "https";

const TOOL_ORDER = ["nmap_deep", "ffuf", "dirsearch", "testssl"] as const;

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

  return (
    <div className="container mx-auto max-w-3xl space-y-5">
      <div>
        <h1 className="text-xl font-semibold">Launch Operation</h1>
        <p className="text-sm text-muted-foreground">
          Run a one-off scan against a manually entered domain or IP. Standalone —
          not linked to recon assets.
        </p>
      </div>

      <div className="rounded-md border border-border bg-card p-4 space-y-3">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          <Field label="Target Type">
            <div className="inline-flex rounded-md border border-border overflow-hidden">
              {(["domain", "ipv4"] as TargetType[]).map((t) => (
                <button
                  key={t}
                  type="button"
                  onClick={() => setTargetType(t)}
                  className={`px-3 py-1 text-xs ${
                    targetType === t
                      ? "bg-primary text-primary-foreground"
                      : "bg-background hover:bg-muted/50"
                  }`}
                >
                  {t === "domain" ? "Domain" : "IP"}
                </button>
              ))}
            </div>
          </Field>

          <Field label="Target">
            <input
              type="text"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder={targetType === "domain" ? "example.com" : "192.0.2.1"}
              className="w-full rounded-md border border-border bg-background px-3 py-1.5 text-sm font-mono"
            />
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
              </SelectContent>
            </Select>
          </Field>

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
        </div>

        {activeProfile?.description && (
          <p className="text-xs text-muted-foreground">{activeProfile.description}</p>
        )}

        <div>
          <div className="text-xxs uppercase text-muted-foreground mb-1">
            Command Preview
          </div>
          <pre className="rounded-md border border-border bg-muted/30 px-3 py-2 text-xs font-mono whitespace-pre-wrap break-all min-h-[2.5rem]">
            {preview || "—"}
          </pre>
          {previewErr && <p className="mt-1 text-xs text-destructive">{previewErr}</p>}
        </div>

        <div>
          <div className="text-xxs uppercase text-muted-foreground mb-1 flex items-center justify-between">
            <span>{isCustom ? "Custom Args" : "Editable Args (switch to Custom)"}</span>
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
            placeholder="-A -T4 -Pn"
            className="w-full rounded-md border border-border bg-background px-3 py-1.5 text-xs font-mono disabled:opacity-60"
          />
        </div>

        {runMut.isError && (
          <div className="rounded-md border border-destructive/40 bg-destructive/5 px-3 py-2 text-xs text-destructive">
            {(runMut.error as Error).message}
          </div>
        )}

        <div className="flex justify-end pt-1">
          <Button
            size="sm"
            onClick={() => runMut.mutate()}
            disabled={runMut.isPending || !preview}
          >
            <Play className="h-3.5 w-3.5 mr-1" />
            {runMut.isPending ? "Starting…" : "Start Operation"}
          </Button>
        </div>
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

export default function LaunchOperationPage() {
  return (
    <AppShell>
      <LaunchForm />
    </AppShell>
  );
}
