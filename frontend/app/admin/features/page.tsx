"use client";

import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Search, ShieldCheck } from "lucide-react";
import { AppShell } from "@/components/AppShell";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
import { cn } from "@/lib/cn";
import { api } from "@/lib/api";

type UserRow = {
  id: string;
  email: string;
  role: "admin" | "analyst";
  is_active: boolean;
};

type FeatureRow = { feature_name: string; enabled: boolean };

const SCOPES: { name: string; label: string; description: string }[] = [
  { name: "recon", label: "Basic Recon", description: "Create and run recon scans (any profile)." },
  { name: "deep_scan", label: "Deep Scan Profile", description: "Request the ‘deep’ scan profile specifically." },
  { name: "target_workspace", label: "Target Workspace", description: "Open per-asset investigation workspaces." },
  { name: "investigations", label: "Investigation Tasks", description: "Launch investigation tasks inside a workspace." },
  { name: "operations", label: "Operations Console", description: "Standalone manual tool operations." },
  { name: "export_reports", label: "Report Export", description: "Export scan reports." },
];

const TOOL_GROUPS: { title: string; tools: { name: string; label: string }[] }[] = [
  {
    title: "Recon pipeline tools",
    tools: [
      { name: "subfinder", label: "Subfinder" },
      { name: "assetfinder", label: "Assetfinder" },
      { name: "amass", label: "Amass" },
      { name: "bbot", label: "BBOT" },
      { name: "dnsx", label: "dnsx" },
      { name: "httpx", label: "httpx" },
      { name: "asnmap", label: "asnmap" },
      { name: "geoip", label: "GeoIP" },
      { name: "wafw00f", label: "wafw00f" },
      { name: "naabu", label: "Naabu" },
      { name: "nmap", label: "Nmap" },
      { name: "gowitness", label: "Gowitness" },
      { name: "risk_prioritizer", label: "AI Risk Prioritizer" },
    ],
  },
  {
    title: "Investigation & Operations tools",
    tools: [
      { name: "ffuf", label: "ffuf" },
      { name: "dirsearch", label: "dirsearch" },
      { name: "nmap_deep", label: "Nmap (deep)" },
      { name: "testssl", label: "testssl.sh" },
    ],
  },
];

export default function AdminFeaturesPage() {
  const qc = useQueryClient();
  const [search, setSearch] = useState("");
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const users = useQuery({
    queryKey: ["admin", "users"],
    queryFn: () => api<UserRow[]>("/users"),
  });

  const activeUsers = useMemo(() => (users.data ?? []).filter((u) => u.is_active), [users.data]);
  const filteredUsers = useMemo(() => {
    const term = search.trim().toLowerCase();
    if (!term) return activeUsers;
    return activeUsers.filter((u) => u.email.toLowerCase().includes(term));
  }, [activeUsers, search]);

  const selectedUser = activeUsers.find((u) => u.id === selectedId) ?? null;

  const featureQuery = useQuery({
    queryKey: ["admin", "user-features", selectedId],
    queryFn: () => api<FeatureRow[]>(`/users/${selectedId}/features`),
    enabled: !!selectedId,
  });

  const byName = useMemo(() => {
    const map: Record<string, boolean> = {};
    (featureQuery.data ?? []).forEach((f) => (map[f.feature_name] = f.enabled));
    return map;
  }, [featureQuery.data]);

  const disabledCount = (featureQuery.data ?? []).filter((f) => !f.enabled).length;

  const toggle = useMutation({
    mutationFn: (vars: { feature: string; enabled: boolean }) =>
      api<FeatureRow>(`/users/${selectedId}/features/${vars.feature}`, {
        method: "PUT",
        body: JSON.stringify({ enabled: vars.enabled }),
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["admin", "user-features", selectedId] });
    },
  });

  return (
    <AppShell>
      <div className="space-y-6">
        <header>
          <h1 className="text-2xl font-semibold tracking-tight">Feature controls</h1>
          <p className="text-sm text-muted-foreground mt-1">
            Pick a user, then restrict a whole area or an individual tool. Default is enabled.
          </p>
        </header>

        <div className="grid grid-cols-[280px_1fr] gap-4 items-start">
          <div className="rounded-lg border border-border bg-card overflow-hidden">
            <div className="p-2 border-b border-border">
              <div className="relative">
                <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
                <Input
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  placeholder="Search users…"
                  className="pl-8"
                />
              </div>
            </div>
            <div className="max-h-[calc(100vh-260px)] overflow-y-auto">
              {users.isLoading && (
                <p className="px-3 py-4 text-sm text-muted-foreground">Loading users…</p>
              )}
              {filteredUsers.map((u) => (
                <button
                  key={u.id}
                  onClick={() => setSelectedId(u.id)}
                  className={cn(
                    "w-full text-left px-3 py-2.5 border-b border-border last:border-0 transition-colors",
                    selectedId === u.id ? "bg-primary/10" : "hover:bg-muted/40",
                  )}
                >
                  <div className="text-sm font-medium truncate">{u.email}</div>
                  <div className="text-xxs text-muted-foreground capitalize">{u.role}</div>
                </button>
              ))}
              {!users.isLoading && filteredUsers.length === 0 && (
                <p className="px-3 py-4 text-sm text-muted-foreground">No users match.</p>
              )}
            </div>
          </div>

          <div className="rounded-lg border border-border bg-card p-5 min-h-[420px]">
            {!selectedUser && (
              <div className="h-full flex flex-col items-center justify-center text-center text-muted-foreground py-20">
                <ShieldCheck className="h-8 w-8 mb-3 opacity-50" />
                <p className="text-sm">Select a user on the left to manage their access.</p>
              </div>
            )}

            {selectedUser && (
              <div className="space-y-6">
                <div className="flex items-center justify-between">
                  <div>
                    <div className="text-base font-semibold">{selectedUser.email}</div>
                    <div className="text-xs text-muted-foreground capitalize">{selectedUser.role}</div>
                  </div>
                  {disabledCount > 0 ? (
                    <Badge variant="warning">{disabledCount} restricted</Badge>
                  ) : (
                    <Badge variant="success">Full access</Badge>
                  )}
                </div>

                {featureQuery.isLoading && (
                  <p className="text-sm text-muted-foreground">Loading feature state…</p>
                )}

                {featureQuery.data && (
                  <>
                    <FeatureSection title="Scopes" description="Broad areas — disabling one blocks every action underneath it, regardless of tool-level flags.">
                      {SCOPES.map((s) => (
                        <FeatureToggle
                          key={s.name}
                          label={s.label}
                          description={s.description}
                          checked={byName[s.name] ?? true}
                          onChange={(v) => toggle.mutate({ feature: s.name, enabled: v })}
                        />
                      ))}
                    </FeatureSection>

                    {TOOL_GROUPS.map((group) => (
                      <FeatureSection key={group.title} title={group.title}>
                        <div className="grid grid-cols-2 gap-x-6">
                          {group.tools.map((t) => (
                            <FeatureToggle
                              key={t.name}
                              label={t.label}
                              checked={byName[t.name] ?? true}
                              onChange={(v) => toggle.mutate({ feature: t.name, enabled: v })}
                              compact
                            />
                          ))}
                        </div>
                      </FeatureSection>
                    ))}
                  </>
                )}
              </div>
            )}
          </div>
        </div>
      </div>
    </AppShell>
  );
}

function FeatureSection({
  title,
  description,
  children,
}: {
  title: string;
  description?: string;
  children: React.ReactNode;
}) {
  return (
    <section>
      <div className="mb-2.5">
        <h2 className="text-sm font-semibold">{title}</h2>
        {description && <p className="text-xs text-muted-foreground mt-0.5">{description}</p>}
      </div>
      <div className="space-y-1">{children}</div>
    </section>
  );
}

function FeatureToggle({
  label,
  description,
  checked,
  onChange,
  compact,
}: {
  label: string;
  description?: string;
  checked: boolean;
  onChange: (value: boolean) => void;
  compact?: boolean;
}) {
  return (
    <div
      className={cn(
        "flex items-center justify-between gap-3 rounded-md px-2.5",
        compact ? "py-1.5" : "py-2 hover:bg-muted/30",
      )}
    >
      <div className="min-w-0">
        <div className={cn("font-medium", compact ? "text-xs" : "text-sm")}>{label}</div>
        {description && <div className="text-xs text-muted-foreground">{description}</div>}
      </div>
      <Switch checked={checked} onCheckedChange={onChange} />
    </div>
  );
}
