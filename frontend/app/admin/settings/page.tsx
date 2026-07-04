"use client";

import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Eye, EyeOff } from "lucide-react";
import { AppShell } from "@/components/AppShell";
import { Badge } from "@/components/ui/badge";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  OPENROUTER_PRESET_MODELS,
  api,
  getOpenRouterSettings,
  testOpenRouterConnection,
  updateOpenRouterSettings,
  type OpenRouterTestResult,
} from "@/lib/api";

type SystemSettings = {
  bbot_timeout: number;
  jwt_access_expire_minutes: number;
  jwt_refresh_expire_days: number;
};

export default function AdminSettingsPage() {
  const qc = useQueryClient();
  const settings = useQuery({
    queryKey: ["admin", "system-settings"],
    queryFn: () => api<SystemSettings>("/settings/system"),
  });

  const [draft, setDraft] = useState<Partial<SystemSettings>>({});
  useEffect(() => {
    if (settings.data) setDraft({});
  }, [settings.data]);

  const save = useMutation({
    mutationFn: () =>
      api<SystemSettings>("/settings/system", {
        method: "PATCH",
        body: JSON.stringify(draft),
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["admin", "system-settings"] }),
  });

  if (!settings.data) return <AppShell><div /></AppShell>;
  const cur = { ...settings.data, ...draft };

  return (
    <AppShell>
      <div className="max-w-2xl space-y-6">
        <header>
          <h1 className="text-2xl font-semibold tracking-tight">System settings</h1>
          <p className="text-sm text-muted-foreground mt-1">
            Runtime knobs for the current process. Restart resets to env values.
          </p>
        </header>

        <form
          onSubmit={(e) => {
            e.preventDefault();
            save.mutate();
          }}
          className="rounded-lg border border-border bg-card p-4 space-y-4"
        >
          <NumberField
            label="bbot timeout (seconds)"
            min={60}
            max={14400}
            value={cur.bbot_timeout}
            onChange={(v) => setDraft({ ...draft, bbot_timeout: v })}
          />

          <div className="text-xs text-muted-foreground space-y-1 border-t border-border pt-3">
            <div>Access token TTL: {cur.jwt_access_expire_minutes} minutes (env-controlled)</div>
            <div>Refresh token TTL: {cur.jwt_refresh_expire_days} days (env-controlled)</div>
          </div>

          <button
            type="submit"
            disabled={save.isPending || Object.keys(draft).length === 0}
            className="bg-primary text-primary-foreground rounded px-4 py-2 text-sm font-medium disabled:opacity-50"
          >
            {save.isPending ? "Saving..." : "Save"}
          </button>
        </form>

        <OpenRouterCard />
      </div>
    </AppShell>
  );
}

const CUSTOM_MODEL = "__custom__";

function OpenRouterCard() {
  const qc = useQueryClient();
  const q = useQuery({
    queryKey: ["admin", "openrouter-settings"],
    queryFn: getOpenRouterSettings,
  });

  const [apiKey, setApiKey] = useState("");
  const [showKey, setShowKey] = useState(false);
  const [model, setModel] = useState("");
  const [customModel, setCustomModel] = useState("");
  const [usingCustom, setUsingCustom] = useState(false);
  const [test, setTest] = useState<OpenRouterTestResult | null>(null);

  useEffect(() => {
    if (!q.data) return;
    const m = q.data.default_model;
    if (OPENROUTER_PRESET_MODELS.includes(m)) {
      setModel(m);
      setUsingCustom(false);
    } else {
      setModel(CUSTOM_MODEL);
      setCustomModel(m);
      setUsingCustom(true);
    }
  }, [q.data]);

  const effectiveModel = usingCustom ? customModel.trim() : model;

  const body = () => ({
    api_key: apiKey.trim() ? apiKey.trim() : null,
    default_model: effectiveModel || null,
  });

  const save = useMutation({
    mutationFn: () => updateOpenRouterSettings(body()),
    onSuccess: () => {
      setApiKey("");
      setTest(null);
      qc.invalidateQueries({ queryKey: ["admin", "openrouter-settings"] });
    },
  });

  const testMut = useMutation({
    mutationFn: () => testOpenRouterConnection(body()),
    onSuccess: (r) => setTest(r),
  });

  if (!q.data) return null;

  return (
    <form
      onSubmit={(e) => {
        e.preventDefault();
        save.mutate();
      }}
      className="rounded-lg border border-border bg-card p-4 space-y-4"
    >
      <div>
        <h2 className="text-sm font-semibold">OpenRouter Configuration</h2>
        <p className="text-xs text-muted-foreground mt-0.5">
          API key + default model for AI features. Stored server-side; the key is
          never shown again.
        </p>
      </div>

      <div>
        <label className="text-sm font-medium">OpenRouter API Key</label>
        <div className="mt-1 flex gap-2">
          <input
            type={showKey ? "text" : "password"}
            value={apiKey}
            onChange={(e) => setApiKey(e.target.value)}
            placeholder={
              q.data.api_key_set
                ? `configured (${q.data.api_key_hint ?? "•••"}) — leave blank to keep`
                : "sk-or-..."
            }
            className="flex-1 bg-neutral-900 border border-neutral-800 rounded px-3 py-2 text-sm font-mono"
          />
          <button
            type="button"
            onClick={() => setShowKey((v) => !v)}
            className="px-3 rounded border border-neutral-800 text-muted-foreground hover:text-foreground"
            aria-label={showKey ? "Hide key" : "Show key"}
          >
            {showKey ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
          </button>
        </div>
      </div>

      <div>
        <label className="text-sm font-medium">Default Model</label>
        <Select
          value={model}
          onValueChange={(v) => {
            setModel(v);
            setUsingCustom(v === CUSTOM_MODEL);
          }}
        >
          <SelectTrigger className="mt-1 h-9 text-sm">
            <SelectValue placeholder="Select model" />
          </SelectTrigger>
          <SelectContent>
            {OPENROUTER_PRESET_MODELS.map((m) => (
              <SelectItem key={m} value={m}>
                {m}
              </SelectItem>
            ))}
            <SelectItem value={CUSTOM_MODEL}>Custom…</SelectItem>
          </SelectContent>
        </Select>
        {usingCustom && (
          <input
            type="text"
            value={customModel}
            onChange={(e) => setCustomModel(e.target.value)}
            placeholder="vendor/model"
            className="mt-2 w-full bg-neutral-900 border border-neutral-800 rounded px-3 py-2 text-sm font-mono"
          />
        )}
      </div>

      {test && (
        <div className="flex items-center gap-2 text-sm">
          <Badge
            variant={
              test.status === "connected"
                ? "success"
                : test.status === "invalid_key"
                  ? "destructive"
                  : "warning"
            }
          >
            {test.status === "connected"
              ? "Connected"
              : test.status === "invalid_key"
                ? "Invalid Key"
                : "Connection Failed"}
          </Badge>
          {test.detail && (
            <span className="text-xs text-muted-foreground">{test.detail}</span>
          )}
        </div>
      )}

      <div className="flex gap-2">
        <button
          type="button"
          onClick={() => testMut.mutate()}
          disabled={testMut.isPending}
          className="border border-border rounded px-4 py-2 text-sm font-medium hover:bg-accent disabled:opacity-50"
        >
          {testMut.isPending ? "Testing..." : "Test Connection"}
        </button>
        <button
          type="submit"
          disabled={save.isPending}
          className="bg-primary text-primary-foreground rounded px-4 py-2 text-sm font-medium disabled:opacity-50"
        >
          {save.isPending ? "Saving..." : "Save"}
        </button>
      </div>
    </form>
  );
}

function NumberField({
  label,
  value,
  min,
  max,
  onChange,
}: {
  label: string;
  value: number;
  min: number;
  max: number;
  onChange: (v: number) => void;
}) {
  return (
    <div>
      <label className="text-sm font-medium">{label}</label>
      <input
        type="number"
        min={min}
        max={max}
        value={value}
        onChange={(e) => onChange(Number(e.target.value))}
        className="mt-1 w-full bg-neutral-900 border border-neutral-800 rounded px-3 py-2 text-sm"
      />
    </div>
  );
}
