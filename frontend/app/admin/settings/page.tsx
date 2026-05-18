"use client";

import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AppShell } from "@/components/AppShell";
import { api } from "@/lib/api";

type SystemSettings = {
  bbot_timeout: number;
  jwt_access_expire_minutes: number;
  jwt_refresh_expire_days: number;
  rl_login_per_15min: number;
  rl_refresh_per_min: number;
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
          <NumberField
            label="login attempts per 15 minutes (per IP)"
            min={1}
            max={1000}
            value={cur.rl_login_per_15min}
            onChange={(v) => setDraft({ ...draft, rl_login_per_15min: v })}
          />
          <NumberField
            label="refresh attempts per minute (per session)"
            min={1}
            max={1000}
            value={cur.rl_refresh_per_min}
            onChange={(v) => setDraft({ ...draft, rl_refresh_per_min: v })}
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
      </div>
    </AppShell>
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
