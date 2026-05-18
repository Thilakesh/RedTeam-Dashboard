"use client";

import { useParams, useRouter } from "next/navigation";
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AppShell } from "@/components/AppShell";
import { ApiError, api } from "@/lib/api";

type UserRow = {
  id: string;
  email: string;
  role: "admin" | "analyst";
  is_active: boolean;
  created_by: string | null;
  created_at: string;
  has_pending_invite: boolean;
};

type FeatureRow = { feature_name: string; enabled: boolean };

type CreateResp = {
  user: UserRow;
  invite_token: string;
  invite_url: string;
};

export default function AdminUserDetailPage() {
  const { id } = useParams<{ id: string }>();
  const router = useRouter();
  const qc = useQueryClient();

  const user = useQuery({
    queryKey: ["admin", "user", id],
    queryFn: () => api<UserRow>(`/users/${id}`),
  });

  const features = useQuery({
    queryKey: ["admin", "user", id, "features"],
    queryFn: () => api<FeatureRow[]>(`/users/${id}/features`),
  });

  const patch = useMutation({
    mutationFn: (body: Partial<{ role: string; is_active: boolean }>) =>
      api<UserRow>(`/users/${id}`, { method: "PATCH", body: JSON.stringify(body) }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["admin", "user", id] }),
  });

  const toggleFeature = useMutation({
    mutationFn: (vars: { feature: string; enabled: boolean }) =>
      api<FeatureRow>(`/users/${id}/features/${vars.feature}`, {
        method: "PUT",
        body: JSON.stringify({ enabled: vars.enabled }),
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["admin", "user", id, "features"] });
      qc.invalidateQueries({ queryKey: ["me"] });
    },
  });

  const regenInvite = useMutation({
    mutationFn: () =>
      api<CreateResp>(`/users/${id}/invite/regenerate`, { method: "POST" }),
  });

  const del = useMutation({
    mutationFn: () => api<void>(`/users/${id}`, { method: "DELETE" }),
    onSuccess: () => router.replace("/admin/users"),
  });

  if (!user.data) return <AppShell><div /></AppShell>;
  const u = user.data;

  return (
    <AppShell>
      <div className="max-w-3xl space-y-6">
        <header>
          <h1 className="text-2xl font-semibold tracking-tight">{u.email}</h1>
          <p className="text-sm text-muted-foreground mt-1 capitalize">
            {u.role} · {u.is_active ? "active" : "disabled"}
            {u.has_pending_invite && " · invite pending"}
          </p>
        </header>

        <div className="rounded-lg border border-border bg-card p-4 space-y-3">
          <h2 className="text-sm font-semibold">Role & status</h2>
          <div className="flex flex-wrap gap-2">
            <button
              onClick={() => patch.mutate({ role: u.role === "admin" ? "analyst" : "admin" })}
              className="text-xs px-3 py-1.5 rounded border border-border hover:bg-accent"
            >
              Make {u.role === "admin" ? "analyst" : "admin"}
            </button>
            <button
              onClick={() => patch.mutate({ is_active: !u.is_active })}
              className="text-xs px-3 py-1.5 rounded border border-border hover:bg-accent"
            >
              {u.is_active ? "Disable" : "Enable"}
            </button>
            <button
              onClick={() => regenInvite.mutate()}
              className="text-xs px-3 py-1.5 rounded border border-border hover:bg-accent"
            >
              Regenerate invite link
            </button>
            <button
              onClick={() => {
                if (confirm(`Delete (disable) ${u.email}?`)) del.mutate();
              }}
              className="text-xs px-3 py-1.5 rounded border border-red-500/40 text-red-400 hover:bg-red-500/10"
            >
              Delete user
            </button>
          </div>
          {patch.error instanceof ApiError && (
            <p className="text-red-400 text-sm">{patch.error.message}</p>
          )}
          {regenInvite.data && (
            <div className="mt-2 p-3 rounded bg-emerald-500/10 border border-emerald-500/40">
              <p className="text-xs text-muted-foreground mb-1">New invite URL (single-use, 24h):</p>
              <input
                readOnly
                value={regenInvite.data.invite_url}
                onFocus={(e) => e.currentTarget.select()}
                className="w-full bg-neutral-900 border border-neutral-800 rounded px-2 py-1 text-xs font-mono"
              />
            </div>
          )}
        </div>

        <div className="rounded-lg border border-border bg-card p-4 space-y-3">
          <h2 className="text-sm font-semibold">Features</h2>
          <p className="text-xs text-muted-foreground">
            Default is enabled. Toggle off to revoke a capability for this user.
          </p>
          <div className="space-y-1">
            {features.data?.map((f) => (
              <label key={f.feature_name} className="flex items-center justify-between text-sm py-1 border-b border-border/40 last:border-b-0">
                <span className="font-mono text-xs">{f.feature_name}</span>
                <input
                  type="checkbox"
                  checked={f.enabled}
                  onChange={(e) =>
                    toggleFeature.mutate({ feature: f.feature_name, enabled: e.target.checked })
                  }
                  className="h-4 w-4"
                />
              </label>
            ))}
          </div>
        </div>
      </div>
    </AppShell>
  );
}
