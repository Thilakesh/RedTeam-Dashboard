"use client";

import { useMemo } from "react";
import { useMutation, useQueries, useQuery, useQueryClient } from "@tanstack/react-query";
import { AppShell } from "@/components/AppShell";
import { api } from "@/lib/api";

type UserRow = {
  id: string;
  email: string;
  role: "admin" | "analyst";
  is_active: boolean;
};

type FeatureRow = { feature_name: string; enabled: boolean };

export default function AdminFeaturesPage() {
  const qc = useQueryClient();

  const users = useQuery({
    queryKey: ["admin", "users"],
    queryFn: () => api<UserRow[]>("/users"),
  });

  const analystUsers = useMemo(
    () => (users.data ?? []).filter((u) => u.is_active),
    [users.data],
  );

  const featuresPerUser = useQueries({
    queries: analystUsers.map((u) => ({
      queryKey: ["admin", "user-features", u.id],
      queryFn: () => api<FeatureRow[]>(`/users/${u.id}/features`),
      enabled: !!u.id,
    })),
  });

  const toggle = useMutation({
    mutationFn: (vars: { user_id: string; feature: string; enabled: boolean }) =>
      api<FeatureRow>(`/users/${vars.user_id}/features/${vars.feature}`, {
        method: "PUT",
        body: JSON.stringify({ enabled: vars.enabled }),
      }),
    onSuccess: (_data, vars) => {
      qc.invalidateQueries({ queryKey: ["admin", "user-features", vars.user_id] });
    },
  });

  const featureNames = useMemo(() => {
    const firstLoaded = featuresPerUser.find((q) => q.data)?.data;
    return firstLoaded?.map((f) => f.feature_name) ?? [];
  }, [featuresPerUser]);

  return (
    <AppShell>
      <div className="space-y-6">
        <header>
          <h1 className="text-2xl font-semibold tracking-tight">Feature controls</h1>
          <p className="text-sm text-muted-foreground mt-1">
            Toggle individual capabilities per user. Default is enabled.
          </p>
        </header>

        <div className="rounded-lg border border-border bg-card overflow-auto">
          <table className="w-full text-sm">
            <thead className="bg-muted/40 text-xs uppercase text-muted-foreground">
              <tr>
                <th className="text-left px-3 py-2 sticky left-0 bg-muted/40">User</th>
                {featureNames.map((f) => (
                  <th key={f} className="text-center px-3 py-2 font-mono text-[10px]">
                    {f}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {analystUsers.map((u, idx) => {
                const flags = featuresPerUser[idx]?.data ?? [];
                const byName: Record<string, boolean> = {};
                flags.forEach((f) => (byName[f.feature_name] = f.enabled));
                return (
                  <tr key={u.id} className="border-t border-border">
                    <td className="px-3 py-2 sticky left-0 bg-card">
                      <div className="font-medium">{u.email}</div>
                      <div className="text-xxs text-muted-foreground capitalize">{u.role}</div>
                    </td>
                    {featureNames.map((f) => (
                      <td key={f} className="text-center px-3 py-2">
                        <input
                          type="checkbox"
                          checked={byName[f] ?? true}
                          onChange={(e) =>
                            toggle.mutate({
                              user_id: u.id,
                              feature: f,
                              enabled: e.target.checked,
                            })
                          }
                          className="h-4 w-4"
                        />
                      </td>
                    ))}
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </AppShell>
  );
}
