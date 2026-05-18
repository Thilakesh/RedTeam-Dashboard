"use client";

import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { AppShell } from "@/components/AppShell";
import { api } from "@/lib/api";

type AuditRow = {
  id: number;
  actor_user_id: string | null;
  actor_ip: string | null;
  action: string;
  target_type: string | null;
  target_id: string | null;
  meta: Record<string, unknown>;
  created_at: string;
};

export default function AdminAuditPage() {
  const [action, setAction] = useState("");
  const audit = useQuery({
    queryKey: ["admin", "audit", action],
    queryFn: () =>
      api<AuditRow[]>(`/admin/audit${action ? `?action=${encodeURIComponent(action)}` : ""}`),
    refetchInterval: 10_000,
  });

  return (
    <AppShell>
      <div className="space-y-6">
        <header className="flex items-center justify-between gap-4">
          <div>
            <h1 className="text-2xl font-semibold tracking-tight">Change logs</h1>
            <p className="text-sm text-muted-foreground mt-1">
              Append-only audit trail of every privileged action.
            </p>
          </div>
          <input
            value={action}
            onChange={(e) => setAction(e.target.value)}
            placeholder="filter action (e.g. auth.login)"
            className="bg-neutral-900 border border-neutral-800 rounded px-3 py-2 text-sm w-72"
          />
        </header>

        <div className="rounded-lg border border-border bg-card overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-muted/40 text-xs uppercase text-muted-foreground">
              <tr>
                <th className="text-left px-3 py-2">When</th>
                <th className="text-left px-3 py-2">Actor</th>
                <th className="text-left px-3 py-2">IP</th>
                <th className="text-left px-3 py-2">Action</th>
                <th className="text-left px-3 py-2">Target</th>
                <th className="text-left px-3 py-2">Meta</th>
              </tr>
            </thead>
            <tbody>
              {audit.data?.map((r) => (
                <tr key={r.id} className="border-t border-border align-top">
                  <td className="px-3 py-2 whitespace-nowrap text-xs">
                    {new Date(r.created_at).toLocaleString()}
                  </td>
                  <td className="px-3 py-2 font-mono text-xs">
                    {r.actor_user_id ? r.actor_user_id.slice(0, 8) : "system"}
                  </td>
                  <td className="px-3 py-2 font-mono text-xs">{r.actor_ip || "—"}</td>
                  <td className="px-3 py-2 font-medium text-xs">{r.action}</td>
                  <td className="px-3 py-2 font-mono text-xs">
                    {r.target_type ? `${r.target_type}/${r.target_id?.slice(0, 8)}` : "—"}
                  </td>
                  <td className="px-3 py-2 font-mono text-xs text-muted-foreground">
                    {Object.keys(r.meta).length ? JSON.stringify(r.meta) : "—"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </AppShell>
  );
}
