"use client";

import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { AppShell } from "@/components/AppShell";
import { api } from "@/lib/api";

type AuditRow = {
  id: number;
  actor_user_id: string | null;
  actor_ip: string | null;
  user_agent: string | null;
  org_id: string | null;
  action: string;
  target_type: string | null;
  target_id: string | null;
  meta: Record<string, unknown>;
  created_at: string;
};

const inputClass =
  "bg-background border border-border rounded px-3 py-2 text-sm text-foreground placeholder:text-muted-foreground";

export default function AdminAuditPage() {
  const [action, setAction] = useState("");
  const [actor, setActor] = useState("");
  const [from, setFrom] = useState("");
  const [to, setTo] = useState("");

  const audit = useQuery({
    queryKey: ["admin", "audit", action, actor, from, to],
    queryFn: () => {
      const params = new URLSearchParams();
      if (action) params.set("action", action);
      if (actor) params.set("actor", actor);
      if (from) params.set("from", new Date(from).toISOString());
      if (to) params.set("to", new Date(to).toISOString());
      const qs = params.toString();
      return api<AuditRow[]>(`/admin/audit${qs ? `?${qs}` : ""}`);
    },
    refetchInterval: 10_000,
  });

  return (
    <AppShell>
      <div className="space-y-6">
        <header>
          <h1 className="text-2xl font-semibold tracking-tight">Change logs</h1>
          <p className="text-sm text-muted-foreground mt-1">
            Append-only audit trail of every privileged action.
          </p>
        </header>

        <div className="flex flex-wrap items-center gap-3">
          <input
            value={action}
            onChange={(e) => setAction(e.target.value)}
            placeholder="filter action (e.g. auth.login)"
            className={`${inputClass} w-64`}
          />
          <input
            value={actor}
            onChange={(e) => setActor(e.target.value)}
            placeholder="filter actor (user UUID)"
            className={`${inputClass} w-64`}
          />
          <label className="flex items-center gap-1.5 text-xs text-muted-foreground">
            From
            <input
              type="datetime-local"
              value={from}
              onChange={(e) => setFrom(e.target.value)}
              className={inputClass}
            />
          </label>
          <label className="flex items-center gap-1.5 text-xs text-muted-foreground">
            To
            <input
              type="datetime-local"
              value={to}
              onChange={(e) => setTo(e.target.value)}
              className={inputClass}
            />
          </label>
        </div>

        <div className="rounded-lg border border-border bg-card overflow-auto">
          <table className="w-full text-sm">
            <thead className="bg-muted/40 text-xs uppercase text-muted-foreground">
              <tr>
                <th className="text-left px-3 py-2">When</th>
                <th className="text-left px-3 py-2">Actor</th>
                <th className="text-left px-3 py-2">IP</th>
                <th className="text-left px-3 py-2">User agent</th>
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
                  <td
                    className="px-3 py-2 font-mono text-xs text-muted-foreground max-w-xs truncate"
                    title={r.user_agent ?? undefined}
                  >
                    {r.user_agent || "—"}
                  </td>
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
