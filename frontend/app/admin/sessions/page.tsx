"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AppShell } from "@/components/AppShell";
import { api } from "@/lib/api";

type SessionRow = {
  id: string;
  user_id: string;
  user_email: string | null;
  device_label: string | null;
  ip_address: string | null;
  expires_at: string;
  revoked: boolean;
  revoked_reason: string | null;
  last_used_at: string | null;
  created_at: string;
};

export default function AdminSessionsPage() {
  const qc = useQueryClient();
  const sessions = useQuery({
    queryKey: ["admin", "sessions"],
    queryFn: () => api<SessionRow[]>("/sessions"),
    refetchInterval: 10_000,
  });

  const revoke = useMutation({
    mutationFn: (id: string) => api<void>(`/sessions/${id}`, { method: "DELETE" }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["admin", "sessions"] }),
  });

  return (
    <AppShell>
      <div className="space-y-6">
        <header>
          <h1 className="text-2xl font-semibold tracking-tight">All sessions</h1>
          <p className="text-sm text-muted-foreground mt-1">
            Every device anyone has signed in on. Revoke to force-logout.
          </p>
        </header>

        <div className="rounded-lg border border-border bg-card overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-muted/40 text-xs uppercase text-muted-foreground">
              <tr>
                <th className="text-left px-3 py-2">User</th>
                <th className="text-left px-3 py-2">Device</th>
                <th className="text-left px-3 py-2">IP</th>
                <th className="text-left px-3 py-2">Last used</th>
                <th className="text-left px-3 py-2">Status</th>
                <th className="px-3 py-2"></th>
              </tr>
            </thead>
            <tbody>
              {sessions.data?.map((s) => (
                <tr key={s.id} className="border-t border-border">
                  <td className="px-3 py-2">{s.user_email}</td>
                  <td className="px-3 py-2 truncate max-w-[260px]">{s.device_label || "—"}</td>
                  <td className="px-3 py-2">{s.ip_address || "—"}</td>
                  <td className="px-3 py-2">
                    {s.last_used_at ? new Date(s.last_used_at).toLocaleString() : "—"}
                  </td>
                  <td className="px-3 py-2">
                    {s.revoked ? (
                      <span className="text-xs text-red-400">revoked ({s.revoked_reason})</span>
                    ) : (
                      <span className="text-xs text-emerald-400">active</span>
                    )}
                  </td>
                  <td className="px-3 py-2 text-right">
                    {!s.revoked && (
                      <button
                        onClick={() => revoke.mutate(s.id)}
                        className="text-xs px-2 py-1 rounded border border-border hover:bg-accent"
                      >
                        Revoke
                      </button>
                    )}
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
