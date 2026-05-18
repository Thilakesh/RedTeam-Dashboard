"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AppShell } from "@/components/AppShell";
import { api } from "@/lib/api";

type SessionRow = {
  id: string;
  user_id: string;
  device_label: string | null;
  ip_address: string | null;
  user_agent: string | null;
  expires_at: string;
  revoked: boolean;
  revoked_reason: string | null;
  last_used_at: string | null;
  created_at: string;
};

export default function MySessionsPage() {
  const qc = useQueryClient();
  const sessions = useQuery({
    queryKey: ["my-sessions"],
    queryFn: () => api<SessionRow[]>("/sessions"),
  });

  const revoke = useMutation({
    mutationFn: (id: string) => api<void>(`/sessions/${id}`, { method: "DELETE" }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["my-sessions"] }),
  });

  return (
    <AppShell>
      <div className="max-w-4xl space-y-6">
        <header>
          <h1 className="text-2xl font-semibold tracking-tight">Your sessions</h1>
          <p className="text-sm text-muted-foreground mt-1">
            Each entry is a device you&apos;re signed in on. Revoke any session to sign that device out immediately.
          </p>
        </header>

        <div className="rounded-lg border border-border bg-card overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-muted/40 text-xs uppercase text-muted-foreground">
              <tr>
                <th className="text-left px-3 py-2">Device</th>
                <th className="text-left px-3 py-2">IP</th>
                <th className="text-left px-3 py-2">Last used</th>
                <th className="text-left px-3 py-2">Expires</th>
                <th className="text-left px-3 py-2">Status</th>
                <th className="px-3 py-2"></th>
              </tr>
            </thead>
            <tbody>
              {sessions.data?.map((s) => (
                <tr key={s.id} className="border-t border-border">
                  <td className="px-3 py-2 truncate max-w-[280px]">{s.device_label || "—"}</td>
                  <td className="px-3 py-2">{s.ip_address || "—"}</td>
                  <td className="px-3 py-2">{s.last_used_at ? new Date(s.last_used_at).toLocaleString() : "—"}</td>
                  <td className="px-3 py-2">{new Date(s.expires_at).toLocaleString()}</td>
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
              {sessions.data?.length === 0 && (
                <tr>
                  <td colSpan={6} className="px-3 py-8 text-center text-muted-foreground text-sm">
                    No sessions.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </AppShell>
  );
}
