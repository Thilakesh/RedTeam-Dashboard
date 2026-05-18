"use client";

import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AppShell } from "@/components/AppShell";
import { ApiError, api } from "@/lib/api";

type Profile = {
  id: string;
  email: string;
  role: string;
  is_active: boolean;
  created_at: string;
};

export default function ProfilePage() {
  const qc = useQueryClient();
  const profile = useQuery({
    queryKey: ["settings", "profile"],
    queryFn: () => api<Profile>("/settings/profile"),
  });

  const [email, setEmail] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [currentPassword, setCurrentPassword] = useState("");
  const [msg, setMsg] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);

  const save = useMutation({
    mutationFn: () =>
      api<Profile>("/settings/profile", {
        method: "PATCH",
        body: JSON.stringify({
          email: email || undefined,
          new_password: newPassword || undefined,
          current_password: currentPassword || undefined,
        }),
      }),
    onSuccess: () => {
      setMsg("Profile updated.");
      setErr(null);
      setNewPassword("");
      setCurrentPassword("");
      qc.invalidateQueries({ queryKey: ["settings", "profile"] });
      qc.invalidateQueries({ queryKey: ["me"] });
    },
    onError: (e) => {
      setMsg(null);
      setErr(e instanceof ApiError ? e.message : (e as Error).message);
    },
  });

  return (
    <AppShell>
      <div className="max-w-xl space-y-6">
        <header>
          <h1 className="text-2xl font-semibold tracking-tight">Profile</h1>
          <p className="text-sm text-muted-foreground mt-1">
            Manage your account email and password.
          </p>
        </header>

        {profile.data && (
          <div className="rounded-lg border border-border bg-card p-4 text-sm space-y-1">
            <div><span className="text-muted-foreground">Email:</span> {profile.data.email}</div>
            <div><span className="text-muted-foreground">Role:</span> <span className="capitalize">{profile.data.role}</span></div>
            <div><span className="text-muted-foreground">Member since:</span> {new Date(profile.data.created_at).toLocaleString()}</div>
          </div>
        )}

        <form
          onSubmit={(e) => {
            e.preventDefault();
            save.mutate();
          }}
          className="space-y-4"
        >
          <div>
            <label className="text-sm font-medium">New email (optional)</label>
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder={profile.data?.email ?? ""}
              className="mt-1 w-full bg-neutral-900 border border-neutral-800 rounded px-3 py-2 text-sm"
            />
          </div>
          <div>
            <label className="text-sm font-medium">New password (optional)</label>
            <input
              type="password"
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              className="mt-1 w-full bg-neutral-900 border border-neutral-800 rounded px-3 py-2 text-sm"
            />
          </div>
          {newPassword && (
            <div>
              <label className="text-sm font-medium">Current password</label>
              <input
                type="password"
                value={currentPassword}
                onChange={(e) => setCurrentPassword(e.target.value)}
                required
                className="mt-1 w-full bg-neutral-900 border border-neutral-800 rounded px-3 py-2 text-sm"
              />
              <p className="text-xs text-muted-foreground mt-1">
                Changing your password signs out every other device.
              </p>
            </div>
          )}
          {msg && <p className="text-emerald-400 text-sm">{msg}</p>}
          {err && <p className="text-red-400 text-sm">{err}</p>}
          <button
            type="submit"
            disabled={save.isPending}
            className="bg-primary text-primary-foreground rounded px-4 py-2 text-sm font-medium disabled:opacity-50"
          >
            {save.isPending ? "Saving..." : "Save changes"}
          </button>
        </form>
      </div>
    </AppShell>
  );
}
