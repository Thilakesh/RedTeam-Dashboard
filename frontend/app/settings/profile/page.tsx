"use client";

import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AppShell } from "@/components/AppShell";
import { ApiError, api } from "@/lib/api";

type Profile = {
  id: string;
  email: string;
  first_name: string | null;
  last_name: string | null;
  role: string;
  is_active: boolean;
  is_super_admin: boolean;
  created_at: string;
};

export default function ProfilePage() {
  const qc = useQueryClient();
  const profile = useQuery({
    queryKey: ["settings", "profile"],
    queryFn: () => api<Profile>("/settings/profile"),
  });

  return (
    <AppShell>
      <div className="max-w-xl space-y-6">
        <header>
          <h1 className="text-2xl font-semibold tracking-tight">Profile</h1>
          <p className="text-sm text-muted-foreground mt-1">
            Manage your account details and password.
          </p>
        </header>

        {profile.data && <ProfileForm profile={profile.data} onSaved={() => {
          qc.invalidateQueries({ queryKey: ["settings", "profile"] });
          qc.invalidateQueries({ queryKey: ["me"] });
        }} />}

        <PasswordForm />
      </div>
    </AppShell>
  );
}

function ProfileForm({ profile, onSaved }: { profile: Profile; onSaved: () => void }) {
  const [firstName, setFirstName] = useState(profile.first_name ?? "");
  const [lastName, setLastName] = useState(profile.last_name ?? "");
  const [email, setEmail] = useState(profile.email);
  const [msg, setMsg] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    setFirstName(profile.first_name ?? "");
    setLastName(profile.last_name ?? "");
    setEmail(profile.email);
  }, [profile]);

  const save = useMutation({
    mutationFn: () =>
      api<Profile>("/settings/profile", {
        method: "PATCH",
        body: JSON.stringify({
          first_name: firstName,
          last_name: lastName,
          email: email !== profile.email ? email : undefined,
        }),
      }),
    onSuccess: () => {
      setMsg("Profile updated.");
      setErr(null);
      onSaved();
    },
    onError: (e) => {
      setMsg(null);
      setErr(e instanceof ApiError ? e.message : (e as Error).message);
    },
  });

  return (
    <form
      onSubmit={(e) => {
        e.preventDefault();
        save.mutate();
      }}
      className="rounded-lg border border-border bg-card p-4 space-y-4"
    >
      <h2 className="text-sm font-semibold">Account details</h2>

      <div className="grid grid-cols-2 gap-3">
        <div>
          <label className="text-sm font-medium">First name</label>
          <input
            value={firstName}
            onChange={(e) => setFirstName(e.target.value)}
            className="mt-1 w-full bg-neutral-900 border border-neutral-800 rounded px-3 py-2 text-sm"
          />
        </div>
        <div>
          <label className="text-sm font-medium">Last name</label>
          <input
            value={lastName}
            onChange={(e) => setLastName(e.target.value)}
            className="mt-1 w-full bg-neutral-900 border border-neutral-800 rounded px-3 py-2 text-sm"
          />
        </div>
      </div>

      <div>
        <label className="text-sm font-medium">Role</label>
        <input
          readOnly
          value={profile.role + (profile.is_super_admin ? " (super admin)" : "")}
          className="mt-1 w-full bg-neutral-900/50 border border-neutral-800 rounded px-3 py-2 text-sm capitalize text-muted-foreground"
        />
        <p className="text-xs text-muted-foreground mt-1">
          Roles are admin-controlled and not editable here.
        </p>
      </div>

      <div>
        <label className="text-sm font-medium">Email</label>
        <input
          type="email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          className="mt-1 w-full bg-neutral-900 border border-neutral-800 rounded px-3 py-2 text-sm"
        />
      </div>

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
  );
}

function PasswordForm() {
  const [oldPw, setOldPw] = useState("");
  const [newPw, setNewPw] = useState("");
  const [confirm, setConfirm] = useState("");
  const [msg, setMsg] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);

  const change = useMutation({
    mutationFn: () =>
      api<unknown>("/settings/profile", {
        method: "PATCH",
        body: JSON.stringify({
          current_password: oldPw,
          new_password: newPw,
        }),
      }),
    onSuccess: () => {
      setMsg("Password changed. Other sessions signed out.");
      setErr(null);
      setOldPw("");
      setNewPw("");
      setConfirm("");
    },
    onError: (e) => {
      setMsg(null);
      setErr(e instanceof ApiError ? e.message : (e as Error).message);
    },
  });

  function submit(e: React.FormEvent) {
    e.preventDefault();
    setMsg(null);
    setErr(null);
    if (newPw.length < 8) {
      setErr("new password must be at least 8 characters");
      return;
    }
    if (newPw !== confirm) {
      setErr("new password and confirm do not match");
      return;
    }
    change.mutate();
  }

  return (
    <form
      onSubmit={submit}
      className="rounded-lg border border-border bg-card p-4 space-y-4"
    >
      <h2 className="text-sm font-semibold">Change password</h2>
      <div>
        <label className="text-sm font-medium">Old password</label>
        <input
          type="password"
          required
          value={oldPw}
          onChange={(e) => setOldPw(e.target.value)}
          className="mt-1 w-full bg-neutral-900 border border-neutral-800 rounded px-3 py-2 text-sm"
        />
      </div>
      <div>
        <label className="text-sm font-medium">New password</label>
        <input
          type="password"
          required
          value={newPw}
          onChange={(e) => setNewPw(e.target.value)}
          className="mt-1 w-full bg-neutral-900 border border-neutral-800 rounded px-3 py-2 text-sm"
        />
      </div>
      <div>
        <label className="text-sm font-medium">Confirm new password</label>
        <input
          type="password"
          required
          value={confirm}
          onChange={(e) => setConfirm(e.target.value)}
          className="mt-1 w-full bg-neutral-900 border border-neutral-800 rounded px-3 py-2 text-sm"
        />
      </div>
      <p className="text-xs text-muted-foreground">
        Changing your password signs out every other device.
      </p>
      {msg && <p className="text-emerald-400 text-sm">{msg}</p>}
      {err && <p className="text-red-400 text-sm">{err}</p>}
      <button
        type="submit"
        disabled={change.isPending}
        className="bg-primary text-primary-foreground rounded px-4 py-2 text-sm font-medium disabled:opacity-50"
      >
        {change.isPending ? "Updating..." : "Change password"}
      </button>
    </form>
  );
}
