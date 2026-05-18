"use client";

import Link from "next/link";
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

type CreateResp = {
  user: UserRow;
  invite_token: string;
  invite_url: string;
};

export default function AdminUsersPage() {
  const qc = useQueryClient();
  const list = useQuery({
    queryKey: ["admin", "users"],
    queryFn: () => api<UserRow[]>("/users"),
  });

  const [showCreate, setShowCreate] = useState(false);
  const [createdInvite, setCreatedInvite] = useState<CreateResp | null>(null);

  const create = useMutation({
    mutationFn: (vars: { email: string; role: string }) =>
      api<CreateResp>("/users", {
        method: "POST",
        body: JSON.stringify(vars),
      }),
    onSuccess: (resp) => {
      setCreatedInvite(resp);
      setShowCreate(false);
      qc.invalidateQueries({ queryKey: ["admin", "users"] });
    },
  });

  return (
    <AppShell>
      <div className="space-y-6">
        <header className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-semibold tracking-tight">Users</h1>
            <p className="text-sm text-muted-foreground mt-1">
              Admin-only. Create users via invite link.
            </p>
          </div>
          <button
            onClick={() => setShowCreate((v) => !v)}
            className="bg-primary text-primary-foreground rounded px-4 py-2 text-sm font-medium"
          >
            {showCreate ? "Cancel" : "New user"}
          </button>
        </header>

        {showCreate && <CreateUserForm onSubmit={(vars) => create.mutate(vars)} pending={create.isPending} error={create.error instanceof ApiError ? create.error.message : null} />}

        {createdInvite && (
          <InvitePanel
            url={createdInvite.invite_url}
            email={createdInvite.user.email}
            onClose={() => setCreatedInvite(null)}
          />
        )}

        <div className="rounded-lg border border-border bg-card overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-muted/40 text-xs uppercase text-muted-foreground">
              <tr>
                <th className="text-left px-3 py-2">Email</th>
                <th className="text-left px-3 py-2">Role</th>
                <th className="text-left px-3 py-2">Status</th>
                <th className="text-left px-3 py-2">Created</th>
                <th className="px-3 py-2"></th>
              </tr>
            </thead>
            <tbody>
              {list.data?.map((u) => (
                <tr key={u.id} className="border-t border-border">
                  <td className="px-3 py-2">{u.email}</td>
                  <td className="px-3 py-2 capitalize">{u.role}</td>
                  <td className="px-3 py-2">
                    {!u.is_active ? (
                      <span className="text-red-400">disabled</span>
                    ) : u.has_pending_invite ? (
                      <span className="text-amber-400">invite pending</span>
                    ) : (
                      <span className="text-emerald-400">active</span>
                    )}
                  </td>
                  <td className="px-3 py-2">{new Date(u.created_at).toLocaleDateString()}</td>
                  <td className="px-3 py-2 text-right">
                    <Link
                      href={`/admin/users/${u.id}`}
                      className="text-xs underline text-primary hover:opacity-80"
                    >
                      Edit
                    </Link>
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

function CreateUserForm({
  onSubmit,
  pending,
  error,
}: {
  onSubmit: (v: { email: string; role: string }) => void;
  pending: boolean;
  error: string | null;
}) {
  const [email, setEmail] = useState("");
  const [role, setRole] = useState("analyst");
  return (
    <form
      onSubmit={(e) => {
        e.preventDefault();
        onSubmit({ email, role });
      }}
      className="rounded-lg border border-border bg-card p-4 space-y-3 max-w-lg"
    >
      <div>
        <label className="text-sm font-medium">Email</label>
        <input
          type="email"
          required
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          className="mt-1 w-full bg-neutral-900 border border-neutral-800 rounded px-3 py-2 text-sm"
        />
      </div>
      <div>
        <label className="text-sm font-medium">Role</label>
        <select
          value={role}
          onChange={(e) => setRole(e.target.value)}
          className="mt-1 w-full bg-neutral-900 border border-neutral-800 rounded px-3 py-2 text-sm"
        >
          <option value="analyst">analyst</option>
          <option value="admin">admin</option>
        </select>
      </div>
      {error && <p className="text-red-400 text-sm">{error}</p>}
      <button
        type="submit"
        disabled={pending}
        className="bg-primary text-primary-foreground rounded px-4 py-2 text-sm font-medium disabled:opacity-50"
      >
        {pending ? "Creating..." : "Create + generate invite link"}
      </button>
    </form>
  );
}

function InvitePanel({ url, email, onClose }: { url: string; email: string; onClose: () => void }) {
  const [copied, setCopied] = useState(false);
  return (
    <div className="rounded-lg border border-emerald-500/40 bg-emerald-500/5 p-4 space-y-3 max-w-2xl">
      <div className="flex items-start justify-between gap-3">
        <div>
          <h2 className="text-sm font-semibold">Invite link for {email}</h2>
          <p className="text-xs text-muted-foreground mt-1">
            Send this to the user. They&apos;ll set their password and log in.
            The link is single-use and expires in 24 hours.
          </p>
        </div>
        <button onClick={onClose} className="text-xs text-muted-foreground hover:text-foreground">
          dismiss
        </button>
      </div>
      <div className="flex gap-2">
        <input
          readOnly
          value={url}
          className="flex-1 bg-neutral-900 border border-neutral-800 rounded px-3 py-2 text-xs font-mono"
          onFocus={(e) => e.currentTarget.select()}
        />
        <button
          onClick={async () => {
            await navigator.clipboard.writeText(url);
            setCopied(true);
            setTimeout(() => setCopied(false), 1500);
          }}
          className="bg-emerald-600 hover:bg-emerald-500 text-white rounded px-3 py-2 text-xs font-medium"
        >
          {copied ? "Copied!" : "Copy"}
        </button>
      </div>
    </div>
  );
}
