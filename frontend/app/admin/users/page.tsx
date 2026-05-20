"use client";

import Link from "next/link";
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AppShell } from "@/components/AppShell";
import { ApiError, api } from "@/lib/api";

type UserRow = {
  id: string;
  email: string;
  first_name: string | null;
  last_name: string | null;
  role: "admin" | "analyst";
  is_active: boolean;
  is_super_admin: boolean;
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
            onClick={() => setShowCreate(true)}
            className="bg-primary text-primary-foreground rounded px-4 py-2 text-sm font-medium"
          >
            Add User
          </button>
        </header>

        {showCreate && (
          <CreateUserModal
            onClose={() => setShowCreate(false)}
            onCreated={(resp) => {
              setShowCreate(false);
              setCreatedInvite(resp);
              qc.invalidateQueries({ queryKey: ["admin", "users"] });
            }}
          />
        )}

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
                <th className="text-left px-3 py-2">Name</th>
                <th className="text-left px-3 py-2">Email</th>
                <th className="text-left px-3 py-2">Role</th>
                <th className="text-left px-3 py-2">Status</th>
                <th className="text-left px-3 py-2">Created</th>
                <th className="px-3 py-2"></th>
              </tr>
            </thead>
            <tbody>
              {list.data?.map((u) => {
                const fullName = [u.first_name, u.last_name].filter(Boolean).join(" ") || "—";
                return (
                  <tr key={u.id} className="border-t border-border">
                    <td className="px-3 py-2">
                      {fullName}
                      {u.is_super_admin && (
                        <span className="ml-2 text-[10px] uppercase tracking-wide text-amber-400 border border-amber-500/40 rounded px-1.5 py-0.5">
                          Super
                        </span>
                      )}
                    </td>
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
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </AppShell>
  );
}

function CreateUserModal({
  onClose,
  onCreated,
}: {
  onClose: () => void;
  onCreated: (resp: CreateResp) => void;
}) {
  const [firstName, setFirstName] = useState("");
  const [lastName, setLastName] = useState("");
  const [email, setEmail] = useState("");
  const [role, setRole] = useState("analyst");

  const create = useMutation({
    mutationFn: () =>
      api<CreateResp>("/users", {
        method: "POST",
        body: JSON.stringify({
          email,
          role,
          first_name: firstName || undefined,
          last_name: lastName || undefined,
        }),
      }),
    onSuccess: onCreated,
  });

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 px-4"
      onClick={onClose}
    >
      <form
        onClick={(e) => e.stopPropagation()}
        onSubmit={(e) => {
          e.preventDefault();
          create.mutate();
        }}
        className="w-full max-w-md rounded-lg border border-border bg-card p-6 space-y-4"
      >
        <header className="flex items-center justify-between">
          <h2 className="text-lg font-semibold">Add User</h2>
          <button
            type="button"
            onClick={onClose}
            className="text-xs text-muted-foreground hover:text-foreground"
          >
            close
          </button>
        </header>

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
          <select
            value={role}
            onChange={(e) => setRole(e.target.value)}
            className="mt-1 w-full bg-neutral-900 border border-neutral-800 rounded px-3 py-2 text-sm"
          >
            <option value="analyst">analyst</option>
            <option value="admin">admin</option>
          </select>
        </div>

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

        {create.error instanceof ApiError && (
          <p className="text-red-400 text-sm">{create.error.message}</p>
        )}

        <div className="flex justify-end gap-2">
          <button
            type="button"
            onClick={onClose}
            className="rounded px-4 py-2 text-sm border border-border hover:bg-accent"
          >
            Cancel
          </button>
          <button
            type="submit"
            disabled={create.isPending}
            className="bg-primary text-primary-foreground rounded px-4 py-2 text-sm font-medium disabled:opacity-50"
          >
            {create.isPending ? "Creating..." : "Generate Invite Link"}
          </button>
        </div>
      </form>
    </div>
  );
}

function InvitePanel({
  url,
  email,
  onClose,
}: {
  url: string;
  email: string;
  onClose: () => void;
}) {
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
