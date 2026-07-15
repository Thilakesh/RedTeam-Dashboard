"use client";

import Link from "next/link";
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Check, Copy, Plus, X } from "lucide-react";
import { AppShell } from "@/components/AppShell";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { cn } from "@/lib/cn";
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

type Filter = "all" | "admin" | "analyst" | "disabled";

export default function AdminUsersPage() {
  const qc = useQueryClient();
  const list = useQuery({
    queryKey: ["admin", "users"],
    queryFn: () => api<UserRow[]>("/users"),
  });

  const [showCreate, setShowCreate] = useState(false);
  const [createdInvite, setCreatedInvite] = useState<CreateResp | null>(null);
  const [filter, setFilter] = useState<Filter>("all");

  const users = list.data ?? [];
  const counts = {
    all: users.length,
    admin: users.filter((u) => u.role === "admin").length,
    analyst: users.filter((u) => u.role === "analyst").length,
    disabled: users.filter((u) => !u.is_active).length,
  };
  const filtered = users.filter((u) => {
    if (filter === "all") return true;
    if (filter === "disabled") return !u.is_active;
    return u.role === filter;
  });

  return (
    <AppShell>
      <div className="space-y-5">
        <header className="flex items-center justify-between flex-wrap gap-3">
          <div>
            <div className="kicker mb-2">Administration</div>
            <h1 className="page-h1">Users</h1>
            <p className="text-sm text-muted-foreground mt-1">
              Admin-only. Create users via invite link.
            </p>
          </div>
          <Button onClick={() => setShowCreate(true)}>
            <Plus className="h-4 w-4" /> Add User
          </Button>
        </header>

        <div className="flex items-center gap-2 flex-wrap">
          {(
            [
              ["all", `All ${counts.all}`],
              ["admin", `Admins ${counts.admin}`],
              ["analyst", `Analysts ${counts.analyst}`],
              ["disabled", `Disabled ${counts.disabled}`],
            ] as [Filter, string][]
          ).map(([key, label]) => (
            <button
              key={key}
              onClick={() => setFilter(key)}
              className={cn("pill", filter === key ? "pill-run" : "pill-out")}
            >
              {label}
            </button>
          ))}
        </div>

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

        <div className="rounded-lg overflow-hidden shadow-[0_0_0_1px_hsl(var(--border))]">
          <table className="w-full text-sm">
            <thead className="bg-foreground/[0.03]">
              <tr>
                <th className="text-left px-3 py-2.5 text-[10px] uppercase tracking-[0.1em] text-muted-foreground-2 font-medium">User</th>
                <th className="text-left px-3 py-2.5 text-[10px] uppercase tracking-[0.1em] text-muted-foreground-2 font-medium">Role</th>
                <th className="text-left px-3 py-2.5 text-[10px] uppercase tracking-[0.1em] text-muted-foreground-2 font-medium">Status</th>
                <th className="text-left px-3 py-2.5 text-[10px] uppercase tracking-[0.1em] text-muted-foreground-2 font-medium">Created</th>
                <th className="px-3 py-2.5"></th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((u) => {
                const fullName = [u.first_name, u.last_name].filter(Boolean).join(" ") || "—";
                const initial = (u.first_name || u.email || "?").trim()[0]?.toUpperCase() ?? "?";
                return (
                  <tr key={u.id} className="row-strip hover:bg-accent/40">
                    <td className="px-3 py-2.5">
                      <div className="flex items-center gap-2.5">
                        <div
                          className={cn(
                            "h-7 w-7 rounded-full bg-primary/25 text-foreground text-xs font-semibold flex items-center justify-center shrink-0",
                            !u.is_active && "opacity-40",
                          )}
                        >
                          {initial}
                        </div>
                        <div className="min-w-0">
                          <div className={cn("text-sm font-medium truncate", !u.is_active && "line-through text-muted-foreground")}>
                            {fullName}
                            {u.is_super_admin && (
                              <span className="ml-2 text-[10px] uppercase tracking-wide text-sev-med-fg border border-sev-med/40 rounded px-1.5 py-0.5">
                                Super
                              </span>
                            )}
                          </div>
                          <div className="text-xs text-muted-foreground-2 truncate">{u.email}</div>
                        </div>
                      </div>
                    </td>
                    <td className="px-3 py-2.5 capitalize text-xs">{u.role}</td>
                    <td className="px-3 py-2.5">
                      {!u.is_active ? (
                        <span className="pill pill-err">disabled</span>
                      ) : u.has_pending_invite ? (
                        <span className="pill pill-warn">invite pending</span>
                      ) : (
                        <span className="pill pill-ok">active</span>
                      )}
                    </td>
                    <td className="px-3 py-2.5 text-xs text-muted-foreground-2">
                      {new Date(u.created_at).toLocaleDateString()}
                    </td>
                    <td className="px-3 py-2.5 text-right">
                      <Link
                        href={`/admin/users/${u.id}`}
                        className="text-xs text-primary hover:underline"
                      >
                        Edit
                      </Link>
                    </td>
                  </tr>
                );
              })}
              {filtered.length === 0 && (
                <tr>
                  <td colSpan={5} className="px-3 py-8 text-center text-sm text-muted-foreground">
                    No users match this filter.
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
        className="w-full max-w-md card-panel space-y-4"
      >
        <header className="flex items-center justify-between">
          <h2 className="panel-title text-base">Add User</h2>
          <button
            type="button"
            onClick={onClose}
            className="text-muted-foreground hover:text-foreground"
          >
            <X className="h-4 w-4" />
          </button>
        </header>

        <div className="grid grid-cols-2 gap-3">
          <div>
            <label className="text-xs text-muted-foreground mb-1.5 block">First name</label>
            <Input value={firstName} onChange={(e) => setFirstName(e.target.value)} />
          </div>
          <div>
            <label className="text-xs text-muted-foreground mb-1.5 block">Last name</label>
            <Input value={lastName} onChange={(e) => setLastName(e.target.value)} />
          </div>
        </div>

        <div>
          <label className="text-xs text-muted-foreground mb-1.5 block">Role</label>
          <div className="seg">
            {(["analyst", "admin"] as const).map((r) => (
              <label key={r} className="seg-opt flex-1 justify-center capitalize">
                <input type="radio" checked={role === r} onChange={() => setRole(r)} />
                <span>{r}</span>
              </label>
            ))}
          </div>
        </div>

        <div>
          <label className="text-xs text-muted-foreground mb-1.5 block">Email</label>
          <Input
            type="email"
            required
            value={email}
            onChange={(e) => setEmail(e.target.value)}
          />
        </div>

        {create.error instanceof ApiError && (
          <p className="text-destructive text-sm">{create.error.message}</p>
        )}

        <div className="flex justify-end gap-2">
          <Button type="button" variant="outline" onClick={onClose}>
            Cancel
          </Button>
          <Button type="submit" disabled={create.isPending}>
            {create.isPending ? "Creating…" : "Generate Invite Link"}
          </Button>
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
    <div className="rounded-lg border border-success/40 bg-success/[0.06] p-4 space-y-3 max-w-2xl">
      <div className="flex items-start justify-between gap-3">
        <div>
          <h2 className="text-sm font-semibold">Invite link for {email}</h2>
          <p className="text-xs text-muted-foreground mt-1">
            Send this to the user. They&apos;ll set their password and log in.
            The link is single-use and expires in 24 hours.
          </p>
        </div>
        <button onClick={onClose} className="text-muted-foreground hover:text-foreground">
          <X className="h-4 w-4" />
        </button>
      </div>
      <div className="flex gap-2">
        <input
          readOnly
          value={url}
          className="flex-1 rounded-md border border-border bg-foreground/[0.03] px-3 py-2 text-xs font-mono"
          onFocus={(e) => e.currentTarget.select()}
        />
        <Button
          size="sm"
          onClick={async () => {
            await navigator.clipboard.writeText(url);
            setCopied(true);
            setTimeout(() => setCopied(false), 1500);
          }}
        >
          {copied ? <Check className="h-3.5 w-3.5" /> : <Copy className="h-3.5 w-3.5" />}
          {copied ? "Copied" : "Copy"}
        </Button>
      </div>
    </div>
  );
}
