"use client";

import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ShieldCheck, Trash2 } from "lucide-react";
import { AppShell } from "@/components/AppShell";
import { TargetBadge } from "@/components/TargetBadge";
import { ApiError, api } from "@/lib/api";
import { useAuth } from "@/lib/auth-context";

type VerifiedTarget = {
  id: string;
  domain: string;
  is_verified: boolean;
  verified_by: string | null;
  verified_by_email: string | null;
  verified_at: string | null;
  created_at: string;
};

export default function VerifiedTargetsPage() {
  const qc = useQueryClient();
  const { isAdmin } = useAuth();
  const list = useQuery({
    queryKey: ["verified-targets"],
    queryFn: () => api<VerifiedTarget[]>("/verified-targets"),
  });

  const [showAdd, setShowAdd] = useState(false);

  return (
    <AppShell>
      <div className="space-y-6">
        <header className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-semibold tracking-tight flex items-center gap-2">
              <ShieldCheck className="h-6 w-6 text-emerald-400" />
              Verified Targets
            </h1>
            <p className="text-sm text-muted-foreground mt-1">
              Trusted domains where aggressive scans (deep recon, intrusive vuln,
              ffuf/dirsearch/naabu/nmap_deep) are unlocked.
              {!isAdmin && " Read-only — only admins can add or remove."}
            </p>
          </div>
          {isAdmin && (
            <button
              onClick={() => setShowAdd(true)}
              className="bg-primary text-primary-foreground rounded px-4 py-2 text-sm font-medium"
            >
              Add Verified Target
            </button>
          )}
        </header>

        {showAdd && isAdmin && (
          <AddVerifiedModal
            onClose={() => setShowAdd(false)}
            onCreated={() => {
              setShowAdd(false);
              qc.invalidateQueries({ queryKey: ["verified-targets"] });
            }}
          />
        )}

        <div className="rounded-lg border border-border bg-card overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-muted/40 text-xs uppercase text-muted-foreground">
              <tr>
                <th className="text-left px-3 py-2">Domain</th>
                <th className="text-left px-3 py-2">Status</th>
                <th className="text-left px-3 py-2">Verified by</th>
                <th className="text-left px-3 py-2">Verified at</th>
                {isAdmin && <th className="px-3 py-2"></th>}
              </tr>
            </thead>
            <tbody>
              {list.data?.map((t) => (
                <Row
                  key={t.id}
                  target={t}
                  isAdmin={isAdmin}
                  onChanged={() => qc.invalidateQueries({ queryKey: ["verified-targets"] })}
                />
              ))}
              {list.data?.length === 0 && (
                <tr>
                  <td colSpan={isAdmin ? 5 : 4} className="px-3 py-12 text-center text-muted-foreground text-sm">
                    No verified targets yet.{isAdmin && " Add one above to unlock aggressive scans."}
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

function AddVerifiedModal({
  onClose,
  onCreated,
}: {
  onClose: () => void;
  onCreated: () => void;
}) {
  const [domain, setDomain] = useState("");
  const add = useMutation({
    mutationFn: () =>
      api<VerifiedTarget>("/verified-targets", {
        method: "POST",
        body: JSON.stringify({ domain }),
      }),
    onSuccess: () => {
      setDomain("");
      onCreated();
    },
  });

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 px-4" onClick={onClose}>
      <form
        onClick={(e) => e.stopPropagation()}
        onSubmit={(e) => {
          e.preventDefault();
          if (domain.trim()) add.mutate();
        }}
        className="w-full max-w-md rounded-lg border border-border bg-card p-6 space-y-4"
      >
        <header className="flex items-center justify-between">
          <h2 className="text-lg font-semibold">Add Verified Target</h2>
          <button type="button" onClick={onClose} className="text-xs text-muted-foreground hover:text-foreground">
            close
          </button>
        </header>
        <div>
          <label className="text-sm font-medium">Domain</label>
          <input
            required
            autoFocus
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
            placeholder="example.com"
            className="mt-1 w-full bg-neutral-900 border border-neutral-800 rounded px-3 py-2 text-sm"
          />
        </div>
        {add.error instanceof ApiError && (
          <p className="text-red-400 text-sm">{add.error.message}</p>
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
            disabled={add.isPending}
            className="bg-primary text-primary-foreground rounded px-4 py-2 text-sm font-medium disabled:opacity-50"
          >
            {add.isPending ? "Adding..." : "Mark verified"}
          </button>
        </div>
      </form>
    </div>
  );
}

function Row({
  target,
  isAdmin,
  onChanged,
}: {
  target: VerifiedTarget;
  isAdmin: boolean;
  onChanged: () => void;
}) {
  const unverify = useMutation({
    mutationFn: () => api<void>(`/verified-targets/${target.id}`, { method: "DELETE" }),
    onSuccess: onChanged,
  });
  return (
    <tr className="border-t border-border">
      <td className="px-3 py-2 font-mono text-xs">{target.domain}</td>
      <td className="px-3 py-2">
        <TargetBadge verified={target.is_verified} />
      </td>
      <td className="px-3 py-2 text-xs">{target.verified_by_email || "—"}</td>
      <td className="px-3 py-2 text-xs">
        {target.verified_at ? new Date(target.verified_at).toLocaleString() : "—"}
      </td>
      {isAdmin && (
        <td className="px-3 py-2 text-right">
          <button
            onClick={() => {
              if (confirm(`Unverify ${target.domain}? Aggressive scans will be blocked.`)) {
                unverify.mutate();
              }
            }}
            className="inline-flex items-center gap-1 text-xs px-2 py-1 rounded border border-red-500/40 text-red-400 hover:bg-red-500/10"
          >
            <Trash2 className="h-3 w-3" />
            Unverify
          </button>
        </td>
      )}
    </tr>
  );
}
