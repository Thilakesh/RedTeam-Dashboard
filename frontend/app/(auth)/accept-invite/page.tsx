"use client";

import { useRouter, useSearchParams } from "next/navigation";
import { useState } from "react";
import { ApiError, acceptInvite } from "@/lib/api";
import { useAuth } from "@/lib/auth-context";

export default function AcceptInvitePage() {
  const router = useRouter();
  const params = useSearchParams();
  const token = params.get("token") || "";
  const { refresh } = useAuth();
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setErr(null);
    if (password !== confirm) {
      setErr("passwords do not match");
      return;
    }
    if (password.length < 8) {
      setErr("password must be at least 8 characters");
      return;
    }
    setBusy(true);
    try {
      await acceptInvite(token, password);
      await refresh();
      router.push("/home");
    } catch (e) {
      if (e instanceof ApiError) setErr(e.message);
      else setErr(e instanceof Error ? e.message : "Failed to accept invite");
    } finally {
      setBusy(false);
    }
  }

  if (!token) {
    return (
      <div className="space-y-3">
        <h1 className="text-2xl font-semibold">Invalid invite</h1>
        <p className="text-neutral-400 text-sm">No invite token in the URL.</p>
      </div>
    );
  }

  return (
    <form onSubmit={submit} className="space-y-4">
      <h1 className="text-2xl font-semibold">Set your password</h1>
      <p className="text-sm text-neutral-400">
        Welcome. Choose a password to activate your account.
      </p>
      <input
        type="password"
        required
        placeholder="new password (min 8 chars)"
        value={password}
        onChange={(e) => setPassword(e.target.value)}
        className="w-full bg-neutral-900 border border-neutral-800 rounded px-3 py-2"
      />
      <input
        type="password"
        required
        placeholder="confirm password"
        value={confirm}
        onChange={(e) => setConfirm(e.target.value)}
        className="w-full bg-neutral-900 border border-neutral-800 rounded px-3 py-2"
      />
      {err && <p className="text-red-400 text-sm">{err}</p>}
      <button
        type="submit"
        disabled={busy}
        className="w-full bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 rounded py-2 font-medium"
      >
        {busy ? "Activating..." : "Activate account"}
      </button>
    </form>
  );
}
