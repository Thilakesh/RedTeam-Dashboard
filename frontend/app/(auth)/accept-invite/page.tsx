"use client";

import { useRouter, useSearchParams } from "next/navigation";
import { Suspense, useState } from "react";
import { ApiError, acceptInvite } from "@/lib/api";
import { useAuth } from "@/lib/auth-context";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";

export default function AcceptInvitePage() {
  return (
    <Suspense fallback={null}>
      <AcceptInviteForm />
    </Suspense>
  );
}

function AcceptInviteForm() {
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
      <div className="min-h-screen flex items-center justify-center px-4">
        <div className="w-full max-w-sm space-y-3">
          <h1 className="text-2xl font-semibold text-foreground">Invalid invite</h1>
          <p className="text-muted-foreground text-sm">No invite token in the URL.</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen flex items-center justify-center px-4">
      <form onSubmit={submit} className="w-full max-w-sm space-y-4">
        <h1 className="text-2xl font-semibold text-foreground">Set your password</h1>
        <p className="text-sm text-muted-foreground">
          Welcome. Choose a password to activate your account.
        </p>
        <Input
          type="password"
          required
          placeholder="new password (min 8 chars)"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
        />
        <Input
          type="password"
          required
          placeholder="confirm password"
          value={confirm}
          onChange={(e) => setConfirm(e.target.value)}
        />
        {err && <p className="text-destructive text-sm">{err}</p>}
        <Button type="submit" disabled={busy} className="w-full">
          {busy ? "Activating..." : "Activate account"}
        </Button>
      </form>
    </div>
  );
}
