"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";
import { ApiError, API_URL, login } from "@/lib/api";
import { useAuth } from "@/lib/auth-context";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";

export default function LoginPage() {
  const router = useRouter();
  const { refresh } = useAuth();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setErr(null);
    try {
      await login(email, password);
      await refresh();
      router.push("/home");
    } catch (e) {
      if (e instanceof ApiError) setErr(e.message);
      else if (e instanceof TypeError)
        setErr(`Cannot reach API at ${API_URL} (CORS or network).`);
      else setErr(e instanceof Error ? e.message : "Login failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={submit} className="space-y-4">
      <h1 className="text-2xl font-semibold text-foreground">Sign in</h1>
      <Input
        type="email"
        required
        placeholder="email"
        value={email}
        onChange={(e) => setEmail(e.target.value)}
      />
      <Input
        type="password"
        required
        placeholder="password"
        value={password}
        onChange={(e) => setPassword(e.target.value)}
      />
      {err && <p className="text-destructive text-sm">{err}</p>}
      <Button type="submit" disabled={busy} className="w-full">
        {busy ? "Signing in..." : "Sign in"}
      </Button>
      <p className="text-xs text-muted-foreground">
        Accounts are admin-created. If you don&apos;t have one, ask your administrator for an invite link.
      </p>
    </form>
  );
}
