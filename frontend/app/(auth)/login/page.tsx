"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { ApiError, api, setToken } from "@/lib/api";

export default function LoginPage() {
  const router = useRouter();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setErr(null);
    try {
      const res = await api<{ access_token: string }>("/auth/login", {
        method: "POST",
        auth: false,
        body: JSON.stringify({ email, password }),
      });
      setToken(res.access_token);
      router.push("/dashboard");
    } catch (e) {
      if (e instanceof ApiError) setErr(e.message);
      else if (e instanceof TypeError) setErr("Cannot reach API at " + (process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000") + " (CORS or network).");
      else setErr(e instanceof Error ? e.message : "Login failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={submit} className="space-y-4">
      <h1 className="text-2xl font-semibold">Sign in</h1>
      <input
        type="email"
        required
        placeholder="email"
        value={email}
        onChange={(e) => setEmail(e.target.value)}
        className="w-full bg-neutral-900 border border-neutral-800 rounded px-3 py-2"
      />
      <input
        type="password"
        required
        placeholder="password"
        value={password}
        onChange={(e) => setPassword(e.target.value)}
        className="w-full bg-neutral-900 border border-neutral-800 rounded px-3 py-2"
      />
      {err && <p className="text-red-400 text-sm">{err}</p>}
      <button
        type="submit"
        disabled={busy}
        className="w-full bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 rounded py-2 font-medium"
      >
        {busy ? "Signing in..." : "Sign in"}
      </button>
      <p className="text-sm text-neutral-400">
        No account?{" "}
        <Link href="/signup" className="text-emerald-400 hover:underline">
          Sign up
        </Link>
      </p>
    </form>
  );
}
