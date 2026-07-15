"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { Radar } from "lucide-react";
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
    <div className="min-h-screen grid lg:grid-cols-2">
      {/* Left brand panel */}
      <div
        className="hidden lg:flex flex-col justify-between p-14 relative overflow-hidden text-foreground"
        style={{ background: "linear-gradient(155deg, hsl(244 43% 27%) 0%, hsl(var(--background)) 65%)" }}
      >
        <div
          className="absolute -top-20 -right-20 w-80 h-80 rounded-full pointer-events-none"
          style={{
            background: "radial-gradient(circle, hsl(var(--primary) / 0.4), transparent 70%)",
            filter: "blur(30px)",
          }}
        />
        <div className="flex items-center gap-3 relative">
          <div className="h-10 w-10 rounded-lg bg-primary/[0.18] flex items-center justify-center">
            <Radar className="h-5 w-5 text-primary" />
          </div>
          <div>
            <div className="text-lg font-medium">Recon Dashboard</div>
            <div className="text-[10px] text-foreground/70 tracking-[0.12em] uppercase">
              Attack Surface Management
            </div>
          </div>
        </div>

        <div className="relative">
          <div className="kicker !text-primary-tint2 mb-3">Continuous asset discovery</div>
          <h1 className="text-[40px] font-medium tracking-[-0.02em] leading-[1.1] mb-5">
            See what an attacker sees.
          </h1>
          <p className="text-sm text-foreground/70 max-w-[380px] leading-[1.7]">
            Passive recon, active probing, and AI-prioritized risk on every subdomain of every
            target you run. Then hand the interesting ones to an analyst workspace.
          </p>
        </div>

        <div className="flex gap-6 relative text-foreground/70">
          <div>
            <div className="text-lg font-medium text-foreground">Recon</div>
            <div className="text-[10px] tracking-[0.08em] uppercase">Asset discovery</div>
          </div>
          <div>
            <div className="text-lg font-medium text-foreground">Investigate</div>
            <div className="text-[10px] tracking-[0.08em] uppercase">Manual + automated</div>
          </div>
          <div>
            <div className="text-lg font-medium text-foreground">Workspaces</div>
            <div className="text-[10px] tracking-[0.08em] uppercase">Multi-tenant</div>
          </div>
        </div>
      </div>

      {/* Right form panel */}
      <div className="flex flex-col justify-center p-8 sm:p-14">
        <div className="w-full max-w-[380px] mx-auto">
          <div className="kicker mb-2.5">Sign in</div>
          <h2 className="text-[28px] font-medium tracking-[-0.02em] mb-1.5">Welcome back.</h2>
          <p className="text-[13px] text-muted-foreground mb-8">
            Invite-only — reach out to your workspace admin for access.
          </p>

          <form onSubmit={submit} className="space-y-4">
            <div>
              <label className="text-xs text-muted-foreground mb-1.5 block">Email</label>
              <Input
                type="email"
                required
                placeholder="you@example.com"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="h-11"
              />
            </div>
            <div>
              <label className="text-xs text-muted-foreground mb-1.5 block">Password</label>
              <Input
                type="password"
                required
                placeholder="············"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="h-11"
              />
            </div>
            {err && <p className="text-destructive text-sm">{err}</p>}
            <Button type="submit" disabled={busy} className="w-full h-[46px]">
              {busy ? "Signing in..." : "Sign in →"}
            </Button>
            <p className="text-[11px] text-muted-foreground text-center">
              Protected by RS256 JWT · rotating refresh tokens
            </p>
          </form>

          <hr className="rule-fade my-8" />
          <p className="text-[11px] text-muted-foreground text-center">
            Have an invite token?{" "}
            <Link href="/accept-invite" className="text-primary hover:underline">
              Accept invite
            </Link>
          </p>
        </div>
      </div>
    </div>
  );
}
