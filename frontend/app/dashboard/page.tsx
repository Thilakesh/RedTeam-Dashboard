"use client";

import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { Info, Plus, Zap } from "lucide-react";
import Link from "next/link";
import { cn } from "@/lib/cn";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { ApiError, api, type Scan } from "@/lib/api";

const PROFILES = [
  { value: "quick", label: "Quick", desc: "Fast pass — subdomains only" },
  { value: "standard", label: "Standard", desc: "Balanced recon depth" },
  { value: "deep", label: "Deep", desc: "Full pipeline, slower" },
] as const;

export default function AddScanPage() {
  const qc = useQueryClient();
  const router = useRouter();
  const [domain, setDomain] = useState("");
  const [profile, setProfile] = useState("standard");
  const [err, setErr] = useState<string | null>(null);
  const [addedDomain, setAddedDomain] = useState<string | null>(null);

  const create = useMutation({
    mutationFn: (body: { domain: string; profile: string; autostart: boolean }) =>
      api<Scan>("/scans", { method: "POST", body: JSON.stringify(body) }),
    onSuccess: (scan, variables) => {
      qc.invalidateQueries({ queryKey: ["scans"] });
      setErr(null);
      if (variables.autostart) {
        router.push(`/scans/${scan.id}`);
      } else {
        setAddedDomain(scan.domain);
        setDomain("");
      }
    },
    onError: (e) => setErr(e instanceof ApiError ? e.message : "Failed to create scan"),
  });

  const handleAdd = () => {
    if (!domain.trim()) return;
    setErr(null);
    setAddedDomain(null);
    create.mutate({ domain: domain.trim(), profile, autostart: false });
  };

  const handleStartScan = () => {
    if (!domain.trim()) return;
    setErr(null);
    setAddedDomain(null);
    create.mutate({ domain: domain.trim(), profile, autostart: true });
  };

  return (
    <div className="max-w-[900px] mx-auto">
      <div className="mb-6">
        <div className="kicker mb-2">Basic Recon</div>
        <h1 className="page-h1">Add Scan</h1>
        <p className="text-sm text-muted-foreground mt-1">
          Enter a domain and choose a profile to start reconnaissance.
        </p>
      </div>
      <Card>
        <CardHeader className="border-b-0 pb-0">
          <div className="flex items-center gap-2">
            <Plus className="h-4 w-4 text-primary" />
            <span className="panel-title">New Scan</span>
          </div>
        </CardHeader>
        <CardContent className="pt-4">
          <label className="text-xs text-muted-foreground mb-1.5 block">Target domain</label>
          <Input
            placeholder="example.com"
            value={domain}
            onChange={(e) => {
              setDomain(e.target.value);
              setAddedDomain(null);
            }}
            className="h-11 mb-5"
            onKeyDown={(e) => {
              if (e.key === "Enter") handleStartScan();
            }}
          />

          <label className="text-xs text-muted-foreground mb-2 block">Profile</label>
          <div className="grid grid-cols-3 gap-2 mb-6">
            {PROFILES.map((p) => (
              <label
                key={p.value}
                className={cn(
                  "relative rounded-lg border px-3.5 py-3 cursor-pointer transition-colors",
                  profile === p.value
                    ? "border-primary bg-primary/10"
                    : "border-border hover:bg-accent/40",
                )}
              >
                <input
                  type="radio"
                  name="profile"
                  value={p.value}
                  checked={profile === p.value}
                  onChange={() => setProfile(p.value)}
                  className="sr-only"
                />
                <div
                  className={cn(
                    "font-medium text-sm mb-0.5",
                    profile === p.value && "text-primary",
                  )}
                >
                  {p.label}
                </div>
                <div className="text-xs text-muted-foreground-2">{p.desc}</div>
                {profile === p.value && (
                  <span className="absolute top-2.5 right-2.5 h-3.5 w-3.5 rounded-full bg-primary ring-2 ring-background" />
                )}
              </label>
            ))}
          </div>

          <div className="flex flex-wrap gap-2 justify-end">
            <Button
              variant="outline"
              onClick={handleAdd}
              disabled={create.isPending || !domain.trim()}
            >
              Add to queue
            </Button>
            <Button
              onClick={handleStartScan}
              disabled={create.isPending || !domain.trim()}
            >
              <Zap className="h-4 w-4" />
              {create.isPending ? "Starting…" : "Start scan"}
            </Button>
          </div>
          {err && <p className="text-sm text-destructive mt-3">{err}</p>}
          {addedDomain && (
            <p className="text-sm text-success mt-3">
              <strong>{addedDomain}</strong> queued — find it in{" "}
              <Link href="/dashboard/recon-jobs" className="underline">
                Recon Jobs
              </Link>
              .
            </p>
          )}
        </CardContent>
      </Card>

      <div className="mt-4 rounded-lg border border-primary/30 bg-primary/[0.06] p-4 flex gap-3">
        <Info className="h-4 w-4 text-primary shrink-0 mt-0.5" />
        <p className="text-xs text-muted-foreground leading-relaxed">
          <strong className="text-foreground">Add to queue</strong> saves the scan without
          running it — start it later from Recon Jobs.{" "}
          <strong className="text-foreground">Start scan</strong> queues it and begins
          execution immediately.
        </p>
      </div>
    </div>
  );
}
