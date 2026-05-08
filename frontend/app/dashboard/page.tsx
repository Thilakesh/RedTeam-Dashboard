"use client";

import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { Plus, Zap } from "lucide-react";
import Link from "next/link";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { ApiError, api, type Scan } from "@/lib/api";

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
    <>
      <div className="mb-6">
        <h1 className="text-2xl font-semibold tracking-tight">Add Scan</h1>
        <p className="text-sm text-muted-foreground mt-1">
          Enter a domain and choose a profile to start reconnaissance.
        </p>
      </div>
      <Card>
      <CardHeader>
        <div className="flex items-center gap-2">
          <Plus className="h-4 w-4 text-primary" />
          <CardTitle>New Scan</CardTitle>
        </div>
        <CardDescription>
          Enter a target domain and choose a profile.{" "}
          <strong>Add</strong> queues it for later;{" "}
          <strong>Start Scan</strong> runs it immediately.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <div className="flex flex-wrap gap-2">
          <Input
            placeholder="example.com"
            value={domain}
            onChange={(e) => {
              setDomain(e.target.value);
              setAddedDomain(null);
            }}
            className="flex-1 min-w-[16rem]"
            onKeyDown={(e) => {
              if (e.key === "Enter") handleStartScan();
            }}
          />
          <Select value={profile} onValueChange={setProfile}>
            <SelectTrigger className="w-36">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="quick">quick</SelectItem>
              <SelectItem value="standard">standard</SelectItem>
              <SelectItem value="deep">deep</SelectItem>
            </SelectContent>
          </Select>
          <Button
            variant="outline"
            onClick={handleAdd}
            disabled={create.isPending || !domain.trim()}
          >
            Add
          </Button>
          <Button
            onClick={handleStartScan}
            disabled={create.isPending || !domain.trim()}
          >
            <Zap className="h-4 w-4" />
            {create.isPending ? "Starting…" : "Start Scan"}
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
    </>
  );
}
