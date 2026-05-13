"use client";

import { useQuery } from "@tanstack/react-query";
import Link from "next/link";
import { ArrowLeft, Globe } from "lucide-react";
import { AppShell } from "@/components/AppShell";
import { api, type EndpointRow } from "@/lib/api";

export default function EndpointDetailPage({
  params,
}: {
  params: { id: string; endpoint_id: string };
}) {
  const q = useQuery({
    queryKey: ["endpoint-detail", params.id, params.endpoint_id],
    queryFn: () =>
      api<EndpointRow>(
        `/vuln-scans/${params.id}/endpoints/${params.endpoint_id}`
      ),
  });

  if (q.isLoading || !q.data) {
    return (
      <AppShell>
        <p className="text-sm text-muted-foreground">Loading endpoint…</p>
      </AppShell>
    );
  }

  const ep = q.data;

  const flags = [
    ep.is_admin && "admin",
    ep.is_login && "login",
    ep.is_api && "api",
    ep.is_upload && "upload",
    ep.is_signup && "signup",
  ].filter(Boolean) as string[];

  const FLAG_COLORS: Record<string, string> = {
    admin: "bg-red-100 text-red-700",
    login: "bg-yellow-100 text-yellow-700",
    api: "bg-blue-100 text-blue-700",
    upload: "bg-purple-100 text-purple-700",
    signup: "bg-green-100 text-green-700",
  };

  return (
    <AppShell>
      <div className="mb-6">
        <Link
          href={`/vuln-scans/${params.id}?tab=endpoints`}
          className="inline-flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground mb-4"
        >
          <ArrowLeft className="h-3.5 w-3.5" />
          Back to Endpoints
        </Link>
        <div className="flex items-center gap-3">
          <Globe className="h-5 w-5 text-primary" />
          <h1 className="text-xl font-semibold font-mono break-all">{ep.url}</h1>
        </div>
        {ep.title && <p className="mt-1 text-sm text-muted-foreground">{ep.title}</p>}
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 mb-6">
        <div className="rounded-lg border border-border bg-card p-4">
          <div className="text-xs text-muted-foreground mb-1">Method</div>
          <div className="text-lg font-bold font-mono">{ep.method}</div>
        </div>
        <div className="rounded-lg border border-border bg-card p-4">
          <div className="text-xs text-muted-foreground mb-1">Status Code</div>
          <div className={`text-lg font-bold tabular-nums ${ep.status_code && ep.status_code < 400 ? "text-green-600" : "text-red-600"}`}>
            {ep.status_code ?? "—"}
          </div>
        </div>
        <div className="rounded-lg border border-border bg-card p-4">
          <div className="text-xs text-muted-foreground mb-1">Content Type</div>
          <div className="text-sm font-mono truncate">{ep.content_type ?? "—"}</div>
        </div>
        <div className="rounded-lg border border-border bg-card p-4">
          <div className="text-xs text-muted-foreground mb-1">Source</div>
          <div className="text-sm">{ep.source_tool}</div>
        </div>
      </div>

      {flags.length > 0 && (
        <div className="mb-6">
          <p className="text-xs text-muted-foreground mb-2 uppercase font-semibold tracking-wide">Flags</p>
          <div className="flex flex-wrap gap-2">
            {flags.map((f) => (
              <span
                key={f}
                className={`rounded-full px-3 py-1 text-sm font-semibold ${FLAG_COLORS[f] ?? "bg-gray-100 text-gray-700"}`}
              >
                {f}
              </span>
            ))}
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
        <div className="rounded-lg border border-border bg-card p-4">
          <div className="text-xs text-muted-foreground mb-1">First seen</div>
          <div className="text-sm">{new Date(ep.first_seen).toLocaleString()}</div>
        </div>
        <div className="rounded-lg border border-border bg-card p-4">
          <div className="text-xs text-muted-foreground mb-1">Last seen</div>
          <div className="text-sm">{new Date(ep.last_seen).toLocaleString()}</div>
        </div>
      </div>
    </AppShell>
  );
}
