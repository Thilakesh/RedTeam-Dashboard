"use client";

import { useMemo, useState } from "react";
import {
  AlertTriangle,
  ExternalLink,
  FolderOpen,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import type { InvestigationFindingOut } from "@/lib/api";
import { statusVariant } from "./shared";

type Row = {
  path: string;
  url: string;
  status: number | null;
  contentType: string | null;
  contentLength: number | null;
  kinds: string[];
};

const HIGH_SIGNAL_KINDS = new Set([
  "exposed_dotgit",
  "exposed_dotenv",
  "backup_file",
  "swagger_exposed",
  "directory_indexing",
]);

const CLASSIFIER_KINDS = [
  "admin_panel",
  "login_form",
  "api_endpoint",
  "upload_form",
  "signup_form",
] as const;

const STATUS_BUCKETS = [
  { id: "2xx", label: "2xx OK", range: [200, 299] },
  { id: "3xx", label: "3xx Redirect", range: [300, 399] },
  { id: "4xx", label: "4xx Client error", range: [400, 499] },
  { id: "5xx", label: "5xx Server error", range: [500, 599] },
] as const;

function bucketFor(code: number | null): string {
  if (code === null) return "other";
  if (code >= 200 && code < 300) return "2xx";
  if (code >= 300 && code < 400) return "3xx";
  if (code >= 400 && code < 500) return "4xx";
  if (code >= 500 && code < 600) return "5xx";
  return "other";
}

function buildRows(findings: InvestigationFindingOut[]): Row[] {
  const byPath = new Map<string, Row>();
  for (const f of findings) {
    if (f.kind === "tool_error") continue;
    const ev = f.evidence as Record<string, unknown>;
    const path = String(ev.path ?? "");
    const url = String(ev.url ?? "");
    if (!url || !path) continue;
    const existing = byPath.get(path);
    if (existing) {
      if (!existing.kinds.includes(f.kind)) existing.kinds.push(f.kind);
    } else {
      byPath.set(path, {
        path,
        url,
        status: typeof ev.status === "number" ? ev.status : null,
        contentType: (ev.content_type as string) ?? null,
        contentLength:
          typeof ev.content_length === "number" ? ev.content_length : null,
        kinds: [f.kind],
      });
    }
  }
  return [...byPath.values()].sort((a, b) => a.path.localeCompare(b.path));
}

export function EndpointsResult({
  findings,
  tool,
}: {
  findings: InvestigationFindingOut[];
  tool: string;
}) {
  const [statusFilter, setStatusFilter] = useState<string | null>(null);
  const [kindFilter, setKindFilter] = useState<string | null>(null);
  const allRows = useMemo(() => buildRows(findings), [findings]);
  const errors = findings.filter((f) => f.kind === "tool_error");

  const statusCounts = useMemo(() => {
    const out: Record<string, number> = {};
    for (const r of allRows) {
      const b = bucketFor(r.status);
      out[b] = (out[b] ?? 0) + 1;
    }
    return out;
  }, [allRows]);

  const kindCounts = useMemo(() => {
    const out: Record<string, number> = {};
    for (const r of allRows) {
      for (const k of r.kinds) out[k] = (out[k] ?? 0) + 1;
    }
    return out;
  }, [allRows]);

  const rows = useMemo(() => {
    return allRows.filter((r) => {
      if (statusFilter && bucketFor(r.status) !== statusFilter) return false;
      if (kindFilter && !r.kinds.includes(kindFilter)) return false;
      return true;
    });
  }, [allRows, statusFilter, kindFilter]);

  const highSignal = allRows.filter((r) =>
    r.kinds.some((k) => HIGH_SIGNAL_KINDS.has(k)),
  );

  return (
    <div className="space-y-4">
      {errors.length > 0 && (
        <section className="rounded-md border border-destructive/40 bg-destructive/5 p-3 text-sm">
          {errors.map((e) => (
            <div key={e.id}>
              <strong>{e.title}</strong>
              {e.description && (
                <div className="text-xs text-muted-foreground mt-1">
                  {e.description}
                </div>
              )}
            </div>
          ))}
        </section>
      )}

      {highSignal.length > 0 && (
        <section className="rounded-md border border-warning/40 bg-warning/5">
          <header className="border-b border-warning/30 px-3 py-2 text-sm font-semibold flex items-center gap-2">
            <AlertTriangle className="h-4 w-4 text-warning" />
            High-signal disclosures
            <Badge variant="outline">{highSignal.length}</Badge>
          </header>
          <ul className="divide-y divide-border/50">
            {highSignal.map((r) => (
              <li key={r.path} className="p-3 space-y-1">
                <div className="flex items-center gap-2 flex-wrap">
                  {r.status !== null && (
                    <Badge variant={statusVariant(r.status)}>{r.status}</Badge>
                  )}
                  <a
                    href={r.url}
                    target="_blank"
                    rel="noreferrer"
                    className="font-mono text-sm text-primary hover:underline"
                  >
                    {r.path}
                  </a>
                  {r.status !== null && r.status >= 200 && r.status < 300 && (
                    <a
                      href={r.url}
                      target="_blank"
                      rel="noreferrer"
                      className="inline-flex items-center gap-1 text-xs text-primary hover:underline"
                    >
                      <ExternalLink className="h-3 w-3" />
                      Open
                    </a>
                  )}
                </div>
                <div className="flex flex-wrap gap-1">
                  {r.kinds
                    .filter((k) => HIGH_SIGNAL_KINDS.has(k))
                    .map((k) => (
                      <Badge key={k} variant="warning">
                        {k.replace(/_/g, " ")}
                      </Badge>
                    ))}
                </div>
              </li>
            ))}
          </ul>
        </section>
      )}

      <section className="rounded-md border border-border p-3 space-y-3">
        <div>
          <div className="text-xs uppercase text-muted-foreground mb-1">
            Status code
          </div>
          <div className="flex flex-wrap gap-2">
            <Button
              variant={statusFilter === null ? "default" : "outline"}
              size="sm"
              onClick={() => setStatusFilter(null)}
            >
              All ({allRows.length})
            </Button>
            {STATUS_BUCKETS.map((b) => {
              const n = statusCounts[b.id] ?? 0;
              if (n === 0) return null;
              return (
                <Button
                  key={b.id}
                  variant={statusFilter === b.id ? "default" : "outline"}
                  size="sm"
                  onClick={() => setStatusFilter(b.id)}
                >
                  {b.label} ({n})
                </Button>
              );
            })}
          </div>
        </div>
        {Object.values(kindCounts).some((n) => n > 0) && (
          <div>
            <div className="text-xs uppercase text-muted-foreground mb-1">
              Classifier flag
            </div>
            <div className="flex flex-wrap gap-2">
              <Button
                variant={kindFilter === null ? "default" : "outline"}
                size="sm"
                onClick={() => setKindFilter(null)}
              >
                All
              </Button>
              {CLASSIFIER_KINDS.map((k) => {
                const n = kindCounts[k] ?? 0;
                if (n === 0) return null;
                return (
                  <Button
                    key={k}
                    variant={kindFilter === k ? "default" : "outline"}
                    size="sm"
                    onClick={() => setKindFilter(k)}
                  >
                    {k.replace(/_/g, " ")} ({n})
                  </Button>
                );
              })}
            </div>
          </div>
        )}
      </section>

      <section className="rounded-md border border-border">
        <header className="border-b border-border bg-muted/30 px-3 py-2 text-sm font-semibold flex items-center justify-between">
          <span className="flex items-center gap-2">
            <FolderOpen className="h-4 w-4" />
            Discovered endpoints ({tool})
          </span>
          <Badge variant="outline">{rows.length}</Badge>
        </header>
        {rows.length === 0 ? (
          <div className="p-3 text-xs text-muted-foreground">
            No endpoints match current filters.
          </div>
        ) : (
          <table className="w-full text-sm">
            <thead className="bg-muted/20 text-xs uppercase text-muted-foreground">
              <tr>
                <th className="px-3 py-2 text-left">Path</th>
                <th className="px-3 py-2 text-left">Status</th>
                <th className="px-3 py-2 text-left">Type</th>
                <th className="px-3 py-2 text-right">Length</th>
                <th className="px-3 py-2 text-left">Flags</th>
                <th className="px-3 py-2 text-right">Action</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => {
                const isOk =
                  r.status !== null && r.status >= 200 && r.status < 300;
                return (
                  <tr key={r.path} className="border-t border-border/50">
                    <td className="px-3 py-2 font-mono text-xs break-all max-w-xs">
                      <a
                        href={r.url}
                        target="_blank"
                        rel="noreferrer"
                        className="text-primary hover:underline"
                      >
                        {r.path}
                      </a>
                    </td>
                    <td className="px-3 py-2">
                      {r.status !== null ? (
                        <Badge variant={statusVariant(r.status)}>
                          {r.status}
                        </Badge>
                      ) : (
                        "—"
                      )}
                    </td>
                    <td className="px-3 py-2 text-xs text-muted-foreground">
                      {r.contentType ?? "—"}
                    </td>
                    <td className="px-3 py-2 text-right font-mono text-xs">
                      {r.contentLength ?? "—"}
                    </td>
                    <td className="px-3 py-2">
                      <div className="flex flex-wrap gap-1">
                        {r.kinds.map((k) => (
                          <Badge key={k} variant="outline" className="text-xxs">
                            {k.replace(/_/g, " ")}
                          </Badge>
                        ))}
                      </div>
                    </td>
                    <td className="px-3 py-2 text-right">
                      {isOk ? (
                        <a
                          href={r.url}
                          target="_blank"
                          rel="noreferrer"
                          className="inline-flex items-center gap-1 rounded-md border border-border px-2 py-1 text-xs text-primary hover:bg-muted"
                        >
                          <ExternalLink className="h-3 w-3" />
                          Open
                        </a>
                      ) : (
                        <span className="text-xs text-muted-foreground">—</span>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </section>
    </div>
  );
}
