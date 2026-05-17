"use client";

import { useMemo, useState } from "react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import type { InvestigationFindingOut } from "@/lib/api";
import { statusVariant } from "./shared";

type EndpointRow = {
  url: string;
  path: string;
  status: number | null;
  contentType: string | null;
  contentLength: number | null;
  kinds: string[];
  severity: string;
};

const CLASSIFIER_KINDS = [
  "admin_panel",
  "login_form",
  "api_endpoint",
  "upload_form",
  "signup_form",
] as const;

function buildRows(findings: InvestigationFindingOut[]): EndpointRow[] {
  const byPath = new Map<string, EndpointRow>();
  for (const f of findings) {
    if (f.kind === "tool_error") continue;
    const ev = f.evidence as Record<string, unknown>;
    const path = String(ev.path ?? "");
    const url = String(ev.url ?? "");
    if (!url || !path) continue;
    const existing = byPath.get(path);
    const sevRank = severityRank(f.severity);
    if (existing) {
      if (!existing.kinds.includes(f.kind)) existing.kinds.push(f.kind);
      if (sevRank > severityRank(existing.severity)) existing.severity = f.severity;
    } else {
      byPath.set(path, {
        url,
        path,
        status: typeof ev.status === "number" ? ev.status : null,
        contentType: (ev.content_type as string) ?? null,
        contentLength:
          typeof ev.content_length === "number" ? ev.content_length : null,
        kinds: [f.kind],
        severity: f.severity,
      });
    }
  }
  return [...byPath.values()].sort((a, b) => a.path.localeCompare(b.path));
}

function severityRank(s: string): number {
  return { critical: 4, high: 3, med: 2, low: 1, info: 0 }[s.toLowerCase()] ?? 0;
}

export function FfufResult({
  findings,
}: {
  findings: InvestigationFindingOut[];
}) {
  const [filter, setFilter] = useState<string | null>(null);
  const allRows = useMemo(() => buildRows(findings), [findings]);
  const rows = filter
    ? allRows.filter((r) => r.kinds.includes(filter))
    : allRows;

  const counts = useMemo(() => {
    const out: Record<string, number> = {};
    for (const r of allRows) {
      for (const k of r.kinds) out[k] = (out[k] ?? 0) + 1;
    }
    return out;
  }, [allRows]);

  const errors = findings.filter((f) => f.kind === "tool_error");

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

      <section className="rounded-md border border-border p-3">
        <div className="flex flex-wrap gap-2 items-center">
          <span className="text-sm font-medium mr-2">Filter:</span>
          <Button
            variant={filter === null ? "default" : "outline"}
            size="sm"
            onClick={() => setFilter(null)}
          >
            All ({allRows.length})
          </Button>
          {CLASSIFIER_KINDS.map((k) => {
            const n = counts[k] ?? 0;
            if (n === 0) return null;
            return (
              <Button
                key={k}
                variant={filter === k ? "default" : "outline"}
                size="sm"
                onClick={() => setFilter(k)}
              >
                {k.replace(/_/g, " ")} ({n})
              </Button>
            );
          })}
        </div>
      </section>

      <section className="rounded-md border border-border">
        <header className="border-b border-border bg-muted/30 px-3 py-2 text-sm font-semibold flex items-center justify-between">
          <span>Discovered endpoints</span>
          <Badge variant="outline">{rows.length}</Badge>
        </header>
        {rows.length === 0 ? (
          <div className="p-3 text-xs text-muted-foreground">
            No endpoints {filter ? `match filter '${filter}'` : "discovered"}.
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
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                <tr key={r.path} className="border-t border-border/50">
                  <td className="px-3 py-2 font-mono text-xs">
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
                      <Badge variant={statusVariant(r.status)}>{r.status}</Badge>
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
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>
    </div>
  );
}
