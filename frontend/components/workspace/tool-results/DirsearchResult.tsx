"use client";

import { useMemo } from "react";
import { AlertTriangle, FolderOpen } from "lucide-react";
import { Badge } from "@/components/ui/badge";
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

export function DirsearchResult({
  findings,
}: {
  findings: InvestigationFindingOut[];
}) {
  const allRows = useMemo(() => buildRows(findings), [findings]);
  const highSignal = allRows.filter((r) =>
    r.kinds.some((k) => HIGH_SIGNAL_KINDS.has(k)),
  );
  const errors = findings.filter((f) => f.kind === "tool_error");

  const grouped = useMemo(() => {
    const out: Record<string, Row[]> = {};
    for (const r of allRows) {
      const code = r.status ?? 0;
      const bucket = code >= 500
        ? "5xx"
        : code >= 400
          ? "4xx"
          : code >= 300
            ? "3xx"
            : code >= 200
              ? "2xx"
              : "other";
      (out[bucket] = out[bucket] ?? []).push(r);
    }
    return out;
  }, [allRows]);

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

      <section className="rounded-md border border-warning/40 bg-warning/5">
        <header className="border-b border-warning/30 px-3 py-2 text-sm font-semibold flex items-center gap-2">
          <AlertTriangle className="h-4 w-4 text-warning" />
          High-signal disclosures
          <Badge variant="outline">{highSignal.length}</Badge>
        </header>
        {highSignal.length === 0 ? (
          <div className="p-3 text-xs text-muted-foreground">
            No .git / .env / backup / swagger / directory-indexing hits.
          </div>
        ) : (
          <ul className="divide-y divide-border/50">
            {highSignal.map((r) => (
              <li key={r.path} className="p-3 space-y-1">
                <div className="flex items-center gap-2">
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
        )}
      </section>

      <section className="rounded-md border border-border">
        <header className="border-b border-border bg-muted/30 px-3 py-2 text-sm font-semibold flex items-center justify-between">
          <span className="flex items-center gap-2">
            <FolderOpen className="h-4 w-4" />
            All discovered paths
          </span>
          <Badge variant="outline">{allRows.length}</Badge>
        </header>
        {allRows.length === 0 ? (
          <div className="p-3 text-xs text-muted-foreground">
            No paths discovered.
          </div>
        ) : (
          <div className="divide-y divide-border/50">
            {(["2xx", "3xx", "4xx", "5xx", "other"] as const).map((bucket) => {
              const rows = grouped[bucket] ?? [];
              if (rows.length === 0) return null;
              return (
                <div key={bucket}>
                  <div className="bg-muted/20 px-3 py-1 text-xs font-medium uppercase text-muted-foreground">
                    {bucket} ({rows.length})
                  </div>
                  <table className="w-full text-sm">
                    <tbody>
                      {rows.map((r) => (
                        <tr key={r.path} className="border-t border-border/30">
                          <td className="px-3 py-1.5 font-mono text-xs">
                            <a
                              href={r.url}
                              target="_blank"
                              rel="noreferrer"
                              className="text-primary hover:underline"
                            >
                              {r.path}
                            </a>
                          </td>
                          <td className="px-3 py-1.5 text-xs text-muted-foreground">
                            {r.contentType ?? "—"}
                          </td>
                          <td className="px-3 py-1.5 text-right font-mono text-xs">
                            {r.contentLength ?? "—"}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              );
            })}
          </div>
        )}
      </section>
    </div>
  );
}
