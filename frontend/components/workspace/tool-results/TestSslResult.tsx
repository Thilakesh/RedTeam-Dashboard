"use client";

import { useMemo } from "react";
import { Lock, ShieldAlert } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import type { InvestigationFindingOut } from "@/lib/api";
import { SeverityBadge } from "./shared";

const KIND_GROUPS: Array<{ id: string; title: string; kinds: string[] }> = [
  {
    id: "vulns",
    title: "TLS vulnerabilities (CVE)",
    kinds: ["tls_vuln"],
  },
  {
    id: "protocols",
    title: "Insecure protocols",
    kinds: ["insecure_protocol"],
  },
  {
    id: "ciphers",
    title: "Weak ciphers",
    kinds: ["weak_cipher"],
  },
  {
    id: "certs",
    title: "Certificate issues",
    kinds: ["expired_cert", "self_signed_cert"],
  },
  {
    id: "misc",
    title: "Other TLS misconfig",
    kinds: ["tls_misconfig"],
  },
];

export function TestSslResult({
  findings,
}: {
  findings: InvestigationFindingOut[];
}) {
  const grouped = useMemo(() => {
    const out: Record<string, InvestigationFindingOut[]> = {};
    for (const g of KIND_GROUPS) out[g.id] = [];
    for (const f of findings) {
      if (f.kind === "tool_error") continue;
      const group = KIND_GROUPS.find((g) => g.kinds.includes(f.kind));
      if (group) out[group.id].push(f);
    }
    return out;
  }, [findings]);

  const errors = findings.filter((f) => f.kind === "tool_error");

  const cveIds = useMemo(() => {
    const ids = new Set<string>();
    for (const f of findings) {
      const ev = f.evidence as Record<string, unknown>;
      const cves = ev.cve_ids;
      if (Array.isArray(cves)) for (const c of cves) ids.add(String(c));
    }
    return [...ids];
  }, [findings]);

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

      {cveIds.length > 0 && (
        <section className="rounded-md border border-destructive/40 bg-destructive/5 p-3">
          <div className="flex items-center gap-2 mb-2 text-sm font-semibold">
            <ShieldAlert className="h-4 w-4 text-destructive" />
            CVEs referenced
          </div>
          <div className="flex flex-wrap gap-1">
            {cveIds.map((c) => (
              <Badge key={c} variant="destructive">
                {c}
              </Badge>
            ))}
          </div>
        </section>
      )}

      {KIND_GROUPS.map((g) => (
        <section key={g.id} className="rounded-md border border-border">
          <header className="border-b border-border bg-muted/30 px-3 py-2 text-sm font-semibold flex items-center justify-between">
            <span className="flex items-center gap-2">
              <Lock className="h-4 w-4" />
              {g.title}
            </span>
            <Badge variant="outline">{grouped[g.id].length}</Badge>
          </header>
          {grouped[g.id].length === 0 ? (
            <div className="p-3 text-xs text-muted-foreground">
              No findings in this category.
            </div>
          ) : (
            <ul className="divide-y divide-border/50">
              {grouped[g.id].map((f) => (
                <li key={f.id} className="p-3 space-y-1">
                  <div className="flex items-center gap-2">
                    <SeverityBadge severity={f.severity} />
                    <span className="font-mono text-xs text-muted-foreground">
                      {f.kind}
                    </span>
                  </div>
                  <div className="text-sm font-medium">{f.title}</div>
                  {f.description && (
                    <pre className="text-xs whitespace-pre-wrap text-muted-foreground">
                      {f.description}
                    </pre>
                  )}
                </li>
              ))}
            </ul>
          )}
        </section>
      ))}
    </div>
  );
}
