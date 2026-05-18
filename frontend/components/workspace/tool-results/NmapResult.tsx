"use client";

import { Badge } from "@/components/ui/badge";
import type { InvestigationFindingOut } from "@/lib/api";
import { SeverityBadge } from "./shared";

type ServiceRow = {
  port: number;
  proto: string;
  service_name: string | null;
  product: string | null;
  version: string | null;
  banner: string | null;
};

function buildServiceTable(findings: InvestigationFindingOut[]): ServiceRow[] {
  // ServiceUpdateRecord data is in the InvestigationFinding.evidence for NSE
  // findings — but nmap_deep emits services separately via ServiceUpdateRecord
  // → upsert path. The findings here are NSE script outputs; we reconstruct the
  // port summary from finding evidence so the per-task page is self-contained
  // (no extra API roundtrip required).
  const seen = new Map<string, ServiceRow>();
  for (const f of findings) {
    const ev = f.evidence as Record<string, unknown>;
    const port = ev.port;
    if (typeof port !== "number") continue;
    const key = `${port}/${ev.proto ?? "tcp"}`;
    if (!seen.has(key)) {
      seen.set(key, {
        port,
        proto: String(ev.proto ?? "tcp"),
        service_name: null,
        product: null,
        version: null,
        banner: null,
      });
    }
  }
  return [...seen.values()].sort((a, b) => a.port - b.port);
}

export function NmapResult({
  findings,
}: {
  findings: InvestigationFindingOut[];
}) {
  const vulnFindings = findings.filter((f) => f.kind.startsWith("nse_vuln_"));
  const bannerFindings = findings.filter(
    (f) => f.kind === "service_banner_leak",
  );
  const otherFindings = findings.filter(
    (f) =>
      !f.kind.startsWith("nse_vuln_") &&
      f.kind !== "service_banner_leak" &&
      f.kind !== "tool_error",
  );
  const errors = findings.filter((f) => f.kind === "tool_error");
  const services = buildServiceTable(findings);

  return (
    <div className="space-y-4">
      {errors.length > 0 && (
        <FindingsSection
          title="Tool errors"
          findings={errors}
          emptyText=""
        />
      )}

      <section className="rounded-md border border-border">
        <header className="border-b border-border bg-muted/30 px-3 py-2 text-sm font-semibold">
          Open ports observed by NSE scripts ({services.length})
        </header>
        {services.length === 0 ? (
          <div className="p-3 text-xs text-muted-foreground">
            No NSE-script-keyed port references. ServiceUpdateRecord rows landed
            in the Service table; consult Service/Ports view on the recon scan.
          </div>
        ) : (
          <table className="w-full text-sm">
            <thead className="bg-muted/20 text-xs uppercase text-muted-foreground">
              <tr>
                <th className="px-3 py-2 text-left">Port</th>
                <th className="px-3 py-2 text-left">Proto</th>
                <th className="px-3 py-2 text-left">NSE hits</th>
              </tr>
            </thead>
            <tbody>
              {services.map((s) => {
                const hits = findings.filter(
                  (f) =>
                    (f.evidence as Record<string, unknown>).port === s.port,
                ).length;
                return (
                  <tr key={`${s.port}/${s.proto}`} className="border-t border-border/50">
                    <td className="px-3 py-2 font-mono">{s.port}</td>
                    <td className="px-3 py-2">{s.proto}</td>
                    <td className="px-3 py-2">{hits}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </section>

      <FindingsSection
        title="NSE vuln findings"
        findings={vulnFindings}
        emptyText="No NSE vuln-script hits."
      />
      <FindingsSection
        title="Banner / info disclosure"
        findings={bannerFindings}
        emptyText="No banner leaks."
      />
      {otherFindings.length > 0 && (
        <FindingsSection
          title="Other NSE output"
          findings={otherFindings}
          emptyText=""
        />
      )}
    </div>
  );
}

function FindingsSection({
  title,
  findings,
  emptyText,
}: {
  title: string;
  findings: InvestigationFindingOut[];
  emptyText: string;
}) {
  return (
    <section className="rounded-md border border-border">
      <header className="border-b border-border bg-muted/30 px-3 py-2 text-sm font-semibold flex items-center justify-between">
        <span>{title}</span>
        <Badge variant="outline">{findings.length}</Badge>
      </header>
      {findings.length === 0 ? (
        <div className="p-3 text-xs text-muted-foreground">{emptyText}</div>
      ) : (
        <ul className="divide-y divide-border/50">
          {findings.map((f) => (
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
  );
}
