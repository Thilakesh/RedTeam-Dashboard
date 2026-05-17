"use client";

import { useMemo } from "react";
import { Lightbulb, Lock, ShieldAlert, ShieldCheck, ShieldX } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import type { InvestigationFindingOut } from "@/lib/api";
import { SeverityBadge } from "./shared";

type Strength = "recommended" | "secure" | "weak" | "insecure" | "unknown";

const STRENGTH_VARIANT: Record<
  Strength,
  "success" | "info" | "warning" | "destructive" | "default"
> = {
  recommended: "success",
  secure: "success",
  weak: "warning",
  insecure: "destructive",
  unknown: "default",
};

const STRENGTH_LABEL: Record<Strength, string> = {
  recommended: "Recommended",
  secure: "Strong",
  weak: "Weak",
  insecure: "Insecure",
  unknown: "Unknown",
};

const STRENGTH_ORDER: Strength[] = [
  "insecure",
  "weak",
  "secure",
  "recommended",
  "unknown",
];

const PROTOCOL_DISPLAY_ORDER = [
  "TLS 1.3",
  "TLS 1.2",
  "TLS 1.1",
  "TLS 1.0",
  "SSL 3.0",
  "SSL 2.0",
];

type ProtocolRow = {
  protocol: string;
  enabled: boolean;
  secure: boolean;
  deprecated: boolean;
};

type CipherRow = {
  cipher: string;
  protocol: string;
  strength: Strength;
};

function asStrength(s: unknown): Strength {
  if (
    s === "recommended" ||
    s === "secure" ||
    s === "weak" ||
    s === "insecure"
  )
    return s;
  return "unknown";
}

export function TestSslResult({
  findings,
}: {
  findings: InvestigationFindingOut[];
}) {
  const protocols: ProtocolRow[] = useMemo(() => {
    return findings
      .filter((f) => f.kind === "protocol_info")
      .map((f) => {
        const ev = f.evidence as Record<string, unknown>;
        return {
          protocol: String(ev.protocol ?? f.title),
          enabled: !!ev.enabled,
          secure: !!ev.secure,
          deprecated: !!ev.deprecated,
        };
      })
      .sort(
        (a, b) =>
          PROTOCOL_DISPLAY_ORDER.indexOf(a.protocol) -
          PROTOCOL_DISPLAY_ORDER.indexOf(b.protocol),
      );
  }, [findings]);

  const ciphers: CipherRow[] = useMemo(() => {
    return findings
      .filter((f) => f.kind === "cipher_info")
      .map((f) => {
        const ev = f.evidence as Record<string, unknown>;
        return {
          cipher: String(ev.cipher ?? f.title),
          protocol: String(ev.protocol ?? "Unknown"),
          strength: asStrength(ev.strength),
        };
      });
  }, [findings]);

  const cipherCounts = useMemo(() => {
    const out: Record<Strength, number> = {
      recommended: 0,
      secure: 0,
      weak: 0,
      insecure: 0,
      unknown: 0,
    };
    for (const c of ciphers) out[c.strength] += 1;
    return out;
  }, [ciphers]);

  const protocolRec = findings.find((f) => f.kind === "protocol_recommendation");
  const cipherRec = findings.find((f) => f.kind === "cipher_recommendation");

  const vulnFindings = findings.filter((f) => f.kind === "tls_vuln");
  const certFindings = findings.filter(
    (f) => f.kind === "expired_cert" || f.kind === "self_signed_cert",
  );
  const miscFindings = findings.filter((f) => f.kind === "tls_misconfig");

  const cveIds = useMemo(() => {
    const ids = new Set<string>();
    for (const f of findings) {
      const ev = f.evidence as Record<string, unknown>;
      const cves = ev.cve_ids;
      if (Array.isArray(cves)) for (const c of cves) ids.add(String(c));
    }
    return [...ids];
  }, [findings]);

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

      <section className="rounded-md border border-border">
        <header className="border-b border-border bg-muted/30 px-3 py-2 text-sm font-semibold flex items-center gap-2">
          <Lock className="h-4 w-4" />
          Protocol matrix
          <Badge variant="outline">{protocols.length}</Badge>
        </header>
        {protocols.length === 0 ? (
          <div className="p-3 text-xs text-muted-foreground">
            No protocol data emitted. Re-run TestSSL to populate.
          </div>
        ) : (
          <table className="w-full text-sm">
            <thead className="bg-muted/20 text-xs uppercase text-muted-foreground">
              <tr>
                <th className="px-3 py-2 text-left">Protocol</th>
                <th className="px-3 py-2 text-left">Status</th>
                <th className="px-3 py-2 text-left">Security</th>
              </tr>
            </thead>
            <tbody>
              {protocols.map((p) => (
                <tr key={p.protocol} className="border-t border-border/50">
                  <td className="px-3 py-2 font-mono">{p.protocol}</td>
                  <td className="px-3 py-2">
                    {p.enabled ? (
                      <Badge variant="warning">enabled</Badge>
                    ) : (
                      <Badge variant="success">disabled</Badge>
                    )}
                    {p.deprecated && (
                      <Badge variant="outline" className="ml-1">
                        deprecated
                      </Badge>
                    )}
                  </td>
                  <td className="px-3 py-2">
                    {!p.enabled ? (
                      <span className="text-xs text-muted-foreground">—</span>
                    ) : p.secure ? (
                      <span className="inline-flex items-center gap-1 text-sm text-success">
                        <ShieldCheck className="h-3.5 w-3.5" />
                        Secure
                      </span>
                    ) : (
                      <span className="inline-flex items-center gap-1 text-sm text-destructive">
                        <ShieldX className="h-3.5 w-3.5" />
                        Insecure
                      </span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>

      {protocolRec && (
        <RecommendationCard
          title="Protocol recommendation"
          severity={protocolRec.severity}
          description={protocolRec.description}
        />
      )}

      <section className="rounded-md border border-border">
        <header className="border-b border-border bg-muted/30 px-3 py-2 text-sm font-semibold flex items-center justify-between">
          <span className="flex items-center gap-2">
            <Lock className="h-4 w-4" />
            Cipher strength (per ciphersuite.info classification)
          </span>
          <div className="flex flex-wrap gap-1">
            {STRENGTH_ORDER.map((s) => {
              const n = cipherCounts[s];
              if (n === 0) return null;
              return (
                <Badge key={s} variant={STRENGTH_VARIANT[s]}>
                  {STRENGTH_LABEL[s]} {n}
                </Badge>
              );
            })}
          </div>
        </header>
        {ciphers.length === 0 ? (
          <div className="p-3 text-xs text-muted-foreground">
            No cipher data emitted. Re-run TestSSL to populate.
          </div>
        ) : (
          <div className="divide-y divide-border/50">
            {STRENGTH_ORDER.map((s) => {
              const group = ciphers.filter((c) => c.strength === s);
              if (group.length === 0) return null;
              return (
                <div key={s}>
                  <div className="bg-muted/20 px-3 py-1.5 text-xs font-semibold uppercase flex items-center gap-2">
                    <Badge variant={STRENGTH_VARIANT[s]}>
                      {STRENGTH_LABEL[s]}
                    </Badge>
                    <span className="text-muted-foreground">
                      ({group.length})
                    </span>
                  </div>
                  <table className="w-full text-sm">
                    <tbody>
                      {group.map((c, idx) => (
                        <tr
                          key={`${c.cipher}-${c.protocol}-${idx}`}
                          className="border-t border-border/30"
                        >
                          <td className="px-3 py-1.5 font-mono text-xs">
                            {c.cipher}
                          </td>
                          <td className="px-3 py-1.5 text-xs text-muted-foreground">
                            {c.protocol}
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

      {cipherRec && (
        <RecommendationCard
          title="Cipher recommendation"
          severity={cipherRec.severity}
          description={cipherRec.description}
        />
      )}

      <FindingsSection
        title="TLS vulnerabilities"
        findings={vulnFindings}
        emptyText="No CVE-bearing TLS vulnerabilities reported."
      />
      <FindingsSection
        title="Certificate issues"
        findings={certFindings}
        emptyText="No certificate validation issues."
      />
      {miscFindings.length > 0 && (
        <FindingsSection
          title="Other TLS misconfig"
          findings={miscFindings}
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

function RecommendationCard({
  title,
  severity,
  description,
}: {
  title: string;
  severity: string;
  description: string | null;
}) {
  return (
    <section className="rounded-md border border-info/40 bg-info/5 p-3">
      <div className="flex items-center gap-2 mb-1 text-sm font-semibold">
        <Lightbulb className="h-4 w-4 text-info" />
        {title}
        <SeverityBadge severity={severity} />
      </div>
      <div className="text-sm">{description}</div>
    </section>
  );
}
