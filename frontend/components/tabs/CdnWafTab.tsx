"use client";

import { useQuery } from "@tanstack/react-query";
import { ShieldAlert } from "lucide-react";
import { api, type CdnWafSummary } from "@/lib/api";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

export function CdnWafTab({ scanId }: { scanId: string }) {
  const { data, isLoading } = useQuery({
    queryKey: ["scan-cdn-waf", scanId],
    queryFn: () => api<CdnWafSummary>(`/scans/${scanId}/cdn-waf`),
  });

  if (isLoading || !data) return <p className="text-sm text-muted-foreground">Loading…</p>;

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-2 gap-3">
        <PctCard label="Behind a CDN" pct={data.behind_cdn_pct} />
        <PctCard label="Behind a WAF" pct={data.behind_waf_pct} />
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <Card>
          <CardHeader><CardTitle>CDN providers</CardTitle></CardHeader>
          <CardContent>
            <BreakdownList items={data.cdn_breakdown} emptyText="No CDN detected on any host." />
          </CardContent>
        </Card>
        <Card>
          <CardHeader><CardTitle>WAF coverage</CardTitle></CardHeader>
          <CardContent>
            <BreakdownList items={data.waf_breakdown} emptyText="No WAFs fingerprinted." />
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader className="flex flex-row items-center gap-2">
          <ShieldAlert className="h-4 w-4 text-destructive" />
          <CardTitle>Unprotected origins ({data.unprotected_origins.length})</CardTitle>
        </CardHeader>
        <CardContent>
          {data.unprotected_origins.length === 0 ? (
            <p className="text-sm text-muted-foreground">All live hosts have a CDN or WAF in front.</p>
          ) : (
            <ul className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-1.5 text-xs font-mono">
              {data.unprotected_origins.map((h) => (
                <li key={h} className="text-foreground">{h}</li>
              ))}
            </ul>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

function PctCard({ label, pct }: { label: string; pct: number }) {
  return (
    <div className="rounded-lg border border-border bg-card px-4 py-4">
      <div className="text-xxs uppercase tracking-wider text-muted-foreground">{label}</div>
      <div className="text-3xl font-semibold mt-1 tabular-nums">{pct}%</div>
      <div className="h-1.5 bg-muted rounded mt-3 overflow-hidden">
        <div className="h-full bg-primary" style={{ width: `${Math.min(pct, 100)}%` }} />
      </div>
    </div>
  );
}

function BreakdownList({ items, emptyText }: { items: { label: string; count: number }[]; emptyText: string }) {
  if (!items.length) return <p className="text-xs text-muted-foreground">{emptyText}</p>;
  const max = Math.max(...items.map((i) => i.count));
  return (
    <ul className="space-y-2">
      {items.map((i) => (
        <li key={i.label}>
          <div className="flex justify-between text-xs mb-1">
            <span>{i.label}</span>
            <span className="font-medium tabular-nums">{i.count}</span>
          </div>
          <div className="h-1.5 bg-muted rounded overflow-hidden">
            <div className="h-full bg-primary" style={{ width: `${(i.count / max) * 100}%` }} />
          </div>
        </li>
      ))}
    </ul>
  );
}
