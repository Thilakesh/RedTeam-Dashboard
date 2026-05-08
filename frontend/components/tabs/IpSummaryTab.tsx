"use client";

import { useQuery } from "@tanstack/react-query";
import { api, type IpRow } from "@/lib/api";
import { CountryFlag } from "@/components/StatusBadge";

export function IpSummaryTab({ scanId }: { scanId: string }) {
  const { data, isLoading } = useQuery({
    queryKey: ["scan-ips", scanId],
    queryFn: () => api<IpRow[]>(`/scans/${scanId}/ips`),
  });

  if (isLoading || !data) return <p className="text-sm text-muted-foreground">Loading IPs…</p>;
  if (!data.length) return <p className="text-sm text-muted-foreground">No IPs resolved yet.</p>;

  return (
    <div className="border border-border rounded-lg overflow-hidden bg-card">
      <table className="w-full text-sm">
        <thead className="bg-muted/50">
          <tr className="text-xxs uppercase tracking-wider text-muted-foreground">
            <th className="text-left px-3 py-2.5 border-b border-border">IP</th>
            <th className="text-left px-3 py-2.5 border-b border-border">Subdomains</th>
            <th className="text-left px-3 py-2.5 border-b border-border">ASN</th>
            <th className="text-left px-3 py-2.5 border-b border-border">Org</th>
            <th className="text-left px-3 py-2.5 border-b border-border">Country</th>
            <th className="text-left px-3 py-2.5 border-b border-border">City</th>
          </tr>
        </thead>
        <tbody>
          {data.map((row) => (
            <tr key={row.asset_id} className="border-b border-border hover:bg-muted/30">
              <td className="px-3 py-2 font-mono text-xs">{row.ip}</td>
              <td className="px-3 py-2 tabular-nums">{row.subdomain_count}</td>
              <td className="px-3 py-2 font-mono text-xs">{row.asn || "—"}</td>
              <td className="px-3 py-2">{row.org || "—"}</td>
              <td className="px-3 py-2"><CountryFlag iso={row.country} /></td>
              <td className="px-3 py-2">{row.city || "—"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
