"use client";

import { useQuery } from "@tanstack/react-query";
import { Server } from "lucide-react";
import { api, type PortsPage } from "@/lib/api";

interface PortsTabProps {
  scanId: string;
}

export function PortsTab({ scanId }: PortsTabProps) {
  const query = useQuery({
    queryKey: ["scan-ports", scanId],
    queryFn: () => api<PortsPage>(`/scans/${scanId}/ports?limit=500`),
  });

  if (query.isLoading) {
    return <p className="text-sm text-muted-foreground py-6">Loading port data…</p>;
  }

  const rows = query.data?.rows ?? [];

  if (rows.length === 0) {
    return (
      <div className="flex flex-col items-center gap-3 py-12 text-center text-muted-foreground">
        <Server className="h-8 w-8 opacity-40" />
        <p className="text-sm">No port scan data yet.</p>
        <p className="text-xs max-w-sm">
          Run a <strong>deep</strong> scan on a verified target to populate this tab.
          Port scanning (naabu + nmap) only runs when the target has been authorized.
        </p>
      </div>
    );
  }

  return (
    <div className="overflow-auto rounded-md border border-border">
      <table className="w-full text-sm border-collapse">
        <thead className="bg-muted/50 sticky top-0 z-10">
          <tr>
            {["Host", "Port", "Proto", "State", "Service", "Product", "Version"].map((h) => (
              <th
                key={h}
                className="px-3 py-2 text-left font-medium text-muted-foreground whitespace-nowrap border-b border-border"
              >
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr
              key={row.asset_id}
              className="border-b border-border hover:bg-muted/30 transition-colors"
            >
              <td className="px-3 py-2 font-mono text-xs">{row.host}</td>
              <td className="px-3 py-2 font-mono text-xs font-semibold text-primary">{row.port}</td>
              <td className="px-3 py-2 text-xs text-muted-foreground">{row.proto}</td>
              <td className="px-3 py-2">
                <span
                  className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ${
                    row.state === "open"
                      ? "bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400"
                      : "bg-muted text-muted-foreground"
                  }`}
                >
                  {row.state}
                </span>
              </td>
              <td className="px-3 py-2 text-xs">{row.service_name ?? <span className="text-muted-foreground">—</span>}</td>
              <td className="px-3 py-2 text-xs">{row.product ?? <span className="text-muted-foreground">—</span>}</td>
              <td className="px-3 py-2 text-xs">{row.version ?? <span className="text-muted-foreground">—</span>}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <div className="px-3 py-2 text-xs text-muted-foreground text-right border-t border-border">
        {rows.length} open port{rows.length !== 1 ? "s" : ""}
      </div>
    </div>
  );
}
