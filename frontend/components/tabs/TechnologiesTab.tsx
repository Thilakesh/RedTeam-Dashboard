"use client";

import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { ChevronDown, ChevronRight } from "lucide-react";
import { api, type TechBucket } from "@/lib/api";
import { cn } from "@/lib/cn";

export function TechnologiesTab({ scanId }: { scanId: string }) {
  const { data, isLoading } = useQuery({
    queryKey: ["scan-tech", scanId],
    queryFn: () => api<TechBucket[]>(`/scans/${scanId}/technologies`),
  });

  if (isLoading || !data) return <p className="text-sm text-muted-foreground">Loading…</p>;
  if (!data.length) return <p className="text-sm text-muted-foreground">No technologies fingerprinted.</p>;

  return (
    <div className="space-y-2">
      {data.map((t) => (
        <TechRow key={t.label} tech={t} />
      ))}
    </div>
  );
}

function TechRow({ tech }: { tech: TechBucket }) {
  const [open, setOpen] = useState(false);
  const hasSubdomains = tech.subdomains.length > 0;

  return (
    <div className="border border-border bg-card rounded-md overflow-hidden">
      <button
        onClick={() => hasSubdomains && setOpen((v) => !v)}
        className={cn(
          "w-full flex items-center justify-between px-3 py-2 text-sm text-left",
          hasSubdomains && "hover:bg-muted/40 transition-colors"
        )}
      >
        <div className="flex items-center gap-2">
          {hasSubdomains ? (
            open ? (
              <ChevronDown className="h-3.5 w-3.5 text-muted-foreground shrink-0" />
            ) : (
              <ChevronRight className="h-3.5 w-3.5 text-muted-foreground shrink-0" />
            )
          ) : (
            <span className="h-3.5 w-3.5 shrink-0" />
          )}
          <span className="font-medium truncate">{tech.label}</span>
        </div>
        <span className="text-xs text-muted-foreground tabular-nums ml-4 shrink-0">
          {tech.count} {tech.count === 1 ? "subdomain" : "subdomains"}
        </span>
      </button>
      {open && hasSubdomains && (
        <div className="border-t border-border bg-muted/20 px-3 py-2 space-y-1">
          {tech.subdomains.map((sub) => (
            <div key={sub} className="text-xs font-mono text-muted-foreground py-0.5">
              {sub}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
