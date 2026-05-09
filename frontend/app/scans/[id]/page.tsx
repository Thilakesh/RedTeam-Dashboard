"use client";

import { Suspense, useEffect, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useRouter, useSearchParams } from "next/navigation";
import { Calendar, Clock, Download, Globe, Share2 } from "lucide-react";
import { AppShell } from "@/components/AppShell";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { OverviewTab } from "@/components/tabs/OverviewTab";
import { IpSummaryTab } from "@/components/tabs/IpSummaryTab";
import { CdnWafTab } from "@/components/tabs/CdnWafTab";
import { TechnologiesTab } from "@/components/tabs/TechnologiesTab";
import { PortsTab } from "@/components/tabs/PortsTab";
import { RisksTab } from "@/components/tabs/RisksTab";
import { SubdomainsTable } from "@/components/SubdomainsTable";
import { api, sseUrl, type ScanDetail, type ScanOverview, type VulnScanOut } from "@/lib/api";

const SSE_EVENTS = [
  "stage.started",
  "stage.completed",
  "stage.failed",
  "scan.completed",
  "scan.failed",
];

const STATUS_VARIANT: Record<string, "success" | "warning" | "destructive" | "default"> = {
  completed: "success",
  running: "warning",
  failed: "destructive",
  created: "default",
};

// Inner component — uses useSearchParams, must be wrapped in Suspense by the page
function ScanDetailContent({ params }: { params: { id: string } }) {
  const qc = useQueryClient();
  const router = useRouter();
  const searchParams = useSearchParams();
  const VALID_TABS = ["overview", "subdomains", "ips", "cdnwaf", "tech", "ports", "risks", "history"];
  const rawTab = searchParams.get("tab");
  const defaultTab = rawTab && VALID_TABS.includes(rawTab) ? rawTab : "subdomains";

  const [vulnLaunching, setVulnLaunching] = useState(false);

  const scan = useQuery({
    queryKey: ["scan", params.id],
    queryFn: () => api<ScanDetail>(`/scans/${params.id}`),
  });

  const overview = useQuery({
    queryKey: ["scan-overview-light", params.id],
    queryFn: () => api<ScanOverview>(`/scans/${params.id}/overview`),
    enabled: !!scan.data,
  });

  useEffect(() => {
    const status = scan.data?.status;
    if (!status || status === "completed" || status === "failed") return;

    const es = new EventSource(sseUrl(`/scans/${params.id}/stream`));
    const refetch = () => {
      qc.invalidateQueries({ queryKey: ["scan", params.id] });
      qc.invalidateQueries({ queryKey: ["scan-subdomains", params.id] });
      qc.invalidateQueries({ queryKey: ["scan-overview", params.id] });
      qc.invalidateQueries({ queryKey: ["scan-overview-light", params.id] });
      qc.invalidateQueries({ queryKey: ["scan-ips", params.id] });
      qc.invalidateQueries({ queryKey: ["scan-cdn-waf", params.id] });
      qc.invalidateQueries({ queryKey: ["scan-tech", params.id] });
      qc.invalidateQueries({ queryKey: ["scan-ports", params.id] });
    };
    SSE_EVENTS.forEach((ev) => es.addEventListener(ev, refetch));
    es.addEventListener("scan.completed", () => {
      qc.invalidateQueries({ queryKey: ["scan-findings", params.id] });
    });
    es.onerror = () => {
      if (es.readyState === EventSource.CLOSED) es.close();
    };
    return () => es.close();
  }, [scan.data?.status, params.id, qc]);

  if (scan.isLoading || !scan.data) {
    return (
      <AppShell>
        <p className="text-sm text-muted-foreground">Loading scan…</p>
      </AppShell>
    );
  }

  const s = scan.data;
  const started = s.started_at ? new Date(s.started_at) : null;
  const finished = s.finished_at ? new Date(s.finished_at) : null;
  const durationMs = started && finished ? finished.getTime() - started.getTime() : null;
  const subCount = overview.data?.subdomain_count ?? 0;

  return (
    <AppShell>
      {/* Header */}
      <div className="mb-6 flex flex-wrap items-start justify-between gap-4">
        <div>
          <div className="text-xs text-muted-foreground mb-1">Scan Results</div>
          <div className="flex items-center gap-3">
            <Globe className="h-5 w-5 text-primary" />
            <h1 className="text-2xl font-semibold tracking-tight">{s.domain}</h1>
            <Badge variant={STATUS_VARIANT[s.status] ?? "default"}>{s.status}</Badge>
          </div>
          <div className="mt-2 flex flex-wrap items-center gap-x-5 gap-y-1 text-xs text-muted-foreground">
            {started && (
              <span className="inline-flex items-center gap-1.5">
                <Calendar className="h-3.5 w-3.5" /> {started.toLocaleString()}
              </span>
            )}
            {durationMs != null && (
              <span className="inline-flex items-center gap-1.5">
                <Clock className="h-3.5 w-3.5" /> Duration: {formatDuration(durationMs)}
              </span>
            )}
            <span>
              Profile: <span className="text-foreground font-medium">{s.profile}</span>
            </span>
            <span>
              Total Subdomains:{" "}
              <span className="text-foreground font-medium">{subCount}</span>
            </span>
          </div>
        </div>
        <div className="flex items-center gap-2">
          {s.status === "completed" && (
            <Button
              variant="outline"
              size="sm"
              disabled={vulnLaunching}
              onClick={async () => {
                setVulnLaunching(true);
                try {
                  const result = await api<VulnScanOut>("/vuln-scans", {
                    method: "POST",
                    body: JSON.stringify({
                      parent_scan_id: params.id,
                      profile: "vuln_quick",
                    }),
                  });
                  router.push(`/vuln-scans/${result.id}`);
                } catch (err) {
                  console.error("Failed to start vuln scan:", err);
                  setVulnLaunching(false);
                }
              }}
            >
              {vulnLaunching ? (
                <span className="h-4 w-4 animate-spin rounded-full border-2 border-current border-t-transparent" />
              ) : null}
              Run Vulnerability Analysis
            </Button>
          )}
          <Button variant="outline" size="sm">
            <Download className="h-4 w-4" /> Export
          </Button>
          <Button size="sm">
            <Share2 className="h-4 w-4" /> Share Report
          </Button>
        </div>
      </div>

      {/* Progress bar (only while running or created) */}
      {(s.status === "running" || s.status === "created") && (
        <div className="mb-6">
          <div className="flex justify-between text-xs mb-1.5 text-muted-foreground">
            <span>Progress</span>
            <span>{s.progress_pct}%</span>
          </div>
          <div className="h-2 bg-muted rounded overflow-hidden">
            <div
              className="h-full bg-primary transition-all"
              style={{ width: `${s.progress_pct}%` }}
            />
          </div>
        </div>
      )}
      {s.error && (
        <p className="mb-6 text-xs text-destructive break-words">Error: {s.error}</p>
      )}

      {/* Tabs */}
      <Tabs value={defaultTab} onValueChange={(t) => router.replace(`?tab=${t}`, { scroll: false })}>
        <TabsList>
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="subdomains">Subdomains</TabsTrigger>
          <TabsTrigger value="ips">IP Summary</TabsTrigger>
          <TabsTrigger value="cdnwaf">CDN / WAF</TabsTrigger>
          <TabsTrigger value="tech">Technologies</TabsTrigger>
          <TabsTrigger value="ports">Ports</TabsTrigger>
          <TabsTrigger value="risks">Risks</TabsTrigger>
          <TabsTrigger value="history">History</TabsTrigger>
        </TabsList>

        <TabsContent value="overview">
          <OverviewTab scanId={params.id} scan={s} />
        </TabsContent>
        <TabsContent value="subdomains">
          <SubdomainsTable scanId={params.id} />
        </TabsContent>
        <TabsContent value="ips">
          <IpSummaryTab scanId={params.id} />
        </TabsContent>
        <TabsContent value="cdnwaf">
          <CdnWafTab scanId={params.id} />
        </TabsContent>
        <TabsContent value="tech">
          <TechnologiesTab scanId={params.id} />
        </TabsContent>
        <TabsContent value="ports">
          <PortsTab scanId={params.id} />
        </TabsContent>
        <TabsContent value="risks">
          <RisksTab scanId={params.id} scanProfile={s.profile} />
        </TabsContent>
        <TabsContent value="history">
          <p className="text-sm text-muted-foreground">
            Historical scan diffing arrives in a future milestone — re-running this target will
            populate added/removed/changed cards here.
          </p>
        </TabsContent>
      </Tabs>
    </AppShell>
  );
}

function formatDuration(ms: number): string {
  const totalSec = Math.round(ms / 1000);
  const m = Math.floor(totalSec / 60);
  const s = totalSec % 60;
  return `${String(m).padStart(2, "0")}:${String(s).padStart(2, "0")}`;
}

// Page export — wraps the inner component in Suspense (required by Next.js for useSearchParams)
export default function ScanDetailPage({ params }: { params: { id: string } }) {
  return (
    <Suspense
      fallback={
        <AppShell>
          <p className="text-sm text-muted-foreground">Loading scan…</p>
        </AppShell>
      }
    >
      <ScanDetailContent params={params} />
    </Suspense>
  );
}
