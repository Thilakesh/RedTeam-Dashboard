"use client";

import { Badge } from "@/components/ui/badge";

export function severityVariant(
  sev: string,
): "destructive" | "warning" | "info" | "success" | "default" {
  switch (sev.toLowerCase()) {
    case "critical":
    case "high":
      return "destructive";
    case "med":
    case "medium":
      return "warning";
    case "low":
      return "info";
    case "info":
      return "default";
    default:
      return "default";
  }
}

export function SeverityBadge({ severity }: { severity: string }) {
  return (
    <Badge variant={severityVariant(severity)} className="uppercase">
      {severity}
    </Badge>
  );
}

export function statusVariant(
  code: number | null | undefined,
): "success" | "warning" | "destructive" | "default" {
  if (code === null || code === undefined) return "default";
  if (code >= 200 && code < 300) return "success";
  if (code >= 300 && code < 400) return "warning";
  if (code >= 400) return "destructive";
  return "default";
}

// Endpoint/finding URLs come from the scanned (attacker-controlled) target's
// own responses. React doesn't sanitize href schemes, so a javascript:/data:
// URL would execute on click if bound directly. Only ever bind through this.
export function safeHref(url: string | null | undefined): string | undefined {
  if (!url) return undefined;
  return /^https?:\/\//i.test(url) ? url : undefined;
}
