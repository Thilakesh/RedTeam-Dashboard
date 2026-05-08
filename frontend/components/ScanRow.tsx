import Link from "next/link";
import { Badge } from "@/components/ui/badge";
import type { Scan } from "@/lib/api";

const STATUS_VARIANT: Record<Scan["status"], "default" | "success" | "warning" | "destructive" | "outline"> = {
  queued: "outline",
  created: "default",
  running: "warning",
  completed: "success",
  failed: "destructive",
  stopped: "default",
};

export function ScanRow({ scan }: { scan: Scan }) {
  return (
    <Link
      href={`/scans/${scan.id}`}
      className="block border border-border bg-card hover:border-primary/50 rounded-md p-3 transition-colors"
    >
      <div className="flex items-center justify-between gap-4">
        <div className="min-w-0">
          <div className="font-medium truncate">{scan.domain}</div>
          <div className="text-xs text-muted-foreground">
            {scan.profile} · {new Date(scan.created_at).toLocaleString()}
          </div>
        </div>
        <div className="flex items-center gap-3 shrink-0">
          <div className="w-32 h-1.5 bg-muted rounded overflow-hidden">
            <div
              className="h-full bg-primary transition-all"
              style={{ width: `${scan.progress_pct}%` }}
            />
          </div>
          <Badge variant={STATUS_VARIANT[scan.status]}>{scan.status}</Badge>
        </div>
      </div>
    </Link>
  );
}
