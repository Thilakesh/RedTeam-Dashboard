import { Badge } from "@/components/ui/badge";

export function StatusBadge({ status }: { status: number | null | undefined }) {
  if (status == null) return <span className="text-muted-foreground">—</span>;
  let v: "success" | "warning" | "destructive" | "info" = "info";
  if (status >= 200 && status < 300) v = "success";
  else if (status >= 300 && status < 400) v = "warning";
  else if (status >= 400) v = "destructive";
  return <Badge variant={v}>{status}</Badge>;
}

export function WafConfBadge({ conf }: { conf: string | null | undefined }) {
  if (!conf || conf === "NONE") return <span className="text-muted-foreground">—</span>;
  const variant = conf === "HIGH" ? "destructive" : conf === "MED" ? "warning" : "info";
  return <Badge variant={variant}>{conf}</Badge>;
}

export function IpTagChip({ tag }: { tag: string | null | undefined }) {
  if (!tag) return <span className="text-muted-foreground">—</span>;
  let cls = "bg-muted text-muted-foreground border border-border";
  if (tag === "Cloudflare IP") cls = "bg-orange-500/10 text-orange-600 border border-orange-500/30 dark:text-orange-400";
  else if (tag === "CDN IP") cls = "bg-emerald-500/10 text-emerald-600 border border-emerald-500/30 dark:text-emerald-400";
  else if (tag === "Direct IP") cls = "bg-rose-500/10 text-rose-600 border border-rose-500/30 dark:text-rose-400";
  return <span className={`inline-flex items-center rounded-md px-2 py-0.5 text-xxs font-medium ${cls}`}>{tag}</span>;
}

export function CountryFlag({ iso }: { iso: string | null | undefined }) {
  if (!iso || iso.length !== 2) return <span className="text-muted-foreground">—</span>;
  const codePoints = [...iso.toUpperCase()].map((c) => 127397 + c.charCodeAt(0));
  const flag = String.fromCodePoint(...codePoints);
  return (
    <span className="inline-flex items-center gap-1.5 text-sm">
      <span aria-hidden>{flag}</span>
      <span className="text-muted-foreground text-xs">{iso}</span>
    </span>
  );
}
