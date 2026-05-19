import { ShieldCheck, Globe } from "lucide-react";
import { cn } from "@/lib/cn";

type Props = {
  verified: boolean;
  className?: string;
};

export function TargetBadge({ verified, className }: Props) {
  if (verified) {
    return (
      <span
        className={cn(
          "inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wide",
          "bg-emerald-500/15 text-emerald-400 border border-emerald-500/30",
          className,
        )}
        title="Verified target — aggressive scans unlocked"
      >
        <ShieldCheck className="h-3 w-3" /> Verified
      </span>
    );
  }
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wide",
        "bg-muted/40 text-muted-foreground border border-border",
        className,
      )}
      title="Public target — only passive scans allowed"
    >
      <Globe className="h-3 w-3" /> Public
    </span>
  );
}
