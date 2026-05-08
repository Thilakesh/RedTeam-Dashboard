import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/lib/cn";

const variants = cva(
  "inline-flex items-center rounded-md px-2 py-0.5 text-xxs font-medium transition-colors whitespace-nowrap",
  {
    variants: {
      variant: {
        default: "bg-muted text-muted-foreground",
        success: "bg-success/15 text-success border border-success/30",
        warning: "bg-warning/15 text-warning border border-warning/30",
        info: "bg-info/15 text-info border border-info/30",
        destructive: "bg-destructive/15 text-destructive border border-destructive/30",
        outline: "border border-border text-foreground",
        primary: "bg-primary text-primary-foreground",
      },
    },
    defaultVariants: { variant: "default" },
  },
);

export type BadgeProps = React.HTMLAttributes<HTMLSpanElement> &
  VariantProps<typeof variants>;

export function Badge({ className, variant, ...props }: BadgeProps) {
  return <span className={cn(variants({ variant }), className)} {...props} />;
}
