"use client";

import { FileBarChart2 } from "lucide-react";
import { AppShell } from "@/components/AppShell";
import { Badge } from "@/components/ui/badge";

export default function ReportsPage() {
  return (
    <AppShell>
      <div className="mb-6 flex items-center gap-3">
        <h1 className="text-2xl font-semibold tracking-tight">Reports</h1>
        <Badge variant="warning">Under development</Badge>
      </div>
      <div className="rounded-lg border border-dashed border-border p-16 text-center text-muted-foreground text-sm flex flex-col items-center gap-3">
        <FileBarChart2 className="h-8 w-8 opacity-50" />
        Report export is under development — check back in a future milestone.
      </div>
    </AppShell>
  );
}
