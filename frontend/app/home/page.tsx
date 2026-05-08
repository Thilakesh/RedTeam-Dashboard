"use client";

import { AppShell } from "@/components/AppShell";

export default function DashboardHomePage() {
  return (
    <AppShell>
      <div className="mb-6">
        <h1 className="text-2xl font-semibold tracking-tight">Dashboard</h1>
        <p className="text-sm text-muted-foreground mt-1">
          Overview and analytics — coming soon.
        </p>
      </div>
      <div className="rounded-lg border border-dashed border-border p-16 text-center text-muted-foreground text-sm">
        Dashboard widgets arrive in a future milestone.
      </div>
    </AppShell>
  );
}
