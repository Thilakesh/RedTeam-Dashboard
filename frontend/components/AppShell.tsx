"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import { useTheme } from "next-themes";
import {
  Bell,
  ChevronRight,
  Crosshair,
  FileBarChart2,
  LayoutDashboard,
  Moon,
  Plus,
  Radar,
  Rocket,
  ScanSearch,
  Settings,
  ShieldAlert,
  Sun,
  Users,
} from "lucide-react";
import { cn } from "@/lib/cn";
import { useAuth } from "@/lib/auth-context";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";

type NavItem = {
  href: string;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  children?: { href: string; label: string }[];
  adminOnly?: boolean;
};

const NAV_MAIN: NavItem[] = [
  { href: "/home", label: "Dashboard", icon: LayoutDashboard },
  {
    href: "/dashboard",
    label: "Basic Recon",
    icon: ScanSearch,
    children: [
      { href: "/dashboard", label: "Add Scan" },
      { href: "/dashboard/recon-jobs", label: "Recon Jobs" },
    ],
  },
  { href: "/vuln-scans", label: "Vulnerability Scans", icon: ShieldAlert },
  {
    href: "/targets",
    label: "Target Workspace",
    icon: Crosshair,
    children: [{ href: "/targets", label: "Assets" }],
  },
  {
    href: "/operations",
    label: "Operations",
    icon: Rocket,
    children: [
      { href: "/operations/launch", label: "Launch Operation" },
      { href: "/operations", label: "Operation History" },
    ],
  },
  { href: "/reports", label: "Reports", icon: FileBarChart2 },
  {
    href: "/settings",
    label: "Settings",
    icon: Settings,
    children: [
      { href: "/settings/profile", label: "Profile" },
      { href: "/settings/sessions", label: "Sessions" },
    ],
  },
];

const NAV_ADMIN: NavItem[] = [
  {
    href: "/admin",
    label: "Administration",
    icon: Users,
    adminOnly: true,
    children: [
      { href: "/admin/users", label: "Users" },
      { href: "/admin/sessions", label: "Sessions" },
      { href: "/admin/features", label: "Feature Controls" },
      { href: "/admin/settings", label: "System Settings" },
      { href: "/admin/audit", label: "Change Logs" },
    ],
  },
];

function buildBreadcrumb(pathname: string): string[] {
  if (pathname === "/home") return ["Dashboard"];
  if (pathname === "/dashboard") return ["Basic Recon", "Add Scan"];
  if (pathname === "/dashboard/recon-jobs") return ["Basic Recon", "Recon Jobs"];
  if (pathname.startsWith("/scans/")) return ["Scan Detail"];
  if (pathname === "/vuln-scans") return ["Vulnerability Scans"];
  if (pathname.startsWith("/vuln-scans/") && pathname.includes("/endpoints/")) {
    return ["Vulnerability Scans", "Detail", "Endpoint"];
  }
  if (pathname.startsWith("/vuln-scans/")) return ["Vulnerability Scans", "Detail"];
  if (pathname.match(/^\/targets\/[^/]+\/workspace\/tasks\/[^/]+$/))
    return ["Target Workspace", "Detail", "Task"];
  if (pathname.match(/^\/targets\/[^/]+\/workspace$/))
    return ["Target Workspace", "Detail"];
  if (pathname.match(/^\/targets\/[^/]+\/risk$/))
    return ["Target Workspace", "Risk View"];
  if (pathname === "/targets") return ["Target Workspace", "Assets"];
  if (pathname === "/operations/launch") return ["Operations", "Launch Operation"];
  if (pathname === "/operations") return ["Operations", "Operation History"];
  if (pathname.match(/^\/operations\/[^/]+$/)) return ["Operations", "Operation History", "Result"];
  if (pathname === "/reports") return ["Reports"];
  if (pathname.startsWith("/settings")) return ["Settings", ...pathname.split("/").slice(2).map(cap)];
  if (pathname.startsWith("/admin")) return ["Administration", ...pathname.split("/").slice(2).map(cap)];
  const parts = pathname.split("/").filter(Boolean);
  return parts.map(cap);
}

function cap(s: string) {
  return s.charAt(0).toUpperCase() + s.slice(1);
}

export function AppShell({ children }: { children: React.ReactNode }) {
  const router = useRouter();
  const pathname = usePathname();
  const { user, loading, isAdmin, logout } = useAuth();

  useEffect(() => {
    if (!loading && !user) router.replace("/login");
  }, [loading, user, router]);

  if (loading || !user) {
    return <div className="min-h-screen bg-background" />;
  }

  const crumbs = buildBreadcrumb(pathname || "/");

  return (
    <div className="h-screen overflow-hidden bg-background flex">
      <Sidebar pathname={pathname || "/"} isAdmin={isAdmin} />
      <div className="flex-1 flex flex-col min-w-0 h-screen">
        <TopBar crumbs={crumbs} email={user.email} role={user.role} onLogout={logout} />
        <main className="flex-1 px-8 py-6 overflow-auto scrollbar-thin">{children}</main>
      </div>
    </div>
  );
}

function Sidebar({ pathname, isAdmin }: { pathname: string; isAdmin: boolean }) {
  const { user } = useAuth();
  return (
    <aside className="w-60 shrink-0 bg-sidebar text-sidebar-foreground border-r border-black/30 flex flex-col">
      <div className="px-5 h-16 flex items-center gap-2 border-b border-white/5">
        <div className="h-8 w-8 rounded-md bg-primary/15 flex items-center justify-center">
          <Radar className="h-4 w-4 text-primary" />
        </div>
        <span className="font-semibold text-white text-[15px] tracking-tight">Recon Dashboard</span>
      </div>
      <div className="px-3 py-3 text-xxs uppercase tracking-wider text-white/40">Main</div>
      <nav className="flex-1 px-2 space-y-0.5 overflow-y-auto">
        {NAV_MAIN.map((item) => (
          <NavRow key={item.href} item={item} pathname={pathname} />
        ))}
        {isAdmin && (
          <>
            <div className="px-3 pt-4 pb-2 text-xxs uppercase tracking-wider text-white/40">
              Admin
            </div>
            {NAV_ADMIN.map((item) => (
              <NavRow key={item.href} item={item} pathname={pathname} />
            ))}
          </>
        )}
      </nav>
      <UserChip email={user?.email ?? ""} role={user?.role ?? "analyst"} />
    </aside>
  );
}

function NavRow({ item, pathname }: { item: NavItem; pathname: string }) {
  const Icon = item.icon;
  const active =
    pathname === item.href ||
    (item.href !== "/" && pathname.startsWith(item.href));
  const [open, setOpen] = useState(active);
  const hasChildren = !!item.children?.length;

  const rowClass = cn(
    "w-full flex items-center gap-3 px-3 py-2 rounded-md text-sm transition-colors",
    active ? "bg-primary/15 text-white" : "text-white/70 hover:bg-white/5 hover:text-white",
  );

  return (
    <div>
      {hasChildren ? (
        <button onClick={() => setOpen((v) => !v)} className={rowClass}>
          <Icon className="h-4 w-4" />
          <span className="flex-1 text-left">{item.label}</span>
          <ChevronRight className={cn("h-3.5 w-3.5 transition-transform", open && "rotate-90")} />
        </button>
      ) : (
        <Link href={item.href} className={rowClass}>
          <Icon className="h-4 w-4" />
          <span className="flex-1 text-left">{item.label}</span>
        </Link>
      )}
      {hasChildren && open && (
        <div className="ml-4 mt-0.5 space-y-0.5 border-l border-white/10 pl-3">
          {item.children!.map((c) => (
            <Link
              key={c.href}
              href={c.href}
              className="flex items-center gap-2 px-2 py-1.5 rounded text-xs text-white/60 hover:text-white hover:bg-white/5"
            >
              <span className="h-1 w-1 rounded-full bg-white/40" />
              {c.label}
            </Link>
          ))}
        </div>
      )}
    </div>
  );
}

function UserChip({ email, role }: { email: string; role: string }) {
  const initial = (email || "?").trim()[0]?.toUpperCase() ?? "?";
  return (
    <div className="border-t border-white/5 p-3">
      <div className="flex items-center gap-3 px-2 py-2 rounded-md hover:bg-white/5">
        <div className="h-8 w-8 rounded-full bg-primary/30 text-white text-sm flex items-center justify-center font-medium">
          {initial}
        </div>
        <div className="flex-1 min-w-0">
          <div className="text-sm font-medium text-white truncate">{email || "—"}</div>
          <div className="text-xxs text-white/50 capitalize">{role}</div>
        </div>
      </div>
    </div>
  );
}

function TopBar({
  crumbs,
  email,
  role,
  onLogout,
}: {
  crumbs: string[];
  email: string;
  role: string;
  onLogout: () => void;
}) {
  const initial = (email || "?").trim()[0]?.toUpperCase() ?? "?";
  return (
    <header className="h-16 px-8 flex items-center justify-between border-b border-border bg-background">
      <nav className="flex items-center gap-2 text-sm">
        {crumbs.map((c, i) => (
          <span key={i} className="flex items-center gap-2">
            {i > 0 && <ChevronRight className="h-3.5 w-3.5 text-muted-foreground" />}
            <span className={cn(i === crumbs.length - 1 ? "text-foreground font-medium" : "text-muted-foreground")}>{c}</span>
          </span>
        ))}
      </nav>
      <div className="flex items-center gap-2">
        <Link
          href="/dashboard"
          className="hidden md:inline-flex items-center gap-1.5 h-9 px-3 rounded-md bg-primary text-primary-foreground text-sm font-medium hover:bg-primary/90"
        >
          <Plus className="h-4 w-4" /> New Scan
        </Link>
        <ThemeToggle />
        <button className="h-9 w-9 rounded-md hover:bg-accent grid place-items-center text-muted-foreground hover:text-foreground">
          <Bell className="h-4 w-4" />
        </button>
        <DropdownMenu>
          <DropdownMenuTrigger className="flex items-center gap-2 h-9 px-1 rounded-md hover:bg-accent">
            <div className="h-7 w-7 rounded-full bg-primary/20 text-primary text-xs flex items-center justify-center font-semibold">{initial}</div>
            <span className="hidden md:inline text-sm font-medium pr-2 capitalize">{role}</span>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="w-56">
            <DropdownMenuLabel className="truncate">{email}</DropdownMenuLabel>
            <DropdownMenuSeparator />
            <DropdownMenuItem asChild>
              <Link href="/settings/profile">Profile</Link>
            </DropdownMenuItem>
            <DropdownMenuItem asChild>
              <Link href="/settings/sessions">Sessions</Link>
            </DropdownMenuItem>
            <DropdownMenuSeparator />
            <DropdownMenuItem onSelect={() => void onLogout()}>Sign out</DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </div>
    </header>
  );
}

function ThemeToggle() {
  const { theme, setTheme, resolvedTheme } = useTheme();
  const [mounted, setMounted] = useState(false);
  useEffect(() => setMounted(true), []);
  if (!mounted) return <div className="h-9 w-9" />;
  const dark = (theme === "system" ? resolvedTheme : theme) === "dark";
  return (
    <button
      onClick={() => setTheme(dark ? "light" : "dark")}
      className="h-9 w-9 rounded-md hover:bg-accent grid place-items-center text-muted-foreground hover:text-foreground"
      aria-label="Toggle theme"
    >
      {dark ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
    </button>
  );
}
