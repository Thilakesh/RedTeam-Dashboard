"use client";

import { useEffect, useState } from "react";
import { useTheme } from "next-themes";
import { Moon, Sun } from "lucide-react";
import { cn } from "@/lib/cn";

export function ThemeToggle({ className }: { className?: string }) {
  const { theme, setTheme, resolvedTheme } = useTheme();
  const [mounted, setMounted] = useState(false);
  useEffect(() => setMounted(true), []);
  if (!mounted) return <div className={cn("h-9 w-9", className)} />;
  const dark = (theme === "system" ? resolvedTheme : theme) === "dark";
  return (
    <button
      onClick={() => setTheme(dark ? "light" : "dark")}
      className={cn(
        "h-9 w-9 rounded-md hover:bg-accent grid place-items-center text-muted-foreground hover:text-foreground",
        className,
      )}
      aria-label="Toggle theme"
    >
      {dark ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
    </button>
  );
}
