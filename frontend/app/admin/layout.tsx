"use client";

import { useRouter } from "next/navigation";
import { useEffect } from "react";
import { useAuth } from "@/lib/auth-context";

export default function AdminLayout({ children }: { children: React.ReactNode }) {
  const { user, loading, isAdmin } = useAuth();
  const router = useRouter();

  useEffect(() => {
    if (loading) return;
    if (!user) router.replace("/login");
    else if (!isAdmin) router.replace("/home");
  }, [loading, user, isAdmin, router]);

  if (loading || !user || !isAdmin) {
    return <div className="min-h-screen bg-background" />;
  }
  return <>{children}</>;
}
