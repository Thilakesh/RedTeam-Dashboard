"use client";

import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useRouter } from "next/navigation";
import { createContext, useCallback, useContext, useMemo } from "react";
import { Me, fetchMe, logout as apiLogout } from "@/lib/api";

type AuthValue = {
  user: Me | null;
  loading: boolean;
  isAdmin: boolean;
  hasFeature: (name: string) => boolean;
  refresh: () => Promise<void>;
  logout: () => Promise<void>;
};

const AuthContext = createContext<AuthValue | null>(null);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const qc = useQueryClient();
  const router = useRouter();

  const q = useQuery<Me | null>({
    queryKey: ["me"],
    queryFn: async () => {
      try {
        return await fetchMe();
      } catch {
        return null;
      }
    },
    retry: false,
    staleTime: 60_000,
    refetchOnWindowFocus: false,
  });

  const refresh = useCallback(async () => {
    await qc.invalidateQueries({ queryKey: ["me"] });
  }, [qc]);

  const logout = useCallback(async () => {
    try {
      await apiLogout();
    } catch {
      /* ignore */
    }
    qc.setQueryData(["me"], null);
    qc.clear();
    router.replace("/login");
  }, [qc, router]);

  const value = useMemo<AuthValue>(() => {
    const user = q.data ?? null;
    return {
      user,
      loading: q.isLoading,
      isAdmin: user?.role === "admin",
      hasFeature: (name: string) => !!user && user.features.includes(name),
      refresh,
      logout,
    };
  }, [q.data, q.isLoading, refresh, logout]);

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within <AuthProvider>");
  return ctx;
}
