import { ThemeToggle } from "@/components/ThemeToggle";

export default function AuthLayout({ children }: { children: React.ReactNode }) {
  return (
    <main className="min-h-screen relative bg-background">
      <ThemeToggle className="absolute top-4 right-4 z-10" />
      {children}
    </main>
  );
}
