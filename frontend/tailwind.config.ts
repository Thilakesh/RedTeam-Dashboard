import type { Config } from "tailwindcss";

const config: Config = {
  darkMode: "class",
  content: ["./app/**/*.{ts,tsx}", "./components/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        background: "hsl(var(--background))",
        foreground: "hsl(var(--foreground))",
        card: {
          DEFAULT: "hsl(var(--card))",
          foreground: "hsl(var(--card-foreground))",
        },
        muted: {
          DEFAULT: "hsl(var(--muted))",
          foreground: "hsl(var(--muted-foreground))",
          "foreground-2": "hsl(var(--muted-foreground-2))",
        },
        border: "hsl(var(--border))",
        divider: "hsl(var(--divider))",
        input: "hsl(var(--input))",
        ring: "hsl(var(--ring))",
        primary: {
          DEFAULT: "hsl(var(--primary))",
          foreground: "hsl(var(--primary-foreground))",
          tint: "hsl(var(--primary-tint))",
          tint2: "hsl(var(--primary-tint-2))",
        },
        accent: {
          DEFAULT: "hsl(var(--accent))",
          foreground: "hsl(var(--accent-foreground))",
        },
        destructive: {
          DEFAULT: "hsl(var(--destructive))",
          foreground: "hsl(var(--destructive-foreground))",
        },
        sidebar: {
          DEFAULT: "hsl(var(--sidebar))",
          foreground: "hsl(var(--sidebar-foreground))",
          active: "hsl(var(--sidebar-active))",
        },
        "surface-deep": "hsl(var(--surface-deep))",
        success: "hsl(var(--success))",
        warning: "hsl(var(--warning))",
        info: "hsl(var(--info))",
        sev: {
          high: "hsl(var(--sev-high))",
          "high-fg": "hsl(var(--sev-high-fg))",
          med: "hsl(var(--sev-med))",
          "med-fg": "hsl(var(--sev-med-fg))",
          low: "hsl(var(--sev-low))",
          "low-fg": "hsl(var(--sev-low-fg))",
          "ok-fg": "hsl(var(--sev-ok-fg))",
        },
      },
      borderRadius: { lg: "10px", md: "8px", sm: "6px" },
      fontSize: { xxs: "0.6875rem" },
      fontFamily: {
        mono: ["SFMono-Regular", "ui-monospace", "Menlo", "monospace"],
      },
    },
  },
  plugins: [],
};
export default config;
