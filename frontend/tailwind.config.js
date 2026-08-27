/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        // ── Dark theme (default / existing) ──
        night: {
          50: "#f8fafc",
          100: "#f1f5f9",
          200: "#e2e8f0",
          300: "#cbd5e1",
          400: "#94a3b8",
          500: "#64748b",
          600: "#475569",
          700: "#1a2540",
          800: "#111a30",
          850: "#0d1526",
          900: "#0a101f",
          950: "#060a14",
        },
        electric: {
          400: "#38bdf8",
          500: "#0ea5e9",
          600: "#0284c7",
        },
        cyber: {
          cyan: "#22d3ee",
          purple: "#a78bfa",
          red: "#f87171",
          orange: "#fb923c",
          yellow: "#facc15",
          green: "#4ade80",
        },
        // ── Semantic surface tokens (set via CSS vars) ──
        surface: {
          DEFAULT: "var(--surface)",
          alt: "var(--surface-alt)",
          raised: "var(--surface-raised)",
          border: "var(--surface-border)",
          "border-strong": "var(--surface-border-strong)",
        },
        on: {
          DEFAULT: "var(--on-surface)",
          muted: "var(--on-surface-muted)",
          faint: "var(--on-surface-faint)",
        },
      },
      fontFamily: {
        sans: ["Inter", "system-ui", "-apple-system", "Segoe UI", "Roboto", "sans-serif"],
        mono: ["JetBrains Mono", "ui-monospace", "SFMono-Regular", "monospace"],
      },
      boxShadow: {
        glow: "0 0 24px rgba(14, 165, 233, 0.25)",
        "glow-red": "0 0 24px rgba(248, 113, 113, 0.25)",
        panel: "0 4px 24px rgba(0, 0, 0, 0.4)",
        "panel-light": "0 4px 24px rgba(0, 0, 0, 0.08)",
      },
      backgroundImage: {
        "soc-grid":
          "linear-gradient(rgba(56,189,248,0.04) 1px, transparent 1px), linear-gradient(90deg, rgba(56,189,248,0.04) 1px, transparent 1px)",
        "soc-grid-light":
          "linear-gradient(rgba(14,165,233,0.06) 1px, transparent 1px), linear-gradient(90deg, rgba(14,165,233,0.06) 1px, transparent 1px)",
        "app-gradient":
          "radial-gradient(1200px 600px at 20% -10%, rgba(14,165,233,0.15), transparent 60%), radial-gradient(1000px 500px at 90% 110%, rgba(167,139,250,0.12), transparent 60%)",
        "app-gradient-light":
          "radial-gradient(1200px 600px at 20% -10%, rgba(14,165,233,0.08), transparent 60%), radial-gradient(1000px 500px at 90% 110%, rgba(167,139,250,0.06), transparent 60%)",
      },
      backgroundSize: {
        grid: "44px 44px",
      },
    },
  },
  plugins: [],
};
