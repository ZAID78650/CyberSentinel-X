/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        night: {
          950: "#060a14",
          900: "#0a101f",
          850: "#0d1526",
          800: "#111a30",
          700: "#1a2540",
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
      },
      fontFamily: {
        sans: ["Inter", "system-ui", "-apple-system", "Segoe UI", "Roboto", "sans-serif"],
        mono: ["JetBrains Mono", "ui-monospace", "SFMono-Regular", "monospace"],
      },
      boxShadow: {
        glow: "0 0 24px rgba(14, 165, 233, 0.25)",
        "glow-red": "0 0 24px rgba(248, 113, 113, 0.25)",
        panel: "0 4px 24px rgba(0, 0, 0, 0.4)",
      },
      backgroundImage: {
        "soc-grid":
          "linear-gradient(rgba(56,189,248,0.04) 1px, transparent 1px), linear-gradient(90deg, rgba(56,189,248,0.04) 1px, transparent 1px)",
        "app-gradient":
          "radial-gradient(1200px 600px at 20% -10%, rgba(14,165,233,0.15), transparent 60%), radial-gradient(1000px 500px at 90% 110%, rgba(167,139,250,0.12), transparent 60%)",
      },
      backgroundSize: {
        grid: "44px 44px",
      },
    },
  },
  plugins: [],
};
