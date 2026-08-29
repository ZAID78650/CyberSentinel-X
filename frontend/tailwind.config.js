/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        // ── Intelligence Command Center palette ──
        navy: {
          50: "#f0f4f8",
          100: "#d9e2ec",
          200: "#bcccdc",
          300: "#9fb3c8",
          400: "#829ab1",
          500: "#627d98",
          600: "#486581",
          700: "#334e68",
          800: "#243b53",
          900: "#102a43",
          950: "#0a1929",
        },
        intel: {
          blue: "#3b82f6",
          cyan: "#06b6d4",
          purple: "#8b5cf6",
          green: "#22c55e",
          amber: "#f59e0b",
          orange: "#f97316",
          red: "#ef4444",
        },
        surface: {
          DEFAULT: "#0c1322",
          50: "#f8fafc",
          100: "#f1f5f9",
          200: "#0c1322",
          300: "#0f172a",
          400: "#131d33",
          500: "#182442",
          600: "#1e2d4a",
          700: "#253756",
          800: "#2d4062",
          900: "#364f70",
          border: "#1e2d4a",
          "border-light": "#2a3f5f",
        },
      },
      fontFamily: {
        sans: ["Inter", "system-ui", "-apple-system", "Segoe UI", "Roboto", "sans-serif"],
        mono: ["JetBrains Mono", "ui-monospace", "SFMono-Regular", "monospace"],
        display: ["Inter", "system-ui", "sans-serif"],
      },
      fontSize: {
        "2xs": ["0.625rem", { lineHeight: "0.875rem" }],
      },
      boxShadow: {
        "intel-sm": "0 1px 3px rgba(0, 0, 0, 0.3)",
        "intel-md": "0 4px 12px rgba(0, 0, 0, 0.4)",
        "intel-lg": "0 8px 24px rgba(0, 0, 0, 0.5)",
        "intel-xl": "0 12px 40px rgba(0, 0, 0, 0.6)",
        "intel-glow-blue": "0 0 20px rgba(59, 130, 246, 0.15)",
        "intel-glow-cyan": "0 0 20px rgba(6, 182, 212, 0.15)",
        "intel-glow-purple": "0 0 20px rgba(139, 92, 246, 0.15)",
        "intel-glow-green": "0 0 20px rgba(34, 197, 94, 0.15)",
        "intel-glow-red": "0 0 20px rgba(239, 68, 68, 0.15)",
        "intel-glow-amber": "0 0 20px rgba(245, 158, 11, 0.15)",
        glow: "0 0 24px rgba(59, 130, 246, 0.25)",
        "glow-red": "0 0 24px rgba(239, 68, 68, 0.25)",
        panel: "0 4px 24px rgba(0, 0, 0, 0.4)",
        "panel-light": "0 4px 24px rgba(0, 0, 0, 0.08)",
      },
      animation: {
        "fade-in": "fadeIn 0.3s ease-out",
        "slide-in-right": "slideInRight 0.3s ease-out",
        "slide-in-left": "slideInLeft 0.3s ease-out",
        "slide-up": "slideUp 0.3s ease-out",
        "scale-in": "scaleIn 0.2s ease-out",
        "pulse-slow": "pulse 4s cubic-bezier(0.4, 0, 0.6, 1) infinite",
        "scan-line": "scanLine 2s linear infinite",
        "data-flow": "dataFlow 1.5s ease-in-out infinite",
        "glow-pulse": "glowPulse 2s ease-in-out infinite",
        countup: "countUp 0.8s ease-out",
      },
      keyframes: {
        fadeIn: {
          "0%": { opacity: "0" },
          "100%": { opacity: "1" },
        },
        slideInRight: {
          "0%": { transform: "translateX(100%)", opacity: "0" },
          "100%": { transform: "translateX(0)", opacity: "1" },
        },
        slideInLeft: {
          "0%": { transform: "translateX(-100%)", opacity: "0" },
          "100%": { transform: "translateX(0)", opacity: "1" },
        },
        slideUp: {
          "0%": { transform: "translateY(16px)", opacity: "0" },
          "100%": { transform: "translateY(0)", opacity: "1" },
        },
        scaleIn: {
          "0%": { transform: "scale(0.95)", opacity: "0" },
          "100%": { transform: "scale(1)", opacity: "1" },
        },
        scanLine: {
          "0%": { transform: "translateY(-100%)" },
          "100%": { transform: "translateY(100%)" },
        },
        dataFlow: {
          "0%, 100%": { opacity: "0.3" },
          "50%": { opacity: "1" },
        },
        glowPulse: {
          "0%, 100%": { opacity: "0.5" },
          "50%": { opacity: "1" },
        },
        countUp: {
          "0%": { transform: "translateY(8px)", opacity: "0" },
          "100%": { transform: "translateY(0)", opacity: "1" },
        },
      },
      backgroundImage: {
        "intel-gradient": "linear-gradient(135deg, rgba(59, 130, 246, 0.05) 0%, rgba(139, 92, 246, 0.05) 100%)",
        "intel-radial": "radial-gradient(ellipse at center, rgba(59, 130, 246, 0.08) 0%, transparent 70%)",
        "navy-gradient": "linear-gradient(180deg, #0c1322 0%, #0a1929 100%)",
      },
      backdropBlur: {
        xs: "2px",
      },
      transitionDuration: {
        250: "250ms",
      },
    },
  },
  plugins: [],
};
