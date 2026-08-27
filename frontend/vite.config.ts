import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    host: true,
    proxy: {
      "/api": {
        target: process.env.VITE_BACKEND_URL || "http://localhost:8000",
        changeOrigin: true,
        ws: true,
      },
      "/ws": {
        target: process.env.VITE_BACKEND_URL || "http://localhost:8000",
        ws: true,
        changeOrigin: true,
      },
    },
  },
  build: {
    outDir: "dist",
    sourcemap: false,
    rollupOptions: {
      output: {
        manualChunks: {
          "vendor-react":["react", "react-dom", "react-router-dom"],
          "vendor-query": ["@tanstack/react-query"],
          "vendor-charts": ["recharts"],
          "vendor-echarts": ["echarts", "echarts-for-react"],
          "vendor-flow": ["@xyflow/react"],
          "vendor-icons": ["lucide-react"],
          "vendor-http": ["axios"],
        },
      },
    },
  },
});
