import path from "node:path";

import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// In dev, proxy API calls to the FastAPI service so the SPA can use relative URLs.
const apiTarget = process.env.VITE_API_PROXY || "http://localhost:8000";

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: { "@": path.resolve(__dirname, "./src") },
  },
  server: {
    host: true,
    port: 5173,
    proxy: {
      "/api": { target: apiTarget, changeOrigin: true },
    },
  },
});
