import { defineConfig } from "vite";
// Uses the esbuild/Babel React plugin instead of @vitejs/plugin-react-swc:
// the SWC native addon (@swc/core) refuses to run on some Windows setups due to
// its cache-directory ACL hardening. This keeps the same React + Vite + TS stack
// with no native binary. Swap back to plugin-react-swc if SWC works on your host.
import react from "@vitejs/plugin-react";
import path from "path";
import { componentTagger } from "lovable-tagger";

// https://vitejs.dev/config/
export default defineConfig(({ mode }) => ({
  server: {
    host: "127.0.0.1",
    port: 8080,
    proxy: {
      "/api/baseline": { target: "http://127.0.0.1:8081", rewrite: (p) => p.replace(/^\/api\/baseline/, "") },
      "/api/hardened": { target: "http://127.0.0.1:8082", rewrite: (p) => p.replace(/^\/api\/hardened/, "") },
    },
    hmr: {
      overlay: false,
    },
  },
  plugins: [react(), mode === "development" && componentTagger()].filter(Boolean),
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
}));
