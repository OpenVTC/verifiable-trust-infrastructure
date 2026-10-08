import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { resolve } from "node:path";

// The member portal: a separate bundle from the admin console, served by the
// VTC daemon at `/members/*` (`src/admin_ui.rs`, `MEMBER_UI_DIR`). Its entry
// HTML lives in `members/`, its sources in `src/members/`; it shares this
// package's dependencies and the console's small, dependency-free helpers
// (`@/lib/webauthn`) but none of the console's shell, plugins or API client.
// `build.rs` passes `--outDir` (under `$OUT_DIR`), as it does for the console.
export default defineConfig({
  root: resolve(__dirname, "members"),
  base: "/members/",
  plugins: [react()],
  build: {
    outDir: resolve(__dirname, "dist-members"),
    emptyOutDir: true,
    sourcemap: true,
  },
  resolve: {
    alias: {
      "@": resolve(__dirname, "src"),
    },
  },
  server: {
    port: 5174,
    proxy: {
      "/health": process.env.VITE_API_PROXY_TARGET || "http://localhost:8200",
      "/v1": process.env.VITE_API_PROXY_TARGET || "http://localhost:8200",
    },
  },
});
