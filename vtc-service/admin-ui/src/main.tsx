import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter } from "react-router-dom";

import App from "@/App";
import { ConfirmDialogProvider } from "@/components/ConfirmDialog";
import { loadThirdPartyPlugins } from "@/lib/plugin-loader";
import { applyStoredTheme } from "@/lib/theme";
import { ToastProvider } from "@/lib/toast";
import { registerBuiltinPlugins } from "@/plugins";
// Self-hosted "cryptographic blueprint" type: Fraunces (display,
// roman + italic), IBM Plex Sans (body), IBM Plex Mono (data/labels).
// Self-hosted rather than CDN so the admin UI stays offline-capable
// and leaks no font request to a third party.
import "@fontsource-variable/fraunces";
import "@fontsource-variable/fraunces/wght-italic.css";
import "@fontsource/ibm-plex-sans/400.css";
import "@fontsource/ibm-plex-sans/500.css";
import "@fontsource/ibm-plex-sans/600.css";
import "@fontsource/ibm-plex-mono/400.css";
import "@fontsource/ibm-plex-mono/500.css";
import "@fontsource/ibm-plex-mono/600.css";
import "@/styles.css";

// Apply the persisted theme before first paint so the cascade picks
// the right `color-scheme` without a flash.
applyStoredTheme();

// Single QueryClient instance per page load. Sane defaults: short
// stale time so the operator's view stays fresh, no automatic
// refetch on window focus (annoying for an admin tool that often
// sits open in a background tab).
const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 5_000,
      refetchOnWindowFocus: false,
      retry: 1,
    },
  },
});

// Plugin discovery happens in two waves:
//
// 1. **Built-ins** (`src/plugins/*`) register synchronously at
//    module load via `registerBuiltinPlugins()`. They ride along
//    with the shell bundle.
// 2. **Third-party plugins** are listed in `/admin/plugins.json`
//    and dynamically `import()`-ed before render. Loading them
//    before mount means the nav has the full plugin set by first
//    paint — no flash of "missing tabs."
//
// Both paths converge on `window.VtcPluginApi.registerPlugin` /
// the local `registerPlugin` import, so the shell renders from a
// unified registry regardless of source.
registerBuiltinPlugins();

// Avoid top-level await (esbuild's default target doesn't permit
// it). Mount after the loader resolves; the registry is fully
// populated by first paint either way.
loadThirdPartyPlugins().finally(() => {
  createRoot(document.getElementById("root")!).render(
    <StrictMode>
      <QueryClientProvider client={queryClient}>
        <ToastProvider>
          <ConfirmDialogProvider>
            <BrowserRouter basename="/admin">
              <App />
            </BrowserRouter>
          </ConfirmDialogProvider>
        </ToastProvider>
      </QueryClientProvider>
    </StrictMode>,
  );
});
