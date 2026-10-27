// Entry point of the member portal bundle (`/members/`).
//
// A separate bundle from the console's, built by `vite.members.config.ts`: it
// imports nothing from the console shell, its plugins or its API client, so a
// member's browser never loads administrator code.

import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

import { ThemePreviewBar } from "@/components/ThemePreviewBar";
import { applyStoredCommunityTheme } from "@/lib/community-theme";
import { applyStoredTheme } from "@/lib/theme";
import { isThemePreview, startThemePreview } from "@/lib/theme-preview";
import { Portal } from "./Portal";
import { previewView, setPreviewView } from "./preview";
// The same self-hosted IBM Plex faces and shared tokens as the console and the
// home page, then the community sign-in sheet, then the portal's own rules.
import "@fontsource/ibm-plex-sans/400.css";
import "@fontsource/ibm-plex-sans/500.css";
import "@fontsource/ibm-plex-sans/600.css";
import "@fontsource/ibm-plex-sans/700.css";
import "@fontsource/ibm-plex-mono/400.css";
import "@fontsource/ibm-plex-mono/500.css";
import "@/styles/tokens.css";
import "../signin/signin.css";
import "./members.css";

// The colour theme chosen here, on the home page or in the console (one shared
// key, `lib/theme.ts`), before first paint.
applyStoredTheme();
// A theme-preview tab draws the editor's candidate, answers the portal's own
// routes from a sample member and sends no write (`./preview`).
startThemePreview();
// Anywhere else, the community's stored theme, sign-in page included.
if (!isThemePreview()) void applyStoredCommunityTheme();

/** The preview bar's switch between the portal's two faces. */
function PreviewViewSwitch() {
  const view = previewView();
  return (
    <>
      <button type="button" aria-pressed={view === "home"} onClick={() => setPreviewView("home")}>
        Signed in
      </button>
      <button type="button" aria-pressed={view === "sign-in"} onClick={() => setPreviewView("sign-in")}>
        Sign-in page
      </button>
    </>
  );
}

const queryClient = new QueryClient({
  defaultOptions: {
    queries: { staleTime: 10_000, refetchOnWindowFocus: false, retry: false },
  },
});

const root = document.getElementById("root");
if (!root) throw new Error("member portal: #root missing");

createRoot(root).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      {isThemePreview() && <ThemePreviewBar controls={<PreviewViewSwitch />} />}
      <Portal />
    </QueryClientProvider>
  </StrictMode>,
);
