// Entry point of the member portal bundle (`/members/`).
//
// A separate bundle from the console's, built by `vite.members.config.ts`: it
// imports nothing from the console shell, its plugins or its API client, so a
// member's browser never loads administrator code.

import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

import { Portal } from "./Portal";
import "./members.css";

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
      <Portal />
    </QueryClientProvider>
  </StrictMode>,
);
