// Rendering and fetch mocking for component tests.
//
// `renderWithProviders` wraps a component in what `main.tsx` gives the app —
// react-query, toasts, the confirmation dialog, a router — so a panel renders
// as it does in the console. `mockFetch` answers the console's requests from a
// table and records each one, so a test can assert what was sent: the method,
// the path, the body, the `Trust-Task` header.

import type { ReactElement } from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { vi } from "vitest";

import { ConfirmDialogProvider } from "@/components/ConfirmDialog";
import { ToastProvider } from "@/lib/toast";

export interface MockRoute {
  method?: string;
  /** Exact path (a query string is ignored), or a pattern over path + query. */
  path: string | RegExp;
  status?: number;
  /** The JSON answer, or a function of the request that returns it. */
  body?: object | ((request: { url: string; body: unknown }) => unknown);
}

export interface RecordedRequest {
  method: string;
  url: string;
  body: unknown;
  headers: Headers;
}

export function mockFetch(routes: MockRoute[]): RecordedRequest[] {
  const requests: RecordedRequest[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL, init: RequestInit = {}) => {
      const url =
        typeof input === "string"
          ? input
          : input instanceof URL
            ? input.href
            : input.url;
      const method = (init.method ?? "GET").toUpperCase();
      const body =
        typeof init.body === "string" ? (JSON.parse(init.body) as unknown) : undefined;
      requests.push({ method, url, body, headers: new Headers(init.headers) });

      const route = routes.find(
        (r) =>
          (r.method ?? "GET") === method &&
          (typeof r.path === "string"
            ? url.split("?")[0] === r.path
            : r.path.test(url)),
      );
      if (!route) {
        return json({ error: `no mock for ${method} ${url}` }, 404);
      }
      const payload =
        typeof route.body === "function"
          ? (route.body as (r: { url: string; body: unknown }) => unknown)({
              url,
              body,
            })
          : route.body;
      return json(payload ?? {}, route.status ?? 200);
    }),
  );
  return requests;
}

function json(body: unknown, status: number): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

/** Members and ACL answers for `useNameBook`, which most panels call. */
export const NAME_BOOK_ROUTES: MockRoute[] = [
  { path: "/v1/members", body: { items: [] } },
  { path: "/v1/acl", body: { entries: [], truncated: false } },
];

/**
 * `path` is the route the component is mounted on, as the shell mounts a
 * plugin on `/<plugin>/*`; a component with descendant `<Routes>` needs it to
 * match its sections.
 */
export function renderWithProviders(
  ui: ReactElement,
  { route = "/", path = "*" }: { route?: string; path?: string } = {},
) {
  const client = new QueryClient({
    defaultOptions: {
      queries: { retry: false, staleTime: 0 },
      mutations: { retry: false },
    },
  });
  return render(
    <QueryClientProvider client={client}>
      <ToastProvider>
        <ConfirmDialogProvider>
          <MemoryRouter initialEntries={[route]}>
            <Routes>
              <Route path={path} element={ui} />
            </Routes>
          </MemoryRouter>
        </ConfirmDialogProvider>
      </ToastProvider>
    </QueryClientProvider>,
  );
}
