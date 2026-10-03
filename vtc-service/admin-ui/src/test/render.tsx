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
import type { WhoamiResponse } from "@/lib/api";
import { ToastProvider } from "@/lib/toast";

export interface MockRoute {
  method?: string;
  /** Exact path (a query string is ignored), or a pattern over path + query. */
  path: string | RegExp;
  /** The status, or a function of the request that returns it. */
  status?: number | ((request: { url: string; body: unknown }) => number);
  /** The JSON answer, or a function of the request that returns it. */
  body?: object | ((request: { url: string; body: unknown }) => unknown);
  /** Match only a document of this `type` (for `POST /v1/trust-tasks`). */
  task?: string;
}

/**
 * `POST /v1/trust-tasks` answering documents of `task`: `answer` is the
 * `#response` payload, or a function of the request's payload returning it.
 * Pair with `vi.mock("@/lib/api", …)` installing `@/test/signed-read`, so the
 * console's signed calls reach this table without a key in the test browser.
 */
export function taskRoute(
  task: string,
  answer: object | ((payload: unknown) => unknown),
  status?: number,
): MockRoute {
  return {
    method: "POST",
    path: "/v1/trust-tasks",
    task,
    status,
    body: ({ body }) => ({
      payload:
        typeof answer === "function"
          ? answer((body as { payload?: unknown } | undefined)?.payload)
          : answer,
    }),
  };
}

/** The `payloads` of every document of `task` a test sent. */
export function sentPayloads(requests: RecordedRequest[], task: string): unknown[] {
  return requests
    .filter((r) => r.url === "/v1/trust-tasks" && (r.body as { type?: string })?.type === task)
    .map((r) => (r.body as { payload?: unknown }).payload);
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
            : r.path.test(url)) &&
          (r.task === undefined || (body as { type?: string } | undefined)?.type === r.task),
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
      const status =
        typeof route.status === "function" ? route.status({ url, body }) : route.status;
      return json(payload ?? {}, status ?? 200);
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

/** `vtc/members/list/0.1`, which the name book and the member pickers read. */
export const MEMBERS_LIST_TASK = "https://trusttasks.org/spec/vtc/members/list/0.1";

/** Members and ACL answers for `useNameBook`, which most panels call. */
export const NAME_BOOK_ROUTES: MockRoute[] = [
  taskRoute(MEMBERS_LIST_TASK, { items: [] }),
  taskRoute("https://trusttasks.org/spec/acl/list/0.2", { entries: [], truncated: false }),
];

/**
 * `path` is the route the component is mounted on, as the shell mounts a
 * plugin on `/<plugin>/*`; a component with descendant `<Routes>` needs it to
 * match its sections. `whoami` seeds the shell's session probe, as `App`
 * leaves it in the cache for the views it hosts.
 */
export function renderWithProviders(
  ui: ReactElement,
  {
    route = "/",
    path = "*",
    whoami,
  }: { route?: string; path?: string; whoami?: WhoamiResponse } = {},
) {
  const client = new QueryClient({
    defaultOptions: {
      queries: { retry: false, staleTime: 0 },
      mutations: { retry: false },
    },
  });
  if (whoami) client.setQueryData(["whoami"], whoami);
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
