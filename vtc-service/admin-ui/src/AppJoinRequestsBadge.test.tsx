// The Join requests nav badge: the number of join requests awaiting an
// administrator's decision, beside the nav entry, for a viewer who may decide
// them — refreshed at sign-in, on focus and every 60 s, like the Actions badge.

import { act, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";

import type { WhoamiResponse } from "@/lib/api";

const ME = "did:key:z6MkAdmin";
const JOINS = "https://trusttasks.org/spec/vtc/join-requests/list/0.1";

const reads = vi.hoisted(() => ({
  /** Pending requests per page; each page but the last carries a cursor. */
  pages: [[]] as { id: string; status: string }[][],
  capabilities: ["vtc.join.decide"] as string[],
  calls: [] as [string, Record<string, unknown>][],
}));

function whoami(): WhoamiResponse {
  return {
    session: { id: "s", subject: ME, issuedAt: "2026-10-02T10:00:00Z", expiresAt: "2099-01-01T00:00:00Z" },
    roles: ["admin"],
    scopes: [],
    capabilities: reads.capabilities,
  } as WhoamiResponse;
}

vi.mock("@/lib/api", async (original) => ({
  ...(await original<typeof import("@/lib/api")>()),
  probeSession: vi.fn(async () => whoami()),
  watchSession: () => () => undefined,
  postSignedRead: vi.fn(async (type: string, payload: Record<string, unknown>) => {
    reads.calls.push([type, payload]);
    if (type === JOINS) {
      const index = payload.cursor ? Number(payload.cursor) : 0;
      const last = index === reads.pages.length - 1;
      return { items: reads.pages[index] ?? [], nextCursor: last ? null : String(index + 1) };
    }
    return {
      actions: [],
      counts: { waitingForMe: 0, requestedByMe: 0 },
      ext: { "org.openvtc": {} },
      items: [],
    };
  }),
}));
vi.mock("@/lib/console-keys-api", async (original) => ({
  ...(await original<typeof import("@/lib/console-keys-api")>()),
  signingStatus: vi.fn(async () => ({
    state: "ready",
    key: {
      consoleDid: "did:key:z6MkConsole",
      adminDid: ME,
      label: null,
      createdAt: "2026-10-01T00:00:00Z",
      expiresAt: "2099-01-01T00:00:00Z",
      lastUsedAt: null,
      revokedAt: null,
      active: true,
    },
    renewSoon: false,
    durability: "persistent",
  })),
}));
vi.mock("@/lib/plugin-loader", () => ({ reloadThirdPartyPlugins: vi.fn(async () => []) }));

import App from "@/App";
import { ConfirmDialogProvider } from "@/components/ConfirmDialog";
import { WAITING_POLL_MS } from "@/lib/action-badge";
import { ToastProvider } from "@/lib/toast";
import { registerPlugin } from "@/plugin-api";

beforeAll(() => {
  registerPlugin({ id: "home", label: "Home", path: "/", reactComponent: () => <p>home</p> });
  registerPlugin({
    id: "join-requests",
    label: "Join requests",
    path: "/join-requests",
    reactComponent: () => <p>join requests page</p>,
    capabilities: ["vtc.join.decide"],
  });
});

const pending = (n: number, from = 0) =>
  Array.from({ length: n }, (_, i) => ({ id: `r${from + i}`, status: "pending" }));

beforeEach(() => {
  reads.pages = [pending(3)];
  reads.capabilities = ["vtc.join.decide"];
  reads.calls.length = 0;
});
afterEach(() => {
  vi.useRealTimers();
});

function shell() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <ToastProvider>
        <ConfirmDialogProvider>
          <MemoryRouter initialEntries={["/"]}>
            <App />
          </MemoryRouter>
        </ConfirmDialogProvider>
      </ToastProvider>
    </QueryClientProvider>,
  );
}

const joinCalls = () => reads.calls.filter(([t]) => t === JOINS);

describe("the Join requests badge", () => {
  it("shows how many join requests await a decision", async () => {
    shell();
    const nav = await screen.findByRole("link", { name: /Join requests/ });
    await waitFor(() => expect(within(nav).getByLabelText("3 pending")).toBeTruthy());
    expect(within(nav).getByText("3")).toBeTruthy();
    expect(joinCalls()[0]).toEqual([JOINS, { status: "pending", limit: 200 }]);
  });

  it("counts every page, not just the first", async () => {
    // The VTC filters each page by status after reading it, so an early page
    // can come back with nothing pending and still carry a cursor.
    reads.pages = [pending(2), [], pending(4, 2)];
    shell();
    const nav = await screen.findByRole("link", { name: /Join requests/ });
    await waitFor(() => expect(within(nav).getByLabelText("6 pending")).toBeTruthy());
    expect(joinCalls().map(([, p]) => p.cursor)).toEqual([undefined, "1", "2"]);
  });

  it("is hidden when nothing awaits a decision", async () => {
    reads.pages = [[]];
    shell();
    const nav = await screen.findByRole("link", { name: /Join requests/ });
    await waitFor(() => expect(joinCalls().length).toBe(1));
    expect(within(nav).queryByLabelText(/pending/)).toBeNull();
  });

  it("is not fetched for a viewer who may not decide join requests", async () => {
    reads.capabilities = ["vtc.audit.read"];
    shell();
    await screen.findByRole("link", { name: /Home/ });
    // The entry itself is hidden, and the count is never read.
    expect(screen.queryByRole("link", { name: /Join requests/ })).toBeNull();
    await new Promise((r) => setTimeout(r, 20));
    expect(joinCalls()).toEqual([]);
  });

  it("follows the count when the tab regains focus", async () => {
    shell();
    const nav = await screen.findByRole("link", { name: /Join requests/ });
    await waitFor(() => expect(within(nav).getByLabelText("3 pending")).toBeTruthy());
    reads.pages = [[]];
    act(() => {
      window.dispatchEvent(new Event("focus"));
    });
    await waitFor(() => expect(within(nav).queryByLabelText(/pending/)).toBeNull());
  });

  it("is polled every minute", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    shell();
    const nav = await screen.findByRole("link", { name: /Join requests/ });
    await waitFor(() => expect(within(nav).getByLabelText("3 pending")).toBeTruthy());
    reads.pages = [pending(5)];
    await act(async () => {
      await vi.advanceTimersByTimeAsync(WAITING_POLL_MS);
    });
    await waitFor(() => expect(within(nav).getByLabelText("5 pending")).toBeTruthy());
  });
});
