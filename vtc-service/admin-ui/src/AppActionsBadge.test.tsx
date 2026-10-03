// The shell's view of the action list (§7.1): the Actions nav item carries the
// count waiting for you, a banner says so after sign-in until dismissed for the
// session, and the tab title is prefixed.

import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";

import type { WhoamiResponse } from "@/lib/api";

const ME = "did:key:z6MkAdmin";
const WHOAMI: WhoamiResponse = {
  session: { id: "s", subject: ME, issuedAt: "2026-10-02T10:00:00Z", expiresAt: "2099-01-01T00:00:00Z" },
  roles: ["admin"],
  scopes: [],
};
const LIST = "https://trusttasks.org/spec/vtc/admin/actions/list/0.1";

const reads = vi.hoisted(() => ({ waiting: 2, calls: [] as [string, unknown][] }));

vi.mock("@/lib/api", async (original) => ({
  ...(await original<typeof import("@/lib/api")>()),
  probeSession: vi.fn(async () => WHOAMI),
  watchSession: () => () => undefined,
  postSignedRead: vi.fn(async (type: string, payload: unknown) => {
    reads.calls.push([type, payload]);
    if (type === LIST) {
      return { actions: [], counts: { waitingForMe: reads.waiting, requestedByMe: 0 } };
    }
    return { items: [], entries: [], truncated: false, breakGlass: [], records: [] };
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
import { BANNER_DISMISSED_KEY } from "@/lib/action-badge";
import { ToastProvider } from "@/lib/toast";
import { registerPlugin } from "@/plugin-api";

beforeAll(() => {
  registerPlugin({ id: "home", label: "Home", path: "/", reactComponent: () => <p>home</p> });
  registerPlugin({
    id: "actions",
    label: "Actions",
    path: "/actions",
    reactComponent: () => <p>actions page</p>,
  });
});

beforeEach(() => {
  reads.waiting = 2;
  reads.calls.length = 0;
  sessionStorage.clear();
  document.title = "VTC Admin";
});
afterEach(() => {
  document.title = "VTC Admin";
});

function shell(route = "/") {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <ToastProvider>
        <ConfirmDialogProvider>
          <MemoryRouter initialEntries={[route]}>
            <App />
          </MemoryRouter>
        </ConfirmDialogProvider>
      </ToastProvider>
    </QueryClientProvider>,
  );
}

describe("the Actions badge", () => {
  it("shows the waiting count on the nav item, a banner, and the tab title", async () => {
    shell();
    const nav = await screen.findByRole("link", { name: /Actions/ });
    await waitFor(() => expect(within(nav).getByLabelText("2 waiting for you")).toBeTruthy());
    expect(screen.getByText("2 actions waiting for your approval.")).toBeTruthy();
    expect(document.title).toBe("(2) VTC Admin");
    expect(reads.calls).toContainEqual([LIST, { view: "waitingForMe", limit: 1 }]);
  });

  it("dismisses the banner for the session, but keeps the badge", async () => {
    shell();
    fireEvent.click(await screen.findByRole("button", { name: "Dismiss for this session" }));
    expect(screen.queryByText(/actions waiting for your approval/)).toBeNull();
    expect(sessionStorage.getItem(BANNER_DISMISSED_KEY)).toBe("1");
    const nav = screen.getByRole("link", { name: /Actions/ });
    expect(within(nav).getByLabelText("2 waiting for you")).toBeTruthy();
  });

  it("shows nothing when nothing waits", async () => {
    reads.waiting = 0;
    shell();
    await screen.findByRole("link", { name: /Actions/ });
    await waitFor(() => expect(reads.calls.some(([t]) => t === LIST)).toBe(true));
    expect(screen.queryByText(/waiting for your approval/)).toBeNull();
    expect(screen.queryByLabelText(/waiting for you/)).toBeNull();
    expect(document.title).toBe("VTC Admin");
  });
});
