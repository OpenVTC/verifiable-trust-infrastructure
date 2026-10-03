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
const LIST = "https://trusttasks.org/spec/vtc/admin/actions/list/0.2";

const reads = vi.hoisted(() => ({
  waiting: 2,
  calls: [] as [string, unknown][],
  ext: {} as Record<string, unknown>,
}));

vi.mock("@/lib/api", async (original) => ({
  ...(await original<typeof import("@/lib/api")>()),
  probeSession: vi.fn(async () => WHOAMI),
  watchSession: () => () => undefined,
  postSignedRead: vi.fn(async (type: string, payload: unknown) => {
    reads.calls.push([type, payload]);
    if (type === LIST) {
      return {
        actions: [],
        counts: { waitingForMe: reads.waiting, requestedByMe: 0 },
        ext: { "org.openvtc": reads.ext },
      };
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
  reads.ext = { operatorWritesUnacknowledged: [], coolingOffAgainstMe: [] };
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

// The two Critical banners (VTI-VTC-023, VTI-APV-019): read off the same
// list response's ext, and never dismissable — each clears only when what it
// reports does.
describe("the Critical action banners", () => {
  const REQUESTER = "did:key:z6MkRequesterBobYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY";
  const LANDS_AT = "2026-10-05T09:00:00Z";

  it("shows a non-dismissable banner while an operator write awaits acknowledgement", async () => {
    reads.ext = { operatorWritesUnacknowledged: ["ack-1"], coolingOffAgainstMe: [] };
    shell();
    const text = await screen.findByText(
      "The operator changed this community's access control offline. Acknowledge it in Actions.",
    );
    const banner = text.closest('[role="alert"]') as HTMLElement;
    expect(banner).toBeTruthy();
    expect(within(banner).queryByRole("button")).toBeNull();
    expect(within(banner).getByRole("link", { name: "Open Actions" }).getAttribute("href")).toBe(
      "/actions?action=ack-1",
    );
    // Dismissing the waiting-count banner leaves it in place.
    fireEvent.click(screen.getByRole("button", { name: "Dismiss for this session" }));
    expect(screen.getByText(/access control offline/)).toBeTruthy();
  });

  it("stays on the Actions page too", async () => {
    reads.ext = { operatorWritesUnacknowledged: ["ack-1", "ack-2"], coolingOffAgainstMe: [] };
    shell("/actions");
    expect(await screen.findByText(/access control offline/)).toBeTruthy();
    expect(screen.getByRole("link", { name: "Open Actions" }).getAttribute("href")).toBe(
      "/actions",
    );
  });

  it("shows a non-dismissable banner while a cooling-off reduces your authority", async () => {
    reads.ext = {
      operatorWritesUnacknowledged: [],
      coolingOffAgainstMe: [{ actionId: "cool-1", requester: REQUESTER, landsAt: LANDS_AT }],
    };
    shell();
    const text = await screen.findByText(/has asked to reduce your authority/);
    expect(text.textContent).toContain(
      `It takes effect at ${new Date(LANDS_AT).toLocaleString()} (`,
    );
    // With a countdown to it, as the action card shows.
    expect(text.textContent).toMatch(/\((lands in \d+ [dhm]( \d+ [hm])?|landing now)\) unless they cancel it\.$/);
    const banner = text.closest('[role="alert"]') as HTMLElement;
    expect(within(banner).queryByRole("button")).toBeNull();
    expect(
      within(banner).getByRole("link", { name: "View the action" }).getAttribute("href"),
    ).toBe("/actions?action=cool-1");
  });

  it("shows neither when the ext is empty", async () => {
    shell();
    await screen.findByText("2 actions waiting for your approval.");
    expect(screen.queryByText(/access control offline/)).toBeNull();
    expect(screen.queryByText(/reduce your authority/)).toBeNull();
  });
});

// Single-administrator mode (VTI-APV-022 item 3): reported to every
// administrator, on every page, for as long as it is in effect — and never
// dismissable.
describe("the single-administrator mode banner", () => {
  it("is shown on every page while the mode is in effect, with no way to dismiss it", async () => {
    reads.ext = { operatorWritesUnacknowledged: [], coolingOffAgainstMe: [], singleAdminMode: true };
    shell();
    const banner = await screen.findByRole("status", {
      name: "Single administrator mode is in effect",
    });
    expect(within(banner).getByText("SINGLE ADMIN MODE")).toBeTruthy();
    expect(banner.textContent).toContain(
      "Approvals are by your own step-up; another administrator's consent is not required.",
    );
    expect(within(banner).queryByRole("button")).toBeNull();
    // Dismissing the waiting-count banner leaves it in place.
    fireEvent.click(screen.getByRole("button", { name: "Dismiss for this session" }));
    expect(screen.getByText("SINGLE ADMIN MODE")).toBeTruthy();
  });

  it("stays on the Actions page too", async () => {
    reads.ext = { singleAdminMode: true };
    shell("/actions");
    expect(await screen.findByText("SINGLE ADMIN MODE")).toBeTruthy();
  });

  it("is not shown when the mode is off", async () => {
    reads.ext = { operatorWritesUnacknowledged: [], coolingOffAgainstMe: [], singleAdminMode: false };
    shell();
    await screen.findByText("2 actions waiting for your approval.");
    expect(screen.queryByText("SINGLE ADMIN MODE")).toBeNull();
  });

  it("is not shown when the daemon says nothing about it", async () => {
    shell();
    await screen.findByText("2 actions waiting for your approval.");
    expect(screen.queryByText("SINGLE ADMIN MODE")).toBeNull();
  });
});
