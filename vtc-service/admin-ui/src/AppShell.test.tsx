// The console shell: the top bar with the community's name, the grouped
// sidebar, the account menu (the operator's own settings, the theme and sign
// out) and the signing-key expiry item in the attention strip.

import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";

import type { WhoamiResponse } from "@/lib/api";

const ME = "did:key:z6MkAdminShellTestXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";
const WHOAMI: WhoamiResponse = {
  session: { id: "s", subject: ME, issuedAt: "2026-10-02T10:00:00Z", expiresAt: "2099-01-01T00:00:00Z" },
  roles: ["admin"],
  scopes: [],
};

const state = vi.hoisted(() => ({ renewSoon: true, signedOut: 0 }));

vi.mock("@/lib/api", async (original) => ({
  ...(await original<typeof import("@/lib/api")>()),
  probeSession: vi.fn(async () => WHOAMI),
  watchSession: () => () => undefined,
  signOut: vi.fn(async () => {
    state.signedOut += 1;
  }),
  postSignedRead: vi.fn(async () => ({
    actions: [],
    counts: { waitingForMe: 0, requestedByMe: 0 },
    ext: { "org.openvtc": {} },
    items: [],
    entries: [],
    truncated: false,
    branding: {},
  })),
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
    renewSoon: state.renewSoon,
    durability: "persistent",
  })),
}));
vi.mock("@/lib/plugin-loader", () => ({ reloadThirdPartyPlugins: vi.fn(async () => []) }));

import App from "@/App";
import { ConfirmDialogProvider } from "@/components/ConfirmDialog";
import { ToastProvider } from "@/lib/toast";
import { registerPlugin } from "@/plugin-api";

beforeAll(() => {
  registerPlugin({
    id: "home",
    label: "Dashboard",
    path: "/",
    group: "overview",
    reactComponent: () => <p>home</p>,
  });
  registerPlugin({
    id: "ceremonies",
    label: "Policies",
    path: "/ceremonies",
    group: "governance",
    reactComponent: () => <p>policies page</p>,
  });
  registerPlugin({
    id: "my-passkeys",
    label: "My passkeys",
    path: "/my-passkeys",
    group: "account",
    reactComponent: () => <p>passkeys page</p>,
  });
  registerPlugin({
    id: "console-keys",
    label: "Signing keys",
    path: "/console-keys",
    group: "account",
    reactComponent: () => <p>signing keys page</p>,
  });
  registerPlugin({
    id: "old-tool",
    label: "Old tool",
    path: "/old-tool",
    reactComponent: () => <p>old tool page</p>,
  });
});

beforeEach(() => {
  state.renewSoon = true;
  state.signedOut = 0;
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string) =>
      url === "/v1/community/public-profile"
        ? new Response(JSON.stringify({ name: "Harbour Makers", logoUrl: null }), {
            headers: { "Content-Type": "application/json" },
          })
        : new Response("{}", { status: 404 }),
    ),
  );
});
afterEach(() => {
  document.documentElement.removeAttribute("data-theme");
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

describe("the top bar", () => {
  it("names the community from its public profile, beside the Operator console pill", async () => {
    shell();
    expect(await screen.findByText("Harbour Makers")).toBeTruthy();
    expect(screen.getByText("Operator console")).toBeTruthy();
  });

  it("falls back to a neutral name when the profile cannot be read", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response("", { status: 404 })));
    shell();
    expect(await screen.findByText("Verifiable Trust Community")).toBeTruthy();
  });
});

describe("the grouped sidebar", () => {
  it("lists entries under their group headings, ungrouped ones under More", async () => {
    shell();
    const nav = await screen.findByRole("complementary", { name: "Console navigation" });
    const governance = within(nav).getByRole("list", { name: "Governance" });
    expect(within(governance).getByRole("link", { name: "Policies" }).getAttribute("href")).toBe(
      "/ceremonies",
    );
    const more = within(nav).getByRole("list", { name: "More" });
    expect(within(more).getByRole("link", { name: "Old tool" })).toBeTruthy();
    // Groups with nothing in them are not shown.
    expect(within(nav).queryByText("Membership")).toBeNull();
    // The operator's own settings are not in the sidebar.
    expect(within(nav).queryByRole("link", { name: /My passkeys/ })).toBeNull();
    expect(within(nav).queryByRole("link", { name: /Signing keys/ })).toBeNull();
  });

  it("keeps the collapse control and its stored setting", async () => {
    // An in-memory Storage, so the test does not depend on the runtime's own
    // (Node 25+ shadows jsdom's with one that needs a backing file).
    const store = new Map<string, string>();
    vi.stubGlobal("localStorage", {
      getItem: (k: string) => store.get(k) ?? null,
      setItem: (k: string, v: string) => void store.set(k, String(v)),
      removeItem: (k: string) => void store.delete(k),
      clear: () => store.clear(),
      key: (i: number) => [...store.keys()][i] ?? null,
      get length() {
        return store.size;
      },
    });
    localStorage.setItem("vtc-admin-nav-collapsed", "1");
    shell();
    const expand = await screen.findByRole("button", { name: "Expand navigation" });
    fireEvent.click(expand);
    expect(localStorage.getItem("vtc-admin-nav-collapsed")).toBe("0");
    expect(screen.getByRole("button", { name: "Collapse navigation" })).toBeTruthy();
  });
});

describe("the account menu", () => {
  it("holds My passkeys, Signing keys, the theme and Sign out", async () => {
    shell();
    const trigger = await screen.findByRole("button", { name: /^Account:/ });
    expect(trigger.getAttribute("aria-expanded")).toBe("false");
    fireEvent.click(trigger);
    expect(trigger.getAttribute("aria-expanded")).toBe("true");

    const panel = document.getElementById(trigger.getAttribute("aria-controls")!)!;
    expect(within(panel).getByText("Signed in as")).toBeTruthy();
    expect(within(panel).getByRole("link", { name: "My passkeys" }).getAttribute("href")).toBe(
      "/my-passkeys",
    );
    expect(
      within(panel).getByRole("link", { name: /Signing keys/ }).getAttribute("href"),
    ).toBe("/console-keys");
    // The expiring key is flagged on its entry too.
    expect(within(panel).getByText("Renew soon")).toBeTruthy();

    fireEvent.click(within(panel).getByRole("button", { name: "Dark" }));
    expect(document.documentElement.getAttribute("data-theme")).toBe("dark");

    fireEvent.click(within(panel).getByRole("button", { name: "Sign out" }));
    await waitFor(() => expect(state.signedOut).toBe(1));
  });

  it("closes on Escape and returns focus to its button", async () => {
    shell();
    const trigger = await screen.findByRole("button", { name: /^Account:/ });
    fireEvent.click(trigger);
    fireEvent.keyDown(document, { key: "Escape" });
    expect(trigger.getAttribute("aria-expanded")).toBe("false");
    expect(document.activeElement).toBe(trigger);
  });

  it("routes My passkeys and Signing keys where they always were", async () => {
    shell("/my-passkeys");
    expect(await screen.findByText("passkeys page")).toBeTruthy();
  });
});

describe("the signing key's expiry", () => {
  it("is an item in the attention strip with its Renew link", async () => {
    shell();
    const text = await screen.findByText("This browser's signing key expires soon.");
    const item = text.closest('[role="status"]') as HTMLElement;
    expect(item.closest('[data-testid="attention-strip"]')).toBeTruthy();
    expect(item.textContent).toContain(
      "Renew it now — one passkey confirmation — so the console keeps working.",
    );
    expect(within(item).getByRole("link", { name: "Renew" }).getAttribute("href")).toBe(
      "/console-keys",
    );
  });

  it("is not shown on the Signing keys page itself", async () => {
    shell("/console-keys");
    expect(await screen.findByText("signing keys page")).toBeTruthy();
    expect(screen.queryByText("This browser's signing key expires soon.")).toBeNull();
  });

  it("is not shown when the key is not close to expiry", async () => {
    state.renewSoon = false;
    shell();
    await screen.findByText("home");
    expect(screen.queryByText("This browser's signing key expires soon.")).toBeNull();
  });
});
