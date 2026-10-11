// The command palette in the console shell: ⌘K / Ctrl+K or "Jump to…" opens
// it; it lists every screen the viewer can see — a plugin registered with no
// group included — and common actions; it is a keyboard-operable, focus-
// trapped combobox over a listbox; and it closes back to where focus was.

import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter, useLocation } from "react-router-dom";

import type { WhoamiResponse } from "@/lib/api";

const ME = "did:key:z6MkAdminPaletteTestXXXXXXXXXXXXXXXXXXXXXXXXXXXX";
const WHOAMI: WhoamiResponse = {
  session: { id: "s", subject: ME, issuedAt: "2026-10-02T10:00:00Z", expiresAt: "2099-01-01T00:00:00Z" },
  roles: ["admin"],
  scopes: [],
  capabilities: ["vtc.members.manage"],
};

const state = vi.hoisted(() => ({ signedOut: 0 }));

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
    renewSoon: false,
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
    id: "members",
    label: "Members",
    path: "/members",
    group: "membership",
    capabilities: ["vtc.members.manage"],
    reactComponent: () => <p>members page</p>,
  });
  registerPlugin({
    id: "acl",
    label: "Access control",
    path: "/acl",
    group: "governance",
    capabilities: ["vtc.acl.manage"],
    reactComponent: () => <p>acl page</p>,
  });
  registerPlugin({
    id: "my-passkeys",
    label: "My passkeys",
    path: "/my-passkeys",
    group: "account",
    reactComponent: () => <p>passkeys page</p>,
  });
  // A third-party plugin as written before groups existed: no `group`.
  registerPlugin({
    id: "weather",
    label: "Weather station",
    path: "/weather",
    reactComponent: () => <p>weather page</p>,
  });
});

beforeEach(() => {
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

function Where() {
  const loc = useLocation();
  return <output data-testid="where">{loc.pathname + loc.search}</output>;
}

function shell(route = "/") {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <ToastProvider>
        <ConfirmDialogProvider>
          <MemoryRouter initialEntries={[route]}>
            <App />
            <Where />
          </MemoryRouter>
        </ConfirmDialogProvider>
      </ToastProvider>
    </QueryClientProvider>,
  );
}

const where = () => screen.getByTestId("where").textContent;
const combobox = () => screen.getByRole("combobox", { name: "Jump to a screen or run an action" });
const optionLabels = () =>
  within(screen.getByRole("listbox")).getAllByRole("option").map(
    (o) => o.querySelector(".palette-option-label")?.textContent,
  );

async function openWithShortcut() {
  await screen.findByText("home");
  fireEvent.keyDown(document, { key: "k", ctrlKey: true });
  return screen.findByRole("dialog", { name: "Command palette" });
}

describe("the command palette", () => {
  it("opens on Ctrl+K and on ⌘K, and closes on the shortcut again", async () => {
    shell();
    const dialog = await openWithShortcut();
    expect(dialog.getAttribute("aria-modal")).toBe("true");
    expect(document.activeElement).toBe(combobox());
    fireEvent.keyDown(document, { key: "k", ctrlKey: true });
    expect(screen.queryByRole("dialog")).toBeNull();
    fireEvent.keyDown(document, { key: "k", metaKey: true });
    expect(await screen.findByRole("dialog", { name: "Command palette" })).toBeTruthy();
  });

  it("opens from the top bar's Jump to…, and gives focus back on Escape", async () => {
    shell();
    const trigger = await screen.findByRole("button", { name: /Jump to…/ });
    trigger.focus();
    fireEvent.click(trigger);
    expect(trigger.getAttribute("aria-expanded")).toBe("true");
    fireEvent.keyDown(combobox(), { key: "Escape" });
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(document.activeElement).toBe(trigger);
  });

  it("lists the screens the viewer can see — a plugin with no group too — and hides the rest", async () => {
    shell();
    await openWithShortcut();
    const screensGroup = screen.getByRole("group", { name: "Screens" });
    const names = within(screensGroup)
      .getAllByRole("option")
      .map((o) => o.querySelector(".palette-option-label")?.textContent);
    expect(names).toEqual(["Dashboard", "Members", "Weather station", "My passkeys"]);
    // Not visible to this viewer (no vtc.acl.manage), so not offered.
    expect(names).not.toContain("Access control");
    expect(screen.getByRole("group", { name: "Actions" })).toBeTruthy();
    expect(optionLabels()).toContain("Add a member");
    expect(optionLabels()).not.toContain("Add an access-control entry");
  });

  it("filters as you type, highlights the first result, and runs it on Enter", async () => {
    shell();
    await openWithShortcut();
    fireEvent.change(combobox(), { target: { value: "weath" } });
    expect(optionLabels()[0]).toBe("Weather station");
    const first = within(screen.getByRole("listbox")).getAllByRole("option")[0]!;
    expect(first.getAttribute("aria-selected")).toBe("true");
    expect(combobox().getAttribute("aria-activedescendant")).toBe(first.id);
    fireEvent.keyDown(combobox(), { key: "Enter" });
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(where()).toBe("/weather");
    expect(await screen.findByText("weather page")).toBeTruthy();
  });

  it("moves the highlight with the arrow keys, wrapping at the ends", async () => {
    shell();
    await openWithShortcut();
    const options = () => within(screen.getByRole("listbox")).getAllByRole("option");
    const selected = () => options().findIndex((o) => o.getAttribute("aria-selected") === "true");
    expect(selected()).toBe(0);
    fireEvent.keyDown(combobox(), { key: "ArrowDown" });
    expect(selected()).toBe(1);
    fireEvent.keyDown(combobox(), { key: "ArrowUp" });
    fireEvent.keyDown(combobox(), { key: "ArrowUp" });
    expect(selected()).toBe(options().length - 1);
    fireEvent.keyDown(combobox(), { key: "Home" });
    expect(selected()).toBe(0);
    fireEvent.keyDown(combobox(), { key: "End" });
    expect(selected()).toBe(options().length - 1);
  });

  it("keeps focus on its input when Tab is pressed", async () => {
    shell();
    await openWithShortcut();
    const input = combobox();
    const tab = fireEvent.keyDown(input, { key: "Tab" });
    expect(tab).toBe(false); // default prevented
    const back = fireEvent.keyDown(input, { key: "Tab", shiftKey: true });
    expect(back).toBe(false);
    expect(document.activeElement).toBe(input);
  });

  it("runs an action: navigating to Add a member, or switching the theme", async () => {
    shell();
    await openWithShortcut();
    fireEvent.change(combobox(), { target: { value: "add a member" } });
    fireEvent.click(screen.getByRole("option", { name: /Add a member/ }));
    expect(where()).toBe("/members?add=1");

    fireEvent.keyDown(document, { key: "k", ctrlKey: true });
    fireEvent.change(await screen.findByRole("combobox"), { target: { value: "dark theme" } });
    fireEvent.keyDown(combobox(), { key: "Enter" });
    expect(document.documentElement.getAttribute("data-theme")).toBe("dark");
  });

  it("searches the members for what was typed, or opens a DID", async () => {
    shell();
    await openWithShortcut();
    const did = "did:webvh:Qm1:example.org:ada";
    fireEvent.change(combobox(), { target: { value: did } });
    fireEvent.click(screen.getByRole("option", { name: new RegExp(`Open member`) }));
    expect(where()).toBe(`/members/${encodeURIComponent(did)}`);
  });

  it("signs out", async () => {
    shell();
    await openWithShortcut();
    fireEvent.change(combobox(), { target: { value: "sign out" } });
    fireEvent.keyDown(combobox(), { key: "Enter" });
    await waitFor(() => expect(state.signedOut).toBe(1));
  });

  it("offers only the member search when no screen or action matches", async () => {
    shell();
    await openWithShortcut();
    fireEvent.change(combobox(), { target: { value: "qqqqzz" } });
    expect(optionLabels()).toEqual(["Search members for “qqqqzz”"]);
    expect(screen.getByText("1 result")).toBeTruthy();
  });

  it("closes on a click outside it", async () => {
    shell();
    const dialog = await openWithShortcut();
    fireEvent.mouseDown(dialog.parentElement!);
    expect(screen.queryByRole("dialog")).toBeNull();
  });
});
