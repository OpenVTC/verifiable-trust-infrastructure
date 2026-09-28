import { fireEvent, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { SessionTimeoutCard } from "@/plugins/SessionTimeoutCard";
import {
  type MockRoute,
  mockFetch,
  renderWithProviders,
  sentPayloads,
  taskRoute,
} from "@/test/render";

import {
  forgetConsoleKey,
  generateConsoleKey,
  resetConsoleKeyCacheForTests,
} from "@/lib/console-key";

// Every config document is signed, by a real console key here: the fetchers
// live in `lib/api.ts` beside the signing, so there is no seam to stand in at.
beforeEach(async () => {
  await generateConsoleKey();
});
afterEach(async () => {
  await forgetConsoleKey();
  resetConsoleKeyCacheForTests();
});

/** The community DID the documents are addressed to. */
const HEALTH: MockRoute = {
  path: "/health",
  body: { status: "ok", version: "t", vtc_did: "did:webvh:QmScid:community.example:vtc" },
};

const KEY = "auth.admin_idle_timeout";
const SHOW = "https://trusttasks.org/spec/config/show/0.1";
const PATCH = "https://trusttasks.org/spec/config/patch/0.1";
const RELOAD = "https://trusttasks.org/spec/config/reload/0.1";

const config = (value: number, source: string): MockRoute =>
  taskRoute(SHOW, {
    fields: [
      { key: "log.level", value: "info", source: "default", requiresRestart: false },
      { key: KEY, value, source, requiresRestart: false },
    ],
  });

const patchRoute: MockRoute = taskRoute(PATCH, {
  applied: [KEY],
  pendingRestart: [],
  rejected: [],
});

const reloadRoute: MockRoute = taskRoute(RELOAD, { keysReloaded: [KEY] });

describe("SessionTimeoutCard", () => {
  it("shows the running timeout", async () => {
    mockFetch([
      HEALTH,config(900, "default")]);
    renderWithProviders(<SessionTimeoutCard />);

    const select = (await screen.findByLabelText("Sign out after")) as HTMLSelectElement;
    expect(select.value).toBe("900");
  });

  it("saves, then reloads so the value actually takes effect", async () => {
    const requests = mockFetch([
      HEALTH,config(900, "default"), patchRoute, reloadRoute]);
    renderWithProviders(<SessionTimeoutCard />);

    const select = await screen.findByLabelText("Sign out after");
    fireEvent.change(select, { target: { value: "1800" } });
    fireEvent.click(screen.getByRole("button", { name: "Save timeout" }));

    await waitFor(() => expect(sentPayloads(requests, RELOAD)).toHaveLength(1));

    expect(sentPayloads(requests, PATCH)).toEqual([{ overrides: { [KEY]: 1800 } }]);
    // The reload is the half that matters: `config/patch` only writes the
    // db-layer override, so without it the daemon keeps running the old value
    // and the operator is told it worked.
    expect(sentPayloads(requests, RELOAD)).toEqual([{}]);
  });

  it("will not offer to edit a value the environment pins", async () => {
    mockFetch([
      HEALTH,config(3600, "env")]);
    renderWithProviders(<SessionTimeoutCard />);

    expect(
      await screen.findByText(/Set by the environment/),
    ).toBeTruthy();
    // An env override outranks the db layer a PATCH writes, so a control
    // here would be one whose Save silently did nothing.
    expect(screen.queryByRole("button", { name: "Save timeout" })).toBeNull();
    expect(screen.getByText(/VTC_AUTH_ADMIN_IDLE_TIMEOUT/)).toBeTruthy();
  });

  it("surfaces a value the daemon refused", async () => {
    mockFetch([
      HEALTH,
      config(900, "default"),
      taskRoute(PATCH, {
        applied: [],
        pendingRestart: [],
        rejected: [
          {
            key: KEY,
            reason:
              "validation failed: auth.admin_idle_timeout must be between 60 and 86400 seconds, got 5",
          },
        ],
      }),
    ]);
    renderWithProviders(<SessionTimeoutCard />);

    const select = await screen.findByLabelText("Sign out after");
    fireEvent.change(select, { target: { value: "1800" } });
    fireEvent.click(screen.getByRole("button", { name: "Save timeout" }));

    expect(await screen.findByText(/between 60 and 86400/)).toBeTruthy();
  });

  it("keeps Save inert until something changes", async () => {
    mockFetch([
      HEALTH,config(900, "default")]);
    renderWithProviders(<SessionTimeoutCard />);

    const save = await screen.findByRole("button", { name: "Save timeout" });
    expect(save.hasAttribute("disabled")).toBe(true);
  });
});
