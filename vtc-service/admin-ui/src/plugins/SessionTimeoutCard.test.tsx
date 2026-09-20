import { fireEvent, screen, waitFor } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { SessionTimeoutCard } from "@/plugins/SessionTimeoutCard";
import { type MockRoute, mockFetch, renderWithProviders } from "@/test/render";

const KEY = "auth.admin_idle_timeout";

const config = (value: number, source: string): MockRoute => ({
  path: "/v1/admin/config",
  body: {
    fields: [
      { key: "log.level", value: "info", source: "default", requiresRestart: false },
      { key: KEY, value, source, requiresRestart: false },
    ],
  },
});

const patchRoute: MockRoute = {
  method: "PATCH",
  path: "/v1/admin/config",
  body: { applied: [KEY], pendingRestart: [], rejected: [] },
};

const reloadRoute: MockRoute = {
  method: "POST",
  path: "/v1/admin/config/reload",
  body: { keysReloaded: [KEY] },
};

describe("SessionTimeoutCard", () => {
  it("shows the running timeout", async () => {
    mockFetch([config(900, "default")]);
    renderWithProviders(<SessionTimeoutCard />);

    const select = (await screen.findByLabelText("Sign out after")) as HTMLSelectElement;
    expect(select.value).toBe("900");
  });

  it("saves, then reloads so the value actually takes effect", async () => {
    const requests = mockFetch([config(900, "default"), patchRoute, reloadRoute]);
    renderWithProviders(<SessionTimeoutCard />);

    const select = await screen.findByLabelText("Sign out after");
    fireEvent.change(select, { target: { value: "1800" } });
    fireEvent.click(screen.getByRole("button", { name: "Save timeout" }));

    await waitFor(() =>
      expect(requests.some((r) => r.method === "POST")).toBe(true),
    );

    const patch = requests.find((r) => r.method === "PATCH")!;
    expect(patch.body).toEqual({ overrides: { [KEY]: 1800 } });
    expect(patch.headers.get("Trust-Task")).toBe(
      "https://trusttasks.org/spec/config/patch/0.1",
    );

    // The reload is the half that matters: PATCH only writes the db-layer
    // override, so without it the daemon keeps running the old value and
    // the operator is told it worked.
    const reload = requests.find((r) => r.method === "POST")!;
    expect(reload.url).toBe("/v1/admin/config/reload");
  });

  it("will not offer to edit a value the environment pins", async () => {
    mockFetch([config(3600, "env")]);
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
      config(900, "default"),
      {
        method: "PATCH",
        path: "/v1/admin/config",
        body: {
          applied: [],
          pendingRestart: [],
          rejected: [
            {
              key: KEY,
              reason:
                "validation failed: auth.admin_idle_timeout must be between 60 and 86400 seconds, got 5",
            },
          ],
        },
      },
    ]);
    renderWithProviders(<SessionTimeoutCard />);

    const select = await screen.findByLabelText("Sign out after");
    fireEvent.change(select, { target: { value: "1800" } });
    fireEvent.click(screen.getByRole("button", { name: "Save timeout" }));

    expect(await screen.findByText(/between 60 and 86400/)).toBeTruthy();
  });

  it("keeps Save inert until something changes", async () => {
    mockFetch([config(900, "default")]);
    renderWithProviders(<SessionTimeoutCard />);

    const save = await screen.findByRole("button", { name: "Save timeout" });
    expect(save.hasAttribute("disabled")).toBe(true);
  });
});
