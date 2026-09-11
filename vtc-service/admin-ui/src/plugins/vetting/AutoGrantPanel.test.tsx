import { fireEvent, screen, waitFor } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { AutoGrantPanel } from "@/plugins/vetting/AutoGrantPanel";
import { type MockRoute, mockFetch, renderWithProviders } from "@/test/render";

const STATUS = {
  enabled: false,
  sweepMinutes: 60,
  validitySeconds: 31_536_000,
  lastSweep: {
    ranAt: "2026-09-11T08:00:00Z",
    granted: 2,
    revoked: 1,
    errors: 1,
  },
};

const ROUTES: MockRoute[] = [
  { path: "/v1/vetting/auto-grant", body: STATUS },
  { path: "/v1/policies/active", body: { bindings: [] } },
  {
    method: "PUT",
    path: "/v1/vetting/auto-grant",
    body: ({ body }) => ({ ...(body as object), lastSweep: STATUS.lastSweep }),
  },
];

describe("AutoGrantPanel", () => {
  it("shows the last sweep and links to the eligibility policy editor", async () => {
    mockFetch(ROUTES);
    renderWithProviders(<AutoGrantPanel />);

    expect(await screen.findByText("2 members")).toBeTruthy();
    expect(screen.getByText("The sweep could not act on 1 member.")).toBeTruthy();
    expect(
      screen.getByRole("link", { name: "View or edit the policy" }).getAttribute("href"),
    ).toBe("/ceremonies?purpose=vetterEligibility");
    expect(await screen.findByText("No revision of this policy is active.")).toBeTruthy();
  });

  it("will not save an out-of-range sweep, then saves valid settings", async () => {
    const requests = mockFetch(ROUTES);
    renderWithProviders(<AutoGrantPanel />);

    const minutes = await screen.findByLabelText("Sweep every (minutes)");
    const save = screen.getByRole("button", { name: "Save settings" }) as HTMLButtonElement;
    expect(save.disabled).toBe(true);

    fireEvent.click(screen.getByRole("switch", { name: /Name vetters automatically/ }));
    fireEvent.change(minutes, { target: { value: "2" } });
    expect(
      screen.getByText("Choose 5 to 1440 minutes (a day); 2 is outside that."),
    ).toBeTruthy();
    expect(save.disabled).toBe(true);

    fireEvent.change(minutes, { target: { value: "30" } });
    expect(save.disabled).toBe(false);
    fireEvent.click(save);

    await waitFor(() => expect(requests.some((r) => r.method === "PUT")).toBe(true));
    const put = requests.find((r) => r.method === "PUT")!;
    expect(put.body).toEqual({
      enabled: true,
      sweepMinutes: 30,
      validitySeconds: 31_536_000,
    });
    expect(put.headers.get("Trust-Task")).toBeNull();
    expect(
      await screen.findByText(
        "Automatic grants are on. The sweep runs every 30 minutes.",
      ),
    ).toBeTruthy();
  });
});
