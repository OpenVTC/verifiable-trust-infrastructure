import { screen, within } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { Vetting } from "@/plugins/vetting";
import { mockFetch, NAME_BOOK_ROUTES, renderWithProviders, taskRoute } from "@/test/render";

// Signed documents reach the fetch table unsigned; there is no console key here.
vi.mock("@/lib/api", async (original) => ({
  ...(await original<typeof import("@/lib/api")>()),
  postSignedRead: (await import("@/test/signed-read")).unsignedRead,
  postSignedTrustTask: (await import("@/test/signed-read")).unsignedTask,
}));

describe("Vetting plugin", () => {
  it("opens the section in the URL and marks its link as the current page", async () => {
    mockFetch([
      taskRoute("https://trusttasks.org/spec/vtc/vetting/revocations/list/0.1", { items: [] }),
      ...NAME_BOOK_ROUTES,
    ]);
    renderWithProviders(<Vetting />, {
      route: "/vetting/withdrawals",
      path: "/vetting/*",
    });

    expect(await screen.findByText("No vetter has withdrawn a statement")).toBeTruthy();
    const nav = screen.getByRole("navigation", { name: "Vetting sections" });
    expect(
      within(nav).getByRole("link", { name: "Withdrawals" }).getAttribute("aria-current"),
    ).toBe("page");
    expect(
      within(nav).getByRole("link", { name: "Vetters" }).getAttribute("aria-current"),
    ).toBeNull();
    expect(
      within(nav).getByRole("link", { name: "Registry preview" }).getAttribute("href"),
    ).toBe("/vetting/registry");
  });
});
