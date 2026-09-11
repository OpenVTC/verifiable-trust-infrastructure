import { screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { Vetting } from "@/plugins/vetting";
import { mockFetch, NAME_BOOK_ROUTES, renderWithProviders } from "@/test/render";

describe("Vetting plugin", () => {
  it("opens the section in the URL and marks its link as the current page", async () => {
    mockFetch([
      { path: "/v1/vetting/revocations", body: { revocations: [] } },
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
