// Where the community's group and room identities are published:
// `dids.webvh_server`, local or a hosting server at the VTA.

import { fireEvent, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { DidHostingCard } from "@/plugins/DidHostingCard";
import { renderWithProviders } from "@/test/render";

const saved: Record<string, unknown>[] = [];

vi.mock("@/lib/api", async (original) => ({
  ...(await original<typeof import("@/lib/api")>()),
  fetchEffectiveConfig: async () => ({
    fields: [{ key: "dids.webvh_server", value: null, source: "default" }],
  }),
}));
vi.mock("@/lib/config-api", async (original) => ({
  ...(await original<typeof import("@/lib/config-api")>()),
  saveConfig: async (patch: Record<string, unknown>) => {
    saved.push(patch);
    return { applied: Object.keys(patch), pendingRestart: [], rejected: [] };
  },
}));

describe("where identities are published", () => {
  it("saves a hosting server at the VTA, by its id", async () => {
    renderWithProviders(<DidHostingCard />);
    fireEvent.click(await screen.findByText("Where identities are published"));
    expect(await screen.findByText(/Not set here/)).toBeTruthy();
    fireEvent.click(screen.getByLabelText(/A hosting server at the community/));
    fireEvent.change(screen.getByPlaceholderText("e.g. hosting"), { target: { value: "hosting-eu" } });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(saved).toEqual([{ "dids.webvh_server": "hosting-eu" }]));
  });
});
