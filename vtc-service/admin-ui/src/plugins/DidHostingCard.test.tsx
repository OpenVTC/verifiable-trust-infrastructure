// Where the community's group and room identities are published:
// `dids.webvh_server`, local or a hosting server at the VTA — chosen from the
// servers the VTA lists (`vtc/config/did-hosting/list`), or typed when it cannot.

import { fireEvent, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { DidHostingCard } from "@/plugins/DidHostingCard";
import { renderWithProviders } from "@/test/render";

const saved: Record<string, unknown>[] = [];
let listing: () => Promise<unknown>;

vi.mock("@/lib/api", async (original) => ({
  ...(await original<typeof import("@/lib/api")>()),
  fetchEffectiveConfig: async () => ({
    fields: [{ key: "dids.webvh_server", value: null, source: "default" }],
  }),
  postSignedRead: () => listing(),
}));
vi.mock("@/lib/config-api", async (original) => ({
  ...(await original<typeof import("@/lib/config-api")>()),
  saveConfig: async (patch: Record<string, unknown>) => {
    saved.push(patch);
    return { applied: Object.keys(patch), pendingRestart: [], rejected: [] };
  },
}));

describe("where identities are published", () => {
  beforeEach(() => {
    saved.length = 0;
  });

  it("offers the hosting servers the VTA lists, and saves the one chosen", async () => {
    listing = async () => ({
      servers: [{ id: "hosting-eu", did: "did:webvh:QmHost:hosting.example.com", label: "EU hosting" }],
    });
    renderWithProviders(<DidHostingCard />);
    fireEvent.click(await screen.findByText("Where identities are published"));
    expect(await screen.findByText(/Not set here/)).toBeTruthy();
    fireEvent.click(screen.getByLabelText(/A hosting server at the community/));
    const select = await screen.findByRole("combobox");
    expect(screen.getByRole("option", { name: "EU hosting (hosting-eu)" })).toBeTruthy();
    fireEvent.change(select, { target: { value: "hosting-eu" } });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(saved).toEqual([{ "dids.webvh_server": "hosting-eu" }]));
  });

  it("takes a typed id when the VTA's servers cannot be listed", async () => {
    listing = async () => {
      throw new Error("the community's VTA did not answer");
    };
    renderWithProviders(<DidHostingCard />);
    fireEvent.click(await screen.findByText("Where identities are published"));
    await screen.findByText(/Not set here/);
    fireEvent.click(screen.getByLabelText(/A hosting server at the community/));
    expect(await screen.findByText(/could not be listed/)).toBeTruthy();
    fireEvent.change(screen.getByPlaceholderText("e.g. hosting"), { target: { value: "hosting-us" } });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(saved).toEqual([{ "dids.webvh_server": "hosting-us" }]));
  });
});
