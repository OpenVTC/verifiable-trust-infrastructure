// How the community's group and room identities are presented:
// `dids.default_did_method` and `dids.scid_also_known_as` (VTI-VTC-004).

import { fireEvent, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { DidPresentationCard } from "@/plugins/DidPresentationCard";
import { renderWithProviders } from "@/test/render";

const saved: Record<string, unknown>[] = [];

vi.mock("@/lib/api", async (original) => ({
  ...(await original<typeof import("@/lib/api")>()),
  fetchEffectiveConfig: async () => ({
    fields: [
      { key: "dids.default_did_method", value: null, source: "default" },
      { key: "dids.scid_also_known_as", value: null, source: "default" },
    ],
  }),
}));
vi.mock("@/lib/config-api", async (original) => ({
  ...(await original<typeof import("@/lib/config-api")>()),
  saveConfig: async (patch: Record<string, unknown>) => {
    saved.push(patch);
    return { applied: Object.keys(patch), pendingRestart: [], rejected: [] };
  },
}));

describe("how identities are presented", () => {
  beforeEach(() => {
    saved.length = 0;
  });

  it("says the VTA decides when unset, and saves did:scid with its alias", async () => {
    renderWithProviders(<DidPresentationCard />);
    fireEvent.click(await screen.findByText("How identities are presented"));
    expect(await screen.findByText(/the community.s VTA decides/)).toBeTruthy();

    fireEvent.change(screen.getByLabelText("Give new identities out as"), {
      target: { value: "scid" },
    });
    // A did:scid always lists its alias, so the choice is not offered.
    const alias = screen.getByRole("checkbox") as HTMLInputElement;
    expect(alias.checked).toBe(true);
    expect(alias.disabled).toBe(true);

    fireEvent.click(screen.getByText("Save"));
    await waitFor(() =>
      expect(saved).toEqual([
        { "dids.default_did_method": "scid", "dids.scid_also_known_as": true },
      ]),
    );
  });

  it("saves did:webvh without the alias", async () => {
    renderWithProviders(<DidPresentationCard />);
    fireEvent.click(await screen.findByText("How identities are presented"));
    fireEvent.click(await screen.findByRole("checkbox"));
    fireEvent.click(screen.getByText("Save"));
    await waitFor(() =>
      expect(saved).toEqual([
        { "dids.default_did_method": "webvh", "dids.scid_also_known_as": false },
      ]),
    );
  });
});
