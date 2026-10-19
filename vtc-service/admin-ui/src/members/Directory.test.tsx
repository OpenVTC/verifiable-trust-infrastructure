// The portal's card editor and publication: saving never changes whether the
// card is published, and stopping publication is one narrowing write.

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

const api = vi.hoisted(() => ({
  showCard: vi.fn(),
  listFields: vi.fn(),
  updateCard: vi.fn(),
  getImage: vi.fn(),
  uploadImage: vi.fn(),
  listEntries: vi.fn(),
  showEntry: vi.fn(),
}));

vi.mock("./directory-api", async (orig) => ({
  ...(await orig<typeof import("./directory-api")>()),
  ...api,
}));

import { MyCardPage } from "./Directory";

const FIELDS = {
  fields: [
    {
      key: "displayName", label: "Name", type: "text", source: "member", base: true,
      required: true, ceiling: "public", defaultVisibility: "members", searchable: true,
      facet: false, order: 0, state: "active",
    },
    {
      key: "avatar", label: "Picture", type: "image", source: "member", base: true,
      required: false, ceiling: "public", defaultVisibility: "admins", searchable: false,
      facet: false, order: 20, state: "active",
    },
  ],
};

function card(external: { state: string; cardDigest?: string } | null) {
  return {
    card: {
      entryId: "dir_Q2xhcmFRMmxoY21GUk1t",
      values: { displayName: "Carol" },
      visibility: { displayName: "public" },
      discoverability: { listing: "listed", search: "byName", external: external !== null },
      introductions: "anyone",
      revision: 7,
      updatedAt: "2026-10-19T09:00:00Z",
      ...(external ? { externalCard: external } : {}),
    },
    missingRequired: [],
  };
}

function renderCard() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MyCardPage />
    </QueryClientProvider>,
  );
}

describe("the portal's card editor", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    api.listFields.mockResolvedValue(FIELDS);
  });

  it("keeps a published card published when the member saves", async () => {
    api.showCard.mockResolvedValue(card({ state: "published", cardDigest: "zQmExample" }));
    api.updateCard.mockResolvedValue(card({ state: "published", cardDigest: "zQmExample" }));
    renderCard();
    await screen.findByText(/published beyond the community/i);
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(api.updateCard).toHaveBeenCalled());
    expect(api.updateCard.mock.calls[0]![0].discoverability.external).toBe(true);
  });

  it("stops publishing as one narrowing write", async () => {
    api.showCard.mockResolvedValue(card({ state: "awaitingSignature" }));
    api.updateCard.mockResolvedValue(card(null));
    renderCard();
    await screen.findByText(/published card was withdrawn/i);
    fireEvent.click(screen.getByRole("button", { name: "Stop publishing" }));
    await waitFor(() => expect(api.updateCard).toHaveBeenCalled());
    expect(api.updateCard.mock.calls[0]![0]).toEqual({
      discoverability: { listing: "listed", search: "byName", external: false },
      expectedRevision: 7,
    });
  });

  it("offers a picture, and never offers to show anything to anyone from here", async () => {
    api.showCard.mockResolvedValue(card(null));
    renderCard();
    await screen.findByText(/seen only inside this community/i);
    expect(screen.getByLabelText("Choose Picture")).toBeTruthy();
    const who = screen.getByLabelText("Who sees Picture") as HTMLSelectElement;
    expect(Array.from(who.options).map((o) => o.value)).not.toContain("public");
  });
});
