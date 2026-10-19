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

vi.mock("./api", async (orig) => ({
  ...(await orig<typeof import("./api")>()),
  vtcDid: vi.fn(async () => "did:webvh:QmHost:acme.example"),
  memberFetch: vi.fn(async () => ({ did: "did:key:z6MkMember" })),
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

describe("show every field to", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("sets each field to the baseline, never wider than the field allows", async () => {
    const { baselineFor } = await import("./Directory");
    expect(baselineFor("members", "public")).toBe("members");
    expect(baselineFor("members", "admins")).toBe("admins");
    expect(baselineFor("groups", "members")).toBe("groups");
    expect(baselineFor("groups", "connections")).toBe("admins");
    expect(baselineFor("admins", "public")).toBe("admins");
  });

  it("applies the baseline as a starting point the member then saves", async () => {
    const fields = {
      fields: [
        ...FIELDS.fields,
        {
          key: "org.example.grade", label: "Grade", type: "text", source: "member", base: false,
          required: false, ceiling: "admins", defaultVisibility: "admins", searchable: false,
          facet: false, order: 60, state: "active",
        },
      ],
    };
    api.listFields.mockResolvedValue(fields);
    api.showCard.mockResolvedValue(card(null));
    api.updateCard.mockResolvedValue(card(null));
    renderCard();
    await screen.findByText(/seen only inside this community/i);
    expect(screen.getByRole("link", { name: /Directory/ }).getAttribute("href")).toBe("#/directory");

    fireEvent.change(screen.getByLabelText("Show every field to"), { target: { value: "members" } });
    fireEvent.click(screen.getByRole("button", { name: "Apply to every field" }));
    expect(screen.getByRole("status").textContent).toMatch(/except Grade/);
    // One field overridden after the baseline.
    fireEvent.change(screen.getByLabelText("Who sees Picture"), { target: { value: "admins" } });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(api.updateCard).toHaveBeenCalled());
    const sent = api.updateCard.mock.calls[0]![0].visibility;
    // The name was shown to anyone: the baseline narrows it. The picture was
    // set back to administrators by hand, its own default, so nothing changes
    // for it; the grade cannot go wider than administrators.
    expect(sent).toEqual({ displayName: "members" });
  });
});

describe("publishing from the portal", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    api.listFields.mockResolvedValue(FIELDS);
    delete (window as { vtaWallet?: unknown }).vtaWallet;
  });

  it("offers no publish button when the wallet has no directory channel", async () => {
    api.showCard.mockResolvedValue(card(null));
    renderCard();
    await screen.findByText(/seen only inside this community/i);
    expect(screen.queryByRole("button", { name: "Publish from your wallet" })).toBeNull();
  });

  it("asks the wallet to publish, naming the community and the signed-in member", async () => {
    const publishCard = vi.fn(async () => ({ state: "published" }));
    (window as { vtaWallet?: unknown }).vtaWallet = { directory: { publishCard } };
    api.showCard.mockResolvedValue(card(null));
    renderCard();
    fireEvent.click(await screen.findByRole("button", { name: "Publish from your wallet" }));
    await waitFor(() => expect(publishCard).toHaveBeenCalled());
    expect(publishCard).toHaveBeenCalledWith({
      hostDid: "did:webvh:QmHost:acme.example",
      member: "did:key:z6MkMember",
    });
  });

  it("offers to sign again when the published card was withdrawn", async () => {
    (window as { vtaWallet?: unknown }).vtaWallet = { directory: { publishCard: vi.fn() } };
    api.showCard.mockResolvedValue(card({ state: "awaitingSignature" }));
    renderCard();
    expect(await screen.findByRole("button", { name: "Sign again from your wallet" })).toBeTruthy();
  });
});
