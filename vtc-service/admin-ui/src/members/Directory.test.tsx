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

import { DirectoryPage, EntryPage, MyCardPage } from "./Directory";

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

describe("verifying a field with a credential", () => {
  const EMPLOYER = {
    key: "org.example.employer", label: "Employer", type: "claim", source: "credential", base: false,
    required: false, ceiling: "members", defaultVisibility: "members", searchable: false,
    facet: false, order: 40, state: "active",
    constraints: { claim: { credentialType: "EmploymentCredential", claimPath: "/employer" } },
  };

  beforeEach(() => {
    vi.clearAllMocks();
    api.listFields.mockResolvedValue({ fields: [...FIELDS.fields, EMPLOYER] });
    api.showCard.mockResolvedValue(card(null));
    delete (window as { vtaWallet?: unknown }).vtaWallet;
  });

  it("offers nothing when the wallet does not present credentials", async () => {
    (window as { vtaWallet?: unknown }).vtaWallet = { directory: { publishCard: vi.fn() } };
    renderCard();
    await screen.findByText(/filled when you present a credential/i);
    expect(screen.queryByRole("button", { name: "Verify with a credential" })).toBeNull();
  });

  it("asks the wallet to present for that one field, and re-reads the card", async () => {
    const presentCredential = vi.fn(async () => ({ verified: {}, revision: 8 }));
    (window as { vtaWallet?: unknown }).vtaWallet = { directory: { presentCredential } };
    renderCard();
    fireEvent.click(await screen.findByRole("button", { name: "Verify with a credential" }));
    await waitFor(() => expect(presentCredential).toHaveBeenCalled());
    expect(presentCredential).toHaveBeenCalledWith({
      hostDid: "did:webvh:QmHost:acme.example",
      member: "did:key:z6MkMember",
      fields: ["org.example.employer"],
    });
    expect(await screen.findByText("Verified from your credential.")).toBeTruthy();
    expect(api.showCard.mock.calls.length).toBeGreaterThan(1);
  });

  it("shows the wallet's sentence beside the field it refused", async () => {
    const presentCredential = vi.fn(async () => {
      throw new Error("Your wallet holds no EmploymentCredential.");
    });
    (window as { vtaWallet?: unknown }).vtaWallet = { directory: { presentCredential } };
    renderCard();
    fireEvent.click(await screen.findByRole("button", { name: "Verify with a credential" }));
    expect((await screen.findByRole("alert")).textContent).toBe("Your wallet holds no EmploymentCredential.");
  });
});

describe("browsing and reading members", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    api.listFields.mockResolvedValue(FIELDS);
  });

  it("folds away members who show no name, and shows them on request", async () => {
    api.listEntries.mockResolvedValue({
      items: [
        { entryId: "dir_aaaaaaaaaaaaaaaa", fields: { displayName: "Glenn Gore", role: "admin" } },
        { entryId: "dir_bbbbbbbbbbbbbbbb", fields: { role: "member" } },
        { entryId: "dir_cccccccccccccccc", fields: { role: "member" } },
      ],
    });
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(
      <QueryClientProvider client={qc}>
        <DirectoryPage />
      </QueryClientProvider>,
    );
    expect(await screen.findByText("Glenn Gore")).toBeTruthy();
    expect(screen.queryByText("A member")).toBeNull();
    const fold = screen.getByRole("button", { name: /2 members haven't added a name yet/ });
    fireEvent.click(fold);
    expect(screen.getAllByText("A member")).toHaveLength(2);
    expect(screen.getByRole("link", { name: "Portal" }).getAttribute("href")).toBe("#/");
  });

  it("draws a member's page: a false personhood is not shown, links are links, and it saves a contact", async () => {
    api.showEntry.mockResolvedValue({
      entry: {
        entryId: "dir_aaaaaaaaaaaaaaaa",
        fields: {
          displayName: "Glenn Gore",
          pronouns: "He/Him",
          bio: "CEO",
          links: ["https://affinidi.com"],
          personhood: false,
          role: "admin",
          did: "did:example:glenn",
        },
      },
    });
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(
      <QueryClientProvider client={qc}>
        <EntryPage entryId="dir_aaaaaaaaaaaaaaaa" />
      </QueryClientProvider>,
    );
    expect(await screen.findByRole("heading", { name: "Glenn Gore" })).toBeTruthy();
    expect(screen.queryByText(/Personhood/i)).toBeNull();
    expect(screen.queryByText("Verified person")).toBeNull();
    const link = screen.getByRole("link", { name: /affinidi\.com/ });
    expect(link.getAttribute("href")).toBe("https://affinidi.com/");
    expect(link.getAttribute("rel")).toContain("noopener");
    expect(screen.getByRole("button", { name: /Save contact/ })).toBeTruthy();
    expect(screen.getByRole("navigation", { name: "Breadcrumb" }).textContent).toContain("Directory");
    // Someone else's entry: nothing to edit.
    expect(screen.queryByRole("link", { name: /Edit my card/ })).toBeNull();
  });

  it("offers the member an edit of their own card from their own entry", async () => {
    api.showEntry.mockResolvedValue({
      entry: { entryId: "dir_aaaaaaaaaaaaaaaa", fields: { displayName: "Glenn Gore" } },
    });
    api.showCard.mockResolvedValue({ card: { entryId: "dir_aaaaaaaaaaaaaaaa", values: {} } });
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(
      <QueryClientProvider client={qc}>
        <EntryPage entryId="dir_aaaaaaaaaaaaaaaa" />
      </QueryClientProvider>,
    );
    const edit = await screen.findByRole("link", { name: /Edit my card/ });
    expect(edit.getAttribute("href")).toBe("#/card");
  });
});

describe("the member's own marks, from their wallet", () => {
  const marksApi = () => ({
    publishCard: vi.fn(),
    marks: vi.fn(async () => ({
      entries: { dir_bbbbbbbbbbbbbbbb: { starred: true, petname: "the route-setter", lists: ["L1"] } },
      lists: [{ listId: "L1", name: "Mentors", order: 0, contactCount: 1 }],
    })),
    mark: vi.fn(async (p: { starred?: boolean }) => ({ starred: p.starred ?? true })),
    putList: vi.fn(),
    deleteList: vi.fn(),
  });

  beforeEach(() => {
    vi.clearAllMocks();
    const store = new Map<string, string>();
    vi.stubGlobal("localStorage", {
      getItem: (k: string) => store.get(k) ?? null,
      setItem: (k: string, v: string) => void store.set(k, v),
      removeItem: (k: string) => void store.delete(k),
    });
    api.listFields.mockResolvedValue(FIELDS);
    api.listEntries.mockResolvedValue({
      items: [
        { entryId: "dir_aaaaaaaaaaaaaaaa", fields: { displayName: "Ada" } },
        { entryId: "dir_bbbbbbbbbbbbbbbb", fields: { displayName: "Sam" } },
      ],
    });
  });

  it("asks nothing until the member turns them on; then stars first, petnames marked as theirs, lists as filters", async () => {
    const wallet = marksApi();
    (window as { vtaWallet?: unknown }).vtaWallet = { directory: wallet };
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(
      <QueryClientProvider client={qc}>
        <DirectoryPage />
      </QueryClientProvider>,
    );
    expect(await screen.findByText("Ada")).toBeTruthy();
    expect(wallet.marks).not.toHaveBeenCalled();
    // The directory is asked the same thing either way.
    expect(api.listEntries).toHaveBeenCalledTimes(1);

    fireEvent.click(screen.getByRole("button", { name: /Show my stars and lists/ }));
    expect(await screen.findByText("Your name for them: the route-setter")).toBeTruthy();
    expect(wallet.marks).toHaveBeenCalledWith({ hostDid: "did:webvh:QmHost:acme.example", member: "did:key:z6MkMember" });
    const names = screen.getAllByText(/^(Ada|Sam)$/).map((n) => n.textContent);
    expect(names).toEqual(["Sam", "Ada"]);
    expect(api.listEntries).toHaveBeenCalledTimes(1);

    fireEvent.click(screen.getByRole("button", { name: "Mentors" }));
    await waitFor(() => expect(screen.queryByText("Ada")).toBeNull());
    expect(screen.getByText("Sam")).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: "Unstar Sam" }));
    await waitFor(() =>
      expect(wallet.mark).toHaveBeenCalledWith(
        expect.objectContaining({ entryId: "dir_bbbbbbbbbbbbbbbb", starred: false }),
      ),
    );
    expect(localStorage.getItem("vtc-member-marks")).toBe("1");
  });

  it("offers no marks where the wallet keeps none", async () => {
    (window as { vtaWallet?: unknown }).vtaWallet = { directory: { publishCard: vi.fn() } };
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(
      <QueryClientProvider client={qc}>
        <DirectoryPage />
      </QueryClientProvider>,
    );
    expect(await screen.findByText("Ada")).toBeTruthy();
    expect(screen.queryByRole("button", { name: /Show my stars and lists/ })).toBeNull();
  });
});
