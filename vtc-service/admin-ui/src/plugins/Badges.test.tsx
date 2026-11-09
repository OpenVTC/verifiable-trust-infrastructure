// The console's Badges page: the badges an administrator may see, defining one, a badge given
// to chosen members and taken back with a reason, and the settings saved with their reason.

import { fireEvent, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import {
  AWARDS_LIST,
  AWARDS_OFFER,
  AWARDS_REVOKE,
  CREATE,
  HOLDERS_LIST,
  LIST,
  SETTINGS_SHOW,
  SETTINGS_UPDATE,
  SHOW,
  CLAIMS_CREATE,
  CLAIMS_LIST,
  CLAIMS_WITHDRAW,
} from "@/lib/badges";
import { GROUPS_LIST_TASK, GROUPS_REQUESTS_LIST_TASK, GROUPS_SHOW_TASK } from "@/lib/groups";
import { ROLES_LIST_TASK } from "@/lib/roles";
import { Badges } from "@/plugins/badges";
import { NAME_BOOK_ROUTES, mockFetch, renderWithProviders, sentPayloads, taskRoute, whoamiWith } from "@/test/render";

vi.mock("@/lib/api", async (original) => ({
  ...(await original<typeof import("@/lib/api")>()),
  postSignedRead: (await import("@/test/signed-read")).unsignedRead,
  postSignedTrustTask: (await import("@/test/signed-read")).unsignedTask,
  vtcDid: async () => COMMUNITY_DID,
}));

const COMMUNITY_DID = "did:webvh:QmCommunity:vtc.example.com";
const GROUP_DID = "did:webvh:QmGroup:vtc.example.com:note-manage";

// jsdom draws nothing on a canvas: the builder's drawing answers four PNG bytes.
vi.mock("@/components/BadgeBuilder", async (original) => {
  const m = await original<typeof import("@/components/BadgeBuilder")>();
  const { createElement } = await import("react");
  const draw = async () => new Blob([new Uint8Array([137, 80, 78, 71])], { type: "image/png" });
  return { ...m, BadgeBuilder: (p: Parameters<typeof m.BadgeBuilder>[0]) => createElement(m.BadgeBuilder, { ...p, draw }) };
});

const ENTRIES = "https://trusttasks.org/spec/vtc/directory/entries/list/0.2";
const BADGE_ID = "bdg_W5k2N8xRb3Qz7TpLAAAAAA";
const GROUP_ID = "grp_W5k2N8xRb3Qz7TpLAAAAAA";
const ENTRY = "dir_Q7m2K9xVb4Tz8LpRAAAAAA";
const OTHER = "dir_A1b2C3d4E5f6G7h8AAAAAA";
const SHA = "ab".repeat(32);

function badge(extra: object = {}) {
  return {
    badgeId: BADGE_ID,
    kind: "community",
    name: "Workshop host",
    description: "Ran a workshop for the community.",
    criteria: "Hosted any workshop on the calendar.",
    image: { sha256: SHA, mediaType: "image/jpeg", size: 1200 },
    repeatable: true,
    requestable: true,
    listed: true,
    groupId: GROUP_ID,
    state: "active",
    holderCount: 1,
    createdAt: "2026-11-01T09:00:00Z",
    ...extra,
  };
}

const SETTINGS = {
  enabled: true,
  kudosMakers: { policy: "members" },
  limits: { maxPinned: 2 },
  showKudosTotals: true,
  automaticBadges: false,
  membersMayRequest: true,
};

const ROUTES = [
  ...NAME_BOOK_ROUTES,
  taskRoute(ENTRIES, {
    items: [
      { entryId: ENTRY, fields: { displayName: "Carol Example" } },
      { entryId: OTHER, fields: { displayName: "Dev Patel" } },
    ],
  }),
  taskRoute(SETTINGS_SHOW, { settings: SETTINGS }),
  taskRoute(GROUPS_LIST_TASK, { items: [] }),
  taskRoute(ROLES_LIST_TASK, { roles: [] }),
];

describe("the Badges page", () => {
  it("lists the badges, with New badge for vtc.badges.admin and Settings for vtc.config.admin", async () => {
    mockFetch([...ROUTES, taskRoute(LIST, { items: [{ badge: badge(), myState: "none", myCount: 0 }] })]);
    renderWithProviders(<Badges />, {
      route: "/badges",
      path: "/badges/*",
      whoami: whoamiWith(["vtc.badges.admin", "vtc.config.admin"]),
    });
    expect(await screen.findByText("Workshop host")).toBeTruthy();
    expect(screen.getByText("Community badge")).toBeTruthy();
    expect(screen.getByRole("link", { name: /New badge/ })).toBeTruthy();
    expect(screen.getByRole("link", { name: /Settings/ })).toBeTruthy();
  });

  it("says when badges are off, and offers no new badge to an owner", async () => {
    mockFetch([
      ...ROUTES.filter((r) => r.task !== SETTINGS_SHOW),
      taskRoute(SETTINGS_SHOW, { settings: { ...SETTINGS, enabled: false } }),
      taskRoute(LIST, { items: [] }),
    ]);
    renderWithProviders(<Badges />, {
      route: "/badges",
      path: "/badges/*",
      whoami: whoamiWith([`vtc.groups.manage:group:${GROUP_ID}`]),
    });
    expect(await screen.findByText("Badges are off")).toBeTruthy();
    expect(await screen.findByText("No badges yet")).toBeTruthy();
    expect(screen.queryByRole("link", { name: /New badge/ })).toBeNull();
  });

  it("defines a community badge once a picture is uploaded", async () => {
    const UPLOAD = "https://trusttasks.org/spec/vtc/badges/images/upload/0.1";
    const requests = mockFetch([
      ...ROUTES,
      taskRoute(UPLOAD, { image: { sha256: SHA, mediaType: "image/png", size: 10 }, expiresAt: "2026-11-02T09:00:00Z" }),
      taskRoute(CREATE, { badge: badge({ name: "Meetup regular" }), group: {} }),
      taskRoute(SHOW, { badge: badge({ name: "Meetup regular" }), myState: "none", myCount: 0, credentialRegime: "inside", owners: [] }),
      taskRoute(LIST, { items: [] }),
    ]);
    vi.stubGlobal("URL", { ...URL, createObjectURL: () => "blob:x", revokeObjectURL: () => undefined });
    renderWithProviders(<Badges />, {
      route: "/badges/new",
      path: "/badges/*",
      whoami: whoamiWith(["vtc.badges.admin"]),
    });
    fireEvent.change(await screen.findByLabelText("Name"), { target: { value: "Meetup regular" } });
    fireEvent.change(screen.getByLabelText("What it is for"), { target: { value: "Came to five meetups." } });
    fireEvent.change(screen.getByLabelText("Why"), { target: { value: "the regulars" } });
    const png = new File([new Uint8Array([137, 80, 78, 71])], "b.png", { type: "image/png" });
    fireEvent.change(screen.getByLabelText("Choose a badge picture"), { target: { files: [png] } });
    await waitFor(() => expect(sentPayloads(requests, UPLOAD)).toHaveLength(1));
    fireEvent.click(screen.getByRole("button", { name: "Create badge" }));
    await waitFor(() =>
      expect(sentPayloads(requests, CREATE)).toEqual([
        expect.objectContaining({
          kind: "community",
          name: "Meetup regular",
          image: { sha256: SHA },
          requestable: true,
          listed: true,
          reason: "the regulars",
        }),
      ]),
    );
  });

  it("defines a badge with a picture built from a colour and an icon", async () => {
    const UPLOAD = "https://trusttasks.org/spec/vtc/badges/images/upload/0.1";
    const requests = mockFetch([
      ...ROUTES,
      taskRoute(UPLOAD, { image: { sha256: SHA, mediaType: "image/png", size: 4 }, expiresAt: "2026-11-02T09:00:00Z" }),
      taskRoute(CREATE, { badge: badge({ name: "Meetup regular" }), group: {} }),
      taskRoute(SHOW, { badge: badge({ name: "Meetup regular" }), myState: "none", myCount: 0, credentialRegime: "inside", owners: [] }),
      taskRoute(LIST, { items: [] }),
    ]);
    vi.stubGlobal("URL", { ...URL, createObjectURL: () => "blob:x", revokeObjectURL: () => undefined });
    renderWithProviders(<Badges />, {
      route: "/badges/new",
      path: "/badges/*",
      whoami: whoamiWith(["vtc.badges.admin"]),
    });
    fireEvent.change(await screen.findByLabelText("Name"), { target: { value: "Meetup regular" } });
    fireEvent.change(screen.getByLabelText("What it is for"), { target: { value: "Came to five meetups." } });
    fireEvent.change(screen.getByLabelText("Why"), { target: { value: "the regulars" } });
    fireEvent.click(screen.getByRole("button", { name: /Build one from a colour and an icon/ }));
    expect(screen.getByRole("img", { name: "Preview: Meetup regular" })).toBeTruthy();
    fireEvent.click(screen.getByLabelText("Green"));
    fireEvent.click(screen.getByRole("button", { name: "Use this picture" }));
    await waitFor(() =>
      expect(sentPayloads(requests, UPLOAD)).toEqual([{ mediaType: "image/png", data: "iVBORw" }]),
    );
    fireEvent.click(screen.getByRole("button", { name: "Create badge" }));
    await waitFor(() =>
      expect(sentPayloads(requests, CREATE)).toEqual([expect.objectContaining({ image: { sha256: SHA } })]),
    );
  });

  it("names the badge group's DID and the community's as the issuer, each to copy or scan", async () => {
    mockFetch([
      ...ROUTES,
      taskRoute(SHOW, { badge: badge(), myState: "none", myCount: 0, credentialRegime: "outside", owners: [] }),
      taskRoute(HOLDERS_LIST, { total: 0, items: [] }),
      taskRoute(GROUPS_SHOW_TASK, {
        group: { groupId: GROUP_ID, groupDid: GROUP_DID, name: "Workshop host", kind: "static", managers: [] },
        myMembership: "none",
      }),
      taskRoute(GROUPS_REQUESTS_LIST_TASK, { items: [] }),
      taskRoute(AWARDS_LIST, { items: [] }),
    ]);
    renderWithProviders(<Badges />, {
      route: `/badges/${BADGE_ID}`,
      path: "/badges/*",
      whoami: whoamiWith(["vtc.badges.admin"]),
    });
    expect(await screen.findByTitle(GROUP_DID)).toBeTruthy();
    expect(await screen.findByTitle(COMMUNITY_DID)).toBeTruthy();
    expect(screen.getByText("The community, also the badge’s creator")).toBeTruthy();
    expect(screen.getAllByRole("button", { name: "Copy DID" }).length).toBeGreaterThanOrEqual(2);
    expect(screen.getAllByRole("button", { name: "Show DID as QR code" }).length).toBeGreaterThanOrEqual(2);
  });

  it("offers a badge to chosen members, and takes an award back with a reason", async () => {
    const requests = mockFetch([
      ...ROUTES,
      taskRoute(SHOW, { badge: badge(), myState: "none", myCount: 0, credentialRegime: "inside", owners: [OTHER] }),
      taskRoute(HOLDERS_LIST, { total: 1, items: [{ entryId: ENTRY, count: 1, since: "2026-11-01T09:00:00Z", latestAt: "2026-11-01T09:00:00Z" }] }),
      taskRoute(GROUPS_SHOW_TASK, { group: { groupId: GROUP_ID, name: "Workshop host", kind: "static", managers: [OTHER] }, myMembership: "none" }),
      taskRoute(GROUPS_REQUESTS_LIST_TASK, { items: [] }),
      taskRoute(AWARDS_LIST, {
        items: [
          {
            award: { awardId: "awd_W5k2N8xRb3Qz7TpLAAAAAA", badgeId: BADGE_ID, entryId: ENTRY, state: "accepted", offeredAt: "2026-11-01T09:00:00Z", decidedAt: "2026-11-01T10:00:00Z", credentialId: "gcred_1" },
            hidden: false,
          },
        ],
      }),
      taskRoute(AWARDS_OFFER, { awards: [{ awardId: "awd_x", badgeId: BADGE_ID, entryId: OTHER, state: "offered", offeredAt: "2026-11-06T09:00:00Z" }], skipped: [] }),
      taskRoute(AWARDS_REVOKE, { award: { awardId: "awd_W5k2N8xRb3Qz7TpLAAAAAA", badgeId: BADGE_ID, entryId: ENTRY, state: "revoked", offeredAt: "2026-11-01T09:00:00Z" } }),
    ]);
    renderWithProviders(<Badges />, {
      route: `/badges/${BADGE_ID}`,
      path: "/badges/*",
      whoami: whoamiWith(["vtc.badges.admin"]),
    });
    expect(await screen.findByRole("heading", { level: 3, name: "Workshop host" })).toBeTruthy();
    // Give it to Dev.
    fireEvent.click(await screen.findByLabelText("Dev Patel"));
    fireEvent.change(screen.getByLabelText(/^For/), { target: { value: "Resin pour" } });
    fireEvent.click(screen.getByRole("button", { name: "Offer to 1 member" }));
    await waitFor(() =>
      expect(sentPayloads(requests, AWARDS_OFFER)).toEqual([{ badgeId: BADGE_ID, to: [OTHER], note: "Resin pour" }]),
    );
    // Take Carol's back.
    fireEvent.click(await screen.findByRole("button", { name: /Take back/ }));
    fireEvent.change(screen.getByLabelText("Why: Take the badge back"), { target: { value: "given in error" } });
    fireEvent.click(screen.getByRole("button", { name: "Take the badge back" }));
    await waitFor(() =>
      expect(sentPayloads(requests, AWARDS_REVOKE)).toEqual([{ awardId: "awd_W5k2N8xRb3Qz7TpLAAAAAA", reason: "given in error" }]),
    );
  });

  it("issues a claim code, shows it once, and withdraws one", async () => {
    const claim = { claimId: "bcl_T4nQ8mLw2Rx9Kv5Z", badgeId: BADGE_ID, label: "Saturday workshop", validUntil: "2026-12-01T18:00:00Z", limit: 40, claims: 3, state: "active", createdAt: "2026-11-08T09:00:00Z" };
    const requests = mockFetch([
      ...ROUTES,
      taskRoute(SHOW, { badge: badge(), myState: "none", myCount: 0, credentialRegime: "inside", owners: [OTHER] }),
      taskRoute(HOLDERS_LIST, { total: 0, items: [] }),
      taskRoute(GROUPS_SHOW_TASK, { group: { groupId: GROUP_ID, name: "Workshop host", kind: "static", managers: [OTHER] }, myMembership: "none" }),
      taskRoute(GROUPS_REQUESTS_LIST_TASK, { items: [] }),
      taskRoute(AWARDS_LIST, { items: [] }),
      taskRoute(CLAIMS_LIST, { items: [claim] }),
      taskRoute(CLAIMS_CREATE, { claim: { ...claim, claims: 0 }, code: "Qm7xV2kR9pLw4Nt8Hs3Fz6Bd1Yc5Je0Ua" }),
      taskRoute(CLAIMS_WITHDRAW, { claim: { ...claim, state: "withdrawn" } }),
    ]);
    renderWithProviders(<Badges />, {
      route: `/badges/${BADGE_ID}`,
      path: "/badges/*",
      whoami: whoamiWith(["vtc.badges.admin"]),
    });
    expect(await screen.findByText("3 of 40")).toBeTruthy();
    fireEvent.change(screen.getByLabelText("Claim code label"), { target: { value: "Sunday" } });
    fireEvent.change(screen.getByLabelText("Claim code until"), { target: { value: "2026-12-02T18:00" } });
    fireEvent.change(screen.getByLabelText("Claim code limit"), { target: { value: "12" } });
    fireEvent.click(screen.getByRole("button", { name: "Issue a code" }));
    expect(await screen.findByText("Qm7xV2kR9pLw4Nt8Hs3Fz6Bd1Yc5Je0Ua")).toBeTruthy();
    const sent = sentPayloads(requests, CLAIMS_CREATE) as { label: string; limit: number }[];
    expect(sent[0]).toMatchObject({ badgeId: BADGE_ID, label: "Sunday", limit: 12 });
    fireEvent.click(screen.getByRole("button", { name: "Withdraw" }));
    await waitFor(() => expect(sentPayloads(requests, CLAIMS_WITHDRAW)).toEqual([{ claimId: claim.claimId }]));
  });

  it("saves the settings with a reason, never sending what the community wrote", async () => {
    const requests = mockFetch([
      ...ROUTES.filter((r) => r.task !== SETTINGS_SHOW),
      taskRoute(SETTINGS_SHOW, { settings: { ...SETTINGS, updatedAt: "2026-11-01T09:00:00Z" } }),
      taskRoute(SETTINGS_UPDATE, { settings: { ...SETTINGS, enabled: false } }),
      taskRoute(LIST, { items: [] }),
    ]);
    renderWithProviders(<Badges />, {
      route: "/badges/settings",
      path: "/badges/*",
      whoami: whoamiWith(["vtc.config.admin"]),
    });
    fireEvent.click(await screen.findByRole("checkbox", { name: /Badges are on/ }));
    fireEvent.change(screen.getByLabelText("Why"), { target: { value: "season over" } });
    fireEvent.click(screen.getByRole("button", { name: "Save with step-up" }));
    await waitFor(() =>
      expect(sentPayloads(requests, SETTINGS_UPDATE)).toEqual([
        { settings: expect.objectContaining({ enabled: false, kudosMakers: { policy: "members" } }), reason: "season over" },
      ]),
    );
    expect(sentPayloads(requests, SETTINGS_UPDATE)[0]).not.toHaveProperty("settings.updatedAt");
  });
});
