// The portal's Badges pages: offers accepted and declined, the wall arranged and a badge
// hidden, one badge with its holders and asking its owners for it, and badges off.
// Every read and write goes through this browser's portal key (`send`, mocked per task).

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { ConfirmDialogProvider } from "@/components/ConfirmDialog";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

const send = vi.fn();
vi.mock("./directory-api", async (orig) => ({
  ...(await orig<typeof import("./directory-api")>()),
  send: (...a: unknown[]) => send(...a),
}));

// jsdom draws nothing on a canvas: the builder's drawing answers four PNG bytes.
vi.mock("@/components/BadgeBuilder", async (original) => {
  const m = await original<typeof import("@/components/BadgeBuilder")>();
  const { createElement } = await import("react");
  const draw = async () => new Blob([new Uint8Array([137, 80, 78, 71])], { type: "image/png" });
  return { ...m, BadgeBuilder: (p: Parameters<typeof m.BadgeBuilder>[0]) => createElement(m.BadgeBuilder, { ...p, draw }) };
});

import { BadgePage, BadgesPage, MakeBadgePage, WallSection } from "./Badges";
import { earnedWords } from "./badge-card";
import {
  AWARDS_SHARE_TASK,
  AWARDS_UNSHARE_TASK,
  BADGES_CREATE_TASK,
  BADGES_IMAGES_UPLOAD_TASK,
  BADGES_HOLDERS_TASK,
  BADGES_IMAGES_GET_TASK,
  BADGES_LIST_TASK,
  BADGES_SETTINGS_TASK,
  BADGES_SHOW_TASK,
  BADGES_WALL_TASK,
  CLAIMS_REDEEM_TASK,
  MINE_ACCEPT_TASK,
  MINE_ARRANGE_TASK,
  MINE_DECLINE_TASK,
  MINE_HIDE_TASK,
  MINE_LIST_TASK,
} from "./badges-api";
import { GROUPS_JOIN_TASK } from "./groups-api";
import { badgesAttention, badgesStatus } from "./home-status";

const ENTRIES = "https://trusttasks.org/spec/vtc/directory/entries/list/0.2";
const BADGE_ID = "bdg_W5k2N8xRb3Qz7TpLAAAAAA";
const KUDOS_ID = "bdg_K1k2N8xRb3Qz7TpLAAAAAA";
const GROUP_ID = "grp_W5k2N8xRb3Qz7TpLAAAAAA";
const ENTRY = "dir_Q7m2K9xVb4Tz8LpRAAAAAA";
const SHA = "ab".repeat(32);

function badge(extra: object = {}) {
  return {
    badgeId: BADGE_ID,
    kind: "community",
    name: "Workshop host",
    description: "Ran a workshop for the community.",
    criteria: "Hosted any workshop on the calendar.",
    image: { sha256: SHA, mediaType: "image/jpeg" },
    repeatable: true,
    requestable: true,
    listed: true,
    groupId: GROUP_ID,
    state: "active",
    holderCount: 9,
    createdAt: "2026-06-02T09:00:00Z",
    ...extra,
  };
}

const KUDOS = badge({ badgeId: KUDOS_ID, kind: "kudos", name: "Clamp whisperer", groupId: undefined, requestable: undefined });

const SETTINGS = {
  enabled: true,
  kudosMakers: { policy: "members" },
  showKudosTotals: true,
  automaticBadges: false,
  membersMayRequest: true,
};

function mine(extra: object = {}) {
  return {
    badges: [
      { badge: KUDOS, count: 3, since: "2026-10-01T09:00:00Z", latestAt: "2026-11-01T09:00:00Z", pinned: false, hidden: false, position: 1 },
      { badge: badge({ badgeId: "bdg_H1k2N8xRb3Qz7TpLAAAAAA", name: "Year one" }), count: 1, since: "2026-10-01T09:00:00Z", pinned: true, hidden: false, position: 0 },
    ],
    offers: [
      {
        award: { awardId: "awd_W5k2N8xRb3Qz7TpLAAAAAA", badgeId: BADGE_ID, entryId: ENTRY, state: "offered", offeredAt: "2026-11-06T06:00:00Z", note: "Resin pour workshop" },
        badge: badge(),
        givenBy: { displayName: "Ben Okafor" },
      },
    ],
    visibility: "members",
    kudosTotal: 3,
    ...extra,
  };
}

function answer(table: Record<string, unknown | ((payload: unknown) => unknown)>) {
  send.mockImplementation(async (type: string, payload: unknown) => {
    if (!(type in table)) throw new Error(`unexpected ${type}`);
    const a = table[type];
    return typeof a === "function" ? (a as (p: unknown) => unknown)(payload) : a;
  });
}

function sent(type: string): unknown[] {
  return send.mock.calls.filter((c) => c[0] === type).map((c) => c[1]);
}

function renderPage(ui: React.ReactElement) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  return render(<QueryClientProvider client={qc}><ConfirmDialogProvider look="portal">{ui}</ConfirmDialogProvider></QueryClientProvider>);
}

const BASE = {
  [BADGES_SETTINGS_TASK]: { settings: SETTINGS },
  [BADGES_IMAGES_GET_TASK]: () => {
    throw new Error("no picture in this test");
  },
  [BADGES_LIST_TASK]: { items: [] },
};

afterEach(() => send.mockReset());

describe("the portal's badges page", () => {
  it("shows the offers waiting, and accepts one", async () => {
    answer({
      ...BASE,
      [MINE_LIST_TASK]: mine(),
      [MINE_ACCEPT_TASK]: { award: { awardId: "awd_W5k2N8xRb3Qz7TpLAAAAAA", state: "accepted", credentialId: "gc_1" }, badge: { badge: badge(), count: 1 } },
    });
    renderPage(<BadgesPage />);
    expect(await screen.findByText("Waiting for you")).toBeTruthy();
    expect(screen.getByText(/Given by Ben Okafor/)).toBeTruthy();
    expect(screen.getByText(/Resin pour workshop/)).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: /Accept/ }));
    await waitFor(() => expect(sent(MINE_ACCEPT_TASK)).toEqual([{ awardId: "awd_W5k2N8xRb3Qz7TpLAAAAAA" }]));
    expect(await screen.findByText(/Its credential is on its way to your wallet/)).toBeTruthy();
  });

  it("declines an offer, which tells no one", async () => {
    answer({ ...BASE, [MINE_LIST_TASK]: mine(), [MINE_DECLINE_TASK]: { award: { state: "declined" } } });
    renderPage(<BadgesPage />);
    fireEvent.click(await screen.findByRole("button", { name: /Decline/ }));
    // Declining is confirmed first (#2607); backing out sends nothing.
    fireEvent.click(await screen.findByRole("button", { name: "Cancel" }));
    expect(sent(MINE_DECLINE_TASK)).toEqual([]);
    fireEvent.click(screen.getByRole("button", { name: /Decline/ }));
    const dialog = await screen.findByRole("dialog");
    fireEvent.click(within(dialog).getByRole("button", { name: "Decline" }));
    await waitFor(() => expect(sent(MINE_DECLINE_TASK)).toEqual([{ awardId: "awd_W5k2N8xRb3Qz7TpLAAAAAA" }]));
    expect(await screen.findByText(/Declined. Nobody is told/)).toBeTruthy();
  });

  it("arranges the wall: pins, orders and hides, and says who sees it", async () => {
    answer({
      ...BASE,
      [MINE_LIST_TASK]: mine({ offers: [] }),
      [MINE_ARRANGE_TASK]: (p: unknown) => ({ badges: [], visibility: (p as { visibility?: string }).visibility ?? "members" }),
      [MINE_HIDE_TASK]: { badge: { badge: KUDOS, count: 3, hidden: true } },
    });
    renderPage(<BadgesPage />);
    expect(await screen.findByText("On your card")).toBeTruthy();
    expect(screen.getByText("×3")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Pin Clamp whisperer" }));
    await waitFor(() =>
      expect(sent(MINE_ARRANGE_TASK)).toEqual([{ pinned: ["bdg_H1k2N8xRb3Qz7TpLAAAAAA", KUDOS_ID] }]),
    );
    fireEvent.click(screen.getByRole("button", { name: "Move Clamp whisperer earlier" }));
    await waitFor(() =>
      expect(sent(MINE_ARRANGE_TASK)[1]).toEqual({ order: [KUDOS_ID, "bdg_H1k2N8xRb3Qz7TpLAAAAAA"] }),
    );
    fireEvent.change(screen.getByLabelText("Who sees your badges"), { target: { value: "nobody" } });
    await waitFor(() => expect(sent(MINE_ARRANGE_TASK)[2]).toEqual({ visibility: "nobody" }));
    fireEvent.click(screen.getByRole("button", { name: "Hide Clamp whisperer" }));
    await waitFor(() => expect(sent(MINE_HIDE_TASK)).toEqual([{ badgeId: KUDOS_ID }]));
    expect(await screen.findByText(/Hidden from your card/)).toBeTruthy();
  });

  it("claims a badge with an event's code, and says when a code admits no one", async () => {
    const { DirectoryError } = await import("./directory-api");
    let claimed = false;
    answer({
      ...BASE,
      [MINE_LIST_TASK]: () => mine(),
      [CLAIMS_REDEEM_TASK]: (p: unknown) => {
        if ((p as { code: string }).code !== "Qm7xV2kR9pLw4Nt8Hs3Fz6Bd1Yc5Je0Ua") {
          throw new DirectoryError("vtc/badges/claims/redeem:codeInvalid", "no");
        }
        claimed = true;
        return { award: { awardId: "awd_C7mT9pQx2Lw8Rv5NAAAA", badgeId: BADGE_ID, entryId: ENTRY, state: "accepted", offeredAt: "2026-11-08T11:30:00Z" } };
      },
    });
    renderPage(<BadgesPage />);
    const input = await screen.findByLabelText("Claim code");
    fireEvent.change(input, { target: { value: "nonsense-code-0000000000" } });
    fireEvent.click(screen.getByRole("button", { name: "Claim the badge" }));
    expect(await screen.findByText(/That code admits no one/)).toBeTruthy();
    fireEvent.change(input, { target: { value: "  Qm7xV2kR9pLw4Nt8Hs3Fz6Bd1Yc5Je0Ua " } });
    fireEvent.click(screen.getByRole("button", { name: "Claim the badge" }));
    expect(await screen.findByText(/Claimed. The badge is yours/)).toBeTruthy();
    expect(claimed).toBe(true);
    expect(sent(CLAIMS_REDEEM_TASK).at(-1)).toEqual({ code: "Qm7xV2kR9pLw4Nt8Hs3Fz6Bd1Yc5Je0Ua" });
  });

  it("shows nothing but a line when the community has badges off", async () => {
    answer({ ...BASE, [BADGES_SETTINGS_TASK]: { settings: { ...SETTINGS, enabled: false } }, [MINE_LIST_TASK]: mine() });
    renderPage(<BadgesPage />);
    expect(await screen.findByText("This community has badges turned off for now.")).toBeTruthy();
    expect(screen.queryByText("Waiting for you")).toBeNull();
  });
});

describe("a member's badges on their card", () => {
  const day = (iso: string) => new Date(iso).toLocaleDateString(undefined, { dateStyle: "medium" });

  it("says when each badge was earned, and since when for one held more than once", async () => {
    answer({
      ...BASE,
      [BADGES_WALL_TASK]: {
        entries: [
          { badge: KUDOS, count: 3, since: "2026-03-03T09:00:00Z", latestAt: "2026-11-01T09:00:00Z", pinned: true },
          { badge: badge(), count: 1, since: "2026-11-08T22:42:06Z", latestAt: "2026-11-08T22:42:06Z", pinned: false },
        ],
        visibility: "members",
      },
    });
    renderPage(<WallSection entryId={ENTRY} name="Carol" own />);
    expect(await screen.findByText(`Earned ${day("2026-11-08T22:42:06Z")}`)).toBeTruthy();
    const repeat = screen.getByText(`Since ${day("2026-03-03T09:00:00Z")}`);
    expect(repeat.getAttribute("title")).toBe(
      `First earned ${day("2026-03-03T09:00:00Z")}, most recently ${day("2026-11-01T09:00:00Z")}`,
    );
  });

  it("says nothing of a date the wall did not name", () => {
    expect(earnedWords(1, undefined, undefined)).toBeNull();
    expect(earnedWords(undefined, undefined, "2026-11-01T09:00:00Z")?.text.startsWith("Earned ")).toBe(true);
  });
});

describe("making a badge in the portal", () => {
  it("builds the picture from a colour and an icon, and makes a kudos badge with it", async () => {
    answer({
      ...BASE,
      [BADGES_IMAGES_UPLOAD_TASK]: { image: { sha256: SHA, mediaType: "image/png", size: 4 }, expiresAt: "2026-11-09T09:00:00Z" },
      [BADGES_CREATE_TASK]: { badge: KUDOS },
    });
    vi.stubGlobal("URL", { ...URL, createObjectURL: () => "blob:x", revokeObjectURL: () => undefined });
    renderPage(<MakeBadgePage />);
    fireEvent.change(screen.getByLabelText(/^Name/), { target: { value: "Clamp whisperer" } });
    fireEvent.change(screen.getByLabelText("What it is for"), { target: { value: "Fixed the clamps." } });
    fireEvent.click(screen.getByLabelText("Build one from a colour and an icon"));
    expect(screen.getByRole("img", { name: "Preview: Clamp whisperer" })).toBeTruthy();
    fireEvent.click(screen.getByLabelText("Tools"));
    fireEvent.click(screen.getByRole("button", { name: "Use this picture" }));
    await waitFor(() => expect(sent(BADGES_IMAGES_UPLOAD_TASK)).toEqual([{ mediaType: "image/png", data: "iVBORw" }]));
    // Back on the upload view, with the built picture shown and the builder closed.
    expect(screen.getByLabelText("Upload my own picture")).toHaveProperty("checked", true);
    fireEvent.click(screen.getByRole("button", { name: "Create badge" }));
    await waitFor(() =>
      expect(sent(BADGES_CREATE_TASK)).toEqual([
        { kind: "kudos", name: "Clamp whisperer", description: "Fixed the clamps.", image: { sha256: SHA }, reason: "made in the portal" },
      ]),
    );
    vi.unstubAllGlobals();
  });
});

describe("one badge in the portal", () => {
  it("shows who holds it, and asks its owners for it with a note", async () => {
    answer({
      ...BASE,
      [BADGES_SHOW_TASK]: { badge: badge(), myState: "none", myCount: 0, credentialRegime: "inside", owners: [ENTRY] },
      [BADGES_HOLDERS_TASK]: {
        total: 1,
        items: [{ entryId: ENTRY, count: 6, since: "2026-01-01T09:00:00Z", latestAt: "2026-10-18T09:00:00Z", fields: { displayName: "Priya Natarajan" } }],
      },
      [ENTRIES]: { items: [{ entryId: ENTRY, fields: { displayName: "Priya Natarajan" } }] },
      [GROUPS_JOIN_TASK]: { outcome: "requested" },
    });
    renderPage(<BadgePage badgeId={BADGE_ID} />);
    expect(await screen.findByRole("heading", { name: "Workshop host" })).toBeTruthy();
    expect(await screen.findByText("Priya Natarajan")).toBeTruthy();
    expect(screen.getByText(/×6/)).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: /Ask for this badge/ }));
    fireEvent.change(screen.getByLabelText("Why you should have it"), { target: { value: "I ran the sharpening session." } });
    fireEvent.click(screen.getByRole("button", { name: "Send request" }));
    await waitFor(() =>
      expect(sent(GROUPS_JOIN_TASK)).toEqual([{ groupId: GROUP_ID, message: "I ran the sharpening session." }]),
    );
    expect(await screen.findByText(/The badge's owners decide/)).toBeTruthy();
  });

  it("shows the member's own awards outside the community, one by one, and stops", async () => {
    const AWARD = "awd_S5k2N8xRb3Qz7TpLAAAAAA";
    const own = { awardId: AWARD, badgeId: BADGE_ID, entryId: ENTRY, state: "accepted", offeredAt: "2026-11-01T09:00:00Z", decidedAt: "2026-11-02T09:00:00Z" };
    const SHARED = {
      verificationUrl: "https://vtc.example.com/badges/shared/T0k3n",
      bakedImageUrl: "https://vtc.example.com/badges/shared/T0k3n/image.png",
      since: "2026-11-08T09:00:00Z",
    };
    let shared = false;
    answer({
      ...BASE,
      [BADGES_SHOW_TASK]: () => ({
        badge: badge({ shareableOutside: true }),
        myState: "holder",
        myCount: 1,
        credentialRegime: "outside",
        owners: [],
        myAwards: [shared ? { ...own, shared: SHARED } : own],
      }),
      [BADGES_HOLDERS_TASK]: { total: 0, items: [] },
      [AWARDS_SHARE_TASK]: () => {
        shared = true;
        return { award: { ...own, shared: SHARED } };
      },
      [AWARDS_UNSHARE_TASK]: () => {
        shared = false;
        return { award: own };
      },
    });
    renderPage(<BadgePage badgeId={BADGE_ID} />);
    expect(await screen.findByRole("heading", { name: "Show it outside the community" })).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Share outside" }));
    await waitFor(() => expect(sent(AWARDS_SHARE_TASK)).toEqual([{ awardId: AWARD }]));
    const link = await screen.findByRole("link", { name: "Link to check it" });
    expect(link.getAttribute("href")).toBe(SHARED.verificationUrl);
    expect(screen.getByRole("link", { name: "Picture with the credential" }).getAttribute("href")).toBe(SHARED.bakedImageUrl);
    fireEvent.click(screen.getByRole("button", { name: "Stop sharing" }));
    await waitFor(() => expect(sent(AWARDS_UNSHARE_TASK)).toEqual([{ awardId: AWARD }]));
    expect(await screen.findByRole("button", { name: "Share outside" })).toBeTruthy();
  });

  it("offers no sharing for a badge kept inside", async () => {
    answer({
      ...BASE,
      [BADGES_SHOW_TASK]: { badge: badge(), myState: "holder", myCount: 1, credentialRegime: "inside", owners: [] },
      [BADGES_HOLDERS_TASK]: { total: 0, items: [] },
    });
    renderPage(<BadgePage badgeId={BADGE_ID} />);
    expect(await screen.findByRole("heading", { name: "Workshop host" })).toBeTruthy();
    expect(screen.queryByText("Show it outside the community")).toBeNull();
  });

  it("is not found when the member may not see it", async () => {
    const { DirectoryError } = await import("./directory-api");
    answer({
      ...BASE,
      [BADGES_SHOW_TASK]: () => {
        throw new DirectoryError("notFound", "no such badge");
      },
    });
    renderPage(<BadgePage badgeId={BADGE_ID} />);
    expect(await screen.findByText(/There is no such badge/)).toBeTruthy();
  });
});

describe("the home page's badge status", () => {
  it("counts what shows and what waits", () => {
    const q = { data: mine() as never, isPending: false, isError: false };
    expect(badgesStatus(q)).toEqual({ text: "2 badges on your card · 1 offer waiting", tone: "attention" });
    expect(badgesAttention(q, "#/badges")).toEqual([
      { key: "badge-offers", text: "1 badge offered to you: accept or decline", href: "#/badges" },
    ]);
    expect(badgesStatus({ data: mine({ offers: [], badges: [] }) as never, isPending: false, isError: false })).toEqual({
      text: "No badges yet",
      tone: "muted",
    });
  });
});
