// The portal's Badges pages: offers accepted and declined, the wall arranged and a badge
// hidden, one badge with its holders and asking its owners for it, and badges off.
// Every read and write goes through this browser's portal key (`send`, mocked per task).

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

const send = vi.fn();
vi.mock("./directory-api", async (orig) => ({
  ...(await orig<typeof import("./directory-api")>()),
  send: (...a: unknown[]) => send(...a),
}));

import { BadgePage, BadgesPage } from "./Badges";
import {
  BADGES_HOLDERS_TASK,
  BADGES_IMAGES_GET_TASK,
  BADGES_LIST_TASK,
  BADGES_SETTINGS_TASK,
  BADGES_SHOW_TASK,
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
  return render(<QueryClientProvider client={qc}>{ui}</QueryClientProvider>);
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

  it("shows nothing but a line when the community has badges off", async () => {
    answer({ ...BASE, [BADGES_SETTINGS_TASK]: { settings: { ...SETTINGS, enabled: false } }, [MINE_LIST_TASK]: mine() });
    renderPage(<BadgesPage />);
    expect(await screen.findByText("This community has badges turned off for now.")).toBeTruthy();
    expect(screen.queryByText("Waiting for you")).toBeNull();
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
