// The console's Boards page, for facilitators: creating a board takes both vtc.boards.manage and
// vtc.elections.manage (VTI-BRD-002); a facilitator decides proposed ideas and, once an idea's
// election is tallied, selects among them.

import { fireEvent, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { Boards, boardChanges } from "@/plugins/boards";
import { mockFetch, renderWithProviders, sentPayloads, taskRoute, whoamiWith } from "@/test/render";

vi.mock("@/lib/api", async (original) => ({
  ...(await original<typeof import("@/lib/api")>()),
  postSignedRead: (await import("@/test/signed-read")).unsignedRead,
  postSignedTrustTask: (await import("@/test/signed-read")).unsignedTask,
}));

const S = "https://trusttasks.org/spec/vtc/boards";
const LIST = `${S}/list/0.1`;
const SHOW = `${S}/show/0.1`;
const DECIDE = `${S}/ideas/decide/0.1`;
const SELECT = `${S}/ideas/select/0.1`;
const NOTES = `${S}/notes/list/0.1`;
const UPDATE = `${S}/update/0.1`;
const DELETE = `${S}/delete/0.1`;
const BOARD_ID = "brd_Uc7N2qLm4Rt8Vx1ZAAAAAA";
const DAY = 86_400_000;
const iso = (ms: number) => new Date(ms).toISOString();

function board(extra: object = {}) {
  const now = Date.now();
  return {
    boardId: BOARD_ID,
    title: "Trust Week Unconference",
    status: "open",
    audience: { kind: "members" },
    proposals: { opensAt: iso(now - 2 * DAY), closesAt: iso(now + DAY) },
    voting: { opensAt: iso(now - DAY), closesAt: iso(now + 2 * DAY) },
    selectionRule: "The twelve sessions most members would attend.",
    timetable: [{ slotId: "s1", label: "Room A", startsAt: iso(now + 3 * DAY), endsAt: iso(now + 3 * DAY + 3600_000) }],
    template: {
      questions: [{ key: "attend", type: "choice", text: "Would you attend?", options: [{ key: "yes" }, { key: "no" }], minSelections: 1, maxSelections: 1, optional: false }],
      secrecy: "open",
      revote: "replace",
      board: { visibility: "public", auditors: [] },
      ballotBox: "did:webvh:QmBox:ballots.example",
      allowEarlyClose: false,
      resultsBeforeClose: false,
      textReleaseThreshold: 10,
    },
    createdAt: iso(now - 3 * DAY),
    facilitator: true,
    ideaCounts: { proposed: 1, open: 1 },
    ...extra,
  };
}

const proposed = {
  ideaId: "ida_Pk3Wq9Ls2Dn6Hy4BAAAAAA",
  boardId: BOARD_ID,
  state: "proposed",
  title: "Accessible wallet sign-in",
  description: "Screen readers.",
  proposer: { entryId: "dir_Rb8Nc3Kq7Wz2Lp5DAAAAAA", name: "Elif Polat" },
  proposedAt: iso(Date.now() - DAY),
  noteCount: 2,
};

const tallied = {
  ...proposed,
  ideaId: "ida_Zt5Mv8Qr1Kc7Jw3EAAAAAA",
  state: "open",
  title: "Who chooses our witnesses?",
  election: {
    electionId: `board.${BOARD_ID}.ida_Zt5Mv8Qr1Kc7Jw3EAAAAAA`,
    state: "closed",
    certified: false,
    result: {
      electionId: "e",
      manifestDigest: "u",
      ballotsCounted: 10,
      questions: [{ question: "attend", abstained: 0, choice: { yes: 7, no: 3 } }],
      head: { electionId: "e", treeSize: 10, rootHash: "u", issuedAt: iso(Date.now()) },
    },
  },
};

describe("the Boards page", () => {
  it("offers a new board only to someone who also manages elections", async () => {
    mockFetch([taskRoute(LIST, { boards: [board()] })]);
    renderWithProviders(<Boards />, { route: "/boards", path: "/boards/*", whoami: whoamiWith(["vtc.boards.manage"]) });
    expect(await screen.findByText("Trust Week Unconference")).toBeTruthy();
    expect(screen.queryByRole("button", { name: /New board/ })).toBeNull();
  });

  it("offers a new board to a holder of both", async () => {
    mockFetch([taskRoute(LIST, { boards: [] })]);
    renderWithProviders(<Boards />, {
      route: "/boards",
      path: "/boards/*",
      whoami: whoamiWith(["vtc.boards.manage", "vtc.elections.manage"]),
    });
    expect(await screen.findByRole("button", { name: /New board/ })).toBeTruthy();
  });

  it("accepts a proposed idea, which opens its election", async () => {
    const requests = mockFetch([
      taskRoute(SHOW, { board: board(), ideas: [proposed] }),
      taskRoute(NOTES, { notes: [] }),
      taskRoute(DECIDE, { idea: { ...proposed, state: "open" } }),
    ]);
    renderWithProviders(<Boards />, {
      route: `/boards/${BOARD_ID}`,
      path: "/boards/*",
      whoami: whoamiWith([`vtc.boards.manage:board:${BOARD_ID}`]),
    });
    fireEvent.click(await screen.findByRole("button", { name: /Accept/ }));
    await waitFor(() => expect(sentPayloads(requests, DECIDE)).toEqual([{ ideaId: proposed.ideaId, decision: "accept" }]));
  });

  it("selects a tallied idea into a slot, and needs a reason to depart from the rule", async () => {
    const requests = mockFetch([
      taskRoute(SHOW, { board: board(), ideas: [tallied] }),
      taskRoute(NOTES, { notes: [] }),
      taskRoute(SELECT, { idea: { ...tallied, state: "selected" } }),
    ]);
    renderWithProviders(<Boards />, {
      route: `/boards/${BOARD_ID}`,
      path: "/boards/*",
      whoami: whoamiWith(["vtc.boards.manage"]),
    });
    expect(await screen.findByText(/10 counted · 70% yes/)).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Decide" }));
    fireEvent.change(screen.getByLabelText("Slot"), { target: { value: "s1" } });
    fireEvent.click(screen.getByLabelText(/departs from how we said/));
    expect((screen.getByRole("button", { name: "Select" }) as HTMLButtonElement).disabled).toBe(true);
    fireEvent.change(screen.getByLabelText("Reason"), { target: { value: "Pairs with the keynote." } });
    fireEvent.click(screen.getByRole("button", { name: "Select" }));
    await waitFor(() =>
      expect(sentPayloads(requests, SELECT)).toEqual([
        { ideaId: tallied.ideaId, decision: "selected", slotId: "s1", departsFromRule: true, reason: "Pairs with the keynote." },
      ]),
    );
  });
});

describe("editing a board", () => {
  const facilitator = whoamiWith([`vtc.boards.manage:board:${BOARD_ID}`]);

  it("sends only what changed, so an open vote's window is never sent (fixedAfterVotingOpens)", async () => {
    const requests = mockFetch([
      taskRoute(SHOW, { board: board(), ideas: [] }),
      taskRoute(NOTES, { notes: [] }),
      taskRoute(UPDATE, { board: board({ title: "Trust Week 2026" }) }),
    ]);
    renderWithProviders(<Boards />, { route: `/boards/${BOARD_ID}`, path: "/boards/*", whoami: facilitator });
    fireEvent.click(await screen.findByRole("button", { name: /Edit board/ }));
    const title = screen.getByDisplayValue("Trust Week Unconference");
    fireEvent.change(title, { target: { value: "Trust Week 2026" } });
    // Voting opened yesterday in this fixture: its window is shown, fixed.
    expect((screen.getAllByText("Fixed: voting has opened.")).length).toBeGreaterThan(0);
    fireEvent.click(screen.getByRole("button", { name: "Save changes" }));
    await waitFor(() => expect(sentPayloads(requests, UPDATE)).toEqual([{ boardId: BOARD_ID, title: "Trust Week 2026" }]));
  });

  it("moves the voting window of a board whose voting has not opened", () => {
    const now = Date.now();
    const b = board({ voting: { opensAt: iso(now + 2 * DAY), closesAt: iso(now + 4 * DAY) } }) as never;
    const voting = { opensAt: iso(now + 60_000), closesAt: iso(now + 4 * DAY) };
    const out = boardChanges(b, {
      title: "Trust Week Unconference",
      description: "",
      audience: "members",
      proposals: (b as { proposals: { opensAt: string; closesAt: string } }).proposals,
      voting,
      topics: [],
      formats: [],
      maxIdeas: "",
      rule: "The twelve sessions most members would attend.",
      timetable: (b as { timetable: never[] }).timetable,
    });
    expect(out).toEqual({ voting });
  });

  it("keeps an existing slot's identifier and gives a new one a fresh one", () => {
    const b = board() as never;
    const kept = (b as { timetable: { slotId: string; label: string; startsAt: string; endsAt: string }[] }).timetable[0]!;
    const added = { slotId: "s2", label: "Room B", startsAt: kept.startsAt, endsAt: kept.endsAt };
    const out = boardChanges(b, {
      title: "Trust Week Unconference",
      description: "",
      audience: "members",
      proposals: (b as { proposals: { opensAt: string; closesAt: string } }).proposals,
      voting: (b as { voting: { opensAt: string; closesAt: string } }).voting,
      topics: [],
      formats: [],
      maxIdeas: "",
      rule: "The twelve sessions most members would attend.",
      timetable: [kept, added],
    });
    expect(out).toEqual({ timetable: [kept, added] });
  });
});

describe("closing and deleting a board", () => {
  it("offers Delete only on a closed board, and only once its title is typed and a reason given", async () => {
    const requests = mockFetch([
      taskRoute(SHOW, { board: board({ status: "closed" }), ideas: [] }),
      taskRoute(NOTES, { notes: [] }),
      taskRoute(DELETE, {
        boardId: BOARD_ID,
        ideasRemoved: 3,
        notesRemoved: 5,
        electionsRemoved: 2,
        tombstones: { kept: 2, removeAt: iso(Date.now() + 365 * DAY) },
      }),
    ]);
    renderWithProviders(<Boards />, {
      route: `/boards/${BOARD_ID}`,
      path: "/boards/*",
      whoami: whoamiWith(["vtc.boards.manage"]),
    });
    fireEvent.click(await screen.findByRole("button", { name: /Delete board/ }));
    const submit = () => screen.getAllByRole("button", { name: /Delete board/ }).at(-1)!;
    expect(submit()).toHaveProperty("disabled", true);
    fireEvent.change(screen.getByLabelText(/Type the board's title/), { target: { value: "Trust Week Unconference" } });
    fireEvent.change(screen.getByLabelText("Why"), { target: { value: "The event is over." } });
    expect(submit()).toHaveProperty("disabled", false);
    fireEvent.click(submit());
    await waitFor(() =>
      expect(sentPayloads(requests, DELETE)).toEqual([{ boardId: BOARD_ID, reason: "The event is over." }]),
    );
  });

  it("does not offer Delete to a facilitator of this one board, nor on an open board", async () => {
    mockFetch([taskRoute(SHOW, { board: board({ status: "closed" }), ideas: [] }), taskRoute(NOTES, { notes: [] })]);
    const { unmount } = renderWithProviders(<Boards />, {
      route: `/boards/${BOARD_ID}`,
      path: "/boards/*",
      whoami: whoamiWith([`vtc.boards.manage:board:${BOARD_ID}`]),
    });
    await screen.findByRole("button", { name: /Archive/ });
    expect(screen.queryByRole("button", { name: /Delete board/ })).toBeNull();
    unmount();
    mockFetch([taskRoute(SHOW, { board: board(), ideas: [] }), taskRoute(NOTES, { notes: [] })]);
    renderWithProviders(<Boards />, {
      route: `/boards/${BOARD_ID}`,
      path: "/boards/*",
      whoami: whoamiWith(["vtc.boards.manage"]),
    });
    await screen.findByRole("button", { name: /Close and end voting/ });
    expect(screen.queryByRole("button", { name: /Delete board/ })).toBeNull();
  });
});

