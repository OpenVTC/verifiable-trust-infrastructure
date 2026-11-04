// The portal's Boards pages. A board is read and written with this browser's portal key
// (`send`, mocked per task here); voting hands off to the member's wallet. The page learns
// "ticket held" only from the wallet, and after a vote is never told whether one was cast
// (VTI-BRD-033).

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const send = vi.fn();
vi.mock("./directory-api", async (orig) => ({
  ...(await orig<typeof import("./directory-api")>()),
  send: (...a: unknown[]) => send(...a),
}));

import { BoardPage, BoardsPage } from "./Boards";
import {
  BOARDS_LIST_TASK,
  BOARDS_SHOW_TASK,
  IDEAS_PROPOSE_TASK,
  NOTES_ADD_TASK,
  NOTES_LIST_TASK,
  grid,
  laneIdeas,
  leadingShare,
  phaseOf,
  type Board,
  type Idea,
} from "./boards-api";

const HOST = "did:webvh:QmHost:acme.example";
const ME = "did:key:z6MkMember";
const DAY = 86_400_000;
const iso = (ms: number) => new Date(ms).toISOString();
const BOARD_ID = "brd_Uc7N2qLm4Rt8Vx1Z00";

function board(over: Partial<Board> = {}): Board {
  const now = Date.now();
  return {
    boardId: BOARD_ID,
    title: "Trust Week Unconference",
    description: "Propose a session for Friday.",
    status: "open",
    audience: { kind: "members" },
    proposals: { opensAt: iso(now - 2 * DAY), closesAt: iso(now + DAY) },
    voting: { opensAt: iso(now - DAY), closesAt: iso(now + 2 * DAY) },
    topics: ["Identity", "Governance"],
    formats: ["Discussion", "Talk"],
    selectionRule: "The twelve sessions most members would attend.",
    timetable: [{ slotId: "s1", label: "Room A", startsAt: iso(now + 3 * DAY), endsAt: iso(now + 3 * DAY + 3600_000) }],
    template: {
      questions: [
        {
          key: "attend",
          type: "choice",
          text: "Would you attend this session?",
          options: [
            { key: "yes", label: "Yes, I'd attend" },
            { key: "no", label: "Not for me" },
          ],
          minSelections: 1,
          maxSelections: 1,
          optional: false,
        },
      ],
      secrecy: "open",
      revote: "replace",
      board: { visibility: "public", auditors: [] },
      ballotBox: "did:webvh:QmBox:ballots.example",
      allowEarlyClose: false,
      resultsBeforeClose: false,
      textReleaseThreshold: 10,
    },
    createdAt: iso(now - 3 * DAY),
    facilitator: false,
    ideaCounts: {},
    ...over,
  } as Board;
}

let n = 0;
function idea(over: Partial<Idea> = {}): Idea {
  n += 1;
  const id = `ida_Pk3Wq9Ls2Dn6Hy4B${String(n).padStart(2, "0")}`;
  return {
    ideaId: id,
    boardId: BOARD_ID,
    state: "proposed",
    title: `Idea ${n}`,
    description: "What it covers.",
    format: "Discussion",
    topic: "Identity",
    proposer: { entryId: "dir_Rb8Nc3Kq7Wz2Lp5D00", name: "Elif Polat" },
    proposedAt: iso(Date.now() - n * 3600_000),
    noteCount: 0,
    ...over,
  } as Idea;
}

function openIdea(ballots: number, over: Partial<Idea> = {}): Idea {
  const i = idea({ state: "open", ...over });
  return { ...i, election: { electionId: `board.${BOARD_ID}.${i.ideaId}`, state: "voting", ballotsOnBoard: ballots } } as Idea;
}

function serve(b: Board, ideas: Idea[], notes: unknown[] = []) {
  send.mockImplementation(async (type: string, payload: Record<string, unknown>) => {
    if (type === BOARDS_SHOW_TASK) return { board: b, ideas };
    if (type === BOARDS_LIST_TASK) return { boards: [b] };
    if (type === NOTES_LIST_TASK) return { notes };
    if (type === IDEAS_PROPOSE_TASK) return { idea: idea({ title: String(payload.title), proposer: { you: true } }) };
    if (type === NOTES_ADD_TASK) return { note: { noteId: "bnt_x", boardId: BOARD_ID, author: { you: true }, text: payload.text, createdAt: iso(Date.now()), state: "visible" } };
    throw new Error(`unexpected ${type}`);
  });
}

function withWallet(heldIds: string[] = []) {
  const wallet = {
    list: vi.fn(async () => ({
      elections: heldIds.map((electionId) => ({
        electionId,
        state: "voting",
        votingOpensAt: iso(Date.now() - DAY),
        votingClosesAt: iso(Date.now() + DAY),
        binding: false,
        ticketHeld: true,
      })),
    })),
    show: vi.fn(),
    takeTicket: vi.fn(async () => ({ ticketHeld: true as const, taken: true })),
    takeTickets: vi.fn(async (p: { electionIds: string[] }) => ({
      tickets: p.electionIds.map((electionId) => ({ electionId, outcome: "taken" as const })),
    })),
    vote: vi.fn(async () => ({ ticketTaken: false })),
  };
  (window as { vtaWallet?: unknown }).vtaWallet = { elections: wallet };
  return wallet;
}

function renderWith(node: React.ReactNode) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={qc}>{node}</QueryClientProvider>);
}

beforeEach(() => {
  send.mockReset();
});
afterEach(() => {
  delete (window as { vtaWallet?: unknown }).vtaWallet;
});

describe("reading a board", () => {
  it("phases follow the board's windows and status", () => {
    const now = Date.now();
    expect(phaseOf(board(), now)).toBe("proposalsAndVoting");
    expect(phaseOf(board({ voting: { opensAt: iso(now + DAY), closesAt: iso(now + 2 * DAY) } }), now)).toBe("proposals");
    expect(phaseOf(board({ status: "closed", voting: { opensAt: iso(now - 2 * DAY), closesAt: iso(now - DAY) } }), now)).toBe("closed");
    expect(phaseOf(board({ status: "archived" }), now)).toBe("archived");
  });

  it("orders the open lane by ballots on the board", () => {
    const a = openIdea(3);
    const b = openIdea(40);
    expect(laneIdeas([a, b], "open").map((i) => i.ideaId)).toEqual([b.ideaId, a.ideaId]);
  });

  it("reads the yes share of a tallied result", () => {
    const i = openIdea(0);
    const tallied = {
      ...i,
      election: {
        ...i.election!,
        state: "tallied",
        result: { electionId: "e", manifestDigest: "u", ballotsCounted: 10, questions: [{ question: "attend", abstained: 0, choice: { yes: 7, no: 3 } }], head: {} },
      },
    } as unknown as Idea;
    expect(leadingShare(tallied)).toEqual({ label: "yes", share: 0.7, counted: 10 });
  });

  it("lays a timetable out by place and time", () => {
    const g = grid(board().timetable!);
    expect(g.places).toEqual(["Room A"]);
    expect(g.at("Room A", g.times[0]!)?.slotId).toBe("s1");
  });
});

describe("BoardsPage", () => {
  it("lists the boards the member can see", async () => {
    serve(board(), []);
    renderWith(<BoardsPage />);
    expect((await screen.findByRole("link", { name: "Trust Week Unconference" })).getAttribute("href")).toBe(`#/boards/${BOARD_ID}`);
  });

  it("says how to get a key when the member signed in without the wallet", async () => {
    const { DirectoryError } = await import("./directory-api");
    send.mockRejectedValue(new DirectoryError("noKey", "no key"));
    renderWith(<BoardsPage />);
    expect(await screen.findByText(/Sign in with your wallet to use boards/)).toBeTruthy();
  });
});

describe("BoardPage", () => {
  it("shows ideas in their lanes, and the ticket only as the wallet reports it", async () => {
    const held = openIdea(12, { title: "Held one" });
    const notHeld = openIdea(5, { title: "Not held" });
    serve(board(), [idea({ title: "Waiting" }), held, notHeld]);
    withWallet([held.election!.electionId]);
    renderWith(<BoardPage boardId={BOARD_ID} hostDid={HOST} member={ME} />);

    const proposed = await screen.findByRole("region", { name: "Proposed" });
    expect(within(proposed).getByText("Waiting")).toBeTruthy();
    const open = screen.getByRole("region", { name: "Open for votes" });
    const cards = within(open).getAllByRole("button");
    expect(cards[0]!.textContent).toContain("Held one");
    expect(cards[0]!.textContent).toContain("12 ballots on the board");
    await waitFor(() => expect(cards[0]!.textContent).toContain("Ticket held"));
    expect(cards[1]!.textContent).toContain("No ticket yet");
    expect(screen.getByRole("button", { name: /Take your tickets \(1\)/ })).toBeTruthy();
  });

  it("takes every missing ticket in one wallet decision", async () => {
    const held = openIdea(12);
    const a = openIdea(5);
    const b = openIdea(2);
    serve(board(), [held, a, b]);
    const wallet = withWallet([held.election!.electionId]);
    renderWith(<BoardPage boardId={BOARD_ID} hostDid={HOST} member={ME} />);
    fireEvent.click(await screen.findByRole("button", { name: /Take your tickets \(2\)/ }));
    await waitFor(() =>
      expect(wallet.takeTickets).toHaveBeenCalledWith({
        hostDid: HOST,
        electionIds: [a.election!.electionId, b.election!.electionId],
        member: ME,
      }),
    );
    expect(wallet.takeTicket).not.toHaveBeenCalled();
  });

  it("asks an older wallet for each ticket in turn", async () => {
    const a = openIdea(5);
    const b = openIdea(2);
    serve(board(), [a, b]);
    const wallet = withWallet();
    delete (wallet as { takeTickets?: unknown }).takeTickets;
    renderWith(<BoardPage boardId={BOARD_ID} hostDid={HOST} member={ME} />);
    fireEvent.click(await screen.findByRole("button", { name: /Take your tickets \(2\)/ }));
    await waitFor(() => expect(wallet.takeTicket).toHaveBeenCalledTimes(2));
  });

  it("asks the board for no ticket or ballot, ever", async () => {
    serve(board(), [openIdea(1)]);
    withWallet();
    renderWith(<BoardPage boardId={BOARD_ID} hostDid={HOST} member={ME} />);
    await screen.findByRole("region", { name: "Open for votes" });
    for (const [, payload] of send.mock.calls) {
      expect(JSON.stringify(payload)).not.toMatch(/ticket|ballot|vote/i);
    }
  });

  it("hands voting to the wallet and is not told whether a vote was cast", async () => {
    const i = openIdea(3, { title: "Vote on me" });
    serve(board(), [i]);
    const wallet = withWallet([i.election!.electionId]);
    renderWith(<BoardPage boardId={BOARD_ID} hostDid={HOST} member={ME} />);
    fireEvent.click(await screen.findByRole("button", { name: /Vote on me/ }));
    fireEvent.click(await screen.findByRole("button", { name: /Vote in your wallet/ }));
    await waitFor(() => expect(wallet.vote).toHaveBeenCalledWith({ hostDid: HOST, electionId: i.election!.electionId, member: ME }));
    expect(await screen.findByText(/Your wallet window closed\. If you cast a ballot/)).toBeTruthy();
    expect(screen.queryByText(/vote (was )?(cast|recorded|counted)|you have voted|thanks for voting/i)).toBeNull();
  });

  it("offers no vote before voting opens, only the ticket (the VTA refuses a cast as notOpen)", async () => {
    const now = Date.now();
    const i = openIdea(0, { title: "Too early" });
    serve(board({ voting: { opensAt: iso(now + 2 * DAY), closesAt: iso(now + 4 * DAY) } }), [i]);
    const wallet = withWallet([i.election!.electionId]);
    renderWith(<BoardPage boardId={BOARD_ID} hostDid={HOST} member={ME} />);
    fireEvent.click(await screen.findByRole("button", { name: /Too early/ }));
    expect((await screen.findAllByText(/Voting opens/)).length).toBeGreaterThan(0);
    expect(screen.getByText("Voting soon")).toBeTruthy();
    expect(screen.queryByRole("button", { name: /Vote in your wallet/ })).toBeNull();
    expect(wallet.vote).not.toHaveBeenCalled();
  });

  it("still offers the ticket before voting opens", async () => {
    const now = Date.now();
    const i = openIdea(0, { title: "Ticket first" });
    serve(board({ voting: { opensAt: iso(now + 2 * DAY), closesAt: iso(now + 4 * DAY) } }), [i]);
    withWallet([]);
    renderWith(<BoardPage boardId={BOARD_ID} hostDid={HOST} member={ME} />);
    fireEvent.click(await screen.findByRole("button", { name: /Ticket first/ }));
    expect((await screen.findAllByRole("button", { name: /Take your ticket/ })).length).toBeGreaterThan(0);
  });

  it("proposes an idea, telling the member first what proposing means", async () => {
    serve(board(), []);
    renderWith(<BoardPage boardId={BOARD_ID} hostDid={HOST} member={ME} />);
    fireEvent.click((await screen.findAllByRole("button", { name: /Propose an idea/ }))[0]!);
    const dialog = screen.getByRole("dialog", { name: "Propose an idea" });
    expect(within(dialog).getByText(/shown under your name/)).toBeTruthy();
    fireEvent.change(within(dialog).getByLabelText("Title"), { target: { value: "Accessible sign-in" } });
    fireEvent.change(within(dialog).getByLabelText("What would you cover?"), { target: { value: "Screen readers." } });
    fireEvent.click(within(dialog).getByRole("button", { name: "Propose" }));
    await waitFor(() =>
      expect(send).toHaveBeenCalledWith(IDEAS_PROPOSE_TASK, {
        boardId: BOARD_ID,
        title: "Accessible sign-in",
        description: "Screen readers.",
        format: "Discussion",
        topic: "Identity",
      }),
    );
  });

  it("offers no proposing once proposals close", async () => {
    const now = Date.now();
    serve(board({ proposals: { opensAt: iso(now - 3 * DAY), closesAt: iso(now - DAY) } }), []);
    renderWith(<BoardPage boardId={BOARD_ID} hostDid={HOST} member={ME} />);
    await screen.findByRole("region", { name: "Proposed" });
    expect(screen.queryByRole("button", { name: /Propose an idea/ })).toBeNull();
  });

  it("shows a hidden note's reason in its place, never its text to others", async () => {
    serve(board(), [], [
      { noteId: "bnt_a", boardId: BOARD_ID, author: { name: "Tomás" }, createdAt: iso(Date.now()), state: "hidden", hiddenReason: "Off topic" },
    ]);
    renderWith(<BoardPage boardId={BOARD_ID} hostDid={HOST} member={ME} />);
    expect(await screen.findByText(/Hidden by a facilitator: Off topic/)).toBeTruthy();
  });
});
