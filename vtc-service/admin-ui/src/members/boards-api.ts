// The community's boards, as a member reads and writes them (`vtc/boards`,
// VTI Community Boards chapter).
//
// Signed by this browser's portal key for the member, which the member
// delegated `vtc/boards` to at sign-in, as the directory and groups pages are.
// Only the member's own acts go this way — proposing, changing or withdrawing
// their idea, and adding or withdrawing their note. A facilitator's decisions
// take their own signature and are made in the console (VTI-BRD-051).
//
// A board never says whether the member took a ticket or voted (VTI-BRD-033).
// Where the page shows "ticket held", that came from the member's wallet
// (`wallet-elections.ts`), never from here.

import type {
  BoardIdeasProposeResponse,
  BoardIdeasUpdateResponse,
  BoardIdeasWithdrawResponse,
  BoardListResponse,
  BoardNotesAddResponse,
  BoardNotesListResponse,
  BoardNotesWithdrawResponse,
  BoardShowResponse,
} from "@/lib/wire-types";

import { send } from "./directory-api";

export const BOARDS_LIST_TASK = "https://trusttasks.org/spec/vtc/boards/list/0.1";
export const BOARDS_SHOW_TASK = "https://trusttasks.org/spec/vtc/boards/show/0.1";
export const IDEAS_PROPOSE_TASK = "https://trusttasks.org/spec/vtc/boards/ideas/propose/0.1";
export const IDEAS_UPDATE_TASK = "https://trusttasks.org/spec/vtc/boards/ideas/update/0.1";
export const IDEAS_WITHDRAW_TASK = "https://trusttasks.org/spec/vtc/boards/ideas/withdraw/0.1";
export const NOTES_ADD_TASK = "https://trusttasks.org/spec/vtc/boards/notes/add/0.1";
export const NOTES_LIST_TASK = "https://trusttasks.org/spec/vtc/boards/notes/list/0.1";
export const NOTES_WITHDRAW_TASK = "https://trusttasks.org/spec/vtc/boards/notes/withdraw/0.1";

export type Board = BoardShowResponse["board"];
export type Idea = BoardShowResponse["ideas"][number];
export type Note = BoardNotesListResponse["notes"][number];
export type IdeaState = Idea["state"];
export type Author = Idea["proposer"];
export type Slot = NonNullable<Board["timetable"]>[number];

export const listBoards = () => send<BoardListResponse>(BOARDS_LIST_TASK, { status: "open", limit: 100 });
export const listAllBoards = () => send<BoardListResponse>(BOARDS_LIST_TASK, { limit: 100 });

/** One board with every idea the member may see. A board holds at most a few hundred ideas, so
 *  this follows `nextCursor` to the end rather than paging the lanes. */
export async function showBoard(boardId: string): Promise<BoardShowResponse> {
  let page = await send<BoardShowResponse>(BOARDS_SHOW_TASK, { boardId, limit: 200 });
  const ideas = [...page.ideas];
  while (page.nextCursor) {
    page = await send<BoardShowResponse>(BOARDS_SHOW_TASK, { boardId, limit: 200, cursor: page.nextCursor });
    ideas.push(...page.ideas);
  }
  return { ...page, ideas, nextCursor: undefined };
}

export interface Proposal {
  title: string;
  description: string;
  format?: string;
  topic?: string;
}

export const proposeIdea = (boardId: string, p: Proposal) =>
  send<BoardIdeasProposeResponse>(IDEAS_PROPOSE_TASK, { boardId, ...p });
export const updateIdea = (ideaId: string, p: Partial<Proposal>) =>
  send<BoardIdeasUpdateResponse>(IDEAS_UPDATE_TASK, { ideaId, ...p });
export const withdrawIdea = (ideaId: string) => send<BoardIdeasWithdrawResponse>(IDEAS_WITHDRAW_TASK, { ideaId });

/** The notes on the board itself, or on one idea. */
export async function listNotes(boardId: string, ideaId?: string): Promise<Note[]> {
  const base = { boardId, limit: 200, ...(ideaId ? { ideaId } : { scope: "board" }) };
  let page = await send<BoardNotesListResponse>(NOTES_LIST_TASK, base);
  const notes = [...page.notes];
  while (page.nextCursor) {
    page = await send<BoardNotesListResponse>(NOTES_LIST_TASK, { ...base, cursor: page.nextCursor });
    notes.push(...page.notes);
  }
  return notes;
}

export const addNote = (boardId: string, text: string, ideaId?: string) =>
  send<BoardNotesAddResponse>(NOTES_ADD_TASK, { boardId, text, ...(ideaId ? { ideaId } : {}) });
export const withdrawNote = (noteId: string) => send<BoardNotesWithdrawResponse>(NOTES_WITHDRAW_TASK, { noteId });

// ── Reading a board ─────────────────────────────────────────────────────────

/** Where the board stands now, in the order its windows run (VTI-BRD-001). */
export type Phase = "upcoming" | "proposals" | "proposalsAndVoting" | "voting" | "counting" | "closed" | "archived";

export function phaseOf(b: Pick<Board, "status" | "proposals" | "voting">, now = Date.now()): Phase {
  if (b.status === "archived") return "archived";
  const pOpen = Date.parse(b.proposals.opensAt);
  const pClose = Date.parse(b.proposals.closesAt);
  const vOpen = Date.parse(b.voting.opensAt);
  const vClose = Date.parse(b.voting.closesAt);
  if (now >= vClose) return b.status === "closed" ? "closed" : "counting";
  const proposing = b.status === "open" && now >= pOpen && now < pClose;
  const voting = now >= vOpen;
  if (proposing && voting) return "proposalsAndVoting";
  if (proposing) return "proposals";
  if (voting) return "voting";
  return now < pOpen ? "upcoming" : "voting";
}

export const PHASE_LABEL: Record<Phase, string> = {
  upcoming: "Not open yet",
  proposals: "Taking proposals",
  proposalsAndVoting: "Proposals and voting",
  voting: "Voting",
  counting: "Counting",
  closed: "Closed",
  archived: "Archived",
};

export function takesProposals(b: Pick<Board, "status" | "proposals">, now = Date.now()): boolean {
  return b.status === "open" && now >= Date.parse(b.proposals.opensAt) && now < Date.parse(b.proposals.closesAt);
}

export function takesNotes(b: Pick<Board, "status">): boolean {
  return b.status === "open";
}

/** The board's lanes, left to right. Declined and merged ideas sit below them; withdrawn ideas
 *  are shown only to their proposer, in the proposed lane's "yours" list. */
export const LANES = ["proposed", "open", "selected", "notSelected"] as const;
export type Lane = (typeof LANES)[number];

export const LANE_LABEL: Record<Lane, string> = {
  proposed: "Proposed",
  open: "Open for votes",
  selected: "Selected",
  notSelected: "Not this time",
};

export const LANE_NOTE: Record<Lane, string> = {
  proposed: "Waiting for a facilitator to open an election.",
  open: "Each idea is its own election. Counts are ballots on the public board.",
  selected: "Tallied and chosen by the facilitators.",
  notSelected: "Tallied, not chosen this time. Notes stay.",
};

/** Ideas the most support first in the open lane; newest first elsewhere. */
export function laneIdeas(ideas: readonly Idea[], lane: Lane): Idea[] {
  const inLane = ideas.filter((i) => i.state === lane);
  if (lane === "open") {
    return inLane.sort((a, b) => (b.election?.ballotsOnBoard ?? 0) - (a.election?.ballotsOnBoard ?? 0));
  }
  return inLane.sort((a, b) => Date.parse(b.proposedAt) - Date.parse(a.proposedAt));
}

/** One question's share for the option that leads it, for the tallied meter: `[key, share]`,
 *  share in 0…1 of the ballots that answered it. `null` when the result has no choice counts. */
export function leadingShare(idea: Idea): { label: string; share: number; counted: number } | null {
  const result = idea.election?.result;
  const q = result?.questions[0];
  const counts = q?.choice as Record<string, number> | undefined;
  if (!result || !counts) return null;
  const total = Object.values(counts).reduce((a, b) => a + b, 0);
  if (total === 0) return { label: "", share: 0, counted: result.ballotsCounted };
  // A board's template usually asks "would you attend?": prefer a `yes` option where there is one.
  const key = "yes" in counts ? "yes" : Object.entries(counts).sort((a, b) => b[1] - a[1])[0]![0];
  return { label: key, share: (counts[key] ?? 0) / total, counted: result.ballotsCounted };
}

export function authorName(a: Author): string {
  if (a.formerMember) return "A former member";
  if (a.you) return "You";
  return a.name ?? "A member";
}

/** The timetable as a grid: distinct places across, distinct start times down. */
export function grid(slots: readonly Slot[]): { places: string[]; times: string[]; at: (place: string, time: string) => Slot | undefined } {
  const places = [...new Set(slots.map((s) => s.label))];
  const times = [...new Set(slots.map((s) => s.startsAt))].sort((a, b) => Date.parse(a) - Date.parse(b));
  return { places, times, at: (place, time) => slots.find((s) => s.label === place && s.startsAt === time) };
}
