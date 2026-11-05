// Community boards, as facilitators run them (`vtc/boards`, docs/03-vtc/boards.md).
//
// Members propose ideas and leave notes from the member portal. Here, a facilitator — a holder
// of `vtc.boards.manage`, for every board or qualified `board:<boardId>` for one — accepts,
// declines and merges ideas, selects among them once their elections are tallied, and hides
// notes. Accepting an idea opens an election from the board's template; the facilitator needs no
// `vtc.elections.manage` for that, because whoever created the board fixed the template and held
// it (VTI-BRD-002, VTI-BRD-030). Creating a board, and changing its template, take both.
//
// Every act is signed by this browser's console key, never a member portal key (VTI-BRD-051).

import { postSignedRead, postSignedTrustTask } from "./api";
import { postSignedWithStepUp, type ConfirmGesture } from "./signed-act";
import type {
  BoardCreatePayload,
  BoardCreateResponse,
  BoardIdeasDecideResponse,
  BoardIdeasSelectResponse,
  BoardListResponse,
  BoardNotesHideResponse,
  BoardNotesListResponse,
  BoardShowResponse,
  BoardUpdatePayload,
  BoardUpdateResponse,
  BoardDeleteResponse,
  BoardFacilitatorsListResponse,
  BoardFacilitatorsResponse,
} from "./wire-types";

export const BOARDS_MANAGE = "vtc.boards.manage";
export const ELECTIONS_MANAGE = "vtc.elections.manage";
export const BOARDS_KEY = ["boards"] as const;

const CREATE = "https://trusttasks.org/spec/vtc/boards/create/0.1";
const UPDATE = "https://trusttasks.org/spec/vtc/boards/update/0.1";
export const DELETE = "https://trusttasks.org/spec/vtc/boards/delete/0.1";
const LIST = "https://trusttasks.org/spec/vtc/boards/list/0.1";
const SHOW = "https://trusttasks.org/spec/vtc/boards/show/0.1";
const DECIDE = "https://trusttasks.org/spec/vtc/boards/ideas/decide/0.1";
const SELECT = "https://trusttasks.org/spec/vtc/boards/ideas/select/0.1";
const NOTES_LIST = "https://trusttasks.org/spec/vtc/boards/notes/list/0.1";
const NOTES_HIDE = "https://trusttasks.org/spec/vtc/boards/notes/hide/0.1";
const FACILITATORS_ADD = "https://trusttasks.org/spec/vtc/boards/facilitators/add/0.1";
const FACILITATORS_REMOVE = "https://trusttasks.org/spec/vtc/boards/facilitators/remove/0.1";
const FACILITATORS_LIST = "https://trusttasks.org/spec/vtc/boards/facilitators/list/0.1";

export type Board = BoardShowResponse["board"];
export type Idea = BoardShowResponse["ideas"][number];
export type Note = BoardNotesListResponse["notes"][number];
export type Template = Board["template"];
export type Slot = NonNullable<Board["timetable"]>[number];
export type Appointment = BoardFacilitatorsListResponse["facilitators"][number];

const PAGE = 200;
const MAX_PAGES = 20;

export async function listBoards(): Promise<Board[]> {
  const out: Board[] = [];
  let cursor: string | undefined;
  for (let i = 0; i < MAX_PAGES; i++) {
    const page = await postSignedRead<BoardListResponse>(LIST, { limit: PAGE, ...(cursor ? { cursor } : {}) });
    out.push(...page.boards);
    if (!page.nextCursor) break;
    cursor = page.nextCursor;
  }
  return out;
}

export async function showBoard(boardId: string): Promise<BoardShowResponse> {
  let page = await postSignedRead<BoardShowResponse>(SHOW, { boardId, limit: PAGE });
  const ideas = [...page.ideas];
  for (let i = 1; i < MAX_PAGES && page.nextCursor; i++) {
    page = await postSignedRead<BoardShowResponse>(SHOW, { boardId, limit: PAGE, cursor: page.nextCursor });
    ideas.push(...page.ideas);
  }
  return { ...page, ideas, nextCursor: undefined };
}

/** Every note on the board, its ideas' included, as a facilitator reads them (hidden and
 *  withdrawn notes with their text). */
export async function listAllNotes(boardId: string): Promise<Note[]> {
  const out: Note[] = [];
  let cursor: string | undefined;
  for (let i = 0; i < MAX_PAGES; i++) {
    const page = await postSignedRead<BoardNotesListResponse>(NOTES_LIST, {
      boardId,
      scope: "all",
      limit: PAGE,
      ...(cursor ? { cursor } : {}),
    });
    out.push(...page.notes);
    if (!page.nextCursor) break;
    cursor = page.nextCursor;
  }
  return out;
}

export const createBoard = (p: BoardCreatePayload) => postSignedTrustTask<BoardCreateResponse>(CREATE, p);
export const updateBoard = (p: BoardUpdatePayload) => postSignedTrustTask<BoardUpdateResponse>(UPDATE, p);

/**
 * Delete a closed board whose voting has ended (VTI-BRD-007): its ideas, notes and each
 * election's content go, each election keeping a tombstone for the community's retention
 * (VTI-BRD-008). Takes `vtc.boards.manage` unqualified and a passkey gesture bound to this one
 * request, which `confirm` asks the operator for.
 */
export const deleteBoard = (boardId: string, reason: string, confirm: ConfirmGesture) =>
  postSignedWithStepUp<BoardDeleteResponse>(DELETE, { boardId, reason }, confirm);

// ── Facilitators by appointment (VTI-BRD-090 – 093) ──────────────────────────
//
// A facilitator appoints a member to facilitate this one board: `vtc.boards.manage` qualified
// `board:<boardId>`, a grant on the member's own entry that names the appointer. Only the
// appointee, or a holder of `vtc.boards.manage` for every board, ends an appointment.

export const listFacilitators = (boardId: string) =>
  postSignedRead<BoardFacilitatorsListResponse>(FACILITATORS_LIST, { boardId }).then((r) => r.facilitators);

export const appointFacilitator = (boardId: string, entryId: string, reason?: string) =>
  postSignedTrustTask<BoardFacilitatorsResponse>(FACILITATORS_ADD, {
    boardId,
    entryId,
    ...(reason ? { reason } : {}),
  }).then((r) => r.facilitators);

export const removeFacilitator = (boardId: string, entryId: string) =>
  postSignedTrustTask<BoardFacilitatorsResponse>(FACILITATORS_REMOVE, { boardId, entryId }).then(
    (r) => r.facilitators,
  );

export type Decision = "accept" | "decline" | "merge" | "reopen";

export function decideIdea(ideaId: string, decision: Decision, opts: { reason?: string; mergeInto?: string } = {}) {
  const reason = opts.reason?.trim();
  return postSignedTrustTask<BoardIdeasDecideResponse>(DECIDE, {
    ideaId,
    decision,
    ...(reason ? { reason } : {}),
    ...(opts.mergeInto ? { mergeInto: opts.mergeInto } : {}),
  });
}

export function selectIdea(
  ideaId: string,
  decision: "selected" | "notSelected",
  opts: { slotId?: string; departsFromRule?: boolean; reason?: string } = {},
) {
  const reason = opts.reason?.trim();
  return postSignedTrustTask<BoardIdeasSelectResponse>(SELECT, {
    ideaId,
    decision,
    ...(decision === "selected" && opts.slotId ? { slotId: opts.slotId } : {}),
    ...(opts.departsFromRule ? { departsFromRule: true } : {}),
    ...(reason ? { reason } : {}),
  });
}

export const hideNote = (noteId: string, action: "hide" | "unhide", reason?: string) =>
  postSignedTrustTask<BoardNotesHideResponse>(NOTES_HIDE, {
    noteId,
    action,
    ...(reason?.trim() ? { reason: reason.trim() } : {}),
  });

/** The template a new board starts from: an unconference's "would you attend?", open ballots on
 *  a public board (so the board can show how many ballots each idea drew, VTI-BRD-033), a later
 *  ballot replacing an earlier one, and no running totals while voting is open. */
export function defaultTemplate(ballotBox: string): Template {
  return {
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
    ballotBox,
    allowEarlyClose: true,
    resultsBeforeClose: false,
    textReleaseThreshold: 10,
  } as Template;
}

/** What a facilitator can do with an idea now, given its state and its election's. */
export type Pending = "decide" | "opening" | "refused" | "voting" | "select" | "decided" | "none";

export function pendingOf(i: Idea): Pending {
  if (i.state === "proposed") {
    if (i.opening?.refusal) return "refused";
    if (i.opening) return "opening";
    return "decide";
  }
  if (i.state === "open") return i.election?.result ? "select" : "voting";
  if (i.state === "selected" || i.state === "notSelected") return "decided";
  return "none";
}

/** A board's slots as `<option>` labels, free ones first. */
export function slotLabel(s: Slot): string {
  const d = new Date(s.startsAt);
  return `${s.label} · ${Number.isNaN(d.getTime()) ? s.startsAt : d.toLocaleString(undefined, { weekday: "short", hour: "2-digit", minute: "2-digit" })}`;
}

/** `<input type="datetime-local">` value ↔ RFC 3339 UTC. */
export function toLocalInput(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "";
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}
export function fromLocalInput(v: string): string {
  const d = new Date(v);
  return Number.isNaN(d.getTime()) ? "" : d.toISOString().replace(/\.\d{3}Z$/, "Z");
}

/** The ordering VTI-BRD-001 requires, checked before sending so the form can say which. */
export function scheduleProblem(p: { opensAt: string; closesAt: string }, v: { opensAt: string; closesAt: string }): string | null {
  const po = Date.parse(p.opensAt);
  const pc = Date.parse(p.closesAt);
  const vo = Date.parse(v.opensAt);
  const vc = Date.parse(v.closesAt);
  if ([po, pc, vo, vc].some((x) => Number.isNaN(x))) return "Set all four times.";
  if (pc <= po) return "Proposals must close after they open.";
  if (vc <= vo) return "Voting must close after it opens.";
  if (vo <= po) return "Voting must open after proposals open.";
  if (vc <= pc) return "Voting must close after proposals close.";
  return null;
}
