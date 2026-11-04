// Where an election came from: a community board, or nowhere in particular.
//
// An election a board opens for an idea is named `board.<boardId>.<ideaId>` (VTI-BRD-031,
// `vtc-service/src/boards/mod.rs` `election_id_for`). That convention is all this reads — no
// wire member says it — so an identifier that only resembles it is a stand-alone election.
// Pure: shared by the console and the member portal, which import nothing of each other's.

const BOARD_ELECTION = /^board\.(brd_[A-Za-z0-9_-]{16,64})\.(ida_[A-Za-z0-9_-]{16,64})$/;

/** The board and idea an election was opened for, or `null` for a stand-alone election. */
export function boardOfElection(electionId: string): { boardId: string; ideaId: string } | null {
  const m = BOARD_ELECTION.exec(electionId);
  return m ? { boardId: m[1]!, ideaId: m[2]! } : null;
}

export interface BoardGroup<T> {
  boardId: string;
  /** The board's title, or a stand-in when it is not known (see `groupByBoard`). */
  title: string;
  /** Whether the title came from the boards list. */
  known: boolean;
  items: T[];
}

export interface Grouped<T> {
  standalone: T[];
  boards: BoardGroup<T>[];
}

/** "Board brd_ff-8cTg…": a board named by its identifier alone. */
export function boardStandIn(boardId: string): string {
  const tail = boardId.slice(4);
  return `Board ${tail.length > 8 ? `${tail.slice(0, 8)}…` : tail}`;
}

/**
 * Splits elections into stand-alone ones and one group per board, keeping the order they came
 * in, within and across groups.
 *
 * `titles`: board identifier → title, from the boards list. `null` when there is no list to read
 * (the read failed, or this viewer may not make it): every board is then named by its identifier.
 * A board absent from a list that was read is `missing` — deleted, or not one this viewer sees.
 */
export function groupByBoard<T extends { electionId: string }>(
  items: readonly T[],
  titles: ReadonlyMap<string, string> | null,
  missing: string,
): Grouped<T> {
  const standalone: T[] = [];
  const byBoard = new Map<string, BoardGroup<T>>();
  for (const item of items) {
    const origin = boardOfElection(item.electionId);
    if (!origin) {
      standalone.push(item);
      continue;
    }
    let group = byBoard.get(origin.boardId);
    if (!group) {
      const title = titles?.get(origin.boardId);
      group = {
        boardId: origin.boardId,
        title: title ?? (titles ? missing : boardStandIn(origin.boardId)),
        known: title !== undefined,
        items: [],
      };
      byBoard.set(origin.boardId, group);
    }
    group.items.push(item);
  }
  return { standalone, boards: [...byBoard.values()] };
}

/** "3 voting · 1 taking tickets": how many of a group's elections are at each stage, in first-seen order. */
export function stageSummary<T>(items: readonly T[], label: (item: T) => string): string {
  const counts = new Map<string, number>();
  for (const item of items) {
    const l = label(item);
    counts.set(l, (counts.get(l) ?? 0) + 1);
  }
  return [...counts].map(([l, n]) => `${n} ${l.toLowerCase()}`).join(" · ");
}
