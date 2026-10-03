// Two counts the shell and the dashboard show: join requests awaiting an
// administrator's decision (the Join requests nav badge and dashboard tile) and
// current members (the Members tile).
//
// Neither listing carries a count. `vtc/join-requests/list/0.1` and
// `vtc/members/list/0.1` both answer `Paginated` pages whose `totalEstimate`
// the VTC leaves unset, so a count is the pages walked to the end. The
// join-request status filter is applied to each page after it is read
// (`routes::join_requests::read::list_join_requests_inner`), so a page can hold
// no pending request and still carry a `nextCursor`: only the cursor running
// out says the count is complete. The walk is bounded; past the bound the
// count is reported as a floor (`more`), shown as `N+`.
//
// Pages are the schema maximum (200 for both, `lib/list-limits.json`): the
// fewest reads, and never more than the listing accepts — the admission
// criteria bug (#1921) was a page size over the maximum.

import { useQuery } from "@tanstack/react-query";

import { postSignedRead } from "./api";
import { useRefetchWhenSeen, WAITING_POLL_MS } from "./action-badge";
import { holds } from "./viewer";
import type { JoinRequestsPage, MembersPage } from "./wire-types";

export const JOIN_REQUESTS_LIST_TASK = "https://trusttasks.org/spec/vtc/join-requests/list/0.1";
export const MEMBERS_LIST_TASK = "https://trusttasks.org/spec/vtc/members/list/0.1";

/** The Join requests plugin's id — the shell draws its nav badge. */
export const JOIN_REQUESTS_PLUGIN_ID = "join-requests";

/** What each count needs, as the nav entries they sit beside do. */
export const JOIN_DECIDE_CAP = "vtc.join.decide";
export const MEMBERS_MANAGE_CAP = "vtc.members.manage";

/** Page size for both walks: each listing's schema maximum. */
export const COUNT_PAGE_SIZE = 200;
/** Pages walked before a count is reported as a floor (10 000 rows). */
export const MAX_COUNT_PAGES = 50;

/** Under the Join requests page's own `["join-requests"]` prefix, so a
 *  decision there (which invalidates that prefix) refreshes the badge too. */
export const PENDING_JOIN_REQUESTS_KEY = ["join-requests", "pending-count"] as const;
/** Likewise under the Members page's `["members"]` prefix. */
export const MEMBER_COUNT_KEY = ["members", "count"] as const;

/** A count, and whether there were more rows than the walk read. */
export interface Tally {
  count: number;
  more: boolean;
}

/** `12`, or `10000+` when the walk stopped at its bound. */
export function formatTally(t: Tally): string {
  return `${t.count}${t.more ? "+" : ""}`;
}

async function tally<T>(
  task: string,
  filter: Record<string, unknown>,
  keep: (item: T) => boolean,
): Promise<Tally> {
  let count = 0;
  let cursor: string | null = null;
  for (let page = 0; page < MAX_COUNT_PAGES; page++) {
    const body: { items: T[]; nextCursor?: string | null } = await postSignedRead(task, {
      ...filter,
      limit: COUNT_PAGE_SIZE,
      ...(cursor ? { cursor } : {}),
    });
    count += body.items.filter(keep).length;
    cursor = body.nextCursor ?? null;
    if (!cursor) return { count, more: false };
  }
  return { count, more: true };
}

/** Join requests awaiting an administrator's decision. */
export function countPendingJoinRequests(): Promise<Tally> {
  // The VTC filters to the status asked for; the item check holds the count to
  // it should a page ever come back unfiltered.
  return tally<JoinRequestsPage["items"][number]>(
    JOIN_REQUESTS_LIST_TASK,
    { status: "pending" },
    (r) => r.status === "pending",
  );
}

/** Current members. */
export function countMembers(): Promise<Tally> {
  return tally<MembersPage["items"][number]>(MEMBERS_LIST_TASK, {}, () => true);
}

/** Whether `caps` holds `cap` anywhere — how the nav decides what to show. */
export function mayCount(caps: ReadonlyArray<string> | null | undefined, cap: string): boolean {
  return holds(caps, cap, "*");
}

/**
 * Pending join requests, kept fresh while `enabled` the way the Actions badge
 * is: fetched when enabled (sign-in), when the tab regains focus or becomes
 * visible, and every 60 s. `undefined` while unknown or on failure — a badge
 * is decoration and must never take the shell down.
 */
export function usePendingJoinRequests(enabled: boolean): Tally | undefined {
  const query = usePendingJoinRequestsQuery(enabled);
  return enabled ? query.data : undefined;
}

/** [`usePendingJoinRequests`]'s query, whole — the dashboard tile shows its
 *  loading and failure states too. One cache entry serves both. */
export function usePendingJoinRequestsQuery(enabled: boolean) {
  const query = useQuery({
    queryKey: PENDING_JOIN_REQUESTS_KEY,
    queryFn: countPendingJoinRequests,
    enabled,
    refetchInterval: enabled ? WAITING_POLL_MS : false,
    refetchIntervalInBackground: true,
    refetchOnWindowFocus: false,
    staleTime: 0,
    retry: false,
  });
  useRefetchWhenSeen(enabled, query.refetch);
  return query;
}

/** Current members, while `enabled`, for the dashboard tile. */
export function useMemberCount(enabled: boolean) {
  return useQuery({
    queryKey: MEMBER_COUNT_KEY,
    queryFn: countMembers,
    enabled,
    retry: false,
  });
}
