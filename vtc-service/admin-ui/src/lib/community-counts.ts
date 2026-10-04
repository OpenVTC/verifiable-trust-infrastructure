// Two counts the shell and the dashboard show: join requests awaiting an
// administrator's decision (the Join requests nav badge and dashboard tile) and
// current members (the Members tile).
//
// Each is **one read**: `vtc/join-requests/list/0.1` and `vtc/members/list/0.1`
// answer `Paginated` pages whose `totalEstimate` the VTC fills with the exact
// number of rows the request's filter admits, and the filter is applied before
// paging (`join::storage::list_join_requests_filtered`,
// `members::storage::list_members_filtered`). So a `limit: 1` page carries the
// count, whatever the community's size. Until the VTC filled it, a count was a
// walk of every page — and since the status filter ran after each page was
// cut, a page could be empty with a `nextCursor`, so only the cursor running
// out said the count was complete.
//
// A VTC that leaves `totalEstimate` out is answered with the floor the one
// page shows (`more`, rendered `N+`); the console is not built for one
// (`vtc-action-list.md` §8a), but a badge must never take the shell down.

import { useQuery } from "@tanstack/react-query";

import { postSignedRead } from "./api";
import { useRefetchWhenSeen } from "./action-badge";
import { useLivePollMs } from "./use-live-events";
import { holds } from "./viewer";
import type { JoinRequestsPage, MembersPage } from "./wire-types";

export const JOIN_REQUESTS_LIST_TASK = "https://trusttasks.org/spec/vtc/join-requests/list/0.1";
export const MEMBERS_LIST_TASK = "https://trusttasks.org/spec/vtc/members/list/0.1";

/** The Join requests plugin's id — the shell draws its nav badge. */
export const JOIN_REQUESTS_PLUGIN_ID = "join-requests";

/** What each count needs, as the nav entries they sit beside do. */
export const JOIN_DECIDE_CAP = "vtc.join.decide";
export const MEMBERS_MANAGE_CAP = "vtc.members.manage";

/** Page size for each count: one row — the count is `totalEstimate`. */
export const COUNT_PAGE_SIZE = 1;

/** Under the Join requests page's own `["join-requests"]` prefix, so a
 *  decision there (which invalidates that prefix) refreshes the badge too. */
export const PENDING_JOIN_REQUESTS_KEY = ["join-requests", "pending-count"] as const;
/** Likewise under the Members page's `["members"]` prefix. */
export const MEMBER_COUNT_KEY = ["members", "count"] as const;

/** A count, and whether it is only a floor (no `totalEstimate` came back). */
export interface Tally {
  count: number;
  more: boolean;
}

/** `12`, or `1+` when the VTC gave no total. */
export function formatTally(t: Tally): string {
  return `${t.count}${t.more ? "+" : ""}`;
}

/** The count a page reports: its `totalEstimate`, or the floor its rows and
 *  cursor show when it has none. */
export function tallyOf(page: {
  items: unknown[];
  nextCursor?: string | null;
  totalEstimate?: number | null;
}): Tally {
  if (typeof page.totalEstimate === "number") {
    return { count: page.totalEstimate, more: false };
  }
  return { count: page.items.length, more: Boolean(page.nextCursor) };
}

async function tally(task: string, filter: Record<string, unknown>): Promise<Tally> {
  const page: JoinRequestsPage | MembersPage = await postSignedRead(task, {
    ...filter,
    limit: COUNT_PAGE_SIZE,
  });
  return tallyOf(page);
}

/** Join requests awaiting an administrator's decision. */
export function countPendingJoinRequests(): Promise<Tally> {
  return tally(JOIN_REQUESTS_LIST_TASK, { status: "pending" });
}

/** Current members. */
export function countMembers(): Promise<Tally> {
  return tally(MEMBERS_LIST_TASK, {});
}

/** Whether `caps` holds `cap` anywhere — how the nav decides what to show. */
export function mayCount(caps: ReadonlyArray<string> | null | undefined, cap: string): boolean {
  return holds(caps, cap, "*");
}

/**
 * Pending join requests, kept fresh while `enabled` the way the Actions badge
 * is: fetched when enabled (sign-in), when the tab regains focus or becomes
 * visible, when the live channel hints at `joinRequests`, and on the same poll
 * (60 s offline, 5 minutes live). `undefined` while unknown or on failure — a badge
 * is decoration and must never take the shell down.
 */
export function usePendingJoinRequests(enabled: boolean): Tally | undefined {
  const query = usePendingJoinRequestsQuery(enabled);
  return enabled ? query.data : undefined;
}

/** [`usePendingJoinRequests`]'s query, whole — the dashboard tile shows its
 *  loading and failure states too. One cache entry serves both. */
export function usePendingJoinRequestsQuery(enabled: boolean) {
  const pollMs = useLivePollMs();
  const query = useQuery({
    queryKey: PENDING_JOIN_REQUESTS_KEY,
    queryFn: countPendingJoinRequests,
    enabled,
    refetchInterval: enabled ? pollMs : false,
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
