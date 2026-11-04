// What the home page says about each part of the portal: one status line per
// tile, and the few things worth the member's attention now. Pure functions
// over the answers the pages themselves read, so the home page and the pages
// share one query each and never disagree.

import type { BoardListResponse, GroupListResponse } from "@/lib/wire-types";

import { phaseOf, PHASE_LABEL } from "./boards-api";
import { DirectoryError } from "./directory-api";
import { holdingsOf, type MemberGitView } from "./git-api";
import { notifiedOnly, stageOf, type ElectionList, type PageNotifiedElection } from "./wallet-elections";
import { actionableOffers, type PageOffer, type PageRoom } from "./wallet-rooms";

/** A tile's status line. `attention`: something the member can act on now. */
export interface Status {
  text: string;
  tone: "ok" | "attention" | "muted";
}

/** One thing worth the member's attention, linked to where they act on it. */
export interface Attention {
  key: string;
  text: string;
  href: string;
}

/** The query states a status reads; the home page passes `useQuery`'s. */
export interface Read<T> {
  data?: T;
  isPending: boolean;
  isError: boolean;
  error?: unknown;
}

export function plural(n: number, one: string, many = `${one}s`): string {
  return `${n} ${n === 1 ? one : many}`;
}

const muted = (text: string): Status => ({ text, tone: "muted" });

/** A read that has no answer yet, or failed: the status that says so, else `null`. */
function unanswered<T>(q: Read<T>): Status | "loading" | null {
  if (q.isError) {
    if (q.error instanceof DirectoryError && q.error.needsWallet) return muted("Sign in with your wallet to see this");
    return muted("Couldn't load right now");
  }
  if (q.isPending || q.data === undefined) return "loading";
  return null;
}

/** The member's rooms: how many are shared with this portal, and offers waiting. */
export function roomsStatus(
  hasWallet: boolean,
  rooms: Read<PageRoom[]>,
  offers: Read<{ offers: PageOffer[] }> | null,
): Status | "loading" {
  if (!hasWallet) return muted("Needs the VTA wallet extension");
  if (rooms.isError) return muted("Your wallet didn't answer");
  if (rooms.isPending || !rooms.data) return "loading";
  const waiting = offers?.data ? actionableOffers(offers.data.offers).length : 0;
  const parts = [rooms.data.length === 0 ? "No rooms shared yet" : `${plural(rooms.data.length, "room")} shared`];
  if (waiting > 0) parts.push(`${plural(waiting, "offer")} waiting`);
  return { text: parts.join(" · "), tone: waiting > 0 ? "attention" : rooms.data.length > 0 ? "ok" : "muted" };
}

export function roomsAttention(offers: Read<{ offers: PageOffer[] }> | null): Attention[] {
  const waiting = offers?.data ? actionableOffers(offers.data.offers).length : 0;
  return waiting > 0
    ? [{ key: "room-offers", text: `${plural(waiting, "room offer")} from the community`, href: "#/rooms" }]
    : [];
}

/** The notified elections the member can still act on that the community's list does not show
 *  them: one per election (`notifiedOnly`), a notice still standing — a withdrawn one cannot be
 *  opened (VTI-NTF-024) — and, where it states one, a voting period not yet over. Read only from
 *  what the notification says (VTI-NTF-063). */
export function actionableNotified(list: ElectionList, now = Date.now()): PageNotifiedElection[] {
  return notifiedOnly(list).filter(
    (n) => n.status === "available" && !(n.votingClosesAt && now >= Date.parse(n.votingClosesAt)),
  );
}

/** Elections, by where each stands for the member, and those they were told about. */
export function electionsStatus(hasWallet: boolean, q: Read<ElectionList>, now = Date.now()): Status | "loading" {
  if (!hasWallet) return muted("Needs the VTA wallet extension");
  if (q.isError) return muted("Your wallet didn't answer");
  if (q.isPending || !q.data) return "loading";
  const stages = q.data.elections.map((e) => stageOf(e, now));
  const voting = stages.filter((s) => s === "voting").length;
  const tickets = stages.filter((s) => s === "ticketsOpen").length;
  const upcoming = stages.filter((s) => s === "upcoming").length;
  const told = actionableNotified(q.data, now).length;
  const parts: string[] = [];
  if (voting) parts.push(`${voting} open for voting`);
  if (tickets) parts.push(`${tickets} taking tickets`);
  if (upcoming) parts.push(`${upcoming} coming up`);
  if (told) parts.push(`${told} you were told about`);
  if (parts.length === 0) return muted("Nothing open right now");
  return { text: parts.join(" · "), tone: voting || tickets || told ? "attention" : "ok" };
}

/** `href` is the Elections page's own link, so the election page takes `memberOf` from the
 *  standing notice in the shared list — never from the link. */
export function electionsAttention(
  q: Read<ElectionList>,
  href: (electionId: string) => string,
  now = Date.now(),
): Attention[] {
  if (!q.data) return [];
  const listed = q.data.elections.flatMap((e): Attention[] => {
    const s = stageOf(e, now);
    const title = e.title || "An election";
    if (s === "voting") {
      return [{ key: `el-${e.electionId}`, text: `Voting is open: ${title}`, href: href(e.electionId) }];
    }
    if (s === "ticketsOpen" && !e.ticketHeld) {
      return [{ key: `el-${e.electionId}`, text: `Take your ticket: ${title}`, href: href(e.electionId) }];
    }
    return [];
  });
  // Only the identifier is known of these until the member opens one.
  const told = actionableNotified(q.data, now).map(
    (n): Attention => ({
      key: `el-${n.electionId}`,
      text:
        n.votingOpensAt && now >= Date.parse(n.votingOpensAt)
          ? `Voting is open: ${n.electionId} (you were told about it)`
          : `You were told about an election: ${n.electionId}`,
      href: href(n.electionId),
    }),
  );
  return [...listed, ...told];
}

/** Boards that are not archived, by phase. */
export function boardsStatus(q: Read<BoardListResponse>, now = Date.now()): Status | "loading" {
  const u = unanswered(q);
  if (u) return u;
  const phases = q.data!.boards.map((b) => phaseOf(b, now));
  const proposing = phases.filter((p) => p === "proposals" || p === "proposalsAndVoting").length;
  const voting = phases.filter((p) => p === "voting" || p === "proposalsAndVoting").length;
  const upcoming = phases.filter((p) => p === "upcoming").length;
  const parts: string[] = [];
  if (proposing) parts.push(`${proposing} taking ideas`);
  if (voting) parts.push(`${voting} voting`);
  if (upcoming) parts.push(`${upcoming} coming up`);
  if (parts.length === 0) return muted("No open boards");
  return { text: parts.join(" · "), tone: proposing || voting ? "attention" : "ok" };
}

export function boardsAttention(
  q: Read<BoardListResponse>,
  href: (boardId: string) => string,
  now = Date.now(),
): Attention[] {
  return (q.data?.boards ?? []).flatMap((b): Attention[] => {
    const p = phaseOf(b, now);
    if (p !== "proposals" && p !== "proposalsAndVoting" && p !== "voting") return [];
    return [{ key: `bd-${b.boardId}`, text: `${PHASE_LABEL[p]}: ${b.title}`, href: href(b.boardId) }];
  });
}

/** The groups the member is in, and where they are waiting to be. */
export function groupsStatus(q: Read<GroupListResponse>): Status | "loading" {
  const u = unanswered(q);
  if (u) return u;
  const items = q.data!.items;
  const mine = items.filter((i) => i.myMembership === "member").length;
  const waiting = items.filter((i) => i.myMembership === "requested" || i.myMembership === "pending").length;
  if (items.length === 0) return muted("No groups yet");
  const parts = [mine > 0 ? `Member of ${plural(mine, "group")}` : `${plural(items.length, "group")} to explore`];
  if (waiting) parts.push(`${waiting} pending`);
  return { text: parts.join(" · "), tone: mine > 0 ? "ok" : "muted" };
}

/** What the member holds on the community's repositories. */
export function reposStatus(q: Read<MemberGitView>, did: string): Status | "loading" {
  const u = unanswered(q);
  if (u) return u;
  const holdings = holdingsOf(q.data!, did);
  const known = new Set(q.data!.repos.map((r) => r.resource));
  const repos = holdings.filter((h) => known.has(h.resource)).length;
  const namespaces = holdings.length - repos;
  const accounts = q.data!.accounts.length;
  if (holdings.length === 0 && accounts === 0) return muted("No repository rights yet");
  const parts: string[] = [];
  if (repos) parts.push(plural(repos, "repository", "repositories"));
  if (namespaces) parts.push(plural(namespaces, "namespace"));
  if (accounts) parts.push(`${plural(accounts, "forge account")} linked`);
  return { text: parts.join(" · "), tone: "ok" };
}
