// The home page's status lines and attention items.

import { describe, expect, it } from "vitest";

import { DirectoryError } from "./directory-api";
import {
  boardsAttention,
  boardsStatus,
  electionsAttention,
  electionsStatus,
  groupsStatus,
  reposStatus,
  roomsAttention,
  roomsStatus,
  type Read,
} from "./home-status";
import type { PageElection } from "./wallet-elections";
import type { PageOffer } from "./wallet-rooms";

const NOW = Date.parse("2026-11-04T12:00:00Z");
const at = (days: number) => new Date(NOW + days * 86_400_000).toISOString();
const ok = <T>(data: T): Read<T> => ({ data, isPending: false, isError: false });
const pending: Read<never> = { isPending: true, isError: false };
const failed = (error: unknown): Read<never> => ({ isPending: false, isError: true, error });

const election = (id: string, state: string, opens: number, closes: number, ticketHeld = false): PageElection => ({
  electionId: id,
  title: id,
  state,
  votingOpensAt: at(opens),
  votingClosesAt: at(closes),
  binding: false,
  ticketHeld,
});

const offer = (state: string) => ({ roomId: `did:r:${state}`, state }) as unknown as PageOffer;

describe("rooms", () => {
  it("says the wallet is needed when there is none", () => {
    expect(roomsStatus(false, pending, null)).toEqual({ text: "Needs the VTA wallet extension", tone: "muted" });
  });
  it("counts shared rooms and only the offers a member can act on", () => {
    const offers = ok({ offers: [offer("offered"), offer("joined")] });
    expect(roomsStatus(true, ok([{ roomId: "a" }, { roomId: "b" }] as never), offers)).toEqual({
      text: "2 rooms shared · 1 offer waiting",
      tone: "attention",
    });
    expect(roomsAttention(offers)).toHaveLength(1);
  });
  it("is loading until the wallet answers", () => {
    expect(roomsStatus(true, pending, null)).toBe("loading");
  });
});

describe("elections", () => {
  const list = ok({
    elections: [
      election("vote-now", "voting", -1, 2, true),
      election("tickets", "registered", 2, 4),
      election("held", "registered", 2, 4, true),
      election("done", "tallied", -5, -2),
    ],
  });
  it("summarises by stage", () => {
    expect(electionsStatus(true, list, NOW)).toEqual({
      text: "1 open for voting · 2 taking tickets",
      tone: "attention",
    });
  });
  it("asks for attention on open voting and on a ticket not yet taken", () => {
    expect(electionsAttention(list, (id) => `#/e/${id}`, NOW).map((a) => a.href)).toEqual([
      "#/e/vote-now",
      "#/e/tickets",
    ]);
  });
  it("says nothing is open when nothing is", () => {
    expect(electionsStatus(true, ok({ elections: [election("done", "closed", -5, -2)] }), NOW)).toEqual({
      text: "Nothing open right now",
      tone: "muted",
    });
  });
});

describe("boards", () => {
  const board = (boardId: string, p: [number, number], v: [number, number], status = "open") => ({
    boardId,
    title: boardId,
    status,
    proposals: { opensAt: at(p[0]), closesAt: at(p[1]) },
    voting: { opensAt: at(v[0]), closesAt: at(v[1]) },
  });
  const q = ok({ boards: [board("ideas", [-1, 2], [3, 5]), board("later", [2, 3], [4, 5])] } as never);
  it("counts boards taking ideas and coming up", () => {
    expect(boardsStatus(q, NOW)).toEqual({ text: "1 taking ideas · 1 coming up", tone: "attention" });
    expect(boardsAttention(q, (id) => id, NOW).map((a) => a.text)).toEqual(["Taking proposals: ideas"]);
  });
  it("tells a member without a wallet key how to see it", () => {
    expect(boardsStatus(failed(new DirectoryError("noKey", "x")), NOW)).toEqual({
      text: "Sign in with your wallet to see this",
      tone: "muted",
    });
  });
});

describe("groups and repositories", () => {
  it("counts the groups the member is in and waiting on", () => {
    const items = ["member", "member", "requested", "none"].map((m) => ({ group: {}, myMembership: m }));
    expect(groupsStatus(ok({ items } as never))).toEqual({ text: "Member of 2 groups · 1 pending", tone: "ok" });
  });
  it("tells repositories from namespaces", () => {
    const view = {
      namespaces: [],
      repos: [{ resource: "github.com/acme/widgets", owners: [] }],
      rights: [
        { subject: "me", right: "git.repo.own", resource: "github.com/acme/widgets" },
        { subject: "me", right: "git.commit.sign", resource: "github.com/acme" },
        { subject: "bob", right: "git.repo.own", resource: "github.com/acme/gadgets" },
      ],
      accounts: [],
    };
    expect(reposStatus(ok(view as never), "me")).toEqual({ text: "1 repository · 1 namespace", tone: "ok" });
  });
});
