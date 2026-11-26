// How the portal lays out a room used for chat (`conversation.ts`). The reading
// rules are the wallet's; what is pinned here is what the page does with them.

import { describe, expect, it } from "vitest";

import {
  absentWords,
  byDay,
  dayLabel,
  excerpt,
  highestVersion,
  isConversation,
  reactedWith,
  reactionValueOk,
  rewatchDelay,
  runsOf,
  shownTime,
  speakerOf,
} from "./conversation";
import type { ConversationRecord } from "./wallet-rooms";

const rec = (over: Partial<ConversationRecord>): ConversationRecord => ({
  key: "k",
  version: 1,
  shown: "message",
  written: {},
  orderAt: "2026-11-24T12:00:00Z",
  orderedBy: "createdAt",
  reactions: [],
  ...over,
});

describe("a room used for chat", () => {
  it("is one holding a message, or a withdrawn one; notes alone are not", () => {
    expect(isConversation({ records: [rec({ shown: "note" })] })).toBe(false);
    expect(isConversation({ records: [rec({ shown: "note" }), rec({ shown: "message" })] })).toBe(true);
    expect(isConversation({ records: [rec({ shown: "withdrawn" })] })).toBe(true);
    expect(isConversation({ records: [] })).toBe(false);
  });

  it("names the member You, another by their own name in the room, else the directory's, else by the DID", () => {
    const byDid = (d: string) => `did(${d})`;
    const none = { own: false, ownName: false, directory: false, did: false };
    const listed = (d: string) => ({ "did:a": "Alberto in the directory", "did:c": " Carol " })[d];
    expect(speakerOf("did:me", "did:me", { "did:me": "Geoff" }, byDid, listed)).toEqual({ ...none, label: "You", own: true });
    // The wallet's reading of the room comes first, so every surface names an author alike.
    expect(speakerOf("did:a", "did:me", { "did:a": " Alberto " }, byDid, listed)).toEqual({ ...none, label: "Alberto", ownName: true });
    // Where the room gives no name, the directory's.
    expect(speakerOf("did:c", "did:me", {}, byDid, listed)).toEqual({ ...none, label: "Carol", directory: true });
    // Else the DID, marked as one.
    expect(speakerOf("did:b", "did:me", {}, byDid, listed)).toEqual({ ...none, label: "did(did:b)", did: true });
    expect(speakerOf("did:b", "did:me", {}, byDid)).toEqual({ ...none, label: "did(did:b)", did: true });
    expect(speakerOf(undefined, "did:me", {}, byDid)).toEqual({ ...none, label: "Someone" });
  });

  it("shows the author's plausible claim of when, else the room's time, and nothing for an implausible claim", () => {
    expect(shownTime(rec({ written: { at: "2026-11-24T09:00:00Z" } }))).toBe("2026-11-24T09:00:00Z");
    expect(shownTime(rec({}))).toBe("2026-11-24T12:00:00Z");
    expect(shownTime(rec({ written: { implausible: true } }))).toBeUndefined();
  });

  it("puts a divider wherever the day changes, in the wallet's order", () => {
    const now = new Date(2026, 10, 24, 18, 0);
    const at = (d: number, h: number) => new Date(2026, 10, d, h).toISOString();
    const groups = byDay(
      [rec({ key: "a", orderAt: at(17, 23) }), rec({ key: "b", orderAt: at(23, 9) }), rec({ key: "c", orderAt: at(24, 9) }), rec({ key: "d", orderAt: at(24, 10) })],
      now,
    );
    expect(groups.map((g) => [g.day === "Today" || g.day === "Yesterday" ? g.day : "other", g.records.map((r) => r.key)])).toEqual([
      ["other", ["a"]],
      ["Yesterday", ["b"]],
      ["Today", ["c", "d"]],
    ]);
    expect(dayLabel(at(17, 23), now)).not.toMatch(/2026/);
    expect(dayLabel(new Date(2025, 0, 2).toISOString(), now)).toMatch(/2025/);
  });

  it("quotes a reply's target by its title, else its words, on one short line", () => {
    expect(excerpt({ title: "Agenda", body: "x" })).toBe("Agenda");
    expect(excerpt({ body: "one\ntwo" })).toBe("one two");
    expect([...excerpt({ body: "x".repeat(200) }, 10)].length).toBe(10);
  });

  it("says what stands where a record cannot be shown, and never its content", () => {
    expect(absentWords({ shown: "withdrawn" })).toMatch(/withdrawn/);
    expect(absentWords({ shown: "refused" })).toMatch(/did not verify/);
    expect(absentWords({ shown: "message" })).toBe("");
  });
});

describe("runs of one author's messages", () => {
  const at = (m: number) => new Date(Date.UTC(2026, 10, 24, 12, m)).toISOString();
  const msg = (key: string, author: string | undefined, m: number, over: Partial<ConversationRecord> = {}) =>
    rec({ key, author, written: { at: at(m) }, orderAt: at(m), ...over });
  const shape = (rs: ConversationRecord[]) => runsOf(rs).map((p) => `${p.first ? "F" : "-"}${p.last ? "L" : "-"}`);

  it("groups consecutive messages by one author within five minutes", () => {
    expect(shape([msg("a", "did:a", 0), msg("b", "did:a", 2), msg("c", "did:a", 6)])).toEqual(["F-", "--", "-L"]);
  });

  it("starts a new run on another author, a longer gap, or anything but a message", () => {
    expect(shape([msg("a", "did:a", 0), msg("b", "did:b", 1), msg("c", "did:b", 9)])).toEqual(["FL", "FL", "FL"]);
    expect(
      shape([msg("a", "did:a", 0), msg("n", "did:a", 1, { shown: "note" }), msg("c", "did:a", 2)]),
    ).toEqual(["FL", "FL", "FL"]);
    expect(shape([msg("a", undefined, 0), msg("b", undefined, 1)])).toEqual(["FL", "FL"]);
  });

  it("keeps the wallet's order and merges nothing", () => {
    const rs = [msg("a", "did:a", 3), msg("b", "did:a", 1)];
    const placed = runsOf(rs);
    expect(placed.map((p) => p.r.key)).toEqual(["a", "b"]);
    // An earlier time after a later one is not read as a run.
    expect(shape(rs)).toEqual(["FL", "FL"]);
  });

  it("takes a reaction a wallet takes: one line, not empty, at most 64 characters", () => {
    expect(reactionValueOk("👍")).toBe(true);
    expect(reactionValueOk("nice")).toBe(true);
    expect(reactionValueOk("")).toBe(false);
    expect(reactionValueOk("a\nb")).toBe(false);
    expect(reactionValueOk("x".repeat(64))).toBe(true);
    expect(reactionValueOk("x".repeat(65))).toBe(false);
  });

  it("knows the member's own reaction, so a click takes it back", () => {
    const rs = [{ value: "👍", authors: ["did:a", "did:me"] }, { value: "😮", authors: ["did:a"] }];
    expect(reactedWith(rs, "👍", "did:me")).toBe(true);
    expect(reactedWith(rs, "😮", "did:me")).toBe(false);
    expect(reactedWith(rs, "👍", undefined)).toBe(false);
  });

  it("tells a watch the highest version read, and waits longer after each close, to a minute", () => {
    expect(highestVersion([{ version: 3 }, { version: 9 }, { version: 4 }])).toBe(9);
    expect(highestVersion([])).toBeUndefined();
    expect([0, 1, 2, 3].map(rewatchDelay)).toEqual([1000, 2000, 4000, 8000]);
    expect(rewatchDelay(20)).toBe(60_000);
  });
});
