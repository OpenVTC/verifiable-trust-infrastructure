// A data room used for chat, as the portal shows it: who said what, when, and
// in what order — the same reading of the room the member's other surfaces
// show (the wallet's console, Keyring), because the wallet applies the reading
// rules and this page only lays out what it was handed (`rooms.conversation`).
//
// Pure: nothing here asks the wallet anything.

import type { Conversation, ConversationRecord } from "./wallet-rooms";

/**
 * Whether a room is being used for chat: it holds a message, or a message its
 * author withdrew. A room of notes and files stays a list of records.
 */
export function isConversation(c: Pick<Conversation, "records">): boolean {
  return c.records.some((r) => r.shown === "message" || r.shown === "withdrawn");
}

/** Who wrote something, for a message's header. */
export interface Speaker {
  label: string;
  /** The member this page acts as. */
  own: boolean;
  /** `label` is the name the author gave themselves in this room: their claim, said as such. */
  ownName: boolean;
  /** `label` is the name the community's directory shows this member for the author. */
  directory: boolean;
  /** `label` is the author's DID, shortened: there is no name to go by. */
  did: boolean;
}

/**
 * The member themselves as "You"; another author by the name they gave
 * themselves in this room, marked as their own — the wallet's reading, which
 * every surface shows alike; else by the name the community's directory shows
 * this member for their DID; else by their DID's short form, marked as a DID.
 */
export function speakerOf(
  author: string | undefined,
  me: string | undefined,
  names: Record<string, string>,
  /** How the page names a DID with no name in this room (`authorName`). */
  byDid: (did: string) => string,
  /** The directory's name for a DID, where it shows one to this member (`room-authors.ts`). */
  directory: (did: string) => string | null | undefined = () => undefined,
): Speaker {
  const none = { own: false, ownName: false, directory: false, did: false };
  if (author === undefined) return { ...none, label: "Someone" };
  if (me !== undefined && author === me) return { ...none, label: "You", own: true };
  const name = names[author]?.trim();
  if (name) return { ...none, label: name, ownName: true };
  const listed = directory(author)?.trim();
  if (listed) return { ...none, label: listed, directory: true };
  return { ...none, label: byDid(author), did: true };
}

/** The instant to show for a record: the author's plausible claim, else when the room got it. None for an implausible claim. */
export function shownTime(r: Pick<ConversationRecord, "written" | "orderAt">): string | undefined {
  if (r.written.at !== undefined) return r.written.at;
  if (r.written.implausible) return undefined;
  return r.orderAt;
}

function localDay(d: Date): string {
  return `${d.getFullYear()}-${d.getMonth()}-${d.getDate()}`;
}

/** A day divider's words: "Today", "Yesterday", "Tue 17 Nov", or with its year when not this year's. */
export function dayLabel(iso: string, now: Date = new Date()): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "";
  if (localDay(d) === localDay(now)) return "Today";
  const yesterday = new Date(now);
  yesterday.setDate(now.getDate() - 1);
  if (localDay(d) === localDay(yesterday)) return "Yesterday";
  return d.toLocaleDateString(undefined, {
    weekday: "short",
    day: "numeric",
    month: "short",
    ...(d.getFullYear() !== now.getFullYear() ? { year: "numeric" } : {}),
  });
}

/** A message's time of day: "23:54" in the reader's locale. */
export function clockTime(iso: string): string {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? "" : d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });
}

/** The records in the wallet's order, under a divider wherever the day changes. */
export function byDay(
  records: readonly ConversationRecord[],
  now: Date = new Date(),
): { day: string; records: ConversationRecord[] }[] {
  const out: { day: string; key: string; records: ConversationRecord[] }[] = [];
  for (const r of records) {
    const d = new Date(r.orderAt);
    const key = Number.isNaN(d.getTime()) ? "" : localDay(d);
    const last = out[out.length - 1];
    if (last && last.key === key) last.records.push(r);
    else out.push({ day: key ? dayLabel(r.orderAt, now) : "", key, records: [r] });
  }
  return out.map(({ day, records: rs }) => ({ day, records: rs }));
}

/** A line of another record, for a reply's quote: its title, else the start of its text. */
export function excerpt(r: Pick<ConversationRecord, "title" | "body" | "file">, max = 80): string {
  const text = (r.title || r.body || r.file?.name || "").replace(/\s+/g, " ").trim();
  return [...text].length > max ? `${[...text].slice(0, max - 1).join("")}…` : text;
}

/** What stands in for a record that has nothing to show. */
export function absentWords(r: Pick<ConversationRecord, "shown">): string {
  switch (r.shown) {
    case "withdrawn":
      return "Message withdrawn by its author";
    case "retracted":
      return "Removed";
    case "placeholder":
      return "Its author could not be verified, so it is not shown";
    case "refused":
      return "Not shown: it did not verify";
    case "unreadable":
      return "Could not be opened";
    default:
      return "";
  }
}

/** How long between two messages by one author still reads as one run of them. */
export const RUN_GAP_MS = 5 * 60_000;

/** A record as the chat lays it out: whether it opens and closes a run of its author's messages. */
export interface Placed<R> {
  r: R;
  /** The first of a run: its author's name and avatar go here. */
  first: boolean;
  /** The last of a run: the next record is someone else's, or not a message, or later. */
  last: boolean;
}

/**
 * Group consecutive messages by one author, each within `gap` of the one before,
 * into runs — layout only: the records stay in the wallet's order, and nothing
 * is merged. A note, a file or an absent record always stands alone. Times are
 * the ones the page shows (`shownTime`), else when the room got the record.
 */
export function runsOf<R extends Pick<ConversationRecord, "author" | "shown" | "written" | "orderAt">>(
  records: readonly R[],
  gap = RUN_GAP_MS,
): Placed<R>[] {
  const at = (r: R) => Date.parse(shownTime(r) ?? r.orderAt);
  const joins = (a: R | undefined, b: R | undefined) => {
    if (!a || !b || a.shown !== "message" || b.shown !== "message") return false;
    if (a.author === undefined || a.author !== b.author) return false;
    const d = at(b) - at(a);
    return Number.isFinite(d) && d >= 0 && d <= gap;
  };
  return records.map((r, i) => ({
    r,
    first: !joins(records[i - 1], r),
    last: !joins(r, records[i + 1]),
  }));
}

// ── Replying, reacting, and staying current ────────────────────────────────

/** The reactions the picker offers. Any short value a wallet takes is shown as the wallet reads it. */
export const QUICK_REACTIONS = ["👍", "❤️", "😂", "😮", "😢", "🙏", "🎉", "👀"] as const;

/** Whether `value` is a reaction a wallet takes: not empty, one line, at most 64 characters. */
export function reactionValueOk(value: string): boolean {
  return value.length > 0 && [...value].length <= 64 && !/[\r\n]/.test(value);
}

/** Whether the member is among those who reacted with `value` — so a click takes it back. */
export function reactedWith(
  reactions: readonly { value: string; authors: readonly string[] }[],
  value: string,
  me: string | undefined,
): boolean {
  if (me === undefined) return false;
  return reactions.some((x) => x.value === value && x.authors.includes(me));
}

/** The highest record version the page holds: what a watch is told it has read. */
export function highestVersion(records: readonly Pick<ConversationRecord, "version">[]): number | undefined {
  let max: number | undefined;
  for (const r of records) if (max === undefined || r.version > max) max = r.version;
  return max;
}

/** How long to wait before watching again after the `attempt`-th close: doubling from a second, at most a minute. */
export function rewatchDelay(attempt: number): number {
  return Math.min(60_000, 1_000 * 2 ** Math.max(0, Math.min(attempt, 6)));
}
