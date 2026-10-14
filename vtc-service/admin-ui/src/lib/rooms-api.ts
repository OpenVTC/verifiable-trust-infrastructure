// The room-hosting administrator's reads and the one change made from them —
// `vtc/rooms/{get,usage,limits/set}/0.1` (docs/05-design-notes/data-rooms-files.md
// §6.3, §8.1).
//
// All three are answered from the host's own authority (`vtc.rooms.admin`),
// never a room's: nothing here needs or could use a room key, and nothing read
// here is derived from a room's contents. The host holds sizes, counts and —
// on an `attributed` room — which member added what. It never holds a record
// title, a file name or a file's contents, so neither does anything below.
//
// The pure helpers (date ranges, limit thresholds, CSV) are exported for their
// tests; the screens are `plugins/rooms/*`.

import { postSignedRead, postSignedTrustTask } from "./api";
import type {
  RoomGetResponse,
  RoomScopeLimits,
  RoomsLimitsSetPayload,
  RoomsLimitsSetResponse,
  RoomsUsagePayload,
  RoomsUsageResponse,
  RoomsUsageRow,
} from "./wire-types";

export const ROOMS_GET_TASK = "https://trusttasks.org/spec/vtc/rooms/get/0.1";
export const ROOMS_USAGE_TASK = "https://trusttasks.org/spec/vtc/rooms/usage/0.1";
export const ROOMS_LIMITS_SET_TASK = "https://trusttasks.org/spec/vtc/rooms/limits/set/0.1";

/** The refusal `vtc/rooms/usage` gives for per-member figures on a `private`
 *  room, whose membership this host cannot see. */
export const MEMBER_USAGE_UNAVAILABLE = "vtc/rooms/usage:memberUsageUnavailable";

export type UsageGroup = RoomsUsagePayload["groupBy"];
export type UsageFilter = NonNullable<RoomsUsagePayload["filter"]>;
export type UsageSort = NonNullable<RoomsUsagePayload["sort"]>;

/** One hosted room's host record, placement, limits and usage. */
export function fetchRoom(roomId: string): Promise<RoomGetResponse> {
  return postSignedRead<RoomGetResponse>(ROOMS_GET_TASK, { roomId });
}

/** The most rows the spec returns per page. */
const USAGE_PAGE = 100;
/** Pages read before stopping: a 400-day history of one selection is four. */
const MAX_USAGE_PAGES = 10;

export interface UsageReport {
  asOf: string;
  from: string;
  to: string;
  items: RoomsUsageRow[];
  /** More rows exist than `MAX_USAGE_PAGES` pages hold. */
  truncated: boolean;
}

/**
 * Every row of one usage query, page by page.
 *
 * The cursor is bound to the query it pages (a changed filter is refused as
 * `invalidCursor`), so each page re-sends the identical grouping, filter and
 * sort with only the cursor added.
 */
export async function fetchUsage(query: {
  groupBy: UsageGroup;
  filter?: UsageFilter;
  sort?: UsageSort;
}): Promise<UsageReport> {
  const items: RoomsUsageRow[] = [];
  let cursor: string | undefined;
  let first: RoomsUsageResponse | null = null;
  for (let page = 0; page < MAX_USAGE_PAGES; page++) {
    const payload: RoomsUsagePayload = {
      groupBy: query.groupBy,
      limit: USAGE_PAGE,
      ...(query.filter ? { filter: query.filter } : {}),
      ...(query.sort ? { sort: query.sort } : {}),
      ...(cursor ? { cursor } : {}),
    };
    const body = await postSignedRead<RoomsUsageResponse>(ROOMS_USAGE_TASK, payload);
    first ??= body;
    items.push(...body.items);
    cursor = body.nextCursor;
    if (!cursor) {
      return { asOf: first.asOf, from: first.from, to: first.to, items, truncated: false };
    }
  }
  return { asOf: first!.asOf, from: first!.from, to: first!.to, items, truncated: true };
}

/** Override or clear one target's limits. Audited with `reason`; not parked —
 *  an allowance can be reversed and loses nothing (the spec's own rule). */
export function setRoomLimits(payload: RoomsLimitsSetPayload): Promise<RoomsLimitsSetResponse> {
  return postSignedTrustTask<RoomsLimitsSetResponse>(ROOMS_LIMITS_SET_TASK, payload);
}

// ── Dates ───────────────────────────────────────────────────────────────

/** `YYYY-MM-DD` of `d` in UTC — the day every usage row is keyed by. */
export function utcDay(d: Date): string {
  return d.toISOString().slice(0, 10);
}

/** The `days`-day range ending today (UTC), both ends inclusive. */
export function rangeEnding(days: number, now: Date = new Date()): { from: string; to: string } {
  const to = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate()));
  const from = new Date(to.getTime() - (days - 1) * 86_400_000);
  return { from: utcDay(from), to: utcDay(to) };
}

/**
 * Every day from `from` to `to` with its row, a day with none as zeros.
 *
 * A day row is written by the collection pass for every room that has one, so
 * a gap is a day before the room held anything (or before history was kept);
 * drawn as zero rather than skipped, so the axis is time and not row order.
 */
export function fillDays(
  rows: readonly RoomsUsageRow[],
  from: string,
  to: string,
): { date: string; row: RoomsUsageRow | null }[] {
  const byDate = new Map(rows.filter((r) => r.date).map((r) => [r.date!, r]));
  const out: { date: string; row: RoomsUsageRow | null }[] = [];
  const end = Date.parse(`${to}T00:00:00Z`);
  for (let t = Date.parse(`${from}T00:00:00Z`); t <= end; t += 86_400_000) {
    const date = utcDay(new Date(t));
    out.push({ date, row: byDate.get(date) ?? null });
  }
  return out;
}

// ── Limits ──────────────────────────────────────────────────────────────

/** The bands §6.3 alerts on. */
export type Threshold = 80 | 95 | 100;

/**
 * How full a scope is: the larger of its bytes and its files against their
 * limits, or `null` where it has neither limit.
 *
 * Reserved bytes count against `maxBytes` — the host does, so two concurrent
 * uploads cannot both fit under a limit only one of them fits — and so they
 * count here too. `maxFiles: 0` (uploads refused outright) reads as full.
 */
export function fullness(
  usage: { files: number; bytes: number; reservedBytes?: number },
  limits: RoomScopeLimits | undefined,
): number | null {
  if (!limits) return null;
  const parts: number[] = [];
  if (limits.maxBytes !== undefined) {
    const used = usage.bytes + (usage.reservedBytes ?? 0);
    parts.push(limits.maxBytes === 0 ? 1 : used / limits.maxBytes);
  }
  if (limits.maxFiles !== undefined) {
    parts.push(limits.maxFiles === 0 ? 1 : usage.files / limits.maxFiles);
  }
  return parts.length ? Math.max(...parts) : null;
}

/** The highest band `fraction` has reached, or `null` under 80 %. */
export function thresholdOf(fraction: number | null): Threshold | null {
  if (fraction === null) return null;
  if (fraction >= 1) return 100;
  if (fraction >= 0.95) return 95;
  if (fraction >= 0.8) return 80;
  return null;
}

// ── Bytes ───────────────────────────────────────────────────────────────

const UNITS = ["B", "KB", "MB", "GB", "TB"] as const;

/** Bytes in the largest unit that keeps the number at or above 1 (1000-based). */
export function formatBytes(n: number): string {
  let v = n;
  let i = 0;
  while (v >= 1000 && i < UNITS.length - 1) {
    v /= 1000;
    i++;
  }
  return i === 0 ? `${n} B` : `${v < 10 ? v.toFixed(1) : Math.round(v)} ${UNITS[i]}`;
}

const FACTOR: Record<string, number> = {
  b: 1,
  kb: 1e3,
  mb: 1e6,
  gb: 1e9,
  tb: 1e12,
  kib: 2 ** 10,
  mib: 2 ** 20,
  gib: 2 ** 30,
  tib: 2 ** 40,
};

/**
 * A size an administrator typed — `1048576`, `500 MB`, `1.5 GB`, `1 GiB` — as
 * whole bytes, or `null` when it is not one. Empty is `undefined`: no limit of
 * that kind at this scope.
 */
export function parseBytes(text: string): number | null | undefined {
  const t = text.trim();
  if (t === "") return undefined;
  const m = /^(\d+(?:\.\d+)?)\s*([a-z]*)$/i.exec(t);
  if (!m) return null;
  const factor = FACTOR[(m[2] || "b").toLowerCase()];
  if (factor === undefined) return null;
  const n = Math.round(Number(m[1]) * factor);
  return Number.isSafeInteger(n) ? n : null;
}

/**
 * A size in the largest unit that states it exactly — `5 GB`, `1 GiB`,
 * `1536 KB` — so a form pre-filled with it saves the same number back.
 */
export function exactBytes(n: number): string {
  for (const unit of ["tib", "tb", "gib", "gb", "mib", "mb", "kib", "kb"] as const) {
    const f = FACTOR[unit]!;
    if (n >= f && n % f === 0) {
      const label = unit.replace(/^(.)(i?)b$/, (_, p: string, i: string) => `${p.toUpperCase()}${i}B`);
      return `${n / f} ${label}`;
    }
  }
  return String(n);
}

/** A count an administrator typed, as above: whole, non-negative, or empty. */
export function parseCount(text: string): number | null | undefined {
  const t = text.trim();
  if (t === "") return undefined;
  return /^\d+$/.test(t) && Number.isSafeInteger(Number(t)) ? Number(t) : null;
}

// ── CSV ─────────────────────────────────────────────────────────────────

/**
 * One CSV cell (RFC 4180), safe to open in a spreadsheet.
 *
 * Room identifiers and member DIDs are chosen by others, so a cell that a
 * spreadsheet would read as a formula (`=`, `+`, `-`, `@`, tab, CR) is
 * prefixed with `'` (OWASP's CSV-injection guidance). Numbers are written as
 * numbers.
 */
export function csvCell(value: string | number | undefined | null): string {
  if (value === undefined || value === null) return "";
  if (typeof value === "number") return String(value);
  const guarded = /^[=+\-@\t\r]/.test(value) ? `'${value}` : value;
  return /[",\r\n]/.test(guarded) ? `"${guarded.replaceAll('"', '""')}"` : guarded;
}

/** The identifying column a grouping's rows carry. */
const KEY_COLUMN: Record<UsageGroup, keyof RoomsUsageRow> = {
  room: "roomId",
  member: "member",
  storageConfig: "storageConfig",
  day: "date",
};

/**
 * A usage report as CSV: the grouping's key (a `room` row also names its
 * storage config), then every figure, then the limits the row carries.
 * CRLF line ends, as RFC 4180 and spreadsheets expect.
 */
export function usageCsv(groupBy: UsageGroup, rows: readonly RoomsUsageRow[]): string {
  const key = KEY_COLUMN[groupBy];
  const header = [
    key,
    ...(groupBy === "room" ? ["storageConfig"] : []),
    "files",
    "bytes",
    "reservedBytes",
    "uploads",
    "downloads",
    "egressBytes",
    "maxFiles",
    "maxBytes",
    "maxFileBytes",
    ...(groupBy === "storageConfig" ? ["capacityBytes"] : []),
  ];
  const lines = rows.map((r) =>
    [
      r[key] as string | undefined,
      ...(groupBy === "room" ? [r.storageConfig] : []),
      r.files,
      r.bytes,
      r.reservedBytes,
      r.uploads,
      r.downloads,
      r.egressBytes,
      r.limits?.maxFiles,
      r.limits?.maxBytes,
      r.limits?.maxFileBytes,
      ...(groupBy === "storageConfig" ? [r.capacityBytes] : []),
    ]
      .map(csvCell)
      .join(","),
  );
  return [header.join(","), ...lines].join("\r\n") + "\r\n";
}
