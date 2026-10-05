// Hidden-vetter admission (PCS, a zero-knowledge proof that `k` of this
// community's vetters vetted an applicant without saying which).
//
// The daemon serves it only when built with the `vetting-pcs` feature, and the
// console cannot tell from anything else whether it was. So support is read
// from `trust-task-discovery/0.3`, which lists exactly the tasks this build
// routes: the same answer a client gets, never a guess from the version string.
//
// A criterion's hidden-vetting parameters are written by
// `vtc/vetting/hidden/publish/0.1` and removed by `vtc/vetting/hidden/withdraw/0.1`.
// What applicants and vetters receive is the join manifest's
// `vetting.ext["org.openvtc.hidden-vetting"]`; what an edit starts from is
// `vtc/vetting/hidden/show/0.1`, the stored configuration, because publish
// replaces the events wholesale and the manifest leaves out each event's
// `approvedBy` and `graceDays`.

import { postSignedRead, postSignedTrustTask } from "@/lib/api";

export const TASK_DISCOVERY = "https://trusttasks.org/spec/trust-task-discovery/0.3";
export const TASK_HIDDEN_PUBLISH = "https://trusttasks.org/spec/vtc/vetting/hidden/publish/0.1";
export const TASK_HIDDEN_WITHDRAW = "https://trusttasks.org/spec/vtc/vetting/hidden/withdraw/0.1";
export const TASK_HIDDEN_SHOW = "https://trusttasks.org/spec/vtc/vetting/hidden/show/0.1";

/** The `vetting.ext` namespace the parameters are published under
 * (`vetting::pcs::HIDDEN_VETTING_NS`). */
export const HIDDEN_VETTING_NS = "org.openvtc.hidden-vetting";

/** What this VTC's build can do with hidden vetting. */
export interface HiddenVettingSupport {
  /** The build routes `vtc/vetting/hidden/publish`, so it can turn PCS on. */
  publish: boolean;
  /** It routes `vtc/vetting/hidden/withdraw`, so it can turn PCS off. */
  withdraw: boolean;
  /** It routes `vtc/vetting/hidden/show`, the stored configuration an edit
   * with events has to start from. */
  show: boolean;
}

export const hiddenVettingKeys = {
  support: ["hidden-vetting", "support"] as const,
  show: (criterionId: string) => ["hidden-vetting", "show", criterionId] as const,
};

/** Read support from discovery, narrowed to the hidden-vetting family. */
export async function fetchHiddenVettingSupport(): Promise<HiddenVettingSupport> {
  const res = await postSignedRead<{ supportedTypes?: unknown[] }>(TASK_DISCOVERY, {
    patterns: ["vtc/vetting/hidden/*"],
  });
  const served = new Set(
    (res.supportedTypes ?? []).filter((t): t is string => typeof t === "string"),
  );
  return {
    publish: served.has(TASK_HIDDEN_PUBLISH),
    withdraw: served.has(TASK_HIDDEN_WITHDRAW),
    show: served.has(TASK_HIDDEN_SHOW),
  };
}

/** An event as published: `approvedBy` and `graceDays` are never in it. */
export interface PublishedEvent {
  eventId: string;
  startDate: string;
  endDate: string;
  groupFloor?: number;
  tiers: { name: string; dripPerTick: number }[];
  closesAfter?: string;
  [key: string]: unknown;
}

/** What a criterion publishes under `vetting.ext[HIDDEN_VETTING_NS]`. */
export interface PublishedHiddenVetting {
  suite: string;
  helperKey: string;
  tokenKey: string;
  vetterLabels: string[];
  tokenLabels: string[];
  dripPerTick: number;
  /** How long one tick of the drip lasts, e.g. `P3D`. Absent from a VTC that
   * predates tick windows. */
  tickLength?: string;
  events: PublishedEvent[];
}

/** The default tick length (`vetting::pcs::DEFAULT_TICK_LENGTH`). */
export const DEFAULT_TICK_LENGTH = "P3D";

const TICK_LENGTH = /^P(?:(\d+)D)?(?:T(\d+)H)?$/;

/** A tick length's hours, or `null` unless it is days and/or hours of at least one hour. */
export function tickLengthHours(text: string): number | null {
  const m = TICK_LENGTH.exec(text.trim());
  if (!m || (m[1] === undefined && m[2] === undefined) || text.trim() === "PT") return null;
  const hours = Number(m[1] ?? 0) * 24 + Number(m[2] ?? 0);
  return hours >= 1 ? hours : null;
}

/** A tick length in words: "3 days", "12 hours", "1 day 6 hours". */
export function describeTickLength(text: string): string {
  const hours = tickLengthHours(text);
  if (hours === null) return text;
  const d = Math.floor(hours / 24);
  const h = hours % 24;
  const part = (n: number, unit: string) => `${n} ${unit}${n === 1 ? "" : "s"}`;
  return [d ? part(d, "day") : "", h ? part(h, "hour") : ""].filter(Boolean).join(" ");
}

/** An event as an administrator writes it into `vtc/vetting/hidden/publish`. */
export interface EventInput {
  eventId: string;
  startDate: string;
  endDate: string;
  graceDays?: number;
  groupFloor?: number;
  tiers: { name: string; dripPerTick: number }[];
  approvedBy?: string;
}

export interface PublishHiddenInput {
  criterionId: string;
  livePeriods?: string[];
  liveTokenLabels?: string[];
  dripPerTick?: number;
  tickLength?: string;
  events?: EventInput[];
}

export interface PublishHiddenResult {
  criterionId: string;
  stored: Record<string, unknown> & { events?: EventInput[] };
  published: PublishedHiddenVetting;
  requirementsDigest: string;
}

export const publishHiddenVetting = (input: PublishHiddenInput): Promise<PublishHiddenResult> =>
  postSignedTrustTask<PublishHiddenResult>(TASK_HIDDEN_PUBLISH, input);

export interface WithdrawHiddenResult {
  criterionId: string;
  withdrawn: boolean;
  requirementsDigest: string | null;
}

export const withdrawHiddenVetting = (criterionId: string): Promise<WithdrawHiddenResult> =>
  postSignedTrustTask<WithdrawHiddenResult>(TASK_HIDDEN_WITHDRAW, { criterionId });

/** The configuration as stored: the bare periods, and events with their approvals. */
export interface StoredHiddenVetting {
  suite: string;
  hvk: string;
  tvk: string;
  livePeriods: string[];
  liveTokenLabels: string[];
  dripPerTick: number;
  tickLength?: string;
  events: (EventInput & { graceDays: number; groupFloor: number })[];
}

/** One event's demand and standing, as counts. */
export interface EventStatus {
  eventId: string;
  groupFloor: number;
  groupSize: number;
  approved: boolean;
  live: boolean;
}

export interface ShowHiddenResult {
  criterionId: string;
  enabled: boolean;
  requirementsDigest: string | null;
  stored?: StoredHiddenVetting;
  published?: PublishedHiddenVetting;
  /** Members enrolled under each live vetter label, e.g. `{"vetter/2026-10": 4}`. */
  enrolledVetters?: Record<string, number>;
  eventStatus?: EventStatus[];
}

export const showHiddenVetting = (criterionId: string): Promise<ShowHiddenResult> =>
  postSignedRead<ShowHiddenResult>(TASK_HIDDEN_SHOW, { criterionId });

/**
 * A publish that changes only what `patch` names, starting from what is
 * stored — so labels, the drip rate and every event, approvals included, are
 * sent back as they are. Publish replaces the whole configuration, so leaving
 * any of them out would remove it.
 */
export function republish(
  criterionId: string,
  stored: StoredHiddenVetting,
  patch: Partial<Omit<PublishHiddenInput, "criterionId">> = {},
): PublishHiddenInput {
  return {
    criterionId,
    livePeriods: stored.livePeriods,
    liveTokenLabels: stored.liveTokenLabels,
    dripPerTick: stored.dripPerTick,
    ...(stored.tickLength ? { tickLength: stored.tickLength } : {}),
    events: stored.events,
    ...patch,
  };
}

/** The token label an event unlocks (`vetting::pcs::HiddenVettingEvent::label`). */
export const eventLabel = (eventId: string) => `token/event/${eventId}`;

/** A manifest criterion's published hidden-vetting parameters, if any. */
export function publishedHiddenVetting(
  criterion: { vetting?: { ext?: Record<string, unknown> | null } | null } | undefined,
): PublishedHiddenVetting | null {
  const ext = criterion?.vetting?.ext?.[HIDDEN_VETTING_NS];
  return ext && typeof ext === "object" ? (ext as PublishedHiddenVetting) : null;
}

/** `YYYY-MM` for `date`, in UTC — the period labels the daemon defaults to. */
export function periodOf(date: Date = new Date()): string {
  return `${date.getUTCFullYear()}-${String(date.getUTCMonth() + 1).padStart(2, "0")}`;
}

/**
 * Whether a criterion's live labels are behind the current month. The daemon
 * never advances them on its own, so a criterion published last month keeps
 * minting and accepting last month's labels until an administrator rolls it.
 */
export function labelsBehind(published: PublishedHiddenVetting, now: Date = new Date()): boolean {
  return !published.vetterLabels.includes(`vetter/${periodOf(now)}`);
}
