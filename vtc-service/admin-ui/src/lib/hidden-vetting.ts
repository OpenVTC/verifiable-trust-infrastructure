// Hidden-vetter admission (PCS, a zero-knowledge proof that `k` of this
// community's vetters vetted an applicant without saying which).
//
// The daemon serves it only when built with the `vetting-pcs` feature, and the
// console cannot tell from anything else whether it was. So support is read
// from `trust-task-discovery/0.3`, which lists exactly the tasks this build
// routes: the same answer a client gets, never a guess from the version string.
//
// A criterion's hidden-vetting parameters are written by
// `vtc/vetting/hidden/publish/0.1`, and read back from the join manifest, under the criterion's
// `vetting.ext["org.openvtc.hidden-vetting"]`: that is what applicants and
// vetters receive, so it is what the console shows.

import { postSignedRead, postSignedTrustTask } from "@/lib/api";

export const TASK_DISCOVERY = "https://trusttasks.org/spec/trust-task-discovery/0.3";
export const TASK_HIDDEN_PUBLISH = "https://trusttasks.org/spec/vtc/vetting/hidden/publish/0.1";

/** The `vetting.ext` namespace the parameters are published under
 * (`vetting::pcs::HIDDEN_VETTING_NS`). */
export const HIDDEN_VETTING_NS = "org.openvtc.hidden-vetting";

/** What this VTC's build can do with hidden vetting. */
export interface HiddenVettingSupport {
  /** The build routes `vtc/vetting/hidden/publish`, so it can turn PCS on. */
  publish: boolean;
}

export const hiddenVettingKeys = {
  support: ["hidden-vetting", "support"] as const,
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
  events: PublishedEvent[];
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
