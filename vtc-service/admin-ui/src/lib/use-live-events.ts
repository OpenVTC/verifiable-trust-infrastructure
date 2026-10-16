// The live channel, wired into the console: one `LiveEvents` per signed-in
// session (`lib/live-events.ts`), whose hints invalidate the react-query keys
// of the reads each topic names, and whose status drives the live/offline
// indicator and how often the screens' own polls run.
//
// Polling stays the fallback and never stops: while live, the badge and tile
// polls slow to `LIVE_POLL_MS`; the moment the stream is not live they are
// back at `WAITING_POLL_MS`, and every topic is re-read at once.
//
// The version is read from `trust-task-discovery`: 0.2 (with `rooms`) when the
// community lists it, else 0.1, whose topic set has no `rooms` — the rooms
// pages then simply poll.

import { useEffect, useSyncExternalStore } from "react";
import { useQueryClient, type QueryClient, type QueryKey } from "@tanstack/react-query";

import { csrfToken, postSignedRead, signedDocument } from "./api";
import { TASK_DISCOVERY } from "./hidden-vetting";
import {
  ALL_TOPICS,
  LIVE_V0_1,
  LiveEvents,
  liveVersionFor,
  type LiveStatus,
  type LiveVersion,
  type SignedSubscribe,
  type Topic,
} from "./live-events";

/** How often a badge or tile polls while the stream is live. */
export const LIVE_POLL_MS = 5 * 60_000;
/** …and while it is not — the console's ordinary poll. */
export const OFFLINE_POLL_MS = 60_000;

/**
 * The react-query keys each topic's read lives under. Prefixes: invalidating
 * `["join-requests"]` refreshes the page, its badge count and the dashboard
 * tile, which all live beneath it.
 */
export function keysFor(topic: Topic): QueryKey[] {
  switch (topic) {
    // The Actions page, and the badge read — which also carries the
    // acknowledgement and single-administrator banners.
    case "actions":
    case "acknowledgements":
      return [["actions"], ["actions-waiting"]];
    case "singleAdminMode":
      return [["actions-waiting"]];
    case "joinRequests":
      return [["join-requests"], ["join-request"], ["vetting", "pending-with-vetting"]];
    case "members":
      return [["members"], ["member"], ["members-removed"]];
    case "config":
      return [["admin-config"], ["profile"], ["community"]];
    // The rooms pages: the list and a room (`vtc/rooms/list`, `vtc/rooms/get`),
    // usage and the near-a-limit panel (`vtc/rooms/usage`), and storage configs
    // (`vtc/storage/configs/*`).
    case "rooms":
      return [["rooms"], ["room-usage"], ["storage"]];
  }
}

/** Re-read `topics`: invalidate each one's keys (de-duplicated). */
export function invalidateTopics(qc: QueryClient, topics: readonly Topic[]): void {
  const seen = new Set<string>();
  for (const topic of topics) {
    for (const key of keysFor(topic)) {
      const k = JSON.stringify(key);
      if (seen.has(k)) continue;
      seen.add(k);
      void qc.invalidateQueries({ queryKey: key });
    }
  }
}

// ─── status, shared across the shell ────────────────────────────────────

let status: LiveStatus = "offline";
/** The open stream's effective topics; empty unless live. */
let effective: readonly Topic[] = [];
const listeners = new Set<() => void>();

function setLiveStatus(next: LiveStatus, topics: readonly Topic[] = []): void {
  const nextEffective = next === "live" ? topics : [];
  if (next === status && nextEffective.join() === effective.join()) return;
  status = next;
  effective = nextEffective;
  for (const l of listeners) l();
}

function subscribeStatus(l: () => void): () => void {
  listeners.add(l);
  return () => listeners.delete(l);
}

/** The channel's status: `live` only while bytes are arriving. */
export function useLiveStatus(): LiveStatus {
  return useSyncExternalStore(subscribeStatus, () => status, () => status);
}

/**
 * The interval a badge, tile or page poll should run at right now: slow only
 * while the stream is live **and** carries `topic` (any topic, when none is
 * named). A topic the stream does not carry — `rooms` on a 0.1 community, or
 * for an administrator who cannot read it — polls at the ordinary pace.
 */
export function useLivePollMs(topic?: Topic): number {
  const live = useSyncExternalStore(
    subscribeStatus,
    () => status === "live" && (topic === undefined || effective.includes(topic)),
    () => false,
  );
  return live ? LIVE_POLL_MS : OFFLINE_POLL_MS;
}

/** The version to subscribe at: 0.2 when discovery lists it, else 0.1 — and
 * 0.1 when discovery cannot be read. */
export async function chooseLiveVersion(): Promise<LiveVersion> {
  try {
    const res = await postSignedRead<{ supportedTypes?: unknown[] }>(TASK_DISCOVERY, {
      patterns: ["vtc/admin/events/*"],
    });
    return liveVersionFor(res.supportedTypes ?? []);
  } catch {
    return LIVE_V0_1;
  }
}

/**
 * Hold the session's one subscription while `enabled` (signed in, with a
 * key that signs). Every topic the console renders goes in it; the community
 * narrows them to what this administrator may read.
 */
export function useLiveEvents(enabled: boolean): void {
  const qc = useQueryClient();
  useEffect(() => {
    if (!enabled) return;
    let client: LiveEvents | null = null;
    let cancelled = false;
    void chooseLiveVersion().then((version) => {
      if (cancelled) return;
      const live: LiveEvents = new LiveEvents(
        ALL_TOPICS,
        {
          onHint: (topic) => invalidateTopics(qc, [topic]),
          onResync: (topics) => invalidateTopics(qc, topics),
          onStatus: (s) => setLiveStatus(s, live.effectiveTopics),
        },
        {
          sign: async (payload) =>
            (await signedDocument(version.subscribe, payload)) as unknown as SignedSubscribe,
          fetch: (input, init) => fetch(input, init),
          csrf: csrfToken,
        },
        version,
      );
      client = live;
      live.start();
    });
    return () => {
      cancelled = true;
      client?.stop();
    };
  }, [enabled, qc]);
}
