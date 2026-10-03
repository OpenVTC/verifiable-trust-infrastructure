// The live channel, wired into the console: one `LiveEvents` per signed-in
// session (`lib/live-events.ts`), whose hints invalidate the react-query keys
// of the reads each topic names, and whose status drives the live/offline
// indicator and how often the screens' own polls run.
//
// Polling stays the fallback and never stops: while live, the badge and tile
// polls slow to `LIVE_POLL_MS`; the moment the stream is not live they are
// back at `WAITING_POLL_MS`, and every topic is re-read at once.

import { useEffect, useSyncExternalStore } from "react";
import { useQueryClient, type QueryClient, type QueryKey } from "@tanstack/react-query";

import { csrfToken, signedDocument } from "./api";
import {
  ALL_TOPICS,
  LiveEvents,
  SUBSCRIBE_TASK,
  type LiveStatus,
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
const listeners = new Set<() => void>();

function setLiveStatus(next: LiveStatus): void {
  if (next === status) return;
  status = next;
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

/** The interval a badge or tile poll should run at right now. */
export function useLivePollMs(): number {
  return useLiveStatus() === "live" ? LIVE_POLL_MS : OFFLINE_POLL_MS;
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
    const client = new LiveEvents(
      ALL_TOPICS,
      {
        onHint: (topic) => invalidateTopics(qc, [topic]),
        onResync: (topics) => invalidateTopics(qc, topics),
        onStatus: setLiveStatus,
      },
      {
        sign: async (payload) =>
          (await signedDocument(SUBSCRIBE_TASK, payload)) as unknown as SignedSubscribe,
        fetch: (input, init) => fetch(input, init),
        csrf: csrfToken,
      },
    );
    client.start();
    return () => client.stop();
  }, [enabled, qc]);
}
