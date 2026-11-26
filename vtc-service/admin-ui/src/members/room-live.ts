// Keeping an open room current: the wallet's watch (`rooms.watch`) says when the
// room moved, never what changed, and the page reads it again through the wallet.
// Where the wallet cannot watch — an older wallet, or a watch refused or
// unavailable — the page reads the room on a gentle timer while the tab is seen.
//
// The status is derived from the latest event and goes back to "not live" the
// moment the watch reports anything else (R6.2: never latched). A watch can
// still stop delivering without saying so — a wedged session, a host that lost
// it — so while it reports itself armed the page also reads the room on a slow
// backstop timer, and at once when the tab is seen again (a hidden tab's timers
// are throttled, and the wallet's worker may have been put to sleep): a broken
// delivery costs minutes, never the watch's whole lease.

import { useEffect, useRef, useState } from "react";

import { rewatchDelay } from "./conversation";
import type { RoomWatchHandle, WalletRooms } from "./wallet-rooms";

/** How often a room is read when nothing can tell the page it moved. */
export const FALLBACK_READ_MS = 20_000;

/** How often a room is read even while the wallet says it is watching. */
export const BACKSTOP_READ_MS = 5 * 60_000;

/** `live`: the wallet is watching. `connecting`: asking it to. `polling`: reading on a timer. `manual`: the wallet cannot watch. */
export type LiveStatus = "live" | "connecting" | "polling" | "manual";

/**
 * Watch `roomId` through the wallet while the page shows it. `read` reads the
 * room again and answers the highest record version it now holds; `held` is that
 * version as the page holds it now, used to start a watch from.
 */
export function useRoomLive(
  wallet: WalletRooms,
  hostDid: string,
  roomId: string,
  held: number | undefined,
  read: () => Promise<number | undefined>,
): LiveStatus {
  const canWatch = typeof wallet.watch === "function";
  const [status, setStatus] = useState<LiveStatus>(canWatch ? "connecting" : "manual");
  // The latest values, without restarting the watch each time they change.
  const heldRef = useRef(held);
  heldRef.current = held;
  const readRef = useRef(read);
  readRef.current = read;

  useEffect(() => {
    if (!canWatch) {
      setStatus("manual");
      return;
    }
    let handle: RoomWatchHandle | null = null;
    let stopped = false;
    let attempt = 0;
    let retry: ReturnType<typeof setTimeout> | undefined;
    let poll: ReturnType<typeof setInterval> | undefined;
    const visible = () => typeof document === "undefined" || document.visibilityState === "visible";

    const startPolling = () => {
      setStatus("polling");
      if (poll !== undefined) return;
      poll = setInterval(() => {
        if (visible()) void readRef.current();
      }, FALLBACK_READ_MS);
    };
    const stopPolling = () => {
      if (poll !== undefined) clearInterval(poll);
      poll = undefined;
    };
    // The room's own latest version, as the watch reported it. The page's records
    // are not every record: reactions, names, edits and withdrawals are folded
    // into the messages they concern, so the highest version shown can sit below
    // the room's — and acknowledging that would have the host fire again at once,
    // forever. Acknowledge the room's version once it has been read.
    let latest = 0;
    const acked = (v: number | undefined) => Math.max(v ?? 0, heldRef.current ?? 0, latest) || undefined;
    const readThenAck = async () => {
      try {
        const v = await readRef.current();
        handle?.read(acked(v));
      } catch {
        // The next change, or the timer, reads again.
      }
    };
    const watch = () => {
      if (stopped) return;
      setStatus((s) => (s === "polling" ? s : "connecting"));
      const since = acked(undefined);
      handle = wallet.watch!({ hostDid, roomId, ...(since !== undefined ? { sinceVersion: since } : {}) }, (e) => {
        if (stopped) return;
        switch (e.type) {
          case "changed":
            attempt = 0;
            latest = Math.max(latest, e.latestVersion);
            void readThenAck();
            return;
          case "state":
            if (e.state === "armed" || e.state === "fired") {
              attempt = 0;
              stopPolling();
              setStatus("live");
            } else if (e.state === "arming") {
              setStatus((s) => (s === "polling" ? s : "connecting"));
            } else if (e.state === "lapsed") {
              // A lapsed watch is armed again once the page says what it has read.
              setStatus("connecting");
              handle?.read(acked(undefined));
            } else {
              // refused | unavailable: the wallet cannot watch this room now.
              startPolling();
            }
            return;
          case "failed":
            startPolling();
            return;
          case "closed":
            handle = null;
            if (stopped) return;
            startPolling();
            retry = setTimeout(watch, rewatchDelay(attempt++));
            return;
        }
      });
    };
    watch();
    // The backstop: while polling, the 20 s timer already reads.
    const backstop = setInterval(() => {
      if (poll === undefined && visible()) void readThenAck();
    }, BACKSTOP_READ_MS);
    const onVisible = () => {
      if (visible()) void readThenAck();
    };
    if (typeof document !== "undefined") document.addEventListener("visibilitychange", onVisible);
    return () => {
      stopped = true;
      if (retry !== undefined) clearTimeout(retry);
      clearInterval(backstop);
      if (typeof document !== "undefined") document.removeEventListener("visibilitychange", onVisible);
      stopPolling();
      handle?.stop();
      handle = null;
    };
  }, [canWatch, wallet, hostDid, roomId]);

  return status;
}
