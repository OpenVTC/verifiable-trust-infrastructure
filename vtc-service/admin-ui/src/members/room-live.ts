// Keeping an open room current: the wallet's watch (`rooms.watch`) says when the
// room moved, never what changed, and the page reads it again through the wallet.
// Where the wallet cannot watch — an older wallet, or a watch refused or
// unavailable — the page reads the room on a gentle timer while the tab is seen.
//
// The status is derived from the latest event and goes back to "not live" the
// moment the watch reports anything else (R6.2: never latched).

import { useEffect, useRef, useState } from "react";

import { rewatchDelay } from "./conversation";
import type { RoomWatchHandle, WalletRooms } from "./wallet-rooms";

/** How often a room is read when nothing can tell the page it moved. */
export const FALLBACK_READ_MS = 20_000;

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

    const startPolling = () => {
      setStatus("polling");
      if (poll !== undefined) return;
      poll = setInterval(() => {
        if (typeof document === "undefined" || document.visibilityState === "visible") void readRef.current();
      }, FALLBACK_READ_MS);
    };
    const stopPolling = () => {
      if (poll !== undefined) clearInterval(poll);
      poll = undefined;
    };
    const readThenAck = async () => {
      try {
        const v = await readRef.current();
        handle?.read(v ?? heldRef.current);
      } catch {
        // The next change, or the timer, reads again.
      }
    };
    const watch = () => {
      if (stopped) return;
      setStatus((s) => (s === "polling" ? s : "connecting"));
      handle = wallet.watch!({ hostDid, roomId, ...(heldRef.current !== undefined ? { sinceVersion: heldRef.current } : {}) }, (e) => {
        if (stopped) return;
        switch (e.type) {
          case "changed":
            attempt = 0;
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
              handle?.read(heldRef.current);
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
    return () => {
      stopped = true;
      if (retry !== undefined) clearTimeout(retry);
      stopPolling();
      handle?.stop();
      handle = null;
    };
  }, [canWatch, wallet, hostDid, roomId]);

  return status;
}
