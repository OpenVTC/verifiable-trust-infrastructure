// Whether the console is being told of changes as they happen, or polling.
//
// The live channel's status (`lib/use-live-events.ts`): `Live` only while
// bytes are arriving on the stream; anything else — connecting, silent for
// twice the heartbeat, ended, refused — is `Polling`, and the screens' polls
// run at their ordinary pace (vtc/admin/events/subscribe/0.1 rules 8–10).

import { useLiveStatus } from "@/lib/use-live-events";

export function LiveIndicator() {
  const status = useLiveStatus();
  const live = status === "live";
  return (
    <div
      className={`live-indicator${live ? " live" : ""}`}
      role="status"
      aria-live="polite"
      title={
        live
          ? "Live: this console is told of changes as they happen."
          : status === "connecting"
            ? "Connecting the live channel; refreshing on a timer meanwhile."
            : "Offline: refreshing on a timer until the live channel is back."
      }
    >
      <span className="live-dot" aria-hidden="true" />
      <span className="live-label">{live ? "Live" : "Polling"}</span>
    </div>
  );
}
