// Whether the operator is using the console right now.
//
// The daemon's idle timeout (`auth.admin_idle_timeout`) signs a session out
// once it has seen no activity for that long. Most of what the console does
// is a signed Trust Task document, which authenticates by its proof and not
// by the session cookie, so on its own the daemon never learned that the
// operator was working and signed them out in the middle of it.
//
// Only the console can tell a click from a poll: the action badge, counts
// and banners post signed reads on timers, and counting those would keep an
// unattended tab signed in forever. So the console notes real input here,
// and a document posted soon after some carries `X-VTC-User-Activity`. The
// daemon counts it only for a document that succeeded and whose signer owns
// the session (`routes::trust_tasks::USER_ACTIVITY_HEADER`).

/** The header the daemon reads (`routes::trust_tasks::USER_ACTIVITY_HEADER`). */
export const USER_ACTIVITY_HEADER = "X-VTC-User-Activity";

/**
 * How recent input must be for a request to count as activity. The daemon
 * records activity at most once a minute (`LAST_SEEN_GRANULARITY_SECS`), so
 * a finer window buys nothing.
 */
export const ACTIVE_WINDOW_MS = 60_000;

/** What counts as the operator doing something. Not mouse movement: a
 * pointer resting on a tab while someone walks past is not interaction. */
const INPUT_EVENTS = ["pointerdown", "keydown", "wheel", "touchstart"] as const;

let lastInputMs: number | null = null;
let installed = false;

/** Record input at `nowMs`. Exported for tests. */
export function noteUserInput(nowMs: number = Date.now()): void {
  lastInputMs = nowMs;
}

/** Whether the operator gave input within [`ACTIVE_WINDOW_MS`] of `nowMs`. */
export function operatorIsActive(nowMs: number = Date.now()): boolean {
  return lastInputMs !== null && nowMs - lastInputMs < ACTIVE_WINDOW_MS;
}

/** Start listening for input. Idempotent; a no-op outside a browser. */
export function installUserActivityTracking(): void {
  if (installed || typeof window === "undefined") return;
  installed = true;
  const note = () => noteUserInput();
  for (const event of INPUT_EVENTS) {
    // Capture phase, so a handler that stops propagation still counts.
    window.addEventListener(event, note, { capture: true, passive: true });
  }
}

/** Forget recorded input. For tests. */
export function resetUserActivityForTests(): void {
  lastInputMs = null;
}
