// Keeping a signed-in console signed in.
//
// The session is an HttpOnly cookie carrying a short-lived access token —
// 300s after a passkey sign-in, because that mints at `acr=aal2` and the
// aal2 TTL is a third of the base. Nothing used to extend it, so an
// operator was signed out five minutes after arriving whether or not they
// were in the middle of something, and learned about it from a request
// that failed.
//
// This module renews the cookie ahead of that deadline. Two rules make the
// renewal honest rather than a way of never expiring:
//
//  1. **The daemon decides, not us.** It refuses to renew a session whose
//     `last_seen` is older than the configured idle timeout. `last_seen`
//     advances on cookie-borne API calls — real console traffic — and
//     explicitly *not* on renewals. So a tab left open overnight keeps
//     asking and starts being told no.
//  2. **A renewal is never the reason for a renewal.** `renewIfNeeded` is
//     called before authenticated requests, and the renewal request itself
//     bypasses it. Without that the first renewal would recurse.
//
// The expiry itself comes from `whoami`, whose `session.expiresAt` the
// console already receives on every probe and, before this, ignored.

/** Renew when the token has this long or less to live. */
const RENEW_WITHIN_SECS = 60;

/** Absolute floor between renewal attempts, so a failing one can't spin. */
const MIN_RETRY_GAP_MS = 5_000;

let expiresAtEpoch: number | null = null;
let inFlight: Promise<void> | null = null;
let lastAttemptMs = 0;

/** Seconds since the epoch, matching the daemon's `expiresAt`. */
function nowEpoch(): number {
  return Math.floor(Date.now() / 1000);
}

/**
 * Record when the current access token expires.
 *
 * Called from the `whoami` probe and after each renewal — the two places
 * that learn it. `null` clears it, which is what sign-out and an expired
 * session do.
 */
export function setSessionExpiry(expiresAt: string | number | null): void {
  if (expiresAt === null) {
    expiresAtEpoch = null;
    return;
  }
  const parsed =
    typeof expiresAt === "number"
      ? expiresAt
      : Math.floor(new Date(expiresAt).getTime() / 1000);
  expiresAtEpoch = Number.isFinite(parsed) ? parsed : null;
}

/** The recorded expiry, for tests and for the session badge. */
export function sessionExpiry(): number | null {
  return expiresAtEpoch;
}

/** Forget everything. Called on sign-out so a later sign-in starts clean. */
export function resetSession(): void {
  expiresAtEpoch = null;
  inFlight = null;
  lastAttemptMs = 0;
}

/**
 * Renew the session cookie if it is close to expiring.
 *
 * Single-flight: concurrent callers await one request rather than each
 * firing their own. That matters more here than for a typical dedupe,
 * because refresh **rotates** the token and claims the old one atomically
 * — a second simultaneous renewal would present a token the first had
 * already consumed and be rejected.
 *
 * Never throws. A renewal that fails leaves the session alone; the
 * request that follows will get its own 401 and the shell handles it
 * there, with one recovery attempt (see `lib/api.ts`).
 */
export async function renewIfNeeded(renew: () => Promise<number | null>): Promise<void> {
  if (expiresAtEpoch === null) return;
  if (nowEpoch() < expiresAtEpoch - RENEW_WITHIN_SECS) return;
  if (inFlight) return inFlight;
  if (Date.now() - lastAttemptMs < MIN_RETRY_GAP_MS) return;

  lastAttemptMs = Date.now();
  inFlight = (async () => {
    try {
      const next = await renew();
      if (next !== null) setSessionExpiry(next);
    } catch {
      // Swallowed deliberately — see the doc comment. The caller's own
      // request is the thing that should surface a broken session.
    } finally {
      inFlight = null;
    }
  })();
  return inFlight;
}

/**
 * Keep the session's deadline in view while the console is open, and say
 * when it has passed.
 *
 * Renewal used to ride only on requests, and an idle dashboard sends almost
 * none that carry the cookie — `/health` is unauthenticated and signed reads
 * authenticate by their proof. So the cookie lapsed unseen, the console went
 * on looking signed in, and the operator found out from the next click that
 * failed (the sign-out that prompted this reported "Sign-out failed").
 *
 * This wakes ahead of the deadline and renews, exactly as a request would.
 * It does not make a session immortal: a renewal is not activity, so once
 * the daemon's idle timeout passes it refuses, the expiry stays put, and the
 * next wake — just after it — calls `onExpired`. The daemon still decides.
 *
 * Returns a cancel function. Nothing is scheduled while no expiry is known.
 */
export function watchSessionDeadline(
  renew: () => Promise<number | null>,
  onExpired: () => void,
): () => void {
  let timer: ReturnType<typeof setTimeout> | null = null;
  let cancelled = false;

  const schedule = (afterAttempt: boolean) => {
    if (cancelled || expiresAtEpoch === null) return;
    const now = Date.now() / 1000;
    if (afterAttempt && now >= expiresAtEpoch) {
      onExpired();
      return;
    }
    const renewAt = expiresAtEpoch - RENEW_WITHIN_SECS;
    // Before the renewal window, wake at its start. Inside it, try at once
    // unless this wake just tried — then a renewal was refused (or held
    // back by the retry gap), so wake just after the deadline to see
    // whether it moved.
    let wakeAt: number;
    if (now < renewAt) wakeAt = renewAt;
    else if (!afterAttempt) wakeAt = now;
    else wakeAt = expiresAtEpoch + 1;
    timer = setTimeout(() => void tick(), Math.max(0, (wakeAt - now) * 1000));
  };

  const tick = async () => {
    timer = null;
    if (cancelled) return;
    await renewIfNeeded(renew);
    schedule(true);
  };

  schedule(false);
  return () => {
    cancelled = true;
    if (timer !== null) clearTimeout(timer);
  };
}
