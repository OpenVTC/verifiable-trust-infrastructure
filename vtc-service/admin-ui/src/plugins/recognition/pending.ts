import type { BackingOff } from "@/lib/api";
import { formatDuration } from "@/lib/format";

/**
 * The Pending tile's foot.
 *
 * `oldestDueSeconds` counts only jobs due now, so it is absent while every
 * pending job waits out a retry backoff — which once read as "4 — nothing
 * waiting". In that case say how many are retrying and when the first moves.
 */
export function pendingFoot(
  oldestDueSeconds: number | null | undefined,
  backingOff: BackingOff | undefined,
  now: number = Date.now(),
): string {
  if (oldestDueSeconds != null) {
    return `oldest ${formatDuration(oldestDueSeconds)}`;
  }
  if (!backingOff || backingOff.count === 0) return "nothing waiting";
  const retrying = `${backingOff.count} retrying`;
  if (!backingOff.nextAttemptAt) return retrying;
  const inSeconds = (Date.parse(backingOff.nextAttemptAt) - now) / 1000;
  return inSeconds > 0
    ? `${retrying} — next in ${formatDuration(inSeconds)}`
    : `${retrying} — next attempt due`;
}
