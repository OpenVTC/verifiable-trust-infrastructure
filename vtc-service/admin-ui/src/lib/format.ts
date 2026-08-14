// Shared formatting helpers used across plugins.
//
// Each helper was previously duplicated in 3–5 plugin files with
// minor variations (some `formatIso`, some `formatEpoch`, some hand-
// rolled `shortDid`). Consolidating here keeps the on-screen
// presentation consistent and gives reviewers one place to change
// when the formatting needs to evolve.

/**
 * Truncate a long opaque identifier (DID, session id, JTI, hash) so
 * it fits in a table cell while still letting an operator visually
 * compare two values. Keeps the first `head` and last `tail`
 * characters and joins with `…`. Returns the input unchanged when
 * it's shorter than the would-be truncation overhead.
 */
export function shorten(value: string, head = 8, tail = 4): string {
  if (value.length <= head + tail + 1) return value;
  return `${value.slice(0, head)}…${value.slice(-tail)}`;
}

/**
 * Abbreviate a DID for table display by shrinking the long opaque middle
 * segment — the `did:webvh` SCID (a content hash) or a `did:key` multibase —
 * while keeping the method prefix and, crucially, the **full tail** (the domain
 * and human-readable path, e.g. `…:webvh.storm.ws:glenn-vta`), which is the part
 * that actually identifies the agent. Unlike a CSS `text-overflow` ellipsis
 * (which clips the *end*), this keeps the end visible. The full DID stays
 * available via a `title` tooltip / copy.
 *
 * - `did:webvh:<scid>:<domain>…:<path>` → SCID abbreviated to `keep` chars + `…`,
 *   everything after it kept verbatim.
 * - `did:key:<multibase>` (and other 3-segment DIDs) → middle-truncate the id,
 *   keeping `keep` head + 6 tail chars.
 * - Non-DID input and already-short DIDs are returned unchanged.
 *
 * ## Kept in step with Rust
 *
 * `vta_sdk::display_name::shorten_did` is a port of this function, used by
 * `pnm`, `cnm` and the `vtc` CLI. An operator moves between a terminal and
 * this console looking at the same community; if the two abbreviate
 * differently, every DID has to be re-identified on the way across.
 *
 * The vectors below are asserted in `shorten_did_matches_shared_vectors`
 * (`vta-sdk/src/display_name/mod.rs`), which is the authority — this console
 * has no test runner. Change either implementation and check both:
 *
 *   "alice"                                        -> "alice"
 *   "did:webvh:QmXkAbCdEfGhIjKlMnOp:webvh.storm.ws:glenn-vta"
 *                          -> "did:webvh:QmXkAbCdEf…:webvh.storm.ws:glenn-vta"
 *   "did:web:QmXkAbCdEfGhIjKlMnOp:example.com"
 *                                    -> "did:web:QmXkAbCdEf…:example.com"
 *   "did:webvh:Qm123:example.com"           -> "did:webvh:Qm123:example.com"
 *   "did:key:z6MkfrQjWzPQrTuVwXyZaBcDeFgHiJkLmNoPqRsTuVwXyZ4rT"
 *                                       -> "did:key:z6MkfrQjWz…XyZ4rT"
 *   "did:key:z6MkfrQjWz"                       -> "did:key:z6MkfrQjWz"
 *   "did:webvh:QmXkAbCdEfGhIjKlMnOpQrSt" -> "did:webvh:QmXkAbCdEf…OpQrSt"
 */
export function shortenDid(did: string, keep = 10): string {
  if (!did.startsWith("did:")) return did;
  const parts = did.split(":");
  if ((parts[1] === "webvh" || parts[1] === "web") && parts.length > 3) {
    const scid = parts[2] ?? "";
    if (scid.length > keep + 1) {
      parts[2] = `${scid.slice(0, keep)}…`;
    }
    return parts.join(":");
  }
  // did:key and other `did:<method>:<id>` shapes: the id carries no human tail,
  // so keep head + tail to aid visual comparison.
  const id = parts.slice(2).join(":");
  if (id.length > keep + 7) {
    return `${parts[0]}:${parts[1]}:${id.slice(0, keep)}…${id.slice(-6)}`;
  }
  return did;
}

/**
 * Format an RFC3339 / ISO-8601 timestamp into the operator's
 * locale-string. Used for `joinedAt`, `created_at`, `activated_at`,
 * audit envelope timestamps, etc. Falls back to the raw input on
 * parse failure so the cell never goes blank.
 */
export function formatIso(iso: string): string {
  try {
    return new Date(iso).toLocaleString();
  } catch {
    return iso;
  }
}

/**
 * Format an elapsed duration in seconds as a compact age (`45s`, `12m`,
 * `3h 20m`, `2d 4h`).
 *
 * Used for staleness — "how long has the oldest sync job been waiting" — where
 * the operator's question is scale, not precision: a queue 3 hours behind and
 * one 3 hours and 12 minutes behind call for the same action. Seconds are shown
 * only under a minute, where they are the whole signal.
 */
export function formatDuration(seconds: number): string {
  if (!Number.isFinite(seconds) || seconds < 0) return "—";
  if (seconds < 60) return `${Math.floor(seconds)}s`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) {
    const rem = minutes % 60;
    return rem ? `${hours}h ${rem}m` : `${hours}h`;
  }
  const days = Math.floor(hours / 24);
  const rem = hours % 24;
  return rem ? `${days}d ${rem}h` : `${days}d`;
}

/**
 * Format a Unix-seconds epoch (i.e. `seconds since 1970-01-01 UTC`)
 * into the operator's locale-string. Used by session / ACL rows
 * that carry epochs rather than ISO strings.
 */
export function formatEpoch(epoch: number): string {
  try {
    return new Date(epoch * 1000).toLocaleString();
  } catch {
    return String(epoch);
  }
}
