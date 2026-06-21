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
