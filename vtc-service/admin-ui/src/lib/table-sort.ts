// Search and sort for the Members list.
//
// The list is read whole (every page of `vtc/members/list/0.1`) and searched
// and sorted here, in the browser: the listing's only server-side filter is an
// exact role, and an operator looking for someone types a fragment of a name,
// a DID's handle or a forge login.
//
// "Lazy" matching: every whitespace-separated term of the query must match
// some field of the row. A term matches a field when it is a substring of it
// (case-insensitive) or — on the short, human fields only — when its letters
// appear in order (`glarr` finds `glance-arrow`). In-order matching is kept
// off the full DID: nearly any short term is a subsequence of a 60-character
// identifier, so it would match every row.

/** What a row is searched by. */
export interface SearchFields {
  /** Human, short: name, role, forge logins, right labels, the DID's handle. */
  short: string[];
  /** Long or opaque: the full DID, resources. Substring matches only. */
  long: string[];
}

const fold = (s: string) => s.toLowerCase();

/** Whether `needle`'s characters appear in `hay` in order. */
function isSubsequence(needle: string, hay: string): boolean {
  let i = 0;
  for (let j = 0; j < hay.length && i < needle.length; j++) {
    if (hay[j] === needle[i]) i++;
  }
  return i === needle.length;
}

/** The query's terms, folded; empty for a blank query. */
export function searchTerms(query: string): string[] {
  return fold(query).split(/\s+/).filter(Boolean);
}

/**
 * How well `fields` match `terms`: `null` when some term matches nothing,
 * otherwise a score where higher is better — a match at the start of a word
 * beats one inside it, which beats letters merely in order.
 */
export function matchScore(terms: string[], fields: SearchFields): number | null {
  if (terms.length === 0) return 0;
  const short = fields.short.map(fold);
  const long = fields.long.map(fold);
  let total = 0;
  for (const term of terms) {
    let best = 0;
    for (const f of [...short, ...long]) {
      const at = f.indexOf(term);
      if (at < 0) continue;
      const wordStart = at === 0 || /[^a-z0-9]/.test(f[at - 1]!);
      best = Math.max(best, wordStart ? 3 : 2);
      if (best === 3) break;
    }
    if (best === 0 && short.some((f) => isSubsequence(term, f))) best = 1;
    if (best === 0) return null;
    total += best;
  }
  return total;
}

/** The last segment of a DID — `glance-arrow` of a `did:webvh:…:glance-arrow`. */
export function didHandle(did: string): string {
  const parts = did.split(":");
  return parts.length > 2 ? parts[parts.length - 1]! : "";
}

export type SortDir = "asc" | "desc";

export interface SortState<K extends string> {
  key: K;
  dir: SortDir;
}

/** The next sort after a click on `key`'s header: a new column starts at its
 *  natural direction, the same column flips. */
export function nextSort<K extends string>(
  current: SortState<K> | null,
  key: K,
  initialDir: SortDir = "asc",
): SortState<K> {
  if (current?.key === key) return { key, dir: current.dir === "asc" ? "desc" : "asc" };
  return { key, dir: initialDir };
}

/** A sort key's value for one row. `null` sorts last in either direction:
 *  a member with no name is not "before A". */
export type SortValue = string | number | null;

/** Compare two sort values in `dir`, empties last. */
export function compareValues(a: SortValue, b: SortValue, dir: SortDir): number {
  if (a === null || a === "") return b === null || b === "" ? 0 : 1;
  if (b === null || b === "") return -1;
  const c =
    typeof a === "number" && typeof b === "number"
      ? a - b
      : String(a).localeCompare(String(b), undefined, { numeric: true, sensitivity: "base" });
  return dir === "asc" ? c : -c;
}
