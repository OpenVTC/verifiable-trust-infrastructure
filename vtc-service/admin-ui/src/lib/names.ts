// DID → human-readable display name, for the admin console.
//
// Mirrors `vta_sdk::display_name` on the Rust side — same sources, same
// precedence, same trust rules. The two must agree: an operator moves between
// `vtc acl list` in a terminal and this console looking at the same community,
// and a DID that is "payroll-bot" in one place and an opaque string in the
// other is a DID they have to re-identify every time they switch.
//
// # The model
//
// A `NameBook` is a `DID → name` map built from responses the console has
// already fetched. It is not a resolver and performs no lookups of its own:
// `useNameBook()` reads the members and ACL listings — two requests, shared
// and cached by react-query across every plugin — and every DID rendered
// anywhere in the console resolves against that.
//
// # Trust
//
// Sources are not equally trustworthy, so `NameSource` is kept rather than
// flattened to a string. A label was typed by an operator into this
// community's own store. A *verified* agent name round-tripped: the DID's
// document claimed it and resolving that name led back to the same DID.
//
// An **unverified** agent name is neither. `alsoKnownAs` is self-asserted —
// the agent-name specification's two-sided binding protects the name→DID
// direction, not the reverse — so a hostile DID can claim
// `mybank.com/@treasury`. Such names rank below every local source and must
// render with their `[unverified]` marker intact; `nameOf` attaches it, and
// no caller should strip it.
//
// Nothing in this deployment publishes `alsoKnownAs` yet, so agent names do
// not appear here today. The shape is in place so they light up without a
// change to any render site.

import { useQuery } from "@tanstack/react-query";

import { getJson } from "@/lib/api";
import { shortenDid } from "@/lib/format";

export type NameSource =
  | "agent-name"
  | "agent-name-unverified"
  | "acl-label"
  | "device-name"
  | "local-alias"
  | "server-label"
  | "context-name";

/** Precedence when two sources name the same DID. Higher wins.
 *  Must stay in step with `NameSource::rank` in Rust. */
const RANK: Record<NameSource, number> = {
  "agent-name": 100,
  "acl-label": 60,
  "local-alias": 50,
  "device-name": 45,
  "server-label": 40,
  "context-name": 30,
  // Lowest by a wide margin: an unchecked claim must never displace the
  // operator's own data.
  "agent-name-unverified": 10,
};

/** Whether a name from this source may be shown without qualification. */
export function isTrusted(source: NameSource): boolean {
  return source !== "agent-name-unverified";
}

export interface DisplayName {
  name: string;
  source: NameSource;
}

/** Marker appended to an unverified name. Restyle it if you like; do not
 *  drop it. */
export const UNVERIFIED_SUFFIX = " [unverified]";

export class NameBook {
  private entries = new Map<string, DisplayName>();

  /** Record a name, keeping whichever source ranks higher. Idempotent and
   *  order-independent, so books can be merged from several responses in
   *  whatever order they arrive. Blank names are dropped — an unset label
   *  often arrives as `""`, and storing it would blank out the DID. */
  insert(did: string, name: string | null | undefined, source: NameSource): void {
    if (!name || !name.trim()) return;
    const existing = this.entries.get(did);
    if (existing && RANK[existing.source] >= RANK[source]) return;
    this.entries.set(did, { name: name.trim(), source });
  }

  get(did: string): DisplayName | undefined {
    return this.entries.get(did);
  }

  get size(): number {
    return this.entries.size;
  }

  /** The name for `did`, tagged when unverified. `undefined` when unnamed,
   *  so callers choose between a placeholder and the shortened DID. */
  nameOf(did: string): string | undefined {
    const entry = this.entries.get(did);
    if (!entry) return undefined;
    return isTrusted(entry.source) ? entry.name : `${entry.name}${UNVERIFIED_SUFFIX}`;
  }

  /** Whether any of `dids` has a name — drives whether a table gives up a
   *  column to names at all. A column of dashes is worse than no column. */
  namesAny(dids: Iterable<string>): boolean {
    for (const did of dids) if (this.entries.has(did)) return true;
    return false;
  }

  /** Name where we have one, shortened DID otherwise. For a cell that has no
   *  room for both. */
  nameOrDid(did: string): string {
    return this.nameOf(did) ?? shortenDid(did);
  }
}

// ── The shared book ─────────────────────────────────────────────────

interface NamedMember {
  did: string;
  label: string | null;
}

interface NamedAclEntry {
  subject: string;
  label?: string | null;
}

const MEMBERS_TASK = "https://trusttasks.org/spec/vtc/members/list/0.1";
const ACL_TASK = "https://trusttasks.org/spec/acl/list/0.1";

/**
 * The console-wide `NameBook`.
 *
 * Two requests — the member list and the ACL list — cover every principal
 * this community knows by name. react-query shares one copy across every
 * plugin that calls this, so a page rendering members, sessions and audit
 * side by side still pays for it once.
 *
 * Failures are swallowed: naming is decoration, and an admin who can read
 * sessions but not the ACL must still get their table. The book simply comes
 * back smaller, and DIDs render bare.
 */
export function useNameBook(): NameBook {
  const query = useQuery({
    queryKey: ["name-book"],
    queryFn: async () => {
      const book = new NameBook();

      const [members, acl] = await Promise.allSettled([
        getJson<{ items: NamedMember[] }>("/v1/members?limit=500", {
          trustTask: MEMBERS_TASK,
        }),
        getJson<{ entries: NamedAclEntry[] }>("/v1/acl", {
          trustTask: ACL_TASK,
        }),
      ]);

      if (members.status === "fulfilled") {
        for (const m of members.value.items ?? []) {
          book.insert(m.did, m.label, "acl-label");
        }
      }
      if (acl.status === "fulfilled") {
        for (const e of acl.value.entries ?? []) {
          book.insert(e.subject, e.label, "acl-label");
        }
      }
      return book;
    },
    // Labels change rarely and this is decoration on every other view;
    // refetching it on each mount would triple the console's request count.
    staleTime: 60_000,
  });

  return query.data ?? EMPTY_BOOK;
}

/** Shared empty book, so `useNameBook()` never returns a fresh object while
 *  loading — a new identity each render would defeat memoisation downstream. */
const EMPTY_BOOK = new NameBook();
