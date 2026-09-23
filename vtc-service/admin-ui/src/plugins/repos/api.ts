// Repos admin API — the reads the Repos plugin renders.
//
// Every route here is one of the administrator's projections of the single
// read the `git-ns/*` family defines, and the daemon gates each of them on
// that task's URI (`routes/mod.rs`, `GIT_NS_VIEW`), so every call carries it.
// Borrowing another URI would be refused; sending none would be too.
//
// There are no writes in this file, and that is the daemon's decision rather
// than an omission: every change to a git right is a *signed* `git-ns/*` Trust
// Task, authorized by the signer's own git rights, and the console cannot yet
// sign one (#1641). `actions.ts` builds those documents for the administrator
// to sign instead.

import { getJson } from "@/lib/api";
import type {
  GitNsDepartedGrants,
  GitNsDriftList,
  GitNsJobList,
  GitNsNamespaceList,
  GitNsProjection,
  GitNsRepoList,
  GitNsRightList,
  MembersPage,
} from "@/lib/wire-types";

/** `git-ns/view/0.1` — the one task every admin read here is gated on. */
export const TASK_GIT_NS_VIEW = "https://trusttasks.org/spec/git-ns/view/0.1";
const TASK_MEMBERS_LIST = "https://trusttasks.org/spec/vtc/members/list/0.1";

const view = { trustTask: TASK_GIT_NS_VIEW };

/** Query keys. Everything under `["git-ns"]` is refreshed together. */
export const gitNsKeys = {
  all: ["git-ns"] as const,
  namespaces: ["git-ns", "namespaces"] as const,
  repos: ["git-ns", "repos"] as const,
  rights: ["git-ns", "rights"] as const,
  departed: ["git-ns", "departed"] as const,
  drift: ["git-ns", "drift"] as const,
  jobs: ["git-ns", "jobs"] as const,
  projection: ["git-ns", "projection"] as const,
  memberFacts: ["git-ns", "member-facts"] as const,
};

export const fetchNamespaces = (): Promise<GitNsNamespaceList> =>
  getJson<GitNsNamespaceList>("/v1/git-ns/namespaces", {
    ...view,
    requires: ["namespaces"],
  });

/** Every repository. Filtering happens client-side: the overview shows every
 *  namespace's counts at once, and a per-namespace request would be one round
 *  trip per card for rows the next click needs anyway. */
export const fetchRepos = (): Promise<GitNsRepoList> =>
  getJson<GitNsRepoList>("/v1/git-ns/repos", { ...view, requires: ["repos"] });

/** Live rights, recorded and role-derived, across every namespace. */
export const fetchRights = (): Promise<GitNsRightList> =>
  getJson<GitNsRightList>("/v1/git-ns/rights", { ...view, requires: ["rights"] });

export const fetchIssuedByDeparted = (): Promise<GitNsDepartedGrants> =>
  getJson<GitNsDepartedGrants>("/v1/git-ns/rights/issued-by-departed", {
    ...view,
    requires: ["granters", "cascadeOnDeparture"],
  });

export const fetchDrift = (): Promise<GitNsDriftList> =>
  getJson<GitNsDriftList>("/v1/git-ns/drift", { ...view, requires: ["repos"] });

export const fetchJobs = (): Promise<GitNsJobList> =>
  getJson<GitNsJobList>("/v1/git-ns/jobs", { ...view, requires: ["jobs"] });

export const fetchProjection = (): Promise<GitNsProjection> =>
  getJson<GitNsProjection>("/v1/git-ns/projection", {
    ...view,
    requires: ["published", "registryConfigured"],
  });

/** One linked forge account, as the bridge stored it on the member row
 *  (`extensions.forges[<host>] = {id, login}`). `id` is authoritative;
 *  `login` is display only — logins are renamed and re-registered. */
export interface ForgeAccount {
  id: string;
  login: string;
}

/** DID → forge host → linked account. */
export type ForgeAccounts = Map<string, Map<string, ForgeAccount>>;

export interface MemberFacts {
  /** Current members, for the person picker. */
  members: { did: string; label?: string | null }[];
  forges: ForgeAccounts;
}

/**
 * Current members and their linked forge accounts, read off the member
 * listing.
 *
 * No git-ns route carries the accounts: `git-ns/account/link` records the
 * link on the member, and the members listing is where a member's
 * `extensions` are served. Anything in `extensions.forges` that is not the
 * `{id, login}` the bridge writes is skipped rather than guessed at.
 */
export async function fetchMemberFacts(): Promise<MemberFacts> {
  const page = await getJson<MembersPage>("/v1/members?limit=500", {
    trustTask: TASK_MEMBERS_LIST,
  });
  const members: MemberFacts["members"] = [];
  const forges: ForgeAccounts = new Map();
  for (const m of page.items ?? []) {
    members.push({ did: m.did, label: m.label });
    const linked = (m.extensions as { forges?: unknown } | null)?.forges;
    if (!linked || typeof linked !== "object") continue;
    const byHost = new Map<string, ForgeAccount>();
    for (const [host, acct] of Object.entries(linked as Record<string, unknown>)) {
      const a = acct as { id?: unknown; login?: unknown } | null;
      if (a && (typeof a.id === "string" || typeof a.id === "number")) {
        byHost.set(host, {
          id: String(a.id),
          login: typeof a.login === "string" ? a.login : String(a.id),
        });
      }
    }
    if (byHost.size > 0) forges.set(m.did, byHost);
  }
  return { members, forges };
}

/** The member whose linked account on `forge` has this id, if any. */
export function memberForAccount(
  forges: ForgeAccounts,
  forge: string,
  id: string,
): string | undefined {
  for (const [did, byHost] of forges) {
    if (byHost.get(forge)?.id === id) return did;
  }
  return undefined;
}
