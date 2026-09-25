// Repos admin API — the reads the Repos plugin renders.
//
// None of these is a specification's read. The one that is —
// `GET /v1/git-ns/view`, gated on `git-ns/view/0.1` — is not used here: the
// screens need the admin columns (admins, bootstrap, forge status) that only
// the console projections carry. Those are projections no specification defines — namespaces with
// their admins and forge status, repositories with bootstrap and guard,
// rights, drift, jobs, the registry mirror, linked accounts, activity — so the
// daemon mounts them behind the admin session with **no** Trust-Task binding
// (`routes/mod.rs`: gating them on `git-ns/view/0.1` would claim a response
// shape they do not have). They go through `getJsonExempt` for that reason,
// which is the smell the helper is meant to be: each one is named here.
//
// Writes are not in this file. Every change is a signed `git-ns/*` Trust Task;
// `actions.ts` builds them and sends them from this browser's console key
// where one is enrolled.

import { getJson, getJsonExempt } from "@/lib/api";
import type {
  GitNsAccountList,
  GitNsActivity,
  GitNsDepartedGrants,
  GitNsDriftList,
  GitNsJobList,
  GitNsNamespaceList,
  GitNsProjection,
  GitNsRepoList,
  GitNsRightList,
  MembersPage,
} from "@/lib/wire-types";

const TASK_MEMBERS_LIST = "https://trusttasks.org/spec/vtc/members/list/0.1";

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
  accounts: ["git-ns", "accounts"] as const,
  activity: (namespace: string) => ["git-ns", "activity", namespace] as const,
  members: ["git-ns", "members"] as const,
};

export const fetchNamespaces = (): Promise<GitNsNamespaceList> =>
  getJsonExempt<GitNsNamespaceList>("/v1/git-ns/namespaces");

/** Every repository. Filtering happens client-side: the overview shows every
 *  namespace's counts at once, and a per-namespace request would be one round
 *  trip per card for rows the next click needs anyway. */
export const fetchRepos = (): Promise<GitNsRepoList> =>
  getJsonExempt<GitNsRepoList>("/v1/git-ns/repos");

/** Live rights, recorded and role-derived, across every namespace. */
export const fetchRights = (): Promise<GitNsRightList> =>
  getJsonExempt<GitNsRightList>("/v1/git-ns/rights");

export const fetchIssuedByDeparted = (): Promise<GitNsDepartedGrants> =>
  getJsonExempt<GitNsDepartedGrants>("/v1/git-ns/rights/issued-by-departed");

export const fetchDrift = (): Promise<GitNsDriftList> =>
  getJsonExempt<GitNsDriftList>("/v1/git-ns/drift");

export const fetchJobs = (): Promise<GitNsJobList> =>
  getJsonExempt<GitNsJobList>("/v1/git-ns/jobs");

export const fetchProjection = (): Promise<GitNsProjection> =>
  getJsonExempt<GitNsProjection>("/v1/git-ns/projection");

/** Members' linked forge accounts (`git-ns/account/link`). `id` is
 *  authoritative; `login` is display only — logins are renamed and
 *  re-registered. */
export const fetchAccounts = (): Promise<GitNsAccountList> =>
  getJsonExempt<GitNsAccountList>("/v1/git-ns/accounts");

/**
 * What happened in one namespace, newest first: rights changes, drift and
 * bridge jobs, read from the git-ns audit rows and the job queue.
 *
 * Narrowed server-side to namespaces the *caller* administers, so a community
 * administrator who holds no `git.ns.admin` there is answered 403 — which the
 * screens render as that, not as an empty history.
 */
export const fetchActivity = (namespace: string, limit = 100): Promise<GitNsActivity> =>
  getJsonExempt<GitNsActivity>(
    `/v1/git-ns/activity?namespace=${encodeURIComponent(namespace)}&limit=${limit}`,
  );

/** The listing clamps a page to 200; asking for more returns 200 silently. */
const MEMBERS_PAGE = 200;

/** One page of current members, for the person picker. */
export async function fetchMembersPage(
  cursor: string | null,
): Promise<{ members: { did: string; label?: string | null }[]; nextCursor: string | null }> {
  const q = new URLSearchParams({ limit: String(MEMBERS_PAGE) });
  if (cursor) q.set("cursor", cursor);
  const page = await getJson<MembersPage>(`/v1/members?${q}`, { trustTask: TASK_MEMBERS_LIST });
  return {
    members: (page.items ?? []).map((m) => ({ did: m.did, label: m.label })),
    nextCursor: page.nextCursor ?? null,
  };
}

/** DID → forge host → linked account. */
export type ForgeAccounts = Map<string, Map<string, { id: string; login: string }>>;

/** Current members' accounts only: one whose member's access lapsed is still
 *  theirs (nobody else may link it) but projects no role and cannot be
 *  adopted, so no screen offers either for it. */
export function indexAccounts(list: GitNsAccountList | undefined): ForgeAccounts {
  const out: ForgeAccounts = new Map();
  for (const a of list?.accounts ?? []) {
    if (!a.memberCurrent) continue;
    const byHost = out.get(a.member) ?? new Map<string, { id: string; login: string }>();
    byHost.set(a.forge, { id: a.id, login: a.login });
    out.set(a.member, byHost);
  }
  return out;
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
