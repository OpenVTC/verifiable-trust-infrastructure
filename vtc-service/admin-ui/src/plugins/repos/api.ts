// Repos admin API — the reads the Repos plugin renders.
//
// Every read here is a signed Trust Task: the namespaces, the repositories,
// the break-glass records, the rights lists, the bridge job queue, the Trust
// Registry projection, the linked-account roster and the activity feed are
// `git-ns/namespace/list/0.1`, `git-ns/repo/list/0.1`, `git-ns/view/0.5`
// (`scope: administrator`, `breakGlass: true`), `git-ns/right/list/0.1`,
// `git-ns/right/issued-by-departed/0.1`, `git-ns/bridge/job/list/0.1`,
// `git-ns/projection/show/0.1`, `git-ns/account/list/0.1` and
// `git-ns/activity/list/0.1` — signed with this browser's console key and
// posted to `/v1/trust-tasks`, the same documents `cnm git` sends over TSP or
// DIDComm. The daemon answers each to the entitlement its own specification
// names (the community-administrator capability for the four
// community-wide reads; either that or `git.ns.admin` on the namespace for
// the rest), never on the strength of a session, so there is no bearer
// fallback: a browser that cannot sign gets `SigningUnavailableError`, which
// the screens turn into "enable console signing".
//
// Each of the six added in trustoverip/dtgwg-trust-tasks-tf#686 pages: at
// most 500 rows a call (default 100), with a `nextCursor` to continue. The
// console reads one page — its screens are single-community operator
// consoles, not audit exports — the same posture `namespace/list` and
// `repo/list` already have with no paging at all.
//
// Writes are not in this file. Every change is a signed `git-ns/*` Trust Task;
// `actions.ts` builds them and sends them from this browser's console key
// where one is enrolled.

import { postSignedRead } from "@/lib/api";
import type {
  GitNsAccountList,
  GitNsActivity,
  GitNsBreakGlassMark,
  GitNsDepartedGrants,
  GitNsDriftItem,
  GitNsJobList,
  GitNsNamespaceList,
  GitNsProjection,
  GitNsRepoList,
  GitNsRightList,
  MembersPage,
} from "@/lib/wire-types";

import type { GitNsBreakGlassItem, GitNsBreakGlassList, GitNsSelfGrantWaived } from "./model";
import { breakGlassState, selfGrantWaivedOf } from "./model";

const TASK_MEMBERS_LIST = "https://trusttasks.org/spec/vtc/members/list/0.1";

// trust-tasks-rs 0.23.4 generates the Rust side of the first three
// (`git_ns::admin_reads`, trustoverip/dtgwg-trust-tasks-tf#659), and 0.24.7
// the other six (trustoverip/dtgwg-trust-tasks-tf#686). No TypeScript binding
// is published for either, so the URIs and the view response shape below stay
// hand-written here, matching the spec.
export const TASK_NAMESPACE_LIST = "https://trusttasks.org/spec/git-ns/namespace/list/0.1";
export const TASK_REPO_LIST = "https://trusttasks.org/spec/git-ns/repo/list/0.1";
export const TASK_VIEW = "https://trusttasks.org/spec/git-ns/view/0.5";
export const TASK_RIGHT_LIST = "https://trusttasks.org/spec/git-ns/right/list/0.1";
export const TASK_RIGHT_ISSUED_BY_DEPARTED =
  "https://trusttasks.org/spec/git-ns/right/issued-by-departed/0.1";
export const TASK_BRIDGE_JOB_LIST = "https://trusttasks.org/spec/git-ns/bridge/job/list/0.1";
export const TASK_PROJECTION_SHOW = "https://trusttasks.org/spec/git-ns/projection/show/0.1";
export const TASK_ACCOUNT_LIST = "https://trusttasks.org/spec/git-ns/account/list/0.1";
export const TASK_ACTIVITY_LIST = "https://trusttasks.org/spec/git-ns/activity/list/0.1";

/** The parts of a `git-ns/view/0.5#response` the break-glass list and the drift read. */
interface GitNsViewAnswer {
  namespaces: { id: string; forge: string; owner: string }[];
  repos?: {
    resource: string;
    sync: { state: string; checkedAt?: string; drift: GitNsDriftItem[] };
  }[];
  rights: {
    subject: string;
    right: string;
    resource: string;
    grantedAt: string;
    breakGlass?: GitNsBreakGlassMark | null;
  }[];
  /** The records single-administrator mode's waiver of separation of duties
   *  made (`ext.org.openvtc.selfGrantWaived`, VTI-APV-022): `RightRecord`
   *  admits no member to carry the mark, so the view lists them beside. */
  ext?: { "org.openvtc"?: { selfGrantWaived?: unknown } };
}

/** The outstanding drift on one repository: its `repos[].sync` in the view. */
export interface GitNsDriftRow {
  resource: string;
  state: string;
  checkedAt?: string;
  drift: GitNsDriftItem[];
}

/** Every repository with outstanding drift — and, from the same view, every
 *  record made under single-administrator mode's self-grant waiver. */
export interface GitNsDriftList {
  repos: GitNsDriftRow[];
  waived: GitNsSelfGrantWaived[];
}

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
  breakGlass: ["git-ns", "break-glass"] as const,
};

/** The namespaces this administrator administers — every one, for a
 *  community administrator (`git-ns/namespace/list/0.1`). */
export const fetchNamespaces = (): Promise<GitNsNamespaceList> =>
  postSignedRead<GitNsNamespaceList>(TASK_NAMESPACE_LIST, {});

/** Every repository. Filtering happens client-side: the overview shows every
 *  namespace's counts at once, and a per-namespace request would be one round
 *  trip per card for rows the next click needs anyway. */
export const fetchRepos = (): Promise<GitNsRepoList> =>
  postSignedRead<GitNsRepoList>(TASK_REPO_LIST, {});

/** Live rights, recorded and role-derived, across every namespace
 *  (`git-ns/right/list/0.1`; the community-administrator capability). */
export const fetchRights = (): Promise<GitNsRightList> =>
  postSignedRead<GitNsRightList>(TASK_RIGHT_LIST, {});

/** Recorded rights whose granter has since left, grouped by granter
 *  (`git-ns/right/issued-by-departed/0.1`; the community-administrator
 *  capability). */
export const fetchIssuedByDeparted = (): Promise<GitNsDepartedGrants> =>
  postSignedRead<GitNsDepartedGrants>(TASK_RIGHT_ISSUED_BY_DEPARTED, {});

/**
 * Every repository whose forge differs from the projection, in the namespaces
 * the caller administers: `git-ns/view/0.5` with `scope: administrator`,
 * whose `repos[].sync` is the drift the bridge last reported. The same answer
 * lists the self-grants single-administrator mode waived, which the people
 * tables flag (`SelfGrantWaivedChip`), so they come with it rather than as a
 * second read of the same view.
 */
export async function fetchDrift(): Promise<GitNsDriftList> {
  const view = await postSignedRead<GitNsViewAnswer>(TASK_VIEW, { scope: "administrator" });
  return { repos: driftRows(view), waived: selfGrantWaivedOf(view.ext) };
}

/** The repositories in `view` with outstanding drift. */
export function driftRows(view: GitNsViewAnswer): GitNsDriftRow[] {
  return (view.repos ?? [])
    .filter((r) => r.sync.drift.length > 0)
    .map((r) => ({
      resource: r.resource,
      state: r.sync.state,
      checkedAt: r.sync.checkedAt,
      drift: r.sync.drift,
    }));
}

/** Bridge jobs in the namespaces the caller administers
 *  (`git-ns/bridge/job/list/0.1`). */
export const fetchJobs = (): Promise<GitNsJobList> =>
  postSignedRead<GitNsJobList>(TASK_BRIDGE_JOB_LIST, {});

/** What is published to the Trust Registry, and how far it is from what the
 *  VTC's records currently call for (`git-ns/projection/show/0.1`; the
 *  community-administrator capability). */
export const fetchProjection = (): Promise<GitNsProjection> =>
  postSignedRead<GitNsProjection>(TASK_PROJECTION_SHOW, {});

/** Members' linked forge accounts (`git-ns/account/list/0.1`; the
 *  community-administrator capability). `id` is authoritative; `login` is
 *  display only — logins are renamed and re-registered. */
export const fetchAccounts = (): Promise<GitNsAccountList> =>
  postSignedRead<GitNsAccountList>(TASK_ACCOUNT_LIST, {});

/**
 * What happened in one namespace, newest first: rights changes, drift and
 * bridge jobs, read from the git-ns audit rows and the job queue
 * (`git-ns/activity/list/0.1`).
 *
 * Narrowed server-side to namespaces the *caller* administers, so a community
 * administrator who holds no `git.ns.admin` there is refused
 * `git-ns/activity/list:notAdministrator` — which the screens render as that,
 * not as an empty history.
 */
export const fetchActivity = (namespace: string, limit = 100): Promise<GitNsActivity> =>
  postSignedRead<GitNsActivity>(TASK_ACTIVITY_LIST, { namespace, limit });

/**
 * Break-glass records — self-granted elevated rights (`git-ns/right/break-glass`)
 * — in the namespaces the caller administers: every one for a community
 * administrator, those of their own namespaces for a namespace admin, and
 * `git-ns/view:notAdministrator` for anyone else. Ratified ones included, as
 * their history.
 *
 * `git-ns/view/0.5` with `scope: administrator` and `breakGlass: true`,
 * shaped here into the list the screens render: each record with its
 * namespace and its state, unratified and delayed first, newest first.
 *
 * Read by the shell's banner on every page as well as by the Repos list, so
 * it lives under `gitNsKeys.all` and refreshes with every change sent here.
 */
export async function fetchBreakGlass(): Promise<GitNsBreakGlassList> {
  const view = await postSignedRead<GitNsViewAnswer>(TASK_VIEW, {
    scope: "administrator",
    breakGlass: true,
  });
  return { items: breakGlassItems(view) };
}

/** A `breakGlass: true` view as break-glass items. */
export function breakGlassItems(view: GitNsViewAnswer, now = Date.now()): GitNsBreakGlassItem[] {
  const items: GitNsBreakGlassItem[] = [];
  for (const r of view.rights ?? []) {
    const mark = r.breakGlass;
    const state = breakGlassState(mark, now);
    if (!mark || !state) continue;
    const nsResource = r.resource.split("/").slice(0, 2).join("/");
    const ns = (view.namespaces ?? []).find((n) => `${n.forge}/${n.owner}` === nsResource);
    items.push({
      namespace: ns?.id ?? "",
      namespaceResource: nsResource,
      subject: r.subject,
      right: r.right,
      resource: r.resource,
      grantedAt: r.grantedAt,
      breakGlass: mark,
      state,
    });
  }
  return items.sort(
    (a, b) =>
      Number(a.state === "ratified") - Number(b.state === "ratified") ||
      b.breakGlass.at.localeCompare(a.breakGlass.at),
  );
}

/** The listing clamps a page to 200; asking for more returns 200 silently. */
const MEMBERS_PAGE = 200;

/** One page of current members, for the person picker. */
export async function fetchMembersPage(
  cursor: string | null,
): Promise<{ members: { did: string; label?: string | null }[]; nextCursor: string | null }> {
  const page = await postSignedRead<MembersPage>(TASK_MEMBERS_LIST, {
    limit: MEMBERS_PAGE,
    ...(cursor ? { cursor } : {}),
  });
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
    byHost.set(a.account.forge, { id: a.account.id, login: a.account.login });
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
