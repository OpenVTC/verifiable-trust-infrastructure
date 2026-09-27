// Answers for the Repos tests, in the daemon's own wire shapes — typed against
// the generated schemas, so a response change fails to compile here as it
// would in the plugin.

import type {
  GitNsAccountRow,
  GitNsActivityItem,
  GitNsNamespaceRow,
  GitNsRepoRow,
  GitNsRightRow,
} from "@/lib/wire-types";
import { type MockRoute } from "@/test/render";

import { TASK_NAMESPACE_LIST, TASK_REPO_LIST, TASK_VIEW } from "./api";
import type { GitNsBreakGlassItem } from "./model";

export const VTC = "did:webvh:QmVtc:acme.dev";
export const BRIDGE = "did:webvh:QmBridge:bridge.acme.dev";
export const ALICE = "did:webvh:QmAlice:alice.dev";
export const BOB = "did:webvh:QmBob:bob.dev";
export const HANA = "did:webvh:QmHana:hana.me";
export const JUN = "did:webvh:QmJun:jun.dev";
export const GUS = "did:webvh:QmGus:gus.dev";
export const PRIYA = "did:webvh:QmPriya:priya.dev";

export const ACME: GitNsNamespaceRow = {
  id: "ns_acme",
  forge: "github.com",
  owner: "acme",
  resource: "github.com/acme",
  mode: "bridge",
  state: "bound",
  kind: "organization",
  ownerId: "91827364",
  bridgeDid: BRIDGE,
  boundBy: ALICE,
  requestedAt: "2026-08-01T00:00:00Z",
  boundAt: "2026-08-01T00:10:00Z",
  admins: [ALICE],
  repoCount: 4,
  headless: false,
  installationRemoved: false,
  roleDrift: "report",
  cascadeOnDeparture: false,
  roleMap: { own: "admin", maintain: "maintain", commit: "none" },
  roleMapSource: "reported",
  roleMapReportedAt: "2026-09-25T00:00:00Z",
};

export const PERSONAL: GitNsNamespaceRow = {
  id: "ns_glenn",
  forge: "github.com",
  owner: "glenn-g",
  resource: "github.com/glenn-g",
  mode: "manual",
  state: "bound",
  kind: "user",
  boundBy: ALICE,
  requestedAt: "2026-08-01T00:00:00Z",
  boundAt: "2026-08-01T00:00:00Z",
  admins: [ALICE],
  repoCount: 0,
  headless: false,
  installationRemoved: false,
  roleDrift: "report",
  cascadeOnDeparture: false,
  roleMapSource: "unknown",
};

const BOOT_ALL = { workflow: true, keyring: true, variables: true, requiredCheck: true };
const BOOT_NONE = { workflow: false, keyring: false, variables: false, requiredCheck: false };

export const WIDGETS: GitNsRepoRow = {
  id: "repo_widgets",
  namespace: "ns_acme",
  resource: "github.com/acme/widgets",
  forgeId: "812736451",
  visibility: "public",
  state: "active",
  owners: [ALICE],
  maintainers: 1,
  committers: 2,
  bootstrap: BOOT_ALL,
  syncState: "inSync",
  driftCount: 0,
  createdBy: ALICE,
  createdAt: "2026-08-02T00:00:00Z",
  steps: [],
  roleMap: { own: "admin", maintain: "maintain", commit: "none" },
  roleMapStale: false,
};

export const DOCS: GitNsRepoRow = {
  ...WIDGETS,
  id: "repo_docs",
  resource: "github.com/acme/docs",
  forgeId: "812736452",
  owners: [BOB],
  syncState: "drift",
  driftCount: 1,
};

export const LEGACY: GitNsRepoRow = {
  ...WIDGETS,
  id: "repo_legacy",
  resource: "github.com/acme/legacy-cli",
  visibility: "private",
  state: "orphaned",
  owners: [],
  bootstrap: { ...BOOT_ALL, requiredCheck: false },
};

export const SANDBOX: GitNsRepoRow = {
  ...WIDGETS,
  id: "repo_sandbox",
  resource: "github.com/acme/sandbox",
  forgeId: "812736459",
  state: "unmanaged",
  owners: [],
  maintainers: 0,
  committers: 0,
  bootstrap: BOOT_NONE,
  syncState: "unchecked",
  createdBy: null,
};

const right = (r: Partial<GitNsRightRow> & Pick<GitNsRightRow, "subject" | "right" | "resource">): GitNsRightRow => ({
  origin: "recorded",
  grantedBy: ALICE,
  grantedAt: "2026-08-09T00:00:00Z",
  subjectMember: true,
  granterDeparted: false,
  ...r,
});

/** A right row with the fixtures' defaults. */
export const rightRow = right;

export const RIGHTS: GitNsRightRow[] = [
  right({ subject: ALICE, right: "git.ns.admin", resource: "github.com/acme", grantedBy: ALICE }),
  right({ subject: BOB, right: "git.repo.create", resource: "github.com/acme" }),
  right({
    subject: BRIDGE,
    right: "git.commit.sign",
    resource: "github.com/acme",
    grantedBy: VTC,
    subjectMember: false,
  }),
  right({ subject: ALICE, right: "git.repo.own", resource: "github.com/acme/widgets" }),
  right({ subject: HANA, right: "git.repo.maintain", resource: "github.com/acme/widgets" }),
  right({
    subject: JUN,
    right: "git.commit.sign",
    resource: "github.com/acme/widgets",
    subjectMember: false,
    expiresAt: "2099-12-31T00:00:00Z",
    reason: "OSS contributor",
  }),
  right({
    subject: PRIYA,
    right: "git.commit.sign",
    resource: "github.com/acme/widgets",
    grantedBy: GUS,
    granterDeparted: true,
  }),
  right({ subject: BOB, right: "git.repo.own", resource: "github.com/acme/docs" }),
];

export const member = (did: string, label: string) => ({
  did,
  label,
  role: "member",
  joinedAt: "2025-01-01T00:00:00Z",
  personhood: false,
  publishConsent: false,
  departurePreference: "tombstone",
  extensions: {},
});

export const MEMBERS = [
  member(ALICE, "Alice Wong"),
  member(BOB, "Bob Mensah"),
  member(HANA, "Hana Sato"),
  member(PRIYA, "Priya Nair"),
];

export const ACCOUNTS: GitNsAccountRow[] = [
  { member: ALICE, forge: "github.com", id: "1001", login: "alicew", memberCurrent: true },
  { member: BOB, forge: "github.com", id: "1002", login: "bobm", memberCurrent: true },
  { member: HANA, forge: "github.com", id: "1003", login: "hsato", memberCurrent: true },
];

export const ACTIVITY: GitNsActivityItem[] = [
  {
    source: "audit",
    action: "gitNs.right.granted",
    at: "2026-09-21T10:00:00Z",
    actor: ALICE,
    subject: JUN,
    right: "git.commit.sign",
    resource: "github.com/acme/widgets",
    namespace: "ns_acme",
  },
  {
    source: "job",
    action: "gitNs.job.bootstrap",
    at: "2026-08-02T00:05:00Z",
    detail: "succeeded",
    resource: "github.com/acme/widgets",
    namespace: "ns_acme",
  },
  {
    source: "audit",
    action: "gitNs.right.granted",
    at: "2026-08-10T00:00:00Z",
    actor: BOB,
    subject: BOB,
    right: "git.repo.own",
    resource: "github.com/acme/docs",
    namespace: "ns_acme",
  },
];

/** Alice, a namespace admin of acme, broke the glass for owner on docs. */
export const ALICE_BREAK_GLASS: GitNsBreakGlassItem = {
  namespace: "ns_acme",
  namespaceResource: "github.com/acme",
  subject: ALICE,
  right: "git.repo.own",
  resource: "github.com/acme/docs",
  grantedAt: "2026-09-25T02:10:31Z",
  breakGlass: {
    by: ALICE,
    at: "2026-09-25T02:10:31Z",
    justification: "CVE fix must ship tonight; Bob unreachable since 22:00.",
  },
  state: "unratified",
};

export function gitNsRoutes(
  over: {
    namespaces?: GitNsNamespaceRow[];
    repos?: GitNsRepoRow[];
    rights?: GitNsRightRow[];
    extra?: MockRoute[];
    activityStatus?: number;
    accounts?: GitNsAccountRow[];
    breakGlass?: GitNsBreakGlassItem[];
    breakGlassStatus?: number;
    namespacesStatus?: number;
    reposStatus?: number;
  } = {},
): MockRoute[] {
  const namespaces = over.namespaces ?? [ACME, PERSONAL];
  return [
    ...(over.extra ?? []),
    signedReads({
      namespaces,
      repos: over.repos ?? [DOCS, LEGACY, SANDBOX, WIDGETS],
      breakGlass: over.breakGlass ?? [],
      breakGlassStatus: over.breakGlassStatus,
      namespacesStatus: over.namespacesStatus,
      reposStatus: over.reposStatus,
    }),
    { path: "/v1/git-ns/rights", body: { rights: over.rights ?? RIGHTS } },
    {
      path: "/v1/git-ns/rights/issued-by-departed",
      body: {
        cascadeOnDeparture: false,
        granters: [{ granter: GUS, rights: RIGHTS.filter((r) => r.granterDeparted) }],
      },
    },
    {
      path: "/v1/git-ns/drift",
      body: {
        repos: [
          {
            resource: "github.com/acme/docs",
            state: "drift",
            drift: [
              {
                type: "roleAdded",
                resource: "github.com/acme/docs",
                observed: "maintain",
                account: { forge: "github.com", id: "1003", login: "hsato" },
              },
            ],
          },
        ],
      },
    },
    { path: "/v1/git-ns/jobs", body: { jobs: [] } },
    { path: "/v1/git-ns/accounts", body: { accounts: over.accounts ?? ACCOUNTS } },
    {
      path: "/v1/git-ns/activity",
      status: over.activityStatus,
      body:
        over.activityStatus === 403
          ? { error: "you administer no namespace here" }
          : { items: ACTIVITY },
    },
    {
      path: "/v1/git-ns/projection",
      body: {
        registryConfigured: true,
        pendingChanges: 1,
        published: [
          {
            entity: ALICE,
            action: "git.repo.own",
            resource: "github.com/acme/widgets",
            context: {},
            publishedAt: "2026-08-02T00:00:00Z",
          },
          {
            entity: ALICE,
            action: "git.commit.sign",
            resource: "github.com/acme/widgets",
            context: { impliedBy: "git.repo.own" },
            publishedAt: "2026-08-02T00:00:00Z",
          },
        ],
      },
    },
    {
      path: "/v1/policies/active",
      body: {
        bindings: [
          {
            purpose: "gitNamespace",
            policy: {
              id: "p1",
              name: "git_ns",
              module: "",
              version: 3,
              createdAt: "2026-08-01T00:00:00Z",
              updatedAt: "2026-08-01T00:00:00Z",
            },
          },
        ],
      },
    },
    { path: "/v1/members", body: { items: MEMBERS } },
    { path: "/v1/acl", body: { entries: [], truncated: false } },
  ];
}

/** A `trust-task-error` document's payload, as `/v1/trust-tasks` answers one
 *  (the reads look at nothing else). */
function refusal(code: string, message: string) {
  return { payload: { code, message } };
}

/**
 * `POST /v1/trust-tasks` answering the administrator's signed reads —
 * `git-ns/namespace/list`, `git-ns/repo/list` and `git-ns/view` 0.5 with
 * `breakGlass: true` — from the fixtures. A status of 403 stands for "this
 * caller administers nothing", which the daemon answers as the task's
 * `notAdministrator` (HTTP 422); any other status is answered as given.
 */
export function signedReads(o: {
  namespaces: GitNsNamespaceRow[];
  repos: GitNsRepoRow[];
  breakGlass: GitNsBreakGlassItem[];
  breakGlassStatus?: number;
  namespacesStatus?: number;
  reposStatus?: number;
}): MockRoute {
  const typeOf = (body: unknown) => (body as { type?: string } | undefined)?.type;
  const statusFor = (s: number | undefined) => (s === 403 ? 422 : (s ?? 200));
  const refused = (s: number | undefined, task: string) =>
    s === 403
      ? refusal(`${task}:notAdministrator`, "you administer no namespace")
      : refusal("internalError", "store unavailable");
  return {
    method: "POST",
    path: "/v1/trust-tasks",
    status: ({ body }) => {
      switch (typeOf(body)) {
        case TASK_NAMESPACE_LIST:
          return statusFor(o.namespacesStatus);
        case TASK_REPO_LIST:
          return statusFor(o.reposStatus);
        case TASK_VIEW:
          return statusFor(o.breakGlassStatus);
        default:
          return 404;
      }
    },
    body: ({ body }) => {
      switch (typeOf(body)) {
        case TASK_NAMESPACE_LIST:
          return o.namespacesStatus && o.namespacesStatus !== 200
            ? refused(o.namespacesStatus, "git-ns/namespace/list")
            : { payload: { namespaces: o.namespaces } };
        case TASK_REPO_LIST:
          return o.reposStatus && o.reposStatus !== 200
            ? refused(o.reposStatus, "git-ns/repo/list")
            : { payload: { repos: o.repos } };
        case TASK_VIEW:
          return o.breakGlassStatus && o.breakGlassStatus !== 200
            ? refused(o.breakGlassStatus, "git-ns/view")
            : { payload: breakGlassView(o.namespaces, o.breakGlass) };
        default:
          return refusal("unsupportedType", `no mock for ${typeOf(body)}`);
      }
    },
  };
}

/** A `git-ns/view/0.5` `breakGlass: true` answer holding these items. A
 *  fixture item marked `ratified` or `pending` gets the mark that says so. */
function breakGlassView(namespaces: GitNsNamespaceRow[], items: GitNsBreakGlassItem[]) {
  return {
    namespaces: namespaces.map((n) => ({
      id: n.id,
      forge: n.forge,
      owner: n.owner,
      mode: n.mode,
      state: n.state,
    })),
    repos: [],
    rights: items.map((i) => ({
      subject: i.subject,
      right: i.right,
      resource: i.resource,
      grantedBy: i.subject,
      grantedAt: i.grantedAt,
      breakGlass: {
        ...i.breakGlass,
        ...(i.state === "ratified" && !i.breakGlass.ratifiedBy
          ? { ratifiedBy: BOB, ratifiedAt: "2026-09-25T09:00:00Z" }
          : {}),
        ...(i.state === "pending" && !i.breakGlass.effectiveAt
          ? { effectiveAt: "2999-01-01T00:00:00Z" }
          : {}),
      },
    })),
    accounts: [],
  };
}

/**
 * Whether a recorded request changes anything: every request but a GET and
 * the administrator's signed reads (`signedReads`). "Sends nothing" in these
 * tests means no change was sent — the reads are sent on every render.
 */
export function isChange(r: { method: string; url: string; body: unknown }): boolean {
  if (r.method === "GET") return false;
  const type = (r.body as { type?: string } | undefined)?.type;
  return !(r.url === "/v1/trust-tasks" && [TASK_NAMESPACE_LIST, TASK_REPO_LIST, TASK_VIEW].includes(type ?? ""));
}
