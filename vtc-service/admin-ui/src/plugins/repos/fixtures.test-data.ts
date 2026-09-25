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
  roleMap: { own: "write", maintain: "write", commit: "none" },
  roleMapSource: "default",
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
  { member: ALICE, forge: "github.com", id: "1001", login: "alicew" },
  { member: BOB, forge: "github.com", id: "1002", login: "bobm" },
  { member: HANA, forge: "github.com", id: "1003", login: "hsato" },
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

export function gitNsRoutes(
  over: {
    namespaces?: GitNsNamespaceRow[];
    repos?: GitNsRepoRow[];
    rights?: GitNsRightRow[];
    extra?: MockRoute[];
    activityStatus?: number;
  } = {},
): MockRoute[] {
  return [
    ...(over.extra ?? []),
    {
      path: "/v1/git-ns/namespaces",
      body: { namespaces: over.namespaces ?? [ACME, PERSONAL] },
    },
    { path: "/v1/git-ns/repos", body: { repos: over.repos ?? [DOCS, LEGACY, SANDBOX, WIDGETS] } },
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
    { path: "/v1/git-ns/accounts", body: { accounts: ACCOUNTS } },
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
