// What the Repos screens compute from the daemon's answers — kept free of
// React so each rule can be tested against the Rust it mirrors.
//
// Three of these are **mirrors**, and say so where they are defined, because a
// mirror that drifts from its original is worse than none: it shows an
// operator a confident answer to a question the daemon answers differently.
//
//   - `consentClass` mirrors `git_ns::ops::consent_class`.
//   - `desiredTuples` mirrors `git_ns::projection::desired_all`, including
//     the implied `git.commit.sign` the projector writes explicitly because
//     verify-trust asks about that action and no other, and the role-derived
//     commit rights inside bound namespaces, which the projector now owns.
//   - `contains` mirrors `Resource::contains` — whole-segment containment, so
//     `github.com/acme` holds `github.com/acme/widgets` and not
//     `github.com/acme-labs/x`.
//
// One is **a report with a labelled fallback**: `guardFor` shows the guard the
// bridge reports in force on a repository (`guard`), and only where it has
// not reported one does it fall back to the guard design §9 assigns — labelled
// as expected, never as observed.

import type {
  GitNsBootstrapStatus,
  GitNsDriftItem,
  GitNsNamespaceRow,
  GitNsPublishedRow,
  GitNsRepoRow,
  GitNsRight,
  GitNsRightRow,
} from "@/lib/wire-types";

export const RIGHTS: readonly GitNsRight[] = [
  "git.ns.admin",
  "git.repo.create",
  "git.repo.own",
  "git.repo.maintain",
  "git.commit.sign",
];

export const RIGHT_LABEL: Record<GitNsRight, string> = {
  "git.ns.admin": "Namespace admin",
  "git.repo.create": "Repo creator",
  "git.repo.own": "Owner",
  "git.repo.maintain": "Maintainer",
  "git.commit.sign": "Committer",
};

/** Strongest first — the order people are listed in on a repository. */
const RIGHT_RANK: Record<GitNsRight, number> = {
  "git.ns.admin": 0,
  "git.repo.create": 1,
  "git.repo.own": 2,
  "git.repo.maintain": 3,
  "git.commit.sign": 4,
};

export function isRight(value: string): value is GitNsRight {
  return (RIGHTS as readonly string[]).includes(value);
}

export function rightLabel(value: string): string {
  return isRight(value) ? RIGHT_LABEL[value] : value;
}

export function rightRank(value: string): number {
  return isRight(value) ? RIGHT_RANK[value] : 99;
}

/** The rights that go on a repository, as opposed to a namespace. */
export const REPO_RIGHTS: readonly GitNsRight[] = [
  "git.repo.own",
  "git.repo.maintain",
  "git.commit.sign",
];

// ── resources ───────────────────────────────────────────────────────────

/** Whole-segment containment. Mirrors `Resource::contains`. */
export function contains(parent: string, child: string): boolean {
  return child === parent || child.startsWith(`${parent}/`);
}

/** `github.com/acme/widgets` → `acme/widgets`: the name people say out loud.
 *  The forge host is dropped for display only; it stays in every link. */
export function shortName(resource: string): string {
  const i = resource.indexOf("/");
  return i < 0 ? resource : resource.slice(i + 1);
}

/** The last segment: `widgets`. */
export function leafName(resource: string): string {
  return resource.slice(resource.lastIndexOf("/") + 1);
}

// ── consent classes (design §6) ─────────────────────────────────────────

export type ConsentClass = "normal" | "elevated" | "destructive";

export type GitNsAction =
  | "namespace.bind"
  | "namespace.unbind"
  | "namespace.reseat"
  | "right.grant"
  | "right.revoke"
  | "repo.adopt"
  | "repo.transfer"
  | "repo.archive"
  | "repo.create"
  | "drift.resolve";

/** Mirrors `git_ns::ops::consent_class`. */
export function consentClass(action: GitNsAction, right?: GitNsRight): ConsentClass {
  if (
    action === "namespace.bind" ||
    action === "namespace.unbind" ||
    action === "namespace.reseat"
  ) {
    return "destructive";
  }
  // A drift revert is gated as the revocation it amounts to
  // (`git_ns::drift::revert` → `consent_gate("right.revoke", impact)`), so it
  // is classed by its impact the same way.
  if (action === "right.grant" || action === "right.revoke" || action === "drift.resolve") {
    if (right === "git.ns.admin") return "destructive";
    if (right === "git.repo.own" || right === "git.repo.create") return "elevated";
    return "normal";
  }
  if (action === "repo.create") return "normal";
  return "elevated";
}

// ── namespaces ──────────────────────────────────────────────────────────

export type Tone = "success" | "warning" | "danger" | "accent" | "neutral";

export interface Finding {
  tone: Tone;
  title: string;
  detail: string;
}

/**
 * What an administrator must know about a namespace before anything else.
 *
 * Only what the daemon reports: a pending binding, a lost installation, a
 * namespace with no admin, and — where the bridge has reported its standing
 * on the forge (`forgeStatus`, absent until it does) — permissions the App
 * lacks and a permission upgrade waiting on the owner. An absent report is
 * not read as "all permissions granted": nothing is said either way.
 */
export function namespaceFindings(ns: GitNsNamespaceRow): Finding[] {
  const out: Finding[] = [];
  const fs = ns.forgeStatus;
  if (ns.state === "pending") {
    out.push({
      tone: "accent",
      title: "Binding not finished",
      detail:
        "The VTC is waiting for the bridge to report the App installed on this owner. Nothing can be granted here until it does.",
    });
  }
  if (ns.installationRemoved) {
    out.push({
      tone: "danger",
      title: "The App lost access",
      detail:
        "The bridge reported the community's App uninstalled from this owner. Rights still stand and are still published, but nothing is applied on the forge and drift is no longer checked. Reinstall the App on the owner to restore it.",
    });
  }
  if (fs && fs.missingPermissions.length > 0) {
    out.push({
      tone: "danger",
      title: `The App is missing ${fs.missingPermissions.length === 1 ? "a permission" : "permissions"}`,
      detail: `The installation lacks ${fs.missingPermissions.join(", ")}. The bridge cannot do what needs ${fs.missingPermissions.length === 1 ? "it" : "them"} until the owner grants ${fs.missingPermissions.length === 1 ? "it" : "them"} in the App's installation settings.`,
    });
  }
  if (fs?.permissionUpgradePending) {
    out.push({
      tone: "warning",
      title: "Permission upgrade awaiting approval",
      detail:
        "A new bridge release asks for more permissions. The forge owner must approve the change on the App's installation page; until then the bridge works with the permissions it had.",
    });
  }
  if (ns.kind === "organization" && ns.mode === "bridge" && fs?.orgRulesets === false) {
    out.push({
      tone: "warning",
      title: "No org rulesets on this plan",
      detail:
        "The owner's plan cannot run the required workflow, so repositories here fall back to code-owner review and a bridge-posted check (design §9).",
    });
  }
  if (ns.headless) {
    out.push({
      tone: "danger",
      title: "No namespace admin",
      detail:
        "Its last admin left or lapsed, so nobody can grant here. A community administrator can reseat it with git-ns/namespace/reseat (cnm git reseat): namespace admin goes to a current member of the community, with a statement of why that is kept in the audit record and shown to the namespace's repository owners. It is refused while a current member holds a live git.ns.admin there, so it never goes around a sitting admin.",
    });
  }
  return out;
}

export function isPersonal(ns: GitNsNamespaceRow): boolean {
  return ns.kind === "user";
}

export function kindLabel(ns: GitNsNamespaceRow): string {
  if (ns.kind === "organization") return "Organization";
  if (ns.kind === "user") return "Personal account";
  return ns.state === "pending" ? "Kind not yet known" : "Kind not reported";
}

export function modeLabel(ns: GitNsNamespaceRow): string {
  if (ns.mode === "manual") return "Manual mode";
  if (ns.state === "pending") return "App install pending";
  return ns.installationRemoved ? "App uninstalled" : "App installed";
}

/** The bridge's own `git.commit.sign` on the namespace — the Dependabot
 *  re-sign service grant (design §9), recorded with `grantedBy` the VTC. */
export function isServiceGrant(right: GitNsRightRow, ns: GitNsNamespaceRow): boolean {
  return (
    !!ns.bridgeDid &&
    right.subject === ns.bridgeDid &&
    right.right === "git.commit.sign" &&
    right.resource === ns.resource &&
    right.origin === "recorded"
  );
}

// ── repositories ────────────────────────────────────────────────────────

export type RepoAction = "view" | "resolve" | "assignOwner" | "adopt";

export interface RepoStatus {
  label: string;
  tone: Tone;
  action?: RepoAction;
  actionLabel?: string;
}

const ACTION_LABEL: Record<RepoAction, string> = {
  view: "View",
  resolve: "Resolve",
  assignOwner: "Assign owner",
  adopt: "Adopt",
};

/**
 * One status per row, lifecycle first and forge sync second: a repository
 * being created or waiting to be adopted has no sync state worth reading yet.
 */
export function repoStatus(repo: GitNsRepoRow): RepoStatus {
  const withAction = (s: Omit<RepoStatus, "actionLabel">): RepoStatus => ({
    ...s,
    actionLabel: s.action ? ACTION_LABEL[s.action] : undefined,
  });
  switch (repo.state) {
    case "pendingCreate":
      return withAction(
        repo.failedStep
          ? { label: `Creating · failed at ${repo.failedStep}`, tone: "danger", action: "view" }
          : { label: "Creating", tone: "accent", action: "view" },
      );
    case "unmanaged":
      return withAction({ label: "Unmanaged", tone: "neutral", action: "adopt" });
    case "orphaned":
      return withAction({ label: "Orphaned", tone: "danger", action: "assignOwner" });
    case "archived":
      return withAction({ label: "Archived", tone: "neutral" });
    case "detached":
      return withAction({ label: "Detached", tone: "neutral" });
  }
  switch (repo.syncState) {
    case "inSync":
      return withAction({ label: "In sync", tone: "success" });
    case "drift":
      return withAction({
        label: `Drift · ${repo.driftCount} ${repo.driftCount === 1 ? "item" : "items"}`,
        tone: "warning",
        action: "resolve",
      });
    case "pending":
      return withAction({ label: "Applying on the forge", tone: "accent" });
    case "unchecked":
      return withAction({ label: "Not checked (manual)", tone: "neutral" });
  }
  return withAction({ label: repo.syncState, tone: "neutral" });
}

export interface BootstrapStep {
  key: keyof GitNsBootstrapStatus;
  label: string;
  detail: string;
  done: boolean;
}

/** The four steps that turn commit trust on, in the order the bridge takes
 *  them (design §5.3). A step the forge's plan does not need reads done. */
export function bootstrapSteps(b: GitNsBootstrapStatus): BootstrapStep[] {
  return [
    {
      key: "workflow",
      label: "Workflow",
      detail: "verify-trust runs on pull requests",
      done: b.workflow,
    },
    {
      key: "keyring",
      label: "Keyring",
      detail: "platform keyring for forge-signed merges",
      done: b.keyring,
    },
    {
      key: "variables",
      label: "Variables",
      detail: "TRUST_REGISTRY_DID · VTC_DID",
      done: b.variables,
    },
    {
      key: "requiredCheck",
      label: "Required check",
      detail: "merge blocked unless the check passes, no bypass",
      done: b.requiredCheck,
    },
  ];
}

export function bootstrapSummary(b: GitNsBootstrapStatus): string {
  const steps = bootstrapSteps(b);
  const done = steps.filter((s) => s.done);
  if (done.length === steps.length) return "All four in place";
  if (done.length === 0) return "Not bootstrapped";
  return `${done.map((s) => s.label).join(", ")} in place; ${steps
    .filter((s) => !s.done)
    .map((s) => s.label.toLowerCase())
    .join(", ")} missing`;
}

// ── the guard (design §9) ───────────────────────────────────────────────

export type GuardMode =
  | "unknown"
  | "requiredWorkflow"
  | "bridgePostedCheck"
  | "codeOwnerReview"
  | "protectedFiles"
  | "soloUnreviewed"
  | "none";

export interface Guard {
  mode: GuardMode;
  label: string;
  detail: string;
  /** `reported` — the bridge said so; `expected` — design §9 for this
   *  namespace, because the bridge has not reported. */
  source: "reported" | "expected";
  tone: Tone;
}

const GUARD: Record<Exclude<GuardMode, "unknown">, Omit<Guard, "mode" | "source">> = {
  requiredWorkflow: {
    label: "Required workflow",
    detail:
      "An org ruleset runs verify-trust from the bridge-managed .vgi repository at a pinned commit, so a pull request cannot change what runs.",
    tone: "success",
  },
  bridgePostedCheck: {
    label: "Bridge-posted check",
    detail:
      "The bridge runs verify-trust itself and posts the check with the community App's identity, which the ruleset pins; no workflow can forge it.",
    tone: "success",
  },
  codeOwnerReview: {
    label: "Owner review",
    detail:
      "CODEOWNERS assigns .github/ to the repository's owners and the ruleset requires their review, so a workflow change needs a second owner. Writers are trusted not to post a forged check.",
    tone: "accent",
  },
  protectedFiles: {
    label: "Protected workflow files",
    detail:
      "Branch protection refuses any pull request that touches a workflow file; such changes go through a namespace admin's direct, audited push. Writers are trusted not to forge a commit status.",
    tone: "accent",
  },
  soloUnreviewed: {
    label: "Solo owner — workflow changes unreviewed",
    detail:
      "Code-owner review needs a second owner to approve. With one, the owner cannot merge their own workflow change; add a co-owner.",
    tone: "warning",
  },
  none: {
    label: "None",
    detail:
      "Nothing stops a pull request from changing what its own check runs, so a writer could make it pass. Commit trust is not guaranteed here.",
    tone: "danger",
  },
};

const REPORTED: Record<string, Exclude<GuardMode, "unknown" | "soloUnreviewed">> = {
  requiredWorkflow: "requiredWorkflow",
  bridgePostedCheck: "bridgePostedCheck",
  codeOwnerReview: "codeOwnerReview",
  protectedFiles: "protectedFiles",
  none: "none",
};

/**
 * The guard that stops a pull request satisfying its own check (design §9).
 *
 * The bridge's report (`repo.guard`) when there is one. Code-owner review
 * with a single owner is reported as what it is in practice — nobody reviews.
 * A report this console does not know is shown verbatim, as reported, and
 * never replaced by a guess. With no report, the guard §9 assigns for this
 * namespace, marked `expected` — and the org-wide required workflow is only
 * expected where the bridge has not said it is unavailable.
 */
export function guardFor(ns: GitNsNamespaceRow, repo: GitNsRepoRow): Guard {
  const solo = repo.owners.length <= 1;
  if (repo.guard) {
    const known = REPORTED[repo.guard];
    if (!known) {
      return {
        mode: "unknown",
        source: "reported",
        label: repo.guard,
        detail:
          "The bridge reported a guard this console does not recognise. It is shown as reported; check the bridge's documentation for what it means.",
        tone: "neutral",
      };
    }
    const mode = known === "codeOwnerReview" && solo ? "soloUnreviewed" : known;
    return { mode, source: "reported", ...GUARD[mode] };
  }
  const fs = ns.forgeStatus;
  const orgWorkflow =
    ns.mode === "bridge" &&
    ns.kind === "organization" &&
    fs?.orgRulesets !== false &&
    fs?.requiredWorkflow !== false;
  let mode: Exclude<GuardMode, "unknown">;
  if (orgWorkflow) {
    mode = "requiredWorkflow";
  } else if (solo) {
    mode = "soloUnreviewed";
  } else if (ns.mode === "bridge") {
    mode = "bridgePostedCheck";
  } else {
    mode = "codeOwnerReview";
  }
  return { mode, source: "expected", ...GUARD[mode] };
}

/** The last verify-trust check the bridge saw. Carried as an object whose
 *  documented members are `{conclusion, at, sha?}`; anything else is ignored. */
export function lastCheckOf(
  repo: GitNsRepoRow,
): { conclusion: string; at?: string; sha?: string } | null {
  const c = repo.lastCheck as Record<string, unknown> | null | undefined;
  if (!c || typeof c.conclusion !== "string") return null;
  return {
    conclusion: c.conclusion,
    at: typeof c.at === "string" ? c.at : undefined,
    sha: typeof c.sha === "string" ? c.sha : undefined,
  };
}

// ── the registry projection ─────────────────────────────────────────────

export interface Tuple {
  entity: string;
  action: string;
  resource: string;
  /** The right this tuple is implied by (`git.repo.own` → `git.commit.sign`). */
  impliedBy?: string;
  /** Whether the daemon reports this exact tuple published. */
  published: boolean;
}

const tupleKey = (t: { entity: string; action: string; resource: string }) =>
  `${t.entity}\u0000${t.action}\u0000${t.resource}`;

/**
 * What the projector should publish. Mirrors `git_ns::projection::desired_all`:
 * only bound namespaces; only repositories whose state publishes (active,
 * orphaned, archived); an archived repository's commit rights withdrawn,
 * records and implications alike; the implied `git.commit.sign` of every
 * `own`, `maintain` and `ns.admin` written explicitly; and a role-derived
 * (`grant_on_role`) commit right on any resource inside a bound namespace —
 * the projection publishes those there, and the hook relay only outside one.
 */
export function desiredTuples(
  rights: GitNsRightRow[],
  namespaces: GitNsNamespaceRow[],
  repos: GitNsRepoRow[],
  published: GitNsPublishedRow[],
): Tuple[] {
  const have = new Set(published.map(tupleKey));
  const out = new Map<string, Tuple>();
  const add = (entity: string, action: string, resource: string, impliedBy?: string) => {
    const key = tupleKey({ entity, action, resource });
    const existing = out.get(key);
    // An explicit record wins over an implication, as `merge` keeps the
    // record's own context.
    if (existing && !existing.impliedBy) return;
    out.set(key, { entity, action, resource, impliedBy, published: have.has(key) });
  };
  for (const r of rights) {
    if (r.origin === "roleDerived") {
      const bound = namespaces.some((n) => n.state === "bound" && contains(n.resource, r.resource));
      if (bound) add(r.subject, "git.commit.sign", r.resource);
      continue;
    }
    if (r.origin !== "recorded") continue;
    const ns = namespaces.find((n) => contains(n.resource, r.resource));
    if (!ns || ns.state !== "bound") continue;
    const repo = repos.find((x) => x.resource === r.resource);
    if (r.resource !== ns.resource) {
      if (!repo || !["active", "orphaned", "archived"].includes(repo.state)) continue;
    }
    const archived = repo?.state === "archived";
    if (!(archived && r.right === "git.commit.sign")) add(r.subject, r.right, r.resource);
    const impliesCommit =
      r.right === "git.repo.own" ||
      r.right === "git.repo.maintain" ||
      r.right === "git.ns.admin";
    if (impliesCommit && !archived) add(r.subject, "git.commit.sign", r.resource, r.right);
  }
  return [...out.values()].sort(
    (a, b) =>
      a.resource.localeCompare(b.resource) ||
      a.entity.localeCompare(b.entity) ||
      rightRank(a.action) - rightRank(b.action),
  );
}

// ── people on a repository ──────────────────────────────────────────────

/** Is the grant past its `expiresAt`, or within `days` of it? */
export function expiresWithin(right: GitNsRightRow, days: number, now = Date.now()): boolean {
  if (!right.expiresAt) return false;
  const at = new Date(right.expiresAt).getTime();
  return !Number.isNaN(at) && at - now <= days * 86_400_000;
}

/** Rights on exactly this repository, strongest first, then by subject. */
export function repoRights(rights: GitNsRightRow[], resource: string): GitNsRightRow[] {
  return rights
    .filter((r) => r.resource === resource)
    .sort(
      (a, b) => rightRank(a.right) - rightRank(b.right) || a.subject.localeCompare(b.subject),
    );
}

/** Namespace-level rights that reach into this repository. */
export function inheritedRights(
  rights: GitNsRightRow[],
  ns: GitNsNamespaceRow,
): GitNsRightRow[] {
  return rights
    .filter((r) => r.resource === ns.resource)
    .filter((r) => r.right === "git.ns.admin" || r.right === "git.commit.sign")
    .sort(
      (a, b) => rightRank(a.right) - rightRank(b.right) || a.subject.localeCompare(b.subject),
    );
}

/** Forge role → the right an owner adopting it into the VTC would grant.
 *  The inverse of the org projection in design §4.2. */
export function rightForForgeRole(role: string | undefined): GitNsRight | null {
  switch (role) {
    case "admin":
      return "git.repo.own";
    case "maintain":
      return "git.repo.maintain";
    case "write":
    case "push":
      return "git.commit.sign";
    default:
      return null;
  }
}

// ── drift ───────────────────────────────────────────────────────────────

const ROLE_DRIFT: readonly GitNsDriftItem["type"][] = ["roleAdded", "roleRemoved", "roleChanged"];

/** Whether a drift item is about one account's role (selected by account). */
export function isRoleDrift(item: GitNsDriftItem): boolean {
  return ROLE_DRIFT.includes(item.type);
}

/**
 * The right the namespace's forge adapter projects to `role` — mirrors
 * `git_ns::drift::projected_right`. On an organisation `admin` projects
 * `git.repo.own` and `maintain` `git.repo.maintain`; on a personal account
 * collaborator `write` is the one level, and projects `git.repo.maintain`.
 */
export function projectedRight(
  kind: string | null | undefined,
  role: string | undefined,
): GitNsRight | null {
  if (kind === "user") return role === "write" ? "git.repo.maintain" : null;
  if (role === "admin") return "git.repo.own";
  if (role === "maintain") return "git.repo.maintain";
  return null;
}

/**
 * The revocation a revert amounts to, which is what the VTC gates it as —
 * mirrors `git_ns::drift::revert`: taking off or lowering a forge role that
 * projects `own` weighs as revoking `own`; any other revert at most as
 * revoking `maintain`.
 */
export function driftRevertImpact(
  item: GitNsDriftItem,
  ns: GitNsNamespaceRow,
): "git.repo.own" | "git.repo.maintain" {
  return isRoleDrift(item) &&
    item.type !== "roleRemoved" &&
    projectedRight(ns.kind, item.observed) === "git.repo.own"
    ? "git.repo.own"
    : "git.repo.maintain";
}

/** What reverting the item has the bridge do, in the operator's words. */
export function driftRevertEffect(item: GitNsDriftItem): string {
  switch (item.type) {
    case "roleAdded":
      return "The bridge takes the forge role off the account, so the repository's roles match the VTC's projection again. No VTC right changes.";
    case "roleRemoved":
    case "roleChanged":
      return "The bridge re-applies the projected roles, so the account holds the level its VTC right calls for again. No VTC right changes.";
    case "requiredCheckMissing":
    case "protectionWeakened":
      return "The bridge re-applies the ruleset, so “Verify commit trust” is required again and the protection is as the VTC projects it. No VTC right changes.";
    default:
      return "The bridge re-runs the bootstrap plan, which restores only what is missing (workflow, keyring, variables, required check). No VTC right changes.";
  }
}

export type RevertStanding =
  | { may: true }
  | { may: false; why: string };

/**
 * Whether the VTC would accept a revert of `item` signed as `viewer` — the
 * same checks `git-ns/drift/resolve` makes, in its order, as far as the
 * console can see them:
 *
 * - the namespace has a bridge to undo anything (`notRevertible` otherwise);
 * - the repository is active or orphaned (`repoNotActive`);
 * - the signer holds `git.repo.own` there, explicit or implied by the
 *   namespace's `git.ns.admin` (`drift_revert_admitted`);
 * - where the revert weighs as revoking `own`, the signer is a community
 *   administrator (`consent_gate`, under `[git_ns] elevated_requires_admin`,
 *   which is on by default and which the console assumes, as it does for
 *   every elevated task).
 *
 * The VTC decides either way; this only keeps the console from offering what
 * it would refuse.
 */
export function revertStanding(
  viewer: string | null,
  superAdmin: boolean,
  ns: GitNsNamespaceRow,
  repo: GitNsRepoRow,
  item: GitNsDriftItem,
): RevertStanding {
  if (ns.mode !== "bridge" || !ns.bridgeDid) {
    return {
      may: false,
      why: "This namespace is governed in manual mode: no bridge can undo a forge-side change, so fix it on the forge by hand.",
    };
  }
  if (repo.state !== "active" && repo.state !== "orphaned") {
    return { may: false, why: `The repository is ${repo.state}; drift is resolved on an active or orphaned one.` };
  }
  const owns = !!viewer && (repo.owners.includes(viewer) || ns.admins.includes(viewer));
  if (!owns) {
    return {
      may: false,
      why: "Reverting drift is an owner's decision: it needs git.repo.own on the repository, which its owners and the namespace's admins hold. This session's DID holds neither, so hand the command below to one of them.",
    };
  }
  if (driftRevertImpact(item, ns) === "git.repo.own" && !superAdmin) {
    return {
      may: false,
      why: "Taking an admin role off the forge weighs as revoking ownership, an elevated action this VTC accepts only from a community administrator who also owns the repository. Hand the command below to one.",
    };
  }
  return { may: true };
}

// ── activity ────────────────────────────────────────────────────────────

const ACTIVITY: Record<string, string> = {
  "gitNs.namespace.bindRequested": "binding requested",
  "gitNs.namespace.bound": "namespace bound",
  "gitNs.namespace.bindFailed": "binding failed",
  "gitNs.namespace.bindExpired": "binding expired unfinished",
  "gitNs.namespace.unbound": "namespace unbound",
  "gitNs.namespace.installationRemoved": "App uninstalled from the owner",
  "gitNs.repo.reserved": "repository name reserved",
  "gitNs.repo.activated": "repository activated",
  "gitNs.repo.adopted": "repository adopted",
  "gitNs.repo.archived": "repository archived",
  "gitNs.repo.detached": "repository detached",
  "gitNs.repo.orphaned": "repository orphaned — its last owner left",
  "gitNs.repo.renamed": "repository renamed",
  "gitNs.repo.transferred": "ownership transferred",
  "gitNs.repo.protectionWeakened": "protection weakened on the forge",
  "gitNs.right.granted": "granted",
  "gitNs.right.revoked": "revoked",
  "gitNs.right.lapsed": "lapsed",
  "gitNs.drift.reported": "drift reported",
  "gitNs.drift.resolved": "drift resolved",
  "gitNs.account.linked": "forge account linked",
};

/** An activity item's action in words. Unknown actions are shown verbatim
 *  rather than dropped: a new audit action is still something that happened. */
export function activityVerb(action: string): string {
  if (ACTIVITY[action]) return ACTIVITY[action];
  if (action.startsWith("gitNs.job.")) return `bridge job ${action.slice("gitNs.job.".length)}`;
  return action;
}
