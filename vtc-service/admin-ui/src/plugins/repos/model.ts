// What the Repos screens compute from the daemon's answers — kept free of
// React so each rule can be tested against the Rust it mirrors.
//
// Three of these are **mirrors**, and say so where they are defined, because a
// mirror that drifts from its original is worse than none: it shows an
// operator a confident answer to a question the daemon answers differently.
//
//   - `consentClass` mirrors `git_ns::ops::consent_class`.
//   - `desiredTuples` mirrors `git_ns::projection::desired`, including the
//     implied `git.commit.sign` the projector writes explicitly because
//     verify-trust asks about that action and no other.
//   - `contains` mirrors `Resource::contains` — whole-segment containment, so
//     `github.com/acme` holds `github.com/acme/widgets` and not
//     `github.com/acme-labs/x`.
//
// One is **an expectation, not a report**: `guardFor` says which guard design
// §9 puts on a repository given what the VTC knows about its namespace. The
// bridge does not report which guard is actually in force, so the screen
// labels it as expected and never as observed.

import type {
  GitNsBootstrapStatus,
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
  | "right.grant"
  | "right.revoke"
  | "repo.adopt"
  | "repo.transfer"
  | "repo.archive";

/** Mirrors `git_ns::ops::consent_class`. */
export function consentClass(action: GitNsAction, right?: GitNsRight): ConsentClass {
  if (action === "namespace.bind" || action === "namespace.unbind") return "destructive";
  if (action === "right.grant" || action === "right.revoke") {
    if (right === "git.ns.admin") return "destructive";
    if (right === "git.repo.own" || right === "git.repo.create") return "elevated";
    return "normal";
  }
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
 * namespace with no admin. What the App was granted on the forge is not
 * reported by the bridge today, so nothing here claims a permission is
 * present or missing.
 */
export function namespaceFindings(ns: GitNsNamespaceRow): Finding[] {
  const out: Finding[] = [];
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
  if (ns.headless) {
    out.push({
      tone: "danger",
      title: "No namespace admin",
      detail:
        "Its last admin left or lapsed, so nobody can grant here. Recovery is to unbind and bind again, which starts from no rights.",
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

export type GuardMode = "requiredWorkflow" | "bridgeCheck" | "ownerReview" | "soloUnreviewed";

export interface Guard {
  mode: GuardMode;
  label: string;
  detail: string;
}

/**
 * The guard that stops a pull request satisfying its own check, as design §9
 * assigns it for this namespace. An **expectation**: the bridge reports whether
 * the required check is in place (`bootstrap.requiredCheck`), not which of
 * these made it so, and an organisation whose plan lacks org rulesets for
 * private repositories falls back to the personal-account guard.
 */
export function guardFor(ns: GitNsNamespaceRow, repo: GitNsRepoRow): Guard {
  if (ns.mode === "bridge" && ns.kind === "organization") {
    return {
      mode: "requiredWorkflow",
      label: "Required workflow",
      detail:
        "An org ruleset runs verify-trust from the bridge-managed .vgi repository at a pinned commit, so a pull request cannot change what runs.",
    };
  }
  const owners = repo.owners.length;
  if (owners <= 1) {
    return {
      mode: "soloUnreviewed",
      label: "Solo owner — workflow changes unreviewed",
      detail:
        "Code-owner review of .github/ needs a second owner to approve. With one, the owner cannot merge their own workflow change; add a co-owner.",
    };
  }
  if (ns.mode === "bridge") {
    return {
      mode: "bridgeCheck",
      label: "Bridge-posted check",
      detail:
        "The bridge runs verify-trust itself and posts the check with the community App's identity, which the ruleset pins; no workflow can forge it. Code owners review .github/.",
    };
  }
  return {
    mode: "ownerReview",
    label: "Owner review",
    detail:
      "CODEOWNERS assigns .github/ to the repository's owners and the ruleset requires their review. Without the App, writers are trusted not to post a forged check.",
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
 * What the projector should publish. Mirrors `git_ns::projection::desired`:
 * only bound namespaces; only repositories whose state publishes (active,
 * orphaned, archived); an archived repository's commit rights withdrawn,
 * records and implications alike; and the implied `git.commit.sign` of every
 * `own`, `maintain` and `ns.admin` written explicitly. Role-derived rights are
 * published by the hook relay, not the projector, and are left out.
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
