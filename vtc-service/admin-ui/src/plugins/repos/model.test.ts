import { describe, expect, it } from "vitest";

import {
  activityVerb,
  bootstrapSummary,
  consentClass,
  contains,
  desiredTuples,
  guardFor,
  isServiceGrant,
  namespaceFindings,
  projectedRight,
  repoStatus,
  forgeRoleFor,
  revertStanding,
  driftRevertImpact,
  adoptStanding,
  projectedRepoRank,
} from "./model";
import {
  ACME,
  ALICE,
  BOB,
  BRIDGE,
  DOCS,
  HANA,
  LEGACY,
  PERSONAL,
  RIGHTS,
  SANDBOX,
  WIDGETS,
} from "./fixtures.test-data";

describe("consentClass — mirrors git_ns::ops::consent_class", () => {
  it("classes bind, unbind and ns.admin as destructive", () => {
    expect(consentClass("namespace.bind")).toBe("destructive");
    expect(consentClass("namespace.unbind")).toBe("destructive");
    expect(consentClass("namespace.reseat")).toBe("destructive");
    expect(consentClass("right.grant", "git.ns.admin")).toBe("destructive");
    expect(consentClass("right.revoke", "git.ns.admin")).toBe("destructive");
  });

  it("classes own, repo.create, transfer, archive and adopt as elevated", () => {
    expect(consentClass("right.grant", "git.repo.own")).toBe("elevated");
    expect(consentClass("right.revoke", "git.repo.create")).toBe("elevated");
    expect(consentClass("repo.transfer")).toBe("elevated");
    expect(consentClass("repo.archive")).toBe("elevated");
    expect(consentClass("repo.adopt")).toBe("elevated");
  });

  it("classes a drift revert as the revocation it weighs as", () => {
    expect(consentClass("drift.resolve", "git.repo.own")).toBe("elevated");
    expect(consentClass("drift.resolve", "git.repo.maintain")).toBe("normal");
  });

  it("leaves commit and maintain grants normal", () => {
    expect(consentClass("right.grant", "git.commit.sign")).toBe("normal");
    expect(consentClass("right.revoke", "git.repo.maintain")).toBe("normal");
  });
});

describe("contains — whole-segment containment", () => {
  it("contains its own repositories and not a sibling owner", () => {
    expect(contains("github.com/acme", "github.com/acme/widgets")).toBe(true);
    expect(contains("github.com/acme", "github.com/acme")).toBe(true);
    expect(contains("github.com/acme", "github.com/acme-labs/x")).toBe(false);
    expect(contains("github.com/acme", "codeberg.org/acme/widgets")).toBe(false);
  });
});

describe("desiredTuples — mirrors git_ns::projection::desired", () => {
  const all = desiredTuples(RIGHTS, [ACME, PERSONAL], [WIDGETS, DOCS, LEGACY, SANDBOX], [
    { entity: ALICE, action: "git.repo.own", resource: WIDGETS.resource, context: {}, publishedAt: "x" },
  ]);
  const on = (entity: string, resource: string) =>
    all.filter((t) => t.entity === entity && t.resource === resource);

  it("writes the implied commit right of own, maintain and ns.admin explicitly", () => {
    expect(on(ALICE, WIDGETS.resource).map((t) => [t.action, t.impliedBy])).toEqual([
      ["git.repo.own", undefined],
      ["git.commit.sign", "git.repo.own"],
    ]);
    expect(on(HANA, WIDGETS.resource).map((t) => t.action)).toEqual([
      "git.repo.maintain",
      "git.commit.sign",
    ]);
    expect(on(ALICE, ACME.resource).map((t) => t.action)).toEqual([
      "git.ns.admin",
      "git.commit.sign",
    ]);
  });

  it("includes the bridge's service grant, and marks what is published", () => {
    expect(on(BRIDGE, ACME.resource).map((t) => t.action)).toEqual(["git.commit.sign"]);
    const own = on(ALICE, WIDGETS.resource);
    expect(own[0]!.published).toBe(true);
    expect(own[1]!.published).toBe(false);
  });

  it("withdraws commit rights on an archived repository, records and implications alike", () => {
    const archived = { ...WIDGETS, state: "archived" };
    const t = desiredTuples(RIGHTS, [ACME], [archived], []).filter(
      (x) => x.resource === WIDGETS.resource,
    );
    expect(t.map((x) => x.action)).toEqual(["git.repo.own", "git.repo.maintain"]);
  });

  it("publishes a role-derived commit right inside a bound namespace, and none outside", () => {
    const roleDerived = [{ ...RIGHTS[5]!, origin: "roleDerived", grantedBy: null }];
    expect(desiredTuples(roleDerived, [ACME], [WIDGETS], []).map((t) => t.action)).toEqual([
      "git.commit.sign",
    ]);
    const elsewhere = [{ ...roleDerived[0]!, resource: "github.com/other/x" }];
    expect(desiredTuples(elsewhere, [ACME], [WIDGETS], [])).toEqual([]);
  });

  it("publishes nothing for a pending namespace or an unmanaged repo", () => {
    expect(desiredTuples(RIGHTS, [{ ...ACME, state: "pending" }], [WIDGETS], [])).toEqual([]);
    const onSandbox = [{ ...RIGHTS[3]!, resource: SANDBOX.resource }];
    expect(desiredTuples(onSandbox, [ACME], [SANDBOX], [])).toEqual([]);
  });
});

describe("repoStatus", () => {
  it("puts lifecycle before sync and names the action each state needs", () => {
    expect(repoStatus(WIDGETS)).toMatchObject({ label: "In sync", tone: "success" });
    expect(repoStatus(DOCS)).toMatchObject({ label: "Drift · 1 item", action: "resolve" });
    expect(repoStatus(LEGACY)).toMatchObject({ label: "Orphaned", actionLabel: "Assign owner" });
    expect(repoStatus(SANDBOX)).toMatchObject({ label: "Unmanaged", actionLabel: "Adopt" });
    expect(
      repoStatus({ ...WIDGETS, state: "pendingCreate", failedStep: "ruleset" }),
    ).toMatchObject({ label: "Creating · failed at ruleset", tone: "danger", action: "view" });
  });
});

describe("guardFor — the guard design §9 assigns", () => {
  it("is the required workflow on a bridge-mode organisation", () => {
    expect(guardFor(ACME, WIDGETS).mode).toBe("requiredWorkflow");
  });

  it("is owner review, or solo-unreviewed with one owner, in fallback", () => {
    expect(guardFor(PERSONAL, { ...WIDGETS, owners: [ALICE, HANA] }).mode).toBe("codeOwnerReview");
    expect(guardFor(PERSONAL, WIDGETS).mode).toBe("soloUnreviewed");
  });

  it("is the bridge-posted check on a personal account with the App", () => {
    expect(
      guardFor({ ...PERSONAL, mode: "bridge" }, { ...WIDGETS, owners: [ALICE, HANA] }).mode,
    ).toBe("bridgePostedCheck");
  });

  it("does not expect the required workflow the bridge says is not in force", () => {
    const ns = { ...ACME, forgeStatus: { missingPermissions: [], requiredWorkflow: false } };
    expect(guardFor(ns, { ...WIDGETS, owners: [ALICE, HANA] }).mode).toBe("bridgePostedCheck");
    expect(guardFor(ns, WIDGETS).mode).toBe("soloUnreviewed");
  });

  it("falls back when the owner's plan has no org rulesets", () => {
    const ns = { ...ACME, forgeStatus: { missingPermissions: [], orgRulesets: false } };
    expect(guardFor(ns, { ...WIDGETS, owners: [ALICE, HANA] }).mode).toBe("bridgePostedCheck");
  });

  it("prefers the guard the bridge reports, and labels which it is", () => {
    const g = guardFor(PERSONAL, { ...WIDGETS, owners: [ALICE, HANA], guard: "protectedFiles" });
    expect(g).toMatchObject({ mode: "protectedFiles", source: "reported" });
    expect(guardFor(ACME, WIDGETS).source).toBe("expected");
    expect(guardFor(ACME, { ...WIDGETS, guard: "none" }).tone).toBe("danger");
    // An unknown report is shown verbatim, as reported — never replaced by
    // the expected (and green) guess.
    expect(guardFor(ACME, { ...WIDGETS, guard: "somethingNew" })).toMatchObject({
      mode: "unknown",
      source: "reported",
      label: "somethingNew",
      tone: "neutral",
    });
  });
});

describe("namespace facts", () => {
  it("recognises the bridge's service grant and nothing else", () => {
    expect(RIGHTS.filter((r) => isServiceGrant(r, ACME)).map((r) => r.subject)).toEqual([BRIDGE]);
  });

  it("warns on missing permissions and a pending upgrade only when reported", () => {
    const titles = namespaceFindings({
      ...ACME,
      forgeStatus: { missingPermissions: ["members:read", "variables:write"], permissionUpgradePending: true },
    }).map((f) => f.title);
    expect(titles).toEqual(["The App is missing permissions", "Permission upgrade awaiting approval"]);
    expect(namespaceFindings({ ...ACME, forgeStatus: { missingPermissions: [] } })).toEqual([]);
  });

  it("names activity actions, and keeps unknown ones verbatim", () => {
    expect(activityVerb("gitNs.right.granted")).toBe("granted");
    expect(activityVerb("gitNs.job.createRepo")).toBe("bridge job createRepo");
    expect(activityVerb("gitNs.something.new")).toBe("gitNs.something.new");
  });

  it("reports a lost installation and a headless namespace", () => {
    const titles = namespaceFindings({ ...ACME, installationRemoved: true, headless: true }).map(
      (f) => f.title,
    );
    expect(titles).toEqual(["The App lost access", "No namespace admin"]);
    const headless = namespaceFindings({ ...ACME, headless: true })[0]!;
    expect(headless.detail).toMatch(/git-ns\/namespace\/reseat \(cnm git reseat\)/);
    // Served now: no "once this VTC serves it", no unbind-and-rebind fallback.
    expect(headless.detail).not.toMatch(/once this VTC serves it|unbind and bind again/);
    expect(headless.detail).toMatch(/A community administrator can reseat it/);
    expect(headless.detail).toMatch(/current member of the community/);
    expect(headless.detail).toMatch(/statement of why that is kept in the audit record/);
    expect(headless.detail).toMatch(/refused while a current member holds a live git\.ns\.admin there/);
    expect(namespaceFindings(ACME)).toEqual([]);
  });

  it("summarises the bootstrap in words", () => {
    expect(bootstrapSummary(WIDGETS.bootstrap)).toBe("All four in place");
    expect(bootstrapSummary(SANDBOX.bootstrap)).toBe("Not bootstrapped");
    expect(bootstrapSummary(LEGACY.bootstrap)).toBe(
      "Workflow, Keyring, Variables in place; required check missing",
    );
  });

  it("shows the forge role a right projects to, and none for a namespace admin", () => {
    const map = { own: "admin", maintain: "admin", commit: "write" };
    expect(forgeRoleFor(map, "git.repo.own")).toBe("admin");
    expect(forgeRoleFor(map, "git.repo.maintain")).toBe("admin");
    expect(forgeRoleFor(map, "git.commit.sign")).toBe("write");
    expect(forgeRoleFor(map, "git.ns.admin")).toBe("none");
    expect(forgeRoleFor(map, "git.repo.create")).toBe("none");
  });
});

describe("revertStanding — what git-ns/drift/resolve accepts", () => {
  const maintain = {
    type: "roleAdded" as const,
    resource: DOCS.resource,
    observed: "maintain",
    account: { forge: "github.com", id: "1003", login: "hsato" },
  };
  const admin = { ...maintain, observed: "admin" };

  it("mirrors projected_right, org and personal", () => {
    const org = { own: "admin", maintain: "maintain", commit: "none" };
    expect(projectedRight(org, "admin")).toBe("git.repo.own");
    expect(projectedRight(org, "maintain")).toBe("git.repo.maintain");
    expect(projectedRight(org, "write")).toBeNull();
    const user = { own: "write", maintain: "write", commit: "none" };
    expect(projectedRight(user, "write")).toBe("git.repo.maintain");
    expect(projectedRight(user, "admin")).toBeNull();
  });

  it("derives the right from the bridge's map: the lowest right with that role", () => {
    const forgejo = { own: "admin", maintain: "admin", commit: "none" };
    expect(projectedRight(forgejo, "admin")).toBe("git.repo.maintain");
    const branches = { own: "admin", maintain: "maintain", commit: "write" };
    expect(projectedRight(branches, "write")).toBe("git.commit.sign");
    expect(projectedRight(branches, "none")).toBeNull();
    expect(projectedRight({ own: "maintain", maintain: "write", commit: "none" }, "admin")).toBeNull();
  });

  it("lets an owner or a namespace admin revert", () => {
    // DOCS is owned by Bob; Alice is ACME's admin.
    expect(revertStanding(BOB, false, ACME, DOCS, maintain).may).toBe(true);
    expect(revertStanding(ALICE, false, ACME, DOCS, maintain).may).toBe(true);
  });

  it("refuses anyone else, and an unknown viewer", () => {
    const r = revertStanding(HANA, true, ACME, DOCS, maintain);
    expect(r.may).toBe(false);
    expect(!r.may && r.why).toMatch(/git\.repo\.own/);
    expect(revertStanding(null, true, ACME, DOCS, maintain).may).toBe(false);
  });

  it("wants a community administrator when the revert weighs as revoking own", () => {
    expect(revertStanding(BOB, false, ACME, DOCS, admin).may).toBe(false);
    expect(revertStanding(BOB, true, ACME, DOCS, admin).may).toBe(true);
    // Re-projecting a removed admin role is not a revocation of own.
    expect(revertStanding(BOB, false, ACME, DOCS, { ...admin, type: "roleRemoved" }).may).toBe(true);
  });

  it("weighs every role revert as revoking own while the map is unknown", () => {
    const unknown = { ...DOCS, roleMap: undefined };
    expect(revertStanding(BOB, false, ACME, unknown, maintain).may).toBe(false);
    expect(revertStanding(BOB, true, ACME, unknown, maintain).may).toBe(true);
    expect(driftRevertImpact({ ...maintain, observed: "read" }, undefined)).toBe("git.repo.own");
    expect(driftRevertImpact({ ...maintain, observed: "none" }, undefined)).toBe("git.repo.maintain");
  });

  it("offers nothing in manual mode, or on a repository that is not active", () => {
    const r = revertStanding(ALICE, true, PERSONAL, { ...DOCS, namespace: PERSONAL.id }, maintain);
    expect(!r.may && r.why).toMatch(/manual mode/);
    expect(revertStanding(ALICE, true, ACME, { ...DOCS, state: "archived" }, maintain).may).toBe(false);
    expect(revertStanding(ALICE, true, ACME, LEGACY, maintain).may).toBe(true);
  });
});

describe("adoptStanding — what git-ns/drift/resolve adopt accepts", () => {
  const added = (observed: string) => ({
    type: "roleAdded" as const,
    resource: DOCS.resource,
    observed,
    account: { forge: "github.com", id: "1003", login: "hsato" },
  });
  const USER_NS = { ...ACME, kind: "user" };

  it("adopts a maintain role as maintainer for an owner, normal-class", () => {
    const r = adoptStanding(BOB, false, ACME, DOCS, added("maintain"), HANA, 0);
    expect(r).toEqual({ may: true, member: HANA, right: "git.repo.maintain" });
  });

  it("projects write to maintainer under a personal account's map, and to nothing on an organisation", () => {
    // The bridge's default map on a personal account: own and maintain both
    // collapse to `write`.
    const personal = { ...DOCS, roleMap: { own: "write", maintain: "write", commit: "none" } };
    expect(adoptStanding(BOB, false, USER_NS, personal, added("write"), HANA, 0)).toEqual({
      may: true,
      member: HANA,
      right: "git.repo.maintain",
    });
    const org = adoptStanding(BOB, false, ACME, DOCS, added("write"), HANA, 0);
    expect(org.may).toBe(false);
    expect(!org.may && org.why).toMatch(/No git right projects to the forge role "write"/);
    // `admin` projects nothing on a personal account.
    expect(adoptStanding(BOB, true, USER_NS, personal, added("admin"), HANA, 0).may).toBe(false);
  });

  it("adopts nothing while the bridge has not reported its role map", () => {
    const unknown = { ...DOCS, roleMap: undefined };
    const r = adoptStanding(BOB, true, ACME, unknown, added("maintain"), HANA, 0);
    expect(r.may).toBe(false);
    expect(!r.may && !r.handOver && r.why).toMatch(/role map/);
  });

  it("refuses a lowering: a roleChanged no higher than what the member holds", () => {
    const changed = { ...added("maintain"), type: "roleChanged" as const };
    // Hana already maintains (rank 2): maintain is no raise.
    const r = adoptStanding(BOB, true, ACME, DOCS, changed, HANA, 2);
    expect(r.may).toBe(false);
    expect(!r.may && !r.handOver && r.why).toMatch(/lowering/);
    // From committer (rank 1) it is a raise.
    expect(adoptStanding(BOB, true, ACME, DOCS, changed, HANA, 1).may).toBe(true);
  });

  it("refuses what records no right, and an account nobody linked", () => {
    expect(
      adoptStanding(BOB, true, ACME, DOCS, { ...added("admin"), type: "roleRemoved" }, HANA, 0).may,
    ).toBe(false);
    const unlinked = adoptStanding(BOB, true, ACME, DOCS, added("maintain"), undefined, 0);
    expect(!unlinked.may && unlinked.why).toMatch(/No member has linked/);
  });

  it("hands over to an owner, and an elevated adopt to a community administrator", () => {
    const outsider = adoptStanding(HANA, true, ACME, DOCS, added("maintain"), HANA, 0);
    expect(outsider).toMatchObject({ may: false, handOver: true, right: "git.repo.maintain" });
    const owner = adoptStanding(BOB, false, ACME, DOCS, added("admin"), HANA, 0);
    expect(owner).toMatchObject({ may: false, handOver: true, right: "git.repo.own" });
    expect(adoptStanding(BOB, true, ACME, DOCS, added("admin"), HANA, 0)).toEqual({
      may: true,
      member: HANA,
      right: "git.repo.own",
    });
    // A namespace admin owns every repository in it.
    expect(adoptStanding(ALICE, false, ACME, DOCS, added("maintain"), HANA, 0).may).toBe(true);
  });

  it("ranks the member's projected right: own-name rights only, unexpired", () => {
    expect(projectedRepoRank(RIGHTS, BOB, DOCS, ACME)).toBe(3);
    expect(projectedRepoRank(RIGHTS, HANA, WIDGETS, ACME)).toBe(2);
    expect(projectedRepoRank(RIGHTS, HANA, DOCS, ACME)).toBe(0);
    const lapsed = [{ ...RIGHTS[4]!, expiresAt: "2000-01-01T00:00:00Z" }];
    expect(projectedRepoRank(lapsed, HANA, WIDGETS, ACME)).toBe(0);
    // A namespace admin projects to no forge role: Alice, ACME's admin with
    // nothing of her own on docs, is projected at nothing there…
    expect(projectedRepoRank(RIGHTS, ALICE, DOCS, ACME)).toBe(0);
    expect(projectedRepoRank([], ALICE, DOCS, ACME)).toBe(0);
    // …and at maintain once she holds it in her own name.
    const maintains = [...RIGHTS, { ...RIGHTS[4]!, subject: ALICE, resource: DOCS.resource }];
    expect(projectedRepoRank(maintains, ALICE, DOCS, ACME)).toBe(2);
    // A v0.1 hook-relay grant is not in the store the projector reads.
    const derived = [{ ...RIGHTS[4]!, resource: DOCS.resource, origin: "roleDerived" }];
    expect(projectedRepoRank(derived, HANA, DOCS, ACME)).toBe(0);
  });

  it("lets a namespace admin holding maintain adopt a forge admin as owner", () => {
    const changed = {
      type: "roleChanged" as const,
      resource: DOCS.resource,
      observed: "admin",
      expected: "maintain",
      account: { forge: "github.com", id: "1001", login: "alicew" },
    };
    // Alice (ACME's admin) is projected at maintain: admin is a raise,
    // which another owner who is a community administrator may adopt.
    expect(adoptStanding(BOB, true, ACME, DOCS, changed, ALICE, 2)).toEqual({
      may: true,
      member: ALICE,
      right: "git.repo.own",
    });
  });

  it("never offers a resolver an elevated right for themselves", () => {
    const changed = {
      type: "roleChanged" as const,
      resource: DOCS.resource,
      observed: "admin",
      expected: "maintain",
      account: { forge: "github.com", id: "1001", login: "alicew" },
    };
    // Alice adopting ownership for herself: handed over, naming break-glass,
    // even as a community administrator.
    const self = adoptStanding(ALICE, true, ACME, DOCS, changed, ALICE, 2);
    expect(self).toMatchObject({ may: false, handOver: true, member: ALICE, right: "git.repo.own" });
    expect(self.may === false && self.why).toMatch(/break-glass/);
    // A lower right is not elevated: an owner adopts maintain for herself.
    const added = {
      type: "roleAdded" as const,
      resource: DOCS.resource,
      observed: "maintain",
      account: { forge: "github.com", id: "1001", login: "alicew" },
    };
    expect(adoptStanding(ALICE, false, ACME, DOCS, added, ALICE, 0)).toEqual({
      may: true,
      member: ALICE,
      right: "git.repo.maintain",
    });
    // Where the map gives maintainers `admin`, maintain is elevated too
    // (`Right::is_elevated_in`): a forge admin adopts as maintain, handed over.
    const maintainersAdmin = { ...DOCS, roleMap: { own: "admin", maintain: "admin", commit: "none" } };
    const raised = adoptStanding(ALICE, true, ACME, maintainersAdmin, { ...added, observed: "admin" }, ALICE, 0);
    expect(raised).toMatchObject({ may: false, handOver: true, member: ALICE, right: "git.repo.maintain" });
    expect(raised.may === false && raised.why).toMatch(/role map/);
    expect(raised.may === false && raised.why).not.toMatch(/break-glass/);
  });
});
