import { describe, expect, it } from "vitest";

import {
  bootstrapSummary,
  consentClass,
  contains,
  desiredTuples,
  guardFor,
  isServiceGrant,
  namespaceFindings,
  repoStatus,
  rightForForgeRole,
} from "./model";
import {
  ACME,
  ALICE,
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

  it("publishes nothing for a pending namespace, an unmanaged repo, or a role-derived right", () => {
    expect(desiredTuples(RIGHTS, [{ ...ACME, state: "pending" }], [WIDGETS], [])).toEqual([]);
    const roleDerived = [{ ...RIGHTS[5]!, origin: "roleDerived" }];
    expect(desiredTuples(roleDerived, [ACME], [WIDGETS], [])).toEqual([]);
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
    expect(guardFor(PERSONAL, { ...WIDGETS, owners: [ALICE, HANA] }).mode).toBe("ownerReview");
    expect(guardFor(PERSONAL, WIDGETS).mode).toBe("soloUnreviewed");
  });

  it("is the bridge-posted check on a personal account with the App", () => {
    expect(
      guardFor({ ...PERSONAL, mode: "bridge" }, { ...WIDGETS, owners: [ALICE, HANA] }).mode,
    ).toBe("bridgeCheck");
  });
});

describe("namespace facts", () => {
  it("recognises the bridge's service grant and nothing else", () => {
    expect(RIGHTS.filter((r) => isServiceGrant(r, ACME)).map((r) => r.subject)).toEqual([BRIDGE]);
  });

  it("reports a lost installation and a headless namespace", () => {
    const titles = namespaceFindings({ ...ACME, installationRemoved: true, headless: true }).map(
      (f) => f.title,
    );
    expect(titles).toEqual(["The App lost access", "No namespace admin"]);
    expect(namespaceFindings(ACME)).toEqual([]);
  });

  it("summarises the bootstrap in words", () => {
    expect(bootstrapSummary(WIDGETS.bootstrap)).toBe("All four in place");
    expect(bootstrapSummary(SANDBOX.bootstrap)).toBe("Not bootstrapped");
    expect(bootstrapSummary(LEGACY.bootstrap)).toBe(
      "Workflow, Keyring, Variables in place; required check missing",
    );
  });

  it("maps a forge role back to the right that projects it", () => {
    expect(rightForForgeRole("admin")).toBe("git.repo.own");
    expect(rightForForgeRole("maintain")).toBe("git.repo.maintain");
    expect(rightForForgeRole("write")).toBe("git.commit.sign");
    expect(rightForForgeRole("triage")).toBeNull();
  });
});
