import { describe, expect, it } from "vitest";

import { bootstrapView, bootstrapViewSummary, commitTrustVerdict } from "./model";
import { ACME, ALICE, BOB, SANDBOX, WIDGETS } from "./fixtures.test-data";

type Repo = typeof WIDGETS;

describe("bootstrapView / commitTrustVerdict — which steps apply here", () => {
  // The case an operator met: the bridge posts the check itself, and its last
  // run reported only the required check and the variables.
  const bridgePosted = {
    ...WIDGETS,
    owners: [ALICE, BOB],
    guard: "bridgePostedCheck",
    bootstrap: { workflow: false, keyring: false, variables: true, requiredCheck: true },
    steps: [
      { step: "requiredCheck", outcome: "applied" },
      { step: "variables", outcome: "unchanged" },
    ],
  } as Repo;

  const states = (repo: Repo) =>
    Object.fromEntries(bootstrapView(ACME, repo).map((s) => [s.key, s.state]));

  it("reads an unused workflow and an unreported keyring as not applicable, not missing", () => {
    expect(states(bridgePosted)).toEqual({
      workflow: "notApplicable",
      keyring: "notApplicable",
      variables: "done",
      requiredCheck: "done",
    });
    const workflow = bootstrapView(ACME, bridgePosted).find((s) => s.key === "workflow")!;
    expect(workflow.why).toMatch(/bridge runs verify-trust itself/);
    expect(bootstrapViewSummary(bootstrapView(ACME, bridgePosted))).toBe(
      "All that apply in place; workflow, keyring not applicable",
    );
  });

  it("calls that repository enforced, with nothing to do", () => {
    const v = commitTrustVerdict(ACME, bridgePosted);
    expect(v.tone).toBe("success");
    expect(v.headline).toMatch(/^Enforced/);
    expect(v.detail).toMatch(/2 of 4 do not apply/);
  });

  it("keeps a step the bridge reported failed as failed, whatever the guard", () => {
    const repo = {
      ...bridgePosted,
      steps: [...bridgePosted.steps, { step: "workflow", outcome: "failed" }],
    } as Repo;
    expect(states(repo).workflow).toBe("failed");
  });

  it("reads a skipped step as not applicable", () => {
    const repo = {
      ...WIDGETS,
      guard: "codeOwnerReview",
      owners: [ALICE, BOB],
      bootstrap: { workflow: true, keyring: false, variables: true, requiredCheck: true },
      steps: [{ step: "keyring", outcome: "skipped" }],
    } as Repo;
    expect(states(repo).keyring).toBe("notApplicable");
  });

  it("with no run on record, a step not in place is missing", () => {
    const repo = { ...SANDBOX, state: "active", steps: [] } as Repo;
    expect(Object.values(states(repo))).toContain("missing");
  });

  it("says untrusted commits can merge when the required check is missing", () => {
    const repo = {
      ...bridgePosted,
      bootstrap: { ...bridgePosted.bootstrap, requiredCheck: false },
      steps: [{ step: "requiredCheck", outcome: "failed" }],
    } as Repo;
    const v = commitTrustVerdict(ACME, repo);
    expect(v.tone).toBe("danger");
    expect(v.headline).toMatch(/untrusted commits can be merged/);
  });

  it("names the failing step when the check is in place but another is not", () => {
    const repo = {
      ...bridgePosted,
      bootstrap: { ...bridgePosted.bootstrap, variables: false },
      steps: [
        { step: "requiredCheck", outcome: "unchanged" },
        { step: "variables", outcome: "failed" },
      ],
    } as Repo;
    const v = commitTrustVerdict(ACME, repo);
    expect(v.tone).toBe("warning");
    expect(v.headline).toBe("Action needed: variables is failing");
  });
});
