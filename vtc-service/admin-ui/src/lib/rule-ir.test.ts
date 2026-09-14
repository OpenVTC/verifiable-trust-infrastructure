// The Rule IR compiler, and the vocabulary each purpose is authored in.
//
// The package assertions read the daemon's own shipped policies rather than a
// list written here: a module compiled into the wrong package compiles cleanly
// and then silently decides nothing, so the console's idea of where a policy
// lives has to be the daemon's.

import { readFileSync, readdirSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

import { ALL_PURPOSES, pkgFor, type Purpose } from "@/lib/policies-api";
import {
  blankIR,
  canAuthorVisually,
  compileToRego,
  conditionsFor,
  effectsFor,
  irToEnglish,
  parseRego,
  type RuleIR,
} from "@/lib/rule-ir";

/** The daemon's shipped policies, relative to this package's root. */
const POLICY_DIR = resolve(process.cwd(), "../policies/default");

/** `package vtc.x` → `vtc.x`, from each shipped default policy. */
function shippedPackages(): Set<string> {
  const packages = new Set<string>();
  for (const file of readdirSync(POLICY_DIR)) {
    if (!file.endsWith(".rego")) continue;
    const declared = readFileSync(resolve(POLICY_DIR, file), "utf8")
      .split("\n")
      .find((l) => l.startsWith("package "));
    if (declared) packages.add(declared.slice("package ".length).trim());
  }
  return packages;
}

describe("pkgFor mirrors PolicyPurpose::expected_package", () => {
  it("names the package each shipped policy declares", () => {
    const shipped = shippedPackages();
    expect(shipped.size).toBeGreaterThan(0);
    for (const purpose of ALL_PURPOSES) {
      expect(shipped).toContain(pkgFor(purpose));
    }
  });

  it("writes the two purposes whose package is not their spelling", () => {
    // The upload form printed `vtc.${purpose}` until this was fixed, handing an
    // operator `vtc.vetterEligibility` — which the daemon refuses.
    expect(pkgFor("vetterEligibility")).toBe("vtc.vetter_eligibility");
    expect(pkgFor("roleChange")).toBe("vtc.role_change");
    expect(pkgFor("join")).toBe("vtc.join");
  });
});

describe("visual authoring is offered where there is a vocabulary", () => {
  it("covers the four ceremonies and vetter eligibility, and nothing else", () => {
    const authorable = ALL_PURPOSES.filter(canAuthorVisually);
    expect(authorable.sort()).toEqual(
      ["directory", "join", "removal", "roleChange", "vetterEligibility"].sort(),
    );
  });

  it("offers the sweep no condition about an actor it does not have", () => {
    const ids = conditionsFor("vetterEligibility").map((c) => c.id);
    expect(ids).toContain("always");
    expect(ids).toContain("tenure_at_least");
    expect(ids).not.toContain("actor_is_admin");
    expect(ids).not.toContain("subject_is_admin");
  });

  it("offers the sweep only the two effects it acts on", () => {
    expect(effectsFor("vetterEligibility").map((e) => e.effect)).toEqual([
      "allow",
      "deny",
    ]);
    // Everything else keeps the four-valued ceremony vocabulary.
    expect(effectsFor("join").map((e) => e.effect)).toEqual([
      "allow",
      "deny",
      "refer",
      "request_more",
    ]);
  });

  it("starts a vetter-eligibility policy on the posture the daemon ships", () => {
    const ir = blankIR("vetterEligibility");
    expect(ir.routes[0]!.then).toEqual({ effect: "deny", with: {} });
  });
});

describe("compiling a vetter-eligibility policy", () => {
  /** The example the shipped policy's own comment suggests. */
  const TENURED: RuleIR = {
    purpose: "vetterEligibility",
    routes: [
      {
        name: "Tenured vetted members",
        when: {
          all: [
            "member_active",
            "not_under_review",
            { admitted_via: "vetting" },
            { tenure_at_least: "180" },
            { vetting_depth_at_most: "2" },
          ],
        },
        then: { effect: "allow", with: {} },
      },
      {
        name: "Everyone else",
        when: { all: ["always"] },
        then: { effect: "deny", with: {} },
      },
    ],
  };

  const rego = compileToRego(TENURED, pkgFor("vetterEligibility"));

  it("emits the package the daemon requires", () => {
    expect(rego.startsWith("package vtc.vetter_eligibility\n")).toBe(true);
  });

  it("reads the member record, with counts unquoted", () => {
    expect(rego).toContain('input.status == "active"');
    expect(rego).toContain("input.underReview == false");
    expect(rego).toContain('input.admittedVia == "vetting"');
    expect(rego).toContain("input.tenureDays >= 180");
    expect(rego).toContain("vetting_depth_within(2)");
  });

  it("pulls in the depth helper, which refuses an unknown depth", () => {
    expect(rego).toContain("vetting_depth_within(n) if {");
    expect(rego).toContain("is_number(input.depth)");
  });

  it("keeps the structural backstop and round-trips through the header", () => {
    expect(rego).toContain(
      'default decision := {"effect": "deny", "with": {"code": "no-matching-route"}}',
    );
    expect(parseRego(rego)).toEqual(TENURED);
  });

  it("says in English what it does, in the sweep's own terms", () => {
    const lines = irToEnglish(TENURED);
    expect(lines[0]!.text).toBe(
      "If membership is active and their own admission is not under review and " +
        "was admitted by vetting and has been a member for at least 180 days and " +
        "is at most 2 vetting hops from a founding member, then name them a vetter.",
    );
    expect(lines[1]!.text).toBe("Otherwise, do not name them.");
  });

  it("compiles an argument that is not a whole number to something false, not to broken Rego", () => {
    const broken: RuleIR = {
      purpose: "vetterEligibility",
      routes: [
        {
          name: "Nonsense",
          when: { all: [{ tenure_at_least: "many" }] },
          then: { effect: "allow", with: {} },
        },
      ],
    };
    // The editor will not produce this; the compiler still has to stay total.
    expect(compileToRego(broken, pkgFor("vetterEligibility"))).toContain(
      'input.tenureDays >= "many"',
    );
  });
});

describe("every purpose the console lists has a package", () => {
  it("maps each purpose without throwing", () => {
    for (const purpose of ALL_PURPOSES as Purpose[]) {
      expect(pkgFor(purpose)).toMatch(/^vtc\.[a-z_]+$/);
    }
  });
});
