// Materializing a ceremony's facts template — the step between the controls an
// operator sets and the `input` document the daemon evaluates a policy against.
//
// The directives are small, and each one exists because a policy asks a
// question the others cannot answer: `$field` substitutes a value, `$if`
// chooses a branch, and an absent branch drops the key — because "this
// criterion does not vet" is asked as `not input.evidence.vetting`, which a
// `null` would answer wrongly.

import { describe, expect, it } from "vitest";

import { defaultValues, evalShowWhen, materializeFacts } from "@/lib/ceremony-manifest";
import type { CeremonyManifest, FieldDef } from "@/lib/ceremony-manifest";

describe("materializeFacts", () => {
  it("substitutes a field, and drops the key when it is unset", () => {
    const facts = materializeFacts(
      { kept: "$field:a", dropped: "$field:b", blank: "$field:c" },
      { a: true, c: "" },
    );
    expect(facts).toEqual({ kept: true });
  });

  it("chooses a branch on truthiness, as it always has", () => {
    const template = {
      member: { $if: "isMember", then: { role: "member" }, else: null },
    };
    expect(materializeFacts(template, { isMember: true })).toEqual({
      member: { role: "member" },
    });
    expect(materializeFacts(template, { isMember: false })).toEqual({
      member: null,
    });
  });

  it("compares a value when the directive says `eq`", () => {
    // Every non-empty option of a select is truthy, so a five-way choice can
    // only be read by comparison.
    const template = {
      consistent: { $if: "outcome", eq: "inconsistent", then: false, else: true },
    };
    expect(materializeFacts(template, { outcome: "inconsistent" })).toEqual({
      consistent: false,
    });
    expect(materializeFacts(template, { outcome: "satisfied" })).toEqual({
      consistent: true,
    });
    expect(materializeFacts(template, { outcome: "none" })).toEqual({
      consistent: true,
    });
  });

  it("drops the key entirely when the chosen branch names nothing", () => {
    const template = {
      evidence: {
        vetting: {
          $if: "outcome",
          eq: "none",
          else: { satisfied: true },
        },
      },
    };
    // Not required: the member is absent, not null — `not input.evidence.vetting`.
    expect(materializeFacts(template, { outcome: "none" })).toEqual({
      evidence: {},
    });
    expect(materializeFacts(template, { outcome: "satisfied" })).toEqual({
      evidence: { vetting: { satisfied: true } },
    });
  });

  it("materializes a whole vetting outcome as one coherent fact set", () => {
    // The shape of the join ceremony's template, which derives every member
    // from the one control so the set is always one the host could produce.
    const template = {
      evidence: {
        vetting: {
          $if: "vettingOutcome",
          eq: "none",
          else: {
            commitments_consistent: {
              $if: "vettingOutcome",
              eq: "inconsistent",
              then: false,
              else: true,
            },
            needs: {
              $if: "vettingOutcome",
              eq: "incomplete",
              then: ["vetting:statements:1"],
              else: [],
            },
            independence_ok: {
              $if: "vettingOutcome",
              eq: "notIndependent",
              then: false,
              else: true,
            },
            satisfied: {
              $if: "vettingOutcome",
              eq: "satisfied",
              then: true,
              else: false,
            },
          },
        },
      },
    };
    const vetting = (outcome: string) =>
      (materializeFacts(template, { vettingOutcome: outcome }) as {
        evidence: { vetting?: Record<string, unknown> };
      }).evidence.vetting;

    expect(vetting("none")).toBeUndefined();
    expect(vetting("inconsistent")).toMatchObject({
      commitments_consistent: false,
      satisfied: false,
    });
    expect(vetting("incomplete")).toMatchObject({
      commitments_consistent: true,
      needs: ["vetting:statements:1"],
      satisfied: false,
    });
    expect(vetting("notIndependent")).toMatchObject({
      commitments_consistent: true,
      needs: [],
      independence_ok: false,
      satisfied: false,
    });
    expect(vetting("satisfied")).toMatchObject({
      commitments_consistent: true,
      needs: [],
      independence_ok: true,
      satisfied: true,
    });
  });
});

describe("field visibility", () => {
  const field = (over: Partial<FieldDef>): FieldDef =>
    ({
      key: "vettingInvitationRequired",
      label: "…and the requirements also demand an invitation",
      type: "toggle",
      default: false,
      ...over,
    }) as FieldDef;

  it("shows a follow-up only for the option it belongs to", () => {
    const f = field({ showWhen: { field: "vettingOutcome", eq: "satisfied" } });
    expect(evalShowWhen(f.showWhen, { vettingOutcome: "satisfied" })).toBe(true);
    expect(evalShowWhen(f.showWhen, { vettingOutcome: "incomplete" })).toBe(false);
    expect(evalShowWhen(f.showWhen, { vettingOutcome: "none" })).toBe(false);
  });

  it("seeds every control from its default", () => {
    const values = defaultValues({
      fields: [
        field({ key: "joinTrusted", default: false }),
        field({ key: "vettingOutcome", type: "select", default: "none" }),
      ],
    } as CeremonyManifest);
    expect(values).toEqual({ joinTrusted: false, vettingOutcome: "none" });
  });
});
