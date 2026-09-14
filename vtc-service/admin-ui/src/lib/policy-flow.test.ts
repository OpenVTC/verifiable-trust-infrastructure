// The chart is induced from evaluations, so the property that matters is that
// it never disagrees with them: for every probe, walking the chart with those
// inputs must reach the ending the policy actually gave. A chart that is
// merely plausible is the failure mode this replaces.

import { describe, expect, it } from "vitest";

import type { CeremonyManifest, FieldValues } from "@/lib/ceremony-manifest";
import {
  countEndings,
  induceFlow,
  probeSpace,
  traceVerdict,
  verdictKey,
  type FlowNode,
  type ProbeRow,
  type Verdict,
} from "@/lib/policy-flow";

/** The join ceremony's controls, as the daemon declares them. */
const JOIN = {
  purpose: "join",
  pkg: "vtc.join",
  nature: "constructive",
  label: "Join",
  wired: "live",
  blurb: "",
  factsTemplate: {},
  fields: [
    { key: "joinTrusted", label: "Presented credential is trusted", type: "toggle", default: false },
    { key: "invitationHeld", label: "Presents a valid invitation", type: "toggle", default: false },
    {
      key: "vettingOutcome",
      label: "Peer identity vetting",
      type: "select",
      default: "none",
      options: [
        { value: "none", label: "not required by the criterion" },
        { value: "incomplete", label: "not enough statements yet" },
        { value: "inconsistent", label: "vetters verified different identities" },
        { value: "notIndependent", label: "vetters not independent enough" },
        { value: "satisfied", label: "requirements met" },
      ],
    },
    {
      key: "vettingInvitationRequired",
      label: "…and the requirements also demand an invitation",
      type: "toggle",
      default: false,
      showWhen: { field: "vettingOutcome", eq: "satisfied" },
    },
  ],
} as unknown as CeremonyManifest;

/** The shipped join policy, as a function — standing in for the daemon. */
function joinPolicy(v: FieldValues): Verdict {
  const outcome = v.vettingOutcome as string;
  const vets = outcome !== "none";
  const consistent = outcome !== "inconsistent";
  const needs = outcome === "incomplete";
  const independent = outcome !== "notIndependent";
  const satisfiedFact = outcome === "satisfied";
  const invitation = v.invitationHeld === true;
  const invitationMissing =
    vets && satisfiedFact && v.vettingInvitationRequired === true && !invitation;
  const satisfied = vets && satisfiedFact && !invitationMissing;
  const vettingOk = !vets || satisfied;

  if (vets && !consistent) return { effect: "refer", with: { queue: "vetting-review" } };
  if (vets && consistent && needs) return { effect: "request_more", with: { needs: ["vetting"] } };
  if (vets && consistent && !needs && !independent)
    return { effect: "refer", with: { queue: "vetting-review" } };
  if (invitationMissing)
    return { effect: "request_more", with: { needs: ["vetting:invitation"] } };
  if (invitation && vettingOk) return { effect: "allow", with: { role: "member" } };
  if (satisfied) return { effect: "allow", with: { role: "member" } };
  if (v.joinTrusted === true && vettingOk) return { effect: "allow", with: { role: "member" } };
  return { effect: "refer", with: { queue: "moderator" } };
}

const probe = (values: FieldValues[]): ProbeRow[] =>
  values.map((v) => ({ values: v, verdict: joinPolicy(v) }));

describe("probeSpace", () => {
  it("varies only the controls the ceremony would show", () => {
    const space = probeSpace(JOIN)!;
    // 5 outcomes × 2 trusted × 2 invitation, and the invitation demand only
    // doubles the one outcome that shows it: (4 + 2) × 4.
    expect(space).toHaveLength(24);
    const hidden = space.filter((s) => s.vettingOutcome !== "satisfied");
    expect(hidden.every((s) => s.vettingInvitationRequired === false)).toBe(true);
  });

  it("refuses rather than truncates when the space is too large", () => {
    expect(probeSpace(JOIN, 8)).toBeNull();
    // A truncated space would induce a chart that is wrong about the states it
    // never saw, which is the whole failure this design avoids.
  });
});

describe("induceFlow", () => {
  const space = probeSpace(JOIN)!;
  const rows = probe(space);
  const flow = induceFlow(JOIN, rows);

  it("agrees with every evaluation it was built from", () => {
    for (const row of rows) {
      const ending = traceVerdict(flow, row.values);
      expect(ending, `no path for ${JSON.stringify(row.values)}`).not.toBeNull();
      expect(ending!.kind).toBe("verdict");
      expect(verdictKey(ending as Verdict)).toBe(verdictKey(row.verdict));
    }
  });

  it("asks about vetting first, because it separates the endings best", () => {
    expect(flow.kind).toBe("ask");
    expect((flow as { field: string }).field).toBe("vettingOutcome");
  });

  it("stops asking once the answer cannot change", () => {
    // Vetters who verified different identities are referred whatever else the
    // applicant presents, so no further question is put on that branch.
    const inconsistent = (flow as { branches: { value: unknown; node: FlowNode }[] })
      .branches.find((b) => b.value === "inconsistent")!.node;
    expect(inconsistent.kind).toBe("verdict");
    expect((inconsistent as { effect: string }).effect).toBe("refer");
  });

  it("keeps the questions that do change the answer", () => {
    // With no vetting required, an invitation or a trusted credential is what
    // decides — the bypass worth seeing.
    const none = (flow as { branches: { value: unknown; node: FlowNode }[] })
      .branches.find((b) => b.value === "none")!.node;
    expect(none.kind).toBe("ask");
    expect(["invitationHeld", "joinTrusted"]).toContain(
      (none as { field: string }).field,
    );
  });

  it("says so when the endings turn on something no control varies", () => {
    // Same inputs, different verdicts: the policy read a fact this ceremony
    // does not declare, so no question the chart can ask will separate them.
    const values: FieldValues = {
      joinTrusted: false,
      invitationHeld: false,
      vettingOutcome: "none",
      vettingInvitationRequired: false,
    };
    const node = induceFlow(JOIN, [
      { values, verdict: { effect: "allow" } },
      { values, verdict: { effect: "refer" } },
    ]);
    expect(node.kind).toBe("varies");
    expect((node as { effects: string[] }).effects).toEqual(["allow", "refer"]);
  });

  it("has an ending for every path it draws", () => {
    expect(countEndings(flow)).toBeGreaterThan(1);
  });
});
