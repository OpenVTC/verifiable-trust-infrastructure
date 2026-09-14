import { screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import type { CeremonyManifest } from "@/lib/ceremony-manifest";
import { induceFlow, probeSpace, type ProbeRow } from "@/lib/policy-flow";
import { PolicyFlow } from "@/plugins/PolicyFlow";
import { renderWithProviders } from "@/test/render";

/** A ceremony with two controls, enough to draw a question and three endings. */
const CEREMONY = {
  purpose: "join",
  pkg: "vtc.join",
  nature: "constructive",
  label: "Join",
  wired: "live",
  blurb: "",
  factsTemplate: {},
  fields: [
    {
      key: "vettingOutcome",
      label: "Peer identity vetting",
      type: "select",
      default: "none",
      options: [
        { value: "none", label: "not required" },
        { value: "satisfied", label: "requirements met" },
        { value: "inconsistent", label: "different identities" },
      ],
    },
    { key: "joinTrusted", label: "Presented credential is trusted", type: "toggle", default: false },
  ],
} as unknown as CeremonyManifest;

function rows(): ProbeRow[] {
  return probeSpace(CEREMONY)!.map((values) => {
    if (values.vettingOutcome === "inconsistent") {
      return { values, verdict: { effect: "refer", with: { queue: "vetting-review" } } };
    }
    if (values.vettingOutcome === "satisfied") {
      return { values, verdict: { effect: "allow", with: { role: "member" } } };
    }
    return values.joinTrusted
      ? { values, verdict: { effect: "allow", with: { role: "member" } } }
      : { values, verdict: { effect: "refer", with: { queue: "moderator" } } };
  });
}

describe("PolicyFlow", () => {
  it("draws the questions and the endings the evaluations produced", () => {
    renderWithProviders(<PolicyFlow ceremony={CEREMONY} probes={rows()} />);

    expect(screen.getByText("Peer identity vetting")).toBeTruthy();
    // Both endings appear, in the ceremony's verdict language.
    expect(screen.getAllByText("ADMIT").length).toBeGreaterThan(0);
    expect(screen.getAllByText("REFER").length).toBeGreaterThan(0);
    expect(screen.getByText("to the vetting-review queue")).toBeTruthy();
    expect(screen.getByText("to the moderator queue")).toBeTruthy();
  });

  it("asks about the credential only where it changes the answer", () => {
    renderWithProviders(<PolicyFlow ceremony={CEREMONY} probes={rows()} />);
    // It matters on one branch of three, so it is drawn once, not on each.
    expect(screen.getAllByText("Presented credential is trusted")).toHaveLength(1);
  });

  it("lights the path the current inputs take", () => {
    const { container } = renderWithProviders(
      <PolicyFlow
        ceremony={CEREMONY}
        probes={rows()}
        values={{ vettingOutcome: "inconsistent", joinTrusted: false }}
      />,
    );
    const svg = container.querySelector("svg.pf")!;
    expect(svg.classList.contains("pf-traced")).toBe(true);
    // The refer-to-vetting-review ending is on the path; something else is not.
    expect(container.querySelectorAll(".pf-lit").length).toBeGreaterThan(0);
    expect(container.querySelectorAll(".pf-dim").length).toBeGreaterThan(0);
  });

  it("names an ending it cannot explain rather than guessing", () => {
    const values = { vettingOutcome: "none", joinTrusted: false };
    const disagreeing: ProbeRow[] = [
      { values, verdict: { effect: "allow" } },
      { values, verdict: { effect: "deny" } },
    ];
    renderWithProviders(<PolicyFlow ceremony={CEREMONY} probes={disagreeing} />);
    expect(screen.getByText("VARIES")).toBeTruthy();
    expect(screen.getByText(/on a fact no control varies/)).toBeTruthy();
  });

  it("agrees with the table it was drawn from", () => {
    // The same property the lib test holds, asserted through the component's
    // own layout: every probe's ending is somewhere in the chart.
    const table = rows();
    const flow = induceFlow(CEREMONY, table);
    renderWithProviders(<PolicyFlow ceremony={CEREMONY} probes={table} />);
    expect(flow.kind).toBe("ask");
    expect(screen.getAllByText(/ADMIT|REFER/).length).toBeGreaterThanOrEqual(3);
  });
});
