import { screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import type { CeremonyManifest } from "@/lib/ceremony-manifest";
import { induceFlow, probeSpace, type ProbeRow } from "@/lib/policy-flow";
import { PolicyFlow, WIDTH, fit, layout } from "@/plugins/PolicyFlow";
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
  /** The labels as drawn — truncated, and without the tooltip copies. */
  const drawn = (container: HTMLElement, selector: string) =>
    [...container.querySelectorAll(selector)].map((n) =>
      [...n.childNodes]
        .filter((c) => c.nodeType === Node.TEXT_NODE)
        .map((c) => c.textContent)
        .join(""),
    );

  it("draws the questions and the endings the evaluations produced", () => {
    const { container } = renderWithProviders(
      <PolicyFlow ceremony={CEREMONY} probes={rows()} />,
    );

    expect(drawn(container, "text.pf-q-label")).toContain("Peer identity vetting");
    expect(screen.getAllByText("ADMIT").length).toBeGreaterThan(0);
    expect(screen.getAllByText("REFER").length).toBeGreaterThan(0);
    const details = drawn(container, "text.pf-term-detail");
    expect(details.some((d) => d.startsWith("to the vetting-review"))).toBe(true);
    expect(details.some((d) => d.startsWith("to the moderator"))).toBe(true);
  });

  it("asks about the credential only where it changes the answer", () => {
    const { container } = renderWithProviders(
      <PolicyFlow ceremony={CEREMONY} probes={rows()} />,
    );
    // It matters on one branch of three, so it is drawn once, not on each.
    const questions = drawn(container, "text.pf-q-label");
    expect(questions.filter((q) => q.startsWith("Presented credential"))).toHaveLength(1);
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
    const { container } = renderWithProviders(
      <PolicyFlow ceremony={CEREMONY} probes={disagreeing} />,
    );
    expect(screen.getByText("VARIES")).toBeTruthy();
    // The reason is drawn, cut to the box, and kept whole in the tooltip.
    const titles = [...container.querySelectorAll("title")].map((t) => t.textContent);
    expect(titles.some((t) => t?.includes("on a fact no control varies"))).toBe(true);
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

  it("gives every node its own row, inside the drawing", () => {
    // The first cut placed a column per depth: four levels wanted about a
    // thousand pixels in a panel that has six hundred, and the endings fell off
    // the right. Depth is an indent now, so this is the invariant that keeps
    // it: one row each, and every box ends inside the viewBox.
    const { container } = renderWithProviders(
      <PolicyFlow ceremony={CEREMONY} probes={rows()} />,
    );
    const boxes = [...container.querySelectorAll("rect")].map((r) => ({
      x: Number(r.getAttribute("x")),
      y: Number(r.getAttribute("y")),
      w: Number(r.getAttribute("width")),
      h: Number(r.getAttribute("height")),
    }));
    expect(boxes.length).toBeGreaterThan(3);
    for (const b of boxes) {
      expect(b.x).toBeGreaterThanOrEqual(0);
      expect(b.x + b.w).toBeLessThanOrEqual(WIDTH);
      expect(b.w).toBeGreaterThan(80);
    }
    for (const a of boxes) {
      for (const b of boxes) {
        if (a === b) continue;
        const apart = a.y + a.h <= b.y || b.y + b.h <= a.y;
        expect(apart, `boxes overlap: ${JSON.stringify([a, b])}`).toBe(true);
      }
    }
  });

  it("is as tall as it has nodes, so nothing is laid over anything", () => {
    const flow = induceFlow(CEREMONY, rows());
    const placed = layout(flow);
    const indexes = placed.map((r) => r.index);
    expect(new Set(indexes).size).toBe(placed.length);
    expect(indexes).toEqual([...indexes].sort((a, b) => a - b));
  });

  it("cuts a label to its box rather than letting it run across the next one", () => {
    const long = "…and the requirements also demand an invitation from the community";
    const cut = fit(long, 200);
    expect(cut.length).toBeLessThan(long.length);
    expect(cut.endsWith("…")).toBe(true);
    // Short labels are left alone.
    expect(fit("admit", 200)).toBe("admit");
  });

  it("keeps the full text reachable when it had to cut it", () => {
    renderWithProviders(<PolicyFlow ceremony={CEREMONY} probes={rows()} />);
    const titles = [...document.querySelectorAll("title")].map((t) => t.textContent);
    expect(titles).toContain("Peer identity vetting");
  });
});