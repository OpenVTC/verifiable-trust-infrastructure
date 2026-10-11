// The attention strip's ordering and folding (`components/AttentionStrip.tsx`).
// The items' own wording, links and roles are covered where they are built
// (`AppActionsBadge.test.tsx`, `plugins/repos/BreakGlass.test.tsx`).

import { fireEvent, render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import {
  AttentionStrip,
  collapsedView,
  orderAttention,
  type AttentionItem,
} from "@/components/AttentionStrip";

const item = (key: string, severity: AttentionItem["severity"]): AttentionItem => ({
  key,
  severity,
  node: (
    <div role={severity === "critical" ? "alert" : "status"} aria-label={key}>
      {key}
    </div>
  ),
});

describe("ordering", () => {
  it("puts the most severe first and keeps the given order within a severity", () => {
    const ordered = orderAttention([
      item("waiting", "info"),
      item("renew", "warning"),
      item("single", "standing"),
      item("writes", "critical"),
      item("cooling", "critical"),
    ]);
    expect(ordered.map((i) => i.key)).toEqual(["writes", "cooling", "single", "renew", "waiting"]);
  });

  it("never folds critical or standing items away", () => {
    const { shown, folded } = collapsedView(
      orderAttention([
        item("waiting", "info"),
        item("renew", "warning"),
        item("single", "standing"),
        item("writes", "critical"),
      ]),
    );
    expect(shown.map((i) => i.key)).toEqual(["writes", "single", "renew"]);
    expect(folded).toBe(1);
  });
});

describe("the strip", () => {
  it("renders nothing when nothing needs attention", () => {
    const { container } = render(<AttentionStrip items={[]} />);
    expect(container.firstChild).toBeNull();
  });

  it("shows a lone item without a count or a toggle", () => {
    render(<AttentionStrip items={[item("waiting", "info")]} />);
    expect(screen.getByRole("status", { name: "waiting" })).toBeTruthy();
    expect(screen.queryByText(/need/)).toBeNull();
    expect(screen.queryByRole("button")).toBeNull();
  });

  it("counts everything, shows the pinned and the most severe other, and expands", () => {
    render(
      <AttentionStrip
        items={[item("waiting", "info"), item("renew", "warning"), item("writes", "critical")]}
      />,
    );
    const strip = screen.getByRole("region", { name: "Needs attention" });
    expect(within(strip).getByText("3 things need attention")).toBeTruthy();
    expect(within(strip).getByRole("alert", { name: "writes" })).toBeTruthy();
    expect(within(strip).getByRole("status", { name: "renew" })).toBeTruthy();
    expect(within(strip).queryByRole("status", { name: "waiting" })).toBeNull();

    // Most severe first in the document.
    const shown = Array.from(strip.querySelectorAll('[role="alert"], [role="status"]')).map((e) =>
      e.getAttribute("aria-label"),
    );
    expect(shown).toEqual(["writes", "renew"]);

    const toggle = within(strip).getByRole("button", { name: /Show 1 more/ });
    expect(toggle.getAttribute("aria-expanded")).toBe("false");
    fireEvent.click(toggle);
    expect(within(strip).getByRole("status", { name: "waiting" })).toBeTruthy();
    const less = within(strip).getByRole("button", { name: /Show less/ });
    expect(less.getAttribute("aria-expanded")).toBe("true");
    fireEvent.click(less);
    expect(within(strip).queryByRole("status", { name: "waiting" })).toBeNull();
    // The critical item never left.
    expect(within(strip).getByRole("alert", { name: "writes" })).toBeTruthy();
  });

  it("is coloured by its most severe item", () => {
    render(<AttentionStrip items={[item("waiting", "info"), item("writes", "critical")]} />);
    expect(screen.getByTestId("attention-strip").className).toContain("attention-strip--critical");
  });
});
