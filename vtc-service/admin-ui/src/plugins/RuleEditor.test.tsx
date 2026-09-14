import { fireEvent, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { pkgFor } from "@/lib/policies-api";
import { blankIR } from "@/lib/rule-ir";
import { RuleEditor } from "@/plugins/RuleEditor";
import { renderWithProviders } from "@/test/render";

function editor(onSave = vi.fn()) {
  renderWithProviders(
    <RuleEditor
      purpose="vetterEligibility"
      pkg={pkgFor("vetterEligibility")}
      initial={blankIR("vetterEligibility")}
      onSave={onSave}
      onCancel={() => {}}
      saving={false}
    />,
  );
  return onSave;
}

describe("RuleEditor authoring a vetter-eligibility policy", () => {
  it("offers the sweep's own vocabulary, and names what its effects do", () => {
    editor();
    const conditions = screen.getByLabelText("Condition");
    expect(conditions.textContent).toContain("has been a member for at least");
    expect(conditions.textContent).not.toContain("actor is admin");
    expect(screen.getByLabelText("Effect").textContent).toBe(
      "Name a vetterDo not name a vetter",
    );
  });

  it("holds a count to a whole number before it can be added", () => {
    editor();
    fireEvent.change(screen.getByLabelText("Condition"), {
      target: { value: "tenure_at_least" },
    });
    const add = screen.getByRole("button", { name: "+ condition" });
    // Nothing typed yet: the condition cannot be added.
    expect((add as HTMLButtonElement).disabled).toBe(true);

    fireEvent.change(screen.getByLabelText("days"), { target: { value: "many" } });
    expect((add as HTMLButtonElement).disabled).toBe(true);
    expect(screen.getByText("The days must be a whole number.")).toBeTruthy();

    fireEvent.change(screen.getByLabelText("days"), { target: { value: "180" } });
    expect((add as HTMLButtonElement).disabled).toBe(false);
    fireEvent.click(add);
    expect(
      screen.getByText("has been a member for at least 180 days"),
    ).toBeTruthy();
  });

  it("makes a value the daemon matches exactly a choice, not free text", () => {
    editor();
    fireEvent.change(screen.getByLabelText("Condition"), {
      target: { value: "admitted_via" },
    });
    const how = screen.getByLabelText("how");
    expect(how.tagName).toBe("SELECT");
    expect(how.textContent).toContain("invitation");
    expect(
      (screen.getByRole("button", { name: "+ condition" }) as HTMLButtonElement)
        .disabled,
    ).toBe(true);

    fireEvent.change(how, { target: { value: "genesis" } });
    fireEvent.click(screen.getByRole("button", { name: "+ condition" }));
    expect(screen.getByText("is a founding member")).toBeTruthy();
  });

  it("saves Rego in the package the daemon requires", () => {
    const onSave = editor();
    fireEvent.change(screen.getByLabelText("Condition"), {
      target: { value: "member_active" },
    });
    fireEvent.click(screen.getByRole("button", { name: "+ condition" }));
    fireEvent.change(screen.getByLabelText("Effect"), { target: { value: "allow" } });
    fireEvent.click(screen.getByRole("button", { name: /Save as new revision/ }));

    expect(onSave).toHaveBeenCalledTimes(1);
    const rego = onSave.mock.calls[0]![0] as string;
    expect(rego.startsWith("package vtc.vetter_eligibility\n")).toBe(true);
    expect(rego).toContain('input.status == "active"');
    expect(rego).toContain('{"effect":"allow"');
  });
});
