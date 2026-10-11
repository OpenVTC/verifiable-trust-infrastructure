// The palette on its own (the shell's wiring is `AppCommandPalette.test.tsx`).

import { fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";

import { CommandPalette } from "@/components/CommandPalette";
import type { PluginManifest } from "@/plugin-api";

const plugin = (id: string, label: string): PluginManifest => ({
  id,
  label,
  path: `/${id}`,
  reactComponent: () => null,
});

function mount(onClose = vi.fn(), run = vi.fn()) {
  render(
    <MemoryRouter>
      <CommandPalette
        open
        onClose={onClose}
        screens={[{ plugin: plugin("audit", "Audit trail"), group: "Overview" }]}
        actions={[{ id: "ping", label: "Ping the daemon", run }]}
      />
    </MemoryRouter>,
  );
  return { onClose, run };
}

describe("CommandPalette", () => {
  it("renders nothing while closed", () => {
    render(
      <MemoryRouter>
        <CommandPalette open={false} onClose={() => {}} screens={[]} actions={[]} />
      </MemoryRouter>,
    );
    expect(screen.queryByRole("dialog")).toBeNull();
  });

  it("is a labelled modal dialog holding a combobox that controls a listbox", () => {
    mount();
    const dialog = screen.getByRole("dialog", { name: "Command palette" });
    expect(dialog.getAttribute("aria-modal")).toBe("true");
    const input = screen.getByRole("combobox");
    const list = screen.getByRole("listbox", { name: "Results" });
    expect(input.getAttribute("aria-controls")).toBe(list.id);
    expect(input.getAttribute("aria-expanded")).toBe("true");
    expect(input.getAttribute("aria-autocomplete")).toBe("list");
    expect(document.activeElement).toBe(input);
    expect(screen.getAllByRole("option")).toHaveLength(2);
  });

  it("says when nothing matches, with no active option", () => {
    mount();
    const input = screen.getByRole("combobox");
    fireEvent.change(input, { target: { value: "zzzz" } });
    expect(screen.getByText(/Nothing matches “zzzz”/)).toBeTruthy();
    expect(screen.getByText("No results")).toBeTruthy();
    expect(input.hasAttribute("aria-activedescendant")).toBe(false);
    // Enter with nothing to run does nothing.
    fireEvent.keyDown(input, { key: "Enter" });
    expect(screen.getByRole("dialog")).toBeTruthy();
  });

  it("closes, then runs an action's callback", () => {
    const { onClose, run } = mount();
    fireEvent.change(screen.getByRole("combobox"), { target: { value: "ping" } });
    fireEvent.keyDown(screen.getByRole("combobox"), { key: "Enter" });
    expect(onClose).toHaveBeenCalled();
    expect(run).toHaveBeenCalledTimes(1);
  });

  it("highlights the option under the pointer", () => {
    mount();
    const [, second] = screen.getAllByRole("option");
    fireEvent.mouseMove(second!);
    expect(second!.getAttribute("aria-selected")).toBe("true");
  });
});
