import { fireEvent, render, screen } from "@testing-library/react";
import { useState } from "react";
import { describe, expect, it, vi } from "vitest";

import { Switch } from "@/components/Switch";

function Controlled({ onChange }: { onChange?: (v: boolean) => void }) {
  const [on, setOn] = useState(false);
  return (
    <Switch
      label="Show system events"
      description={on ? "On" : "Off"}
      checked={on}
      onChange={(e) => {
        setOn(e.target.checked);
        onChange?.(e.target.checked);
      }}
    />
  );
}

describe("Switch", () => {
  it("is announced as a switch named by its label, off then on", () => {
    const seen = vi.fn();
    render(<Controlled onChange={seen} />);
    const sw = screen.getByRole("switch", { name: /Show system events/ }) as HTMLInputElement;
    expect(sw.checked).toBe(false);
    expect(screen.getByRole("switch", { checked: false })).toBe(sw);

    fireEvent.click(sw);
    expect(sw.checked).toBe(true);
    expect(screen.getByRole("switch", { checked: true })).toBe(sw);
    expect(seen).toHaveBeenLastCalledWith(true);
    expect(screen.getByText("On")).toBeTruthy();
  });

  it("toggles from a click on its label text", () => {
    render(<Controlled />);
    fireEvent.click(screen.getByText("Show system events"));
    expect((screen.getByRole("switch") as HTMLInputElement).checked).toBe(true);
  });

  it("is a native checkbox underneath, so the keyboard and forms work unchanged", () => {
    render(<Controlled />);
    const sw = screen.getByRole("switch") as HTMLInputElement;
    expect(sw.tagName).toBe("INPUT");
    expect(sw.type).toBe("checkbox");
    // The drawn track is decoration.
    expect(sw.nextElementSibling?.getAttribute("aria-hidden")).toBe("true");
  });

  it("does nothing when disabled, and says so", () => {
    const changed = vi.fn();
    render(<Switch label="Locked" checked={false} disabled onChange={changed} />);
    const sw = screen.getByRole("switch", { name: "Locked" }) as HTMLInputElement;
    expect(sw.disabled).toBe(true);
    expect(sw.closest("label")!.classList.contains("switch--disabled")).toBe(true);
  });
});
