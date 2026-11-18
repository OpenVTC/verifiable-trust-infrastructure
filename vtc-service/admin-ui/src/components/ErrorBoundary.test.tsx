import { render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { ErrorBoundary } from "@/components/ErrorBoundary";

function Bomb({ explode }: { explode: boolean }) {
  if (explode) throw new Error("rows is undefined");
  return <p>Screen content</p>;
}

describe("ErrorBoundary (#2605)", () => {
  beforeEach(() => {
    // React and the boundary both report the caught error; keep the run quiet.
    vi.spyOn(console, "error").mockImplementation(() => {});
  });
  afterEach(() => vi.restoreAllMocks());

  it("draws an error card with the message and a reload button instead of blanking", () => {
    render(
      <div>
        <nav>Sidebar</nav>
        <ErrorBoundary what="This screen">
          <Bomb explode />
        </ErrorBoundary>
      </div>,
    );
    const alert = screen.getByRole("alert");
    expect(alert.textContent).toContain("This screen couldn't be shown");
    expect(alert.textContent).toContain("rows is undefined");
    expect(screen.getByRole("button", { name: "Reload this page" })).toBeTruthy();
    // What sits outside the boundary survives.
    expect(screen.getByText("Sidebar")).toBeTruthy();
  });

  it("recovers when its reset key changes", () => {
    const { rerender } = render(
      <ErrorBoundary resetKey="/boards/a">
        <Bomb explode />
      </ErrorBoundary>,
    );
    expect(screen.getByRole("alert")).toBeTruthy();
    rerender(
      <ErrorBoundary resetKey="/groups">
        <Bomb explode={false} />
      </ErrorBoundary>,
    );
    expect(screen.queryByRole("alert")).toBeNull();
    expect(screen.getByText("Screen content")).toBeTruthy();
  });

  it("draws the portal's alert in the alert variant", () => {
    render(
      <ErrorBoundary variant="alert">
        <Bomb explode />
      </ErrorBoundary>,
    );
    expect(screen.getByRole("alert").className).toBe("alert");
  });
});
