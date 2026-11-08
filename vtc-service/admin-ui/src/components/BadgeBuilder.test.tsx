// The badge picture builder: what is chosen is what is drawn, the size each shape is
// drawn at, the name on a banner, and a drawing that fails.

import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { BUILDER_COLOURS, BadgeBuilder, bannerText } from "./BadgeBuilder";

function art(): SVGSVGElement {
  return screen.getByRole("img", { name: /^Preview/ }) as unknown as SVGSVGElement;
}

describe("the badge picture builder", () => {
  it("draws a banner with the name at 1024 wide, in the colour and icon chosen", async () => {
    const png = new Blob([new Uint8Array([137, 80, 78, 71])], { type: "image/png" });
    const draw = vi.fn(async () => png);
    const onUse = vi.fn();
    render(<BadgeBuilder name="Workshop host" onUse={onUse} draw={draw} />);
    expect(art().getAttribute("viewBox")).toBe("0 0 300 100");
    expect(art().textContent).toContain("Workshop host");
    fireEvent.click(screen.getByLabelText("Teal"));
    fireEvent.click(screen.getByLabelText("Trophy"));
    expect(art().querySelector("rect")?.getAttribute("fill")).toBe(BUILDER_COLOURS[1].value);
    expect(art().querySelector("svg")?.getAttribute("class")).toContain("trophy");
    fireEvent.click(screen.getByRole("button", { name: "Use this picture" }));
    await waitFor(() => expect(onUse).toHaveBeenCalledWith(png));
    expect(draw).toHaveBeenCalledWith(art(), 1024, 341);
  });

  it("draws a square without the name at 512 by 512", async () => {
    const draw = vi.fn(async () => new Blob([], { type: "image/png" }));
    render(<BadgeBuilder name="Workshop host" onUse={() => undefined} draw={draw} />);
    fireEvent.click(screen.getByLabelText("Square"));
    expect(art().getAttribute("viewBox")).toBe("0 0 120 120");
    expect(art().textContent).not.toContain("Workshop host");
    fireEvent.click(screen.getByRole("button", { name: "Use this picture" }));
    await waitFor(() => expect(draw).toHaveBeenCalledWith(art(), 512, 512));
  });

  it("says why when the picture can't be drawn, and hands nothing on", async () => {
    const onUse = vi.fn();
    render(
      <BadgeBuilder
        name="x"
        onUse={onUse}
        draw={async () => {
          throw new Error("This browser can't draw the picture.");
        }}
      />,
    );
    fireEvent.click(screen.getByRole("button", { name: "Use this picture" }));
    expect((await screen.findByRole("alert")).textContent).toBe("This browser can't draw the picture.");
    expect(onUse).not.toHaveBeenCalled();
  });

  it("asks for a name before a banner can show one", () => {
    render(<BadgeBuilder name="  " onUse={() => undefined} draw={async () => new Blob()} />);
    expect(screen.getByText("Give the badge a name to show it on the banner.")).toBeTruthy();
  });

  it("shortens a long name on a banner", () => {
    expect(bannerText("  Short  ")).toBe("Short");
    const long = bannerText("The longest-serving volunteer of the year");
    expect([...long]).toHaveLength(22);
    expect(long.endsWith("…")).toBe(true);
  });
});
