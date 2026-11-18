// The badge picture builder: what is chosen is what is drawn, the size each shape is
// drawn at, the name on a banner, and a drawing that fails.

import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { BUILDER_COLOURS, BadgeBuilder, bannerText, findIcons, iconLabel } from "./BadgeBuilder";
import { icons, tags } from "./badge-icons";

const SET = { icons, tags };

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

  it("finds any icon of the whole set by name, and draws the one chosen", async () => {
    const draw = vi.fn(async () => new Blob([], { type: "image/png" }));
    render(<BadgeBuilder name="Bug hunter" onUse={() => undefined} draw={draw} />);
    expect(screen.queryByLabelText("Bug")).toBeNull();
    fireEvent.change(screen.getByLabelText("Find an icon"), { target: { value: "bug" } });
    fireEvent.click(await screen.findByLabelText("Bug"));
    expect(art().querySelector("svg")?.getAttribute("class")).toContain("lucide-bug");
    expect(screen.getByText(/icons? match/)).toBeTruthy();
    // Clearing the search goes back to the icons offered first, keeping the choice.
    fireEvent.change(screen.getByLabelText("Find an icon"), { target: { value: "" } });
    expect(screen.getByLabelText("Tools")).toBeTruthy();
    expect(screen.getByText("Chosen: Bug. Search by name or meaning, or browse them all.")).toBeTruthy();
    expect(art().querySelector("svg")?.getAttribute("class")).toContain("lucide-bug");
  });

  it("says when nothing matches", async () => {
    render(<BadgeBuilder name="x" onUse={() => undefined} draw={async () => new Blob()} />);
    fireEvent.change(screen.getByLabelText("Find an icon"), { target: { value: "zzqx" } });
    expect(await screen.findByText("No icon matches “zzqx”. Try another word, such as what it means.")).toBeTruthy();
  });

  it("names lucide's icons in words, and caps a broad search", () => {
    expect(iconLabel("BadgeCheck")).toBe("Badge check");
    expect(iconLabel("AArrowDown")).toBe("A arrow down");
    expect(Object.keys(icons).length).toBeGreaterThan(1000);
    // Every word must be in the name; the offered names ("Tools") count too.
    expect(findIcons(SET, "tools").matches[0]?.name).toBe("Tools");
    // Icons named for every word come before those found through their tags.
    const named = (i: { name: string }) => /arrow/i.test(i.name) && /down/i.test(i.name);
    const arrowDown = findIcons(SET, "arrow down", Number.POSITIVE_INFINITY).matches;
    const firstTagged = arrowDown.findIndex((i) => !named(i));
    expect(arrowDown.slice(0, firstTagged === -1 ? undefined : firstTagged).length).toBeGreaterThan(0);
    if (firstTagged !== -1) expect(arrowDown.slice(firstTagged).some(named)).toBe(false);
    // lucide's own spelling, with hyphens, reads as words.
    expect(findIcons(SET, "bug-off").matches.map((i) => i.name)).toContain("Bug off");
    const broad = findIcons(SET, "a", 10);
    expect(broad.matches).toHaveLength(10);
    expect(broad.total).toBeGreaterThan(10);
    // Nothing typed: every icon, once.
    expect(findIcons(SET, "", Number.POSITIVE_INFINITY).total).toBe(Object.keys(icons).length);
  });

  it("names every icon once, so no two tiles share a name", () => {
    const names = findIcons(SET, "", Number.POSITIVE_INFINITY).matches.map((i) => i.name);
    expect(names).toHaveLength(Object.keys(icons).length);
    expect(new Set(names).size).toBe(names.length);
    // The offered open book and lucide's closed one are told apart.
    expect(names).toContain("Open book");
    expect(names).toContain("Book");
  });

  it("finds an icon by what it means, after those named for it", () => {
    // Every icon has its tags, keyed as lucide-react names it: lucide-react and
    // lucide-static are one release, so the two catalogues name the same icons.
    expect(Object.keys(tags).sort()).toEqual(Object.keys(icons).sort());
    expect(tags.Bug).toContain("insect");
    const insect = findIcons(SET, "insect").matches.map((i) => i.name);
    expect(insect).toContain("Bug");
    // "Trophy" is named for itself; the icons filed under "trophy" come after it.
    const trophy = findIcons(SET, "trophy").matches;
    expect(trophy[0]?.name).toBe("Trophy");
    // A word from the name and one from the tags together.
    expect(findIcons(SET, "bug insect").matches.map((i) => i.name)).toContain("Bug");
    expect(findIcons(SET, "prize").matches.map((i) => i.name)).toContain("Trophy");
  });

  it("browses every icon in a dialog, narrows it by meaning, and chooses one", async () => {
    render(<BadgeBuilder name="Bug hunter" onUse={() => undefined} draw={async () => new Blob()} />);
    const opener = screen.getByRole("button", { name: "Browse all icons" });
    fireEvent.click(opener);
    const dialog = await screen.findByRole("dialog", { name: "All icons" });
    expect(await screen.findByText(`All ${Object.keys(icons).length} icons. Type to narrow them, by name or by meaning.`)).toBeTruthy();
    expect(document.activeElement).toBe(screen.getByLabelText("Find among all icons"));
    expect(dialog.querySelectorAll("button[aria-pressed]").length).toBe(Object.keys(icons).length);
    fireEvent.change(screen.getByLabelText("Find among all icons"), { target: { value: "insect" } });
    const bug = await screen.findByRole("button", { name: "Bug" });
    expect(bug.getAttribute("title")).toContain("insect");
    fireEvent.click(bug);
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(art().querySelector("svg")?.getAttribute("class")).toContain("lucide-bug");
    expect(screen.getByText("Chosen: Bug. Search by name or meaning, or browse them all.")).toBeTruthy();
    expect(document.activeElement).toBe(opener);
    // Rendering all 1,544 tiles is slow in jsdom while the rest of the suite runs beside it.
  }, 30_000);

  it("closes the browser on Escape, keeping the choice", async () => {
    render(<BadgeBuilder name="x" onUse={() => undefined} draw={async () => new Blob()} />);
    fireEvent.click(screen.getByRole("button", { name: "Browse all icons" }));
    await screen.findByRole("dialog", { name: "All icons" });
    fireEvent.keyDown(window, { key: "Escape" });
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(screen.getByText("Chosen: Award. Search by name or meaning, or browse them all.")).toBeTruthy();
  });

  it("shortens a long name on a banner", () => {
    expect(bannerText("  Short  ")).toBe("Short");
    const long = bannerText("The longest-serving volunteer of the year");
    expect([...long]).toHaveLength(22);
    expect(long.endsWith("…")).toBe(true);
  });
});
