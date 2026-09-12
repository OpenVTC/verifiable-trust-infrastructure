import { render } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { PluginIcon } from "@/App";
import type { PluginManifest } from "@/plugin-api";

/** A third-party manifest whose only interesting member is the icon. */
function pluginWith(icon: string): PluginManifest {
  return {
    id: "third-party",
    label: "Third party",
    path: "/third-party",
    elementTag: "x-third-party",
    icon,
  };
}

/** Every `on*` attribute anywhere in the rendered output. */
function eventHandlerAttributes(root: HTMLElement): string[] {
  return Array.from(root.querySelectorAll("*")).flatMap((el) =>
    Array.from(el.attributes)
      .map((a) => a.name)
      .filter((name) => name.startsWith("on")),
  );
}

describe("PluginIcon", () => {
  it("renders a plugin's SVG icon as an image, so nothing inside it can run", () => {
    // The icon string is attacker-shaped: `script-src 'self'` would stop a
    // `<script>` here, but it says nothing about an inline handler, which is
    // why injecting this as markup was the finding.
    const { container } = render(
      <PluginIcon
        plugin={pluginWith(
          '<svg onload="globalThis.__pluginIconRan = true"><rect /></svg>',
        )}
      />,
    );

    const img = container.querySelector("img");
    expect(img).not.toBeNull();
    expect(img?.getAttribute("src")).toMatch(
      /^data:image\/svg\+xml;charset=utf-8,/,
    );
    // The decisive assertion: the SVG is not in the document as DOM, so
    // there is no element for the handler to be attached to.
    expect(container.querySelector("svg")).toBeNull();
    expect(eventHandlerAttributes(container)).toEqual([]);
    expect(
      (globalThis as Record<string, unknown>).__pluginIconRan,
    ).toBeUndefined();
  });

  it("keeps the icon's bytes intact, so a legitimate SVG still draws", () => {
    // Rendering it safely is only half the requirement; a plugin's icon still
    // has to arrive unmangled.
    const icon = '<svg viewBox="0 0 16 16"><circle cx="8" cy="8" r="7" /></svg>';
    const { container } = render(<PluginIcon plugin={pluginWith(icon)} />);

    const src = container.querySelector("img")?.getAttribute("src") ?? "";
    const payload = src.replace("data:image/svg+xml;charset=utf-8,", "");
    expect(decodeURIComponent(payload)).toBe(icon);
  });

  it("renders markup that is not an SVG as text", () => {
    const icon = '<img src=x onerror="globalThis.__pluginIconRan = true">';
    const { container } = render(<PluginIcon plugin={pluginWith(icon)} />);

    // No element of any kind — React escaped the string.
    expect(container.querySelector("img")).toBeNull();
    expect(container.textContent).toBe(icon);
    expect(
      (globalThis as Record<string, unknown>).__pluginIconRan,
    ).toBeUndefined();
  });

  it("renders a single glyph as itself", () => {
    const { container } = render(<PluginIcon plugin={pluginWith("★")} />);

    expect(container.querySelector("img")).toBeNull();
    expect(container.textContent).toBe("★");
  });

  it("falls back to the label's first letter when there is no icon", () => {
    const { container } = render(
      <PluginIcon plugin={{ id: "vetting", label: "vetting", path: "/vetting" }} />,
    );

    expect(container.textContent).toBe("V");
  });
});
