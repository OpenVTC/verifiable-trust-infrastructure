// The isolation a protected surface rests on (`vtc/community/theme/show/0.1`,
// client item 2): its children are in a shadow tree, the theme stylesheet is
// not in it, and the default tokens are declared inside it.

import { render, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { Protected, rescopeRoot, setProtectedIsolationForTests } from "./Protected";
import { applyCommunityTheme } from "@/lib/community-theme";

describe("rescopeRoot", () => {
  it.each([
    [":root { --a: 1; }", ".protected-root { --a: 1; }"],
    ["@media (prefers-color-scheme: dark) { :root { --a: 1; } }", "@media (prefers-color-scheme: dark) { .protected-root { --a: 1; } }"],
    [":root[data-community-accent] { --b: 2; }", ".protected-root[data-community-accent] { --b: 2; }"],
    ["a, :root { color: red; }", "a, .protected-root { color: red; }"],
  ])("%s", (input, expected) => expect(rescopeRoot(input)).toBe(expected));

  it("leaves names that only contain root alone", () => {
    expect(rescopeRoot(".rooted :root-ish { x: 1; }")).toBe(".rooted :root-ish { x: 1; }");
  });
});

describe("Protected", () => {
  beforeEach(() => {
    const bundle = document.createElement("style");
    bundle.id = "test-bundle";
    bundle.textContent = ":root { --text: #0f0f17; } .btn { color: var(--text); }";
    document.head.appendChild(bundle);
    applyCommunityTheme(":root { --text: #ff00ff; } .btn { color: #ff00ff; }");
    setProtectedIsolationForTests(true);
  });
  afterEach(() => {
    setProtectedIsolationForTests(false);
    applyCommunityTheme("");
    document.getElementById("test-bundle")?.remove();
  });

  it("renders its children in a shadow tree carrying the page's CSS but not the theme", () => {
    const { container } = render(
      <Protected>
        <button className="btn">Decline</button>
      </Protected>,
    );
    const host = container.querySelector("[data-protected]")!;
    expect(host.shadowRoot).not.toBeNull();
    // Not in the light DOM, where the theme's selectors reach.
    expect(container.querySelector("button")).toBeNull();
    const button = host.shadowRoot!.querySelector("button")!;
    expect(button.textContent).toBe("Decline");
    expect(button.closest(".protected-root")).not.toBeNull();

    const css = host.shadowRoot!.querySelector("style")!.textContent!;
    // The browser serialises each rule its own way; match on the content.
    expect(css).toMatch(/\.protected-root\s*\{\s*--text:\s*#0f0f17;?\s*\}/);
    expect(css).not.toContain("#ff00ff");
    expect(css).toMatch(/\.protected-root\s*\{\s*all: initial;/);
  });

  it("renders inline when already inside a protected surface", () => {
    const { container } = render(
      <Protected>
        <Protected>
          <span>inner</span>
        </Protected>
      </Protected>,
    );
    const outer = container.querySelector("[data-protected]")!;
    expect(outer.shadowRoot!.querySelector("[data-protected]")).toBeNull();
    expect(outer.shadowRoot!.querySelector("span")!.textContent).toBe("inner");
  });

  // The production build lowers `light-dark()` into toggles only
  // `[data-theme]` flips, and the re-scoped `:root` rule resets them inside
  // the isolation: without the attribute there, a pinned Dark on a light OS
  // drew every protected surface light.
  it("carries the pinned light / dark onto its root, and follows a change", async () => {
    document.documentElement.setAttribute("data-theme", "dark");
    try {
      const { container } = render(
        <Protected>
          <span>inner</span>
        </Protected>,
      );
      const inner = container.querySelector("[data-protected]")!.shadowRoot!.querySelector(".protected-root")!;
      expect(inner.getAttribute("data-theme")).toBe("dark");

      document.documentElement.setAttribute("data-theme", "light");
      await waitFor(() => expect(inner.getAttribute("data-theme")).toBe("light"));

      // "Match system" removes the attribute; so does the isolation.
      document.documentElement.removeAttribute("data-theme");
      await waitFor(() => expect(inner.hasAttribute("data-theme")).toBe(false));
    } finally {
      document.documentElement.removeAttribute("data-theme");
    }
  });

  // A protected card is the one thing on a themed page not in the theme's
  // colours; it says why, from inside the isolation, only while a theme is drawn.
  it("marks a protected card as a protected area while a community theme is drawn", async () => {
    const { container } = render(
      <Protected ground="card">
        <section className="card">Decide</section>
      </Protected>,
    );
    const shadow = container.querySelector("[data-protected]")!.shadowRoot!;
    const inner = shadow.querySelector(".protected-root")!;
    // beforeEach drew a theme.
    expect(inner.hasAttribute("data-community-theme")).toBe(true);
    const css = shadow.querySelector("style")!.textContent!;
    expect(css).toContain('[data-ground="card"][data-community-theme]::before');
    expect(css).toContain("Protected area");

    applyCommunityTheme("");
    await waitFor(() => expect(inner.hasAttribute("data-community-theme")).toBe(false));
  });
});
