// A surface the community theme cannot reach (`vtc/community/theme/show/0.1`,
// client item 2): where an administrator or member decides, approves,
// declines, consents, signs or is warned.
//
// Isolation by structure, not by selector. The children render in a shadow
// tree, which no document stylesheet's selectors enter, carrying:
//
// - a copy of the page's own stylesheets — everything but the theme, with each
//   `:root` rule re-scoped to the isolation's root element, so the default
//   tokens are declared *inside* the shadow tree. Custom properties inherit
//   into a shadow tree; declaring every token again on the inner root is what
//   stops a theme's `--text: transparent` reaching through (the spec's
//   "declares every custom property it reads inside the isolation");
// - `all: initial` on that root, so no inheritable property a theme set on an
//   ancestor (`color`, `font-family`, `letter-spacing`, …) arrives either.
//   `color-scheme` alone is taken from outside: a theme cannot set it, and it
//   is how the page's own light / dark choice reaches `light-dark()`.
//
// React portals into the shadow root, so state, context and events behave as
// for any other child.
//
// Testing Library does not look inside shadow roots, so the test setup turns
// isolation off and every existing test sees the children inline; this
// component's own test turns it back on.

import { createContext, useContext, useLayoutEffect, useRef, useState, type ReactNode } from "react";
import { createPortal } from "react-dom";

const THEME_STYLE_ID = "vtc-community-theme";
const ROOT_CLASS = "protected-root";

let isolate = true;

/** For tests: render children inline instead of in a shadow tree. */
export function setProtectedIsolationForTests(on: boolean): void {
  isolate = on;
  cachedSheet = null;
}

const InsideProtected = createContext(false);

let cachedSheet: string | null = null;

/**
 * The page's own CSS, theme excluded, with `:root` re-scoped. Built once: the
 * bundle's stylesheets do not change after load, and the theme is the one
 * stylesheet left out by construction.
 */
function isolatedCss(): string {
  if (cachedSheet !== null) return cachedSheet;
  const parts: string[] = [];
  // By element rather than `document.styleSheets`, so the theme's own
  // `<style>` is left out by its id however the sheet reports its owner.
  for (const el of Array.from(document.querySelectorAll("style, link[rel~='stylesheet']"))) {
    if (el.id === THEME_STYLE_ID) continue;
    const sheet = (el as HTMLStyleElement | HTMLLinkElement).sheet;
    if (!sheet) continue;
    let rules: CSSRuleList;
    try {
      rules = sheet.cssRules;
    } catch {
      continue; // not readable; the bundle is same-origin, so this is not ours
    }
    for (const rule of Array.from(rules)) {
      // Font faces are document-wide already.
      if (rule.constructor.name === "CSSFontFaceRule" || rule.cssText.startsWith("@font-face")) continue;
      parts.push(rescopeRoot(rule.cssText));
    }
  }
  parts.push(`
    .${ROOT_CLASS} {
      all: initial;
      display: block;
      color-scheme: inherit;
      color: var(--text);
      font-family: var(--font-sans);
      font-size: var(--text-base);
      line-height: calc(var(--text-base-leading) / var(--text-base));
      letter-spacing: var(--tracking-tight);
      -webkit-font-smoothing: antialiased;
    }
    .${ROOT_CLASS}[data-ground="surface"] { background-color: var(--bg-elev); }
    .${ROOT_CLASS}[data-ground="page"] { background-color: var(--bg); }
    .${ROOT_CLASS}[data-ground="none"] { display: contents; }
  `);
  cachedSheet = parts.join("\n");
  return cachedSheet;
}

/**
 * The focused element as `node`'s own root sees it. Inside a shadow tree
 * `document.activeElement` is the host, never the focused button, so a focus
 * trap must ask the shadow root.
 */
export function activeElementOf(node: Node): Element | null {
  const root = node.getRootNode() as Document | ShadowRoot;
  return root.activeElement ?? document.activeElement;
}

/** `:root` → the isolation's root, in a rule's selector text. */
export function rescopeRoot(cssText: string): string {
  return cssText.replace(/(^|[\s,{(>+~])(:root)(?![\w-])/g, `$1.${ROOT_CLASS}`);
}

/**
 * What a protected surface is drawn on.
 *
 * The ground behind a surface belongs to its ancestors, which the theme
 * styles: text isolated in its default colour is still hidden on a ground the
 * theme painted that colour. So a protected surface paints its own —
 * `surface` (a card's `--bg-elev`, the default) or `page` (`--bg`). `none` is
 * only for a surface that paints an opaque ground of its own over everything
 * (the modal dialogs).
 */
export type ProtectedGround = "surface" | "page" | "none";

/**
 * Render `children` out of the community theme's reach. The host is
 * `display: contents`, so it does not break the flex or grid row it sits in.
 * Nested inside another `Protected`, it renders inline: already isolated.
 */
export function Protected({
  children,
  ground = "surface",
}: {
  children: ReactNode;
  ground?: ProtectedGround;
}) {
  const nested = useContext(InsideProtected);
  const host = useRef<HTMLDivElement>(null);
  const [root, setRoot] = useState<HTMLElement | null>(null);

  useLayoutEffect(() => {
    if (nested || !isolate || !host.current) return;
    const shadow = host.current.shadowRoot ?? host.current.attachShadow({ mode: "open" });
    const style = document.createElement("style");
    style.textContent = isolatedCss();
    const inner = document.createElement("div");
    // The body's classes too: a surface's own stylesheet may be scoped under
    // one (the member portal's `.vtc-signin`), and no ancestor of a shadow
    // tree's content matches a selector inside it.
    inner.className = `${ROOT_CLASS} ${document.body.className}`.trim();
    inner.dataset.ground = ground;
    shadow.replaceChildren(style, inner);
    setRoot(inner);
    return () => {
      shadow.replaceChildren();
      setRoot(null);
    };
  }, [nested, ground]);

  if (nested || !isolate) return <>{children}</>;
  return (
    <div ref={host} data-protected="" style={{ display: "contents" }}>
      {root &&
        createPortal(<InsideProtected.Provider value>{children}</InsideProtected.Provider>, root)}
    </div>
  );
}
