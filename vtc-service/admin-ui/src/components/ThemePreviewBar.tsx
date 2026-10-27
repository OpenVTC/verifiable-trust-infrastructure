// The bar across the top of a theme-preview tab, in the console and the member
// portal alike.
//
// It is drawn in its own shadow tree with literal colours — no token, no class
// the page's stylesheets know — because it is the one thing in a preview the
// theme being previewed must not be able to restyle: the notice that nothing
// here is saved (`vtc/community/theme/show/0.1`, client items 2 and 4).
// Custom properties inherit into a shadow tree, so it reads none.

import { useEffect, useState, type ReactNode } from "react";
import { createPortal } from "react-dom";

import { exitThemePreview, PREVIEW_NOOP_EVENT } from "@/lib/theme-preview";

const SHEET = `
  :host { all: initial; }
  .bar {
    position: fixed; inset: 0 0 auto 0; z-index: 2147483647;
    display: flex; align-items: center; gap: 12px; flex-wrap: wrap;
    padding: 8px 16px; box-sizing: border-box; min-height: 40px;
    background: #1a1a1a; color: #ffffff; border-bottom: 2px solid #ffcc00;
    font: 500 13px/1.4 system-ui, -apple-system, "Segoe UI", sans-serif;
    letter-spacing: normal; text-transform: none;
  }
  .tag {
    background: #ffcc00; color: #1a1a1a; border-radius: 4px; padding: 2px 8px;
    font-weight: 700; font-size: 11px; text-transform: uppercase; letter-spacing: 0.06em;
  }
  .grow { flex: 1 1 auto; }
  .flash { color: #ffcc00; font-weight: 600; }
  button {
    font: inherit; color: #ffffff; background: #333333; border: 1px solid #666666;
    border-radius: 4px; padding: 4px 10px; cursor: pointer;
  }
  button:hover { background: #444444; }
  button[aria-pressed="true"] { background: #ffffff; color: #1a1a1a; border-color: #ffffff; }
`;

/** The spacer height the page keeps clear under the fixed bar. */
const BAR_SPACE = "44px";

export function ThemePreviewBar({ controls }: { controls?: ReactNode }) {
  const [root, setRoot] = useState<ShadowRoot | null>(null);
  const [flash, setFlash] = useState(false);

  useEffect(() => {
    const host = document.createElement("div");
    host.setAttribute("data-theme-preview-bar", "");
    document.body.prepend(host);
    const shadow = host.attachShadow({ mode: "open" });
    const style = document.createElement("style");
    style.textContent = SHEET;
    shadow.appendChild(style);
    // Keep the page's own content clear of the bar.
    const previous = document.body.style.paddingTop;
    document.body.style.paddingTop = BAR_SPACE;
    setRoot(shadow);
    return () => {
      document.body.style.paddingTop = previous;
      host.remove();
    };
  }, []);

  useEffect(() => {
    let timer: ReturnType<typeof setTimeout> | undefined;
    const on = () => {
      setFlash(true);
      clearTimeout(timer);
      timer = setTimeout(() => setFlash(false), 2500);
    };
    window.addEventListener(PREVIEW_NOOP_EVENT, on);
    return () => {
      window.removeEventListener(PREVIEW_NOOP_EVENT, on);
      clearTimeout(timer);
    };
  }, []);

  if (!root) return null;
  return createPortal(
    <div className="bar" role="status">
      <span className="tag">Theme preview</span>
      <span className="grow">
        {flash ? (
          <span className="flash">Nothing was changed — writes are switched off in a preview.</span>
        ) : (
          "Nothing you do here is saved or sent to the community."
        )}
      </span>
      {controls}
      <button type="button" onClick={exitThemePreview}>
        Exit preview
      </button>
    </div>,
    root,
  );
}
