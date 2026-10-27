// "Custom theme" in the console's top bar while a community theme is drawn
// (`vtc/community/theme/show/0.1`, client item 4): shown where the theme
// cannot reach, so a theme cannot hide that it is in force.

import { useEffect, useState } from "react";

import { Protected } from "@/components/Protected";

function themed(): boolean {
  return document.documentElement.hasAttribute("data-community-theme");
}

export function CustomThemeMarker() {
  const [on, setOn] = useState(themed);

  useEffect(() => {
    const observer = new MutationObserver(() => setOn(themed()));
    observer.observe(document.documentElement, {
      attributes: true,
      attributeFilter: ["data-community-theme"],
    });
    return () => observer.disconnect();
  }, []);

  if (!on) return null;
  return (
    // `none` keeps the top bar's row intact; the chip paints its own opaque
    // ground instead, from the isolation's default tokens.
    <Protected ground="none">
      <span
        className="chip"
        style={{ backgroundColor: "var(--bg-elev)", margin: 0 }}
        title="This community draws its pages with a custom theme. Approvals, confirmations and warnings always use the standard look."
      >
        Custom theme
      </span>
    </Protected>
  );
}
