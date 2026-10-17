// A community theme (`vtc/community/theme/*`): one stylesheet in the theme
// profile, drawn over the built-in look of the console and the member portal.
//
// Every stylesheet goes through `checkThemeStylesheet` before it is drawn
// (`theme/show` client item 1) — a built-in, an upload and a preview candidate
// alike — and nothing of a stylesheet that fails is applied.
//
// Dependency-free, like `theme-profile.ts`: the member portal imports it.

import { checkThemeStylesheet, type ProfileCheck } from "./theme-profile";
import contrast from "@/styles/themes/contrast.css?raw";
import forest from "@/styles/themes/forest.css?raw";
import ocean from "@/styles/themes/ocean.css?raw";
import slate from "@/styles/themes/slate.css?raw";
import sunset from "@/styles/themes/sunset.css?raw";

export interface BuiltinTheme {
  id: string;
  name: string;
  /** Swatches for the picker: ground, surface, brand. */
  swatches: [string, string, string];
  stylesheet: string;
}

/** The themes the console ships. `default` is no stylesheet at all. */
export const BUILTIN_THEMES: readonly BuiltinTheme[] = [
  { id: "default", name: "Default", swatches: ["#fafaff", "#ffffff", "#5b5bd6"], stylesheet: "" },
  { id: "forest", name: "Forest", swatches: ["#f8f7f2", "#ffffff", "#1f8a63"], stylesheet: forest },
  { id: "ocean", name: "Ocean", swatches: ["#f6fafd", "#ffffff", "#1673c4"], stylesheet: ocean },
  { id: "slate", name: "Slate", swatches: ["#f8f9fa", "#ffffff", "#4b6283"], stylesheet: slate },
  { id: "sunset", name: "Sunset", swatches: ["#fffaf6", "#ffffff", "#dc552a"], stylesheet: sunset },
  { id: "contrast", name: "High contrast", swatches: ["#ffffff", "#000000", "#0044cc"], stylesheet: contrast },
];

const STYLE_ID = "vtc-community-theme";

/**
 * Draw `css` over the page's own styles, after checking it. A stylesheet that
 * fails the profile removes whatever theme was drawn: the page falls back to
 * its built-in look rather than half of a theme. Returns the check.
 */
export function applyCommunityTheme(css: string): ProfileCheck {
  const check = checkThemeStylesheet(css);
  if (typeof document === "undefined") return check;
  const existing = document.getElementById(STYLE_ID);
  if (!check.ok || check.stylesheet.trim() === "") {
    existing?.remove();
    document.documentElement.removeAttribute("data-community-theme");
    return check;
  }
  const style = existing ?? document.createElement("style");
  style.id = STYLE_ID;
  // textContent, never innerHTML: the profile already refuses `<`, and this
  // keeps the stylesheet text even if it did not.
  style.textContent = check.stylesheet;
  // Last in <head>, so a theme rule outranks the bundle's rule of equal
  // specificity, and nothing else.
  document.head.appendChild(style);
  document.documentElement.setAttribute("data-community-theme", "");
  return check;
}

/** Offer `css` to the browser as a file to save. */
export function downloadStylesheet(css: string, filename = "community-theme.css"): void {
  const url = URL.createObjectURL(new Blob([css], { type: "text/css" }));
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}
