// Theme strategy: the CSS uses `light-dark()` so the default mode
// follows the OS via `color-scheme: light dark`. Operators who want
// to pin a specific mode flip `data-theme` on <html>, which sets
// `color-scheme` to a single value and lets the cascade resolve.
//
// Preference persists in localStorage under `vtc-admin-theme`. The
// values are intentionally narrow ("auto" / "light" / "dark") so we
// can switch on them without normalisation.
//
// One key for the community's three surfaces: the console, the member portal
// (which imports this module) and the home page (`website-default/theme.js`,
// which reads and writes the same key). They share an origin, so a choice
// made on one is the choice on all three. The key keeps its original name so
// a choice made before the portal and home page had a switcher carries over.
//
// "auto" stores nothing: it is the absence of a choice, and the page follows
// `prefers-color-scheme` live, with no listener needed, because that is what
// `color-scheme: light dark` already does.

export type ThemePreference = "auto" | "light" | "dark";

export const THEME_STORAGE_KEY = "vtc-admin-theme";
const STORAGE_KEY = THEME_STORAGE_KEY;
type Listener = (pref: ThemePreference) => void;
const listeners = new Set<Listener>();

export function isThemePreference(v: unknown): v is ThemePreference {
  return v === "auto" || v === "light" || v === "dark";
}

export function getStoredTheme(): ThemePreference {
  try {
    const v = window.localStorage.getItem(STORAGE_KEY);
    return isThemePreference(v) ? v : "auto";
  } catch {
    return "auto";
  }
}

export function applyStoredTheme(): void {
  if (typeof document === "undefined") return;
  apply(getStoredTheme());
  watchOtherTabs();
}

export function setTheme(pref: ThemePreference): void {
  try {
    if (pref === "auto") window.localStorage.removeItem(STORAGE_KEY);
    else window.localStorage.setItem(STORAGE_KEY, pref);
  } catch {
    /* fall through — preference still applies for this session */
  }
  apply(pref);
  notify(pref);
}

export function subscribeTheme(listener: Listener): () => void {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

/** The theme actually showing: the pinned one, or the system's. */
export function effectiveTheme(pref: ThemePreference = getStoredTheme()): "light" | "dark" {
  if (pref !== "auto") return pref;
  try {
    return window.matchMedia?.("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  } catch {
    return "light";
  }
}

function notify(pref: ThemePreference): void {
  for (const l of listeners) l(pref);
}

function apply(pref: ThemePreference): void {
  const root = document.documentElement;
  if (pref === "auto") {
    root.removeAttribute("data-theme");
  } else {
    root.setAttribute("data-theme", pref);
  }
}

// A choice made in another tab (or on the home page, open beside the console)
// arrives as a `storage` event; follow it so two open surfaces never disagree.
let watching = false;
function watchOtherTabs(): void {
  if (watching || typeof window === "undefined") return;
  watching = true;
  window.addEventListener("storage", (e) => {
    if (e.key !== STORAGE_KEY && e.key !== null) return;
    const pref = getStoredTheme();
    apply(pref);
    notify(pref);
  });
}
