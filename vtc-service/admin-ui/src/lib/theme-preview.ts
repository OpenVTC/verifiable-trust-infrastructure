// Theme preview: the console or the member portal drawn with a candidate
// theme, in which nothing an administrator does reaches the community
// (`vtc/community/theme/update/0.1`, client item 1).
//
// The editor writes the candidate to localStorage and opens the surface with
// `?theme-preview=1` in a new tab. The flag is held in that tab's
// sessionStorage, so navigation inside the app keeps it and no other tab picks
// it up. The candidate follows the editor live through the `storage` event.
//
// What "nothing reaches the community" means, at the two seams every console
// request leaves through (`lib/api.ts`): a plain request goes only if it is a
// GET, and a Trust Task document only if its task is a read — by the last
// segment of its slug, against a short allow-list. Anything else is refused
// here, before it is sent, with `PreviewNoopError`. Default-deny, so a task
// this file has never heard of is refused, not sent.
//
// Dependency-free: the member portal imports it too.

import { applyCommunityTheme } from "./community-theme";

const FLAG_KEY = "vtc-theme-preview";
const QUERY_PARAM = "theme-preview";
/** The candidate stylesheet the editor hands the preview tabs. */
export const PREVIEW_CSS_KEY = "vtc-theme-preview-css";

/** The message every refused write shows. */
export const PREVIEW_NOOP_MESSAGE = "Theme preview — nothing was changed. Writes are switched off here.";

export class PreviewNoopError extends Error {
  readonly status = 0;
  constructor(readonly what: string) {
    super(PREVIEW_NOOP_MESSAGE);
    this.name = "PreviewNoopError";
  }
}

let active: boolean | null = null;

/** Is this tab a theme preview? Decided once per load. */
export function isThemePreview(): boolean {
  if (active !== null) return active;
  active = false;
  try {
    const params = new URLSearchParams(window.location.search);
    if (params.get(QUERY_PARAM) === "1") {
      window.sessionStorage.setItem(FLAG_KEY, "1");
      // Drop the parameter from the address bar; the flag carries on.
      params.delete(QUERY_PARAM);
      const query = params.toString();
      window.history.replaceState(
        window.history.state,
        "",
        `${window.location.pathname}${query ? `?${query}` : ""}${window.location.hash}`,
      );
    }
    active = window.sessionStorage.getItem(FLAG_KEY) === "1";
  } catch {
    active = false;
  }
  return active;
}

/** Leave preview in this tab. The page reloads drawn as normal. */
export function exitThemePreview(): void {
  try {
    window.sessionStorage.removeItem(FLAG_KEY);
  } catch {
    /* nothing held */
  }
  window.location.reload();
}

/** The candidate stylesheet, or the empty string. */
export function previewStylesheet(): string {
  try {
    return window.localStorage.getItem(PREVIEW_CSS_KEY) ?? "";
  } catch {
    return "";
  }
}

/** Hand `css` to every open preview tab (and to the next one opened). */
export function setPreviewStylesheet(css: string): void {
  try {
    window.localStorage.setItem(PREVIEW_CSS_KEY, css);
  } catch {
    /* a private window: the preview opens with the built-in look */
  }
}

/**
 * In a preview tab, draw the candidate and follow the editor's changes.
 * A no-op anywhere else.
 */
export function startThemePreview(): void {
  if (!isThemePreview()) return;
  applyCommunityTheme(previewStylesheet());
  window.addEventListener("storage", (e) => {
    if (e.key === PREVIEW_CSS_KEY || e.key === null) applyCommunityTheme(previewStylesheet());
  });
}

/** The last slug segments of tasks that change nothing. */
const READ_VERBS = new Set([
  "list",
  "show",
  "get",
  "view",
  "manifest",
  "usage",
  "graph",
  "diagnostics",
  "whoami",
  "admin-list",
  "subscribe",
  "trust-task-discovery",
]);

/** Is `typeUri` a task that changes nothing? */
export function isReadTask(typeUri: string): boolean {
  const m = /^https:\/\/trusttasks\.org\/spec\/(.+)\/\d+\.\d+(#.*)?$/.exec(typeUri);
  if (!m) return false;
  const last = m[1]!.split("/").pop()!;
  return READ_VERBS.has(last);
}

/** Dispatched on `window` each time a preview refuses a write; the preview bar shows it. */
export const PREVIEW_NOOP_EVENT = "vtc-theme-preview-noop";

function refuse(what: string): never {
  try {
    window.dispatchEvent(new CustomEvent(PREVIEW_NOOP_EVENT, { detail: { what } }));
  } catch {
    /* no DOM */
  }
  throw new PreviewNoopError(what);
}

/** Refuse a Trust Task document a preview must not send. */
export function guardPreviewDocument(typeUri: string): void {
  if (isThemePreview() && !isReadTask(typeUri)) refuse(typeUri);
}

/** Refuse a plain request a preview must not send. */
export function guardPreviewRequest(method: string, path: string): void {
  const m = method.toUpperCase();
  if (isThemePreview() && m !== "GET" && m !== "HEAD") refuse(`${m} ${path}`);
}

/** For tests: forget the decision so the next call re-reads the flag. */
export function resetThemePreviewForTests(): void {
  active = null;
}
