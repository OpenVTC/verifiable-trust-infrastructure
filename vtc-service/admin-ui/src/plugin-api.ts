// Plugin API — the framework-agnostic boundary between the React
// shell and individual plugins.
//
// A plugin is a JS module that calls `registerPlugin(...)` (exposed
// on `window.VtcPluginApi`) at load time. The plugin describes:
//
// - `id` — globally unique, used in URLs and DOM ids.
// - `label` — human-readable, shown in the nav.
// - `path` — the route under `/admin/` where the plugin mounts.
// - `element` — the custom-element tag the shell renders. The
//   plugin is responsible for `customElements.define(...)` before
//   `registerPlugin` returns.
// - `icon` (optional) — SVG markup or a single emoji shown in the
//   nav. Falls back to the first letter of `label`.
// - `scopes` (optional) — admin / super-admin / etc. The shell
//   hides the nav entry when the signed-in operator lacks the
//   scope. Plugins should also enforce server-side; this is UX.
//
// Plugin discovery has two sources:
//
// 1. **Built-in plugins** (in `@/plugins/...`) are imported
//    statically from `src/plugins/index.ts::registerBuiltinPlugins`.
//    They ride along with the shell bundle.
//
// 2. **Third-party plugins** are listed in
//    `GET /admin/plugins.json` (served by the daemon) and
//    dynamically `import()`-ed at boot. The daemon serves their
//    files under `/admin/plugins/<id>/`. (Loader implementation
//    lands in a follow-up; the API + registry below already
//    supports it.)
//
// The plugin API surface is intentionally tiny so it can stay
// stable across shell rewrites. Adding capabilities (slot
// extension points, event bus, etc.) is additive — never break
// `registerPlugin`'s shape.

import type { ComponentType } from "react";

export interface PluginManifest {
  /** Stable, unique. Lowercase kebab-case. */
  readonly id: string;
  /** Human-readable nav label. */
  readonly label: string;
  /**
   * Route path under `/admin/`. Leading slash, no trailing.
   * Sub-routes are the plugin's concern (it owns the rest of the
   * URL via its own router).
   */
  readonly path: string;
  /**
   * The custom-element tag name the shell will render when the
   * plugin's route is active. The plugin module is responsible
   * for calling `customElements.define(elementTag, …)` before it
   * calls `registerPlugin`. Mutually exclusive with
   * `reactComponent`.
   */
  readonly elementTag?: string;
  /**
   * Optional icon shown in the nav. Strings (single emoji / inline
   * SVG markup) are the framework-agnostic surface for third-party
   * plugins. Built-in React plugins should prefer `iconComponent`,
   * which renders a proper lucide-react icon and inherits the shell's
   * 16px stroke-1.75 styling. Set at most one.
   *
   * **How the shell renders this.** A string starting with `<svg` is
   * rendered as `<img src="data:image/svg+xml,…">` — a picture, not
   * markup. Nothing inside it executes: scripts and `on*` handlers
   * never run in an `<img>`, which is what lets the shell accept SVG
   * from a plugin it does not control.
   *
   * The consequence for authors is that an `<img>` is a separate
   * document, so it inherits nothing from the shell: `currentColor`
   * and the 1.75 stroke width do **not** apply. Give the SVG its own
   * explicit colours and a `viewBox` sized against a 16px box, or
   * ship an `iconComponent` instead when the icon needs to follow the
   * theme.
   *
   * Any other string is rendered as text, so markup that is not an
   * SVG appears as its own characters rather than as elements.
   */
  readonly icon?: string;
  /**
   * Built-in plugins only: a React component rendered inside the
   * nav's icon slot. Typically a lucide-react icon. Takes precedence
   * over `icon` when both are set.
   */
  readonly iconComponent?: ComponentType<{
    "aria-hidden"?: boolean | "true" | "false";
  }>;
  /** UX-only scope hint. Server still enforces. */
  readonly scopes?: ReadonlyArray<"admin" | "super-admin">;
  /**
   * **Built-in plugins only**: a React component the shell renders
   * directly instead of a custom element. Lets first-party plugins
   * skip the web-component wrapper without breaking the
   * framework-agnostic boundary for third parties. Set EITHER
   * `elementTag` OR `reactComponent`, never both.
   */
  readonly reactComponent?: ComponentType;
}

// In-memory registry. Plugins register at module load; the shell
// reads on render. The registry is intentionally unsorted (insert
// order = nav order); plugins that care can `path` themselves
// into a particular slot.
const registry: PluginManifest[] = [];

// Subscribers notified when the registry changes. The shell uses
// this to rerender the nav when a third-party plugin lands after
// boot (operator added a new plugin and hit "Reload plugins" or the
// window-focus auto-refetch picked it up).
type ChangeListener = () => void;
const listeners = new Set<ChangeListener>();

function notify(): void {
  for (const l of listeners) {
    try {
      l();
    } catch (err) {
      console.error("[plugin-api] change listener threw:", err);
    }
  }
}

/**
 * Subscribe to registry changes. Returns an unsubscribe function.
 * Listeners are called synchronously after each successful
 * `registerPlugin`.
 */
export function subscribePlugins(listener: ChangeListener): () => void {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

/** Read-only snapshot of registered plugin IDs. */
export function getPluginIds(): ReadonlySet<string> {
  return new Set(registry.map((p) => p.id));
}

/**
 * Plugin registration entry point.
 *
 * Exposed on `window.VtcPluginApi.registerPlugin` so third-party
 * plugins loaded via `<script type="module">` can call it without
 * importing this module. Built-in plugins import this function
 * directly.
 */
export function registerPlugin(manifest: PluginManifest): void {
  if (manifest.elementTag && manifest.reactComponent) {
    throw new Error(
      `plugin '${manifest.id}' set both elementTag and reactComponent — pick one`,
    );
  }
  if (!manifest.elementTag && !manifest.reactComponent) {
    throw new Error(
      `plugin '${manifest.id}' set neither elementTag nor reactComponent`,
    );
  }
  if (registry.some((p) => p.id === manifest.id)) {
    throw new Error(`plugin '${manifest.id}' is already registered`);
  }
  registry.push(manifest);
  notify();
}

/** Snapshot of currently-registered plugins, in registration order. */
export function getPlugins(): ReadonlyArray<PluginManifest> {
  return [...registry];
}

/**
 * Resolve a plugin by its `path`. Used by the shell's router to
 * find which plugin owns a given URL.
 */
export function findPluginByPath(path: string): PluginManifest | undefined {
  return registry.find((p) => p.path === path);
}

// Expose the API on `window` so script-tag plugin loaders can use
// it without `import`. Type-safe surface for in-tree plugins (above);
// untyped surface here for third parties.
//
// Capability additions (the optional `toast` slot below, and any
// future additive surfaces) attach to the same object — third-party
// plugins probe with `if (window.VtcPluginApi?.toast)` so they keep
// working against shells that predate the capability.
import type { ToastApi } from "@/lib/toast";

declare global {
  interface Window {
    VtcPluginApi?: {
      registerPlugin: typeof registerPlugin;
      /** Toast surface, populated by `ToastProvider` at App mount. */
      toast?: ToastApi;
    };
  }
}
if (typeof window !== "undefined") {
  window.VtcPluginApi = { registerPlugin, ...(window.VtcPluginApi ?? {}) };
}
