# Admin UX plugins — third-party authoring guide

The VTC admin SPA at `/admin/` ships with a built-in set of plugins
(dashboard, members, ACL, join requests, profile, policies, my
passkeys, sessions, audit trail). Operators can also drop their
own plugins into the daemon's configured `admin_ui.plugin_dir` and
they appear in the nav alongside the built-ins — no rebuild of the
daemon, no rebuild of the SPA shell.

This document describes how to author one.

## Concept

A plugin is a JavaScript ES module that:

1. Defines a custom HTML element (`customElements.define(...)`).
2. Calls `window.VtcPluginApi.registerPlugin({ ... })` at module
   top-level, naming that element.

The shell renders your element when the operator navigates to your
plugin's `path`. From there, your element owns its sub-tree — it
can be Web Components, Lit, plain vanilla DOM, or React mounted
inside the shadow root. The shell makes no assumptions about your
framework.

## On-disk layout

The daemon serves plugins from `admin_ui.plugin_dir`. Each plugin
gets its own subdirectory whose name is the plugin's stable id
(lowercase, kebab-case):

```text
<plugin_dir>/
  hello-world/
    manifest.json
    index.js          # entry module
    style.css         # optional, fetched by your own code
    icon.svg          # optional, referenced from manifest
```

The plugin id (= directory name) must match `^[a-z][a-z0-9-]*$`.
Anything else is silently dropped by the daemon's manifest scanner
(with a warning in the daemon log) — the regex keeps IDs URL- and
filesystem-safe.

## `manifest.json`

```json
{
  "id": "hello-world",
  "label": "Hello, world",
  "path": "/hello",
  "entry": "index.js",
  "icon": "👋",
  "scopes": []
}
```

| Field | Required | Meaning |
|-------|----------|---------|
| `id`  | optional | Inferred from the directory name. Provided values that don't match are silently overridden by the directory name. |
| `label` | yes | Human-readable nav label. |
| `path` | yes | Route under `/admin/`. Must start with `/` and not end with `/`. Sub-routes (`/hello/details/...`) belong to your element. |
| `entry` | yes | Filename inside your plugin directory the shell `import()`s. Must be a relative path with no `..` segments. |
| `icon` | optional | Emoji or short SVG. Shown in the nav. |
| `scopes` | optional | Array of `"admin"` / `"super-admin"`. Plugins with `super-admin` in `scopes` are hidden from the nav for operators who aren't super-admin. The server still enforces. |

## `entry` module contract

Your `entry` file is loaded by the shell with a dynamic `import()`
after the operator signs in. Its top-level code is expected to:

1. Define a custom element.
2. Call `registerPlugin({...})`, naming that element via the
   `elementTag` field.

```js
class HelloWorldElement extends HTMLElement {
  connectedCallback() {
    this.innerHTML = `
      <section class="page">
        <h2>Hello, world</h2>
        <p>Mounted at <code>${window.location.pathname}</code></p>
      </section>
    `;
  }
}

customElements.define("vtc-hello-world", HelloWorldElement);

window.VtcPluginApi.registerPlugin({
  id: "hello-world",
  label: "Hello, world",
  path: "/hello",
  elementTag: "vtc-hello-world",
  icon: "👋",
});
```

### Choosing a nav group

The console's sidebar is grouped: Overview, Membership, Governance and
Community, then **More**. Add an optional `group` to the
`registerPlugin` call to place your entry:

| `group` | Where the entry appears |
|---------|-------------------------|
| `"overview"`, `"membership"`, `"governance"`, `"community"` | Under that sidebar heading, after the built-in entries. |
| `"account"` | In the account menu in the top bar, beside *My passkeys* and *Signing keys*. Use it for something that is the operator's own rather than the community's. |
| absent, or any other value | Under **More**, after the named groups. |

`group` is placement only. Your route, element, icon and `scopes` /
`capabilities` behave the same in every group, and a plugin written
before groups existed needs no change: it is listed under **More**.

The shell holds the custom-element tag, not the class. When your
route activates, the shell does:

```js
const node = document.createElement(elementTag);
hostElement.appendChild(node);
```

so any state your element needs lives inside the element itself
(constructor, fields, shadow DOM). The shell never reaches into
your element.

## Talking to the daemon

The session cookie set at admin sign-in (`vtc_admin_session`) is
`HttpOnly`, scoped to `/`, and `SameSite=Strict`. The browser
attaches it automatically to fetches from your plugin. You do
**not** see the JWT — that's deliberate; only the server can mint
or revoke it.

For mutating requests, mirror the `csrf` cookie's value into an
`X-CSRF-Token` header:

```js
async function csrfHeader() {
  const m = document.cookie.match(/(?:^|;\s*)csrf=([^;]+)/);
  return m ? { "X-CSRF-Token": m[1] } : {};
}

await fetch("/v1/community/profile", {
  method: "PUT",
  credentials: "include",
  headers: {
    "Content-Type": "application/json",
    "Trust-Task": "https://trusttasks.org/openvtc/vtc/community/profile/manage/1.0",
    ...(await csrfHeader()),
  },
  body: JSON.stringify(updatedProfile),
});
```

### Trust-Task header

Every `/v1/*` endpoint requires a matching `Trust-Task` header.
Missing or wrong value → `400 TrustTaskMissing`. Look up the
right URL in `trust-tasks/index.json` (served as part of the
project source; also published on `openvtc.org/trust-tasks` at
release).

### The `window.VtcPluginApi.toast` surface

The shell exposes a toaster on `window.VtcPluginApi.toast`:

```js
const toast = window.VtcPluginApi?.toast;
if (toast) {
  toast.push("success", "Saved");
  toast.push("error", "Something went wrong");
  toast.pushFromError(err, "Save failed"); // formats an ApiError
}
```

Always probe with `?.` — older shells didn't have this surface.

## Plugin lifecycle

| Event | Effect |
|-------|--------|
| Daemon boot | The daemon scans `admin_ui.plugin_dir` on every request to `/admin/plugins.json` — no caching. Drop a new plugin into the directory and refresh the SPA. |
| SPA boot | The shell fetches `/admin/plugins.json` and dynamically `import()`s every entry. Plugins register synchronously. |
| Operator focuses the tab | The shell refetches `/admin/plugins.json` and imports any IDs that aren't already registered. New plugins appear in the nav without a hard refresh. |
| "Reload plugins" button | Same as focus, but operator-initiated. |
| Plugin removed from disk | Already-loaded plugins stay loaded for the current SPA session — JS modules can't be unregistered. Refresh the SPA tab to drop a removed plugin. |
| Plugin's JS file changed | The shell does **not** hot-reload modified module bodies — re-importing a changed plugin would either no-op (browser module cache) or throw on duplicate `registerPlugin`. Refresh the SPA tab. |

## Versioning

There is no plugin API version field yet. Capability additions
(`toast`, future event bus, slot extension points) attach to the
same `window.VtcPluginApi` object additively. Probe for what you
need (`if (window.VtcPluginApi?.toast)`) rather than depending on
a version stamp.

If `registerPlugin` ever needs a breaking change, the shell will
expose `window.VtcPluginApi.v2` next to the existing surface and
both will live in parallel for at least one release.

## Security

The plugin directory is a trust boundary the operator owns. Files
served from `/admin/plugins/<id>/<path>` come straight off disk;
the daemon does no signing or sandboxing of plugin code. Treat
the contents of `admin_ui.plugin_dir` the same way you'd treat any
other piece of software you install on the host.

A plugin's JS runs in the same origin as the rest of the admin
SPA, which means it can:

- Read the `csrf` cookie (intentional — see above).
- Call any authenticated `/v1/*` endpoint that the signed-in
  operator could.
- Read `localStorage` set by the shell or other plugins.

It **cannot**:

- Read the `vtc_admin_session` cookie (it's HttpOnly).
- Bypass the daemon's Trust-Task gating.
- Re-register a plugin id already in use (`registerPlugin`
  throws).

## Reference

- Plugin manifest scanning: `vtc-service/src/routes/admin_ui.rs`
- Plugin registry: `vtc-service/admin-ui/src/plugin-api.ts`
- Built-in examples: `vtc-service/admin-ui/src/plugins/*.tsx` —
  these use the same `registerPlugin` API but pass
  `reactComponent` instead of `elementTag` because the shell
  imports them statically.
