# vtc-service admin UX

React + TypeScript + Vite source for the VTC's admin console. Built
by `vtc-service`'s `build.rs` and baked into the daemon binary via
`include_dir!` (see `vtc-service/src/admin_ui.rs`). Served at
`/admin/*` when the `admin-ui` cargo feature is on (default).

## Architecture

The shell is a React app. Each feature ships as a **plugin** that
registers itself against `window.VtcPluginApi.registerPlugin(...)`
(or imports `registerPlugin` directly for in-tree plugins).

```
admin-ui/
├── package.json          npm metadata
├── vite.config.ts        Vite build config (base: "/admin/")
├── tsconfig.json         TypeScript config
├── index.html            Vite entry shim
└── src/
    ├── main.tsx          React root + QueryClient + plugin registry boot
    ├── App.tsx           Layout (nav + content) + plugin routes
    ├── plugin-api.ts     Framework-agnostic plugin registration API
    ├── styles.css        Shell + plugin shared styles
    ├── components/
    │   └── PluginHost.tsx  Renders either a React component (in-tree)
    │                       or a custom element (third-party plugin)
    ├── lib/
    │   └── api.ts        Tiny fetch wrapper for daemon JSON endpoints
    ├── pages/
    │   └── Install.tsx   Public install-claim ceremony (unauth route)
    └── plugins/
        ├── index.ts      Built-in plugin registry
        └── dashboard.tsx Health + community profile readout
```

### Plugin boundary

The shell is React; plugins are framework-agnostic. Plugins register
EITHER:

- A **React component** (`reactComponent`) — for in-tree first-party
  plugins that don't want the custom-element wrapper.
- A **custom-element tag** (`elementTag`) — anyone writing a plugin
  in any framework. The shell mounts the custom element into the
  page and the plugin owns the rest.

Both paths share the same `PluginManifest` shape. Third-party
plugins ship as a JS bundle that calls
`window.VtcPluginApi.registerPlugin({...})` at load time.

### Build

```sh
npm install          # one-time
npm run build        # produces dist/
```

`cargo build` (from `vtc-service/`) runs `npm install && npm run
build` automatically via `build.rs`. To skip the build (e.g. in
air-gapped environments shipping a pre-built `dist/`):

```sh
VTC_SKIP_ADMIN_UI_BUILD=1 cargo build -p vtc-service
```

**`cargo build` does not write to `dist/`.** It points vite's
`--outDir` at `$OUT_DIR` and bakes the bundle from there, because
`include_dir!` makes every baked file a compile input of the lib —
regenerating them inside the source tree recompiled the whole crate
on every single `cargo build` (#1243). A plain `npm run build` still
writes `dist/` for local inspection and for the
`VTC_SKIP_ADMIN_UI_BUILD=1` path, which reads it if it's there.

### Develop

```sh
npm run dev          # Vite dev server on :5173, proxies /v1 + /health
                     # to the daemon on localhost:8200
```

Set `VITE_API_PROXY_TARGET=http://other-host:8200` to point at a
different daemon.

## Adding an in-tree plugin

1. Create `src/plugins/<name>/` (or `src/plugins/<name>.tsx` for
   single-file plugins) with an exported React component.
2. Add a `registerPlugin({...})` call in `src/plugins/index.ts`:
   ```ts
   registerPlugin({
     id: "my-feature",
     label: "My feature",
     path: "/my-feature",
     icon: "✨",
     reactComponent: MyFeature,
   });
   ```
3. `npm run build`. The new plugin's nav entry shows up next to the
   existing ones.

## Writing a third-party plugin

Third-party plugins are framework-agnostic. The shell loads them by
fetching `GET /admin/plugins.json`, dynamically `import()`ing each
manifest entry, and the plugin's module body registers itself via
`window.VtcPluginApi.registerPlugin(...)`. The plugin's UI lives
inside a **custom element** the shell mounts when the plugin's
route is active.

### Manifest format

`/admin/plugins.json` returns:

```json
{
  "plugins": [
    {
      "id": "audit-viewer",
      "label": "Audit viewer",
      "path": "/audit",
      "entry": "/admin/plugins/audit-viewer/index.js",
      "icon": "📜",
      "scopes": ["admin"]
    }
  ]
}
```

The daemon scans `admin_ui.plugin_dir` on every fetch and emits
this manifest from whatever it finds on disk. See
[`docs/03-vtc/admin-ui-plugins.md`](../../docs/03-vtc/admin-ui-plugins.md)
for the canonical on-disk layout, scoping rules, and the
serve route's caching contract.

### Plugin module shape

The `entry` URL must resolve to an ES module whose top-level body
calls `registerPlugin` and defines the custom element. Any
framework is fine — vanilla JS, Lit, Vue, Svelte — as long as the
output is a single JS file that runs at module load:

```js
class MyFeatureElement extends HTMLElement {
  connectedCallback() {
    this.innerHTML = `<section class="page"><h2>My feature</h2></section>`;
  }
}
customElements.define("vtc-plugin-my-feature", MyFeatureElement);

window.VtcPluginApi.registerPlugin({
  id: "my-feature",
  label: "My feature",
  path: "/my-feature",
  elementTag: "vtc-plugin-my-feature",
  icon: "✨",
});
```

The shell stamps `<vtc-plugin-my-feature></vtc-plugin-my-feature>`
into the page when the operator navigates to `/admin/my-feature`.
The plugin owns everything inside that element.

### Distributing a plugin

Drop a `<id>/` directory under the daemon's
`admin_ui.plugin_dir` (a `manifest.json` + entry JS). The daemon
serves the bundle at `/admin/plugins/<id>/...`, surfaces it in
`/admin/plugins.json`, and the shell dynamically `import()`s the
entry. Full layout + manifest schema in
[`docs/03-vtc/admin-ui-plugins.md`](../../docs/03-vtc/admin-ui-plugins.md).
