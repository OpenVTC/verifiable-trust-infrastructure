import { useEffect, useRef } from "react";

import { PluginContext } from "@/lib/plugin-context";
import type { PluginManifest } from "@/plugin-api";

/**
 * Renders a plugin's UI inside the shell's main content area.
 *
 * Two paths:
 *
 * 1. **Built-in plugins** ship a `reactComponent` — we render it
 *    directly. Lets first-party plugins skip the custom-element
 *    wrapper.
 * 2. **Third-party plugins** ship an `elementTag` — we render the
 *    custom element. The plugin owns whatever happens inside.
 *    Anything that fits in a DOM tree (Lit, Vue, vanilla JS,
 *    server-rendered HTML hydrated client-side) works.
 *
 * The boundary is deliberately a one-way write: the shell tells the
 * plugin which route it's on; plugins ask the shell for nothing
 * beyond global APIs (`fetch`, `window.location`, etc.). When the
 * plugin needs a richer host interaction (event bus, slot
 * extension), that's an additive change to `plugin-api.ts`.
 */
export function PluginHost({ plugin }: { plugin: PluginManifest }) {
  if (plugin.reactComponent) {
    const Component = plugin.reactComponent;
    // Built-ins read which plugin they are (the page header's breadcrumb,
    // `lib/plugin-context.ts`). A custom element gets nothing new.
    return (
      <PluginContext.Provider value={plugin}>
        <Component />
      </PluginContext.Provider>
    );
  }
  if (!plugin.elementTag) {
    return <PluginMisconfigured id={plugin.id} />;
  }
  return <CustomElementHost tag={plugin.elementTag} />;
}

function PluginMisconfigured({ id }: { id: string }) {
  return (
    <section className="page">
      <h2>Plugin misconfigured</h2>
      <p>
        Plugin <code>{id}</code> declares neither an
        <code> elementTag</code> nor a <code>reactComponent</code> —
        nothing to render.
      </p>
    </section>
  );
}

function CustomElementHost({ tag }: { tag: string }) {
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const host = ref.current;
    if (!host) return;
    // Clear any previous element (route change → tag change).
    host.replaceChildren();
    const el = document.createElement(tag);
    host.appendChild(el);
    return () => {
      host.replaceChildren();
    };
  }, [tag]);

  return <div className="plugin-host" ref={ref} />;
}
