import type { PluginManifest } from "@/plugin-api";

/**
 * The nav's icon slot for one plugin.
 *
 * Exported for its own test: the `<img>` below is a security property, not a
 * styling choice, and a later refactor back to injected markup would look like
 * a simplification.
 */
export function PluginIcon({ plugin }: { plugin: PluginManifest }) {
  // Built-in plugins ship a lucide-react component; third-party
  // plugins fall back to the `icon` string (inline SVG or single
  // glyph). If neither is set, fall back to the label's first
  // letter so the nav row stays balanced.
  if (plugin.iconComponent) {
    const Icon = plugin.iconComponent;
    return <Icon aria-hidden="true" />;
  }
  if (plugin.icon) {
    // An SVG icon is rendered as an image, never injected as markup.
    //
    // This used to be `dangerouslySetInnerHTML`, which put the plugin's
    // string into the document as live DOM. `script-src 'self'`
    // (`vtc-service/src/routing/security_headers.rs`) stops a `<script>` in
    // it from executing — but an `onload=` / `onerror=` attribute is not
    // script-src's business, and `icon` reaches the shell from plugin
    // JavaScript that a third party may have written.
    //
    // Inside an `<img>` an SVG is a picture: the browser renders it in a
    // non-scripted context, so neither scripts nor event handlers in it ever
    // run, and `img-src 'self' data:` already admits the data URL. No
    // sanitiser, and so no dependency on one being configured correctly.
    if (/^<svg[\s>]/i.test(plugin.icon.trim())) {
      const src = `data:image/svg+xml;charset=utf-8,${encodeURIComponent(
        plugin.icon,
      )}`;
      return (
        <img className="plugin-icon-raw" src={src} alt="" aria-hidden="true" />
      );
    }
    // Anything else is text — a glyph or emoji as before, and markup that is
    // not an SVG as its own characters, because React escapes it.
    return <span aria-hidden="true">{plugin.icon}</span>;
  }
  return <span aria-hidden="true">{plugin.label.charAt(0).toUpperCase()}</span>;
}
