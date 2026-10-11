// How the shell arranges the plugins the viewer may see: the grouped sidebar
// and the account menu (`plugin-api.ts`, `PluginManifest.group`).
//
// Pure, so the arrangement is tested without rendering the shell
// (`nav-groups.test.ts`).

import {
  MORE_GROUP_LABEL,
  NAV_GROUPS,
  type PluginManifest,
} from "@/plugin-api";

export interface NavSection {
  /** A `PluginGroup`, or `"more"` for plugins that name none. */
  readonly id: string;
  readonly label: string;
  readonly plugins: readonly PluginManifest[];
}

export interface NavArrangement {
  /** Sidebar sections in display order. A section the viewer can see none
   *  of is left out. */
  readonly sections: readonly NavSection[];
  /** Entries for the top bar's account menu (`group: "account"`). */
  readonly account: readonly PluginManifest[];
}

const KNOWN = new Set<string>(NAV_GROUPS.map((g) => g.id));

/**
 * Arrange `plugins` — already filtered to what the viewer may see — into the
 * sidebar's sections and the account menu. Within a section, registration
 * order is kept. A plugin with no `group`, or with a value this shell does not
 * know (a third-party plugin written for a later shell, say), is listed under
 * "More", after the named groups.
 */
export function arrangeNav(plugins: readonly PluginManifest[]): NavArrangement {
  const account: PluginManifest[] = [];
  const byGroup = new Map<string, PluginManifest[]>();
  const more: PluginManifest[] = [];
  for (const p of plugins) {
    const g = p.group as string | undefined;
    if (g === "account") account.push(p);
    else if (g && KNOWN.has(g)) {
      const list = byGroup.get(g) ?? [];
      list.push(p);
      byGroup.set(g, list);
    } else more.push(p);
  }
  const sections: NavSection[] = [];
  for (const g of NAV_GROUPS) {
    const list = byGroup.get(g.id);
    if (list && list.length > 0) sections.push({ id: g.id, label: g.label, plugins: list });
  }
  if (more.length > 0) sections.push({ id: "more", label: MORE_GROUP_LABEL, plugins: more });
  return { sections, account };
}
