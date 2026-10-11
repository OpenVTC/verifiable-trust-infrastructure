// Which plugin the shell is rendering, for components that place a screen in
// the console's navigation — the page header's breadcrumb (`Membership /
// Members`). Provided by `PluginHost`; `null` outside a plugin (the step-up
// page, a test rendering a component on its own).

import { createContext, useContext } from "react";

import { NAV_GROUPS, MORE_GROUP_LABEL, type PluginManifest } from "@/plugin-api";

export const PluginContext = createContext<PluginManifest | null>(null);

export function useCurrentPlugin(): PluginManifest | null {
  return useContext(PluginContext);
}

/** The heading of the nav group `plugin` is listed under, as the sidebar
 *  shows it; "Account" for the account menu's entries. */
export function groupLabelOf(plugin: PluginManifest): string {
  if (plugin.group === "account") return "Account";
  return NAV_GROUPS.find((g) => g.id === plugin.group)?.label ?? MORE_GROUP_LABEL;
}
