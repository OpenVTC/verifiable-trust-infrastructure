// The grouped navigation (`lib/nav-groups.ts`) and the plugin API's optional
// `group`: the built-ins land in their sections, the operator's own entries go
// to the account menu, and a plugin that names no group — every third-party
// plugin written before groups existed, registered through
// `window.VtcPluginApi` as a custom element — still registers, routes and is
// listed, under "More".

import { beforeAll, describe, expect, it } from "vitest";

import { arrangeNav } from "@/lib/nav-groups";
import { pluginVisible } from "@/lib/viewer";
import type { WhoamiResponse } from "@/lib/api";
import { findPluginByPath, getPlugins, type PluginManifest } from "@/plugin-api";
import { registerBuiltinPlugins } from "@/plugins";

const ids = (ps: readonly PluginManifest[]) => ps.map((p) => p.id);

function viewer(capabilities: string[]): WhoamiResponse {
  return {
    session: { id: "s", subject: "did:key:z6MkV", issuedAt: "", expiresAt: "" },
    roles: ["admin"],
    scopes: [],
    capabilities,
  } as unknown as WhoamiResponse;
}

const EVERYTHING = viewer([
  "vtc.audit.read",
  "vtc.join.decide",
  "vtc.members.manage",
  "vtc.invitations.manage",
  "vtc.vetting.manage",
  "vtc.sessions.revoke",
  "vtc.surface.admin",
  "vtc.registry.admin",
  "git.ns.admin",
]);

beforeAll(() => {
  registerBuiltinPlugins();
  // A pre-groups third-party plugin, registered the way plugins/<id>/index.js
  // does it: through the window global, as a custom element, with no group.
  customElements.define("x-legacy-plugin", class extends HTMLElement {});
  window.VtcPluginApi!.registerPlugin({
    id: "legacy",
    label: "Legacy tool",
    path: "/legacy",
    elementTag: "x-legacy-plugin",
    icon: "L",
  });
  // One written for a later shell, naming a group this one does not know.
  window.VtcPluginApi!.registerPlugin({
    id: "future",
    label: "Future tool",
    path: "/future",
    elementTag: "x-legacy-plugin",
    group: "analytics" as never,
  });
  // One that opts into a known group.
  window.VtcPluginApi!.registerPlugin({
    id: "grouped",
    label: "Grouped tool",
    path: "/grouped",
    elementTag: "x-legacy-plugin",
    group: "membership",
  });
});

describe("the grouped sidebar", () => {
  it("lists the built-ins in the four groups, in order", () => {
    const nav = arrangeNav(getPlugins().filter((p) => pluginVisible(EVERYTHING, p)));
    const byId = Object.fromEntries(nav.sections.map((s) => [s.id, s]));

    expect(nav.sections.map((s) => s.label)).toEqual([
      "Overview",
      "Membership",
      "Governance",
      "Community",
      "More",
    ]);
    expect(ids(byId.overview!.plugins)).toEqual(["dashboard", "actions", "audit"]);
    expect(ids(byId.membership!.plugins)).toEqual([
      "join-requests",
      "members",
      "invitations",
      "vetting",
      "relationships",
      "grouped",
    ]);
    expect(ids(byId.governance!.plugins)).toEqual(["ceremonies", "roles", "acl", "sessions"]);
    expect(ids(byId.community!.plugins)).toEqual(["profile", "recognition", "rooms", "repos"]);
  });

  it("relabels Ceremonies as Policies and Community profile as Profile, on the same routes", () => {
    const all = getPlugins();
    const policies = all.find((p) => p.id === "ceremonies")!;
    expect(policies.label).toBe("Policies");
    expect(policies.path).toBe("/ceremonies");
    const profile = all.find((p) => p.id === "profile")!;
    expect(profile.label).toBe("Profile");
    expect(profile.path).toBe("/profile");
  });

  it("moves My passkeys and Signing keys to the account menu, routes unchanged", () => {
    const nav = arrangeNav(getPlugins().filter((p) => pluginVisible(EVERYTHING, p)));
    expect(ids(nav.account)).toEqual(["my-passkeys", "console-keys"]);
    const inSidebar = nav.sections.flatMap((s) => ids(s.plugins));
    expect(inSidebar).not.toContain("my-passkeys");
    expect(inSidebar).not.toContain("console-keys");
    expect(findPluginByPath("/my-passkeys")?.id).toBe("my-passkeys");
    expect(findPluginByPath("/console-keys")?.id).toBe("console-keys");
  });

  it("puts plugins with no group, or an unknown one, under More, last", () => {
    const nav = arrangeNav(getPlugins());
    const last = nav.sections[nav.sections.length - 1]!;
    expect(last.id).toBe("more");
    expect(ids(last.plugins)).toEqual(["legacy", "future"]);
  });

  it("keeps a custom-element plugin registered through window.VtcPluginApi intact", () => {
    const legacy = findPluginByPath("/legacy")!;
    expect(legacy).toMatchObject({ id: "legacy", elementTag: "x-legacy-plugin", icon: "L" });
    expect(legacy.group).toBeUndefined();
  });

  it("hides a group the viewer can see nothing in", () => {
    // An auditor: no membership, governance-only-by-default or community
    // capabilities beyond what every administrator reads.
    const nav = arrangeNav(
      getPlugins()
        .filter((p) => !["legacy", "future", "grouped"].includes(p.id))
        .filter((p) => pluginVisible(viewer(["vtc.audit.read"]), p)),
    );
    const labels = nav.sections.map((s) => s.label);
    expect(labels).toContain("Overview");
    expect(labels).not.toContain("More");
    const membership = nav.sections.find((s) => s.id === "membership");
    // Relationships is readable by every administrator, so the group stays,
    // holding only that.
    expect(ids(membership!.plugins)).toEqual(["relationships"]);

    expect(arrangeNav([]).sections).toEqual([]);
    const onlyCommunity = arrangeNav(getPlugins().filter((p) => p.id === "rooms"));
    expect(onlyCommunity.sections.map((s) => s.id)).toEqual(["community"]);
  });
});
