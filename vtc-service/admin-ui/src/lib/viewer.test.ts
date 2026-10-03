import { describe, expect, it } from "vitest";

import type { WhoamiResponse } from "@/lib/api";
import { getPlugins } from "@/plugin-api";
import { registerBuiltinPlugins } from "@/plugins";
import { holds, isCommunityAdmin, isSuperAdmin, pluginVisible } from "@/lib/viewer";

const withCaps = (capabilities: string[], adminRole: string | null): WhoamiResponse => ({
  session: {
    id: "sess_1",
    subject: "did:key:z6Mk",
    issuedAt: "2026-09-01T00:00:00Z",
    expiresAt: "2026-09-01T00:05:00Z",
  },
  roles: ["admin"],
  scopes: [],
  capabilities,
  ext: { "org.openvtc": { adminRole, approves: [] } },
});

describe("holds — the VTC's covers rule", () => {
  const caps = [
    "vtc.audit.read",
    "git.repo.manage@git-ns:github.com/acme",
    "vtc.policy.admin@policy:join",
  ];
  it("an unqualified holding covers every resource", () => {
    expect(holds(caps, "vtc.audit.read")).toBe(true);
    expect(holds(caps, "vtc.audit.read", "git-ns:github.com/x")).toBe(true);
  });
  it("a namespace covers its repositories and sub-namespaces, nothing beside them", () => {
    expect(holds(caps, "git.repo.manage", "git-repo:github.com/acme/r#1")).toBe(true);
    expect(holds(caps, "git.repo.manage", "git-ns:github.com/acme/team")).toBe(true);
    expect(holds(caps, "git.repo.manage", "git-ns:github.com/acme")).toBe(true);
    expect(holds(caps, "git.repo.manage", "git-repo:github.com/acme-evil/r#1")).toBe(false);
  });
  it("an unqualified want is covered only by an unqualified holding", () => {
    expect(holds(caps, "git.repo.manage")).toBe(false);
    expect(holds(caps, "vtc.policy.admin")).toBe(false);
    expect(holds(caps, "vtc.policy.admin", "policy:removal")).toBe(false);
  });
  it("`*` asks for the capability at any qualifier", () => {
    expect(holds(caps, "vtc.policy.admin", "*")).toBe(true);
    expect(holds(caps, "vtc.members.manage", "*")).toBe(false);
    expect(holds(undefined, "vtc.audit.read")).toBe(false);
  });
});

describe("navigation follows capabilities, not the session role", () => {
  registerBuiltinPlugins();
  const visible = (who: WhoamiResponse) =>
    getPlugins()
      .filter((p) => pluginVisible(who, p))
      .map((p) => p.id);

  it("an auditor sees the audit trail but not members", () => {
    const ids = visible(withCaps(["vtc.audit.read"], "auditor"));
    expect(ids).toContain("audit");
    expect(ids).not.toContain("members");
    expect(ids).not.toContain("sessions");
    // What every administrator may read stays.
    expect(ids).toEqual(expect.arrayContaining(["dashboard", "actions", "acl", "roles"]));
  });

  it("a moderator sees members, join requests and invitations, not the audit trail", () => {
    const ids = visible(
      withCaps(["vtc.members.manage", "vtc.join.decide", "vtc.invitations.manage"], "moderator"),
    );
    expect(ids).toEqual(expect.arrayContaining(["members", "join-requests", "invitations"]));
    expect(ids).not.toContain("audit");
    expect(ids).not.toContain("profile");
    expect(ids).not.toContain("vetting");
  });

  it("a qualified vetting lead sees vetting", () => {
    expect(visible(withCaps(["vtc.vetting.manage@criterion:age"], "vetting-lead"))).toContain(
      "vetting",
    );
  });

  it("a third-party super-admin scope reads as a community administrator", () => {
    const plugin = { scopes: ["super-admin"] };
    expect(pluginVisible(withCaps(["vtc.roles.assign"], "community-admin"), plugin)).toBe(true);
    expect(pluginVisible(withCaps(["vtc.audit.read"], "auditor"), plugin)).toBe(false);
    expect(isCommunityAdmin(withCaps(["vtc.roles.assign"], "moderator"))).toBe(false);
  });
});

const who = (roles: string[], scopes: string[]): WhoamiResponse => ({
  session: {
    id: "sess_1",
    subject: "did:key:z6Mk",
    issuedAt: "2026-09-01T00:00:00Z",
    expiresAt: "2026-09-01T00:05:00Z",
  },
  roles,
  scopes,
});

describe("isSuperAdmin", () => {
  it("is the admin role with no context restriction", () => {
    expect(isSuperAdmin(who(["admin"], []))).toBe(true);
    expect(isSuperAdmin(who(["admin"], ["ctx-a"]))).toBe(false);
    expect(isSuperAdmin(who(["initiator"], []))).toBe(false);
    expect(isSuperAdmin(null)).toBe(false);
    expect(isSuperAdmin(undefined)).toBe(false);
  });
});
