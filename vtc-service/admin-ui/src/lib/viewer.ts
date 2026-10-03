// Who is looking at the console, as the shell's `whoami` probe answered.

import { useQuery } from "@tanstack/react-query";

import { probeSession, type WhoamiResponse } from "@/lib/api";

/**
 * A signed-in administrator, as the session says: the admin session role with
 * no context restriction. Since administration became role-based
 * (`docs/05-design-notes/vtc-admin-roles.md`) every administrative role signs
 * in this way — a moderator or an auditor as well as a community
 * administrator — so this is only a hint for what the console offers. What the
 * viewer may actually do is the capabilities its own ACL entry holds, which
 * the VTC reads at every operation and refuses by name (`does not hold
 * vtc.…`); the Access-control page shows them.
 */
export function isSuperAdmin(who: WhoamiResponse | null | undefined): boolean {
  return !!who && who.roles.includes("admin") && who.scopes.length === 0;
}

/**
 * `isSuperAdmin` for the signed-in viewer, read from the shell's `whoami`
 * cache. It observes that cache and never fetches (`enabled: false`); the
 * query function is the shell's own, so the two cannot race with different
 * answers (see `plugins/sessions.tsx`). Until a probe has answered, the
 * viewer is not one.
 */
export function useIsSuperAdmin(): boolean {
  return isSuperAdmin(useWhoami());
}

/**
 * The DID the signed-in viewer's session authenticates, read the same way
 * from the shell's `whoami` cache; `null` until a probe has answered. A
 * console key signs `git-ns` tasks as this DID (`git_ns::tasks::acting_as`),
 * so it is whose git rights decide what the console may offer.
 */
export function useViewerDid(): string | null {
  return useWhoami()?.session.subject ?? null;
}

// ─── capabilities (`docs/05-design-notes/vtc-admin-roles.md` §4, §5) ──────

/** One held capability, `cap` or `cap@resource`, split. */
function parseCap(s: string): { cap: string; resource: string | null } {
  const at = s.indexOf("@");
  return at < 0 ? { cap: s, resource: null } : { cap: s.slice(0, at), resource: s.slice(at + 1) };
}

/** Whether holding `held` (a resource qualifier) covers `wanted` — the same
 *  resource, or one inside it: a namespace covers its sub-namespaces and its
 *  repositories (VTI-ACL-035). */
function qualifierCovers(held: string, wanted: string): boolean {
  if (held === wanted) return true;
  const ns = held.startsWith("git-ns:") ? held.slice("git-ns:".length) : null;
  if (ns === null) return false;
  for (const kind of ["git-ns:", "git-repo:"]) {
    if (wanted.startsWith(kind) && wanted.slice(kind.length).startsWith(`${ns}/`)) return true;
  }
  return false;
}

/**
 * Whether `caps` (the viewer's `whoami.capabilities`) covers `cap` at
 * `resource` — `undefined` asks for it community-wide, `"*"` for it at any
 * qualifier. An unqualified holding covers every resource; a qualified one
 * covers its resource and what is inside it; an unqualified want is covered
 * only by an unqualified holding (the VTC's `CapRef::covers`).
 */
export function holds(
  caps: ReadonlyArray<string> | null | undefined,
  cap: string,
  resource?: string,
): boolean {
  if (!caps) return false;
  return caps.some((s) => {
    const h = parseCap(s);
    if (h.cap !== cap) return false;
    if (resource === "*") return true;
    if (h.resource === null) return true;
    if (resource === undefined) return false;
    return qualifierCovers(h.resource, resource);
  });
}

/** The viewer's capabilities, read live by the VTC behind `whoami`. Empty
 *  until a probe has answered. A hint for what to offer: every operation is
 *  still decided by the VTC against the viewer's entry. */
export function useCapabilities(): string[] {
  return useWhoami()?.capabilities ?? [];
}

/** `holds` for the signed-in viewer. */
export function useCan(cap: string, resource?: string): boolean {
  return holds(useCapabilities(), cap, resource);
}

/** What the viewer may approve (`ext["org.openvtc"].approves`). */
export function useApproves(): string[] {
  return useWhoami()?.ext?.["org.openvtc"]?.approves ?? [];
}

/** The viewer's administrative role (`community-admin`, `moderator`, a custom
 *  role, …), or `null`. */
export function useAdminRole(): string | null {
  return useWhoami()?.ext?.["org.openvtc"]?.adminRole ?? null;
}

/**
 * A community administrator holding `vtc.roles.assign` community-wide — what
 * the git-ns verbs reserved to "a community administrator" sign with. Read
 * from the capabilities, not the session's role hint.
 */
export function isCommunityAdmin(who: WhoamiResponse | null | undefined): boolean {
  return (
    who?.ext?.["org.openvtc"]?.adminRole === "community-admin" &&
    holds(who.capabilities, "vtc.roles.assign")
  );
}

export function useIsCommunityAdmin(): boolean {
  return isCommunityAdmin(useWhoami());
}

/**
 * Whether the shell shows a plugin's nav entry to `who`: any of its
 * `capabilities` held at any qualifier, and a `super-admin` scope (a
 * third-party plugin's hint) read as a community administrator. Navigation is
 * a hint only — the VTC decides every operation.
 */
export function pluginVisible(
  who: WhoamiResponse | null | undefined,
  plugin: {
    readonly capabilities?: ReadonlyArray<string>;
    readonly scopes?: ReadonlyArray<string>;
  },
): boolean {
  if (plugin.capabilities && plugin.capabilities.length > 0) {
    if (!plugin.capabilities.some((c) => holds(who?.capabilities, c, "*"))) return false;
  }
  if (plugin.scopes?.includes("super-admin")) return isCommunityAdmin(who);
  return true;
}

/** How the signed-in viewer authenticated (RFC 8176 `amr`), from the same
 *  cache — `["passkey"]` for a passkey sign-in, absent for a wallet one. */
export function useViewerAmr(): string[] | undefined {
  return useWhoami()?.session.amr;
}

function useWhoami(): WhoamiResponse | null | undefined {
  const { data } = useQuery({
    queryKey: ["whoami"],
    queryFn: probeSession,
    enabled: false,
  });
  return data;
}
