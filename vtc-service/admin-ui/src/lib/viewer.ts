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
