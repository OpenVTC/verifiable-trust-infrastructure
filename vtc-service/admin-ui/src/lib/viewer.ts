// Who is looking at the console, as the shell's `whoami` probe answered.

import { useQuery } from "@tanstack/react-query";

import { probeSession, type WhoamiResponse } from "@/lib/api";

/**
 * A community ("super") administrator: the admin role with no context
 * restriction. It is what the VTC calls the community-administrator
 * capability. The shell uses it to hide super-admin plugins; a view uses it to
 * hide actions only such an admin can sign. The VTC decides either way — this
 * only keeps the console from offering what it would refuse.
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
  const { data } = useQuery({
    queryKey: ["whoami"],
    queryFn: probeSession,
    enabled: false,
  });
  return isSuperAdmin(data);
}
