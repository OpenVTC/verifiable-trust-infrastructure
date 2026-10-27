// A route the console has moved (`lib/legacy-routes.ts`): sent on to where it
// went, with its query and fragment.

import type { ReactNode } from "react";
import { Navigate, useLocation } from "react-router-dom";

import { legacyTarget } from "@/lib/legacy-routes";

export function LegacyRedirect({ fallback = null }: { fallback?: ReactNode }) {
  const { pathname, search, hash } = useLocation();
  const to = legacyTarget(pathname, search, hash);
  return to ? <Navigate to={to} replace /> : <>{fallback}</>;
}
