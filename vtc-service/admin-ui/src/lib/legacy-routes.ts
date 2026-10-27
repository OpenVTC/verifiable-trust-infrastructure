// Routes the console has moved, and where they went. Bookmarks, links in old
// notices and anything typed from memory still land on the right screen; the
// shell (`App.tsx`) mounts a redirect for each `from` no plugin claims.
//
// Pure, so it is tested without rendering anything.

export interface LegacyRoute {
  /** The old route, under `/admin`. */
  readonly from: string;
  /** The new one. */
  readonly to: string;
  /** Carry what followed `from` (`/storage/<id>` → `/rooms/storage/<id>`). */
  readonly keepRest: boolean;
}

export const LEGACY_ROUTES: readonly LegacyRoute[] = [
  // Storage and Room usage became tabs of Data rooms (`plugins/dataRooms.tsx`).
  { from: "/storage", to: "/rooms/storage", keepRest: true },
  { from: "/room-usage", to: "/rooms/usage", keepRest: false },
];

/**
 * Where `pathname` (with its `search` and `hash`) has moved to, or `null` when
 * it has not. `pathname` is the location's own, still encoded, so an
 * identifier in the rest is carried byte for byte.
 */
export function legacyTarget(
  pathname: string,
  search = "",
  hash = "",
  routes: readonly LegacyRoute[] = LEGACY_ROUTES,
): string | null {
  for (const r of routes) {
    if (pathname !== r.from && !pathname.startsWith(`${r.from}/`)) continue;
    const rest = r.keepRest ? pathname.slice(r.from.length).replace(/^\/+$/, "") : "";
    return `${r.to}${rest}${search}${hash}`;
  }
  return null;
}
