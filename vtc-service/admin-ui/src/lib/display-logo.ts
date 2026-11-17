// Which community logo a page may show. Dependency-free, so the member bundle
// (`/members/`) can use it without pulling in the console's plugins.

/**
 * A logo the console or the member portal may show. Both are served with the
 * VTC's CSP, `img-src 'self' data:`, so a logo on another origin would only be
 * blocked (and reported); those fall back to the gradient mark rather than a
 * broken image.
 */
export function displayableLogo(url: string | null | undefined, origin?: string): string | null {
  if (!url) return null;
  if (url.startsWith("/") && !url.startsWith("//")) return url;
  try {
    const here = origin ?? window.location.origin;
    return new URL(url).origin === here ? url : null;
  } catch {
    return null;
  }
}

/** What the public profile (or the portal's `community`) says about the logo. */
export interface LogoSource {
  readonly logo?: { readonly url?: unknown } | null;
  readonly logoUrl?: unknown;
}

/**
 * The logo a page should try: the one the community stored and serves from
 * its own origin (`vtc/community/logo/update/0.1`, the `logo` member) when it
 * holds one, else the profile's `logoUrl`. Pass the result through
 * {@link displayableLogo} before drawing it.
 */
export function chosenLogo(source: LogoSource | null | undefined): string | null {
  const stored = source?.logo?.url;
  if (typeof stored === "string" && stored) return stored;
  const url = source?.logoUrl;
  return typeof url === "string" && url ? url : null;
}

/**
 * The note the profile form shows under its Logo URL field: `null` when these
 * pages will draw the URL, else why they will not. Saving is still allowed —
 * readers of the public profile elsewhere can use any address.
 */
export function logoUrlWarning(url: string, origin?: string): string | null {
  const trimmed = url.trim();
  if (!trimmed || displayableLogo(trimmed, origin)) return null;
  return (
    "These pages only show images from this community's own address, so they won't show a logo " +
    "from another site. Upload the logo in the Logo card below instead."
  );
}
