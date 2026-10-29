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
