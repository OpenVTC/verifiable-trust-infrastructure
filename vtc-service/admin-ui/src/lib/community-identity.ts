// The community's identity in the console frame: its name and mark in the top
// bar, and its accent colour as the console's brand.
//
// - Name and logo come from the unauthenticated public profile
//   (`GET /v1/community/public-profile`), the same read the home page and the
//   member portal make.
// - The accent comes from the community's branding (the Vetting screen's
//   Branding card, `vtc/community/branding/show/0.1`), a signed read, so it is
//   asked for only once this browser can sign. It shares the card's query key,
//   so saving the card re-themes the console at once.
//
// Everything here is decoration: any failure leaves the defaults (the
// community-neutral name, the gradient mark, indigo) and never reaches the
// operator as an error.

import { useEffect } from "react";
import { useQuery } from "@tanstack/react-query";

import { fetchBranding, vettingKeys } from "@/plugins/vetting/api";

export interface PublicProfileView {
  readonly name: string | null;
  readonly logoUrl: string | null;
}

/** The name shown when the profile cannot be read. */
export const FALLBACK_COMMUNITY_NAME = "Verifiable Trust Community";

export const PUBLIC_PROFILE_KEY = ["community-public-profile"] as const;

async function fetchPublicProfile(): Promise<PublicProfileView> {
  const res = await fetch("/v1/community/public-profile", {
    headers: { Accept: "application/json" },
  });
  if (!res.ok) throw new Error(`public profile: HTTP ${res.status}`);
  const body = (await res.json()) as { name?: unknown; logoUrl?: unknown };
  return {
    name: typeof body.name === "string" && body.name.trim() ? body.name.trim() : null,
    logoUrl: typeof body.logoUrl === "string" && body.logoUrl ? body.logoUrl : null,
  };
}

/**
 * A logo the console may show. The console's CSP is `img-src 'self' data:`,
 * so a logo on another origin would only be blocked (and reported); those fall
 * back to the gradient mark rather than a broken image.
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

const HEX = /^#[0-9a-f]{6}$/i;

/** Relative luminance (WCAG 2.x) of a `#rrggbb` colour. */
function luminance(hex: string): number {
  const ch = [1, 3, 5].map((i) => parseInt(hex.slice(i, i + 2), 16) / 255);
  const [r, g, b] = ch.map((c) => (c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4));
  return 0.2126 * r! + 0.7152 * g! + 0.0722 * b!;
}

/** The label colour for text on `accent`: white where it reads at 4.5:1,
 *  else the near-black ink. `null` for anything that is not `#rrggbb`. */
export function accentForeground(accent: string): string | null {
  if (!HEX.test(accent)) return null;
  const contrastWithWhite = 1.05 / (luminance(accent) + 0.05);
  return contrastWithWhite >= 4.5 ? "#ffffff" : "#0b0b1a";
}

/** Put the community accent on <html> (`styles/tokens.css`,
 *  `:root[data-community-accent]`), or take it off. */
export function applyCommunityAccent(accent: string | null | undefined): void {
  const root = document.documentElement;
  const fg = accent ? accentForeground(accent) : null;
  if (accent && fg) {
    root.style.setProperty("--community-accent", accent.toLowerCase());
    root.style.setProperty("--community-accent-fg", fg);
    root.setAttribute("data-community-accent", "");
  } else {
    root.style.removeProperty("--community-accent");
    root.style.removeProperty("--community-accent-fg");
    root.removeAttribute("data-community-accent");
  }
}

export interface CommunityIdentity {
  readonly name: string;
  /** A logo the console can show, or `null` for the gradient mark. */
  readonly logoUrl: string | null;
}

/**
 * The community's name and mark, and — once `canSign` — its accent applied as
 * the console's brand.
 */
export function useCommunityIdentity(canSign: boolean): CommunityIdentity {
  const profile = useQuery({
    queryKey: PUBLIC_PROFILE_KEY,
    queryFn: fetchPublicProfile,
    staleTime: 5 * 60_000,
    retry: false,
  });
  const branding = useQuery({
    queryKey: vettingKeys.branding,
    queryFn: fetchBranding,
    enabled: canSign,
    staleTime: 5 * 60_000,
    retry: false,
  });
  const accent = (branding.data as { accentColor?: unknown } | undefined)?.accentColor;
  const accentHex = typeof accent === "string" ? accent : null;

  useEffect(() => {
    applyCommunityAccent(accentHex);
    return () => applyCommunityAccent(null);
  }, [accentHex]);

  return {
    name: profile.data?.name ?? FALLBACK_COMMUNITY_NAME,
    logoUrl: displayableLogo(profile.data?.logoUrl),
  };
}
