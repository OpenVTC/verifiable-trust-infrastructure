// The member portal in theme preview (`@/lib/theme-preview`).
//
// An administrator previewing a theme is usually not a member, and must not
// need to become one to see the portal, so the portal's own routes answer from
// the sample member below instead of the daemon. Everything public — the
// community profile, the sign-in configuration — is still read for real, so
// the preview shows this community's name and logo.
//
// The preview bar switches between the signed-in home and the sign-in page.

import type { MemberMe, MemberPasskey } from "./api";

const VIEW_KEY = "vtc-theme-preview-member-view";

export type PreviewView = "home" | "sign-in";

export function previewView(): PreviewView {
  try {
    return window.sessionStorage.getItem(VIEW_KEY) === "sign-in" ? "sign-in" : "home";
  } catch {
    return "home";
  }
}

export function setPreviewView(view: PreviewView): void {
  try {
    window.sessionStorage.setItem(VIEW_KEY, view);
  } catch {
    /* the default view, then */
  }
  window.location.reload();
}

const SAMPLE_ME: Omit<MemberMe, "community"> = {
  did: "did:example:sample-member-for-theme-preview",
  sessionId: "theme-preview",
  accessExpiresAt: Math.floor(Date.now() / 1000) + 3600,
  amr: ["did"],
  joinedAt: "2026-01-15T09:30:00Z",
  role: "member",
  personhood: true,
  canManagePasskeys: true,
};

const SAMPLE_PASSKEYS: MemberPasskey[] = [
  { credentialId: "preview-laptop", label: "Laptop", registeredAt: "2026-02-03T10:00:00Z" },
  { credentialId: "preview-phone", label: "Phone", registeredAt: "2026-05-21T18:45:00Z" },
];

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

/**
 * The preview's answer for a GET of the portal's own `path`, or `null` to send
 * it for real (a public read).
 */
export async function previewMemberResponse(path: string): Promise<Response | null> {
  if (path === "/v1/member/me") {
    if (previewView() === "sign-in") return json({ message: "not signed in (preview)" }, 401);
    const profile = await fetch("/v1/community/public-profile", { credentials: "same-origin" })
      .then((r) => (r.ok ? r.json() : {}))
      .catch(() => ({}));
    const p = profile as { name?: string | null; logoUrl?: string | null };
    return json({ ...SAMPLE_ME, community: { name: p.name ?? "Your community", logoUrl: p.logoUrl ?? null, did: null } });
  }
  if (path === "/v1/member/passkeys") return json(SAMPLE_PASSKEYS);
  if (path.startsWith("/v1/member/")) return json({ message: "not available in a theme preview" }, 404);
  return null;
}
