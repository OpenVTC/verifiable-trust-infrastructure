// The community's sign-in layout, shared by the member portal (`/members/`)
// and the operator console's login page (`/admin/`): the top bar with the
// community's name, the centred sign-in card (eyebrow, heading, lead text,
// options), the "Using an older wallet?" disclosure and the page footer.
//
// Styles are `./signin.css`, scoped under `.vtc-signin`. Nothing here imports
// the console's shell, API client or plugins, so the member bundle can use it.

import type { ReactNode } from "react";

/** The community's top bar. The brand links to the community's home page. */
export function CommunityTopbar({
  communityName,
  logoUrl,
  tag,
  children,
}: {
  communityName?: string | null;
  logoUrl?: string | null;
  /** The pill beside the name: "Members", "Operator console". */
  tag: string;
  /** Anything on the right, such as the signed-in identity. */
  children?: ReactNode;
}) {
  return (
    <header className="topbar">
      <div className="topbar-inner">
        <a className="brand" href="/">
          {logoUrl ? (
            <img src={logoUrl} alt="" className="brand-logo" />
          ) : (
            <span className="brand-mark" aria-hidden="true" />
          )}
          <span>{communityName || "Verifiable Trust Community"}</span>
        </a>
        <span className="topbar-tag">{tag}</span>
        {children}
      </div>
    </header>
  );
}

/** The centred sign-in card and the footer lines under it. */
export function SignInPage({
  eyebrow,
  title,
  lead,
  children,
  after,
  foot,
}: {
  eyebrow: string;
  title: ReactNode;
  lead: ReactNode;
  /** The sign-in options, in order. */
  children: ReactNode;
  /** Inside the card, after the options: errors and the like. */
  after?: ReactNode;
  /** Footer lines under the card, one `<p>` each. */
  foot?: ReactNode[];
}) {
  return (
    <main className="signin" id="main">
      <section className="signin-card" aria-labelledby="signin-heading">
        <p className="eyebrow">{eyebrow}</p>
        <h1 id="signin-heading">{title}</h1>
        <p className="lead">{lead}</p>
        <div className="signin-options">{children}</div>
        {after}
      </section>
      {foot?.map((line, i) => (
        <p className="signin-foot" key={i}>
          {line}
        </p>
      ))}
    </main>
  );
}

/** "Using an older wallet?" — the deprecated SIOPv2 sign-ins (contract C7),
 *  kept but behind a disclosure. */
export function OlderWalletOptions({ children }: { children: ReactNode }) {
  return (
    <details className="legacy-signin">
      <summary>Using an older wallet?</summary>
      {children}
    </details>
  );
}

/** "Back to <community>": the community's home page, `/`. */
export function HomeLink({ communityName }: { communityName?: string | null }) {
  return (
    <a className="home-link" href="/">
      <span aria-hidden="true">←</span> Back to {communityName || "the community's home page"}
    </a>
  );
}

/** The community's public name and logo, from the unauthenticated
 *  `GET /v1/community/public-profile`. `null` when it has none or the call
 *  fails: a sign-in page must render without it. */
export async function fetchCommunityProfile(): Promise<{
  name: string | null;
  logoUrl: string | null;
}> {
  try {
    const res = await fetch("/v1/community/public-profile");
    if (!res.ok) return { name: null, logoUrl: null };
    const p = (await res.json()) as { name?: string; logoUrl?: string | null };
    return { name: p.name || null, logoUrl: p.logoUrl || null };
  } catch {
    return { name: null, logoUrl: null };
  }
}
