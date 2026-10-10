// The member portal shell: sign-in when there is no member session, otherwise
// the member's home. What a member can *do* here grows from this page; for
// now it is who you are, your membership, and how you sign in.

import { useQuery, useQueryClient } from "@tanstack/react-query";
import { BadgeCheck, LogOut, Sparkles } from "lucide-react";

import { MemberApiError, memberFetch, postMember, type MemberMe } from "./api";
import { Passkeys } from "./Passkeys";
import { forgetSessionKey } from "./oob";
import { SignIn } from "./SignIn";

async function fetchMe(): Promise<MemberMe | null> {
  try {
    return await memberFetch<MemberMe>("/v1/member/me");
  } catch (e) {
    // No session, or no longer an active member: show sign-in.
    if (e instanceof MemberApiError && (e.status === 401 || e.status === 403)) {
      return null;
    }
    throw e;
  }
}

async function fetchCommunityName(): Promise<string | null> {
  try {
    const res = await fetch("/v1/community/public-profile");
    if (!res.ok) return null;
    const p = (await res.json()) as { name?: string };
    return p.name || null;
  } catch {
    return null;
  }
}

function shortDid(did: string): string {
  return did.length > 34 ? `${did.slice(0, 20)}…${did.slice(-8)}` : did;
}

export function Portal() {
  const qc = useQueryClient();
  const me = useQuery({ queryKey: ["member-me"], queryFn: fetchMe });
  const name = useQuery({
    queryKey: ["community-name"],
    queryFn: fetchCommunityName,
    staleTime: Infinity,
  });

  const signOut = async () => {
    try {
      await postMember("/v1/member/sign-out");
    } finally {
      // A wallet sign-in's browser key ends with the session (base design §13.5).
      forgetSessionKey();
      qc.setQueryData(["member-me"], null);
      qc.removeQueries({ queryKey: ["member-passkeys"] });
    }
  };

  const communityName = me.data?.community.name ?? name.data;

  return (
    <>
      <a className="skip" href="#main">
        Skip to content
      </a>
      <header className="topbar">
        <div className="topbar-inner">
          <a className="brand" href="/">
            {me.data?.community.logoUrl ? (
              <img src={me.data.community.logoUrl} alt="" className="brand-logo" />
            ) : (
              <span className="brand-mark" aria-hidden="true" />
            )}
            <span>{communityName || "Verifiable Trust Community"}</span>
          </a>
          <span className="topbar-tag">Members</span>
          {me.data && (
            <div className="topbar-user">
              <code title={me.data.did}>{shortDid(me.data.did)}</code>
              <button type="button" className="btn btn-ghost btn-sm" onClick={signOut}>
                <LogOut size={14} aria-hidden="true" /> Sign out
              </button>
            </div>
          )}
        </div>
      </header>

      {me.isPending ? (
        <main className="signin" id="main">
          <p className="muted">Checking your session…</p>
        </main>
      ) : me.isError ? (
        <main className="signin" id="main">
          <div className="alert" role="alert">
            <p className="alert-title">The portal couldn't reach this community.</p>
            <p>{(me.error as Error).message}</p>
          </div>
        </main>
      ) : !me.data ? (
        <SignIn communityName={communityName} />
      ) : (
        <Home me={me.data} />
      )}
    </>
  );
}

function Home({ me }: { me: MemberMe }) {
  const joined = new Date(me.joinedAt);
  return (
    <main className="home" id="main">
      <section className="welcome">
        <p className="eyebrow">Member portal</p>
        <h1>Welcome back</h1>
        <p className="lead">
          You're signed in as a member of{" "}
          {me.community.name || "this community"}.
        </p>
      </section>

      <div className="grid">
        <section className="card" aria-labelledby="membership-heading">
          <div className="card-head">
            <BadgeCheck size={18} aria-hidden="true" />
            <h2 id="membership-heading">Your membership</h2>
          </div>
          <dl className="facts">
            <div>
              <dt>Status</dt>
              <dd>
                <span className="pill pill-ok">Active</span>
              </dd>
            </div>
            <div>
              <dt>Role</dt>
              <dd className="cap">{me.role}</dd>
            </div>
            <div>
              <dt>Member since</dt>
              <dd>{joined.toLocaleDateString()}</dd>
            </div>
            <div>
              <dt>Your identity</dt>
              <dd>
                <code className="wrap">{me.did}</code>
              </dd>
            </div>
            <div>
              <dt>Signed in with</dt>
              <dd>{signInMethod(me.amr)}</dd>
            </div>
          </dl>
        </section>

        <Passkeys canManage={me.canManagePasskeys} />

        <section className="card card-soon" aria-labelledby="soon-heading">
          <div className="card-head">
            <Sparkles size={18} aria-hidden="true" />
            <h2 id="soon-heading">Coming to the portal</h2>
          </div>
          <ul className="soon">
            <li>Your credentials and their status</li>
            <li>Repositories you can create, own and sign for</li>
            <li>Data rooms you belong to</li>
            <li>Relationships and endorsements</li>
          </ul>
        </section>
      </div>
    </main>
  );
}

/** How the member signed in, from the session's `amr`. A wallet sign-in by
 *  trigger link carries `oob`; the legacy SIOPv2 path carries only `did`. */
function signInMethod(amr: string[]): string {
  if (amr.includes("passkey")) return "Passkey";
  if (amr.includes("oob")) return "Your wallet";
  return "Your VTA (SIOPv2)";
}
