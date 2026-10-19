// The member portal shell: sign-in when there is no member session, otherwise
// the member's home. What a member can *do* here grows from this page; for
// now it is who you are, your membership, and how you sign in.

import { useEffect, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { BadgeCheck, BookUser, Boxes, LogOut, Sparkles } from "lucide-react";

import { MemberApiError, memberFetch, postMember, vtcDid, type MemberMe } from "./api";
import { DirectoryPage, EntryPage, MyCardPage } from "./Directory";
import { listFields, showCard } from "./directory-api";
import { MemberAvatar, nameOf, text } from "./member-card";
import { RoomPage, RoomsPage } from "./Rooms";
import { Passkeys } from "./Passkeys";
import { forgetMemberSessionKey } from "@/lib/console-key";
import { forgetSessionKey } from "./oob";
import { SignIn } from "./SignIn";
import { CommunityTopbar, fetchCommunityProfile } from "../signin/SignInLayout";

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

/** The portal's page, from the location hash: `#/rooms`, `#/rooms/<roomId>`,
 *  `#/directory`, `#/directory/<entryId>`, `#/card`, else home. */
export type Route =
  | { page: "home" }
  | { page: "rooms" }
  | { page: "room"; roomId: string }
  | { page: "directory" }
  | { page: "entry"; entryId: string }
  | { page: "card" };

export function routeOf(hash: string): Route {
  const path = hash.replace(/^#/, "");
  if (path === "/rooms") return { page: "rooms" };
  if (path === "/directory") return { page: "directory" };
  if (path === "/card") return { page: "card" };
  const entry = /^\/directory\/(dir_[A-Za-z0-9_-]{16,64})$/.exec(path);
  if (entry) return { page: "entry", entryId: entry[1]! };
  const m = /^\/rooms\/(.+)$/.exec(path);
  if (m) {
    try {
      const roomId = decodeURIComponent(m[1]!);
      if (roomId.startsWith("did:")) return { page: "room", roomId };
    } catch {
      // A malformed address is the home page.
    }
  }
  return { page: "home" };
}

function useRoute(): Route {
  const [route, setRoute] = useState(() => routeOf(window.location.hash));
  useEffect(() => {
    const on = () => setRoute(routeOf(window.location.hash));
    window.addEventListener("hashchange", on);
    return () => window.removeEventListener("hashchange", on);
  }, []);
  return route;
}

function shortDid(did: string): string {
  return did.length > 34 ? `${did.slice(0, 20)}…${did.slice(-8)}` : did;
}

export function Portal() {
  const qc = useQueryClient();
  const me = useQuery({ queryKey: ["member-me"], queryFn: fetchMe });
  const profile = useQuery({
    queryKey: ["community-profile"],
    queryFn: fetchCommunityProfile,
    staleTime: Infinity,
  });

  const signOut = async () => {
    try {
      await postMember("/v1/member/sign-out");
    } finally {
      // A wallet sign-in's browser key ends with the session (base design §13.5).
      forgetSessionKey();
      await forgetMemberSessionKey();
      qc.setQueryData(["member-me"], null);
      qc.removeQueries({ queryKey: ["member-passkeys"] });
    }
  };

  const communityName = me.data?.community.name ?? profile.data?.name;
  const logoUrl = me.data?.community.logoUrl ?? profile.data?.logoUrl;

  return (
    <>
      <a className="skip" href="#main">
        Skip to content
      </a>
      <CommunityTopbar communityName={communityName} logoUrl={logoUrl} tag="Members">
        {me.data && (
          <div className="topbar-user">
            <code title={me.data.did}>{shortDid(me.data.did)}</code>
            <button type="button" className="btn btn-ghost btn-sm" onClick={signOut}>
              <LogOut size={14} aria-hidden="true" /> Sign out
            </button>
          </div>
        )}
      </CommunityTopbar>

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
        <SignedIn me={me.data} />
      )}
    </>
  );
}

/** A signed-in member's pages. The room pages need the community's DID: the
 *  member's wallet holds them to the portal that DID's document names. */
function SignedIn({ me }: { me: MemberMe }) {
  const route = useRoute();
  const roomPage = route.page === "rooms" || route.page === "room";
  const host = useQuery({
    queryKey: ["community-did"],
    queryFn: async () => me.community.did ?? (await vtcDid()),
    staleTime: Infinity,
    enabled: roomPage,
  });
  if (route.page === "home") return <Home me={me} />;
  if (route.page === "directory") return <DirectoryPage />;
  if (route.page === "entry") return <EntryPage entryId={route.entryId} />;
  if (route.page === "card") return <MyCardPage />;
  if (!host.data) {
    return (
      <main className="home" id="main">
        <p className="muted">{host.isError ? (host.error as Error).message : "Loading…"}</p>
      </main>
    );
  }
  return route.page === "rooms" ? (
    <RoomsPage hostDid={host.data} member={me.did} />
  ) : (
    <RoomPage hostDid={host.data} roomId={route.roomId} />
  );
}

/** The member's own card, on the home page: who they are here, and what the
 *  other members see. Read through the browser key a wallet sign-in delegated;
 *  any other sign-in reads nothing and the panel says how to get it. */
function useOwnCard() {
  const card = useQuery({ queryKey: ["directory", "card"], queryFn: showCard, retry: false });
  const fields = useQuery({ queryKey: ["directory", "fields"], queryFn: listFields, retry: false });
  return { card, fields };
}

function OwnCardPanel({ own }: { own: ReturnType<typeof useOwnCard> }) {
  const c = own.card.data?.card;
  const values = (c?.values ?? {}) as Record<string, unknown>;
  const name = nameOf(values);
  const sub = [text(values.nickname), text(values.pronouns)].filter(Boolean).join(" · ");
  const shownToMembers = (own.fields.data?.fields ?? [])
    .filter((f) => f.state === "active" && f.source !== "derived" && values[f.key] !== undefined)
    .filter((f) => {
      const a = (c?.visibility?.[f.key] as string | undefined) ?? f.defaultVisibility;
      return a === "members" || a === "public";
    })
    .map((f) => f.label);
  const published = c?.discoverability.external && c.externalCard?.state === "published";
  return (
    <section className="card" aria-labelledby="own-card-heading">
      <div className="card-head">
        <BookUser size={18} aria-hidden="true" />
        <h2 id="own-card-heading">Your card</h2>
      </div>
      {!c ? (
        <p className="muted">
          {own.card.isPending
            ? "Loading…"
            : "Sign in with your wallet to see and edit your card here."}
        </p>
      ) : (
        <>
          <div className="me-card">
            <MemberAvatar entryId={c.entryId} value={values.avatar} name={name} size={64} />
            <div className="me-card-names">
              <strong>{name ?? "No name yet"}</strong>
              {sub && <span className="muted">{sub}</span>}
              {published && <span className="pill pill-ok">Published beyond the community</span>}
            </div>
          </div>
          <p className="muted">
            {name === null
              ? "Add your name so other members can find you."
              : shownToMembers.length > 0
                ? `Every member sees your ${shownToMembers.join(", ")}.`
                : "Only some members see anything on your card."}
          </p>
        </>
      )}
      <p>
        <a className="btn btn-primary" href="#/card">
          Edit your card
        </a>{" "}
        <a className="btn btn-ghost" href="#/directory">
          Browse members
        </a>
      </p>
    </section>
  );
}

function Home({ me }: { me: MemberMe }) {
  const joined = new Date(me.joinedAt);
  const own = useOwnCard();
  const values = (own.card.data?.card.values ?? {}) as Record<string, unknown>;
  const name = nameOf(values);
  const first = name?.split(/\s+/)[0];
  return (
    <main className="home" id="main">
      <section className="welcome welcome-personal">
        {own.card.data && (
          <MemberAvatar
            entryId={own.card.data.card.entryId}
            value={values.avatar}
            name={name}
            size={72}
          />
        )}
        <div>
          <p className="eyebrow">Member portal</p>
          <h1>{first ? `Welcome back, ${first}` : "Welcome back"}</h1>
          <p className="lead">
            You're signed in as a member of{" "}
            {me.community.name || "this community"}.
          </p>
        </div>
      </section>

      <div className="grid">
        <OwnCardPanel own={own} />

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

        <section className="card" aria-labelledby="rooms-card-heading">
          <div className="card-head">
            <Boxes size={18} aria-hidden="true" />
            <h2 id="rooms-card-heading">Data rooms</h2>
          </div>
          <p className="muted">
            Shared spaces for notes and files, encrypted for their members. They open through your wallet, which
            shows you everything you add before it is added.
          </p>
          <p>
            <a className="btn btn-primary" href="#/rooms">
              Open your rooms
            </a>
          </p>
        </section>

        <section className="card card-soon" aria-labelledby="soon-heading">
          <div className="card-head">
            <Sparkles size={18} aria-hidden="true" />
            <h2 id="soon-heading">Coming to the portal</h2>
          </div>
          <ul className="soon">
            <li>Your credentials and their status</li>
            <li>Repositories you can create, own and sign for</li>
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
