// The member portal shell: sign-in when there is no member session, otherwise
// the member's home (`./Home`) and the pages it links to.

import { useEffect, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { LogOut } from "lucide-react";

import { MemberApiError, memberFetch, postMember, vtcDid, type MemberMe } from "./api";
import { DirectoryPage, EntryPage, MyCardPage } from "./Directory";
import { GroupPage, GroupsPage } from "./Groups";
import { Home } from "./Home";
import { ReposPage } from "./Repos";
import { ElectionPage, ElectionsPage } from "./Elections";
import { BoardPage, BoardsPage } from "./Boards";
import { RoomPage, RoomsPage } from "./Rooms";
import { forgetMemberSessionKey } from "@/lib/console-key";
import { forgetSessionKey } from "./oob";
import { SignIn, isJoinIntent } from "./SignIn";
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
 *  `#/directory`, `#/directory/<entryId>`, `#/card`, `#/groups`,
 *  `#/groups/<groupId>`, `#/repos`, `#/elections`, `#/elections/<electionId>`,
 *  `#/boards`, `#/boards/<boardId>`,
 *  else home. */
export type Route =
  | { page: "home" }
  | { page: "rooms" }
  | { page: "room"; roomId: string }
  | { page: "directory" }
  | { page: "entry"; entryId: string }
  | { page: "card" }
  | { page: "groups" }
  | { page: "group"; groupId: string }
  | { page: "repos" }
  | { page: "elections" }
  | { page: "election"; electionId: string }
  | { page: "boards" }
  | { page: "board"; boardId: string };

export function routeOf(hash: string): Route {
  const path = hash.replace(/^#/, "");
  if (path === "/rooms") return { page: "rooms" };
  if (path === "/repos") return { page: "repos" };
  if (path === "/elections") return { page: "elections" };
  if (path === "/boards") return { page: "boards" };
  const board = /^\/boards\/(brd_[A-Za-z0-9_-]{16,64})$/.exec(path);
  if (board) return { page: "board", boardId: board[1]! };
  const election = /^\/elections\/([A-Za-z0-9._-]{1,128})$/.exec(path);
  if (election) return { page: "election", electionId: election[1]! };
  if (path === "/directory") return { page: "directory" };
  if (path === "/card") return { page: "card" };
  if (path === "/groups") return { page: "groups" };
  const group = /^\/groups\/(grp_[A-Za-z0-9_-]{16,64})$/.exec(path);
  if (group) return { page: "group", groupId: group[1]! };
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
      ) : !me.data || isJoinIntent() ? (
        // The join page shows even to a signed-in member: joining again with a
        // separate identity starts here, and only the wallet can offer it.
        <SignIn communityName={communityName} signedInAs={me.data?.did} />
      ) : (
        <SignedIn me={me.data} />
      )}
    </>
  );
}

/** A signed-in member's pages. The room and repository pages need the
 *  community's DID: the member's wallet holds them to the portal that DID's
 *  document names. */
function SignedIn({ me }: { me: MemberMe }) {
  const route = useRoute();
  const walletPage =
    route.page === "rooms" ||
    route.page === "room" ||
    route.page === "repos" ||
    route.page === "elections" ||
    route.page === "election" ||
    route.page === "board";
  const host = useQuery({
    queryKey: ["community-did"],
    queryFn: async () => me.community.did ?? (await vtcDid()),
    staleTime: Infinity,
    enabled: walletPage,
  });
  if (route.page === "home") return <Home me={me} />;
  if (route.page === "directory") return <DirectoryPage />;
  if (route.page === "entry") return <EntryPage entryId={route.entryId} />;
  if (route.page === "card") return <MyCardPage />;
  if (route.page === "groups") return <GroupsPage />;
  if (route.page === "group") return <GroupPage groupId={route.groupId} />;
  if (route.page === "boards") return <BoardsPage />;
  // A board reads without the wallet; only its vote buttons need the community's DID.
  if (route.page === "board") return <BoardPage boardId={route.boardId} hostDid={host.data} member={me.did} />;
  if (!host.data) {
    return (
      <main className="home" id="main">
        <p className="muted">{host.isError ? (host.error as Error).message : "Loading…"}</p>
      </main>
    );
  }
  if (route.page === "repos") return <ReposPage hostDid={host.data} member={me.did} />;
  if (route.page === "elections") return <ElectionsPage hostDid={host.data} member={me.did} />;
  if (route.page === "election") {
    return <ElectionPage hostDid={host.data} member={me.did} electionId={route.electionId} />;
  }
  return route.page === "rooms" ? (
    <RoomsPage hostDid={host.data} member={me.did} />
  ) : (
    <RoomPage hostDid={host.data} roomId={route.roomId} />
  );
}
