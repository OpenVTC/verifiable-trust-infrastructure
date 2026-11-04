// The signed-in member's home: who they are here, what needs them now, and
// where each part of the portal stands. Every status is read with the same
// query (key and function) as the page it links to, so opening a tile shows
// what the tile said without asking again. Nothing here prompts the wallet:
// its `list` and `offers` calls never open a window.

import { useState, type ReactNode } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  BellRing,
  Boxes,
  Check,
  ChevronRight,
  Copy,
  GitBranch,
  Sparkles,
  SquareKanban,
  UserRound,
  Users,
  UsersRound,
  Vote,
  type LucideIcon,
} from "lucide-react";

import { vtcDid, type MemberMe } from "./api";
import { listAllBoards } from "./boards-api";
import { boardHref } from "./Boards";
import { listFields, showCard } from "./directory-api";
import { electionHref } from "./Elections";
import { viewRepos } from "./git-api";
import { listGroups } from "./groups-api";
import {
  boardsAttention,
  boardsStatus,
  electionsAttention,
  electionsStatus,
  groupsStatus,
  reposStatus,
  roomsAttention,
  roomsStatus,
  type Attention,
  type Status,
} from "./home-status";
import { MemberAvatar, nameOf, text } from "./member-card";
import { Passkeys } from "./Passkeys";
import { walletElections } from "./wallet-elections";
import { walletRooms } from "./wallet-rooms";

const STALE = 30_000;

export function Home({ me }: { me: MemberMe }) {
  const card = useQuery({ queryKey: ["directory", "card"], queryFn: showCard, retry: false });
  const fields = useQuery({ queryKey: ["directory", "fields"], queryFn: listFields, retry: false });
  const host = useQuery({
    queryKey: ["community-did"],
    queryFn: async () => me.community.did ?? (await vtcDid()),
    staleTime: Infinity,
  });
  const hostDid = host.data;

  const rw = walletRooms();
  const ew = walletElections();
  const rooms = useQuery({
    queryKey: ["member-rooms", hostDid],
    queryFn: async () => (await rw!.list({ hostDid: hostDid! })).rooms,
    enabled: !!rw && !!hostDid,
    retry: false,
    staleTime: STALE,
  });
  const offers = useQuery({
    queryKey: ["member-room-offers", hostDid],
    queryFn: async () => rw!.offers!({ hostDid: hostDid! }),
    enabled: !!rw && typeof rw.offers === "function" && !!hostDid,
    retry: false,
    staleTime: STALE,
  });
  const elections = useQuery({
    queryKey: ["member-elections", hostDid, me.did],
    queryFn: () => ew!.list({ hostDid: hostDid!, member: me.did }),
    enabled: !!ew && !!hostDid,
    retry: false,
    staleTime: STALE,
  });
  const boards = useQuery({ queryKey: ["boards"], queryFn: listAllBoards, retry: false, staleTime: STALE });
  const groups = useQuery({ queryKey: ["groups", "list"], queryFn: listGroups, retry: false, staleTime: STALE });
  const git = useQuery({ queryKey: ["git", "view"], queryFn: viewRepos, retry: false, staleTime: STALE });

  const c = card.data?.card;
  const values = (c?.values ?? {}) as Record<string, unknown>;
  const name = nameOf(values);
  const first = name?.split(/\s+/)[0];
  const sub = [text(values.nickname), text(values.pronouns)].filter(Boolean).join(" · ");

  const attention: Attention[] = [
    ...(c && name === null ? [{ key: "card-name", text: "Add your name so other members can find you", href: "#/card" }] : []),
    ...roomsAttention(rw ? offers : null),
    ...electionsAttention(elections, electionHref),
    ...boardsAttention(boards, boardHref),
  ];

  return (
    <main className="home" id="main">
      <section className="ph-profile" aria-labelledby="welcome-heading">
        <div className="ph-profile-who">
          {c ? (
            <MemberAvatar entryId={c.entryId} value={values.avatar} name={name} size={72} />
          ) : (
            <span className="avatar ph-avatar-blank" aria-hidden="true">
              <UserRound size={32} />
            </span>
          )}
          <div className="ph-profile-names">
            <h1 id="welcome-heading">{first ? `Welcome back, ${first}` : "Welcome back"}</h1>
            <p className="muted">
              {[name, sub, `Member of ${me.community.name || "this community"}`].filter(Boolean).join(" · ")}
            </p>
          </div>
          <div className="ph-profile-actions">
            <a className="btn btn-primary btn-sm" href="#/card">
              Edit your card
            </a>
          </div>
        </div>

        <dl className="ph-facts">
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
            <dd>{new Date(me.joinedAt).toLocaleDateString(undefined, { dateStyle: "medium" })}</dd>
          </div>
          <div>
            <dt>Signed in with</dt>
            <dd>{signInMethod(me.amr)}</dd>
          </div>
          <div className="ph-facts-did">
            <dt>Your identity</dt>
            <dd>
              <DidChip did={me.did} />
            </dd>
          </div>
        </dl>

        <p className="ph-visibility muted">{visibilityLine(c, values, fields.data?.fields, card.isPending)}</p>
      </section>

      {attention.length > 0 && (
        <section className="ph-attention" aria-labelledby="attention-heading">
          <h2 id="attention-heading">
            <BellRing size={16} aria-hidden="true" /> Needs your attention
          </h2>
          <ul>
            {attention.slice(0, 6).map((a) => (
              <li key={a.key}>
                <a href={a.href}>
                  <span>{a.text}</span>
                  <ChevronRight size={16} aria-hidden="true" />
                </a>
              </li>
            ))}
          </ul>
        </section>
      )}

      <section aria-labelledby="community-heading">
        <h2 className="ph-section" id="community-heading">
          Your community
        </h2>
        <div className="ph-tiles">
          <Tile href="#/directory" icon={Users} title="Members" status={null}>
            Find people in the community and see their cards.
          </Tile>
          <Tile href="#/groups" icon={UsersRound} title="Groups" status={groupsStatus(groups)}>
            Join groups and see who is in them.
          </Tile>
          <Tile href="#/boards" icon={SquareKanban} title="Boards" status={boardsStatus(boards)}>
            Propose ideas, leave notes and vote on what happens next.
          </Tile>
          <Tile href="#/elections" icon={Vote} title="Elections" status={electionsStatus(!!ew, elections)}>
            Vote privately: your wallet holds your ballot, never this site.
          </Tile>
          <Tile
            href="#/rooms"
            icon={Boxes}
            title="Data rooms"
            status={roomsStatus(!!rw, rooms, rw && typeof rw.offers === "function" ? offers : null)}
          >
            Encrypted notes and files, opened through your wallet.
          </Tile>
          <Tile href="#/repos" icon={GitBranch} title="Repositories" status={reposStatus(git, me.did)}>
            Repositories you can create, maintain and sign commits for.
          </Tile>
        </div>
      </section>

      <section aria-labelledby="account-heading">
        <h2 className="ph-section" id="account-heading">
          Sign-in and security
        </h2>
        <div className="ph-account">
          <Passkeys canManage={me.canManagePasskeys} />
          <aside className="ph-soon" aria-labelledby="soon-heading">
            <h3 id="soon-heading">
              <Sparkles size={14} aria-hidden="true" /> Coming to the portal
            </h3>
            <ul>
              <li>Your credentials and their status</li>
              <li>Relationships and endorsements</li>
            </ul>
          </aside>
        </div>
      </section>
    </main>
  );
}

function Tile({
  href,
  icon: Icon,
  title,
  status,
  children,
}: {
  href: string;
  icon: LucideIcon;
  title: string;
  status: Status | "loading" | null;
  children: ReactNode;
}) {
  return (
    <a className="ph-tile" href={href}>
      <span className="ph-tile-head">
        <span className="ph-tile-icon" aria-hidden="true">
          <Icon size={18} />
        </span>
        <span className="ph-tile-title">{title}</span>
        <ChevronRight className="ph-tile-go" size={16} aria-hidden="true" />
      </span>
      <span className="ph-tile-desc">{children}</span>
      {status === "loading" ? (
        <span className="ph-status ph-status-loading" aria-label="Loading">
          <span className="ph-skeleton" />
        </span>
      ) : status ? (
        <span className={`ph-status ph-status-${status.tone}`}>
          <span className="ph-dot" aria-hidden="true" />
          {status.text}
        </span>
      ) : null}
    </a>
  );
}

function DidChip({ did }: { did: string }) {
  const [copied, setCopied] = useState(false);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(did);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1500);
    } catch {
      // No clipboard (insecure context): the DID stays selectable.
    }
  };
  return (
    <span className="ph-did">
      <code title={did}>{did}</code>
      <button type="button" className="btn btn-ghost btn-sm" onClick={copy} aria-label="Copy your DID">
        {copied ? <Check size={14} aria-hidden="true" /> : <Copy size={14} aria-hidden="true" />}
      </button>
    </span>
  );
}

type Card = NonNullable<Awaited<ReturnType<typeof showCard>>["card"]>;
type Field = Awaited<ReturnType<typeof listFields>>["fields"][number];

/** What the other members see of the member's card, in one line. */
function visibilityLine(
  c: Card | undefined,
  values: Record<string, unknown>,
  fields: Field[] | undefined,
  pending: boolean,
): string {
  if (!c) return pending ? "" : "Sign in with your wallet to see and edit your card here.";
  const shown = (fields ?? [])
    .filter((f) => f.state === "active" && f.source !== "derived" && values[f.key] !== undefined)
    .filter((f) => {
      const a = (c.visibility?.[f.key] as string | undefined) ?? f.defaultVisibility;
      return a === "members" || a === "public";
    })
    .map((f) => f.label);
  const published = c.discoverability.external && c.externalCard?.state === "published";
  const base =
    shown.length > 0 ? `Every member sees your ${shown.join(", ")}.` : "Only some members see anything on your card.";
  return [base, published ? "Your card is also published beyond the community." : ""].filter(Boolean).join(" ");
}

/** How the member signed in, from the session's `amr`. A wallet sign-in by
 *  trigger link carries `oob`; the legacy SIOPv2 path carries only `did`. */
export function signInMethod(amr: string[]): string {
  if (amr.includes("passkey")) return "Passkey";
  if (amr.includes("oob")) return "Your wallet";
  return "Your VTA (SIOPv2)";
}
