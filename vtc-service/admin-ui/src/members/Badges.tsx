// Member badges in the member portal (`vtc/badges/*`):
//
//   #/badges          Your badges: the offers waiting for you, what shows on
//                     your card and how it is arranged, what you hid, every
//                     badge you may browse, the kudos badges you made.
//   #/badges/<id>     One badge: who else holds it, asking its owners for it,
//                     or giving it to someone when it is a kudos badge.
//   #/badges/new      Make a kudos badge of your own.
//
// Signed by this browser's portal key for the member, as the directory is.
// Only the member's own acts go this way: accepting and declining, hiding and
// showing, arranging, giving kudos, making a kudos badge. A community badge is
// defined and given from the console by its owners; asking for one is a
// request to join its badge group, which its owners decide.
//
// Nothing a member hides is shown to anyone: the wall on their card, a badge's
// holder list and its counts leave a hidden badge out, while the member still
// holds it (VTI-BDG-030). The page says so where it matters.

import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  ArrowDown,
  ArrowUp,
  Award,
  Check,
  Eye,
  EyeOff,
  Gift,
  ImagePlus,
  MessageSquare,
  Pin,
  PinOff,
  Plus,
  X,
} from "lucide-react";

import { Protected } from "@/components/Protected";

import {
  acceptOffer,
  arrangeWall,
  badgeHref,
  badgesHref,
  createKudosBadge,
  declineOffer,
  giveKudos,
  hideBadge,
  listBadges,
  listHolders,
  listMine,
  makeBadgeHref,
  redeemClaim,
  shareAward,
  showBadge,
  showBadgeAgain,
  showSettings,
  showWall,
  unshareAward,
  uploadBadgeImage,
  type Badge,
  type MyAward,
  type MyBadge,
  type Offer,
  type WallVisibility,
} from "./badges-api";
import { BadgeArt, BadgeTile, ago } from "./badge-card";
import { DirectoryError, listEntries } from "./directory-api";
import { joinGroup, leaveGroup } from "./groups-api";
import { Crumbs, MemberAvatar, nameOf } from "./member-card";
import { PictureError, prepare, toBase64Url } from "./picture";

const MINE_KEY = ["badges", "mine"] as const;
const SETTINGS_KEY = ["badges", "settings"] as const;

function Unavailable({ error }: { error: unknown }) {
  const e = error instanceof DirectoryError ? error : null;
  return (
    <div className="alert" role="status">
      {e?.needsWallet ? (
        <>
          <p className="alert-title">Sign in with your wallet to see your badges.</p>
          <p>
            Your wallet lets this browser act for you in the community for this session. Sign out, then sign in
            again with &ldquo;Sign in with your wallet&rdquo;.
          </p>
        </>
      ) : (
        <>
          <p className="alert-title">Badges aren&rsquo;t available right now.</p>
          <p>{(error as Error)?.message}</p>
        </>
      )}
    </div>
  );
}

/** Whether the community has badges on at all; off hides every surface. */
function useBadgesOn(): { on: boolean | null; makers: "nobody" | "roles" | "members" | null; showTotals: boolean } {
  const q = useQuery({ queryKey: SETTINGS_KEY, queryFn: showSettings, retry: false, staleTime: 60_000 });
  return {
    on: q.data ? q.data.enabled : q.isError ? false : null,
    makers: q.data?.kudosMakers.policy ?? null,
    showTotals: q.data?.showKudosTotals ?? true,
  };
}

function Off() {
  return (
    <main className="home" id="main">
      <Crumbs trail={[{ label: "Badges" }]} />
      <section className="welcome">
        <p className="eyebrow">Badges</p>
        <h1>Badges</h1>
        <p className="lead">This community has badges turned off for now.</p>
      </section>
    </main>
  );
}

// ─── claiming with a code ──────────────────────────────────────────────────

/** A code an event's host handed out (VTI-BDG-026): entering it is claiming the badge. */
function ClaimForm() {
  const qc = useQueryClient();
  const [code, setCode] = useState("");
  const [said, setSaid] = useState<{ ok: boolean; text: string } | null>(null);
  const claim = useMutation({
    mutationFn: () => redeemClaim(code),
    onSuccess: () => {
      setCode("");
      setSaid({ ok: true, text: "Claimed. The badge is yours, and its credential is on its way to your wallet." });
      void qc.invalidateQueries({ queryKey: MINE_KEY });
    },
    onError: (e) => {
      const c = e instanceof DirectoryError ? e.code : "";
      setSaid({
        ok: false,
        text: c.endsWith(":alreadyClaimed")
          ? "You have already claimed this code."
          : c.endsWith(":alreadyHeld")
            ? "You already hold this badge."
            : c.endsWith(":codeInvalid")
              ? "That code admits no one: check it, or ask the host."
              : e instanceof Error
                ? e.message
                : "That did not work. Try again.",
      });
    },
  });
  return (
    <section className="bw-section" aria-labelledby="bw-claim">
      <h2 id="bw-claim">Have a code?</h2>
      <form
        className="bw-claim"
        onSubmit={(e) => {
          e.preventDefault();
          if (code.trim()) claim.mutate();
        }}
      >
        <input
          aria-label="Claim code"
          placeholder="The code from the event"
          value={code}
          autoComplete="off"
          onChange={(e) => setCode(e.target.value)}
        />
        <button type="submit" className="btn btn-primary btn-sm" disabled={!code.trim() || claim.isPending}>
          {claim.isPending ? "Claiming…" : "Claim the badge"}
        </button>
      </form>
      {said && (
        <p className={said.ok ? "muted" : "error"} role={said.ok ? "status" : "alert"}>
          {said.text}
        </p>
      )}
    </section>
  );
}

// ─── your badges ───────────────────────────────────────────────────────────

export function BadgesPage() {
  const { on, makers } = useBadgesOn();
  const mine = useQuery({ queryKey: MINE_KEY, queryFn: listMine, retry: false });
  const all = useQuery({ queryKey: ["badges", "list"], queryFn: () => listBadges(), retry: false });
  const made = useQuery({ queryKey: ["badges", "list", "mine"], queryFn: () => listBadges("kudos", true), retry: false });
  if (on === false) return <Off />;
  const badges = mine.data?.badges ?? [];
  const shown = badges.filter((b) => !b.hidden);
  const hidden = badges.filter((b) => b.hidden);
  const offers = mine.data?.offers ?? [];
  const held = new Set(badges.map((b) => b.badge.badgeId));
  const offered = new Set(offers.map((o) => o.badge.badgeId));
  const browse = (all.data?.items ?? []).filter((i) => !held.has(i.badge.badgeId) && !offered.has(i.badge.badgeId));
  const myKudos = made.data?.items ?? [];
  return (
    <main className="home" id="main">
      <Crumbs trail={[{ label: "Badges" }]} />
      <section className="welcome">
        <p className="eyebrow">Badges</p>
        <h1>Your badges</h1>
        <p className="lead">
          {mine.data
            ? `${shown.length} on your card${hidden.length ? `, ${hidden.length} hidden` : ""}${
                offers.length ? `, ${offers.length} waiting for you` : ""
              }. Only you see this page; your card shows what you choose.`
            : "What you were given, what you show, and every badge in the community."}
        </p>
        <div className="bw-actions">
          <a className="btn btn-ghost btn-sm" href="#browse">
            Browse all badges
          </a>
          {makers !== "nobody" && (
            <a className="btn btn-primary btn-sm" href={makeBadgeHref}>
              <Plus size={14} aria-hidden="true" /> Make a badge
            </a>
          )}
        </div>
      </section>
      {mine.isPending && <p className="muted">Loading…</p>}
      {mine.isError && <Unavailable error={mine.error} />}
      {offers.length > 0 && <Offers offers={offers} />}
      <ClaimForm />
      {mine.data && <Wall badges={shown} visibility={mine.data.visibility} kudosTotal={mine.data.kudosTotal} />}
      {hidden.length > 0 && <Hidden badges={hidden} />}
      {myKudos.length > 0 && (
        <section className="bw-section" aria-labelledby="bw-made">
          <h2 id="bw-made">Badges you give out</h2>
          <p className="muted">{myKudos.length} you made. Open one to give it.</p>
          <div className="bw-wall">
            {myKudos.map(({ badge }) => (
              <BadgeTile key={badge.badgeId} badge={badge} width={140}>
                <span className="bw-tile-sub">
                  {typeof badge.holderCount === "number" ? `${badge.holderCount} hold it` : "Give it"}
                </span>
              </BadgeTile>
            ))}
          </div>
        </section>
      )}
      <section className="bw-section" id="browse" aria-labelledby="bw-browse">
        <h2 id="bw-browse">All badges</h2>
        {all.isError && <Unavailable error={all.error} />}
        {all.isSuccess && browse.length === 0 && (
          <p className="muted">{badges.length > 0 ? "You hold every badge you can see." : "There are no badges to see yet."}</p>
        )}
        <div className="bw-wall">
          {browse.map(({ badge, myState }) => (
            <BadgeTile key={badge.badgeId} badge={badge} width={140}>
              <span className="bw-tile-sub">
                {myState === "requested"
                  ? "You asked for it"
                  : badge.kind === "kudos"
                    ? "Kudos"
                    : badge.requestable
                      ? "You can ask for it"
                      : "Given by its owners"}
              </span>
            </BadgeTile>
          ))}
        </div>
      </section>
    </main>
  );
}

/** Offers waiting for the member. Deciding is a surface of the member's own: drawn out of the
 *  community theme's reach. */
function Offers({ offers }: { offers: Offer[] }) {
  return (
    <Protected ground="card">
      <OffersSurface offers={offers} />
    </Protected>
  );
}

function OffersSurface({ offers }: { offers: Offer[] }) {
  const qc = useQueryClient();
  const [note, setNote] = useState<string | null>(null);
  const refresh = () => {
    void qc.invalidateQueries({ queryKey: ["badges"] });
    void qc.invalidateQueries({ queryKey: ["groups"] });
  };
  const accept = useMutation({
    mutationFn: (awardId: string) => acceptOffer(awardId),
    onSuccess: (r) => {
      setNote(
        r.award.credentialId
          ? `You hold ${r.badge.badge.name}. Its credential is on its way to your wallet.`
          : `You hold ${r.badge.badge.name}.`,
      );
      refresh();
    },
    onError: (e) => setNote((e as Error).message),
  });
  const decline = useMutation({
    mutationFn: (awardId: string) => declineOffer(awardId),
    onSuccess: () => {
      setNote("Declined. Nobody is told, and it can be offered again.");
      refresh();
    },
    onError: (e) => setNote((e as Error).message),
  });
  return (
    <section className="card bw-offers" aria-labelledby="bw-offers">
      <h2 id="bw-offers">Waiting for you</h2>
      <p className="muted">
        {offers.length} badge{offers.length === 1 ? " was" : "s were"} offered to you. Nothing shows on your card
        until you accept.
      </p>
      {note && (
        <p className="alert alert-info" role="status">
          {note}
        </p>
      )}
      <ul className="bw-offer-list">
        {offers.map(({ award, badge, givenBy }) => {
          const giver = givenBy ? nameOf(givenBy as Record<string, unknown>) : null;
          return (
            <li key={award.awardId} className="bw-offer">
              <BadgeArt badge={badge} width={110} />
              <div className="bw-offer-text">
                <strong>{badge.name}</strong>
                <span className="muted">
                  {giver ? `Given by ${giver}` : badge.kind === "kudos" ? "Given by a member" : "Given by the community"} ·{" "}
                  {ago(award.offeredAt)}
                </span>
                {award.note && <span className="bw-offer-note">&ldquo;{award.note}&rdquo;</span>}
                <span className="muted">
                  {badge.kind === "community"
                    ? "Comes with an Open Badge credential for your wallet"
                    : "Picture only, no credential"}
                  {typeof badge.holderCount === "number" ? ` · ${badge.holderCount} members hold this` : ""}
                </span>
              </div>
              <div className="bw-offer-actions">
                <button
                  type="button"
                  className="btn btn-ghost btn-sm"
                  onClick={() => decline.mutate(award.awardId)}
                  disabled={decline.isPending || accept.isPending}
                >
                  <X size={14} aria-hidden="true" /> Decline
                </button>
                <button
                  type="button"
                  className="btn btn-primary btn-sm"
                  onClick={() => accept.mutate(award.awardId)}
                  disabled={decline.isPending || accept.isPending}
                >
                  <Check size={14} aria-hidden="true" /> Accept
                </button>
              </div>
            </li>
          );
        })}
      </ul>
      <p className="muted bw-fine">
        Declining tells no one. A credential-backed badge is issued when you accept and offered to your wallet.
      </p>
    </section>
  );
}

/** The badges on the member's card, in their order, pinned ones first; the tools to arrange them. */
function Wall({ badges, visibility, kudosTotal }: { badges: MyBadge[]; visibility: WallVisibility; kudosTotal?: number }) {
  const qc = useQueryClient();
  const [note, setNote] = useState<string | null>(null);
  const ordered = useMemo(
    () =>
      [...badges].sort((a, b) =>
        a.pinned !== b.pinned ? (a.pinned ? -1 : 1) : (a.position ?? 1e9) - (b.position ?? 1e9) || (a.since < b.since ? 1 : -1),
      ),
    [badges],
  );
  const arrange = useMutation({
    mutationFn: (p: { order?: string[]; pinned?: string[]; visibility?: WallVisibility }) => arrangeWall(p),
    onSuccess: () => {
      setNote(null);
      void qc.invalidateQueries({ queryKey: MINE_KEY });
    },
    onError: (e) => setNote((e as Error).message),
  });
  const hide = useMutation({
    mutationFn: (badgeId: string) => hideBadge(badgeId),
    onSuccess: () => {
      setNote("Hidden from your card. You still hold it; the badge's holder list leaves you out.");
      void qc.invalidateQueries({ queryKey: MINE_KEY });
    },
    onError: (e) => setNote((e as Error).message),
  });
  const ids = ordered.map((b) => b.badge.badgeId);
  const pinned = ordered.filter((b) => b.pinned).map((b) => b.badge.badgeId);
  const move = (id: string, by: -1 | 1) => {
    const i = ids.indexOf(id);
    const j = i + by;
    if (i < 0 || j < 0 || j >= ids.length) return;
    const next = [...ids];
    [next[i], next[j]] = [next[j]!, next[i]!];
    arrange.mutate({ order: next });
  };
  const togglePin = (id: string, on: boolean) =>
    arrange.mutate({ pinned: on ? [...pinned, id] : pinned.filter((x) => x !== id) });
  return (
    <section className="bw-section" aria-labelledby="bw-wall">
      <div className="bw-section-head">
        <h2 id="bw-wall">On your card</h2>
        <span className="muted">
          {badges.length} · pinned ones show beside your name
          {typeof kudosTotal === "number" ? ` · ${kudosTotal} kudos received` : ""}
        </span>
        <label className="bw-visibility">
          Who sees your badges
          <select
            aria-label="Who sees your badges"
            value={visibility}
            disabled={arrange.isPending}
            onChange={(e) => arrange.mutate({ visibility: e.target.value as WallVisibility })}
          >
            <option value="members">Members who can see my card</option>
            <option value="nobody">Only me</option>
          </select>
        </label>
      </div>
      {note && (
        <p className="alert alert-info" role="status">
          {note}
        </p>
      )}
      {badges.length === 0 ? (
        <p className="muted">Nothing on your card yet. Badges you accept show here.</p>
      ) : (
        <div className="bw-wall">
          {ordered.map((b, i) => (
            <BadgeTile key={b.badge.badgeId} badge={b.badge} count={b.count} pinned={b.pinned} width={150}>
              <div className="bw-tile-tools" role="group" aria-label={`Arrange ${b.badge.name}`}>
                <button
                  type="button"
                  className="btn btn-ghost btn-xs"
                  title={b.pinned ? "Unpin" : "Pin next to your name"}
                  aria-label={b.pinned ? `Unpin ${b.badge.name}` : `Pin ${b.badge.name}`}
                  disabled={arrange.isPending}
                  onClick={() => togglePin(b.badge.badgeId, !b.pinned)}
                >
                  {b.pinned ? <PinOff size={14} aria-hidden="true" /> : <Pin size={14} aria-hidden="true" />}
                </button>
                <button
                  type="button"
                  className="btn btn-ghost btn-xs"
                  title="Move earlier"
                  aria-label={`Move ${b.badge.name} earlier`}
                  disabled={arrange.isPending || i === 0}
                  onClick={() => move(b.badge.badgeId, -1)}
                >
                  <ArrowUp size={14} aria-hidden="true" />
                </button>
                <button
                  type="button"
                  className="btn btn-ghost btn-xs"
                  title="Move later"
                  aria-label={`Move ${b.badge.name} later`}
                  disabled={arrange.isPending || i === ordered.length - 1}
                  onClick={() => move(b.badge.badgeId, 1)}
                >
                  <ArrowDown size={14} aria-hidden="true" />
                </button>
                <button
                  type="button"
                  className="btn btn-ghost btn-xs"
                  title="Hide from your card"
                  aria-label={`Hide ${b.badge.name}`}
                  disabled={hide.isPending}
                  onClick={() => hide.mutate(b.badge.badgeId)}
                >
                  <EyeOff size={14} aria-hidden="true" />
                </button>
              </div>
            </BadgeTile>
          ))}
        </div>
      )}
    </section>
  );
}

function Hidden({ badges }: { badges: MyBadge[] }) {
  const qc = useQueryClient();
  const show = useMutation({
    mutationFn: (badgeId: string) => showBadgeAgain(badgeId),
    onSuccess: () => void qc.invalidateQueries({ queryKey: MINE_KEY }),
  });
  return (
    <section className="bw-section" aria-labelledby="bw-hidden">
      <h2 id="bw-hidden">Hidden</h2>
      <p className="muted">
        {badges.length} · you still hold {badges.length === 1 ? "it" : "them"}; nobody else is shown{" "}
        {badges.length === 1 ? "it" : "them"}, and the badge&rsquo;s holder list leaves you out.
      </p>
      <div className="bw-wall">
        {badges.map((b) => (
          <BadgeTile key={b.badge.badgeId} badge={b.badge} count={b.count} width={140}>
            <button
              type="button"
              className="btn btn-ghost btn-xs"
              disabled={show.isPending}
              onClick={() => show.mutate(b.badge.badgeId)}
            >
              <Eye size={14} aria-hidden="true" /> Show again
            </button>
          </BadgeTile>
        ))}
      </div>
    </section>
  );
}

// ─── one badge ─────────────────────────────────────────────────────────────

const REGIME: Record<string, string> = {
  none: "Picture only; nothing goes to a wallet",
  inside: "An Open Badge credential issued by the badge's own group identity, for use inside the community",
  outside: "An Open Badge credential you may show outside the community",
};

export function BadgePage({ badgeId }: { badgeId: string }) {
  const { on } = useBadgesOn();
  const q = useQuery({ queryKey: ["badges", "show", badgeId], queryFn: () => showBadge(badgeId), retry: false });
  const holders = useQuery({
    queryKey: ["badges", "holders", badgeId],
    queryFn: () => listHolders(badgeId),
    retry: false,
    enabled: q.isSuccess,
  });
  if (on === false) return <Off />;
  const badge = q.data?.badge;
  const owners = q.data?.owners ?? [];
  return (
    <main className="home" id="main">
      <Crumbs trail={[{ label: "Badges", href: badgesHref }, { label: badge?.name ?? "Badge" }]} />
      {q.isPending && <p className="muted">Loading…</p>}
      {q.isError &&
        (q.error instanceof DirectoryError && q.error.code === "notFound" ? (
          <p className="muted">There is no such badge, or it isn&rsquo;t one you can see.</p>
        ) : (
          <Unavailable error={q.error} />
        ))}
      {badge && q.data && (
        <section className="bw-detail">
          <article className="card bw-hero">
            <BadgeArt badge={badge} width={300} />
            <h1>{badge.name}</h1>
            <p className="lead">{badge.description}</p>
            <div className="pills">
              {typeof badge.holderCount === "number" && (
                <span className="pill">
                  {badge.holderCount} member{badge.holderCount === 1 ? "" : "s"} hold it
                </span>
              )}
              <span className="pill">{badge.kind === "community" ? "Community badge" : "Kudos badge"}</span>
              {badge.repeatable && <span className="pill">Can be earned more than once</span>}
              {badge.state === "retired" && <span className="pill pill-warn">Retired</span>}
              {q.data.myState === "holder" && (
                <span className="pill pill-ok">You hold it{q.data.myCount > 1 ? ` ×${q.data.myCount}` : ""}</span>
              )}
              {q.data.myState === "offered" && <span className="pill pill-warn">Offered to you</span>}
              {q.data.myState === "requested" && <span className="pill">You asked for it</span>}
            </div>
            <dl className="bw-facts">
              {badge.kind === "community" && (
                <>
                  <dt>Owners</dt>
                  <dd>
                    {owners.length === 0 ? "The community's administrators" : <OwnerNames entryIds={owners} />}
                  </dd>
                </>
              )}
              {badge.kind === "kudos" && q.data.maker && (
                <>
                  <dt>Made by</dt>
                  <dd>
                    <OwnerNames entryIds={[q.data.maker]} />
                  </dd>
                </>
              )}
              <dt>Credential</dt>
              <dd>{REGIME[q.data.credentialRegime] ?? q.data.credentialRegime}</dd>
              <dt>Created</dt>
              <dd>{new Date(badge.createdAt).toLocaleDateString(undefined, { dateStyle: "long" })}</dd>
            </dl>
            {badge.criteria && (
              <div className="bw-criteria">
                <p className="eyebrow">How to earn it</p>
                <p>{badge.criteria}</p>
              </div>
            )}
            {q.data.myState === "offered" && (
              <a className="btn btn-primary" href={badgesHref}>
                <Gift size={16} aria-hidden="true" /> Accept or decline it
              </a>
            )}
            {badge.state === "active" && badge.kind === "community" && badge.groupId && (
              <AskForBadge badge={badge} groupId={badge.groupId} myState={q.data.myState} />
            )}
            {badge.state === "active" && badge.kind === "kudos" && <GiveBadge badge={badge} />}
          </article>
          {badge.state === "active" && q.data.credentialRegime === "outside" && (q.data.myAwards?.length ?? 0) > 0 && (
            <ShareOutside badgeId={badge.badgeId} awards={q.data.myAwards ?? []} />
          )}
          <section className="card bw-holders" aria-labelledby="bw-holders-title">
            <h2 id="bw-holders-title">Who holds it</h2>
            {holders.isPending && <p className="muted">Loading…</p>}
            {holders.isError && <p className="muted">The badge doesn&rsquo;t show you its holders.</p>}
            {holders.data && (
              <>
                <p className="muted">
                  {holders.data.total} member{holders.data.total === 1 ? "" : "s"} · most recent first
                </p>
                <ul className="directory-grid bw-holder-grid">
                  {holders.data.items.map((h) => {
                    const fields = (h.fields ?? {}) as Record<string, unknown>;
                    const name = nameOf(fields);
                    return (
                      <li key={h.entryId}>
                        <a className="card directory-entry" href={`#/directory/${encodeURIComponent(h.entryId)}`}>
                          <span className="directory-entry-head">
                            <MemberAvatar entryId={h.entryId} value={fields.avatar} name={name} size={40} />
                            <span className="directory-entry-names">
                              <span className="directory-name">{name ?? "A member"}</span>
                              <span className="directory-sub muted">
                                {h.count > 1 ? `×${h.count} · ` : ""}
                                {ago(h.latestAt)}
                              </span>
                            </span>
                          </span>
                        </a>
                      </li>
                    );
                  })}
                </ul>
                <p className="muted bw-fine">
                  A member who has hidden this badge is not listed and not counted. Names and pictures follow the
                  directory&rsquo;s own visibility.
                </p>
              </>
            )}
          </section>
        </section>
      )}
    </main>
  );
}

/** Showing one's own awards of a badge outside the community (VTI-BDG-070): each award
 *  shared on its own, by the member's choice, at locations only those they give them to
 *  know. Stopping is not a revocation. */
function ShareOutside({ badgeId, awards }: { badgeId: string; awards: MyAward[] }) {
  const qc = useQueryClient();
  const [error, setError] = useState<string | null>(null);
  const done = () => {
    setError(null);
    void qc.invalidateQueries({ queryKey: ["badges", "show", badgeId] });
  };
  const share = useMutation({ mutationFn: shareAward, onSuccess: done, onError: (e) => setError(refusal(e)) });
  const stop = useMutation({ mutationFn: unshareAward, onSuccess: done, onError: (e) => setError(refusal(e)) });
  const busy = share.isPending || stop.isPending;
  return (
    <section className="card bw-share" aria-labelledby="bw-share-title">
      <h2 id="bw-share-title">Show it outside the community</h2>
      <p className="muted">
        Share an award to get a link anyone can open to check it, and a picture with the credential inside it for a
        website or an email signature. Only people you give the link to can find it. The credential names you and
        each award&rsquo;s note, so share only an award you are happy to show.
      </p>
      <ul className="bw-share-list">
        {awards.map((a) => (
          <li key={a.awardId} className="bw-share-item">
            <span className="bw-share-when">
              Awarded {a.decidedAt ? new Date(a.decidedAt).toLocaleDateString(undefined, { dateStyle: "medium" }) : ""}
              {a.note && <span className="bw-offer-note"> &ldquo;{a.note}&rdquo;</span>}
            </span>
            {a.shared ? (
              <span className="bw-share-links">
                <CopyLink label="Link to check it" value={a.shared.verificationUrl} />
                {a.shared.bakedImageUrl && <CopyLink label="Picture with the credential" value={a.shared.bakedImageUrl} />}
                <button type="button" className="btn btn-ghost" disabled={busy} onClick={() => stop.mutate(a.awardId)}>
                  Stop sharing
                </button>
              </span>
            ) : (
              <button type="button" className="btn btn-primary" disabled={busy} onClick={() => share.mutate(a.awardId)}>
                Share outside
              </button>
            )}
          </li>
        ))}
      </ul>
      {error && (
        <p className="error" role="alert">
          {error}
        </p>
      )}
    </section>
  );
}

function CopyLink({ label, value }: { label: string; value: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <span className="bw-copy">
      <a href={value} target="_blank" rel="noreferrer noopener">
        {label}
      </a>
      <button
        type="button"
        className="btn btn-ghost btn-small"
        onClick={() => {
          void navigator.clipboard?.writeText(value).then(() => setCopied(true));
        }}
      >
        {copied ? "Copied" : "Copy"}
      </button>
    </span>
  );
}

/** What a refused share or stop says to the member. */
function refusal(e: unknown): string {
  const code = e instanceof DirectoryError ? e.code : "";
  if (code.endsWith(":notShareable")) return "This badge can no longer be shown outside the community.";
  if (code.endsWith(":publicLocationUnavailable"))
    return "The community has no public address to show badges at yet. Try again later.";
  if (code.endsWith(":notFound")) return "That award is no longer yours to share.";
  return e instanceof Error ? e.message : "That did not work. Try again.";
}

/** Members named by their directory entry, as the directory shows them to this member. */
function OwnerNames({ entryIds }: { entryIds: string[] }) {
  const entries = useQuery({
    queryKey: ["directory", "entries", "names"],
    queryFn: () => listEntries({ limit: 100 }),
    retry: false,
    staleTime: 60_000,
  });
  const names = new Map((entries.data?.items ?? []).map((e) => [e.entryId, nameOf((e.fields ?? {}) as Record<string, unknown>)]));
  return (
    <>
      {entryIds.map((id, i) => (
        <span key={id}>
          {i > 0 ? ", " : ""}
          <a href={`#/directory/${encodeURIComponent(id)}`}>{names.get(id) ?? "A member"}</a>
        </span>
      ))}
    </>
  );
}

/** Asking a community badge's owners for it: a request to join its badge group. */
function AskForBadge({ badge, groupId, myState }: { badge: Badge; groupId: string; myState: string }) {
  const qc = useQueryClient();
  const [open, setOpen] = useState(false);
  const [message, setMessage] = useState("");
  const [note, setNote] = useState<string | null>(null);
  const refresh = () => {
    void qc.invalidateQueries({ queryKey: ["badges"] });
    void qc.invalidateQueries({ queryKey: ["groups"] });
  };
  const ask = useMutation({
    mutationFn: () => joinGroup(groupId, message.trim() || undefined),
    onSuccess: (a) => {
      setOpen(false);
      setMessage("");
      setNote(a.outcome === "joined" ? "You hold it. Your wallet receives its credential." : "Asked. The badge's owners decide; you're told either way.");
      refresh();
    },
    onError: (e) => setNote((e as Error).message),
  });
  const withdraw = useMutation({
    mutationFn: () => leaveGroup(groupId),
    onSuccess: () => {
      setNote("Your request is withdrawn.");
      refresh();
    },
    onError: (e) => setNote((e as Error).message),
  });
  if (myState === "holder" && !badge.repeatable) return null;
  if (!badge.requestable && myState !== "requested") return null;
  return (
    <div className="bw-ask">
      {note && (
        <p className="alert alert-info" role="status">
          {note}
        </p>
      )}
      {myState === "requested" ? (
        <>
          <p className="muted">You&rsquo;ve asked for this badge. Its owners decide.</p>
          <button type="button" className="btn btn-ghost btn-sm" onClick={() => withdraw.mutate()} disabled={withdraw.isPending}>
            Withdraw my request
          </button>
        </>
      ) : !open ? (
        <>
          <button type="button" className="btn btn-primary" onClick={() => setOpen(true)}>
            <MessageSquare size={16} aria-hidden="true" /> Ask for this badge
          </button>
          <p className="muted bw-fine">Your request goes to the badge&rsquo;s owners with a note from you. They decide.</p>
        </>
      ) : (
        <form
          className="card-form"
          onSubmit={(e) => {
            e.preventDefault();
            ask.mutate();
          }}
        >
          <label className="card-field">
            <span>Why you should have it</span>
            <textarea rows={3} value={message} maxLength={280} onChange={(e) => setMessage(e.target.value)} />
          </label>
          <p className="muted bw-fine">The owners see your name and this note, nothing else.</p>
          <div className="bw-actions">
            <button type="button" className="btn btn-ghost btn-sm" onClick={() => setOpen(false)}>
              Cancel
            </button>
            <button type="submit" className="btn btn-primary btn-sm" disabled={ask.isPending}>
              Send request
            </button>
          </div>
        </form>
      )}
    </div>
  );
}

/** A member search over the directory, as the member already sees it, naming one entry. */
function MemberSelect({ value, onChange, exclude }: { value: string; onChange: (entryId: string) => void; exclude?: string }) {
  const [query, setQuery] = useState("");
  const entries = useQuery({
    queryKey: ["directory", "entries", "search", query],
    queryFn: () => listEntries({ limit: 100, ...(query.trim() ? { query: query.trim() } : {}) }),
    retry: false,
    staleTime: 30_000,
  });
  const items = (entries.data?.items ?? []).filter((e) => e.entryId !== exclude);
  return (
    <div className="bw-member-select">
      <input
        type="search"
        aria-label="Find a member"
        placeholder="Find a member…"
        value={query}
        onChange={(e) => setQuery(e.target.value)}
      />
      <select aria-label="Member" value={value} onChange={(e) => onChange(e.target.value)} size={Math.min(6, Math.max(2, items.length + 1))}>
        <option value="">Choose a member…</option>
        {items.map((e) => (
          <option key={e.entryId} value={e.entryId}>
            {nameOf((e.fields ?? {}) as Record<string, unknown>) ?? "A member"}
          </option>
        ))}
      </select>
    </div>
  );
}

/** Give a kudos badge to another member. */
function GiveBadge({ badge, to: fixedTo, toName }: { badge: Badge; to?: string; toName?: string }) {
  const qc = useQueryClient();
  const [open, setOpen] = useState(Boolean(fixedTo));
  const [to, setTo] = useState(fixedTo ?? "");
  const [note, setNote] = useState("");
  const [said, setSaid] = useState<string | null>(null);
  const give = useMutation({
    mutationFn: () => giveKudos(badge.badgeId, to, note.trim() || undefined),
    onSuccess: () => {
      setSaid(`Offered${toName ? ` to ${toName}` : ""}. They're told you offered it and choose whether to take it.`);
      setNote("");
      if (!fixedTo) setTo("");
      void qc.invalidateQueries({ queryKey: ["badges"] });
    },
    onError: (e) => setSaid((e as Error).message),
  });
  return (
    <div className="bw-ask">
      {said && (
        <p className="alert alert-info" role="status">
          {said}
        </p>
      )}
      {!open ? (
        <button type="button" className="btn btn-primary" onClick={() => setOpen(true)}>
          <Gift size={16} aria-hidden="true" /> Give {badge.name}
        </button>
      ) : (
        <form
          className="card-form"
          onSubmit={(e) => {
            e.preventDefault();
            if (to) give.mutate();
          }}
        >
          {!fixedTo && (
            <div className="card-field">
              <span>To</span>
              <MemberSelect value={to} onChange={setTo} />
            </div>
          )}
          <label className="card-field">
            <span>A note (optional)</span>
            <input value={note} maxLength={500} onChange={(e) => setNote(e.target.value)} />
          </label>
          <div className="bw-actions">
            {!fixedTo && (
              <button type="button" className="btn btn-ghost btn-sm" onClick={() => setOpen(false)}>
                Cancel
              </button>
            )}
            <button type="submit" className="btn btn-primary btn-sm" disabled={!to || give.isPending}>
              <Gift size={14} aria-hidden="true" /> Offer badge
            </button>
          </div>
        </form>
      )}
    </div>
  );
}

// ─── make a badge ──────────────────────────────────────────────────────────

export function MakeBadgePage() {
  const { on, makers } = useBadgesOn();
  const qc = useQueryClient();
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [image, setImage] = useState<{ sha256: string; preview: string } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const upload = useMutation({
    mutationFn: async (file: File) => {
      const { mediaType, bytes } = await prepare(file);
      const answer = await uploadBadgeImage(mediaType, toBase64Url(bytes));
      return { sha256: answer.image.sha256, preview: URL.createObjectURL(file) };
    },
    onSuccess: (img) => {
      setError(null);
      setImage(img);
    },
    onError: (e) => setError(e instanceof PictureError || e instanceof DirectoryError ? e.message : "The picture couldn't be sent."),
  });
  const create = useMutation({
    mutationFn: () =>
      createKudosBadge({
        name: name.trim(),
        description: description.trim(),
        image: { sha256: image!.sha256 },
        reason: "made in the portal",
      }),
    onSuccess: (r) => {
      void qc.invalidateQueries({ queryKey: ["badges"] });
      window.location.hash = badgeHref(r.badge.badgeId);
    },
    onError: (e) => setError((e as Error).message),
  });
  if (on === false) return <Off />;
  const ok = name.trim() && description.trim() && image;
  return (
    <main className="home" id="main">
      <Crumbs trail={[{ label: "Badges", href: badgesHref }, { label: "Make a badge" }]} />
      <section className="welcome">
        <p className="eyebrow">Badges</p>
        <h1>Make a badge</h1>
        <p className="lead">
          A badge you make is a kudos badge: a picture and a name, no credential, that any member may give another.
          Members can see who made it and who holds it.
        </p>
      </section>
      {makers === "nobody" && <p className="alert">This community doesn&rsquo;t let members make badges.</p>}
      <form
        className="card card-form bw-make"
        onSubmit={(e) => {
          e.preventDefault();
          if (ok) create.mutate();
        }}
      >
        <label className="card-field">
          <span>Name</span>
          <input value={name} maxLength={64} onChange={(e) => setName(e.target.value)} />
          <small className="muted">Up to 64 characters. Shown on the wall.</small>
        </label>
        <label className="card-field">
          <span>What it is for</span>
          <textarea rows={2} value={description} maxLength={1000} onChange={(e) => setDescription(e.target.value)} />
        </label>
        <div className="card-field">
          <span>Picture</span>
          <div className="bw-upload">
            {image ? (
              <img className="bw-art" src={image.preview} alt="" style={{ width: 160 }} />
            ) : (
              <span className="bw-art bw-art-blank" aria-hidden="true" style={{ width: 120, height: 120 }}>
                <Award size={32} />
              </span>
            )}
            <div>
              <label className="btn btn-ghost btn-sm">
                <ImagePlus size={14} aria-hidden="true" /> {upload.isPending ? "Sending…" : image ? "Replace" : "Upload a picture"}
                <input
                  type="file"
                  accept="image/png,image/jpeg,image/webp"
                  aria-label="Choose a badge picture"
                  hidden
                  disabled={upload.isPending}
                  onChange={(e) => {
                    const file = e.target.files?.[0];
                    e.target.value = "";
                    if (file) upload.mutate(file);
                  }}
                />
              </label>
              <p className="muted bw-fine">
                Scaled and re-encoded by the community, with nothing about where or how it was made. Wide banners
                and squares both work; the wall keeps the picture&rsquo;s shape.
              </p>
            </div>
          </div>
        </div>
        {error && (
          <p className="alert" role="alert">
            {error}
          </p>
        )}
        <div className="bw-actions">
          <a className="btn btn-ghost btn-sm" href={badgesHref}>
            Cancel
          </a>
          <button type="submit" className="btn btn-primary btn-sm" disabled={!ok || create.isPending}>
            {create.isPending ? "Creating…" : "Create badge"}
          </button>
        </div>
      </form>
    </main>
  );
}

// ─── a member's wall, on their card ────────────────────────────────────────

/** The badges a member shows, on their directory card; and giving them a kudos badge. */
export function WallSection({ entryId, name, own }: { entryId: string; name: string | null; own: boolean }) {
  const { on, showTotals } = useBadgesOn();
  const wall = useQuery({ queryKey: ["badges", "wall", entryId], queryFn: () => showWall(entryId), retry: false, enabled: on === true });
  const kudos = useQuery({ queryKey: ["badges", "list", "kudos"], queryFn: () => listBadges("kudos"), retry: false, enabled: on === true && !own });
  const [giving, setGiving] = useState<Badge | null>(null);
  if (on !== true) return null;
  const entries = wall.data?.entries ?? [];
  const pinned = entries.filter((e) => e.pinned);
  const rest = entries.filter((e) => !e.pinned);
  const kudosBadges = (kudos.data?.items ?? []).map((i) => i.badge).filter((b) => b.state === "active");
  if (wall.isError && !own) return null;
  return (
    <section className="profile-section bw-on-card" aria-labelledby="bw-card-title">
      <div className="bw-section-head">
        <h2 id="bw-card-title">Badges</h2>
        {wall.data && (
          <span className="muted">
            {entries.length === 0 ? "none shown" : `${entries.length} shown`}
            {showTotals && typeof wall.data.kudosTotal === "number" ? ` · ${wall.data.kudosTotal} kudos received` : ""}
          </span>
        )}
        {own && (
          <a className="btn btn-ghost btn-sm" href={badgesHref}>
            Arrange your badges
          </a>
        )}
      </div>
      {wall.isError && own && <p className="muted">Sign in with your wallet to see your badges here.</p>}
      {wall.data && entries.length === 0 && <p className="muted">{own ? "Nothing on your card yet." : "No badges shown."}</p>}
      {pinned.length > 0 && (
        <div className="bw-wall bw-pinned-row">
          {pinned.map((e) => (
            <BadgeTile key={e.badge.badgeId} badge={e.badge} count={e.count} pinned width={130} />
          ))}
        </div>
      )}
      {rest.length > 0 && (
        <div className="bw-wall">
          {rest.map((e) => (
            <BadgeTile key={e.badge.badgeId} badge={e.badge} count={e.count} width={110} />
          ))}
        </div>
      )}
      {!own && kudosBadges.length > 0 && (
        <div className="bw-give-card">
          {!giving ? (
            <>
              <p className="muted">Give {name ?? "this member"} a badge:</p>
              <div className="bw-wall">
                {kudosBadges.map((b) => (
                  <button key={b.badgeId} type="button" className="bw-pick" onClick={() => setGiving(b)} title={b.description}>
                    <BadgeArt badge={b} width={80} />
                    <span>{b.name}</span>
                  </button>
                ))}
              </div>
            </>
          ) : (
            <div className="bw-giving">
              <div className="bw-giving-head">
                <BadgeArt badge={giving} width={90} />
                <strong>{giving.name}</strong>
                <button type="button" className="btn btn-ghost btn-xs" onClick={() => setGiving(null)} aria-label="Choose another badge">
                  <X size={14} aria-hidden="true" /> Another
                </button>
              </div>
              <GiveBadge badge={giving} to={entryId} toName={name ?? undefined} />
            </div>
          )}
        </div>
      )}
    </section>
  );
}
