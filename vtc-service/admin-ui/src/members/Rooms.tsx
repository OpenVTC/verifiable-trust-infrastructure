// Data rooms in the member portal: the rooms a member shared with this portal,
// and one room's records and files.
//
// Everything here goes through the member's wallet (`wallet-rooms.ts`): this
// page holds no key, the portal's server sees no room content, and the wallet
// decides what this page may see. A room appears here only once the member
// shared it with this portal in their wallet's own window, and every note or
// file they add is confirmed there first. Design:
// `docs/05-design-notes/data-rooms-files.md` §8.5.

import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowLeft, Boxes, Download, Eye, FileText, FilePlus2, Gift, NotebookPen, RefreshCw, Share2 } from "lucide-react";

import { blobBytes, createLimiter, mayPreview, showBytes, worthAutoPreview, type Shown } from "./file-preview";
import { InstallWallet } from "./InstallWallet";
import {
  actionableOffers,
  offerDeclined,
  settledOffers,
  adverseVerification,
  fileWontFit,
  formatBytes,
  openFailure,
  roomName,
  shareRefusalHint,
  walletRooms,
  type OfferAccepted,
  type PageOffer,
  type PageRoom,
  type RoomInfo,
  type RoomRecord,
  type TransferProgress,
  type WalletRooms,
} from "./wallet-rooms";

function shortDid(did: string): string {
  return did.length > 40 ? `${did.slice(0, 22)}…${did.slice(-10)}` : did;
}

function errorText(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

/** A room's address in the portal. */
export function roomHref(roomId: string): string {
  return `#/rooms/${encodeURIComponent(roomId)}`;
}

function NoWallet() {
  return (
    <section className="card" aria-labelledby="no-wallet-heading">
      <div className="card-head">
        <Boxes size={18} aria-hidden="true" />
        <h2 id="no-wallet-heading">Your rooms are in your wallet</h2>
      </div>
      <p className="muted">
        Data rooms open through your VTA Wallet browser extension, which holds nothing this site can read: it acts
        in a room as you, through your own agent, and shows you each thing you add before it is added. Install it,
        or allow it on this site from its popup, then reload this page.
      </p>
      <InstallWallet open={false} />
    </section>
  );
}

// ── The list ────────────────────────────────────────────────────────────────

/** `member`: the DID signed in to this portal — who the wallet should act as here. */
export function RoomsPage({ hostDid, member }: { hostDid: string; member?: string }) {
  const wallet = walletRooms();
  return (
    <main className="home" id="main">
      <p>
        <a href="#/" className="back">
          <ArrowLeft size={14} aria-hidden="true" /> Home
        </a>
      </p>
      <section className="welcome">
        <p className="eyebrow">Member portal</p>
        <h1>Data rooms</h1>
        <p className="lead">
          The rooms you have shared with this portal. Their contents are encrypted for the room's members; this
          site shows them only through your wallet.
        </p>
      </section>
      {wallet ? (
        <>
          <OfferList wallet={wallet} hostDid={hostDid} member={member} />
          <RoomList wallet={wallet} hostDid={hostDid} member={member} />
        </>
      ) : (
        <NoWallet />
      )}
    </main>
  );
}

// ── Offers ──────────────────────────────────────────────────────────────────

/** The longest room description the page shows: the schema's own bound (`RoomDescription`). */
const MAX_OFFER_DESCRIPTION = 1000;

/**
 * An offer's room description, as text: the wallet's, trimmed and cut to the
 * schema's bound. React renders it as a text node, never as markup.
 */
function offerDescription(o: PageOffer): string {
  if (typeof o.description !== "string") return "";
  return [...o.description.trim()].slice(0, MAX_OFFER_DESCRIPTION).join("");
}

/**
 * This community's offers of its rooms to the member, through their wallet.
 * The page lists what the wallet shows it — never an offer's credentials — and
 * asks; the member accepts in the wallet's own window, which names the room and
 * the identity it joins as. Shown only when something is waiting, and only by a
 * wallet that can do it.
 */
function OfferList({ wallet, hostDid, member }: { wallet: WalletRooms; hostDid: string; member?: string }) {
  const qc = useQueryClient();
  const [done, setDone] = useState<{ offer: PageOffer; result: OfferAccepted } | null>(null);
  const supported = typeof wallet.offers === "function" && typeof wallet.acceptOffer === "function";
  const offers = useQuery({
    queryKey: ["member-room-offers", hostDid],
    queryFn: async () => wallet.offers!({ hostDid }),
    enabled: supported,
  });
  const accept = useMutation({
    mutationFn: async (o: PageOffer) => ({
      offer: o,
      result: await wallet.acceptOffer!({ hostDid, roomId: o.roomId, member: o.member }),
    }),
    onSuccess: (r) => {
      setDone(r);
      void qc.invalidateQueries({ queryKey: ["member-room-offers", hostDid] });
    },
  });
  // The rooms already shared with this portal: the same query as the list below, so one
  // wallet call answers both. A joined room that is here opens directly.
  const shared = useQuery({
    queryKey: ["member-rooms", hostDid],
    queryFn: async () => (await wallet.list({ hostDid })).rooms,
  });
  const isShared = (roomId: string) => shared.data?.some((r) => r.roomId === roomId) ?? false;
  // Sharing is the wallet letting this portal see the room; once it has, go to it.
  const share = useMutation({
    mutationFn: (roomId: string) => wallet.choose({ hostDid, suggest: roomId, ...(member ? { member } : {}) }),
    onSuccess: (r, roomId) => {
      qc.setQueryData(["member-rooms", hostDid], r.rooms);
      if (r.rooms.some((room) => room.roomId === roomId)) window.location.hash = roomHref(roomId);
    },
  });

  if (!supported || offers.isPending) return null;
  if (offers.isError) {
    return (
      <section className="card" aria-labelledby="offers-heading">
        <div className="card-head">
          <Gift size={18} aria-hidden="true" />
          <h2 id="offers-heading">Offers from this community</h2>
        </div>
        <p className="muted">Your wallet could not read this community's offers: {errorText(offers.error)}</p>
      </section>
    );
  }
  const waiting = actionableOffers(offers.data.offers);
  const settled = settledOffers(offers.data.offers);
  if (waiting.length === 0 && settled.length === 0 && !done && !offers.data.needsOrigin) return null;
  // The acceptance just made, until the list shows it: then its own row says the same.
  const doneListed =
    done !== null &&
    settled.some((o) => o.roomId === done.offer.roomId && o.member === done.offer.member && o.state === "joined");

  return (
    <section className="card" aria-labelledby="offers-heading">
      <div className="card-head">
        <Gift size={18} aria-hidden="true" />
        <h2 id="offers-heading">Rooms from this community</h2>
      </div>
      {offers.data.needsOrigin ? (
        <p className="muted">
          Your wallet has not been allowed to reach this community yet, so it cannot read its offers. Allow it from
          the wallet's console (Data rooms → Offers), or share a room with this portal.
        </p>
      ) : (
        <p className="muted">
          Every room the community has offered you, and where each stands — the same as your wallet and your other
          apps show. Accepting is your decision in your wallet, which shows you the room and the identity you join
          as before anything happens.
        </p>
      )}
      {waiting.length > 0 && (
        <ul className="room-list">
          {waiting.map((o) => (
            <li key={`${o.roomId}|${o.member}`}>
              <span>
                {o.label ? <strong className="wrap">{o.label}</strong> : <code className="wrap">{shortDid(o.roomId)}</code>}
              </span>
              {offerDescription(o) && <span className="muted wrap">{offerDescription(o)}</span>}
              <span className="muted small">
                {o.visibility} · {o.actions.join(", ")} · until {new Date(o.validUntil).toLocaleDateString()}
                {o.member === member ? " · as you" : ` · as ${shortDid(o.member)}`}
                {o.state === "unfinished" ? " · accepted, not finished — finish it here" : ""}
              </span>
              <div className="actions">
                <button
                  type="button"
                  className="btn btn-primary"
                  onClick={() => accept.mutate(o)}
                  disabled={accept.isPending}
                >
                  {accept.isPending && accept.variables?.roomId === o.roomId
                    ? "Waiting for your wallet…"
                    : o.state === "unfinished"
                      ? "Finish accepting…"
                      : "Accept…"}
                </button>
              </div>
            </li>
          ))}
        </ul>
      )}
      {settled.length > 0 && (
        <ul className="room-list" aria-label="Rooms you have answered">
          {settled.map((o) => (
            <li key={`${o.roomId}|${o.member}`}>
              <span>
                {o.label ? <strong className="wrap">{o.label}</strong> : <code className="wrap">{shortDid(o.roomId)}</code>}
              </span>
              <span className="muted small">
                {o.visibility} · {o.member === member ? "as you" : `as ${shortDid(o.member)}`} ·{" "}
                {o.state === "joined"
                  ? "joined"
                  : o.state === "removed"
                    ? `removed${o.removedAt ? ` ${new Date(o.removedAt).toLocaleDateString()}` : ""}`
                    : "needs re-admission"}
              </span>
              {o.state === "needsReadmission" && (
                <span className="muted small">
                  Your agent never joined this room, and the community no longer keeps what it needs to finish. Ask
                  an administrator to remove and re-admit you.
                </span>
              )}
              {o.state === "joined" && openHere(o.roomId)}
            </li>
          ))}
        </ul>
      )}
      {accept.isError &&
        (offerDeclined(accept.error) ? (
          <p className="muted" role="status">
            Not accepted. The offer stays open.
          </p>
        ) : (
          <p className="error" role="alert">
            {errorText(accept.error)}
          </p>
        ))}
      {done && !doneListed && (
        <div className="alert alert-info" role="status">
          <p className="alert-title">
            {done.result.joined ? "Joined" : "Accepted"} {done.offer.label || shortDid(done.offer.roomId)}
          </p>
          {done.result.joined && openHere(done.offer.roomId)}
        </div>
      )}
      {share.isError && (
        <p className="error" role="alert">
          {errorText(share.error)}
        </p>
      )}
    </section>
  );

  /** Open a joined room here: directly once shared, else through the wallet's window first. */
  function openHere(roomId: string) {
    if (isShared(roomId)) {
      return (
        <div className="actions">
          <a className="btn" href={roomHref(roomId)}>
            Open
          </a>
        </div>
      );
    }
    return (
      <div className="actions">
        <button type="button" className="btn" onClick={() => share.mutate(roomId)} disabled={share.isPending}>
          <Share2 size={14} aria-hidden="true" />{" "}
          {share.isPending && share.variables === roomId ? "Waiting for your wallet…" : "Open it here…"}
        </button>
        <span className="muted small">Your wallet asks before this portal can see the room.</span>
      </div>
    );
  }
}

function RoomList({ wallet, hostDid, member }: { wallet: WalletRooms; hostDid: string; member?: string }) {
  const qc = useQueryClient();
  const [refused, setRefused] = useState<{ roomId: string; reason: string }[]>([]);
  const list = useQuery({
    queryKey: ["member-rooms", hostDid],
    queryFn: async () => (await wallet.list({ hostDid })).rooms,
  });
  const choose = useMutation({
    // Who is signed in here, so the wallet picks that identity among the ones it
    // holds for this community. It never adds one on the page's word.
    mutationFn: () => wallet.choose({ hostDid, ...(member ? { member } : {}) }),
    onSuccess: (r) => {
      setRefused(r.refused);
      qc.setQueryData(["member-rooms", hostDid], r.rooms);
    },
  });

  return (
    <section className="card" aria-labelledby="rooms-heading">
      <div className="card-head">
        <Boxes size={18} aria-hidden="true" />
        <h2 id="rooms-heading">Your rooms here</h2>
      </div>
      {list.isPending ? (
        <p className="muted">Asking your wallet…</p>
      ) : list.isError ? (
        <div className="alert" role="alert">
          <p className="alert-title">Your wallet did not list your rooms.</p>
          <p>{errorText(list.error)}</p>
        </div>
      ) : list.data.length === 0 ? (
        <p className="empty">
          You have not shared any rooms with this portal. Your wallet lists the rooms your agent holds, and you
          choose which belong to this community.
        </p>
      ) : (
        <ul className="room-list">
          {list.data.map((r) => (
            <RoomRow key={`${r.roomId}|${r.member ?? ""}`} room={r} me={member} />
          ))}
        </ul>
      )}
      {refused.length > 0 && (
        <div className="alert" role="status">
          <p className="alert-title">Not shared</p>
          <ul>
            {refused.map((r) => {
              const hint = shareRefusalHint(r.reason);
              const name = roomName(list.data?.find((s) => s.roomId === r.roomId));
              return (
                <li key={r.roomId}>
                  {name ? <b>{name}</b> : <code className="wrap">{shortDid(r.roomId)}</code>}: {hint ?? r.reason}
                  {hint && <span className="muted small"> ({r.reason})</span>}
                </li>
              );
            })}
          </ul>
        </div>
      )}
      {choose.isError && (
        <p className="error" role="alert">
          {errorText(choose.error)}
        </p>
      )}
      <div className="actions">
        <button type="button" className="btn btn-primary" onClick={() => choose.mutate()} disabled={choose.isPending}>
          <Share2 size={14} aria-hidden="true" /> {choose.isPending ? "Waiting for your wallet…" : "Share rooms…"}
        </button>
      </div>
    </section>
  );
}

function RoomRow({ room, me }: { room: PageRoom; me?: string }) {
  // A community room by the name its administrators gave it, the DID beneath;
  // any other room by its DID.
  const name = roomName(room);
  return (
    <li>
      <a href={roomHref(room.roomId)} className="room-link">
        {name ? <span className="room-name">{name}</span> : <code className="wrap">{shortDid(room.roomId)}</code>}
      </a>
      {name && (
        <code className="wrap muted small" title={room.roomId}>
          {shortDid(room.roomId)}
        </code>
      )}
      <span className="muted small">
        {room.held
          ? `epoch ${room.epoch ?? "?"}${room.earliestReadableEpoch && room.earliestReadableEpoch > 1 ? ` · history from epoch ${room.earliestReadableEpoch}` : ""}`
          : "your agent no longer holds this room's keys"}
        {room.member ? (room.member === me ? " · as you" : ` · as ${shortDid(room.member)}`) : ""}
        {" · shared until "}
        {new Date(room.expiresAt).toLocaleDateString()}
      </span>
    </li>
  );
}

// ── One room ────────────────────────────────────────────────────────────────

export function RoomPage({ hostDid, roomId }: { hostDid: string; roomId: string }) {
  const wallet = walletRooms();
  return (
    <main className="home" id="main">
      <p>
        <a href="#/rooms" className="back">
          <ArrowLeft size={14} aria-hidden="true" /> Data rooms
        </a>
      </p>
      <section className="welcome">
        <p className="eyebrow">Data room</p>
        {wallet ? (
          <RoomHeading wallet={wallet} hostDid={hostDid} roomId={roomId} />
        ) : (
          <h1 className="wrap room-title">{shortDid(roomId)}</h1>
        )}
      </section>
      {wallet ? <Room wallet={wallet} hostDid={hostDid} roomId={roomId} /> : <NoWallet />}
    </main>
  );
}

/** The room's name over its DID when the wallet knows one — from the same list the rooms page reads. */
function RoomHeading({ wallet, hostDid, roomId }: { wallet: WalletRooms; hostDid: string; roomId: string }) {
  const list = useQuery({
    queryKey: ["member-rooms", hostDid],
    queryFn: async () => (await wallet.list({ hostDid })).rooms,
  });
  const name = roomName(list.data?.find((r) => r.roomId === roomId));
  if (!name) return <h1 className="wrap room-title">{shortDid(roomId)}</h1>;
  return (
    <>
      <h1 className="wrap">{name}</h1>
      <p className="muted small">
        <code className="wrap" title={roomId}>
          {roomId}
        </code>
      </p>
    </>
  );
}

function Room({ wallet, hostDid, roomId }: { wallet: WalletRooms; hostDid: string; roomId: string }) {
  const info = useQuery({
    queryKey: ["member-room-info", roomId],
    queryFn: () => wallet.info({ hostDid, roomId }),
  });
  const [open, setOpen] = useState<string | null>(null);

  if (info.isPending) return <p className="muted">Asking your wallet…</p>;
  if (info.isError) {
    return (
      <div className="alert" role="alert">
        <p className="alert-title">This room did not open.</p>
        <p>{errorText(info.error)}</p>
        <p>
          If you have not shared it with this portal, go back and choose <b>Share rooms…</b>.
        </p>
      </div>
    );
  }
  return (
    <div className="grid room-grid">
      <RoomFacts info={info.data} />
      <Records wallet={wallet} hostDid={hostDid} roomId={roomId} open={open} setOpen={setOpen} />
      {open ? (
        <RecordView wallet={wallet} hostDid={hostDid} roomId={roomId} recordKey={open} />
      ) : (
        <AddToRoom wallet={wallet} hostDid={hostDid} info={info.data} />
      )}
    </div>
  );
}

function Meter({ label, used, max }: { label: string; used: number; max?: number }) {
  return (
    <div>
      <dt>{label}</dt>
      <dd>
        {formatBytes(used)}
        {max !== undefined ? ` of ${formatBytes(max)}` : ""}
      </dd>
    </div>
  );
}

function RoomFacts({ info }: { info: RoomInfo }) {
  const mine = info.usage.member;
  return (
    <section className="card" aria-labelledby="room-facts-heading">
      <div className="card-head">
        <Boxes size={18} aria-hidden="true" />
        <h2 id="room-facts-heading">This room</h2>
      </div>
      <dl className="facts">
        <div>
          <dt>Tier</dt>
          <dd className="cap">{info.visibility}</dd>
        </div>
        <div>
          <dt>Epoch</dt>
          <dd>{info.epoch}</dd>
        </div>
        <div>
          <dt>You, here</dt>
          <dd>
            <code className="wrap">{info.member}</code>
          </dd>
        </div>
        <Meter label="Room storage" used={info.usage.room.bytes} max={info.limits.room?.maxBytes} />
        {mine && <Meter label="Your storage" used={mine.usage.bytes} max={mine.limits.maxBytes} />}
      </dl>
      {info.visibility === "attributed" && (
        <p className="muted small">
          On an attributed room the community hosting it sees which member added what, and when — never what it
          says.
        </p>
      )}
    </section>
  );
}

function Records({
  wallet,
  hostDid,
  roomId,
  open,
  setOpen,
}: {
  wallet: WalletRooms;
  hostDid: string;
  roomId: string;
  open: string | null;
  setOpen: (k: string | null) => void;
}) {
  const listing = useQuery({
    queryKey: ["member-room-records", roomId],
    queryFn: () => wallet.browse({ hostDid, roomId }),
  });
  const warning = listing.data ? adverseVerification(listing.data.verification) : null;
  return (
    <section className="card" aria-labelledby="records-heading">
      <div className="card-head">
        <FileText size={18} aria-hidden="true" />
        <h2 id="records-heading">Records</h2>
        <button
          type="button"
          className="btn btn-ghost btn-sm push"
          onClick={() => void listing.refetch()}
          aria-label="Refresh"
        >
          <RefreshCw size={14} aria-hidden="true" />
        </button>
      </div>
      {warning && (
        <div className="alert" role="alert">
          <p className="alert-title">The host's listing does not add up.</p>
          <p>{warning} Your wallet still shows what it was given.</p>
        </div>
      )}
      {listing.isPending ? (
        <p className="muted">Reading the room…</p>
      ) : listing.isError ? (
        <p className="error" role="alert">
          {errorText(listing.error)}
        </p>
      ) : listing.data.records.length === 0 ? (
        <p className="empty">Nothing in this room yet.</p>
      ) : (
        <ul className="record-list">
          {[...listing.data.records]
            .sort((a, b) => b.version - a.version)
            .map((r, i) => (
              <li key={r.key} className={open === r.key ? "selected" : undefined}>
                <button type="button" className="record-link" onClick={() => setOpen(open === r.key ? null : r.key)}>
                  <RecordTitle
                    wallet={wallet}
                    hostDid={hostDid}
                    roomId={roomId}
                    summary={r}
                    autoOpen={i < AUTO_OPEN}
                  />
                </button>
                <span className="muted small">
                  v{r.version} · {new Date(r.updatedAt).toLocaleString()}
                  {r.author ? ` · ${shortDid(r.author)}` : ""}
                  {r.status && r.status !== "active" ? ` · ${r.status}` : ""}
                </span>
                {i < AUTO_OPEN && (
                  <RecordThumbnail
                    wallet={wallet}
                    hostDid={hostDid}
                    roomId={roomId}
                    recordKey={r.key}
                    onOpen={() => setOpen(r.key)}
                  />
                )}
              </li>
            ))}
        </ul>
      )}
      {listing.data && !listing.data.complete && (
        <p className="muted small">The listing stopped at a page bound; older records are not shown.</p>
      )}
    </section>
  );
}

/** How many of the newest sealed records are opened for their titles without a click. A
 *  listing carries metadata only, so each title is one read through the wallet. */
const AUTO_OPEN = 25;

/** A row's title: an open room's from the listing, a sealed room's opened by the wallet. */
function RecordTitle({
  wallet,
  hostDid,
  roomId,
  summary,
  autoOpen,
}: {
  wallet: WalletRooms;
  hostDid: string;
  roomId: string;
  summary: { key: string; title?: string; status?: string };
  autoOpen: boolean;
}) {
  const sealed = summary.title === undefined && summary.status !== "retracted";
  const rec = useQuery({
    queryKey: ["member-room-record", roomId, summary.key],
    queryFn: () => wallet.read({ hostDid, roomId, key: summary.key }),
    enabled: sealed && autoOpen,
    staleTime: Infinity,
  });
  if (!sealed) return <span>{summary.title ?? "(retracted)"}</span>;
  if (!autoOpen && !rec.data) return <span className="muted">Sealed record — open it</span>;
  if (rec.isPending) return <span className="muted">Opening…</span>;
  if (rec.isError) {
    const why = openFailure(rec.error);
    return (
      <span className="error" title={why?.hint ?? errorText(rec.error)}>
        {why?.label ?? "Did not open"}
      </span>
    );
  }
  return (
    <span>
      {rec.data.file ? <FileText size={13} aria-hidden="true" /> : <NotebookPen size={13} aria-hidden="true" />}{" "}
      {rec.data.title || rec.data.file?.name || "(untitled)"}
    </span>
  );
}

function RecordView({
  wallet,
  hostDid,
  roomId,
  recordKey,
}: {
  wallet: WalletRooms;
  hostDid: string;
  roomId: string;
  recordKey: string;
}) {
  const rec = useQuery({
    queryKey: ["member-room-record", roomId, recordKey],
    queryFn: () => wallet.read({ hostDid, roomId, key: recordKey }),
    staleTime: Infinity,
  });
  return (
    <section className="card" aria-labelledby="record-heading">
      <div className="card-head">
        <NotebookPen size={18} aria-hidden="true" />
        <h2 id="record-heading">{rec.data?.title || rec.data?.file?.name || "Record"}</h2>
      </div>
      {rec.isPending ? (
        <p className="muted">Opening…</p>
      ) : rec.isError ? (
        <RecordRefused error={rec.error} />
      ) : (
        <RecordBody wallet={wallet} hostDid={hostDid} roomId={roomId} rec={rec.data} />
      )}
    </section>
  );
}

/** Why a record did not open: in a member's words where the reason is known, the agent's beside it. */
function RecordRefused({ error }: { error: unknown }) {
  const why = openFailure(error);
  return (
    <div className={why ? "alert alert-info" : "alert"} role={why ? "status" : "alert"}>
      <p className="alert-title">{why?.label ?? "This record did not open."}</p>
      {why && <p>{why.hint}</p>}
      <p className={why ? "muted small" : undefined}>{errorText(error)}</p>
    </div>
  );
}

function RecordBody({
  wallet,
  hostDid,
  roomId,
  rec,
}: {
  wallet: WalletRooms;
  hostDid: string;
  roomId: string;
  rec: RoomRecord;
}) {
  if (rec.status === "retracted") return <p className="empty">This record was retracted.</p>;
  return (
    <>
      <dl className="facts">
        {rec.author && (
          <div>
            <dt>By</dt>
            <dd>
              <code className="wrap">{rec.author}</code>
            </dd>
          </div>
        )}
        <div>
          <dt>Version</dt>
          <dd>
            {rec.version} · {new Date(rec.updatedAt).toLocaleString()}
          </dd>
        </div>
      </dl>
      {!rec.sealed && (
        <p className="muted small">This room is open: its host can read and store this text as it likes.</p>
      )}
      {rec.description && <p>{rec.description}</p>}
      {/* Another member's words: rendered as text, never as markup. */}
      {rec.body && <div className="note-body">{rec.body}</div>}
      {rec.tags && rec.tags.length > 0 && (
        <p className="muted small">{rec.tags.map((t) => `#${t}`).join(" ")}</p>
      )}
      {rec.file && <FileBox wallet={wallet} hostDid={hostDid} roomId={roomId} rec={rec} />}
    </>
  );
}

// ── Files ───────────────────────────────────────────────────────────────────

/** What the wallet hands over for a file: verified bytes and the record's account of them. */
type GotFile = Awaited<ReturnType<WalletRooms["getFile"]>>;

/** Thumbnails fetched unasked: two at a time, so a big room does not fire dozens of
 *  reads at the member's agent, and a click is not stuck behind them. */
const THUMBNAILS = createLimiter(2);

/** How long a fetched file stays in memory once nothing on the page shows it. */
const FILE_CACHE_MS = 60_000;

/**
 * One verified fetch per record version, shared by the thumbnail, the preview
 * and the download — so a picture shown in the list is not read again to save
 * it. Always `wallet.getFile`: the portal reads no room content any other way.
 * `auto` fetches unasked, through the thumbnail queue; `fetchNow` is a click's.
 */
function useRoomFile(
  wallet: WalletRooms,
  hostDid: string,
  roomId: string,
  rec: { key: string; version: number },
  auto: boolean,
) {
  const qc = useQueryClient();
  const queryKey = ["member-room-file", roomId, rec.key, rec.version];
  const [progress, setProgress] = useState<TransferProgress | null>(null);
  const got = useQuery({
    queryKey,
    // A row scrolled away or a page left before its turn is not fetched.
    queryFn: ({ signal }) =>
      THUMBNAILS.run(async () => {
        if (signal.aborted) throw new Error("no longer shown");
        return wallet.getFile({ hostDid, roomId, key: rec.key });
      }),
    enabled: auto,
    staleTime: Infinity,
    gcTime: FILE_CACHE_MS,
    retry: false,
  });
  const fetchNow = (): Promise<GotFile> =>
    qc
      .fetchQuery({
        queryKey,
        queryFn: () => wallet.getFile({ hostDid, roomId, key: rec.key, onProgress: setProgress }),
        staleTime: Infinity,
        gcTime: FILE_CACHE_MS,
        retry: false,
      })
      .finally(() => setProgress(null));
  return { got, fetchNow, progress };
}

/** A file name another member chose, safe to offer as a download name. */
export function downloadName(name: string): string {
  const base = name.split(/[\\/]/).pop()?.replace(/^\.+/, "").replace(/[\u0000-\u001f]/g, "").trim() ?? "";
  return base || "room-file";
}

/** Hand a verified file to the member, under a name that cannot choose where it lands. */
function saveFile(got: GotFile): void {
  const url = URL.createObjectURL(got.blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = downloadName(got.file.name);
  a.rel = "noopener";
  document.body.appendChild(a);
  a.click();
  a.remove();
  // The download has its own reference by now; this one only holds memory.
  setTimeout(() => URL.revokeObjectURL(url), 60_000);
}

/**
 * What a verified file is shown as, once its bytes are read — or `null` until
 * then. Decided by the bytes alone (`file-preview.ts`).
 */
function useShown(blob: Blob | undefined): Shown | null {
  const [state, setState] = useState<{ blob: Blob; shown: Shown } | null>(null);
  useEffect(() => {
    if (!blob) return;
    let live = true;
    blobBytes(blob).then(
      (bytes) => live && setState({ blob, shown: showBytes(bytes) }),
      () => live && setState({ blob, shown: { kind: "none" } }),
    );
    return () => {
      live = false;
    };
  }, [blob]);
  return state && state.blob === blob ? state.shown : null;
}

/** A verified picture, drawn from a `data:` URL typed by its bytes. */
function PreviewImage({ url, name, className }: { url: string; name: string; className: string }) {
  return <img className={className} src={url} alt={name} decoding="async" />;
}

/** Text from a verified file: a text node in a scrollable `<pre>`, never markup. */
function PreviewText({ text, cut }: { text: string; cut: boolean }) {
  return (
    <pre className="file-text" aria-label="File preview">
      {text}
      {cut ? "\n…" : ""}
    </pre>
  );
}

/**
 * A small picture's thumbnail in the record list, fetched unasked through the
 * wallet (one queued read per row; see `THUMBNAILS`). Only pictures are drawn
 * here: text, and bytes that turn out to be no picture whatever the record
 * claims, wait for the record's own view.
 */
function RecordThumbnail({
  wallet,
  hostDid,
  roomId,
  recordKey,
  onOpen,
}: {
  wallet: WalletRooms;
  hostDid: string;
  roomId: string;
  recordKey: string;
  onOpen: () => void;
}) {
  // Reads only what the row's title already opened; never a read of its own.
  const rec = useQuery({
    queryKey: ["member-room-record", roomId, recordKey],
    queryFn: () => wallet.read({ hostDid, roomId, key: recordKey }),
    enabled: false,
    staleTime: Infinity,
  });
  const data = rec.data;
  if (!data?.file || data.status === "retracted" || !worthAutoPreview(data.file)) return null;
  return <Thumbnail wallet={wallet} hostDid={hostDid} roomId={roomId} rec={data} onOpen={onOpen} />;
}

function Thumbnail({
  wallet,
  hostDid,
  roomId,
  rec,
  onOpen,
}: {
  wallet: WalletRooms;
  hostDid: string;
  roomId: string;
  rec: RoomRecord;
  onOpen: () => void;
}) {
  const { got } = useRoomFile(wallet, hostDid, roomId, rec, true);
  const shown = useShown(got.data?.blob);
  const name = rec.file?.name ?? "file";
  if (got.isError) return <p className="error small">No preview: {errorText(got.error)}</p>;
  if (!got.data || !shown) {
    return (
      <span className="thumb-loading" aria-label="Loading a preview">
        Loading preview…
      </span>
    );
  }
  if (shown.kind !== "image") return null;
  return (
    <button type="button" className="thumb" onClick={onOpen} aria-label={`Open ${name}`}>
      <PreviewImage url={shown.url} name={name} className="thumb-img" />
    </button>
  );
}

/**
 * A record's file: its preview, and its download.
 *
 * One verified fetch serves the thumbnail, the preview and the download: the
 * bytes reach this page only after the wallet has matched every one against the
 * digest the author signed, and a preview is chosen from those bytes, never
 * from the record's claimed type (`file-preview.ts`). A small picture is
 * fetched without a click; anything else waits for Preview or Download.
 */
function FileBox({
  wallet,
  hostDid,
  roomId,
  rec,
}: {
  wallet: WalletRooms;
  hostDid: string;
  roomId: string;
  rec: RoomRecord;
}) {
  const file = rec.file!;
  const auto = worthAutoPreview(file);
  const { got, fetchNow, progress } = useRoomFile(wallet, hostDid, roomId, rec, auto);
  const [saved, setSaved] = useState(false);
  const preview = useMutation({ mutationFn: fetchNow });
  const download = useMutation({
    mutationFn: fetchNow,
    onSuccess: (res) => {
      saveFile(res);
      setSaved(true);
    },
  });
  const shown = useShown(got.data?.blob);
  const busy = preview.isPending || download.isPending || got.isFetching;
  const error = download.error ?? preview.error ?? (got.data ? null : got.error);
  return (
    <div className="file-box">
      <p>
        <FileText size={14} aria-hidden="true" /> <b className="wrap">{file.name}</b> · {formatBytes(file.size)}
        {file.mediaType ? ` · ${file.mediaType}` : ""}
      </p>
      {busy && !got.data && auto && !download.isPending && (
        <span className="thumb-loading" aria-label="Loading a preview">
          Loading preview…
        </span>
      )}
      {shown?.kind === "image" && <PreviewImage url={shown.url} name={file.name} className="file-preview-img" />}
      {shown?.kind === "text" && <PreviewText text={shown.text} cut={shown.cut} />}
      {shown?.kind === "none" && (
        <p className="muted small">No preview for this kind of file. Download it to open it.</p>
      )}
      <div className="actions">
        <button
          type="button"
          className="btn btn-primary"
          onClick={() => download.mutate()}
          disabled={download.isPending}
        >
          <Download size={14} aria-hidden="true" />{" "}
          {download.isPending ? describe(progress) : saved ? "Download again" : "Download"}
        </button>
        {!got.data && !auto && mayPreview(file) && (
          <button type="button" className="btn" onClick={() => preview.mutate()} disabled={busy}>
            <Eye size={14} aria-hidden="true" /> {preview.isPending ? describe(progress) : "Preview"}
          </button>
        )}
      </div>
      {error && (
        <p className="error" role="alert">
          {errorText(error)}
        </p>
      )}
      {got.data ? (
        <p className="muted small">
          ✓ Every byte matches the digest its author signed. Its type is the author&rsquo;s word for it — open it
          with that in mind.
        </p>
      ) : (
        <p className="muted small">
          Decrypted in your wallet and checked against what its author signed before this page receives a byte.
        </p>
      )}
    </div>
  );
}

function describe(p: TransferProgress | null): string {
  if (!p) return "Starting…";
  const words: Record<string, string> = {
    checking: "Checking the room",
    sealing: "Encrypting",
    uploading: "Uploading",
    writing: "Writing the record",
    reading: "Reading the record",
    downloading: "Downloading",
    verifying: "Verifying",
  };
  const w = words[p.stage] ?? p.stage;
  return p.done !== undefined && p.total ? `${w} ${p.done}/${p.total}` : `${w}…`;
}

// ── Adding ──────────────────────────────────────────────────────────────────

function AddToRoom({ wallet, hostDid, info }: { wallet: WalletRooms; hostDid: string; info: RoomInfo }) {
  const qc = useQueryClient();
  const roomId = info.roomId;
  const [title, setTitle] = useState("");
  const [body, setBody] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [progress, setProgress] = useState<TransferProgress | null>(null);
  const [done, setDone] = useState<string | null>(null);

  const refresh = () => {
    void qc.invalidateQueries({ queryKey: ["member-room-records", roomId] });
    void qc.invalidateQueries({ queryKey: ["member-room-info", roomId] });
  };
  const note = useMutation({
    mutationFn: () => wallet.putNote({ hostDid, roomId, title: title.trim(), ...(body ? { body } : {}) }),
    onSuccess: () => {
      setTitle("");
      setBody("");
      setDone("Note added.");
      refresh();
    },
  });
  const upload = useMutation({
    mutationFn: (f: File) =>
      wallet.putFile({
        hostDid,
        roomId,
        file: f,
        name: f.name,
        ...(title.trim() ? { title: title.trim() } : {}),
        onProgress: setProgress,
      }),
    onSuccess: () => {
      setFile(null);
      setTitle("");
      setDone("File added.");
      refresh();
    },
    onSettled: () => setProgress(null),
  });
  const wontFit = file ? fileWontFit(info, file.size) : null;
  const sealedTier = info.visibility !== "open";

  return (
    <section className="card" aria-labelledby="add-heading">
      <div className="card-head">
        <FilePlus2 size={18} aria-hidden="true" />
        <h2 id="add-heading">Add to this room</h2>
      </div>
      {!sealedTier ? (
        <p className="muted">
          This room is open: what is in it is readable by its host. Adding from the portal is for attributed rooms.
        </p>
      ) : (
        <>
          <p className="muted small">
            Your wallet shows you what will be added, signed as <code className="wrap">{info.member}</code>, before
            anything is sent.
          </p>
          <label className="field">
            <span>Title</span>
            <input value={title} maxLength={512} onChange={(e) => setTitle(e.target.value)} />
          </label>
          <label className="field">
            <span>Note</span>
            <textarea value={body} rows={5} onChange={(e) => setBody(e.target.value)} />
          </label>
          <div className="actions">
            <button
              type="button"
              className="btn btn-primary"
              disabled={!title.trim() || note.isPending}
              onClick={() => {
                setDone(null);
                note.mutate();
              }}
            >
              <NotebookPen size={14} aria-hidden="true" /> {note.isPending ? "Waiting for your wallet…" : "Add note"}
            </button>
          </div>
          <label className="field">
            <span>Or a file</span>
            <input type="file" onChange={(e) => setFile(e.target.files?.[0] ?? null)} />
          </label>
          {file && (
            <p className="muted small">
              {file.name} · {formatBytes(file.size)}
            </p>
          )}
          {wontFit && (
            <p className="error" role="alert">
              {wontFit}
            </p>
          )}
          <div className="actions">
            <button
              type="button"
              className="btn btn-primary"
              disabled={!file || !!wontFit || upload.isPending}
              onClick={() => {
                setDone(null);
                if (file) upload.mutate(file);
              }}
            >
              <FilePlus2 size={14} aria-hidden="true" /> {upload.isPending ? describe(progress) : "Add file"}
            </button>
          </div>
        </>
      )}
      {(note.isError || upload.isError) && (
        <p className="error" role="alert">
          {errorText(note.error ?? upload.error)}
        </p>
      )}
      {done && <p role="status">{done}</p>}
    </section>
  );
}
