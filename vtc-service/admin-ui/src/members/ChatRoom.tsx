// A data room used for chat, laid out as a chat: the conversation fills the
// page under a header naming the room, the member's own messages on the right,
// another author's under their name and initials once per run, notes and files
// as small cards that open in a drawer, and the composer docked beneath.
//
// Layout only. The wallet assembled the conversation by the reading rules
// (`rooms.conversation`): kinds, order, replies, reactions and the names
// authors gave themselves are its, never re-derived here, so the portal, the
// wallet's console and Keyring show one room alike. An author the room gives
// no name is named as the community's directory shows them (`room-authors.ts`),
// asked only where the room's host already sees who wrote what. Every write
// goes through the wallet, which shows it to the member before it is sent.

import { useEffect, useLayoutEffect, useRef, useState, type ReactNode } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowLeft, CornerDownRight, FileText, MessagesSquare, NotebookPen, Paperclip, RefreshCw, Reply, Send, SmilePlus, X } from "lucide-react";

import {
  absentWords,
  byDay,
  clockTime,
  excerpt,
  highestVersion,
  QUICK_REACTIONS,
  reactedWith,
  reactionValueOk,
  runsOf,
  shownTime,
  speakerOf,
  type Speaker,
} from "./conversation";
import { AuthorAvatar, AuthorName } from "./author-card";
import { authorsOf, mayLookUpAuthors, useAuthorCards } from "./room-authors";
import { useRoomLive, type LiveStatus } from "./room-live";
import {
  adverseVerification,
  declinedInWallet,
  fileWontFit,
  notListed,
  formatBytes,
  roomName,
  type Conversation as ConversationView,
  type ConversationRecord,
  type RoomInfo,
  type TransferProgress,
  type WalletRooms,
} from "./wallet-rooms";
import { formatDateTime, shortenDid } from "@/lib/format";
import { messageOf } from "@/lib/messages";

/** What the room's tier means for what the community sees, in a member's words. */
export function privacyLine(visibility: string): string {
  switch (visibility) {
    case "attributed":
      return "The community sees who added what, and when — never what it says.";
    case "private":
      return "Sealed for its members. The community does not see who wrote what.";
    case "open":
      return "This room is open: its host can read what is written here.";
    default:
      return "";
  }
}

function Meter({ label, used, max }: { label: string; used: number; max?: number }) {
  return (
    <span>
      {label} <b>{formatBytes(used)}</b>
      {max !== undefined ? ` of ${formatBytes(max)}` : ""}
    </span>
  );
}

export function ChatRoom({
  wallet,
  hostDid,
  info,
  view,
  onRefresh,
  backHref,
  byDid,
  renderRecord,
}: {
  wallet: WalletRooms;
  hostDid: string;
  info: RoomInfo;
  view: ConversationView;
  /** Read the conversation again; resolves once it is read. */
  onRefresh: () => Promise<unknown> | void;
  /** Where the header's back arrow goes: the rooms list. */
  backHref: string;
  /** How the page names a DID nobody names (`authorName`). */
  byDid: (did: string) => string;
  /** The record view (Rooms.tsx), with its author named as the chat names them. */
  renderRecord: (key: string, onClose: () => void, byline: (did: string) => ReactNode) => ReactNode;
}) {
  const roomId = info.roomId;
  const me = info.member;
  const [open, setOpen] = useState<string | null>(null);
  const qc = useQueryClient();
  // What the member is answering, chosen on a message; the composer sends it with the reply.
  const [replyTo, setReplyTo] = useState<ConversationRecord | null>(null);
  // The room's profile does not list what replies and reactions need: offer neither again.
  const [unlisted, setUnlisted] = useState(false);
  const [reactError, setReactError] = useState<string | null>(null);
  // A wallet that reacts also writes replies; an older one takes neither.
  const canAnswer = typeof wallet.react === "function" && typeof wallet.putMessage === "function" && !unlisted;
  const live = useRoomLive(wallet, hostDid, roomId, highestVersion(view.records), async () => {
    await onRefresh();
    const now = qc.getQueryData<ConversationView>(["member-room-conversation", roomId]);
    return highestVersion(now?.records ?? view.records);
  });
  const reaction = useMutation({
    mutationFn: async ({ r, value, mine }: { r: ConversationRecord; value: string; mine: boolean }) => {
      if (mine) return wallet.unreact!({ hostDid, roomId, key: r.key, value });
      return wallet.react!({ hostDid, roomId, key: r.key, version: r.version, value });
    },
    onMutate: () => setReactError(null),
    onSuccess: () => void onRefresh(),
    onError: (e) => {
      if (notListed(e)) setUnlisted(true);
      else if (!declinedInWallet(e)) setReactError(messageOf(e));
    },
  });
  const onReact = (r: ConversationRecord, value: string) => {
    if (!reactionValueOk(value) || reaction.isPending) return;
    reaction.mutate({ r, value, mine: reactedWith(r.reactions, value, me) });
  };
  const list = useQuery({
    queryKey: ["member-rooms", hostDid],
    queryFn: async () => (await wallet.list({ hostDid })).rooms,
  });
  const title = roomName(list.data?.find((r) => r.roomId === roomId));

  // Only the authors the room itself gives no name: the wallet's reading comes first.
  // The member too, for "you post as" — their own card is always theirs to read.
  const unnamed = [...authorsOf(view.records, me), ...(me ? [me] : [])].filter((d) => !view.names[d]?.trim());
  const cards = useAuthorCards(unnamed, mayLookUpAuthors(info.visibility));
  const directory = (d: string) => cards.get(d)?.name;
  const speaker = (did: string | undefined) => speakerOf(did, me, view.names, byDid, directory);
  const nameOf = (did: string | undefined, sp: Speaker = speaker(did)) => (
    <AuthorName speaker={sp} did={did} card={did ? cards.get(did) : undefined} />
  );
  // The member as others see them: not "You".
  const asOthersSee = me ? speakerOf(me, undefined, view.names, byDid, directory) : undefined;

  const byKey = new Map(view.records.map((r) => [r.key, r]));
  const warning = adverseVerification(view.verification);
  const scroller = useStickToNewest(view.records, me);
  const privacy = privacyLine(info.visibility);
  const mine = info.usage.member;

  return (
    <div className={open ? "chat-room has-drawer" : "chat-room"}>
      <section className="chat-shell" aria-labelledby="chat-title">
        <header className="chat-head">
          <div className="chat-head-row">
            <a href={backHref} className="chat-back" aria-label="Data rooms" title="Data rooms">
              <ArrowLeft size={18} aria-hidden="true" />
            </a>
            <span className="chat-head-icon" aria-hidden="true">
              <MessagesSquare size={18} />
            </span>
            <h1 id="chat-title" className="chat-title" title={roomId}>
              {title ?? shortenDid(roomId)}
            </h1>
            <span className="tier-pill">{info.visibility}</span>
            <span className="push" />
            <LiveBadge status={live} />
            {live !== "live" && (
              <button type="button" className="btn btn-ghost btn-sm" onClick={() => void onRefresh()} aria-label="Refresh">
                <RefreshCw size={14} aria-hidden="true" />
              </button>
            )}
          </div>
          {privacy && <p className="chat-privacy">{privacy}</p>}
          <details className="chat-about">
            <summary>About this room</summary>
            <dl className="chat-about-facts">
              <div>
                <dt>Room</dt>
                <dd>
                  <code className="wrap">{roomId}</code>
                </dd>
              </div>
              {asOthersSee && me && (
                <div>
                  <dt>You post as</dt>
                  <dd>
                    {nameOf(me, asOthersSee)}
                  </dd>
                </div>
              )}
              <div>
                <dt>Epoch</dt>
                <dd>{info.epoch}</dd>
              </div>
              <div>
                <dt>Storage</dt>
                <dd className="chat-about-meters">
                  <Meter label="Room" used={info.usage.room.bytes} max={info.limits.room?.maxBytes} />
                  {mine && <Meter label="Yours" used={mine.usage.bytes} max={mine.limits.maxBytes} />}
                </dd>
              </div>
              <div>
                <dt>Updates</dt>
                <dd>
                  {liveWords(live)}{" "}
                  <button type="button" className="link-button" onClick={() => void onRefresh()}>
                    Refresh now
                  </button>
                </dd>
              </div>
            </dl>
          </details>
        </header>
        {warning && (
          <div className="alert chat-alert" role="alert">
            <p className="alert-title">The host's listing does not add up.</p>
            <p>{warning} Your wallet still shows what it was given.</p>
          </div>
        )}
        {unlisted && (
          <p className="chat-notice" role="status">
            This room doesn't take replies and reactions yet — an administrator can turn on <b>Replies and reactions</b>{" "}
            for it.
          </p>
        )}
        {reactError && (
          <p className="error chat-notice" role="alert">
            {reactError}
          </p>
        )}
        <div className="chat-scroll" ref={scroller.ref} onScroll={scroller.onScroll} tabIndex={0}>
          {!view.complete && (
            <p className="chat-older muted small">The listing stopped at a page bound; older messages are not shown.</p>
          )}
          <ol className="chat" aria-label="Messages">
            {byDay(view.records).map(({ day, records }, i) => (
              <li key={`${day}-${i}`} className="chat-day">
                {day && <p className="chat-divider">{day}</p>}
                <ol className="chat-day-items">
                  {runsOf(records).map(({ r, first, last }) => (
                    <ChatItem
                      key={r.key}
                      r={r}
                      first={first}
                      last={last}
                      target={r.replyTo ? byKey.get(r.replyTo.key) : undefined}
                      speaker={speaker}
                      nameOf={nameOf}
                      selected={open === r.key}
                      onOpen={() => setOpen(open === r.key ? null : r.key)}
                      me={me}
                      canAnswer={canAnswer}
                      onReply={() => setReplyTo(r)}
                      onReact={(value) => onReact(r, value)}
                    />
                  ))}
                </ol>
              </li>
            ))}
          </ol>
        </div>
        <ChatComposer
          wallet={wallet}
          hostDid={hostDid}
          info={info}
          postAs={asOthersSee?.label}
          replyTo={replyTo && canAnswer ? replyTo : null}
          replyingTo={replyTo ? speaker(replyTo.author).label : ""}
          onClearReply={() => setReplyTo(null)}
          onUnlisted={() => setUnlisted(true)}
        />
      </section>
      {open && (
        <RecordDrawer onClose={() => setOpen(null)}>
          {renderRecord(open, () => setOpen(null), (did) => nameOf(did))}
        </RecordDrawer>
      )}
    </div>
  );
}

/** Where the room's updates stand, in a member's words. */
export function liveWords(status: LiveStatus): string {
  switch (status) {
    case "live":
      return "New messages appear as they arrive.";
    case "connecting":
      return "Asking your wallet to watch this room…";
    case "polling":
      return "Your wallet cannot watch this room now, so it is read every few seconds.";
    case "manual":
      return "Your wallet cannot watch rooms: refresh to see new messages.";
  }
}

/** A small mark while the wallet watches the room. Derived from its latest event, never latched. */
function LiveBadge({ status }: { status: LiveStatus }) {
  if (status !== "live") return null;
  return (
    <span className="chat-live" title={liveWords(status)} role="status">
      <span className="chat-live-dot" aria-hidden="true" /> Live
    </span>
  );
}

/** How close to the bottom, in pixels, still counts as reading the newest. */
const NEAR_NEWEST_PX = 48;

/**
 * Keep a conversation's scrolling window at its newest message, as a chat does:
 * it opens there, and follows a new message while the member is at the bottom, or
 * when the newest is their own (they just sent it) — never pulling them down from
 * something older they scrolled up to read. Layout only: the order is the wallet's.
 */
function useStickToNewest(records: readonly ConversationRecord[], me: string | undefined) {
  const ref = useRef<HTMLDivElement>(null);
  const atNewest = useRef(true);
  const lastKey = useRef<string | undefined>(undefined);
  const last = records.at(-1);
  useLayoutEffect(() => {
    const el = ref.current;
    if (!el) return;
    const arrived = lastKey.current !== undefined && last?.key !== lastKey.current;
    const mine = arrived && me !== undefined && last?.author === me;
    lastKey.current = last?.key;
    if (atNewest.current || mine) {
      el.scrollTop = el.scrollHeight;
      atNewest.current = true;
    }
  }, [last?.key, last?.author, records.length, me]);
  const onScroll = () => {
    const el = ref.current;
    if (el) atNewest.current = el.scrollHeight - el.scrollTop - el.clientHeight <= NEAR_NEWEST_PX;
  };
  return { ref, onScroll };
}

function ChatItem({
  r,
  first,
  last,
  target,
  speaker,
  nameOf,
  selected,
  onOpen,
  me,
  canAnswer,
  onReply,
  onReact,
}: {
  r: ConversationRecord;
  first: boolean;
  last: boolean;
  target?: ConversationRecord;
  speaker: (did: string | undefined) => Speaker;
  nameOf: (did: string | undefined) => ReactNode;
  selected: boolean;
  onOpen: () => void;
  me?: string;
  /** The wallet replies and reacts, and the room takes both. */
  canAnswer: boolean;
  onReply: () => void;
  onReact: (value: string) => void;
}) {
  const [actions, setActions] = useState(false);
  const [picking, setPicking] = useState(false);
  const bar = useRef<HTMLDivElement>(null);
  // Opened on the newest message, the actions would sit below the fold on a phone.
  useEffect(() => {
    if ((actions || picking) && typeof bar.current?.scrollIntoView === "function") {
      bar.current.scrollIntoView({ block: "nearest" });
    }
  }, [actions, picking]);
  const time = shownTime(r);
  const stamp = time && (
    <time dateTime={time} title={formatDateTime(time)}>
      {clockTime(time)}
    </time>
  );
  if (r.shown === "note") {
    // A note or a file is a small card in the conversation; it opens in the drawer.
    const who = speaker(r.author);
    return (
      <li className={`chat-note${who.own ? " own" : ""}${selected ? " selected" : ""}`}>
        <span className="chat-note-icon" aria-hidden="true">
          {r.file ? <FileText size={16} /> : <NotebookPen size={16} />}
        </span>
        <span className="chat-note-text">
          <span className="chat-note-kind">{r.file && !r.title ? "File" : "Note"}</span>
          <b className="chat-note-title">{r.title || r.file?.name || "(untitled)"}</b>
          <span className="chat-note-meta">
            {nameOf(r.author)}
            {stamp && <> · {stamp}</>}
          </span>
        </span>
        <button type="button" className="btn btn-sm" onClick={onOpen} aria-current={selected ? "true" : undefined}>
          Open
        </button>
      </li>
    );
  }
  if (r.shown !== "message") {
    return (
      <li className="chat-absent" title={r.reason}>
        {absentWords(r)}
      </li>
    );
  }
  const who = speaker(r.author);
  const classes = [
    "chat-msg",
    who.own ? "own" : "",
    first ? "first" : "",
    last ? "last" : "",
    actions || picking ? "acting" : "",
  ].filter(Boolean);
  return (
    <li className={classes.join(" ")}>
      {!who.own && (
        <span className="chat-avatar">
          {first && <AuthorAvatar speaker={who} did={r.author} />}
        </span>
      )}
      <div className="chat-stack">
        {who.own ? (
          <span className="visually-hidden">You</span>
        ) : (
          first && (
            <p className="chat-from">
              {nameOf(r.author)}
              {who.ownName && <span className="chat-from-note"> (their own name)</span>}
            </p>
          )
        )}
        <div
          className="chat-bubble"
          onClick={(e) => {
            // A tap shows a message's actions where there is no hover (a phone); links and buttons keep theirs.
            if (canAnswer && !(e.target as HTMLElement).closest("button, a")) setActions((a) => !a);
          }}
        >
          {r.replyTo && (
            <p className="chat-reply">
              <CornerDownRight size={12} aria-hidden="true" />{" "}
              {r.replyTo.available && target
                ? `${speaker(target.author).label}: ${excerpt(target)}`
                : "a message that is not available"}
            </p>
          )}
          {/* Another member's words: rendered as text, never as markup. */}
          <p className="chat-body">{r.body}</p>
          {r.file && (
            <button type="button" className="chat-file" onClick={onOpen}>
              <FileText size={14} aria-hidden="true" /> {r.file.name}
            </button>
          )}
          <p className="chat-meta">
            {r.rewrite && <span>rewritten by {nameOf(r.rewrite.by)} · </span>}
            {r.edited && <span>edited · </span>}
            {r.written.arrivedLate && (
              <span title={`claims ${r.written.arrivedLate.claimed}`}>arrived later than it says · </span>
            )}
            {stamp}
          </p>
        </div>
        {canAnswer && (
          <div className="chat-actions" role="toolbar" aria-label="Message actions" ref={bar}>
            <button type="button" className="chat-action" aria-label="Reply" title="Reply" onClick={() => { setActions(false); onReply(); }}>
              <Reply size={15} aria-hidden="true" />
            </button>
            <button
              type="button"
              className="chat-action"
              aria-label="React"
              title="React"
              aria-expanded={picking}
              onClick={() => setPicking((p) => !p)}
            >
              <SmilePlus size={15} aria-hidden="true" />
            </button>
            {picking && (
              <span className="chat-picker" role="group" aria-label="Reactions">
                {QUICK_REACTIONS.map((v) => (
                  <button
                    key={v}
                    type="button"
                    className={reactedWith(r.reactions, v, me) ? "chat-pick mine" : "chat-pick"}
                    aria-label={`React ${v}`}
                    aria-pressed={reactedWith(r.reactions, v, me)}
                    onClick={() => {
                      setPicking(false);
                      setActions(false);
                      onReact(v);
                    }}
                  >
                    {v}
                  </button>
                ))}
              </span>
            )}
          </div>
        )}
        {r.reactions.length > 0 && (
          <p className="chat-reactions">
            {r.reactions.map((x) => {
              const mine = reactedWith(r.reactions, x.value, me);
              const who_ = x.authors.map((a) => speaker(a).label).join(", ");
              // Another member's reaction value is text: rendered as such, never markup.
              return canAnswer ? (
                <button
                  key={x.value}
                  type="button"
                  className={mine ? "chat-reaction mine" : "chat-reaction"}
                  title={mine ? `${who_} — select to take yours back` : who_}
                  aria-pressed={mine}
                  aria-label={`${x.value} ${x.count}${mine ? ", including yours" : ""}`}
                  onClick={() => onReact(x.value)}
                >
                  {x.value} {x.count}
                </button>
              ) : (
                <span key={x.value} className="chat-reaction" title={who_}>
                  {x.value} {x.count}
                </span>
              );
            })}
          </p>
        )}
      </div>
    </li>
  );
}

/** The opened note or file, beside the conversation (a sheet over it on a phone). Escape closes it. */
function RecordDrawer({ onClose, children }: { onClose: () => void; children: ReactNode }) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);
  return (
    <>
      <div className="chat-drawer-backdrop" onClick={onClose} aria-hidden="true" />
      <aside className="chat-drawer" aria-label="Opened record">
        {children}
      </aside>
    </>
  );
}

// ── Writing ────────────────────────────────────────────────────────────────

/**
 * The composer, docked under the conversation: a message (Enter sends, Shift+Enter
 * starts a new line), a note behind its own toggle, and a file through the paperclip.
 * A wallet older than messages takes only notes, and is offered nothing else. Every
 * write goes to the wallet, which shows it to the member before anything is sent.
 */
function ChatComposer({
  wallet,
  hostDid,
  info,
  postAs,
  replyTo,
  replyingTo,
  onClearReply,
  onUnlisted,
}: {
  wallet: WalletRooms;
  hostDid: string;
  info: RoomInfo;
  postAs?: string;
  /** The message being answered, when the member chose one. */
  replyTo: ConversationRecord | null;
  /** Its author, named as the chat names them. */
  replyingTo: string;
  onClearReply: () => void;
  /** The room's profile does not list what a reply needs. */
  onUnlisted: () => void;
}) {
  const qc = useQueryClient();
  const roomId = info.roomId;
  const takesMessages = typeof wallet.putMessage === "function";
  const [noting, setNoting] = useState(!takesMessages);
  const [text, setText] = useState("");
  const [title, setTitle] = useState("");
  const [body, setBody] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [progress, setProgress] = useState<TransferProgress | null>(null);
  const [done, setDone] = useState<string | null>(null);
  const picker = useRef<HTMLInputElement>(null);
  const box = useRef<HTMLTextAreaElement>(null);

  const refresh = () => {
    void qc.invalidateQueries({ queryKey: ["member-room-records", roomId] });
    void qc.invalidateQueries({ queryKey: ["member-room-conversation", roomId] });
    void qc.invalidateQueries({ queryKey: ["member-room-info", roomId] });
  };
  // A reply the room refused for want of its record members: offered again as a plain message.
  const [replyRefused, setReplyRefused] = useState(false);
  const message = useMutation({
    mutationFn: (answer: ConversationRecord | null) =>
      wallet.putMessage!({
        hostDid,
        roomId,
        body: text,
        ...(answer ? { replyTo: { key: answer.key, version: answer.version } } : {}),
      }),
    onSuccess: () => {
      setText("");
      setDone("Message sent.");
      setReplyRefused(false);
      onClearReply();
      refresh();
    },
    onError: (e) => {
      if (notListed(e)) {
        setReplyRefused(true);
        onUnlisted();
      }
    },
  });
  // The box takes the focus when the member chooses a message to answer.
  useEffect(() => {
    if (replyTo) box.current?.focus();
  }, [replyTo]);
  const note = useMutation({
    mutationFn: () => wallet.putNote({ hostDid, roomId, title: title.trim(), ...(body ? { body } : {}) }),
    onSuccess: () => {
      setTitle("");
      setBody("");
      setDone("Note added.");
      if (takesMessages) setNoting(false);
      refresh();
    },
  });
  const upload = useMutation({
    mutationFn: (f: File) => wallet.putFile({ hostDid, roomId, file: f, name: f.name, onProgress: setProgress }),
    onSuccess: () => {
      setFile(null);
      if (picker.current) picker.current.value = "";
      setDone("File added.");
      refresh();
    },
    onSettled: () => setProgress(null),
  });
  const send = () => {
    if (!text.trim() || message.isPending) return;
    setDone(null);
    message.mutate(replyTo);
  };
  // The box grows with what is typed, up to a few lines.
  useLayoutEffect(() => {
    const el = box.current;
    if (!el) return;
    el.style.height = "auto";
    el.style.height = `${Math.min(el.scrollHeight, 160)}px`;
  }, [text]);

  const wontFit = file ? fileWontFit(info, file.size) : null;
  const busy = message.isPending || note.isPending || upload.isPending;
  const shown = (e: unknown) => (e && !notListed(e) && !declinedInWallet(e) ? e : null);
  const error = shown(message.error) ?? note.error ?? upload.error;
  const what = noting ? "note" : file ? "file" : "message";

  return (
    <div className="chat-compose">
      {replyTo && !noting && (
        <div className="chat-compose-reply">
          <CornerDownRight size={14} aria-hidden="true" />
          <span className="chat-compose-reply-text">
            Replying to <b>{replyingTo}</b>: {excerpt(replyTo, 60)}
          </span>
          <button type="button" className="btn btn-ghost btn-sm" aria-label="Cancel the reply" onClick={onClearReply}>
            <X size={14} aria-hidden="true" />
          </button>
        </div>
      )}
      {replyRefused && (
        <div className="chat-compose-reply" role="alert">
          <span className="chat-compose-reply-text">
            This room doesn't take replies yet — an administrator can turn on <b>Replies and reactions</b>.
          </span>
          <button
            type="button"
            className="btn btn-sm"
            disabled={!text.trim() || message.isPending}
            onClick={() => {
              setReplyRefused(false);
              setDone(null);
              onClearReply();
              message.mutate(null);
            }}
          >
            Send as a plain message
          </button>
        </div>
      )}
      {file && (
        <div className="chat-compose-file">
          <FileText size={16} aria-hidden="true" />
          <span className="chat-compose-file-name">
            {file.name} <span className="muted small">· {formatBytes(file.size)}</span>
          </span>
          <button
            type="button"
            className="btn btn-primary btn-sm"
            disabled={!!wontFit || upload.isPending}
            onClick={() => {
              setDone(null);
              upload.mutate(file);
            }}
          >
            {upload.isPending ? describe(progress) : "Add file"}
          </button>
          <button
            type="button"
            className="btn btn-ghost btn-sm"
            aria-label="Remove the file"
            disabled={upload.isPending}
            onClick={() => {
              setFile(null);
              if (picker.current) picker.current.value = "";
            }}
          >
            <X size={14} aria-hidden="true" />
          </button>
          {wontFit && (
            <p className="error chat-compose-wide" role="alert">
              {wontFit}
            </p>
          )}
        </div>
      )}
      {noting ? (
        <div className="chat-compose-note">
          <label className="field">
            <span>Title</span>
            <input value={title} maxLength={512} onChange={(e) => setTitle(e.target.value)} />
          </label>
          <label className="field">
            <span>Note</span>
            <textarea value={body} rows={4} onChange={(e) => setBody(e.target.value)} />
          </label>
          <div className="actions">
            {takesMessages && (
              <button type="button" className="btn btn-ghost" onClick={() => setNoting(false)}>
                Back to the message
              </button>
            )}
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
        </div>
      ) : (
        <div className="chat-compose-row">
          <button
            type="button"
            className="chat-tool"
            aria-label="Write a note"
            title="Write a note"
            onClick={() => {
              setDone(null);
              setNoting(true);
            }}
          >
            <NotebookPen size={18} aria-hidden="true" />
          </button>
          <button
            type="button"
            className="chat-tool"
            aria-label="Attach a file"
            title="Attach a file"
            onClick={() => picker.current?.click()}
          >
            <Paperclip size={18} aria-hidden="true" />
          </button>
          <textarea
            ref={box}
            className="chat-input"
            aria-label="Message"
            placeholder="Write a message"
            value={text}
            rows={1}
            onChange={(e) => setText(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter" && !e.shiftKey && !e.nativeEvent.isComposing) {
                e.preventDefault();
                send();
              }
            }}
          />
          <button
            type="button"
            className="chat-send"
            aria-label={message.isPending ? "Waiting for your wallet" : "Send"}
            title="Send"
            disabled={!text.trim() || message.isPending}
            onClick={send}
          >
            <Send size={18} aria-hidden="true" />
          </button>
        </div>
      )}
      <input
        ref={picker}
        type="file"
        className="visually-hidden"
        aria-label="Choose a file"
        tabIndex={-1}
        onChange={(e) => {
          setDone(null);
          setFile(e.target.files?.[0] ?? null);
        }}
      />
      <p className="chat-compose-hint">
        {busy ? (
          "Waiting for your wallet…"
        ) : (
          <>
            Your wallet shows you each {what} before it is sent{postAs ? <>, signed as <b>{postAs}</b></> : null}.
            {!noting && takesMessages && <span className="chat-compose-keys"> Enter sends · Shift+Enter for a new line.</span>}
          </>
        )}
      </p>
      {info.visibility === "open" && (
        <p className="chat-compose-hint">
          This room is open: what you write is stored in the clear, and a file under a key its record carries in the
          clear — its host can read both.
        </p>
      )}
      {error && (
        <p className="error" role="alert">
          {messageOf(error)}
        </p>
      )}
      {done && !busy && (
        <p className="chat-compose-hint" role="status">
          {done}
        </p>
      )}
    </div>
  );
}

/** Where a file transfer stands, in a member's words. */
export function describe(p: TransferProgress | null): string {
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
