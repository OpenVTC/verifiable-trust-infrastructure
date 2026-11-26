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
import { ArrowLeft, CornerDownRight, FileText, MessagesSquare, NotebookPen, Paperclip, RefreshCw, Send, X } from "lucide-react";

import {
  absentWords,
  byDay,
  clockTime,
  excerpt,
  runsOf,
  shownTime,
  speakerOf,
  type Speaker,
} from "./conversation";
import { AuthorAvatar, AuthorName } from "./author-card";
import { authorsOf, mayLookUpAuthors, useAuthorCards } from "./room-authors";
import {
  adverseVerification,
  fileWontFit,
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
  onRefresh: () => void;
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
            <button type="button" className="btn btn-ghost btn-sm" onClick={onRefresh} aria-label="Refresh">
              <RefreshCw size={14} aria-hidden="true" />
            </button>
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
            </dl>
          </details>
        </header>
        {warning && (
          <div className="alert chat-alert" role="alert">
            <p className="alert-title">The host's listing does not add up.</p>
            <p>{warning} Your wallet still shows what it was given.</p>
          </div>
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
                    />
                  ))}
                </ol>
              </li>
            ))}
          </ol>
        </div>
        <ChatComposer wallet={wallet} hostDid={hostDid} info={info} postAs={asOthersSee?.label} />
      </section>
      {open && (
        <RecordDrawer onClose={() => setOpen(null)}>
          {renderRecord(open, () => setOpen(null), (did) => nameOf(did))}
        </RecordDrawer>
      )}
    </div>
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
}: {
  r: ConversationRecord;
  first: boolean;
  last: boolean;
  target?: ConversationRecord;
  speaker: (did: string | undefined) => Speaker;
  nameOf: (did: string | undefined) => ReactNode;
  selected: boolean;
  onOpen: () => void;
}) {
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
  const classes = ["chat-msg", who.own ? "own" : "", first ? "first" : "", last ? "last" : ""].filter(Boolean);
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
        <div className="chat-bubble">
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
        {r.reactions.length > 0 && (
          <p className="chat-reactions">
            {r.reactions.map((x) => (
              <span key={x.value} className="chat-reaction" title={x.authors.map((a) => speaker(a).label).join(", ")}>
                {x.value} {x.count}
              </span>
            ))}
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
}: {
  wallet: WalletRooms;
  hostDid: string;
  info: RoomInfo;
  postAs?: string;
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
  const message = useMutation({
    mutationFn: () => wallet.putMessage!({ hostDid, roomId, body: text }),
    onSuccess: () => {
      setText("");
      setDone("Message sent.");
      refresh();
    },
  });
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
    message.mutate();
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
  const error = message.error ?? note.error ?? upload.error;
  const what = noting ? "note" : file ? "file" : "message";

  return (
    <div className="chat-compose">
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
