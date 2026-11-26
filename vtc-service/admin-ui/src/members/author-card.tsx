// An author's name in a conversation, and the card it opens: what the
// community's directory shows this member of them, and their DID.
//
// Opens on hover, on keyboard focus and on a tap; Escape closes it. It opens
// below the name, or above it when there is no room below, and never outside
// the window. Everything shown is text: values members typed are never markup.

import { useId, useLayoutEffect, useRef, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Check, Copy, IdCard, User } from "lucide-react";

import { showWall } from "./badges-api";
import type { Speaker } from "./conversation";
import { hueOf, initials, usePicture } from "./member-card";
import type { AuthorCard } from "./room-authors";

/** The most badge names the card lists before "+N". */
const CARD_BADGES = 4;

/**
 * An author's picture, read through the directory's projection by their entry
 * (digest-checked, `usePicture`); else their initials on their own colour — or
 * a plain figure for a DID with no name.
 */
export function AuthorAvatar({
  speaker,
  did,
  card,
  size = 32,
}: {
  speaker: Speaker;
  did?: string;
  card?: AuthorCard;
  size?: number;
}) {
  const picture = usePicture(card?.entryId ?? "", "avatar", card?.entryId ? card.avatar : undefined);
  if (picture) {
    return (
      <img
        className="avatar chat-avatar-face"
        src={picture}
        alt=""
        width={size}
        height={size}
        style={{ width: size, height: size }}
      />
    );
  }
  const style = {
    width: size,
    height: size,
    fontSize: Math.round(size * 0.4),
    ["--avatar-hue" as string]: hueOf(did ?? speaker.label),
  };
  return (
    <span className="avatar avatar-initials chat-avatar-face" aria-hidden="true" style={style}>
      {speaker.did || !did ? <User size={Math.round(size * 0.55)} /> : initials(speaker.label)}
    </span>
  );
}

/** Copy `text`, and say so for a moment. */
function CopyDid({ did }: { did: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      type="button"
      className="author-card-copy"
      aria-label={copied ? "Copied" : "Copy DID"}
      title={copied ? "Copied" : "Copy DID"}
      onClick={() => {
        void navigator.clipboard
          ?.writeText(did)
          .then(() => {
            setCopied(true);
            window.setTimeout(() => setCopied(false), 1500);
          })
          .catch(() => {});
      }}
    >
      {copied ? <Check size={13} aria-hidden="true" /> : <Copy size={13} aria-hidden="true" />}
    </button>
  );
}

/** The badges a member shows on their card, by name — one read, made when their card is opened. Nothing when badges are off or hidden. */
function CardBadges({ entryId }: { entryId: string }) {
  const wall = useQuery({
    queryKey: ["badges", "wall", entryId],
    queryFn: () => showWall(entryId),
    retry: false,
    staleTime: 60_000,
  });
  const entries = wall.data?.entries ?? [];
  if (entries.length === 0) return null;
  const shown = entries.slice(0, CARD_BADGES);
  return (
    <span className="author-card-badges" aria-label="Badges">
      {shown.map((e) => (
        <span key={e.badge.badgeId} className="author-card-badge">
          {e.badge.name}
          {e.count > 1 ? ` ×${e.count}` : ""}
        </span>
      ))}
      {entries.length > shown.length && <span className="muted small">+{entries.length - shown.length}</span>}
    </span>
  );
}

/** Where the card goes: below unless it would leave its scroll area (or the window) and fits above. */
function usePlacement(open: boolean) {
  const wrap = useRef<HTMLSpanElement>(null);
  const card = useRef<HTMLSpanElement>(null);
  const [place, setPlace] = useState<{ up: boolean; shift: number }>({ up: false, shift: 0 });
  useLayoutEffect(() => {
    if (!open) {
      setPlace({ up: false, shift: 0 });
      return;
    }
    const w = wrap.current;
    const c = card.current;
    if (!w || !c || typeof w.getBoundingClientRect !== "function") return;
    const scroller = w.closest(".chat-scroll");
    const bounds = scroller?.getBoundingClientRect() ?? {
      top: 0,
      bottom: window.innerHeight,
    };
    const bottom = Math.min(bounds.bottom, window.innerHeight);
    const top = Math.max(bounds.top, 0);
    const name = w.getBoundingClientRect();
    const box = c.getBoundingClientRect();
    const below = bottom - name.bottom;
    const above = name.top - top;
    const up = box.height + 8 > below && above > below;
    const overRight = name.left + box.width - (window.innerWidth - 8);
    setPlace({ up, shift: overRight > 0 ? -Math.min(overRight, name.left - 8) : 0 });
  }, [open]);
  return { wrap, card, place };
}

export function AuthorName({
  speaker,
  did,
  card,
}: {
  speaker: Speaker;
  /** The author's DID; none for "Someone". */
  did?: string;
  card?: AuthorCard;
}) {
  const [open, setOpen] = useState(false);
  const id = useId();
  const { wrap, card: cardRef, place } = usePlacement(open);
  const label = speaker.did ? (
    <>
      <code className="author-did">{speaker.label}</code>
      <span className="did-tag" aria-label="(a DID)">
        DID
      </span>
    </>
  ) : (
    speaker.label
  );
  if (!did || speaker.own) return <>{label}</>;
  const name = card?.name ?? (speaker.did ? null : speaker.label);
  return (
    <span
      ref={wrap}
      className="author"
      onMouseEnter={() => setOpen(true)}
      onMouseLeave={() => setOpen(false)}
      onKeyDown={(e) => {
        if (e.key === "Escape") setOpen(false);
      }}
      onBlur={(e) => {
        // Moving focus into the card (its copy button) keeps it open.
        if (!e.currentTarget.contains(e.relatedTarget as Node | null)) setOpen(false);
      }}
    >
      <button
        type="button"
        className="author-name"
        aria-expanded={open}
        aria-controls={id}
        onClick={() => setOpen((o) => !o)}
        onFocus={() => setOpen(true)}
      >
        {label}
      </button>
      {open && (
        <span
          ref={cardRef}
          id={id}
          className={place.up ? "author-card up" : "author-card"}
          style={place.shift ? { transform: `translateX(${place.shift}px)` } : undefined}
          role="group"
          aria-label={`About ${speaker.label}`}
        >
          <span className="author-card-head">
            <AuthorAvatar speaker={{ ...speaker, did: !name }} did={did} card={card} size={44} />
            <span className="author-card-names">
              <b>{name ?? "No name shown to you"}</b>
              {card?.nickname && card.nickname !== card.name && <span className="muted small">@{card.nickname}</span>}
              {card?.pronouns && <span className="muted small">{card.pronouns}</span>}
            </span>
          </span>
          {card?.role && <span className="small">Role: {card.role}</span>}
          {/* A member's words: text, never markup. */}
          {card?.bio && <span className="author-card-bio">{card.bio}</span>}
          {card?.entryId && <CardBadges entryId={card.entryId} />}
          {speaker.ownName && (
            <span className="muted small">
              The name they gave themselves in this room.
              {card?.name && card.name !== speaker.label ? ` The directory shows ${card.name}.` : ""}
            </span>
          )}
          {!card && !speaker.ownName && (
            <span className="muted small">The directory shows you no card for this DID.</span>
          )}
          <span className="author-card-did-row">
            <code className="author-card-did">{did}</code>
            <CopyDid did={did} />
          </span>
          {card?.entryId && (
            <a className="btn btn-sm author-card-open" href={`#/directory/${encodeURIComponent(card.entryId)}`}>
              <IdCard size={14} aria-hidden="true" /> Open card
            </a>
          )}
        </span>
      )}
    </span>
  );
}
