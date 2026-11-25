// An author's name in a conversation, and the card it opens: what the
// community's directory shows this member of them, and their DID.
//
// Opens on hover, on keyboard focus and on a tap; Escape closes it. Everything
// shown is text: values members typed are never markup.

import { useId, useState } from "react";

import type { Speaker } from "./conversation";
import { hueOf, initials } from "./member-card";
import type { AuthorCard } from "./room-authors";

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
  return (
    <span
      className="author"
      onMouseEnter={() => setOpen(true)}
      onMouseLeave={() => setOpen(false)}
      onKeyDown={(e) => {
        if (e.key === "Escape") setOpen(false);
      }}
    >
      <button
        type="button"
        className="author-name"
        aria-expanded={open}
        aria-controls={id}
        onClick={() => setOpen((o) => !o)}
        onFocus={() => setOpen(true)}
        onBlur={() => setOpen(false)}
      >
        {label}
      </button>
      {open && (
        <span id={id} className="author-card" role="group" aria-label={`About ${speaker.label}`}>
          <span className="author-card-head">
            <span
              className="avatar avatar-initials"
              aria-hidden="true"
              style={{ width: 40, height: 40, fontSize: 15, ["--avatar-hue" as string]: hueOf(did) }}
            >
              {initials(card?.name ?? (speaker.did ? null : speaker.label))}
            </span>
            <span className="author-card-names">
              <b>{card?.name ?? (speaker.did ? "No name shown to you" : speaker.label)}</b>
              {card?.nickname && card.nickname !== card.name && <span className="muted small">@{card.nickname}</span>}
              {card?.pronouns && <span className="muted small">{card.pronouns}</span>}
            </span>
          </span>
          {card?.role && <span className="small">Role: {card.role}</span>}
          {speaker.ownName && (
            <span className="muted small">
              The name they gave themselves in this room.
              {card?.name && card.name !== speaker.label ? ` The directory shows ${card.name}.` : ""}
            </span>
          )}
          {speaker.directory && <span className="muted small">As the community's directory shows them to you.</span>}
          {!card && !speaker.ownName && (
            <span className="muted small">The directory shows you no card for this DID.</span>
          )}
          <code className="author-card-did">{did}</code>
        </span>
      )}
    </span>
  );
}
