// The member's directory card, at the top of their page: what they wrote about
// themselves — picture, name, pronouns, about, links — and every other field
// the administrator's projection shows, with verified values badged by their
// issuer. Read through `vtc/directory/entries/show` like the Entries tab, so
// nothing here reaches past the projection. A member with no card, or a role
// that cannot read the directory, shows no card at all.
//
// Member values are text the member typed, rendered as text, never as markup;
// a link is a link only when it is http or https.

import { useMemo } from "react";
import { useQuery } from "@tanstack/react-query";

import {
  DirectoryAvatar,
  DirectoryPicture,
  VerifiedValueView,
  blobRef,
  verifiedValue,
} from "@/components/DirectoryAvatar";
import { listFields, showEntryByDid } from "@/lib/directory";

/** Shown in the card's header, not the field list. */
const HEADER_FIELDS = new Set(["avatar", "displayName", "nickname", "pronouns", "bio", "links"]);
/** Shown elsewhere on the member's page already. */
const PAGE_FIELDS = new Set(["did", "role", "joinedAt", "personhood"]);

function text(v: unknown): string {
  if (v === null || v === undefined) return "";
  if (Array.isArray(v)) return v.join(", ");
  if (typeof v === "object") return "";
  return String(v);
}

/** `s` as a link target, only when it is an http or https URL. */
export function safeUrl(s: string): string | null {
  try {
    const u = new URL(s);
    return u.protocol === "https:" || u.protocol === "http:" ? u.toString() : null;
  } catch {
    return null;
  }
}

export function MemberProfileCard({ did }: { did: string }) {
  const entry = useQuery({
    queryKey: ["directory", "entry-by-did", did],
    queryFn: () => showEntryByDid(did),
    retry: false,
  });
  const fields = useQuery({
    queryKey: ["directory", "fields", false],
    queryFn: () => listFields(false),
    retry: false,
  });
  const labels = useMemo(
    () => new Map((fields.data?.fields ?? []).map((f) => [f.key, f.label])),
    [fields.data],
  );
  if (!entry.data) return null;
  const { entryId, fields: values } = entry.data.entry;
  const name = text(values.displayName) || null;
  const nickname = text(values.nickname);
  const pronouns = text(values.pronouns);
  const bio = text(values.bio);
  const links = Array.isArray(values.links) ? values.links.map(String) : [];
  const rest = Object.entries(values).filter(
    ([k]) => !HEADER_FIELDS.has(k) && !PAGE_FIELDS.has(k),
  );

  return (
    <section className="card member-profile" aria-label="Directory card">
      <div className="member-profile-head">
        <DirectoryAvatar
          entryId={entryId}
          value={values.avatar}
          name={name || nickname}
          colourKey={entryId}
          size={72}
        />
        <div className="member-profile-names">
          <h3>{name || nickname || <span className="muted">No name in the directory</span>}</h3>
          {(nickname && name) || pronouns ? (
            <p className="muted">
              {[name && nickname ? `“${nickname}”` : "", pronouns].filter(Boolean).join(" · ")}
            </p>
          ) : null}
        </div>
      </div>
      {bio && <p className="member-profile-bio">{bio}</p>}
      {links.length > 0 && (
        <ul className="member-profile-links">
          {links.map((l) => {
            const href = safeUrl(l);
            return (
              <li key={l}>
                {href ? (
                  <a href={href} target="_blank" rel="noopener noreferrer nofollow">
                    {l}
                  </a>
                ) : (
                  l
                )}
              </li>
            );
          })}
        </ul>
      )}
      {rest.length > 0 && (
        <dl className="kv">
          {rest.map(([k, v]) => {
            const verified = verifiedValue(v);
            return (
              <div key={k}>
                <dt>{labels.get(k) ?? k}</dt>
                <dd>
                  {blobRef(v) ? (
                    <DirectoryPicture entryId={entryId} field={k} value={v} />
                  ) : verified ? (
                    <VerifiedValueView value={verified} />
                  ) : (
                    text(v)
                  )}
                </dd>
              </div>
            );
          })}
        </dl>
      )}
      <p className="muted">
        What the member wrote in the directory. Administrators see every field; other members see
        only what the member chose to show them.
      </p>
    </section>
  );
}
