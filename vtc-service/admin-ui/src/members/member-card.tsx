// The pieces every directory page draws a member with: their picture (or their
// initials), the way back, and a contact a viewer can save.
//
// Everything here works on a projection — what this viewer is allowed to see of
// a member — so it never shows, saves or links anything more than the page
// already holds. Values members typed are text, never markup; a link is a link
// only when it is http or https.

import { useQuery } from "@tanstack/react-query";
import { BadgeCheck } from "lucide-react";

import type { DirectoryCardBlobRef } from "@/lib/wire-types";

import { getImage } from "./directory-api";
import { pictureUrl } from "./picture";

/** `v` as plain text: a list joined, an object (a picture) nothing. */
export function text(v: unknown): string {
  if (v === null || v === undefined) return "";
  if (Array.isArray(v)) return v.join(", ");
  if (typeof v === "object") return "";
  return String(v);
}

/** `v` as a picture reference, if it is one. */
export function blobRef(v: unknown): DirectoryCardBlobRef | null {
  if (!v || typeof v !== "object" || Array.isArray(v)) return null;
  const r = v as Partial<DirectoryCardBlobRef>;
  return typeof r.sha256 === "string" && typeof r.mediaType === "string"
    ? (r as DirectoryCardBlobRef)
    : null;
}

/** A value filled from a credential the member presented: the claim, and the
 *  issuer that attests it (`vtc/directory/card/present`). */
export interface VerifiedValue {
  value: string | number | boolean;
  issuer: string;
  credentialType?: string;
  verifiedAt: string;
  validUntil?: string;
}

/** `v` as a verified value, if it is one. */
export function verifiedOf(v: unknown): VerifiedValue | null {
  if (!v || typeof v !== "object" || Array.isArray(v)) return null;
  const r = v as Partial<VerifiedValue>;
  return typeof r.issuer === "string" && "value" in r && typeof r.verifiedAt === "string"
    ? (r as VerifiedValue)
    : null;
}

/** A verified value, badged with its issuer. Only a value written by
 *  presenting a credential is ever shaped this way, so the badge is never on a
 *  value the member typed. */
export function Verified({ value }: { value: VerifiedValue }) {
  const shown = typeof value.value === "boolean" ? (value.value ? "Yes" : "No") : String(value.value);
  const until = value.validUntil ? `, until ${new Date(value.validUntil).toLocaleDateString()}` : "";
  return (
    <span className="verified-value">
      {shown}{" "}
      <span className="pill pill-ok" title={`Verified by ${value.issuer}${until}`}>
        <BadgeCheck size={12} aria-hidden="true" /> {value.credentialType ?? "Verified"}
      </span>
    </span>
  );
}

/** The name a member goes by on this projection, or `null` when they show none. */
export function nameOf(fields: Record<string, unknown>): string | null {
  return text(fields.displayName).trim() || text(fields.nickname).trim() || null;
}

/** Up to two initials from a name; `?` when there is none. */
export function initials(name: string | null): string {
  if (!name) return "?";
  const words = name.trim().split(/\s+/).filter(Boolean);
  const letters = words.length > 1 ? [words[0]!, words[words.length - 1]!] : [words[0] ?? ""];
  return (
    letters
      .map((w) => [...w][0] ?? "")
      .join("")
      .toUpperCase() || "?"
  );
}

/** A stable hue for an entry, so a member keeps one colour wherever they appear. */
export function hueOf(entryId: string): number {
  let h = 0;
  for (const c of entryId) h = (h * 31 + c.charCodeAt(0)) % 360;
  return h;
}

async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", bytes as BufferSource);
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, "0")).join("");
}

/** One picture on an entry, read through the projection; `null` until it is
 *  read, and when it is not this viewer's to see. Shown only once its bytes
 *  match the digest the card names. */
export function usePicture(entryId: string, field: string, value: unknown): string | null {
  const ref = blobRef(value);
  const picture = useQuery({
    queryKey: ["directory", "image", entryId, field, ref?.sha256 ?? ""],
    enabled: ref !== null,
    retry: false,
    staleTime: Infinity,
    queryFn: async () => {
      const got = await getImage(entryId, field, ref!.sha256);
      const b64 = got.data.replace(/-/g, "+").replace(/_/g, "/");
      const bytes = Uint8Array.from(atob(b64 + "=".repeat((4 - (b64.length % 4)) % 4)), (c) =>
        c.charCodeAt(0),
      );
      if ((await sha256Hex(bytes)) !== ref!.sha256) throw new Error("picture digest mismatch");
      return pictureUrl(got.image.mediaType, got.data);
    },
  });
  return picture.data ?? null;
}

/** A member's picture, or their initials on their own colour. */
export function MemberAvatar({
  entryId,
  value,
  name,
  size = 48,
}: {
  entryId: string;
  value: unknown;
  name: string | null;
  size?: number;
}) {
  const url = usePicture(entryId, "avatar", value);
  const style = { width: size, height: size };
  if (url) return <img className="avatar" src={url} alt="" width={size} height={size} style={style} />;
  return (
    <span
      className="avatar avatar-initials"
      aria-hidden="true"
      style={{ ...style, fontSize: Math.round(size * 0.38), ["--avatar-hue" as string]: hueOf(entryId) }}
    >
      {initials(name)}
    </span>
  );
}

/** Any other picture field, at `size`. */
export function FieldPicture({
  entryId,
  field,
  value,
  size = 96,
}: {
  entryId: string;
  field: string;
  value: unknown;
  size?: number;
}) {
  const url = usePicture(entryId, field, value);
  return url ? (
    <img className="field-picture" src={url} alt="" style={{ maxWidth: size, maxHeight: size }} />
  ) : (
    <span className="muted">(picture)</span>
  );
}

/** The way back: the portal, then each page above this one. */
export function Crumbs({ trail }: { trail: ReadonlyArray<{ label: string; href?: string }> }) {
  return (
    <nav aria-label="Breadcrumb" className="crumbs">
      <ol>
        <li>
          <a href="#/">Portal</a>
        </li>
        {trail.map((c, i) => (
          <li key={`${c.label}-${i}`}>
            {c.href ? (
              <a href={c.href}>{c.label}</a>
            ) : (
              <span aria-current="page">{c.label}</span>
            )}
          </li>
        ))}
      </ol>
    </nav>
  );
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

/** Escape a vCard text value (RFC 6350 §3.4). */
function vEscape(s: string): string {
  return s.replace(/\\/g, "\\\\").replace(/\n/g, "\\n").replace(/,/g, "\\,").replace(/;/g, "\\;");
}

/**
 * A vCard 4.0 (RFC 6350; `PRONOUNS` from RFC 9554) of what this viewer sees of a
 * member — nothing more than the page shows, made in the browser, sent nowhere.
 */
export function vcardOf(
  entryId: string,
  fields: Record<string, unknown>,
  labels: ReadonlyMap<string, string>,
  community: string,
): string {
  const lines = ["BEGIN:VCARD", "VERSION:4.0"];
  const name = nameOf(fields) ?? "Member";
  lines.push(`FN:${vEscape(name)}`);
  if (text(fields.nickname)) lines.push(`NICKNAME:${vEscape(text(fields.nickname))}`);
  if (text(fields.pronouns)) lines.push(`PRONOUNS:${vEscape(text(fields.pronouns))}`);
  if (text(fields.bio)) lines.push(`NOTE:${vEscape(text(fields.bio))}`);
  const links = Array.isArray(fields.links) ? fields.links.map(String) : [];
  for (const l of links) {
    const u = safeUrl(l);
    if (u) lines.push(`URL:${u}`);
  }
  if (text(fields.did)) lines.push(`IMPP:${vEscape(text(fields.did))}`);
  lines.push(`ORG:${vEscape(community)}`);
  if (text(fields.role)) lines.push(`ROLE:${vEscape(text(fields.role))}`);
  const shown = new Set([
    "displayName", "nickname", "pronouns", "bio", "links", "did", "role", "avatar",
    "joinedAt", "personhood",
  ]);
  for (const [key, value] of Object.entries(fields)) {
    if (shown.has(key) || blobRef(value)) continue;
    const v = text(value);
    if (v) lines.push(`X-VTC-FIELD;LABEL=${vEscape(labels.get(key) ?? key)}:${vEscape(v)}`);
  }
  lines.push(`UID:urn:vtc-directory:${entryId}`, "END:VCARD");
  return lines.join("\r\n") + "\r\n";
}

/** Offer `vcard` as a file the browser saves. */
export function saveVcard(vcard: string, name: string): void {
  const blob = new Blob([vcard], { type: "text/vcard;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `${name.replace(/[^\p{L}\p{N} _-]/gu, "").trim() || "member"}.vcf`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 0);
}
