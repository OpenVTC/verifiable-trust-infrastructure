// A member's directory picture in the console — or their initials when they
// show none — and the other value shapes a directory entry holds that are not
// text: a picture reference and a verified value.
//
// A picture is read only through `vtc/directory/images/get`, which answers
// what the administrator's projection allows, and is shown only once its bytes
// match the digest the card names. It is shown as a `data:` URL, never fetched
// from anywhere else.

import { useQuery } from "@tanstack/react-query";
import { BadgeCheck } from "lucide-react";

import { getImage } from "@/lib/directory";
import type { DirectoryCardBlobRef } from "@/lib/wire-types";
import { pictureUrl } from "@/members/picture";

/** `v` as a picture reference, if it is one. */
export function blobRef(v: unknown): DirectoryCardBlobRef | null {
  if (!v || typeof v !== "object" || Array.isArray(v)) return null;
  const r = v as Partial<DirectoryCardBlobRef>;
  return typeof r.sha256 === "string" && typeof r.mediaType === "string"
    ? (r as DirectoryCardBlobRef)
    : null;
}

/** A credential-sourced value: the claim, and the issuer that attests it. */
export interface VerifiedValue {
  value: string | number | boolean;
  issuer: string;
  credentialType?: string;
  verifiedAt: string;
  validUntil?: string;
}

/** `v` as a verified value, if it is one. */
export function verifiedValue(v: unknown): VerifiedValue | null {
  if (!v || typeof v !== "object" || Array.isArray(v)) return null;
  const r = v as Partial<VerifiedValue>;
  return typeof r.issuer === "string" &&
    "value" in r &&
    typeof r.verifiedAt === "string"
    ? (r as VerifiedValue)
    : null;
}

/** Up to two initials from a name; `?` when there is none. */
export function initials(name: string | null | undefined): string {
  const words = (name ?? "").trim().split(/\s+/).filter(Boolean);
  if (words.length === 0) return "?";
  const letters =
    words.length > 1 ? [words[0]!, words[words.length - 1]!] : [words[0]!];
  return (
    letters
      .map((w) => [...w][0] ?? "")
      .join("")
      .toUpperCase() || "?"
  );
}

/** A stable hue for a key, so a member keeps one colour wherever they appear. */
export function hueOf(key: string): number {
  let h = 0;
  for (const c of key) h = (h * 31 + c.charCodeAt(0)) % 360;
  return h;
}

async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", bytes as BufferSource);
  return Array.from(new Uint8Array(digest), (b) =>
    b.toString(16).padStart(2, "0"),
  ).join("");
}

/** The picture `value` names on `entryId`'s `field`, as a `data:` URL; `null`
 *  until it is read, and when it is not this administrator's to see. */
export function useDirectoryPicture(
  entryId: string | undefined,
  field: string,
  value: unknown,
): string | null {
  const ref = blobRef(value);
  const q = useQuery({
    queryKey: ["directory", "image", entryId ?? "", field, ref?.sha256 ?? ""],
    enabled: Boolean(entryId) && ref !== null,
    retry: false,
    staleTime: Infinity,
    queryFn: async () => {
      const got = await getImage(entryId!, field, ref!.sha256);
      const b64 = got.data.replace(/-/g, "+").replace(/_/g, "/");
      const bytes = Uint8Array.from(
        atob(b64 + "=".repeat((4 - (b64.length % 4)) % 4)),
        (c) => c.charCodeAt(0),
      );
      if ((await sha256Hex(bytes)) !== ref!.sha256)
        throw new Error("picture digest mismatch");
      return pictureUrl(got.image.mediaType, got.data);
    },
  });
  return q.data ?? null;
}

/** A member's avatar, or their initials on their own colour. */
export function DirectoryAvatar({
  entryId,
  value,
  name,
  colourKey,
  size = 32,
}: {
  entryId?: string;
  value: unknown;
  name: string | null | undefined;
  /** What the initials' colour is derived from: the entry, else the DID. */
  colourKey: string;
  size?: number;
}) {
  const url = useDirectoryPicture(entryId, "avatar", value);
  const style = { width: size, height: size };
  if (url) {
    return (
      <img
        className="dir-avatar"
        src={url}
        alt=""
        width={size}
        height={size}
        style={style}
      />
    );
  }
  return (
    <span
      className="dir-avatar dir-avatar-initials"
      aria-hidden="true"
      style={{
        ...style,
        fontSize: Math.round(size * 0.4),
        ["--avatar-hue" as string]: hueOf(colourKey),
      }}
    >
      {initials(name)}
    </span>
  );
}

/** Any other picture field, scaled to `size`. */
export function DirectoryPicture({
  entryId,
  field,
  value,
  size = 120,
}: {
  entryId: string;
  field: string;
  value: unknown;
  size?: number;
}) {
  const url = useDirectoryPicture(entryId, field, value);
  return url ? (
    <img
      className="dir-picture"
      src={url}
      alt=""
      style={{ maxWidth: size, maxHeight: size }}
    />
  ) : (
    <span className="muted">(picture)</span>
  );
}

/** A verified value with its issuer as the badge. */
export function VerifiedValueView({ value }: { value: VerifiedValue }) {
  return (
    <span className="dir-verified">
      {String(value.value)}{" "}
      <span
        className="chip success"
        title={`Verified ${value.verifiedAt}${value.validUntil ? `, until ${value.validUntil}` : ""}`}
      >
        <BadgeCheck size={12} aria-hidden="true" />{" "}
        {value.credentialType ?? "Verified"} · <code>{value.issuer}</code>
      </span>
    </span>
  );
}
