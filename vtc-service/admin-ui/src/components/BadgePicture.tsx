// A badge's picture in the console, and the field that uploads one.
//
// A picture is read only through `vtc/badges/images/get`, which answers for a
// badge the administrator may see, and is shown only once its bytes match the
// digest the badge names — a `data:` URL, never fetched from anywhere else.
// An upload goes through the same pipeline a card picture does: scaled in the
// browser (`@/members/picture`), re-encoded by the community, and named by the
// digest the community answered, which `create` and `update` then quote.

import { useEffect, useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { ImagePlus, Trash2 } from "lucide-react";

import { getBadgeImage, uploadBadgeImage, type BadgeImageRef } from "@/lib/badges";
import { PictureError, pictureUrl, prepare, toBase64Url } from "@/members/picture";

async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", bytes as BufferSource);
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, "0")).join("");
}

/** The picture `image` names on `badgeId`, as a `data:` URL; `null` until it is read. */
export function useBadgePicture(badgeId: string | undefined, image: BadgeImageRef | null | undefined): string | null {
  const q = useQuery({
    queryKey: ["badges", "image", badgeId ?? "", image?.sha256 ?? ""],
    enabled: Boolean(badgeId) && Boolean(image?.sha256),
    retry: false,
    staleTime: Infinity,
    queryFn: async () => {
      const got = await getBadgeImage(badgeId!, image!.sha256);
      const b64 = got.data.replace(/-/g, "+").replace(/_/g, "/");
      const bytes = Uint8Array.from(atob(b64 + "=".repeat((4 - (b64.length % 4)) % 4)), (c) => c.charCodeAt(0));
      if ((await sha256Hex(bytes)) !== image!.sha256) throw new Error("picture digest mismatch");
      return pictureUrl(got.image.mediaType, got.data);
    },
  });
  return q.data ?? null;
}

/** A badge's picture at `size` wide, or its name's first letter while there is none. */
export function BadgePicture({
  badgeId,
  image,
  name,
  size = 64,
}: {
  badgeId: string;
  image: BadgeImageRef;
  name: string;
  size?: number;
}) {
  const url = useBadgePicture(badgeId, image);
  return url ? (
    <img className="badge-picture" src={url} alt="" style={{ width: size, maxHeight: size * 1.5 }} />
  ) : (
    <span className="badge-picture badge-picture-blank" aria-hidden="true" style={{ width: size, height: size }}>
      {[...name.trim()][0]?.toUpperCase() ?? "?"}
    </span>
  );
}

/**
 * Choose and upload a badge picture. `value` is the digest the next `create` /
 * `update` quotes; a chosen file is previewed from the browser's own copy
 * until a badge holds the community's re-encoding.
 */
export function BadgePictureField({
  badgeId,
  current,
  value,
  onChange,
}: {
  /** The badge being changed, to show its current picture; absent for a new one. */
  badgeId?: string;
  /** The badge's picture as it is, for the preview. */
  current?: BadgeImageRef | null;
  /** The upload chosen for the next write, if any. */
  value: BadgeImageRef | null;
  onChange: (next: BadgeImageRef | null) => void;
}) {
  const [error, setError] = useState<string | null>(null);
  const [preview, setPreview] = useState<string | null>(null);
  useEffect(() => () => void (preview && URL.revokeObjectURL(preview)), [preview]);
  const stored = useBadgePicture(badgeId, value ? null : current);
  const send = useMutation({
    mutationFn: async (file: File) => {
      const { mediaType, bytes } = await prepare(file);
      const answer = await uploadBadgeImage(mediaType, toBase64Url(bytes));
      return { image: answer.image, local: URL.createObjectURL(file) };
    },
    onSuccess: ({ image, local }) => {
      setError(null);
      setPreview(local);
      onChange(image);
    },
    onError: (e) => setError(e instanceof PictureError ? e.message : (e as Error).message || "The picture couldn't be sent."),
  });
  const shown = value ? preview : stored;
  return (
    <div className="badge-picture-field">
      {shown ? (
        <img className="badge-picture" src={shown} alt="" style={{ width: 96, maxHeight: 144 }} />
      ) : (
        <span className="badge-picture badge-picture-blank" aria-hidden="true" style={{ width: 96, height: 96 }}>
          ?
        </span>
      )}
      <div className="badge-picture-actions">
        <label className="secondary btn-file">
          <ImagePlus size={14} aria-hidden="true" /> {send.isPending ? "Sending…" : value || current ? "Replace picture" : "Choose a picture"}
          <input
            type="file"
            accept="image/png,image/jpeg,image/webp"
            aria-label="Choose a badge picture"
            hidden
            disabled={send.isPending}
            onChange={(e) => {
              const file = e.target.files?.[0];
              e.target.value = "";
              if (file) send.mutate(file);
            }}
          />
        </label>
        {value && (
          <button type="button" className="secondary" onClick={() => onChange(null)}>
            <Trash2 size={14} aria-hidden="true" /> Keep the old one
          </button>
        )}
        <p className="muted">
          Scaled and re-encoded by the community, with nothing about where or how it was made. Wide banners and
          squares both work; the wall keeps the picture&rsquo;s shape.
        </p>
        {error && (
          <p className="field-error" role="alert">
            {error}
          </p>
        )}
      </div>
    </div>
  );
}
