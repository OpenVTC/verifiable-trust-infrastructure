// The pieces every portal page draws a badge with: its picture, a tile on a
// wall, and the words for where an award stands.
//
// A badge's picture is read only through `vtc/badges/images/get`, which
// answers for a badge this member may see, and is shown only once its bytes
// match the digest the badge names — a `data:` URL, never fetched from
// anywhere else. The picture keeps its own shape: a wide banner stays wide, a
// square stays square.

import { useQuery } from "@tanstack/react-query";
import { ShieldCheck } from "lucide-react";

import { badgeHref, getBadgeImage, type Badge } from "./badges-api";
import { pictureUrl } from "./picture";

async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", bytes as BufferSource);
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, "0")).join("");
}

/** The badge's picture as a `data:` URL; `null` until it is read. */
export function useBadgePicture(badge: Badge | null | undefined): string | null {
  const q = useQuery({
    queryKey: ["badges", "image", badge?.badgeId ?? "", badge?.image.sha256 ?? ""],
    enabled: Boolean(badge),
    retry: false,
    staleTime: Infinity,
    queryFn: async () => {
      const got = await getBadgeImage(badge!.badgeId, badge!.image.sha256);
      const b64 = got.data.replace(/-/g, "+").replace(/_/g, "/");
      const bytes = Uint8Array.from(atob(b64 + "=".repeat((4 - (b64.length % 4)) % 4)), (c) => c.charCodeAt(0));
      if ((await sha256Hex(bytes)) !== badge!.image.sha256) throw new Error("picture digest mismatch");
      return pictureUrl(got.image.mediaType, got.data);
    },
  });
  return q.data ?? null;
}

/** A badge's picture, `width` wide; its name's first letter while there is none. */
export function BadgeArt({ badge, width = 120 }: { badge: Badge; width?: number }) {
  const url = useBadgePicture(badge);
  return url ? (
    <img className="bw-art" src={url} alt="" style={{ width }} />
  ) : (
    <span className="bw-art bw-art-blank" aria-hidden="true" style={{ width, height: width }}>
      {[...badge.name.trim()][0]?.toUpperCase() ?? "?"}
    </span>
  );
}

/** A badge on a wall: its picture, its name, how many times it is held, a
 *  pin, and the credential mark on a community badge. Links to the badge. */
export function BadgeTile({
  badge,
  count,
  pinned,
  width = 150,
  children,
}: {
  badge: Badge;
  count?: number;
  pinned?: boolean;
  width?: number;
  children?: React.ReactNode;
}) {
  return (
    <div className={`bw-tile${pinned ? " bw-tile-pinned" : ""}`} style={{ width }}>
      <a className="bw-tile-link" href={badgeHref(badge.badgeId)} title={badge.description}>
        <span className="bw-tile-art">
          <BadgeArt badge={badge} width={width - 16} />
          {badge.kind === "community" && (
            <span className="bw-vc" title="Comes with a credential">
              <ShieldCheck size={14} aria-hidden="true" />
            </span>
          )}
          {typeof count === "number" && count > 1 && <span className="bw-count">×{count}</span>}
        </span>
        <span className="bw-tile-name">{badge.name}</span>
      </a>
      {children}
    </div>
  );
}

export const STATE_WORDS: Record<string, string> = {
  offered: "Waiting for you",
  accepted: "Accepted",
  declined: "Declined",
  withdrawn: "Withdrawn",
  expired: "Expired",
  revoked: "Taken back",
};

/** A date, as the portal shows one. */
export function ago(iso: string | undefined): string {
  if (!iso) return "";
  const ms = Date.now() - Date.parse(iso);
  const d = Math.floor(ms / 86_400_000);
  if (d <= 0) {
    const h = Math.floor(ms / 3_600_000);
    return h <= 0 ? "just now" : `${h} hour${h === 1 ? "" : "s"} ago`;
  }
  if (d < 30) return `${d} day${d === 1 ? "" : "s"} ago`;
  return new Date(iso).toLocaleDateString(undefined, { dateStyle: "medium" });
}
