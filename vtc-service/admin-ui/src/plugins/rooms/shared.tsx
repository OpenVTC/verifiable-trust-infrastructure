// What the rooms list and a room's own page both say about a room: its tier and
// its lifecycle state. The reasoning behind both is in `plugins/rooms.tsx`'s
// header.

import { roomStateLabel } from "@/lib/community-rooms-api";
import type { CommunityRoomStatus } from "@/lib/wire-types";

export const TIERS = ["open", "attributed", "private"] as const;
export type Tier = (typeof TIERS)[number];

export const TIER_BLURB: Record<Tier, string> = {
  open: "Records are stored in the clear. This host can read every one of them.",
  attributed: "Records are sealed, and this host sees who wrote which.",
  private: "Records are sealed and this host cannot see the membership at all.",
};

export const LIFECYCLE_MEANS: Record<string, string> = {
  live: "Renewed. Accepting writes.",
  lapsed:
    "The epoch expired, so the room is read-only. Nothing is destroyed or hidden, and one renewal returns it to live — often this is just somebody on holiday.",
  dormant:
    "Still unrenewed after the grace window. The owner is owed the notice, and a successor the room nominated may claim it from here.",
  reclaimable:
    "Past the retention period agreed at creation. The host may delete it; reads keep working until it does.",
};

export function LifecyclePill({ value }: { value: string }) {
  // `lapsed` must not read as a failure — the room is intact and one renewal
  // fixes it. `reclaimable` is the only state where anything is at risk.
  const tone =
    value === "live" ? "success" : value === "reclaimable" ? "danger" : "warning";
  return (
    <span className={`chip ${tone}`} title={LIFECYCLE_MEANS[value] ?? value}>
      {value}
    </span>
  );
}

/** What each owner-lifecycle state means — the room's state as its owner (this
 *  community) set it, beside the host's computed lifecycle above. */
export const ROOM_STATE_MEANS: Record<string, string> = {
  active: "Open to change.",
  archived:
    "Closed to change: it admits no one and its host accepts no writes. Reversible with Unarchive.",
  removalScheduled:
    "Every credential is withdrawn and its content is kept until the purge date. The removal can be cancelled until then.",
  purging: "Its content is being deleted at the host and every storage location. Not reversible.",
  removed: "Its content is gone. This record is kept as the room's history.",
};

/** A room's owner-lifecycle state, in words — never colour alone. Active is
 *  neutral; archived is neutral; anything on its way out is a warning, and
 *  removed is muted. */
export function RoomStateChip({ status }: { status?: CommunityRoomStatus }) {
  const state = status?.state ?? "active";
  const tone =
    state === "removalScheduled" || state === "purging" ? "warning" : "";
  return (
    <span className={`chip ${tone}`.trim()} title={ROOM_STATE_MEANS[state] ?? state}>
      {roomStateLabel(status)}
    </span>
  );
}

// ── Where things are on the Data rooms page (`plugins/dataRooms.tsx`) ──
//
// One page with four tabs: the rooms list at `/rooms`, usage at
// `/rooms/usage`, storage at `/rooms/storage` (a config at
// `/rooms/storage/<configId>`), and the rooms the community owns at
// `/rooms/community` (one at `/rooms/community/<roomId>`). A room's own page is `/rooms/r/<roomId>`, not
// `/rooms/<roomId>`: a room's identifier is whatever its owner minted (the
// `rooms/create` schema says only "string", and the host does not assign or
// constrain it), so a bare segment could be `usage` or `storage` and land on a
// tab instead of the room.

/** The Data rooms page: the plugin's path, and its Rooms tab. */
export const ROOMS_PATH = "/rooms";
/** The Usage tab. */
export const USAGE_PATH = `${ROOMS_PATH}/usage`;
/** The Storage tab. */
export const STORAGE_PATH = `${ROOMS_PATH}/storage`;
/** The Community rooms tab: rooms this community owns. */
export const COMMUNITY_PATH = `${ROOMS_PATH}/community`;

/** Where a room's own page is. */
export function roomPath(roomId: string): string {
  return `${ROOMS_PATH}/r/${encodeURIComponent(roomId)}`;
}

/** Where a room the community owns is run from. Its identifier is a DID the
 *  community's VTA minted, so it can never be mistaken for a sub-path. */
export function communityRoomPath(roomId: string): string {
  return `${COMMUNITY_PATH}/${encodeURIComponent(roomId)}`;
}

/** Where one storage config's page is. */
export function configPath(configId: string): string {
  return `${STORAGE_PATH}/${encodeURIComponent(configId)}`;
}
