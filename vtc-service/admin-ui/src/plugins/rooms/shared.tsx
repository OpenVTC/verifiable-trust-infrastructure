// What the rooms list and a room's own page both say about a room: its tier and
// its lifecycle state. The reasoning behind both is in `plugins/rooms.tsx`'s
// header.

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

// ── Where things are on the Data rooms page (`plugins/dataRooms.tsx`) ──
//
// One page with three tabs: the rooms list at `/rooms`, usage at
// `/rooms/usage`, storage at `/rooms/storage` (a config at
// `/rooms/storage/<configId>`). A room's own page is `/rooms/r/<roomId>`, not
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

/** Where a room's own page is. */
export function roomPath(roomId: string): string {
  return `${ROOMS_PATH}/r/${encodeURIComponent(roomId)}`;
}

/** Where one storage config's page is. */
export function configPath(configId: string): string {
  return `${STORAGE_PATH}/${encodeURIComponent(configId)}`;
}
