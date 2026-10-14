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

/** Where a room's detail page is, relative to the rooms list. */
export function roomPath(roomId: string): string {
  return `/rooms/${encodeURIComponent(roomId)}`;
}
