// What the host pages (the Rooms list and a room's own page) can say about a
// room's name.
//
// A host never knows what a room is called: the name is the owner's, and a
// member-owned room's never reaches this community. The one exception is a room
// the community owns itself, whose label it chose at `vtc/rooms/community/create`
// and keeps in its own record. So for a viewer who may read that record
// (`vtc.rooms.manage`), the owner's list (`vtc/rooms/community/list/0.2`) is
// joined on room DID and the host pages show the label and description (never
// the tags, which are the Community rooms tab's filing); a viewer with only the
// host's authority (`vtc.rooms.admin`) sees the DID, as before, and is not
// shown an error for a read they were never going to be allowed.
//
// The read shares its query with the Community rooms tab, under `["rooms"]`,
// so a live `rooms` hint re-reads it as it does the host's own reads.

import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";

import { fetchCommunityRooms } from "@/lib/community-rooms-api";
import { useLivePollMs } from "@/lib/use-live-events";
import { useCan } from "@/lib/viewer";

import { COMMUNITY_ROOMS_KEY } from "./CommunityRooms";
import { communityRoomPath } from "./shared";

/** What the console knows about whose a room is. */
export type RoomName =
  /** The community owns it, and these are the label and description it gave
   *  the room. */
  | { readonly kind: "community"; readonly label: string; readonly description?: string }
  /** The community's own list was read in full and the room is not in it, so a
   *  member owns it — and named it, out of this community's sight. */
  | { readonly kind: "member" }
  /** The console cannot tell: the viewer may not read the community's rooms,
   *  or the read failed, is pending, or was cut short. */
  | { readonly kind: "unknown" };

const UNKNOWN: RoomName = { kind: "unknown" };

/** A lookup from room DID to what can be said about its name. */
export function useRoomNames(): (roomId: string) => RoomName {
  const manager = useCan("vtc.rooms.manage", "*");
  const pollMs = useLivePollMs("rooms");
  const q = useQuery({
    queryKey: [...COMMUNITY_ROOMS_KEY, "list"],
    queryFn: fetchCommunityRooms,
    enabled: manager,
    refetchInterval: pollMs,
    // A refused or failed read leaves the DID showing; it is not worth retrying
    // ahead of the next poll.
    retry: false,
  });
  if (!manager || !q.data) return () => UNKNOWN;
  const owned = new Map(q.data.rooms.map((r) => [r.room.roomId, r]));
  const complete = !q.data.truncated;
  return (roomId) => {
    const r = owned.get(roomId);
    if (r !== undefined) {
      return {
        kind: "community",
        label: r.label,
        ...(r.description ? { description: r.description } : {}),
      };
    }
    return complete ? { kind: "member" } : UNKNOWN;
  };
}

/** The badge a community-owned room carries on the host pages, linking to where
 *  the community runs it. */
export function CommunityRoomBadge({ roomId }: { roomId: string }) {
  return (
    <Link to={communityRoomPath(roomId)} className="chip" title="Run from the Community rooms tab">
      Community room
    </Link>
  );
}

/** Said on a member-owned room instead of a blank name. */
export const MEMBER_NAMED_NOTE = "Named by its owner; this community never sees room names.";
