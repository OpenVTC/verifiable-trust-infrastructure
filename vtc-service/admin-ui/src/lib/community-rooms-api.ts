// Rooms the community itself owns — `vtc/rooms/community/*/0.1`
// (docs/03-vtc/community-rooms.md, docs/05-design-notes/data-rooms-files.md §8.4).
//
// The community is the room's **owner** here, not only its host: its VTA mints
// the room's DID and holds its keys, and the VTC keeps the owner's record of
// whom it offered admission to and admitted. Every task answers a holder of
// `vtc.rooms.manage` — the owner's authority, distinct from hosting's
// `vtc.rooms.admin` — read from the signer's live entry.
//
// `create`, `members/add` and `members/remove` take the requester's passkey
// gesture bound to the one document (`crate::acl::bound_step_up`): the VTC runs
// its checks, refuses with `details.stepUpRequest`, and the identical document
// is sent again once the gesture is recorded (`postSignedWithStepUp`). None is
// parked for a second administrator: a room the community owns is its own, and
// membership is reversible by removal.
//
// Admission is pull-shaped: `members/add` makes an **offer** the member collects
// with their own VTA (`vtc/rooms/offers/*`, `pnm rooms offers accept`). Nothing
// here returns a credential, a key or anything from a room's content.

import type { ApiError } from "./api";
import { postSignedRead } from "./api";
import { GestureDeclinedError, postSignedWithStepUp, type ConfirmGesture } from "./signed-act";
import type {
  CommunityRoom,
  CommunityRoomCreatePayload,
  CommunityRoomCreateResponse,
  CommunityRoomGetResponse,
  CommunityRoomMember,
  CommunityRoomMemberAction,
  CommunityRoomMembersAddPayload,
  CommunityRoomMembersAddResponse,
  CommunityRoomMembersListPayload,
  CommunityRoomMembersListResponse,
  CommunityRoomMemberState,
  CommunityRoomMembersRemovePayload,
  CommunityRoomMembersRemoveResponse,
  CommunityRoomsListResponse,
} from "./wire-types";

export const COMMUNITY_ROOMS_CREATE_TASK = "https://trusttasks.org/spec/vtc/rooms/community/create/0.1";
export const COMMUNITY_ROOMS_LIST_TASK = "https://trusttasks.org/spec/vtc/rooms/community/list/0.1";
export const COMMUNITY_ROOMS_GET_TASK = "https://trusttasks.org/spec/vtc/rooms/community/get/0.1";
export const COMMUNITY_ROOMS_MEMBERS_ADD_TASK =
  "https://trusttasks.org/spec/vtc/rooms/community/members/add/0.1";
export const COMMUNITY_ROOMS_MEMBERS_REMOVE_TASK =
  "https://trusttasks.org/spec/vtc/rooms/community/members/remove/0.1";
export const COMMUNITY_ROOMS_MEMBERS_LIST_TASK =
  "https://trusttasks.org/spec/vtc/rooms/community/members/list/0.1";

/** The owner's authority over the rooms the community owns. */
export const ROOMS_MANAGE = "vtc.rooms.manage";

/** The most rooms or members the specifications return per page. */
const COMMUNITY_PAGE = 100;
/** Pages read before stopping. */
const MAX_COMMUNITY_PAGES = 20;

/** The actions a member may be given. Never `admin`: that is the community's own. */
export const MEMBER_ACTIONS: readonly { id: CommunityRoomMemberAction; hint: string }[] = [
  { id: "read", hint: "Open and read the room's records and files." },
  { id: "write", hint: "Add records and files." },
  { id: "curate", hint: "Edit and remove what others wrote." },
];

/** Whether community rooms are on, and if not what the operator adds — the
 *  list's `ext["org.openvtc"].communityRooms`. Absent means on. */
export interface CommunityRoomsSetting {
  enabled: boolean;
  /** The configuration section to add, when off. */
  configure?: string;
}

/** How the renewal of the community's own authority over a room stands — the
 *  VTC's `ext["org.openvtc"].authorityRenewal` (the shared `CommunityRoom`
 *  has no member for it). The VTC renews it itself, from `renewWithinDays`
 *  before it lapses. */
export interface AuthorityRenewal {
  state: "ok" | "failing";
  attempts?: number;
  lastAttemptAt?: string;
  nextAttemptAt?: string;
  lastError?: string;
  lastRenewedAt?: string;
}

function renewalStatus(v: unknown): AuthorityRenewal | null {
  const r = v as Record<string, unknown> | undefined;
  if (!r || (r.state !== "ok" && r.state !== "failing")) return null;
  const str = (k: string) => (typeof r[k] === "string" ? { [k]: r[k] as string } : {});
  return {
    state: r.state,
    ...(typeof r.attempts === "number" ? { attempts: r.attempts } : {}),
    ...str("lastAttemptAt"),
    ...str("nextAttemptAt"),
    ...str("lastError"),
    ...str("lastRenewedAt"),
  };
}

function renewalExt(ext: unknown): Record<string, unknown> | undefined {
  return (ext as { "org.openvtc"?: { authorityRenewal?: Record<string, unknown> } } | undefined)?.[
    "org.openvtc"
  ]?.authorityRenewal;
}

/** One room's renewal, from a `get`'s `ext`, and the window it renews in. */
export function roomRenewalOf(ext: unknown): (AuthorityRenewal & { renewWithinDays?: number }) | null {
  const r = renewalExt(ext);
  const status = renewalStatus(r);
  if (!status) return null;
  return typeof r?.renewWithinDays === "number" ? { ...status, renewWithinDays: r.renewWithinDays } : status;
}

export interface CommunityRoomsListing {
  rooms: CommunityRoom[];
  setting: CommunityRoomsSetting;
  /** Each listed room's renewal, by room DID, where the VTC has one to report. */
  renewal: Record<string, AuthorityRenewal>;
  /** More rooms exist than the pages read hold. */
  truncated: boolean;
}

function settingOf(ext: unknown): CommunityRoomsSetting | null {
  const c = (ext as { "org.openvtc"?: { communityRooms?: { enabled?: unknown; configure?: unknown } } } | undefined)?.[
    "org.openvtc"
  ]?.communityRooms;
  if (!c || typeof c.enabled !== "boolean") return null;
  return {
    enabled: c.enabled,
    ...(typeof c.configure === "string" ? { configure: c.configure } : {}),
  };
}

/** Every room the community owns, page by page, and whether the feature is on. */
export async function fetchCommunityRooms(): Promise<CommunityRoomsListing> {
  const rooms: CommunityRoom[] = [];
  const renewal: Record<string, AuthorityRenewal> = {};
  let setting: CommunityRoomsSetting | null = null;
  let cursor: string | undefined;
  for (let page = 0; page < MAX_COMMUNITY_PAGES; page++) {
    const body = await postSignedRead<CommunityRoomsListResponse>(COMMUNITY_ROOMS_LIST_TASK, {
      limit: COMMUNITY_PAGE,
      ...(cursor ? { cursor } : {}),
    });
    rooms.push(...body.items);
    setting ??= settingOf(body.ext);
    const perRoom = renewalExt(body.ext)?.rooms as Record<string, unknown> | undefined;
    for (const [id, v] of Object.entries(perRoom ?? {})) {
      const status = renewalStatus(v);
      if (status) renewal[id] = status;
    }
    cursor = body.nextCursor;
    if (!cursor) return { rooms, setting: setting ?? { enabled: true }, renewal, truncated: false };
  }
  return { rooms, setting: setting ?? { enabled: true }, renewal, truncated: true };
}

export function fetchCommunityRoom(roomId: string): Promise<CommunityRoomGetResponse> {
  return postSignedRead<CommunityRoomGetResponse>(COMMUNITY_ROOMS_GET_TASK, { roomId });
}

/** Every member record of one room — offered, admitted and removed, or only
 *  those in `state`. */
export async function fetchCommunityRoomMembers(
  roomId: string,
  state?: CommunityRoomMemberState,
): Promise<{ items: CommunityRoomMember[]; truncated: boolean }> {
  const items: CommunityRoomMember[] = [];
  let cursor: string | undefined;
  for (let page = 0; page < MAX_COMMUNITY_PAGES; page++) {
    const payload: CommunityRoomMembersListPayload = {
      roomId,
      limit: COMMUNITY_PAGE,
      ...(state ? { state } : {}),
      ...(cursor ? { cursor } : {}),
    };
    const body = await postSignedRead<CommunityRoomMembersListResponse>(
      COMMUNITY_ROOMS_MEMBERS_LIST_TASK,
      payload,
    );
    items.push(...body.items);
    cursor = body.nextCursor;
    if (!cursor) return { items, truncated: false };
  }
  return { items, truncated: true };
}

/** `vtc/rooms/community/create/0.1`, after the requester's bound gesture. */
export function createCommunityRoom(
  payload: CommunityRoomCreatePayload,
  confirmGesture: ConfirmGesture,
): Promise<CommunityRoomCreateResponse> {
  return postSignedWithStepUp<CommunityRoomCreateResponse>(
    COMMUNITY_ROOMS_CREATE_TASK,
    payload,
    confirmGesture,
  );
}

/** `vtc/rooms/community/members/add/0.1`, after the requester's bound gesture. */
export function addCommunityRoomMember(
  payload: CommunityRoomMembersAddPayload,
  confirmGesture: ConfirmGesture,
): Promise<CommunityRoomMembersAddResponse> {
  return postSignedWithStepUp<CommunityRoomMembersAddResponse>(
    COMMUNITY_ROOMS_MEMBERS_ADD_TASK,
    payload,
    confirmGesture,
  );
}

/** `vtc/rooms/community/members/remove/0.1`, after the requester's bound gesture. */
export function removeCommunityRoomMember(
  payload: CommunityRoomMembersRemovePayload,
  confirmGesture: ConfirmGesture,
): Promise<CommunityRoomMembersRemoveResponse> {
  return postSignedWithStepUp<CommunityRoomMembersRemoveResponse>(
    COMMUNITY_ROOMS_MEMBERS_REMOVE_TASK,
    payload,
    confirmGesture,
  );
}

// ── Dates ───────────────────────────────────────────────────────────────

/** `days` from `now`, as the RFC 3339 instant a member's admission lasts to. */
export function validUntilIn(days: number, now: Date = new Date()): string {
  return new Date(now.getTime() + days * 86_400_000).toISOString().replace(/\.\d{3}Z$/, "Z");
}

/** Whole days from `now` until `iso`: negative once past, `null` if unreadable. */
export function daysUntil(iso: string | undefined, now: number = Date.now()): number | null {
  if (!iso) return null;
  const at = Date.parse(iso);
  if (Number.isNaN(at)) return null;
  return Math.floor((at - now) / 86_400_000);
}

/** How soon before the community's own authority over a room lapses the page
 *  starts saying so. */
export const AUTHORITY_WARN_DAYS = 30;

// ── What removal does, said before it is signed ─────────────────────────
//
// `vtc/rooms/community/members/remove/0.1` producer item 1: show the requester,
// before the request is signed and before the gesture bound to it, what removal
// does and does not do on the room's tier, and the member's `validUntil`. Item
// 2: report the answer from its structured members, never as ending access to
// what the member already read.

/** What removing `member` from a room at `visibility` will do. */
export function removalPreview(visibility: string, member: CommunityRoomMember): string {
  if (member.state === "offered") {
    return "Their open offer is withdrawn, so it can never be accepted. Nothing was issued to the room's group, so nothing else changes.";
  }
  if (visibility === "open") {
    return (
      "This room is open: it has no group, so removal withdraws nothing cryptographically. " +
      `Their authority credential is not revoked and a host honours it until ${member.validUntil}. ` +
      "Nothing they already read can be recalled."
    );
  }
  return (
    "They leave the room's group and the room advances to an epoch sealed to everyone else, so they " +
    "cannot open anything written from now on. Nothing they already read can be recalled, nothing " +
    "written before is re-sealed, and their authority credential is not revoked: a host honours it " +
    `until ${member.validUntil}, though it opens nothing written after this.`
  );
}

/** What a completed removal did, from the answer's structured members. */
export function removalOutcome(answer: CommunityRoomMembersRemoveResponse): string {
  const until = `Their authority credential is honoured by a host until ${answer.member.validUntil}.`;
  if (answer.epoch !== undefined) {
    return `Removed. Epoch ${answer.epoch} is the first sealed without them. ${until}`;
  }
  return `Removed. Nothing was withdrawn cryptographically (an open room, or an offer withdrawn). ${until}`;
}

// ── Refusals, and what to do about them ─────────────────────────────────

/** What fixes a refusal from one of these tasks, when there is something to do. */
export function refusalFix(err: unknown): string | null {
  if (err instanceof GestureDeclinedError) return null;
  const e = err as ApiError | null;
  const code = e?.code ?? "";
  const short = code.slice(code.lastIndexOf(":") + 1);
  if (code === "permissionDenied") {
    return (
      `Your access-control entry does not hold ${ROOMS_MANAGE}. Ask an administrator who can ` +
      "grant it for a role that includes it (community-admin does)."
    );
  }
  if (!code.startsWith("vtc/rooms/community/")) return null;
  switch (short) {
    case "noKeyHolder":
      return (
        "Community rooms need configuration on this VTC: do what the message says in its " +
        "configuration file and restart it. At the community's VTA, the VTC's own DID also needs " +
        "an entry in that context that may mint DIDs, issue credentials and keep them " +
        "(`pnm acl create --did <VTC DID> --role initiator --contexts <context> " +
        "--capabilities key-mint,credential-write,vault-write`)."
      );
    case "visibilityNotPermitted":
      return (
        "The community's rooms policy refuses a community-owned room at this tier. Choose " +
        "another tier, or change the rooms policy (Policies) to allow it — its input has " +
        "`room.communityOwned = true`."
      );
    case "unknownStorageConfig":
      return "Choose an active storage location from the Storage tab, or leave it empty for the default.";
    case "keyHolderUnavailable": {
      const minted = (e?.details as { roomId?: unknown } | undefined)?.roomId;
      if (code.includes("/members/remove:")) {
        return "The outcome is unknown. Remove them again: the community's VTA settles a removal it may have completed from its own record.";
      }
      return (
        "The community's VTA did not answer and nothing was stored here. Try again once it is " +
        "reachable." +
        (typeof minted === "string"
          ? ` It may have minted ${minted}, which nothing uses: retire it at the VTA.`
          : "")
      );
    }
    case "keyHolderRefused": {
      const d = e?.details as { code?: unknown; message?: unknown } | undefined;
      const said = typeof d?.code === "string" ? ` It answered ${d.code}.` : "";
      return (
        `The community's VTA refused and nothing changed.${said} Check that the VTC's entry at its ` +
        "VTA holds key-mint, credential-write and vault-write in the `[rooms.community]` context, " +
        "and that the community's own authority over this room has not lapsed."
      );
    }
    case "notAMember":
      return "Only an active member of this community can be admitted. Use the DID the member is listed under on the Members page.";
    case "alreadyMember":
      return "They already hold an offer or an admission here. To change their actions or expiry, remove them and add them again.";
    case "notInRoom":
      return "They hold neither an admission nor an open offer here; the list below may be out of date.";
    case "notFound":
      return "This community owns no room with that identifier. A room it only hosts is on the Rooms tab.";
    default:
      return null;
  }
}

/** A refusal's own message. */
export function refusalMessage(err: unknown): string {
  return (err as { message?: string } | null)?.message ?? String(err);
}
