// Rooms the community itself owns — `vtc/rooms/community/*`
// (docs/03-vtc/community-rooms.md, docs/05-design-notes/data-rooms-files.md §8.4).
// The console is baked into the VTC it talks to, so it reads and creates at 0.2
// only: the shape that carries each room's description, tags and who last
// changed them (`CommunityRoomV2`).
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
// `update` changes a room's label, description and tags and takes no gesture:
// it reaches no key holder and changes nobody's access. They are the
// community's own record as the room's owner; tags are for administrators only
// and never reach an offer. All three are administrator-written free text,
// rendered as text and never as markup.
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
  CommunityRoomUpdatePayload,
  CommunityRoomUpdateResponse,
} from "./wire-types";

export const COMMUNITY_ROOMS_CREATE_TASK = "https://trusttasks.org/spec/vtc/rooms/community/create/0.3";
export const COMMUNITY_ROOMS_LIST_TASK = "https://trusttasks.org/spec/vtc/rooms/community/list/0.2";
export const COMMUNITY_ROOMS_GET_TASK = "https://trusttasks.org/spec/vtc/rooms/community/get/0.2";
export const COMMUNITY_ROOMS_UPDATE_TASK = "https://trusttasks.org/spec/vtc/rooms/community/update/0.2";
export const COMMUNITY_ROOMS_MEMBERS_ADD_TASK =
  "https://trusttasks.org/spec/vtc/rooms/community/members/add/0.1";
export const COMMUNITY_ROOMS_MEMBERS_REMOVE_TASK =
  "https://trusttasks.org/spec/vtc/rooms/community/members/remove/0.2";
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

/** One `pnm` command of a [`VtaFix`], and what it is for. */
export interface VtaFixCommand {
  purpose: string;
  command: string;
}

/** Which refusal a [`VtaFix`] answers: a `vtc/rooms/community/*` refusal whose code
 *  ends in `:<refusal>`, and — when `messageContains` is given — whose message
 *  (which, for `keyHolderRefused`, carries the VTA's own code and message) contains
 *  one of those phrases. */
export interface VtaFixWhen {
  refusal: string;
  messageContains?: string[];
}

/** The `pnm` commands, filled in with this VTC's DID and contexts, for one way its
 *  entry at its VTA can be wrong (`vtc_service::rooms::vta_access`). */
export interface VtaFix {
  /** `noEntry`, `scope`, `capability` or `permission`. */
  id: string;
  when: VtaFixWhen[];
  summary: string;
  commands: VtaFixCommand[];
  note: string;
  /** The command that shows the result. */
  check: string;
}

/** What the community's entry at its VTA must hold — the list's
 *  `ext["org.openvtc"].communityRooms.vtaAccess`. Carried on the list, to a holder
 *  of `vtc.rooms.manage`, rather than on a refusal: a refusal's message may not name
 *  the VTA's contexts. */
export interface VtaAccess {
  vtcDid: string;
  /** The context at the VTA holding the VTC's DID, when the VTC records it. */
  vtcDidContext?: string;
  roomsContext?: string;
  /** Whether the rooms context is that context or beneath it. */
  roomsContextInside?: boolean;
  /** The contexts the entry needs. */
  contexts: string[];
  /** What looks wrong in the VTC's configuration. */
  warning?: string;
  /** In the order to try them. */
  fixes: VtaFix[];
}

/** Whether community rooms are on, and if not what the operator adds — the
 *  list's `ext["org.openvtc"].communityRooms`. Absent means on. */
export interface CommunityRoomsSetting {
  enabled: boolean;
  /** The configuration section to add, when off. */
  configure?: string;
  /** What the community's entry at its VTA must hold, and the commands that fix it. */
  vtaAccess?: VtaAccess;
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

/** Whether the room's own profile — its label and description, written into the
 *  room by the community's VTA so its members can read what it is — is written,
 *  still being retried, or was never written (a room made before create 0.3,
 *  until its next update). The VTC's `ext["org.openvtc"].roomProfile`. */
export interface RoomProfileState {
  state: "written" | "pending" | "none";
  attempts?: number;
  writtenAt?: string;
  nextAttemptAt?: string;
  lastError?: string;
}

/** One room's profile state, from a `get`'s `ext`. */
export function roomProfileStateOf(ext: unknown): RoomProfileState | null {
  const r = (ext as { "org.openvtc"?: { roomProfile?: Record<string, unknown> } } | undefined)?.[
    "org.openvtc"
  ]?.roomProfile;
  if (!r || (r.state !== "written" && r.state !== "pending" && r.state !== "none")) return null;
  const str = (k: string) => (typeof r[k] === "string" ? { [k]: r[k] as string } : {});
  return {
    state: r.state,
    ...(typeof r.attempts === "number" ? { attempts: r.attempts } : {}),
    ...str("writtenAt"),
    ...str("nextAttemptAt"),
    ...str("lastError"),
  };
}

/** What a create or update's `roomProfile` means, in words — `null` when it needs none. */
export function roomProfileNotice(roomProfile: string | undefined): string | null {
  return roomProfile === "pending"
    ? "Its members cannot read the new name in the room yet: the community's VTA has not written it. The VTC keeps trying."
    : null;
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

function accessOf(v: unknown): VtaAccess | undefined {
  const a = v as Partial<VtaAccess> | undefined;
  if (!a || typeof a.vtcDid !== "string" || !Array.isArray(a.fixes)) return undefined;
  const fixes = a.fixes.filter(
    (f): f is VtaFix =>
      !!f &&
      typeof f.id === "string" &&
      Array.isArray(f.when) &&
      Array.isArray(f.commands) &&
      f.commands.every((c) => typeof c?.command === "string"),
  );
  return { ...a, contexts: Array.isArray(a.contexts) ? a.contexts : [], fixes } as VtaAccess;
}

function settingOf(ext: unknown): CommunityRoomsSetting | null {
  const c = (
    ext as
      | { "org.openvtc"?: { communityRooms?: { enabled?: unknown; configure?: unknown; vtaAccess?: unknown } } }
      | undefined
  )?.["org.openvtc"]?.communityRooms;
  if (!c || typeof c.enabled !== "boolean") return null;
  const vtaAccess = accessOf(c.vtaAccess);
  return {
    enabled: c.enabled,
    ...(typeof c.configure === "string" ? { configure: c.configure } : {}),
    ...(vtaAccess ? { vtaAccess } : {}),
  };
}

/** The query key of the owner's list, under `["rooms"]` (which a live `rooms` hint
 *  invalidates). A refusal card reads the same cached list for its fix. */
export const COMMUNITY_ROOMS_LIST_KEY = ["rooms", "community", "list"] as const;

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

/** A removal the community owes a member who left it, until its worker completes it —
 *  `ext["org.openvtc"].departureRemovals` on the community-room reads. */
export interface DepartureRemoval {
  roomId: string;
  member: string;
  /** `left`, `removed`, `aclRemoved`, `expired` or `suspended`. */
  cause: string;
  departedAt: string;
  /** `pending`, or `retrying` once an attempt has failed. */
  status: string;
  attempts: number;
  nextAttemptAt: string;
  lastAttemptAt?: string;
  lastError?: string;
}

export function departureRemovalsOf(ext: unknown): DepartureRemoval[] {
  const rows = (ext as { "org.openvtc"?: { departureRemovals?: unknown } } | undefined)?.[
    "org.openvtc"
  ]?.departureRemovals;
  if (!Array.isArray(rows)) return [];
  return rows.filter(
    (r): r is DepartureRemoval =>
      typeof r === "object" &&
      r !== null &&
      typeof (r as DepartureRemoval).member === "string" &&
      typeof (r as DepartureRemoval).roomId === "string",
  );
}

/** Every member record of one room — offered, admitted and removed, or only
 *  those in `state` — and the removals owed to those who left the community. */
export async function fetchCommunityRoomMembers(
  roomId: string,
  state?: CommunityRoomMemberState,
): Promise<{ items: CommunityRoomMember[]; truncated: boolean; departures: DepartureRemoval[] }> {
  const items: CommunityRoomMember[] = [];
  let departures: DepartureRemoval[] | null = null;
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
    departures ??= departureRemovalsOf(body.ext);
    cursor = body.nextCursor;
    if (!cursor) return { items, truncated: false, departures };
  }
  return { items, truncated: true, departures: departures ?? [] };
}

/** `vtc/rooms/community/create/0.3`, after the requester's bound gesture: the
 *  community's VTA also writes the label and description into the room as its
 *  profile (`roomProfile` says whether it did yet). */
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

/** `vtc/rooms/community/update/0.2` — and a new label or description is written
 *  into the room as its profile. It asks for no gesture; one is given only
 *  if the community's policy asks for it all the same. */
export function updateCommunityRoom(
  payload: CommunityRoomUpdatePayload,
  confirmGesture: ConfirmGesture,
): Promise<CommunityRoomUpdateResponse> {
  return postSignedWithStepUp<CommunityRoomUpdateResponse>(
    COMMUNITY_ROOMS_UPDATE_TASK,
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

/** `vtc/rooms/community/members/remove/0.2`, after the requester's bound gesture. */
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

// ── A room's details ────────────────────────────────────────────────────

/** The most tags a room carries (`RoomTags`). */
export const MAX_TAGS = 8;
/** The longest description (`RoomDescription`). */
export const MAX_DESCRIPTION = 1000;
const TAG = /^[a-z0-9][a-z0-9-]{0,31}$/;

/** Tags as typed — separated by commas or spaces — read as a set, in the order
 *  first given; or what is wrong with them. Case is not changed: `Board` is
 *  refused rather than silently filed as `board`. */
export function parseTags(text: string): { tags: string[] } | { error: string } {
  const tags: string[] = [];
  for (const t of text.split(/[\s,]+/).filter((t) => t !== "")) {
    if (!TAG.test(t)) {
      return {
        error: `“${t}” is not a tag: lower-case letters, digits and hyphens, starting with a letter or digit, at most 32.`,
      };
    }
    if (!tags.includes(t)) tags.push(t);
  }
  if (tags.length > MAX_TAGS) return { error: `At most ${MAX_TAGS} tags.` };
  return { tags };
}

/** The details an Edit details form holds. */
export interface RoomDetailsForm {
  label: string;
  description: string;
  tags: string[];
  reason: string;
}

const sameSet = (a: readonly string[], b: readonly string[]) =>
  a.length === b.length && a.every((t) => b.includes(t));

/** The `update` payload naming only what `form` changes on `room` — each member
 *  given replaces the stored one — or `null` when it changes nothing. An emptied
 *  description is `removeDescription`, emptied tags are `tags: []`. */
export function detailsUpdate(room: CommunityRoom, form: RoomDetailsForm): CommunityRoomUpdatePayload | null {
  const payload: CommunityRoomUpdatePayload = { roomId: room.room.roomId, reason: form.reason.trim() };
  const label = form.label.trim();
  if (label !== room.label) payload.label = label;
  const description = form.description.trim();
  if (description === "" && room.description) payload.removeDescription = true;
  else if (description !== "" && description !== room.description) payload.description = description;
  if (!sameSet(form.tags, room.tags ?? [])) payload.tags = form.tags;
  return Object.keys(payload).length > 2 ? payload : null;
}

/** Every tag the rooms carry, sorted, for the list's filter. */
export function tagsOf(rooms: readonly CommunityRoom[]): string[] {
  return [...new Set(rooms.flatMap((r) => r.tags ?? []))].sort();
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
// `vtc/rooms/community/members/remove/0.2` producer item 1: show the requester,
// before the request is signed and before the gesture bound to it, what removal
// does and does not do on the room's tier, and on a private room the member's
// `validUntil`. Item 2: report the answer from its structured members —
// `revocation` and `revokedAt` where present, `validUntil` where they are
// absent, and `epoch` — never as ending access to what the member already read.

/** What removing `member` from a room at `visibility` will do. */
export function removalPreview(visibility: string, member: CommunityRoomMember): string {
  if (visibility === "private") {
    if (member.state === "offered") {
      return "Their open offer is withdrawn, so it can never be accepted.";
    }
    return (
      "This room is private: a member cannot be withdrawn one at a time, because its host does not " +
      "know who its members are. They leave the room's group, so they cannot open anything written " +
      `from now on, but a host honours their credentials until ${member.validUntil}. Nothing they ` +
      "already read can be recalled."
    );
  }
  const withdrawn =
    "The room's host refuses their credentials — and anything they delegated to an agent — from the " +
    "moment it accepts the room's revocation list.";
  if (member.state === "offered") {
    return `Their open offer is withdrawn, so it can never be accepted. ${withdrawn}`;
  }
  if (visibility === "open") {
    return `${withdrawn} Nothing they already read can be recalled.`;
  }
  return (
    `${withdrawn} They also leave the room's group and the room advances to an epoch sealed to ` +
    "everyone else. Nothing they already read can be recalled, and nothing written before is re-sealed."
  );
}

/** What a completed removal did, from the answer's structured members. */
export function removalOutcome(answer: CommunityRoomMembersRemoveResponse): string {
  const sealed =
    answer.epoch !== undefined ? ` Epoch ${answer.epoch} is the first sealed without them.` : "";
  if (answer.revocation !== undefined) {
    return (
      `Removed. The host refuses their credentials from ${answer.revokedAt ?? "now"} ` +
      `(revocation list ${answer.revocation.sequence}).${sealed}`
    );
  }
  return (
    `Removed.${sealed} Their credentials were not withdrawn at the host (a private room) and are ` +
    `honoured until ${answer.member.validUntil}.`
  );
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
        "an entry covering the context that holds the VTC's DID and the rooms context, that may " +
        "mint DIDs, issue credentials and keep them (key-mint,credential-write,vault-write; the " +
        "community rooms guide has the command)."
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
        `The community's VTA refused and nothing changed.${said} If it is a permission refusal, ` +
        "the VTC's entry at its VTA must cover the context holding the VTC's own DID (the " +
        "persona the community acts as) as well as the rooms context, as initiator; on a room " +
        "already created, check too that the community's own authority over it has not lapsed."
      );
    }
    case "notAMember":
      return "Only an active member of this community can be admitted. Use the DID the member is listed under on the Members page.";
    case "alreadyMember":
      return "They already hold an offer or an admission here. To change their actions or expiry, remove them and add them again.";
    case "notInRoom":
      return "They hold neither an admission nor an open offer here; the list below may be out of date.";
    case "notFound":
      return "This community owns no room with that identifier. A room it only hosts is on the Rooms tab, and its name is its owner's.";
    default:
      return null;
  }
}

/** The fix on the list that answers `err`, when it is a refusal the community's
 *  entry at its VTA explains: the first whose `when` matches (the same rule as
 *  `vtc_service::rooms::vta_access::Fix::matches`). */
export function vtaFixFor(err: unknown, access: VtaAccess | undefined): VtaFix | null {
  if (!access || err instanceof GestureDeclinedError) return null;
  const e = err as ApiError | null;
  const code = e?.code ?? "";
  if (!code.startsWith("vtc/rooms/community/")) return null;
  const short = code.slice(code.lastIndexOf(":") + 1);
  const message = e?.message ?? "";
  return (
    access.fixes.find((f) =>
      f.when.some(
        (w) =>
          w.refusal === short &&
          (!w.messageContains?.length || w.messageContains.some((m) => message.includes(m))),
      ),
    ) ?? null
  );
}

/** A refusal's own message. */
export function refusalMessage(err: unknown): string {
  return (err as { message?: string } | null)?.message ?? String(err);
}
