// Member badges, administered (`vtc/badges/*`, docs/03-vtc/badges.md).
//
// A community badge is a badge group: its owners are the group's managers, its holders the
// group's members, and the group's own identity signs each holder's badge credential. So
// requests to be given a badge are the group's join requests (`vtc/groups/requests/*`), and
// owners are appointed as the group's managers (`vtc/groups/managers/*`) — both through
// `@/lib/groups`. What is here is the badges family itself: the settings, the definitions,
// the pictures, awards given and taken back, and the reads an administrator or owner makes.
//
// Every act is signed by this browser's console key, never a member portal key
// (VTI-BDG-095). The settings and a community badge's retirement take a step-up bound to the
// document (`postSignedWithStepUp`); nothing here parks in the action list.

import { postSignedRead, postSignedTrustTask } from "./api";
import { postSignedWithStepUp, type ConfirmGesture } from "./signed-act";
import type {
  BadgeAwardsListResponse,
  BadgeAwardsOfferPayload,
  BadgeAwardsOfferResponse,
  BadgeAwardsRevokeResponse,
  BadgeAwardsWithdrawResponse,
  BadgeClaimsCreateResponse,
  BadgeClaimsListResponse,
  BadgeClaimsWithdrawResponse,
  BadgeCreatePayload,
  BadgeCreateResponse,
  BadgeHoldersListResponse,
  BadgeImagesGetResponse,
  BadgeImagesUploadResponse,
  BadgeKudosListResponse,
  BadgeListResponse,
  BadgeMineListResponse,
  BadgePromotePayload,
  BadgePromoteResponse,
  BadgeRetireResponse,
  BadgeSettingsShowResponse,
  BadgeSettingsUpdateResponse,
  BadgeShowResponse,
  BadgeUpdatePayload,
  BadgeUpdateResponse,
} from "./wire-types";

export const SETTINGS_SHOW = "https://trusttasks.org/spec/vtc/badges/settings/show/0.1";
export const SETTINGS_UPDATE = "https://trusttasks.org/spec/vtc/badges/settings/update/0.1";
export const CREATE = "https://trusttasks.org/spec/vtc/badges/create/0.1";
export const UPDATE = "https://trusttasks.org/spec/vtc/badges/update/0.1";
export const RETIRE = "https://trusttasks.org/spec/vtc/badges/retire/0.1";
export const PROMOTE = "https://trusttasks.org/spec/vtc/badges/promote/0.1";
export const LIST = "https://trusttasks.org/spec/vtc/badges/list/0.1";
export const SHOW = "https://trusttasks.org/spec/vtc/badges/show/0.1";
export const IMAGES_UPLOAD = "https://trusttasks.org/spec/vtc/badges/images/upload/0.1";
export const IMAGES_GET = "https://trusttasks.org/spec/vtc/badges/images/get/0.1";
export const AWARDS_OFFER = "https://trusttasks.org/spec/vtc/badges/awards/offer/0.1";
export const AWARDS_WITHDRAW = "https://trusttasks.org/spec/vtc/badges/awards/withdraw/0.1";
export const AWARDS_REVOKE = "https://trusttasks.org/spec/vtc/badges/awards/revoke/0.1";
export const AWARDS_LIST = "https://trusttasks.org/spec/vtc/badges/awards/list/0.1";
export const CLAIMS_CREATE = "https://trusttasks.org/spec/vtc/badges/claims/create/0.1";
export const CLAIMS_LIST = "https://trusttasks.org/spec/vtc/badges/claims/list/0.1";
export const CLAIMS_WITHDRAW = "https://trusttasks.org/spec/vtc/badges/claims/withdraw/0.1";
export const HOLDERS_LIST = "https://trusttasks.org/spec/vtc/badges/holders/list/0.1";
export const KUDOS_LIST = "https://trusttasks.org/spec/vtc/badges/kudos/list/0.1";

/** Defines, changes and retires community badges; gives any badge. */
export const BADGES_ADMIN = "vtc.badges.admin";
/** The badge settings (with a bound step-up). */
export const CONFIG_ADMIN = "vtc.config.admin";
export const BADGES_KEY = ["badges"] as const;

export type Badge = BadgeShowResponse["badge"];
export type BadgeSettings = BadgeSettingsShowResponse["settings"];
export type BadgeLimits = NonNullable<BadgeSettings["limits"]>;
export type KudosMakers = BadgeSettings["kudosMakers"];
export type Award = BadgeAwardsListResponse["items"][number]["award"];
export type AwardRow = BadgeAwardsListResponse["items"][number];
export type AwardState = Award["state"];
export type Holder = BadgeHoldersListResponse["items"][number];
export type BadgeListItem = BadgeListResponse["items"][number];
export type MyBadge = BadgeMineListResponse["badges"][number];
export type KudosRow = BadgeKudosListResponse["items"][number];
export type Skipped = BadgeAwardsOfferResponse["skipped"][number];
export type BadgeImageRef = Badge["image"];

/** The badge listings' largest page (`list-limits.json`). */
const PAGE = 200;
/** How many pages a full read follows before it stops. */
const MAX_PAGES = 20;

/** The limits as the community applies them when a setting is unset (`docs/03-vtc/badges.md`). */
export const DEFAULT_LIMITS: Required<Omit<BadgeLimits, "offerExpiresAfterDays">> & {
  offerExpiresAfterDays?: number;
} = {
  kudosPerGiverPerDay: 10,
  sameGiverSameMember: "day",
  minTenureDays: 7,
  kudosBadgesPerMakerPerMonth: 5,
  maxPinned: 2,
};

export const AWARD_STATE_LABEL: Record<AwardState, string> = {
  offered: "Offered",
  accepted: "Accepted",
  declined: "Declined",
  withdrawn: "Withdrawn",
  expired: "Expired",
  revoked: "Taken back",
};

export const SKIPPED_LABEL: Record<Skipped["reason"], string> = {
  notActiveMember: "not an active member",
  alreadyOffered: "already offered",
  alreadyHolder: "already holds it",
  requestPending: "has a request waiting",
};

// ── Settings ─────────────────────────────────────────────────────────────

export const showSettings = () =>
  postSignedRead<BadgeSettingsShowResponse>(SETTINGS_SHOW, {}).then((r) => r.settings);

/** Change the settings: `vtc.config.admin` and the requester's bound step-up. */
export const updateSettings = (settings: BadgeSettings, reason: string, confirm: ConfirmGesture) =>
  postSignedWithStepUp<BadgeSettingsUpdateResponse>(
    SETTINGS_UPDATE,
    { settings: forWire(settings), reason },
    confirm,
  ).then((r) => r.settings);

/** The settings as `settings/update` takes them: nothing the community wrote (`updatedAt`). */
function forWire(s: BadgeSettings): Omit<BadgeSettings, "updatedAt"> {
  const { updatedAt: _updatedAt, ...rest } = s;
  return rest;
}

// ── Definitions ──────────────────────────────────────────────────────────

/** Every badge the signer may see, retired and unlisted ones included, a page at a time. */
export async function listBadges(): Promise<BadgeListItem[]> {
  const out: BadgeListItem[] = [];
  let cursor: string | undefined;
  for (let i = 0; i < MAX_PAGES; i++) {
    const page = await postSignedRead<BadgeListResponse>(LIST, {
      includeRetired: true,
      includeUnlisted: true,
      limit: PAGE,
      ...(cursor ? { cursor } : {}),
    });
    out.push(...page.items);
    if (typeof page.nextCursor !== "string") break;
    cursor = page.nextCursor;
  }
  return out;
}

export const showBadge = (badgeId: string) => postSignedRead<BadgeShowResponse>(SHOW, { badgeId });

export const createBadge = (p: BadgeCreatePayload) => postSignedTrustTask<BadgeCreateResponse>(CREATE, p);

export const updateBadge = (p: BadgeUpdatePayload) =>
  postSignedTrustTask<BadgeUpdateResponse>(UPDATE, p).then((r) => r.badge);

/** Retire a badge. A community badge takes the requester's bound step-up: its group is deleted
 *  and every credential it issued revoked at once. */
export const retireBadge = (badgeId: string, reason: string, confirm: ConfirmGesture) =>
  postSignedWithStepUp<BadgeRetireResponse>(RETIRE, { badgeId, reason }, confirm).then((r) => r.badge);

export const promoteBadge = (p: BadgePromotePayload) => postSignedTrustTask<BadgePromoteResponse>(PROMOTE, p);

// ── Pictures ─────────────────────────────────────────────────────────────

/** Upload a picture for a badge this signer is about to define or change: the community's
 *  re-encoding and its digest, which `create` / `update` name. */
export const uploadBadgeImage = (mediaType: string, data: string) =>
  postSignedTrustTask<BadgeImagesUploadResponse>(IMAGES_UPLOAD, { mediaType, data });

export const getBadgeImage = (badgeId: string, sha256?: string) =>
  postSignedRead<BadgeImagesGetResponse>(IMAGES_GET, { badgeId, ...(sha256 ? { sha256 } : {}) });

// ── Awards ───────────────────────────────────────────────────────────────

export const offerAwards = (p: BadgeAwardsOfferPayload) =>
  postSignedTrustTask<BadgeAwardsOfferResponse>(AWARDS_OFFER, p);

export const withdrawAward = (awardId: string, reason: string) =>
  postSignedTrustTask<BadgeAwardsWithdrawResponse>(AWARDS_WITHDRAW, { awardId, reason }).then((r) => r.award);

export const revokeAward = (awardId: string, reason: string) =>
  postSignedTrustTask<BadgeAwardsRevokeResponse>(AWARDS_REVOKE, { awardId, reason }).then((r) => r.award);

/** A badge's awards, every page, to its owners. */
export async function listAwards(badgeId: string, state?: AwardState): Promise<AwardRow[]> {
  const out: AwardRow[] = [];
  let cursor: string | undefined;
  for (let i = 0; i < MAX_PAGES; i++) {
    const page = await postSignedRead<BadgeAwardsListResponse>(AWARDS_LIST, {
      badgeId,
      ...(state ? { state } : {}),
      limit: PAGE,
      ...(cursor ? { cursor } : {}),
    });
    out.push(...page.items);
    if (typeof page.nextCursor !== "string") break;
    cursor = page.nextCursor;
  }
  return out;
}

/** A badge's holders who show it, every page, and how many there are. */
export async function listHolders(badgeId: string): Promise<{ total: number; items: Holder[] }> {
  const items: Holder[] = [];
  let total = 0;
  let cursor: string | undefined;
  for (let i = 0; i < MAX_PAGES; i++) {
    const page = await postSignedRead<BadgeHoldersListResponse>(HOLDERS_LIST, {
      badgeId,
      limit: PAGE,
      ...(cursor ? { cursor } : {}),
    });
    total = page.total;
    items.push(...page.items);
    if (typeof page.nextCursor !== "string") break;
    cursor = page.nextCursor;
  }
  return { total, items };
}

/** Every giving of a kudos badge, to an administrator (`all`). */
export async function listKudosGivings(badgeId: string): Promise<KudosRow[]> {
  const out: KudosRow[] = [];
  let cursor: string | undefined;
  for (let i = 0; i < MAX_PAGES; i++) {
    const page = await postSignedRead<BadgeKudosListResponse>(KUDOS_LIST, {
      badgeId,
      all: true,
      limit: PAGE,
      ...(cursor ? { cursor } : {}),
    });
    out.push(...page.items);
    if (typeof page.nextCursor !== "string") break;
    cursor = page.nextCursor;
  }
  return out;
}

// ── Claim codes (VTI-BDG-025 – 027) ─────────────────────────────────────

export type ClaimCode = BadgeClaimsListResponse["items"][number];

/** Issue a claim code for an event: the record, and the code itself — answered this once;
 *  the community keeps only its digest. */
export const createClaim = (badgeId: string, label: string, validUntil: string, admits: number) =>
  postSignedTrustTask<BadgeClaimsCreateResponse>(CLAIMS_CREATE, { badgeId, label, validUntil, limit: admits });

export const withdrawClaim = (claimId: string) =>
  postSignedTrustTask<BadgeClaimsWithdrawResponse>(CLAIMS_WITHDRAW, { claimId }).then((r) => r.claim);

/** A badge's claim codes, every page — never a code. */
export async function listClaims(badgeId: string): Promise<ClaimCode[]> {
  const out: ClaimCode[] = [];
  let cursor: string | undefined;
  for (let i = 0; i < MAX_PAGES; i++) {
    const page = await postSignedRead<BadgeClaimsListResponse>(CLAIMS_LIST, {
      badgeId,
      limit: PAGE,
      ...(cursor ? { cursor } : {}),
    });
    out.push(...page.items);
    if (typeof page.nextCursor !== "string") break;
    cursor = page.nextCursor;
  }
  return out;
}

/** The holder's own view is a portal read; the console never signs it. Exported for the type. */
export type MineList = BadgeMineListResponse;

/** Who may see a badge's holders: the badge group's `showMembers`. */
export const HOLDERS_AUDIENCES: { id: "admins" | "groupMembers" | "members"; label: string }[] = [
  { id: "admins", label: "Its owners and administrators" },
  { id: "groupMembers", label: "Its holders, owners and administrators" },
  { id: "members", label: "Every member" },
];
