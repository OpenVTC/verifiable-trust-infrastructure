// Member badges, as a member holds, shows and gives them (`vtc/badges/*`,
// docs/03-vtc/badges.md).
//
// Signed by this browser's portal key for the member, which the member
// delegated `vtc/badges` to at sign-in, as the directory, groups and boards
// pages are. Only the holder's own acts go this way — accepting and declining
// an offer, hiding, showing and arranging their wall, giving kudos, making a
// kudos badge — and the reads any member makes. Defining, changing and
// retiring a community badge, and giving one out, take an owner's or
// administrator's own key in the console (VTI-BDG-095).
//
// Asking for a community badge is a request to join its badge group, decided
// by the badge's owners: `vtc/groups/join` on `badge.groupId` (`./groups-api`).

import type {
  BadgeAwardsShareResponse,
  BadgeAwardsUnshareResponse,
  BadgeClaimsRedeemResponse,
  BadgeCreatePayload,
  BadgeCreateResponse,
  BadgeHoldersListResponse,
  BadgeImagesGetResponse,
  BadgeImagesUploadResponse,
  BadgeKudosGiveResponse,
  BadgeKudosListResponse,
  BadgeListResponse,
  BadgeMineAcceptResponse,
  BadgeMineArrangePayload,
  BadgeMineArrangeResponse,
  BadgeMineDeclineResponse,
  BadgeMineHideResponse,
  BadgeMineListResponse,
  BadgeMineShowResponse,
  BadgeSettingsShowResponse,
  BadgeShowResponse,
  BadgeWallShowResponse,
} from "@/lib/wire-types";

import { send } from "./directory-api";

export const BADGES_SETTINGS_TASK = "https://trusttasks.org/spec/vtc/badges/settings/show/0.1";
export const BADGES_LIST_TASK = "https://trusttasks.org/spec/vtc/badges/list/0.1";
export const BADGES_SHOW_TASK = "https://trusttasks.org/spec/vtc/badges/show/0.1";
export const BADGES_CREATE_TASK = "https://trusttasks.org/spec/vtc/badges/create/0.1";
export const BADGES_IMAGES_UPLOAD_TASK = "https://trusttasks.org/spec/vtc/badges/images/upload/0.1";
export const BADGES_IMAGES_GET_TASK = "https://trusttasks.org/spec/vtc/badges/images/get/0.1";
export const BADGES_HOLDERS_TASK = "https://trusttasks.org/spec/vtc/badges/holders/list/0.1";
export const BADGES_WALL_TASK = "https://trusttasks.org/spec/vtc/badges/wall/show/0.1";
export const MINE_LIST_TASK = "https://trusttasks.org/spec/vtc/badges/mine/list/0.1";
export const MINE_ACCEPT_TASK = "https://trusttasks.org/spec/vtc/badges/mine/accept/0.1";
export const MINE_DECLINE_TASK = "https://trusttasks.org/spec/vtc/badges/mine/decline/0.1";
export const MINE_HIDE_TASK = "https://trusttasks.org/spec/vtc/badges/mine/hide/0.1";
export const MINE_SHOW_TASK = "https://trusttasks.org/spec/vtc/badges/mine/show/0.1";
export const MINE_ARRANGE_TASK = "https://trusttasks.org/spec/vtc/badges/mine/arrange/0.1";
export const KUDOS_GIVE_TASK = "https://trusttasks.org/spec/vtc/badges/kudos/give/0.1";
export const KUDOS_LIST_TASK = "https://trusttasks.org/spec/vtc/badges/kudos/list/0.1";
export const AWARDS_SHARE_TASK = "https://trusttasks.org/spec/vtc/badges/awards/share/0.1";
export const AWARDS_UNSHARE_TASK = "https://trusttasks.org/spec/vtc/badges/awards/unshare/0.1";
export const CLAIMS_REDEEM_TASK = "https://trusttasks.org/spec/vtc/badges/claims/redeem/0.1";

export type Badge = BadgeShowResponse["badge"];
export type BadgeSettings = BadgeSettingsShowResponse["settings"];
export type MyBadge = BadgeMineListResponse["badges"][number];
export type Offer = BadgeMineListResponse["offers"][number];
export type Award = Offer["award"];
export type WallEntry = BadgeWallShowResponse["entries"][number];
export type WallVisibility = BadgeWallShowResponse["visibility"];
export type Holder = BadgeHoldersListResponse["items"][number];
export type ListedBadge = BadgeListResponse["items"][number];
export type KudosRow = BadgeKudosListResponse["items"][number];
export type MyState = ListedBadge["myState"];
/** One of the member's own accepted awards of a badge, as `show` answers them. */
export type MyAward = NonNullable<BadgeShowResponse["myAwards"]>[number];

/** The community's badge settings, as any member reads them. `enabled: false`
 *  hides every badge surface; the pages show nothing then. */
export const showSettings = () => send<BadgeSettingsShowResponse>(BADGES_SETTINGS_TASK, {}).then((r) => r.settings);

/** The badges the member may see: listed ones, and any they hold or were offered.
 *  `mine`: only the kudos badges they made. */
export const listBadges = (kind?: "community" | "kudos", mine?: boolean) =>
  send<BadgeListResponse>(BADGES_LIST_TASK, { limit: 200, ...(kind ? { kind } : {}), ...(mine ? { mine } : {}) });

export const showBadge = (badgeId: string) => send<BadgeShowResponse>(BADGES_SHOW_TASK, { badgeId });

/** The member's own badges and the offers waiting for them. */
export const listMine = () => send<BadgeMineListResponse>(MINE_LIST_TASK, {});

export const acceptOffer = (awardId: string) => send<BadgeMineAcceptResponse>(MINE_ACCEPT_TASK, { awardId });
export const declineOffer = (awardId: string) => send<BadgeMineDeclineResponse>(MINE_DECLINE_TASK, { awardId });
export const hideBadge = (badgeId: string) => send<BadgeMineHideResponse>(MINE_HIDE_TASK, { badgeId });
export const showBadgeAgain = (badgeId: string) => send<BadgeMineShowResponse>(MINE_SHOW_TASK, { badgeId });
export const arrangeWall = (p: BadgeMineArrangePayload) => send<BadgeMineArrangeResponse>(MINE_ARRANGE_TASK, p);

/** Show one accepted award outside the community (VTI-BDG-070): the community answers
 *  the public locations it now serves it at. The member's own choice, award by award;
 *  the page never shares one on its own. */
export const shareAward = (awardId: string) =>
  send<BadgeAwardsShareResponse>(AWARDS_SHARE_TASK, { awardId }).then((r) => r.award);

/** Claim a badge with a code an event's host handed out (VTI-BDG-026): the redemption is
 *  the member's consent, and the badge is theirs from the answer. */
export const redeemClaim = (code: string) =>
  send<BadgeClaimsRedeemResponse>(CLAIMS_REDEEM_TASK, { code: code.trim() }).then((r) => r.award);

/** Stop showing it: the locations answer nothing from now on. Revokes nothing. */
export const unshareAward = (awardId: string) =>
  send<BadgeAwardsUnshareResponse>(AWARDS_UNSHARE_TASK, { awardId }).then((r) => r.award);

/** A member's wall, as the directory shows it to this member. */
export const showWall = (entryId: string) => send<BadgeWallShowResponse>(BADGES_WALL_TASK, { entryId });

/** Who holds a badge, where the badge shows its holders to this member. */
export const listHolders = (badgeId: string) =>
  send<BadgeHoldersListResponse>(BADGES_HOLDERS_TASK, { badgeId, limit: 200 });

export const giveKudos = (badgeId: string, to: string, note?: string) =>
  send<BadgeKudosGiveResponse>(KUDOS_GIVE_TASK, { badgeId, to, ...(note ? { note } : {}) });

/** Kudos the member received, or gave. */
export const listKudos = (direction: "received" | "given") =>
  send<BadgeKudosListResponse>(KUDOS_LIST_TASK, { direction, limit: 200 });

/** Make a kudos badge, the member's own to give. */
export const createKudosBadge = (p: Omit<BadgeCreatePayload, "kind">) =>
  send<BadgeCreateResponse>(BADGES_CREATE_TASK, { kind: "kudos", ...p });

export const uploadBadgeImage = (mediaType: string, data: string) =>
  send<BadgeImagesUploadResponse>(BADGES_IMAGES_UPLOAD_TASK, { mediaType, data });

export const getBadgeImage = (badgeId: string, sha256: string) =>
  send<BadgeImagesGetResponse>(BADGES_IMAGES_GET_TASK, { badgeId, sha256 });

/** The portal's badge pages, by hash. */
export const badgesHref = "#/badges";
export const badgeHref = (badgeId: string) => `#/badges/${encodeURIComponent(badgeId)}`;
export const makeBadgeHref = "#/badges/new";
