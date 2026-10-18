// The member's rooms, through their wallet extension.
//
// The portal holds no room credential, no group key and no file key, and its
// server never sees a room's content: every room act goes through the member's
// wallet (`window.vtaWallet.rooms`, the extension's P7b channel), which acts in
// the room as the member's own identity through their VTA. The wallet accepts a
// call only from the portal this community's DID document names
// (`SignInPortal`), and only for rooms the member shared with it in the
// wallet's own window; every write is confirmed there too. Design:
// `docs/05-design-notes/data-rooms-files.md` §8.5.
//
// These types restate the extension's page-facing views
// (`packages/extension/src/bridge-protocol.ts` in OpenVTC/vta-browser-plugin):
// the portal imports nothing from the extension, and a member without it sees
// how to get it instead.

/** A room the member shared with this portal. */
export interface PageRoom {
  roomId: string;
  /** The member (persona DID) the wallet acts as in this room for this portal.
   *  Absent from a wallet older than per-member shares. */
  member?: string;
  epoch?: number;
  earliestReadableEpoch?: number;
  /** False when the member's VTA no longer holds keys for it. */
  held: boolean;
  sharedAt: string;
  expiresAt: string;
  /** The room's name, for a room this community owns: the label its
   *  administrators gave it, which the wallet learns from the community's offer
   *  to the member. Absent for a room a member owns, when the wallet has not
   *  learned it, and from a wallet older than room names. */
  label?: string;
  /** The room's tier, as the same offer gave it. */
  visibility?: string;
}

/**
 * What to call a room: its name when the wallet knows one, else `null` and the
 * page shows the room's DID. The one place the portal decides a room's title —
 * a name from a sealed in-room profile, when rooms have one, comes in here.
 */
export function roomName(room: Pick<PageRoom, "label"> | undefined): string | null {
  const label = room?.label?.trim();
  return label ? label : null;
}

export interface ScopeLimits {
  maxFiles?: number;
  maxFileBytes?: number;
  maxBytes?: number;
}

export interface Usage {
  files: number;
  bytes: number;
  reservedBytes?: number;
  reservedFiles?: number;
}

export interface RoomInfo {
  roomId: string;
  visibility: "open" | "attributed" | "private" | string;
  epoch: number;
  /** The member the wallet acts as in this room. */
  member: string;
  limits: { filesEnabled?: boolean; room?: ScopeLimits; member?: ScopeLimits };
  usage: { room: Usage; member?: { usage: Usage; limits: ScopeLimits } };
}

export interface RecordSummary {
  key: string;
  version: number;
  updatedAt: string;
  status?: string;
  epoch?: number;
  author?: string;
  title?: string;
  description?: string;
}

export interface Listing {
  records: RecordSummary[];
  complete: boolean;
  verification: Record<string, unknown> | undefined;
}

export interface RoomRecord {
  key: string;
  version: number;
  status: string;
  updatedAt: string;
  author?: string;
  title?: string;
  description?: string;
  body?: string;
  tags?: string[];
  file?: { name: string; mediaType?: string; size: number };
  sealed: boolean;
  verification: Record<string, unknown> | undefined;
}

/**
 * One of this community's offers of its rooms to the member, as the wallet
 * shows it (`PageOfferView`): never the offer's credentials. A wallet without
 * offers support has no `offers` method.
 */
export interface PageOffer {
  roomId: string;
  /** The identity the offer is addressed to, which accepting joins as. */
  member: string;
  /** The room's label, as the community's administrators wrote it. */
  label: string;
  /**
   * What the room is for, as the community's administrators wrote it
   * (`vtc/rooms/offers/list/0.2`). Plain text, shown as text and never as
   * markup. Absent when the room has none, or the wallet read the offer from a
   * community or through an agent that does not carry it yet.
   */
  description?: string;
  visibility: "open" | "attributed" | "private" | string;
  actions: string[];
  validUntil: string;
  offeredAt: string;
  state: "open" | "accepted";
  /** An accept began in the wallet and did not finish: accepting again finishes it. */
  inProgress: boolean;
}

/** What the wallet reports after an accept. */
export interface OfferAccepted {
  roomId: string;
  member: string;
  visibility: string;
  /** The member's agent holds the room's group now (a sealed room). */
  joined: boolean;
  epoch?: number;
  resumed: boolean;
}

export interface TransferProgress {
  stage: string;
  done?: number;
  total?: number;
}

export interface WalletRooms {
  list(p: { hostDid: string }): Promise<{ rooms: PageRoom[] }>;
  /** `member`: who is signed in here. The wallet offers only identities it
   *  holds for this community, and uses this to pick among them. */
  choose(p: { hostDid: string; suggest?: string; member?: string }): Promise<{
    rooms: PageRoom[];
    refused: { roomId: string; reason: string }[];
  }>;
  forget(p: { hostDid: string; roomId: string }): Promise<{ forgotten: boolean }>;
  /** This community's offers to the identities the member uses here. Never
   *  prompts. `needsOrigin`: the member has not yet let the wallet reach the
   *  community. Absent from a wallet older than offers support. */
  offers?(p: { hostDid: string }): Promise<{ offers: PageOffer[]; needsOrigin?: string }>;
  /** Ask to accept one: the member decides in the wallet's own window. */
  acceptOffer?(p: { hostDid: string; roomId: string; member?: string }): Promise<OfferAccepted>;
  info(p: { hostDid: string; roomId: string }): Promise<RoomInfo>;
  browse(p: { hostDid: string; roomId: string; prefix?: string; sinceVersion?: number }): Promise<Listing>;
  read(p: { hostDid: string; roomId: string; key: string }): Promise<RoomRecord>;
  putNote(p: {
    hostDid: string;
    roomId: string;
    title: string;
    body?: string;
    description?: string;
    tags?: string[];
  }): Promise<{ key: string; version: number }>;
  getFile(p: {
    hostDid: string;
    roomId: string;
    key: string;
    onProgress?: (p: TransferProgress) => void;
  }): Promise<{
    file: { name: string; mediaType?: string; size: number };
    author: string;
    version: number;
    title?: string;
    blob: Blob;
  }>;
  putFile(p: {
    hostDid: string;
    roomId: string;
    file: Blob;
    name: string;
    title?: string;
    description?: string;
    tags?: string[];
    onProgress?: (p: TransferProgress) => void;
  }): Promise<{ key: string; version: number; size: number }>;
}

/** The wallet's room methods, or `null` when no wallet (or an older one) is on this page. */
export function walletRooms(): WalletRooms | null {
  const w = (window as { vtaWallet?: { rooms?: WalletRooms } }).vtaWallet;
  return w?.rooms && typeof w.rooms.list === "function" ? w.rooms : null;
}

/**
 * A wallet's reason for not sharing a room, with the fix in plain words where
 * the reason is one a member can act on. The wallet's own words stay beside it.
 */
export function shareRefusalHint(reason: string): string | null {
  if (/principalAmbiguous|more than one member|as more than one/.test(reason)) {
    return (
      "Your agent holds this room as more than one identity — for example as the community itself and as you — " +
      "and your wallet did not say which to use. Update your VTA Wallet extension, then choose Share rooms… again " +
      "and tick the room as the identity you signed in here with."
    );
  }
  if (/notAMember|no credential|no group state/.test(reason)) {
    return (
      "Your agent holds no membership in this room for the identity you signed in with. Accept the room's offer " +
      "as that identity first, or sign in here as the identity that holds it."
    );
  }
  return null;
}

/** The offers a member can still act on: open ones, and any whose accept began in the wallet. */
export function actionableOffers(offers: readonly PageOffer[]): PageOffer[] {
  return offers.filter((o) => o.state === "open" || o.inProgress);
}

/** Whether a wallet answer says the member chose not to accept here (the offer stays open). */
export function offerDeclined(e: unknown): boolean {
  const text = e instanceof Error ? e.message : String(e);
  return /declined|did not allow/.test(text);
}

/** Whether a listing's verification says the host contradicted itself. */
export function adverseVerification(v: Record<string, unknown> | undefined): string | null {
  if (!v) return null;
  if (v.count === "short") {
    return "The host committed to more records than it listed: some are being withheld from you.";
  }
  if (v.priorRoots === "conflict") {
    return "The host has shown this room two different ways at the same version.";
  }
  if (v.anchor === "behind" || v.anchor === "conflict") {
    return "The host is serving this room in a state its own witnessed record contradicts.";
  }
  if (v.trace === "failed") {
    return "The host's proof that this record is in the room does not hold.";
  }
  return null;
}

/** Bytes for a person: 0 B, 12.3 KB, 4.0 MB. */
export function formatBytes(n: number): string {
  if (!Number.isFinite(n)) return "—";
  if (n < 1000) return `${n} B`;
  if (n < 1_000_000) return `${(n / 1000).toFixed(1)} KB`;
  if (n < 1_000_000_000) return `${(n / 1_000_000).toFixed(1)} MB`;
  return `${(n / 1_000_000_000).toFixed(2)} GB`;
}

/** Why `size` bytes will not fit, naming the limit and who can raise it — or `null`. */
export function fileWontFit(info: RoomInfo, size: number): string | null {
  if (info.visibility === "open") {
    return "This room is open: its records are readable by its host, so files go in attributed rooms.";
  }
  if (info.limits.filesEnabled === false) return "This community does not accept files in this room.";
  const perFile = Math.min(
    info.limits.room?.maxFileBytes ?? Infinity,
    info.usage.member?.limits.maxFileBytes ?? info.limits.member?.maxFileBytes ?? Infinity,
  );
  if (size > perFile) {
    return `The file is ${formatBytes(size)}; this room takes files up to ${formatBytes(perFile)}. The community sets that limit.`;
  }
  const mine = info.usage.member;
  if (mine?.limits.maxFiles !== undefined && mine.usage.files + (mine.usage.reservedFiles ?? 0) >= mine.limits.maxFiles) {
    return `You have added ${mine.usage.files} of the ${mine.limits.maxFiles} files you may keep in this room. The room's owner can raise your allowance.`;
  }
  const roomFiles = info.limits.room?.maxFiles;
  if (roomFiles !== undefined && info.usage.room.files + (info.usage.room.reservedFiles ?? 0) >= roomFiles) {
    return `The room holds its limit of ${roomFiles} files. The community can raise the room's limit.`;
  }
  const myMax = mine?.limits.maxBytes;
  if (mine && myMax !== undefined && mine.usage.bytes + (mine.usage.reservedBytes ?? 0) + size > myMax) {
    return `You have ${formatBytes(Math.max(0, myMax - mine.usage.bytes))} left of your ${formatBytes(myMax)} in this room. The room's owner can raise your allowance.`;
  }
  const roomMax = info.limits.room?.maxBytes;
  const room = info.usage.room;
  if (roomMax !== undefined && room.bytes + (room.reservedBytes ?? 0) + size > roomMax) {
    return `The room has ${formatBytes(Math.max(0, roomMax - room.bytes))} left of ${formatBytes(roomMax)}. The community can raise the room's limit.`;
  }
  return null;
}
