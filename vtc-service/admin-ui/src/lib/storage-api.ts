// Where this community keeps its rooms' files — `vtc/storage/configs/{list,get,
// create,update}/0.2`, `vtc/storage/configs/{retire,probe}/0.1` and
// `vtc/rooms/storage/{assign,migrate}/0.1` (docs/05-design-notes/data-rooms-files.md §7).
//
// A config is a named backend; every room is assigned to one, which receives
// its new uploads, and every file remembers the config it was written to, so
// moving a room strands nothing. None of these tasks sends or returns a
// credential. An S3 config through a VTA account names an external account at the
// community's VTA, which issues one presigned request per object and holds the
// authority itself. `ambient` (the machine's own cloud identity, S3 optionally
// assuming a named role) and `sealed` (a credential the community keeps) are its
// host operator's to permit; with either, the community mints a credential scoped to
// one room for at most 15 minutes. A sealed credential is never typed into this
// console: it is sealed to the community in `cnm` (`cnm storage credentials set`).
//
// Reads and the probe answer a holder of `vtc.rooms.admin`. Creating, changing
// and retiring a config, and moving a room, decide where members' files go, so
// each needs the requester's operation-bound step-up and is then parked for the
// other holders' consent (`postSignedWithStepUp` → a `ParkedAction`, a success).

import { postSignedRead, postSignedTrustTask } from "./api";
import { postSignedWithStepUp, type ConfirmGesture } from "./signed-act";
import type {
  RoomStorageAssignResponse,
  RoomStorageMigrateResponse,
  StorageConfigCreatePayload,
  StorageConfigCreateResponse,
  StorageConfigGetResponse,
  StorageConfigItem,
  StorageConfigProbeResponse,
  StorageConfigRetireResponse,
  StorageConfigsListResponse,
  StorageConfigUpdatePayload,
  StorageConfigUpdateResponse,
  StorageCredentialState,
} from "./wire-types";

export const STORAGE_LIST_TASK = "https://trusttasks.org/spec/vtc/storage/configs/list/0.2";
export const STORAGE_GET_TASK = "https://trusttasks.org/spec/vtc/storage/configs/get/0.2";
export const STORAGE_CREATE_TASK = "https://trusttasks.org/spec/vtc/storage/configs/create/0.2";
export const STORAGE_UPDATE_TASK = "https://trusttasks.org/spec/vtc/storage/configs/update/0.2";
export const STORAGE_RETIRE_TASK = "https://trusttasks.org/spec/vtc/storage/configs/retire/0.1";
export const STORAGE_PROBE_TASK = "https://trusttasks.org/spec/vtc/storage/configs/probe/0.1";
export const ROOM_STORAGE_ASSIGN_TASK = "https://trusttasks.org/spec/vtc/rooms/storage/assign/0.1";
export const ROOM_STORAGE_MIGRATE_TASK = "https://trusttasks.org/spec/vtc/rooms/storage/migrate/0.1";

/** The most configs the spec returns per page. */
const CONFIGS_PAGE = 100;
/** Pages read before stopping. A community has a handful of configs. */
const MAX_CONFIG_PAGES = 10;

/** Every config, page by page. */
export async function fetchStorageConfigs(): Promise<StorageConfigItem[]> {
  const items: StorageConfigItem[] = [];
  let cursor: string | undefined;
  for (let page = 0; page < MAX_CONFIG_PAGES; page++) {
    const body = await postSignedRead<StorageConfigsListResponse>(STORAGE_LIST_TASK, {
      limit: CONFIGS_PAGE,
      ...(cursor ? { cursor } : {}),
    });
    items.push(...body.items);
    cursor = body.nextCursor;
    if (!cursor) break;
  }
  return items;
}

export function fetchStorageConfig(configId: string): Promise<StorageConfigGetResponse> {
  return postSignedRead<StorageConfigGetResponse>(STORAGE_GET_TASK, { configId });
}

/**
 * Write and read back a canary under the config's own `probe/` prefix — or,
 * without `includeWrite`, only check that the backend answers. Not parked: it
 * changes nothing a room holds.
 */
export function probeStorageConfig(
  configId: string,
  includeWrite: boolean,
): Promise<StorageConfigProbeResponse> {
  return postSignedTrustTask<StorageConfigProbeResponse>(STORAGE_PROBE_TASK, {
    configId,
    includeWrite,
  });
}

export function createStorageConfig(
  payload: StorageConfigCreatePayload,
  confirmGesture: ConfirmGesture,
): Promise<StorageConfigCreateResponse> {
  return postSignedWithStepUp(STORAGE_CREATE_TASK, payload, confirmGesture);
}

export function updateStorageConfig(
  payload: StorageConfigUpdatePayload,
  confirmGesture: ConfirmGesture,
): Promise<StorageConfigUpdateResponse> {
  return postSignedWithStepUp(STORAGE_UPDATE_TASK, payload, confirmGesture);
}

export function retireStorageConfig(
  configId: string,
  reason: string,
  confirmGesture: ConfirmGesture,
): Promise<StorageConfigRetireResponse> {
  return postSignedWithStepUp(STORAGE_RETIRE_TASK, { configId, reason }, confirmGesture);
}

/** Point a room's new uploads at `configId`. Its existing files stay put. */
export function assignRoomStorage(
  roomId: string,
  configId: string,
  reason: string,
  confirmGesture: ConfirmGesture,
): Promise<RoomStorageAssignResponse> {
  return postSignedWithStepUp(
    ROOM_STORAGE_ASSIGN_TASK,
    { roomId, configId, reason },
    confirmGesture,
  );
}

/** The slowest copy rate a migration may be asked for (64 KiB/s). */
export const MIN_MIGRATION_BYTES_PER_SECOND = 65_536;

/**
 * Move a room's existing files onto the storage it is assigned to
 * (`vtc/rooms/storage/migrate/0.1`): copied, checked against what their
 * uploaders committed to, switched, and the old copies deleted after the grace
 * window. Parked for approval like an assignment. Sent again for a room whose
 * migration is running or paused, it answers with that migration — resuming a
 * paused one — and parks nothing.
 */
export function migrateRoomStorage(
  roomId: string,
  reason: string,
  maxBytesPerSecond: number | undefined,
  confirmGesture: ConfirmGesture,
): Promise<RoomStorageMigrateResponse> {
  return postSignedWithStepUp(
    ROOM_STORAGE_MIGRATE_TASK,
    { roomId, reason, ...(maxBytesPerSecond !== undefined ? { maxBytesPerSecond } : {}) },
    confirmGesture,
  );
}

// ── Saying what a config is ─────────────────────────────────────────────

/** What a kind means for a room's files, in one line (§7.2). */
export const KIND_MEANS: Record<string, string> = {
  local: "Files on this host's own disk. Removed when deleted. Not in a VTC backup.",
  s3: "An S3-compatible object store. Removed when deleted.",
  gcs: "Google Cloud Storage. Removed when deleted.",
  walrus: "Public ciphertext on Walrus. Removal is cryptographic: storage lapses, it is not erased.",
};

/**
 * What a `sealed` config is labelled with wherever it is shown
 * (`vtc/storage/configs/create/0.2` item 9, `get/0.2` item 5).
 */
export const SEALED_WARNING =
  "A stored credential protects against every administrator, but not against whoever operates the machine this community runs on: they can recover it.";

/** The command that seals a `sealed` config's credential to the community and sets it.
 *  The console never takes the credential itself. */
export function credentialSetCommand(configId: string): string {
  return `cnm storage credentials set --config ${configId} --file <credential.json> --reason "…"`;
}

/** Whether a config stores nothing until someone acts: no credential yet, or a mode
 *  the host no longer permits. */
export function needsAttention(c: StorageCredentialState): boolean {
  return c.status === "required" || c.status === "notAllowed";
}

/**
 * How the config authenticates, never with a credential (§7.6):
 * `vta-account community/eu-s3 · 14 rooms holding credentials`, `ambient`,
 * `sealed · fingerprint …`, `credential required`, or — for `local` — none.
 */
export function describeCredential(c: StorageCredentialState): string {
  switch (c.status) {
    case "vta-account": {
      const name = [c.context, c.account].filter(Boolean).join("/");
      const rooms =
        c.roomsHoldingCredentials !== undefined
          ? ` · ${c.roomsHoldingCredentials} ${c.roomsHoldingCredentials === 1 ? "room" : "rooms"} holding credentials`
          : "";
      return `VTA account ${name}${rooms}`;
    }
    case "ambient": {
      const rooms =
        c.roomsHoldingCredentials !== undefined ? ` · ${c.roomsHoldingCredentials} holding room credentials` : "";
      return `this machine's cloud identity${rooms}`;
    }
    case "sealed":
      return c.fingerprint
        ? `stored credential · ${c.fingerprint.slice(0, 12)}… — recoverable by this machine's operator`
        : "stored credential — recoverable by this machine's operator";
    case "required":
      return "credential required";
    case "notAllowed":
      return "a mode this community's host no longer permits — change how it authenticates";
    case "none":
      return "none needed";
    default:
      return c.status;
  }
}

/** The pattern a config's identifier must match (`StorageConfigId`). */
export const CONFIG_ID_PATTERN = /^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/;
/** S3 bucket naming, as the spec checks it. */
export const BUCKET_PATTERN = /^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/;
/** GCS bucket naming, as the spec checks it. */
export const GCS_BUCKET_PATTERN = /^[a-z0-9][a-z0-9._-]{1,220}[a-z0-9]$/;
/** An AWS IAM role ARN, in any partition (`AwsRoleArn`). */
export const ROLE_ARN_PATTERN = /^arn:aws(-[a-z]+)*:iam::[0-9]{12}:role\/[A-Za-z0-9+=,.@_/-]{1,512}$/;
/** An object-key prefix ending in `/` (`ObjectPrefix`). Through a VTA account the
 *  VTA's scope accepts lowercase segments only, so the form asks for those. */
export const PREFIX_PATTERN = /^(?:[a-z0-9][a-z0-9._-]*\/)+$/;
/** The region, as the store names it (`eu-west-1`, `auto`). */
export const REGION_PATTERN = /^[a-z0-9-]+$/;
