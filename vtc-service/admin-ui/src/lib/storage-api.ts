// Where this community keeps its rooms' files — `vtc/storage/configs/*/0.1` and
// `vtc/rooms/storage/assign/0.1` (docs/05-design-notes/data-rooms-files.md §7).
//
// A config is a named backend; every room is assigned to one, which receives
// its new uploads, and every file remembers the config it was written to, so
// moving a room strands nothing. None of these tasks sends or returns a
// credential: an S3 config names an external account at the community's VTA,
// which issues one presigned request per object and holds the authority itself.
//
// Reads and the probe answer a holder of `vtc.rooms.admin`. Creating, changing
// and retiring a config, and moving a room, decide where members' files go, so
// each needs the requester's operation-bound step-up and is then parked for the
// other holders' consent (`postSignedWithStepUp` → a `ParkedAction`, a success).

import { postSignedRead, postSignedTrustTask } from "./api";
import { postSignedWithStepUp, type ConfirmGesture } from "./signed-act";
import type {
  RoomStorageAssignResponse,
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

export const STORAGE_LIST_TASK = "https://trusttasks.org/spec/vtc/storage/configs/list/0.1";
export const STORAGE_GET_TASK = "https://trusttasks.org/spec/vtc/storage/configs/get/0.1";
export const STORAGE_CREATE_TASK = "https://trusttasks.org/spec/vtc/storage/configs/create/0.1";
export const STORAGE_UPDATE_TASK = "https://trusttasks.org/spec/vtc/storage/configs/update/0.1";
export const STORAGE_RETIRE_TASK = "https://trusttasks.org/spec/vtc/storage/configs/retire/0.1";
export const STORAGE_PROBE_TASK = "https://trusttasks.org/spec/vtc/storage/configs/probe/0.1";
export const ROOM_STORAGE_ASSIGN_TASK = "https://trusttasks.org/spec/vtc/rooms/storage/assign/0.1";

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

// ── Saying what a config is ─────────────────────────────────────────────

/** What a kind means for a room's files, in one line (§7.2). */
export const KIND_MEANS: Record<string, string> = {
  local: "Files on this host's own disk. Removed when deleted. Not in a VTC backup.",
  s3: "An S3-compatible object store. Removed when deleted.",
  gcs: "Google Cloud Storage. Removed when deleted.",
  walrus: "Public ciphertext on Walrus. Removal is cryptographic: storage lapses, it is not erased.",
};

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
    case "ambient":
      return "this machine's cloud identity";
    case "sealed":
      return c.fingerprint ? `stored credential · ${c.fingerprint.slice(0, 12)}…` : "stored credential";
    case "required":
      return "credential required";
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
/** An object-key prefix ending in `/` (`ObjectPrefix`). Through a VTA account the
 *  VTA's scope accepts lowercase segments only, so the form asks for those. */
export const PREFIX_PATTERN = /^(?:[a-z0-9][a-z0-9._-]*\/)+$/;
/** The region, as the store names it (`eu-west-1`, `auto`). */
export const REGION_PATTERN = /^[a-z0-9-]+$/;
