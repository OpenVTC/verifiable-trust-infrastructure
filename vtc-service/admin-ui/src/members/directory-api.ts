// The member directory, as a member reads and edits it — `vtc/directory/*`,
// signed by the portal's sign-in key (`K_b`).
//
// A wallet sign-in at `auth/oob/*/0.2` asks the member to let `K_b` sign
// directory documents as them, for that session (`auth/oob/grant/0.2`
// `signingScope: ["vtc/directory"]`). The portal keeps `K_b` for the session
// (`@/lib/console-key` `loadMemberSessionKey`) and signs every directory
// document with it; the VTC reads each as the member's while the session that
// armed it lives. A passkey sign-in, or a wallet that signed a 0.1 grant,
// delegated nothing: the VTC answers `notMember` / `permissionDenied`, and the
// pages say to sign in with the wallet.
//
// A delegated key can never make a value `public` or publish the card beyond
// the community: those go through the member's wallet, and the editor does
// not offer them here. It may upload a picture for the member's card, read
// pictures as the member, and stop a published card being published.

import {
  buildTrustTaskDocument,
  loadMemberSessionKey,
  signTrustTaskDocument,
} from "@/lib/console-key";
import { guardPreviewRequest, isThemePreview } from "@/lib/theme-preview";
import type {
  DirectoryCardShowResponse,
  DirectoryCardUpdatePayload,
  DirectoryCardUpdateResponse,
  DirectoryEntriesListPayload,
  DirectoryEntriesListResponse,
  DirectoryEntriesShowResponse,
  DirectoryFieldsListResponse,
  DirectoryImagesGetResponse,
  DirectoryImagesUploadPayload,
  DirectoryImagesUploadResponse,
} from "@/lib/wire-types";

import { vtcDid } from "./api";

export const FIELDS_LIST_TASK = "https://trusttasks.org/spec/vtc/directory/fields/list/0.1";
export const CARD_SHOW_TASK = "https://trusttasks.org/spec/vtc/directory/card/show/0.1";
export const CARD_UPDATE_TASK = "https://trusttasks.org/spec/vtc/directory/card/update/0.1";
export const ENTRIES_LIST_TASK = "https://trusttasks.org/spec/vtc/directory/entries/list/0.1";
export const ENTRIES_SHOW_TASK = "https://trusttasks.org/spec/vtc/directory/entries/show/0.1";
export const IMAGES_UPLOAD_TASK = "https://trusttasks.org/spec/vtc/directory/images/upload/0.1";
export const IMAGES_GET_TASK = "https://trusttasks.org/spec/vtc/directory/images/get/0.1";

/** A refusal: the local part of its code, its message and its details. */
export class DirectoryError extends Error {
  constructor(
    readonly code: string,
    message: string,
    readonly details: Record<string, unknown> = {},
  ) {
    super(message);
    this.name = "DirectoryError";
  }

  /** Whether the refusal means this browser's key may not act as the member:
   *  no key, a sign-in that delegated nothing, or a session that ended. */
  get needsWallet(): boolean {
    return this.code === "noKey" || this.code === "notMember" || this.code === "permissionDenied";
  }
}

let recipient: Promise<string> | null = null;

async function send<T>(typeUri: string, payload: unknown): Promise<T> {
  if (isThemePreview()) {
    // A preview signs nothing; its sample member has no directory.
    guardPreviewRequest("POST", "/v1/trust-tasks");
  }
  const key = await loadMemberSessionKey();
  if (!key) {
    throw new DirectoryError(
      "noKey",
      "Sign in with your wallet to use the directory: it lets this browser read and edit your card for this session.",
    );
  }
  recipient ??= vtcDid();
  const doc = await signTrustTaskDocument(
    buildTrustTaskDocument({ typeUri, payload, issuer: key.consoleDid, recipient: await recipient }),
    key,
    { proofPurpose: "authentication" },
  );
  const res = await fetch("/v1/trust-tasks", {
    method: "POST",
    headers: { "content-type": "application/json" },
    credentials: "same-origin",
    body: JSON.stringify(doc),
  });
  const body = (await res.json().catch(() => null)) as {
    type?: string;
    payload?: Record<string, unknown>;
  } | null;
  const ok = res.ok && !(body?.type ?? "").includes("/trust-task-error/");
  if (ok) return (body?.payload ?? {}) as T;
  const p = body?.payload ?? {};
  const raw = typeof p.code === "string" ? p.code : `http${res.status}`;
  const local = raw.includes(":") ? raw.slice(raw.lastIndexOf(":") + 1) : raw;
  throw new DirectoryError(
    local,
    typeof p.message === "string" ? p.message : `The community answered ${res.status}.`,
    (p.details as Record<string, unknown>) ?? {},
  );
}

export const listFields = () => send<DirectoryFieldsListResponse>(FIELDS_LIST_TASK, {});
export const showCard = () => send<DirectoryCardShowResponse>(CARD_SHOW_TASK, {});
export const updateCard = (p: DirectoryCardUpdatePayload) =>
  send<DirectoryCardUpdateResponse>(CARD_UPDATE_TASK, p);
export const listEntries = (p: DirectoryEntriesListPayload) =>
  send<DirectoryEntriesListResponse>(ENTRIES_LIST_TASK, p);
export const showEntry = (entryId: string) =>
  send<DirectoryEntriesShowResponse>(ENTRIES_SHOW_TASK, { entryId });
export const uploadImage = (p: DirectoryImagesUploadPayload) =>
  send<DirectoryImagesUploadResponse>(IMAGES_UPLOAD_TASK, p);
export const getImage = (entryId: string, field: string, sha256: string) =>
  send<DirectoryImagesGetResponse>(IMAGES_GET_TASK, { entryId, field, sha256 });
