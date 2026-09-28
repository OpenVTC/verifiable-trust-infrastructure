// The console's signing keys — `auth/signing-key/{enroll,list,revoke}/0.1`,
// signed documents on `POST /v1/trust-tasks`.
//
// Everything here is about the *delegation record*, which lives on the daemon.
// The key itself never leaves this browser — see `console-key.ts`.
//
// Enrolment needs no key of the operator's: the document is signed by the new
// key (proof that this browser holds it), and the VTC asks for a passkey
// gesture of the operator's identity bound to that one enrolment. The gesture
// is answered here, from this browser, and the identical document is sent
// again (`postSignedWithStepUp`).

import { type ApiError, fetchWhoami, postSignedRead, postSignedTrustTask } from "./api";
import { forgetConsoleKey, generateConsoleKey, loadConsoleKey } from "./console-key";
import { type ConfirmGesture, postSignedWithStepUp } from "./signed-act";
import type { ConsoleKey } from "./wire-types";

export type { ConsoleKey } from "./wire-types";

export const TASK_SIGNING_KEY_ENROLL = "https://trusttasks.org/spec/auth/signing-key/enroll/0.1";
export const TASK_SIGNING_KEY_LIST = "https://trusttasks.org/spec/auth/signing-key/list/0.1";
export const TASK_SIGNING_KEY_REVOKE = "https://trusttasks.org/spec/auth/signing-key/revoke/0.1";

/** `auth/_shared/0.1/signing-key.schema.json`'s `SigningKey`. */
interface SigningKey {
  signingKeyDid: string;
  identityDid: string;
  scope: string;
  deviceLabel?: string;
  createdAt: string;
  expiresAt: string;
  lastUsedAt?: string;
  revokedAt?: string;
  active: boolean;
}

function asConsoleKey(k: SigningKey): ConsoleKey {
  return {
    consoleDid: k.signingKeyDid,
    adminDid: k.identityDid,
    label: k.deviceLabel ?? null,
    createdAt: k.createdAt,
    expiresAt: k.expiresAt,
    lastUsedAt: k.lastUsedAt ?? null,
    revokedAt: k.revokedAt ?? null,
    active: k.active,
  };
}

/**
 * Your identity's signing keys, newest first, revoked ones included.
 *
 * The list is read with this browser's key, which speaks for your identity
 * only once enrolled — so a browser with no enrolled key sees none, and
 * enrolling this one is how to see the rest.
 */
export async function listConsoleKeys(): Promise<ConsoleKey[]> {
  if (!(await loadConsoleKey())) return [];
  try {
    const body = await postSignedRead<{ signingKeys: SigningKey[] }>(TASK_SIGNING_KEY_LIST, {});
    return body.signingKeys.map(asConsoleKey);
  } catch (e) {
    if ((e as ApiError | null)?.code === "permissionDenied") return [];
    throw e;
  }
}

/**
 * Enrol this browser's key for your identity, generating one first if the
 * profile has none. `confirmGesture` asks you to confirm the passkey gesture
 * the VTC then requests — its own click, so the ceremony runs in a fresh user
 * gesture with the act on screen.
 *
 * Generating before enrolling is safe: a key nobody has enrolled authorises
 * nothing at all.
 */
export async function enrolThisBrowser(
  label: string | undefined,
  confirmGesture: ConfirmGesture,
): Promise<ConsoleKey> {
  const key = (await loadConsoleKey()) ?? (await generateConsoleKey());
  const identity = (await fetchWhoami()).session.subject;
  const payload: Record<string, unknown> = {
    signingKeyDid: key.consoleDid,
    identityDid: identity,
    scope: "console",
  };
  const trimmed = label?.trim();
  if (trimmed) payload.deviceLabel = trimmed;
  const body = await postSignedWithStepUp<{ signingKey: SigningKey }>(
    TASK_SIGNING_KEY_ENROLL,
    payload,
    confirmGesture,
  );
  return asConsoleKey(body.signingKey);
}

/**
 * Revoke a delegation. Takes effect on the very next document — the daemon
 * reads the record when it executes one.
 *
 * No step-up: requiring a fresh gesture to *withdraw* a credential is a gate
 * that protects the attacker. Signed by this browser's key, which the VTC
 * accepts for its own identity's keys and for itself.
 *
 * When the revoked key is the one this browser holds, the local copy goes
 * too: keeping it would leave a key that signs documents the daemon refuses.
 */
export async function revokeConsoleKey(consoleDid: string): Promise<void> {
  await postSignedTrustTask<unknown>(TASK_SIGNING_KEY_REVOKE, { signingKeyDid: consoleDid });
  const held = await loadConsoleKey();
  if (held?.consoleDid === consoleDid) await forgetConsoleKey();
}
