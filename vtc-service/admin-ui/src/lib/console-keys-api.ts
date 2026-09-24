// The console-key enrolment surface — `/v1/admin/console-keys` (#1692).
//
// Three bearer routes, mounted without a Trust-Task binding because no
// published task family describes enrolling a signing-key delegation; the
// handler records what the upstream `auth/signing-key/{enroll,list,revoke}`
// family should be, and these bodies are already those payloads. So they use
// the `*Exempt` helpers, and the smell is the intended one.
//
// Everything here is about the *delegation record*, which lives on the
// daemon. The key itself never leaves this browser — see `console-key.ts`.

import { deleteJsonExempt, getJsonExempt, postJsonExempt } from "./api";
import {
  forgetConsoleKey,
  generateConsoleKey,
  loadConsoleKey,
} from "./console-key";
import { stepUpSession } from "./step-up";
import type { ConsoleKey, ConsoleKeyListResponse } from "./wire-types";

export type { ConsoleKey } from "./wire-types";

/** The caller's own console keys, newest first, revoked ones included. */
export async function listConsoleKeys(): Promise<ConsoleKey[]> {
  const body = await getJsonExempt<ConsoleKeyListResponse>(
    "/v1/admin/console-keys",
  );
  return body.consoleKeys;
}

/**
 * Enrol this browser's key, generating one first if the profile has none.
 *
 * The step-up runs **before** the POST rather than on a caught
 * `step_up_required`, for the reason `stepUpSession`'s own doc gives: it keeps
 * the operator's passkey gesture tied to the click that asked for it, which is
 * the whole point of requiring a *recent* second factor. The daemon's own
 * reason for demanding one here is narrower than `acl/grant`'s and worth
 * knowing: a delegation confers no role, but it can author signed documents in
 * the caller's name with no gesture at use time, so a stolen session must not
 * be enough to leave one behind.
 *
 * Generating before enrolling is safe: a key nobody has enrolled authorises
 * nothing at all.
 */
export async function enrolThisBrowser(label?: string): Promise<ConsoleKey> {
  const key = (await loadConsoleKey()) ?? (await generateConsoleKey());
  await stepUpSession();
  const body: Record<string, unknown> = { consoleDid: key.consoleDid };
  const trimmed = label?.trim();
  if (trimmed) body.label = trimmed;
  return postJsonExempt<ConsoleKey>("/v1/admin/console-keys", body);
}

/**
 * Revoke a delegation. Takes effect on the very next document — the daemon
 * reads the record when it executes one, not when the session began.
 *
 * No step-up: requiring a fresh gesture to *withdraw* a credential is a gate
 * that protects the attacker, and an operator who suspects a browser should
 * not have to find their authenticator before disowning it.
 *
 * When the revoked key is the one this browser holds, the local copy goes too.
 * Keeping it would leave a key that signs documents the daemon refuses, which
 * presents to the operator as a console that has quietly stopped working.
 *
 * The response body (`ConsoleKeyRevokeResponse`: `{consoleDid, revokedAt,
 * remainingActive}`) is not read: the caller refetches the list, which is
 * what it wants to render anyway.
 */
export async function revokeConsoleKey(consoleDid: string): Promise<void> {
  await deleteJsonExempt<unknown>(
    `/v1/admin/console-keys/${encodeURIComponent(consoleDid)}`,
  );
  const held = await loadConsoleKey();
  if (held?.consoleDid === consoleDid) await forgetConsoleKey();
}

/** Did the daemon refuse for want of a live step-up, rather than a real 403? */
export function isStepUpRequired(error: unknown): boolean {
  const message = (error as { message?: string } | null)?.message;
  // `AppError::StepUpRequired` serialises `{"error":"step_up_required", …}`
  // and `daemonErrorMessage` returns `body.error` first, so this is the code
  // rather than the prose. `ApprovalRequired` spells the same thing with an
  // `auth:` prefix, and both mean "run the ceremony and retry".
  return message === "step_up_required" || message === "auth:step_up_required";
}
