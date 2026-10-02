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
//
// Every administrator verb the console sends is a signed document, so an
// administrator whose browser holds no enrolled key can do nothing here. The
// shell therefore asks [`signingStatus`] once a session exists, and puts the
// operator through enrolment (`pages/SetupSigning.tsx`) before it shows them
// anything that would sign.

import {
  addressedDocument,
  type ApiError,
  fetchWhoami,
  postSignedRead,
  postSignedTrustTask,
} from "./api";
import { isWalletSigningAvailable, signWithWallet } from "./wallet";
import {
  adoptConsoleKey,
  ed25519Available,
  forgetConsoleKey,
  keyStorageDurability,
  loadConsoleKey,
  mintConsoleKey,
  type StorageDurability,
} from "./console-key";
import { type ConfirmGesture, GestureDeclinedError, postSignedWithStepUp } from "./signed-act";
import type { ConsoleKey } from "./wire-types";

export type { ConsoleKey } from "./wire-types";

export const TASK_SIGNING_KEY_ENROLL = "https://trusttasks.org/spec/auth/signing-key/enroll/0.2";
/** Never sent alone: the identity's signed terms, carried as `authorization`. */
export const TASK_SIGNING_KEY_AUTHORIZE =
  "https://trusttasks.org/spec/auth/signing-key/authorize/0.1";
export const TASK_SIGNING_KEY_LIST = "https://trusttasks.org/spec/auth/signing-key/list/0.1";
export const TASK_SIGNING_KEY_REVOKE = "https://trusttasks.org/spec/auth/signing-key/revoke/0.1";

/**
 * Offer renewal when the delegation has this little left. The VTC caps a
 * delegation at 30 days (`console_key::MAX_LIFETIME_DAYS`), and an expired one
 * cannot be revived — renewing early is one passkey gesture; renewing late is
 * the same gesture after the console has already stopped working.
 */
export const RENEW_WITHIN_MS = 5 * 24 * 60 * 60 * 1000;

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

/** The daemon refused the signer as speaking for no identity here. */
function isUnrecognisedSigner(e: unknown): boolean {
  const err = e as ApiError | null;
  return err?.code === "permissionDenied" || err?.status === 403;
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
    if (isUnrecognisedSigner(e)) return [];
    throw e;
  }
}

/** Whether this browser can act for the signed-in administrator, and if not why. */
export type SigningStatus =
  /** No WebCrypto Ed25519 in this browser. */
  | { state: "unsupported" }
  /** This browser holds no key. */
  | { state: "no-key" }
  /**
   * This browser holds a key the VTC does not accept: never enrolled, expired,
   * revoked, or dropped by a restore (delegations are not backed up).
   */
  | { state: "not-enrolled"; consoleDid: string }
  /** This browser's key acts for a different identity — another admin used it. */
  | { state: "other-identity"; consoleDid: string; identityDid: string }
  /** Enrolled and active for this identity. */
  | {
      state: "ready";
      key: ConsoleKey;
      /** Within [`RENEW_WITHIN_MS`] of expiring. */
      renewSoon: boolean;
      durability: StorageDurability;
    };

/**
 * Ask the VTC whether this browser's key acts for `identity`.
 *
 * One signed read, and only when there is a key to ask about. A key the VTC
 * does not recognise is answered `not-enrolled`; any other failure — the
 * network, a 5xx, a rate limit, the browser's key store — is thrown, because
 * none of them is evidence the key stopped working and the operator must not
 * be sent to re-enrol on the strength of one.
 */
export async function signingStatus(identity: string): Promise<SigningStatus> {
  if (!(await ed25519Available())) return { state: "unsupported" };
  const held = await loadConsoleKey();
  if (!held) return { state: "no-key" };
  let keys: SigningKey[];
  try {
    keys = (await postSignedRead<{ signingKeys: SigningKey[] }>(TASK_SIGNING_KEY_LIST, {}))
      .signingKeys;
  } catch (e) {
    if (isUnrecognisedSigner(e)) return { state: "not-enrolled", consoleDid: held.consoleDid };
    throw e;
  }
  const mine = keys.find((k) => k.signingKeyDid === held.consoleDid);
  if (!mine || !mine.active) return { state: "not-enrolled", consoleDid: held.consoleDid };
  if (mine.identityDid !== identity) {
    return { state: "other-identity", consoleDid: held.consoleDid, identityDid: mine.identityDid };
  }
  return {
    state: "ready",
    key: asConsoleKey(mine),
    renewSoon: Date.parse(mine.expiresAt) - Date.now() < RENEW_WITHIN_MS,
    durability: await keyStorageDurability(),
  };
}

/** How the operator shows the VTC they control their identity. */
export type EnrolEvidence =
  /** A passkey gesture bound to this enrolment (the step-up). */
  | "passkey"
  /** The identity's own signature, made by the VTA through the wallet. */
  | "wallet";

export interface EnrolOptions {
  /** Default `passkey`. */
  evidence?: EnrolEvidence;
  /** An active key of this identity to revoke in the same step (at the cap). */
  replaces?: string;
}

/**
 * The evidence to offer first: a passkey for a session signed in with one,
 * the wallet for a session the wallet signed in (it has the identity's key,
 * and usually no passkey here).
 */
export function preferredEvidence(amr: string[] | undefined): EnrolEvidence {
  if (amr?.includes("passkey")) return "passkey";
  return isWalletSigningAvailable() ? "wallet" : "passkey";
}

/** One of the identity's active keys, as a `tooManyKeys` refusal lists it. */
export interface ActiveKeySummary {
  signingKeyDid: string;
  deviceLabel?: string;
  createdAt: string;
  expiresAt: string;
  lastUsedAt?: string;
}

/**
 * The identity is at the VTC's cap on active keys. `activeKeys` (least
 * recently used first) is what the operator chooses a key to replace from;
 * the VTC lists them only once the enrolment's evidence was accepted.
 */
export class TooManyKeysError extends Error {
  constructor(
    readonly activeKeys: ActiveKeySummary[],
    readonly maxActiveKeys: number | null,
  ) {
    super(
      `You already have ${maxActiveKeys ?? "the maximum number of"} active signing keys. ` +
        "Choose one you no longer use to replace.",
    );
    this.name = "TooManyKeysError";
  }
}

function tooManyKeysOf(e: unknown): TooManyKeysError | null {
  const err = e as ApiError | null;
  if (typeof err?.code !== "string" || !err.code.endsWith(":tooManyKeys")) return null;
  const details = (err.details ?? {}) as { activeKeys?: unknown; maxActiveKeys?: unknown };
  const keys = Array.isArray(details.activeKeys) ? (details.activeKeys as ActiveKeySummary[]) : [];
  const max = typeof details.maxActiveKeys === "number" ? details.maxActiveKeys : null;
  return new TooManyKeysError(keys, max);
}

/** What [`enrolThisBrowser`] reports beyond the delegation. */
export interface Enrolment {
  key: ConsoleKey;
  durability: StorageDurability;
}

/**
 * Enrol a freshly generated key for your identity and make it this browser's.
 * `confirmGesture` asks you to confirm the passkey gesture the VTC then
 * requests — its own click, so the ceremony runs in a fresh user gesture with
 * the act on screen.
 *
 * Always a fresh key (see `mintConsoleKey`): the VTC never enrols a key twice,
 * so the key a lapsed or revoked delegation named is dead for good. The new
 * key is stored only once the VTC has enrolled it, so a cancelled or failed
 * ceremony leaves this browser as it was. The key it replaces, if it was ours
 * and still active, is revoked afterwards, so a renewal does not leave a live
 * delegation behind for a key this browser no longer holds.
 */
export async function enrolThisBrowser(
  label: string | undefined,
  confirmGesture: ConfirmGesture,
  options: EnrolOptions = {},
): Promise<Enrolment> {
  const previous = await loadConsoleKey().catch(() => null);
  const key = await mintConsoleKey();
  const identity = (await fetchWhoami()).session.subject;
  const terms: Record<string, unknown> = {
    signingKeyDid: key.consoleDid,
    identityDid: identity,
    scope: "console",
  };
  const trimmed = label?.trim();
  if (trimmed) terms.deviceLabel = trimmed;
  if (options.replaces) terms.replaces = options.replaces;

  let body: { signingKey: SigningKey };
  try {
    if (options.evidence === "wallet") {
      // `auth/signing-key/enroll/0.2` item 13: the identity signs exactly
      // these terms, through the wallet (the VTA holds the key), and that
      // signature is the evidence — no passkey involved.
      const authorization = await signWithWallet(
        { ...(await addressedDocument(TASK_SIGNING_KEY_AUTHORIZE, terms, identity)) },
        identity,
      );
      body = await postSignedTrustTask<{ signingKey: SigningKey }>(
        TASK_SIGNING_KEY_ENROLL,
        { ...terms, authorization },
        key,
      );
    } else {
      body = await postSignedWithStepUp<{ signingKey: SigningKey }>(
        TASK_SIGNING_KEY_ENROLL,
        terms,
        confirmGesture,
        key,
      );
    }
  } catch (e) {
    throw tooManyKeysOf(e) ?? e;
  }
  let durability: StorageDurability;
  try {
    durability = await adoptConsoleKey(key);
  } catch (e) {
    // Enrolled, but this browser cannot keep it. Withdraw the delegation
    // rather than leave one live for a key that dies with this tab.
    await postSignedTrustTask<unknown>(
      TASK_SIGNING_KEY_REVOKE,
      { signingKeyDid: key.consoleDid },
      key,
    ).catch(() => undefined);
    throw e;
  }
  if (previous && previous.consoleDid !== key.consoleDid) {
    // Best-effort: `notFound` when it was never enrolled, or not ours.
    await postSignedTrustTask<unknown>(TASK_SIGNING_KEY_REVOKE, {
      signingKeyDid: previous.consoleDid,
    }).catch(() => undefined);
  }
  return { key: asConsoleKey(body.signingKey), durability };
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

/** The `code` an enrolment refusal carries, without its task prefix. */
function enrolCode(e: unknown): string | null {
  const code = (e as ApiError | null)?.code;
  if (typeof code !== "string") return null;
  return code.slice(code.lastIndexOf(":") + 1);
}

/**
 * What to tell an operator whose enrolment failed. Every refusal they can act
 * on says what to do; anything else is the daemon's own message.
 */
export function explainEnrolError(e: unknown): string {
  if (e instanceof GestureDeclinedError) {
    return "Cancelled — nothing was changed. Set up signing again when you are ready.";
  }
  if ((e as Error | null)?.name === "KeyStorageError") {
    return (
      `${(e as Error).message}. This browser cannot keep a signing key — a private ` +
      "window, or a browser set to block site data, does this. Use a normal window, " +
      "or allow this site to store data, and try again."
    );
  }
  if ((e as Error | null)?.name === "NotAllowedError") {
    return "The passkey prompt was dismissed or timed out. Try again, and complete it with your passkey.";
  }
  switch (enrolCode(e)) {
    case "authorizationInvalid":
      return (
        "The VTC did not accept the wallet's signature for this browser. Make sure " +
        "the wallet is signed in as the identity this community knows you as, and try again."
      );
    case "replaceNotFound":
      return "That key is no longer one of your active keys. Choose another, or try again.";
    case "tooManyKeys":
      return (
        "Your identity already has the maximum number of active signing keys (five), " +
        "from other browsers. Revoke one you no longer use — on the Signing keys page " +
        "of a browser that still signs, or ask another community administrator to — " +
        "or wait for one to expire; keys last at most 30 days."
      );
    default:
      return (e as Error | null)?.message ?? String(e);
  }
}
