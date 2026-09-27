// Members' step-up passkeys — the console side of `crate::step_up_passkey`.
//
// A step-up passkey answers one thing: an operation-bound step-up issued to
// its own member (a git break-glass, say), always beside the member's own
// signature on the answer. It never signs anyone in. A member who is no
// console user gets their first one only through a community administrator's
// invite: a URL and, delivered over another channel, a claim code.
//
// Every step is a Trust Task on `POST /v1/trust-tasks` — the same tasks the
// VTC serves over TSP and DIDComm:
//
// - the administrator signs `auth/passkey/enroll/invite/0.2`, with a passkey
//   gesture of their own bound to it (`bound-step-up.ts`);
// - the member signs `auth/passkey/enroll/redeem/start/0.1` with `cnm`, since
//   the invite redeems only for the DID it names, and `cnm` prints the link
//   this console finishes it on (`/admin/enrol-step-up#enrollment=…`);
// - this console sends `auth/passkey/enroll/redeem/finish/0.1` from the
//   browser that made the passkey, unsigned — its authority is the ceremony
//   the member's signed start opened;
// - the administrator revokes with `auth/passkey/revoke/{start,finish}/0.2`,
//   verifying with their own passkey.

import { getJsonExempt, postSignedTrustTask, postUnsignedTrustTask } from "./api";
import {
  base64urlToBuffer,
  decodePublicKeyOptions,
  serializeAssertion,
  serializeRegistration,
  type JsonPublicKeyOptions,
} from "./webauthn";
import type { StepUpPasskeyList } from "./wire-types";

export const INVITE_TASK = "https://trusttasks.org/spec/auth/passkey/enroll/invite/0.2";
export const REDEEM_FINISH_TASK =
  "https://trusttasks.org/spec/auth/passkey/enroll/redeem/finish/0.1";
export const REVOKE_START_TASK = "https://trusttasks.org/spec/auth/passkey/revoke/start/0.2";
export const REVOKE_FINISH_TASK = "https://trusttasks.org/spec/auth/passkey/revoke/finish/0.2";

/** `auth/passkey/enroll/invite/0.2#response`. */
export interface StepUpPasskeyInvite {
  invite: { token: string; url: string };
  subject: string;
  purpose: "stepUp";
  expiresAt: string;
  claimCode: string;
}

/** `auth/passkey/enroll/redeem/start/0.1#response`, as `cnm` hands it over. */
export interface RedeemStarted {
  enrollmentId: string;
  subject: string;
  purpose: "stepUp";
  deviceLabel?: string;
  options: JsonPublicKeyOptions;
  uvOptions?: JsonPublicKeyOptions;
  expiresAt: string;
}

/** `auth/passkey/enroll/redeem/finish/0.1#response`. */
export interface RedeemFinished {
  credentialId: string;
  subject: string;
  purpose: "stepUp";
  deviceLabel?: string;
  registeredAt: string;
}

/** `auth/passkey/revoke/start/0.2#response`. */
interface RevokeStarted {
  revocationId: string;
  uvOptions: JsonPublicKeyOptions;
}

/** `auth/passkey/revoke/finish/0.2#response`. */
export interface StepUpPasskeyRevoked {
  credentialId: string;
  subject: string;
  purpose: "stepUp";
  revokedAt: string;
  remaining: number;
}

export const stepUpPasskeyKeys = {
  of: (subject: string) => ["step-up-passkeys", subject] as const,
};

/** A member's step-up passkeys. Community administrators only. No published
 *  task lists another subject's credentials (`auth/passkey/list` is the
 *  signer's own), so this read carries no Trust-Task binding, as the
 *  console-key listing does not. */
export function fetchStepUpPasskeys(subject: string): Promise<StepUpPasskeyList> {
  return getJsonExempt<StepUpPasskeyList>(
    `/v1/admin/step-up-passkeys?subject=${encodeURIComponent(subject)}`,
  );
}

/** The invite, signed by this browser's console key. The first send is
 *  refused for a passkey gesture bound to it (`details.stepUpRequest`); the
 *  caller answers that and sends the **same** document again. */
export function inviteStepUpPasskey(
  subject: string,
  deviceLabel?: string,
): Promise<StepUpPasskeyInvite> {
  return postSignedTrustTask<StepUpPasskeyInvite>(INVITE_TASK, {
    subject,
    purpose: "stepUp",
    ...(deviceLabel ? { deviceLabel } : {}),
  });
}

/** Revoke a member's step-up passkey, verifying with the administrator's own. */
export async function revokeStepUpPasskey(
  subject: string,
  credentialId: string,
  credentials: Pick<CredentialsContainer, "get"> = navigator.credentials,
): Promise<StepUpPasskeyRevoked> {
  const start = await postSignedTrustTask<RevokeStarted>(REVOKE_START_TASK, {
    subject,
    credentialId,
  });
  const publicKey = decodePublicKeyOptions(start.uvOptions) as PublicKeyCredentialRequestOptions;
  const uv = (await credentials.get({ publicKey })) as PublicKeyCredential | null;
  if (!uv) throw new Error("the passkey ceremony returned no credential");
  return postSignedTrustTask<StepUpPasskeyRevoked>(REVOKE_FINISH_TASK, {
    revocationId: start.revocationId,
    uvCredential: serializeAssertion(uv),
  });
}

/** The token from an invite URL's fragment (`#token=…`), never sent to a server. */
export function tokenFromHash(hash: string): string | null {
  const params = new URLSearchParams(hash.replace(/^#/, ""));
  const token = params.get("token");
  return token && token.length >= 16 && token.length <= 512 && /^[A-Za-z0-9_-]+$/.test(token)
    ? token
    : null;
}

function isRedeemStarted(v: unknown): v is RedeemStarted {
  if (!v || typeof v !== "object") return false;
  const r = v as Record<string, unknown>;
  const options = r.options;
  return (
    typeof r.enrollmentId === "string" &&
    typeof r.subject === "string" &&
    r.purpose === "stepUp" &&
    !!options &&
    typeof options === "object" &&
    typeof (options as Record<string, unknown>).challenge === "string" &&
    (r.uvOptions === undefined || (typeof r.uvOptions === "object" && r.uvOptions !== null))
  );
}

/** The redemption `cnm` opened, from `#enrollment=<base64url(JSON)>`. */
export function enrollmentFromHash(hash: string): RedeemStarted | null {
  const params = new URLSearchParams(hash.replace(/^#/, ""));
  const raw = params.get("enrollment");
  if (!raw || !/^[A-Za-z0-9_-]+$/.test(raw)) return null;
  try {
    const json = new TextDecoder("utf-8", { fatal: true }).decode(base64urlToBuffer(raw));
    const value: unknown = JSON.parse(json);
    return isRedeemStarted(value) ? value : null;
  } catch {
    return null;
  }
}

/** The command a member runs to redeem the invite at `inviteUrl`. The URL is
 *  this VTC's own (`tokenFromHash` accepted its token), so single quotes hold
 *  it in any shell. */
export function redeemCommand(inviteUrl: string): string {
  return `cnm git enrol-step-up-passkey '${inviteUrl.replace(/'/g, "")}'`;
}

/** Create the passkey — and, when the member already holds one, answer the
 *  gesture it asks for first — then bind it. */
export async function redeemFinish(
  started: RedeemStarted,
  deviceLabel: string | undefined,
  credentials: Pick<CredentialsContainer, "create" | "get"> = navigator.credentials,
): Promise<RedeemFinished> {
  let uvCredential: unknown;
  if (started.uvOptions) {
    const publicKey = decodePublicKeyOptions(
      started.uvOptions,
    ) as PublicKeyCredentialRequestOptions;
    const uv = (await credentials.get({ publicKey })) as PublicKeyCredential | null;
    if (!uv) throw new Error("the gesture from your existing step-up passkey returned nothing");
    uvCredential = serializeAssertion(uv);
  }
  const publicKey = decodePublicKeyOptions(started.options) as PublicKeyCredentialCreationOptions;
  const created = (await credentials.create({ publicKey })) as PublicKeyCredential | null;
  if (!created) throw new Error("passkey creation returned no credential");
  return postUnsignedTrustTask<RedeemFinished>(
    REDEEM_FINISH_TASK,
    {
      enrollmentId: started.enrollmentId,
      credential: serializeRegistration(created),
      ...(uvCredential ? { uvCredential } : {}),
      ...(deviceLabel ? { deviceLabel } : {}),
    },
    started.subject,
  );
}
