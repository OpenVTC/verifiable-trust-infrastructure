// Members' step-up passkeys — the console side of `crate::step_up_passkey`.
//
// A step-up passkey answers one thing: an operation-bound step-up issued to
// its own member (a git break-glass, say). It never signs anyone in. A member
// who is no console user gets their first one only through a community
// administrator's invite: a URL and, delivered over another channel, a claim
// code. A further one also needs a gesture from one they already hold.

import { getJsonExempt, postJson } from "./api";
import {
  decodePublicKeyOptions,
  serializeAssertion,
  serializeRegistration,
  type JsonPublicKeyOptions,
} from "./webauthn";
import type {
  StepUpPasskeyInvite,
  StepUpPasskeyList,
  StepUpPasskeyRedeemed,
  StepUpPasskeyRedeemStarted,
  StepUpPasskeyRevoked,
  StepUpPasskeyRevokeStarted,
} from "./wire-types";

export const INVITE_TASK = "https://trusttasks.org/spec/auth/passkey/enroll/invite/0.2";
export const REDEEM_START_TASK =
  "https://trusttasks.org/spec/auth/passkey/enroll/redeem/start/0.1";
export const REDEEM_FINISH_TASK =
  "https://trusttasks.org/spec/auth/passkey/enroll/redeem/finish/0.1";
export const REVOKE_START_TASK = "https://trusttasks.org/spec/auth/passkey/revoke/start/0.2";
export const REVOKE_FINISH_TASK = "https://trusttasks.org/spec/auth/passkey/revoke/finish/0.2";

export const stepUpPasskeyKeys = {
  of: (subject: string) => ["step-up-passkeys", subject] as const,
};

/** A member's step-up passkeys. Community administrators only. The route
 *  carries no Trust-Task binding — no published task lists another subject's
 *  credentials — as the console-key routes do not. */
export function fetchStepUpPasskeys(subject: string): Promise<StepUpPasskeyList> {
  return getJsonExempt<StepUpPasskeyList>(
    `/v1/admin/step-up-passkeys?subject=${encodeURIComponent(subject)}`,
  );
}

/** Issue an invite. The caller has stepped the session up first. */
export function inviteStepUpPasskey(
  subject: string,
  deviceLabel?: string,
): Promise<StepUpPasskeyInvite> {
  return postJson<StepUpPasskeyInvite>(
    "/v1/admin/step-up-passkeys/invites",
    { subject, purpose: "stepUp", ...(deviceLabel ? { deviceLabel } : {}) },
    { trustTask: INVITE_TASK, requires: ["invite.url", "claimCode"] },
  );
}

/** Revoke a member's step-up passkey, verifying with the administrator's own. */
export async function revokeStepUpPasskey(
  subject: string,
  credentialId: string,
  credentials: Pick<CredentialsContainer, "get"> = navigator.credentials,
): Promise<StepUpPasskeyRevoked> {
  const start = await postJson<StepUpPasskeyRevokeStarted>(
    "/v1/admin/step-up-passkeys/revoke/start",
    { subject, credentialId },
    { trustTask: REVOKE_START_TASK, requires: ["revocationId", "uvOptions.challenge"] },
  );
  const publicKey = decodePublicKeyOptions(
    start.uvOptions as unknown as JsonPublicKeyOptions,
  ) as PublicKeyCredentialRequestOptions;
  const uv = (await credentials.get({ publicKey })) as PublicKeyCredential | null;
  if (!uv) throw new Error("the passkey ceremony returned no credential");
  return postJson<StepUpPasskeyRevoked>(
    "/v1/admin/step-up-passkeys/revoke/finish",
    { revocationId: start.revocationId, uvCredential: serializeAssertion(uv) },
    { trustTask: REVOKE_FINISH_TASK },
  );
}

/** The token from an invite URL's fragment (`#token=…`), never sent to a server. */
export function tokenFromHash(hash: string): string | null {
  const params = new URLSearchParams(hash.replace(/^#/, ""));
  const token = params.get("token");
  return token && token.length >= 16 && token.length <= 512 ? token : null;
}

export function redeemStart(token: string, claimCode: string): Promise<StepUpPasskeyRedeemStarted> {
  return postJson<StepUpPasskeyRedeemStarted>(
    "/v1/step-up-passkeys/redeem/start",
    { token, claimCode },
    { trustTask: REDEEM_START_TASK, requires: ["enrollmentId", "subject", "options.challenge"] },
  );
}

/** Create the passkey — and, when the member already holds one, answer the
 *  gesture it asks for first — then bind it. */
export async function redeemFinish(
  started: StepUpPasskeyRedeemStarted,
  deviceLabel: string | undefined,
  credentials: Pick<CredentialsContainer, "create" | "get"> = navigator.credentials,
): Promise<StepUpPasskeyRedeemed> {
  let uvCredential: unknown;
  if (started.uvOptions) {
    const publicKey = decodePublicKeyOptions(
      started.uvOptions as unknown as JsonPublicKeyOptions,
    ) as PublicKeyCredentialRequestOptions;
    const uv = (await credentials.get({ publicKey })) as PublicKeyCredential | null;
    if (!uv) throw new Error("the gesture from your existing step-up passkey returned nothing");
    uvCredential = serializeAssertion(uv);
  }
  const publicKey = decodePublicKeyOptions(
    started.options as unknown as JsonPublicKeyOptions,
  ) as PublicKeyCredentialCreationOptions;
  const created = (await credentials.create({ publicKey })) as PublicKeyCredential | null;
  if (!created) throw new Error("passkey creation returned no credential");
  return postJson<StepUpPasskeyRedeemed>(
    "/v1/step-up-passkeys/redeem/finish",
    {
      enrollmentId: started.enrollmentId,
      credential: serializeRegistration(created),
      ...(uvCredential ? { uvCredential } : {}),
      ...(deviceLabel ? { deviceLabel } : {}),
    },
    { trustTask: REDEEM_FINISH_TASK },
  );
}
