// An administrator's own login passkeys — `auth/passkey/{list,enroll,revoke}`,
// the console side of `trust_tasks::admin_passkey_tasks`.
//
// Each is a signed document on `POST /v1/trust-tasks` from this browser's
// console key, which the VTC reads as the administrator that enrolled it — so
// every passkey here is that administrator's own. Each specification declares
// `proof` REQUIRED, and their `/v1/admin/passkeys/*` bearer routes are gone
// (#1641).
//
// Register is a dual ceremony: a new-credential `create` plus a step-up UV
// `get` against an existing passkey in the same start/finish pair. Revoke is a
// single UV ceremony. The UV is the gate a console key cannot pass by itself.

import { postSignedRead, postSignedTrustTask } from "./api";
import type { PasskeyListResponse } from "./wire-types";
import {
  decodePublicKeyOptions,
  serializeAssertion,
  serializeRegistration,
  type JsonPublicKeyOptions,
} from "./webauthn";

// Canonical `auth/passkey/*` tasks (trust-tasks-tf#145). One task per
// ceremony leg — the retired `admin/passkeys/{register,revoke}/1.0` pair
// had start and finish sharing a URI.
export const TRUST_TASK_LIST = "https://trusttasks.org/spec/auth/passkey/list/0.1";
export const TRUST_TASK_ENROLL_START =
  "https://trusttasks.org/spec/auth/passkey/enroll/start/0.2";
export const TRUST_TASK_ENROLL_FINISH =
  "https://trusttasks.org/spec/auth/passkey/enroll/finish/0.2";
export const TRUST_TASK_REVOKE_START =
  "https://trusttasks.org/spec/auth/passkey/revoke/start/0.1";
export const TRUST_TASK_REVOKE_FINISH =
  "https://trusttasks.org/spec/auth/passkey/revoke/finish/0.1";

// The list and its rows are the generated wire types, not local interfaces: a
// local copy is what let `GET /v1/admin/passkeys` be documented with another
// endpoint's shape (#1697) without anything here noticing. `deviceLabel` and
// `lastUsedAt` are both genuinely optional: the schema is explicit that a
// consumer must not invent a label, "because an invented one is
// indistinguishable from a chosen one to somebody deciding which credential to
// revoke", so an unlabelled credential renders as unlabelled.

// `enroll/start/0.2` sends the *inner* WebAuthn options — the value that goes
// in `navigator.credentials.create({ publicKey: … })` — not the wrapper. The
// daemon used to send `{publicKey: …}` and this file unwrapped it only to
// re-wrap it one line later; #1112 removed that round trip.
interface RegisterStartResponse {
  enrollmentId: string;
  options: JsonPublicKeyOptions;
  uvOptions: JsonPublicKeyOptions;
}

interface RevokeStartResponse {
  revocationId: string;
  uvOptions: JsonPublicKeyOptions;
}

/** Your own passkeys. */
export async function fetchPasskeys(): Promise<PasskeyListResponse> {
  return postSignedRead<PasskeyListResponse>(TRUST_TASK_LIST, {});
}

/** Register another passkey, verified by one you already hold. */
export async function registerPasskey(
  args: { label: string },
  credentials: Pick<CredentialsContainer, "create" | "get"> = navigator.credentials,
): Promise<void> {
  // `enroll/start` returns BOTH a create challenge (for the new passkey) and a
  // UV challenge (against existing passkeys, for step-up). The browser runs
  // both ceremonies, then `enroll/finish` takes both results.
  const start = await postSignedTrustTask<RegisterStartResponse>(TRUST_TASK_ENROLL_START, {});
  if (!start?.enrollmentId || !start.options?.challenge || !start.uvOptions?.challenge) {
    throw new Error(
      "the VTC's enrolment challenge is missing a member this console needs " +
        "(enrollmentId, options.challenge, uvOptions.challenge)",
    );
  }

  const createPublicKey = decodePublicKeyOptions(
    start.options,
  ) as PublicKeyCredentialCreationOptions;
  const newCred = (await credentials.create({
    publicKey: createPublicKey,
  })) as PublicKeyCredential | null;
  if (!newCred) {
    throw new Error("Passkey creation returned no credential");
  }

  const uvPublicKey = decodePublicKeyOptions(
    start.uvOptions,
  ) as PublicKeyCredentialRequestOptions;
  const uvCred = (await credentials.get({
    publicKey: uvPublicKey,
  })) as PublicKeyCredential | null;
  if (!uvCred) {
    throw new Error("Step-up UV returned no credential");
  }

  await postSignedTrustTask<unknown>(TRUST_TASK_ENROLL_FINISH, {
    enrollmentId: start.enrollmentId,
    credential: serializeRegistration(newCred),
    uvCredential: serializeAssertion(uvCred),
    ...(args.label ? { deviceLabel: args.label } : {}),
  });
}

/** Revoke one of your passkeys, verified by one you hold. */
export async function revokePasskey(
  args: { credentialId: string },
  credentials: Pick<CredentialsContainer, "get"> = navigator.credentials,
): Promise<void> {
  const start = await postSignedTrustTask<RevokeStartResponse>(TRUST_TASK_REVOKE_START, {
    credentialId: args.credentialId,
  });
  if (!start?.revocationId || !start.uvOptions?.challenge) {
    throw new Error(
      "the VTC's revocation challenge is missing a member this console needs " +
        "(revocationId, uvOptions.challenge)",
    );
  }

  const uvPublicKey = decodePublicKeyOptions(
    start.uvOptions,
  ) as PublicKeyCredentialRequestOptions;
  const uvCred = (await credentials.get({
    publicKey: uvPublicKey,
  })) as PublicKeyCredential | null;
  if (!uvCred) {
    throw new Error("Step-up UV returned no credential");
  }

  await postSignedTrustTask<unknown>(TRUST_TASK_REVOKE_FINISH, {
    revocationId: start.revocationId,
    uvCredential: serializeAssertion(uvCred),
  });
}
