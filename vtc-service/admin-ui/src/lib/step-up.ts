/** Elevating this session with a passkey user-verification gesture.
 *
 * Shared because the daemon's gate is shared: since #1645 every path that
 * confers the `admin` role — promoting a member (`acl/change-role`) and adding
 * an admin ACL entry outright (`acl/grant`) — requires a **live** elevation on
 * the caller's session. A console screen that offers one of those operations
 * without running this first can only ever answer `step_up_required`.
 *
 * The elevation is independent of what it authorises: the daemon stamps a
 * bounded window on the session, and any operation gated on a fresh step-up
 * can spend it while it is open.
 */

import { postJson } from "./api";
import {
  decodePublicKeyOptions,
  serializeAssertion,
  type JsonPublicKeyOptions,
} from "./webauthn";

const TRUST_TASK_PASSKEY_STEP_UP_START =
  "https://trusttasks.org/spec/auth/passkey/login/start/0.2";
const TRUST_TASK_PASSKEY_STEP_UP_FINISH =
  "https://trusttasks.org/spec/auth/passkey/login/finish/0.2";

// As on the sign-in path: `login/start/0.2` sends the inner WebAuthn options,
// not webauthn-rs's `{publicKey: …}` wrapper (#1112).
interface StepUpStartResponse {
  authId: string;
  options: JsonPublicKeyOptions;
}

/** Run the `purpose: stepUp` ceremony against the caller's current session.
 *
 * Callers run this **before** the operation it authorises, rather than
 * attempting the operation, catching `step_up_required` and retrying: that
 * keeps the operator's passkey gesture tied to the click that asked for it,
 * which is the whole point of requiring a *recent* second factor.
 */
export async function stepUpSession(): Promise<void> {
  const start = await postJson<StepUpStartResponse>(
    "/v1/auth/passkey-login/start",
    { purpose: "stepUp" },
    {
      trustTask: TRUST_TASK_PASSKEY_STEP_UP_START,
      requires: ["authId", "options.challenge"],
    },
  );

  const publicKey = decodePublicKeyOptions(
    start.options,
  ) as PublicKeyCredentialRequestOptions;
  const credential = (await navigator.credentials.get({
    publicKey,
  })) as PublicKeyCredential | null;
  if (!credential) throw new Error("Passkey ceremony returned no credential");

  await postJson<unknown>(
    "/v1/auth/passkey-login/finish",
    {
      auth_id: start.authId,
      credential: serializeAssertion(credential),
    },
    { trustTask: TRUST_TASK_PASSKEY_STEP_UP_FINISH },
  );
}
