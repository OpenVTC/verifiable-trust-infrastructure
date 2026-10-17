// The bearer → cookie bridge, `vtc/auth/admin-session/0.1`, for the SIOPv2
// wallet sign-ins on the login page ("Using an older wallet?").
//
// Those sign-ins end with an access token in hand, and the console runs on the
// cookie session, so the token is exchanged for the cookies. The task declares
// `proof` REQUIRED (VTI-OPS-020), so it is a signed document on
// `POST /v1/trust-tasks` — the bearer route `POST /v1/auth/admin-session` is
// gone (#1641) — and the VTC accepts it only when the document is signed by
// the token's own subject, or by a console key that subject enrolled. Holding
// the token alone is no longer enough to turn it into a cookie session.
//
// Who signs, in order:
//
// 1. **The wallet, as the identity it just signed in as.** It holds that key
//    (or the VTA does, for a persona), and it prompts for this signature as it
//    prompts for every one.
// 2. **This browser's console key**, when the wallet cannot sign Trust Tasks.
//    The VTC accepts it only if it was enrolled by the identity that signed in,
//    which a returning browser's key usually was.
//
// With neither, the sign-in cannot finish here, and the error says which
// sign-in to use instead.

import {
  addressedDocument,
  postSignedDocument,
  postSignedTrustTask,
  signingAvailable,
} from "./api";
import {
  adoptBrowserSessionKey,
  mintBrowserSessionKey,
  type SignedTrustTaskDocument,
} from "./console-key";
import { isWalletSigningAvailable, signWithWallet } from "./wallet";

export const TASK_ADMIN_SESSION = "https://trusttasks.org/spec/vtc/auth/admin-session/0.1";

/** `vtc/auth/admin-session/0.1`'s response. */
export interface AdminSessionResponse {
  sessionId: string;
  /** Unix seconds — the access token's own expiry. */
  expiresAt: number;
}

/** Neither the wallet nor this browser can sign the exchange. */
export class AdminSessionSigningError extends Error {
  constructor() {
    super(
      "This wallet cannot sign the request that opens your console session, and this " +
        "browser holds no signing key for you. Use “Sign in with your wallet” or your " +
        "passkey instead.",
    );
    this.name = "AdminSessionSigningError";
  }
}

/**
 * Exchange `accessToken`, issued to `subject` by a wallet sign-in, for the
 * console's cookie session. The VTC sets the cookies on this response.
 */
export async function openAdminSession(
  accessToken: string,
  subject: string,
): Promise<AdminSessionResponse> {
  // A fresh browser key, bound to the session in the same signed document —
  // the signer's proof covers it — and kept only once the VTC has bound it.
  // It signs `whoami` from then on (`console-key.ts`).
  const sessionKey = await mintBrowserSessionKey();
  const payload = {
    accessToken,
    ext: { "org.openvtc": { sessionKey: sessionKey.consoleDid } },
  };
  let response: AdminSessionResponse;
  if (isWalletSigningAvailable()) {
    const signed = await signWithWallet(
      { ...(await addressedDocument(TASK_ADMIN_SESSION, payload, subject)) },
      subject,
    );
    response = await postSignedDocument<AdminSessionResponse>(
      signed as unknown as SignedTrustTaskDocument,
    );
  } else if (await signingAvailable()) {
    response = await postSignedTrustTask<AdminSessionResponse>(TASK_ADMIN_SESSION, payload);
  } else {
    throw new AdminSessionSigningError();
  }
  await adoptBrowserSessionKey(sessionKey);
  return response;
}
