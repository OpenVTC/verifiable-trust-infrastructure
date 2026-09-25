// The passkey gesture a signed document needs before the VTC will act on it —
// an **operation-bound** step-up (`crate::acl::bound_step_up`,
// `auth/step-up/approve-request/0.3` with `boundTo`).
//
// ## The flow
//
// 1. The console sends a signed document (`git-ns/right/break-glass`, say).
//    The VTC runs every check that decides whether the act is allowed, then
//    refuses `permissionDenied` with the ceremony inline as
//    `details.stepUpRequest`.
// 2. The operator answers with a passkey: `navigator.credentials.get` over the
//    request's WebAuthn options, sent back as
//    `auth/step-up/approve-response/0.4` with `evidence.kind = webauthn`. The
//    VTC records the gesture against *that one operation* — nothing is
//    elevated, no session changes.
// 3. The console sends the **identical** signed document again, which spends
//    the gesture and completes.
//
// Step 2 is its own click, never chained onto the refusal: a WebAuthn
// ceremony needs a user gesture in some browsers, and the gesture is the
// operator consenting to the act the request names, so it should be taken
// with that act on screen.
//
// ## Handed over from a terminal
//
// `cnm` cannot run a passkey ceremony. On the same refusal it prints
// `/admin/step-up#request=<base64url(JSON)>`; that page (`StepUpPage`) runs
// step 2 here, and `cnm` then re-sends its document. The request travels in
// the fragment, which browsers never send to a server.

import { postSignedTrustTask, postUnsignedTrustTask, SigningUnavailableError } from "./api";
import {
  base64urlToBuffer,
  bufferToBase64url,
  decodePublicKeyOptions,
  serializeAssertion,
  type JsonPublicKeyOptions,
} from "./webauthn";

export const APPROVE_RESPONSE_URI =
  "https://trusttasks.org/spec/auth/step-up/approve-response/0.4";

/** Where the console answers a step-up handed over from `cnm`. */
export const STEP_UP_PATH = "/step-up";

/** `auth/step-up/approve-request/0.3`, as the VTC sends it for a bound step-up. */
export interface StepUpRequest {
  subject: string;
  challenge: string;
  boundTo?: string;
  sessionId?: string;
  reason: string;
  targetAcr?: string;
  acceptableEvidence?: string[];
  webauthn?: {
    challenge: string;
    allowCredentials?: { type: string; id: string }[];
    userVerification?: string;
    rpId?: string;
    timeout?: number;
  };
  ttl?: number;
}

function isStepUpRequest(v: unknown): v is StepUpRequest {
  if (!v || typeof v !== "object") return false;
  const r = v as Record<string, unknown>;
  return (
    typeof r.subject === "string" &&
    typeof r.challenge === "string" &&
    r.challenge.length >= 16 &&
    typeof r.reason === "string" &&
    (r.webauthn === undefined || (typeof r.webauthn === "object" && r.webauthn !== null))
  );
}

/** The step-up a refusal asks for, if it asks for one. */
export function stepUpRequestOf(err: unknown): StepUpRequest | null {
  if (!err || typeof err !== "object") return null;
  const details = (err as { details?: unknown }).details;
  if (!details || typeof details !== "object") return null;
  const req = (details as { stepUpRequest?: unknown }).stepUpRequest;
  return isStepUpRequest(req) ? req : null;
}

/** Whether this request can be answered here: webauthn evidence accepted, and
 *  options to run it with. */
export function answerableHere(req: StepUpRequest): boolean {
  const kinds = req.acceptableEvidence;
  return !!req.webauthn && (!kinds || kinds.includes("webauthn"));
}

/** The fragment `cnm` puts after `/admin/step-up#request=`. */
export function encodeStepUpRequest(req: StepUpRequest): string {
  const bytes = new TextEncoder().encode(JSON.stringify(req));
  return bufferToBase64url(bytes.buffer as ArrayBuffer);
}

/** Read a request from `#request=…`, or `null` if it is absent or not one. */
export function decodeStepUpRequest(hash: string): StepUpRequest | null {
  const params = new URLSearchParams(hash.replace(/^#/, ""));
  const raw = params.get("request");
  if (!raw || !/^[A-Za-z0-9_-]+$/.test(raw)) return null;
  try {
    const json = new TextDecoder("utf-8", { fatal: true }).decode(base64urlToBuffer(raw));
    const value: unknown = JSON.parse(json);
    return isStepUpRequest(value) ? value : null;
  } catch {
    return null;
  }
}

/** What the VTC answered the gesture with. */
export interface ApproveAck {
  status: "recorded" | "rejected" | "elevated";
  boundTo?: string;
  reason?: string;
}

/**
 * Run the passkey ceremony `req` asks for and send the approve-response.
 *
 * Resolves once the VTC has **recorded** the gesture against the operation;
 * throws if it rejected it, or if the browser returned no credential. The
 * approve-response is itself a signed document from this browser's console
 * key; the WebAuthn assertion inside it is the gate, and the VTC checks that
 * it came from a passkey registered to `req.subject`.
 */
export async function answerStepUp(
  req: StepUpRequest,
  credentials: Pick<CredentialsContainer, "get"> = navigator.credentials,
): Promise<ApproveAck> {
  if (!answerableHere(req)) {
    throw new Error("the VTC asked for a step-up this console cannot answer with a passkey");
  }
  const w = req.webauthn!;
  // The request's challenge is the one the VTC bound server-side. An options
  // object carrying a different one would produce an assertion over a nonce
  // nobody is waiting for — refuse it rather than ask for a useless gesture.
  if (w.challenge !== req.challenge) {
    throw new Error("the step-up request's WebAuthn challenge does not match its own challenge");
  }
  const publicKey = decodePublicKeyOptions({
    ...(w as unknown as JsonPublicKeyOptions),
    userVerification: w.userVerification ?? "required",
  }) as PublicKeyCredentialRequestOptions;
  const credential = (await credentials.get({ publicKey })) as PublicKeyCredential | null;
  if (!credential) throw new Error("the passkey ceremony returned no credential");

  const payload: Record<string, unknown> = {
    subject: req.subject,
    challenge: req.challenge,
    decision: "approved",
    evidence: { kind: "webauthn", assertion: serializeAssertion(credential) },
  };
  if (req.sessionId) payload.sessionId = req.sessionId;
  // A console user's browser signs with its console key. A member who is no
  // console user answers with a step-up passkey and has no key here: the
  // assertion is the gate, so the answer goes unsigned.
  let ack: ApproveAck;
  try {
    ack = await postSignedTrustTask<ApproveAck>(APPROVE_RESPONSE_URI, payload);
  } catch (e) {
    if (!(e instanceof SigningUnavailableError)) throw e;
    ack = await postUnsignedTrustTask<ApproveAck>(APPROVE_RESPONSE_URI, payload, req.subject);
  }
  if (ack.status !== "recorded") {
    throw new Error(
      ack.reason
        ? `the VTC did not record the gesture: ${ack.reason}`
        : `the VTC did not record the gesture (${ack.status})`,
    );
  }
  return ack;
}
