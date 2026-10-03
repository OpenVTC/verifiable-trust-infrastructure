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
//
// ## Who signs the answer
//
// A console user's browser holds a session passkey of the operator's and no
// key of theirs — its console key is a delegation, and a delegated key is
// never accepted as an approver's attestation (`auth/signing-key/enroll/0.1`
// item 7). So it answers **unsigned**, with the passkey assertion as the gate
// (approve-response 0.4 `evidence.kind = webauthn`). A member who is no
// console user answers with a step-up passkey, which is only ever beside the
// member's own proof, so this page does the ceremony and shows an **answer
// code** — the assertion — which `cnm` signs into the approve-response with
// the member's own key.
//
// ## Or with a step-up approver
//
// A wallet administrator holds no passkey here. When the request `accepts`
// `approverSigned` (approve-request 0.4) and the VTA browser plugin exposes
// `approveStepUp`, the plugin's **approver** — a `did:key` bound to the
// subject as their step-up factor, unlocked only by a user gesture — signs an
// `auth/step-up/approver/attest/0.1` statement over the challenge and
// `boundTo`, after recomputing `boundTo` from the operation it is shown. The
// console then has the wallet sign `auth/step-up/approve-response/0.6`
// carrying that statement **as the subject's own DID** — never the console
// key, which is a delegation the VTC refuses for this (VTI-APV-015 as amended,
// VTI-APV-016).

import { addressedDocument, postSignedDocument, postUnsignedTrustTask, vtcDid } from "./api";
import type { SignedTrustTaskDocument } from "./console-key";
import {
  approveStepUpWithWallet,
  isWalletApproverAvailable,
  signWithWallet,
  type ApproverStepUpRequest,
} from "./wallet";
import {
  base64urlToBuffer,
  bufferToBase64url,
  decodePublicKeyOptions,
  serializeAssertion,
  type JsonPublicKeyOptions,
} from "./webauthn";

export const APPROVE_RESPONSE_URI =
  "https://trusttasks.org/spec/auth/step-up/approve-response/0.4";
/** The approve-response version that carries `approverSigned` evidence. */
export const APPROVE_RESPONSE_V0_6_URI =
  "https://trusttasks.org/spec/auth/step-up/approve-response/0.6";

/** Where the console answers a step-up handed over from `cnm`. */
export const STEP_UP_PATH = "/step-up";

/** `auth/step-up/approve-request/0.4` (or 0.3), as the VTC sends it for a
 *  bound step-up. */
export interface StepUpRequest {
  subject: string;
  challenge: string;
  boundTo?: string;
  sessionId?: string;
  reason: string;
  targetAcr?: string;
  /** 0.4: every evidence kind the VTC will take for this step-up. */
  accepts?: string[];
  /** 0.4: the subject's bound approver DIDs, present iff `accepts` lists
   *  `approverSigned`. */
  approvers?: string[];
  /** 0.3's spelling of `accepts`, still read for a request from an older VTC. */
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

/** The evidence kinds `req` accepts: 0.4's `accepts`, else 0.3's
 *  `acceptableEvidence`, else (neither stated) a passkey if it carries
 *  options for one. */
export function acceptedKinds(req: StepUpRequest): string[] {
  return req.accepts ?? req.acceptableEvidence ?? (req.webauthn ? ["webauthn"] : []);
}

/** Whether this request can be answered here with a passkey: webauthn
 *  evidence accepted, and options to run it with. */
export function answerableHere(req: StepUpRequest): boolean {
  return !!req.webauthn && acceptedKinds(req).includes("webauthn");
}

/** Whether this request can be answered here with the wallet plugin's step-up
 *  approver: `approverSigned` accepted, an approver named, and a plugin that
 *  can answer and sign as the subject. */
export function approverAnswerableHere(req: StepUpRequest): boolean {
  return (
    acceptedKinds(req).includes("approverSigned") &&
    (req.approvers?.length ?? 0) > 0 &&
    isWalletApproverAvailable()
  );
}

/** The refused operation a step-up is bound to — what the approver recomputes
 *  `boundTo` from. */
export interface StepUpOperation {
  type: string;
  payload: unknown;
}

/** The operation a refused signed document carries. */
export function operationOf(document: { type: string; payload: unknown }): StepUpOperation {
  return { type: document.type, payload: document.payload };
}

/** Whether anything this console holds can answer `req`, given the operation
 *  it is for (an approver needs the operation; a passkey does not). */
export function answerableAtAll(req: StepUpRequest, operation?: StepUpOperation): boolean {
  return (!!operation && approverAnswerableHere(req)) || answerableHere(req);
}

/** What to tell an operator this console holds nothing to answer `req` with.
 *  Names only routes that exist for them — never a self-invite. */
export function noFactorGuidance(req: StepUpRequest): string {
  const wantsApprover = acceptedKinds(req).includes("approverSigned");
  return (
    `This needs a step-up from ${req.subject}` +
    (wantsApprover
      ? ", answered by your step-up approver — open the console in the browser whose VTA wallet plugin holds it."
      : ", and you hold no step-up factor this console can use.") +
    " To enrol one, ask another community administrator to invite you (Members → you → " +
    '"Invite to enrol an approver"), or have the operator run ' +
    `\`vtc admin enrol-approver --did ${req.subject}\` on the host with the daemon stopped.`
  );
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
 * Run the passkey ceremony `req` asks for and return the assertion.
 *
 * Throws if the request cannot be answered here, or the browser returned no
 * credential.
 */
export async function runStepUpCeremony(
  req: StepUpRequest,
  credentials: Pick<CredentialsContainer, "get"> = navigator.credentials,
): Promise<PublicKeyCredential> {
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
  return credential;
}

/**
 * Answer the step-up `req` asks for and send the approve-response.
 *
 * With `operation` (the refused document's type and payload), an
 * `approverSigned` request and a wallet plugin exposing `approveStepUp`, the
 * plugin's approver signs the statement and the wallet signs approve-response
 * 0.6 as `req.subject` ([`answerWithApprover`]). Otherwise the passkey
 * ceremony runs and approve-response 0.4 goes **unsigned**: the WebAuthn
 * assertion is the gate, and the VTC checks that it came from a console
 * passkey registered to `req.subject`. With neither, it throws
 * [`noFactorGuidance`].
 *
 * Resolves once the VTC has **recorded** the gesture against the operation;
 * throws if it rejected it or the browser returned no credential. A member's
 * step-up passkey is refused this way — use [`runStepUpCeremony`] and
 * [`answerCodeOf`], and let `cnm` sign.
 */
export async function answerStepUp(
  req: StepUpRequest,
  credentials: Pick<CredentialsContainer, "get"> = navigator.credentials,
  operation?: StepUpOperation,
): Promise<ApproveAck> {
  if (operation && approverAnswerableHere(req)) {
    return answerWithApprover(req, operation);
  }
  if (!answerableHere(req)) {
    throw new Error(noFactorGuidance(req));
  }
  const credential = await runStepUpCeremony(req, credentials);
  const payload: Record<string, unknown> = {
    subject: req.subject,
    challenge: req.challenge,
    decision: "approved",
    evidence: { kind: "webauthn", assertion: serializeAssertion(credential) },
  };
  if (req.sessionId) payload.sessionId = req.sessionId;
  const ack = await postUnsignedTrustTask<ApproveAck>(APPROVE_RESPONSE_URI, payload, req.subject);
  return recorded(ack);
}

/**
 * The `approverSigned` answer: the plugin's approver signs the statement over
 * `req` (after recomputing `boundTo` from `operation`), and the wallet signs
 * `auth/step-up/approve-response/0.6` around it **as `req.subject`** — the
 * outer proof must be the subject's own DID, never a console key's delegation
 * (approve-response 0.6, consumer step 1a).
 */
export async function answerWithApprover(
  req: StepUpRequest,
  operation: StepUpOperation,
): Promise<ApproveAck> {
  const audience = await vtcDid();
  const { statement, approverDid } = await approveStepUpWithWallet({
    request: req as unknown as ApproverStepUpRequest,
    operation,
    audience,
  });
  if (req.approvers && !req.approvers.includes(approverDid)) {
    throw new Error(
      `The wallet answered with approver ${approverDid}, which is not one this community ` +
        "has bound to you. Enrol it first, or answer from the browser that holds a bound one.",
    );
  }
  const payload: Record<string, unknown> = {
    subject: req.subject,
    challenge: req.challenge,
    decision: "approved",
    evidence: { kind: "approverSigned", statement },
  };
  if (req.sessionId) payload.sessionId = req.sessionId;
  const envelope = await addressedDocument(APPROVE_RESPONSE_V0_6_URI, payload, req.subject);
  const signed = await signWithWallet({ ...envelope }, req.subject);
  const ack = await postSignedDocument<ApproveAck>(signed as unknown as SignedTrustTaskDocument);
  return recorded(ack);
}

function recorded(ack: ApproveAck): ApproveAck {
  if (ack.status !== "recorded") {
    throw new Error(
      ack.reason
        ? `the VTC did not record the gesture: ${ack.reason}`
        : `the VTC did not record the gesture (${ack.status})`,
    );
  }
  return ack;
}

/** The prefix `cnm` reads an answer code by. */
export const ANSWER_CODE_PREFIX = "sua1.";

/**
 * The assertion as an **answer code** for `cnm` to sign into the
 * approve-response: `sua1.<rawId>.<authenticatorData>.<clientDataJSON>.<signature>[.<userHandle>]`,
 * each part base64url. One unwrapped line, short enough for a terminal to
 * read back (macOS reads at most 1024 bytes a line from a tty). It is useless
 * without the member's signature, and good for one challenge only.
 */
export function answerCodeOf(credential: PublicKeyCredential): string {
  const a = serializeAssertion(credential) as {
    rawId: string;
    response: {
      authenticatorData: string;
      clientDataJSON: string;
      signature: string;
      userHandle: string | null;
    };
  };
  const parts = [
    a.rawId,
    a.response.authenticatorData,
    a.response.clientDataJSON,
    a.response.signature,
  ];
  if (a.response.userHandle) parts.push(a.response.userHandle);
  return ANSWER_CODE_PREFIX + parts.join(".");
}
