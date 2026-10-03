// Step-up approvers — the console side of `auth/step-up/approver/*`
// (`crate::step_up_approver` at the VTC).
//
// A step-up approver is a `did:key` bound at this community to one subject as
// their step-up factor: the VTA browser plugin's approver identity, whose seed
// is unlocked only by a user gesture. It confers nothing — no role, no scope,
// no session — and is read only when the VTC asks the subject for an
// operation-bound step-up. It counts as a second factor only because it was
// bound on an anchor independent of the subject's signing key (VTI-APV-016):
//
// - an administrator's **invite** (`invite/0.1`), redeemed by the invited
//   subject's own signature plus a claim code delivered on another channel
//   (`redeem/{start,finish}/0.1`);
// - a factor the subject **already holds** (`enroll/0.1`, self-service), over
//   a digest of the enrolment's terms;
// - the install token, or the host (`vtc admin enrol-approver`, offline).
//
// Every enrolment also carries the approver's own enrolment statement
// (`attest/0.1`, `purpose: enrol`) — proof of possession — and is signed by
// the subject's **own DID** through the wallet, never by a console key.

import {
  addressedDocument,
  postSignedDocument,
  postSignedTrustTask,
  vtcDid,
  type ApiError,
} from "./api";
import { answerStepUp, operationOf, stepUpRequestOf } from "./bound-step-up";
import type { SignedTrustTaskDocument } from "./console-key";
import { base58btcEncode, jcsCanonicalize, sha256 } from "./jcs";
import { GestureDeclinedError, postSignedWithStepUp, type ConfirmGesture } from "./signed-act";
import { attestApproverWithWallet, signWithWallet, walletApproverDid } from "./wallet";

export const APPROVER_LIST_TASK = "https://trusttasks.org/spec/auth/step-up/approver/list/0.1";
export const APPROVER_REVOKE_TASK = "https://trusttasks.org/spec/auth/step-up/approver/revoke/0.1";
export const APPROVER_INVITE_TASK = "https://trusttasks.org/spec/auth/step-up/approver/invite/0.1";
export const APPROVER_ENROLL_TASK = "https://trusttasks.org/spec/auth/step-up/approver/enroll/0.1";
export const APPROVER_REDEEM_START_TASK = "https://trusttasks.org/spec/auth/step-up/approver/redeem/start/0.1";
export const APPROVER_REDEEM_FINISH_TASK = "https://trusttasks.org/spec/auth/step-up/approver/redeem/finish/0.1";

/** Invite lifetimes (`invite/0.1`): 15 minutes by default, a day at most. */
export const DEFAULT_INVITE_TTL_SECS = 900;
export const MAX_INVITE_TTL_SECS = 86_400;

/** The anchor a binding rested on (`_shared/0.1#/$defs/EnrolledVia`). */
export type EnrolledVia = "install" | "invite" | "selfService" | "offline";

/** One binding (`_shared/0.1#/$defs/Approver`). */
export interface Approver {
  approverDid: string;
  subject: string;
  label?: string;
  enrolledAt: string;
  enrolledVia: EnrolledVia;
  lastUsedAt?: string;
}

/** `list/0.1#response`. */
export interface ApproverList {
  approvers: Approver[];
}

/** `revoke/0.1#response`. */
export interface ApproverRevoked {
  revoked: Approver;
  revokedAt: string;
  remainingApprovers: number;
}

/** `invite/0.1#response`. The claim code is shown exactly once. */
export interface ApproverInvite {
  inviteId: string;
  url: string;
  claimCode: string;
  expiresAt: string;
}

/** `redeem/start/0.1#response`. */
export interface ApproverRedeemStarted {
  enrollmentId: string;
  challenge: string;
  audience: string;
  expiresAt: string;
}

/** `redeem/finish/0.1#response` and `enroll/0.1#response`. */
export interface ApproverBound {
  approver: Approver;
}

export const ENROLLED_VIA_LABEL: Record<EnrolledVia, string> = {
  install: "install",
  invite: "administrator's invite",
  selfService: "self-service",
  offline: "host (offline)",
};

export const approverKeys = {
  of: (subject: string | null) => ["step-up-approvers", subject ?? "self"] as const,
};

/** The subject's live approvers — their own when `subject` is absent, another
 *  member's for an administrator over them. Signed by this browser's console
 *  key; reading changes nothing (not even `lastUsedAt`). */
export function fetchApprovers(subject?: string): Promise<ApproverList> {
  return postSignedTrustTask<ApproverList>(APPROVER_LIST_TASK, subject ? { subject } : {});
}

/** Revoke one approver — the caller's own, or (naming `subject`) a member's
 *  as an administrator over them. The VTC asks the caller for a bound step-up
 *  first; revoking the last one is allowed and recoverable by invite. */
export function revokeApprover(
  args: { approverDid: string; subject?: string; reason?: string },
  confirmGesture: ConfirmGesture,
): Promise<ApproverRevoked> {
  return postSignedWithStepUp<ApproverRevoked>(
    APPROVER_REVOKE_TASK,
    {
      approverDid: args.approverDid,
      ...(args.subject ? { subject: args.subject } : {}),
      ...(args.reason ? { reason: args.reason } : {}),
    },
    confirmGesture,
  );
}

/** Invite `subject` to enrol an approver (an administrator, never for
 *  themselves), behind the inviting administrator's own bound step-up. */
export function inviteApprover(
  args: { subject: string; label?: string; ttl?: number },
  confirmGesture: ConfirmGesture,
): Promise<ApproverInvite> {
  return postSignedWithStepUp<ApproverInvite>(
    APPROVER_INVITE_TASK,
    {
      subject: args.subject,
      ...(args.label ? { label: args.label } : {}),
      ...(args.ttl ? { ttl: args.ttl } : {}),
    },
    confirmGesture,
  );
}

/**
 * The **terms digest** a self-service enrolment's statement binds as
 * `boundTo` (`auth/step-up/approver/enroll/0.1`, *Enrolment terms and their
 * digest*): `"z" + base58btc(0x12 0x20 ‖ SHA-256(UTF-8(JCS({type, subject,
 * challenge, terms}))))`, where `terms` is the enrolment payload without
 * `statement` and `challenge` is the step-up that authorized it. The VTC
 * recomputes it identically (`step_up_approver::terms_digest`).
 */
export async function termsDigest(
  subject: string,
  challenge: string,
  terms: Record<string, unknown>,
): Promise<string> {
  const { statement: _statement, ...bare } = terms;
  void _statement;
  const digest = await sha256(
    jcsCanonicalize({ type: APPROVER_ENROLL_TASK, subject, challenge, terms: bare }),
  );
  const multihash = new Uint8Array(2 + digest.length);
  multihash.set([0x12, 0x20]);
  multihash.set(digest, 2);
  return `z${base58btcEncode(multihash)}`;
}

/** A document of `typeUri` from `subject`, signed by the wallet **as
 *  `subject`'s own DID** — what every enrolment step requires. */
async function walletSigned(
  typeUri: string,
  payload: unknown,
  subject: string,
): Promise<SignedTrustTaskDocument> {
  const envelope = await addressedDocument(typeUri, payload, subject);
  return (await signWithWallet({ ...envelope }, subject)) as unknown as SignedTrustTaskDocument;
}

/**
 * Self-service enrolment (`enroll/0.1`): add this browser's plugin approver
 * for `subject`, on the evidence of a step-up factor they already hold.
 *
 * 1. The enrolment's terms are sent without a statement, signed by the wallet
 *    as `subject`; the VTC answers with the bound step-up it needs.
 * 2. That step-up is answered with an existing factor ([`answerStepUp`]).
 * 3. The plugin's approver signs its enrolment statement over the step-up's
 *    challenge, bound to the [`termsDigest`]; the terms are sent again with
 *    it, and the VTC binds the approver.
 */
export async function enrolApproverSelfService(
  args: { subject: string; label?: string; replaces?: string },
  confirmGesture: ConfirmGesture,
): Promise<ApproverBound> {
  const audience = await vtcDid();
  const approverDid = await walletApproverDid(audience);
  const terms: Record<string, unknown> = {
    approverDid,
    ...(args.label ? { label: args.label } : {}),
    ...(args.replaces ? { replaces: args.replaces } : {}),
  };

  let request;
  try {
    return await postSignedDocument<ApproverBound>(
      await walletSigned(APPROVER_ENROLL_TASK, terms, args.subject),
    );
  } catch (e) {
    request = stepUpRequestOf(e);
    if (!request) throw e;
  }
  if (!(await confirmGesture(request))) throw new GestureDeclinedError();
  await answerStepUp(request, undefined, operationOf({ type: APPROVER_ENROLL_TASK, payload: terms }));

  const boundTo = await termsDigest(args.subject, request.challenge, terms);
  const { statement } = await attestApproverWithWallet({
    purpose: "enrol",
    subject: args.subject,
    audience,
    challenge: request.challenge,
    boundTo,
  });
  return postSignedDocument<ApproverBound>(
    await walletSigned(APPROVER_ENROLL_TASK, { ...terms, statement }, args.subject),
  );
}

/** `redeem/start/0.1`: open the enrolment an invite allows, signed by the
 *  wallet as the invited subject. */
export async function redeemApproverStart(
  subject: string,
  token: string,
  claimCode: string,
): Promise<ApproverRedeemStarted> {
  return postSignedDocument<ApproverRedeemStarted>(
    await walletSigned(APPROVER_REDEEM_START_TASK, { token, claimCode: claimCode.trim() }, subject),
  );
}

/** `redeem/finish/0.1`: the plugin's approver proves possession over the
 *  ceremony's challenge (`boundTo` = `enrollmentId`), and the wallet signs the
 *  finish as the subject. */
export async function redeemApproverFinish(
  subject: string,
  started: ApproverRedeemStarted,
  label?: string,
): Promise<ApproverBound> {
  const { statement, approverDid } = await attestApproverWithWallet({
    purpose: "enrol",
    subject,
    audience: started.audience,
    challenge: started.challenge,
    boundTo: started.enrollmentId,
  });
  return postSignedDocument<ApproverBound>(
    await walletSigned(
      APPROVER_REDEEM_FINISH_TASK,
      {
        enrollmentId: started.enrollmentId,
        approverDid,
        ...(label ? { label } : {}),
        statement,
      },
      subject,
    ),
  );
}

/** Operator-facing text for the codes the approver family declares. */
const CODE_TEXT: Record<string, string> = {
  "auth/step-up/approver/invite:selfInvite":
    "An administrator cannot invite themselves — ask another administrator.",
  "auth/step-up/approver/invite:subjectUnknown": "That DID is not a current member.",
  "auth/step-up/approver/invite:ttlTooLong": "An invite lives at most 24 hours.",
  "auth/step-up/approver/redeem/start:inviteNotFound":
    "This invite is not valid here, or has already been used.",
  "auth/step-up/approver/redeem/start:inviteExpired":
    "This invite has expired. Ask the administrator for a new one.",
  "auth/step-up/approver/redeem/start:inviteVoided":
    "Too many wrong claim codes: this invite is void. Ask the administrator for a new one.",
  "auth/step-up/approver/redeem/start:notInvitedSubject":
    "This invite is for a different DID than the one your wallet signed as.",
  "auth/step-up/approver/redeem/start:codeMismatch": "The claim code is wrong.",
  "auth/step-up/approver/redeem/finish:enrollmentNotFound":
    "The enrolment is no longer open — start again from the invite link.",
  "auth/step-up/approver/redeem/finish:enrollmentExpired":
    "The enrolment lapsed. Start again while the invite is still valid.",
  "auth/step-up/approver/redeem/finish:notInvitedSubject":
    "The finish must be signed by the invited DID itself.",
  "auth/step-up/approver/redeem/finish:statementInvalid":
    "The approver's enrolment statement was refused.",
  "auth/step-up/approver/redeem/finish:approverNotDistinct":
    "That approver is one of your own signing keys; a step-up factor must be a different key.",
  "auth/step-up/approver/redeem/finish:approverAlreadyBound":
    "That approver is already bound here, or was revoked — the plugin must use a new one.",
  "auth/step-up/approver/redeem/finish:tooManyApprovers":
    "You already hold five approvers. Revoke one first.",
  "auth/step-up/approver/enroll:subjectMismatch":
    "An enrolment must be signed by your own DID through the wallet, not by a console key.",
  "auth/step-up/approver/enroll:noFactorHeld":
    "You hold no step-up factor to authorize this with. Ask a community administrator to invite you to enrol an approver (Members → you → \"Invite to enrol an approver\").",
  "auth/step-up/approver/enroll:statementInvalid": "The approver's enrolment statement was refused.",
  "auth/step-up/approver/enroll:approverNotDistinct":
    "That approver is one of your own signing keys; a step-up factor must be a different key.",
  "auth/step-up/approver/enroll:approverAlreadyBound":
    "That approver is already bound here, or was revoked.",
  "auth/step-up/approver/enroll:tooManyApprovers":
    "You already hold five approvers. Revoke one first.",
  "auth/step-up/approver/enroll:replaceNotFound": "The approver to replace is not one of yours.",
  "auth/step-up/approver/revoke:notFound": "No such approver you may revoke.",
};

/** The text to show for a refusal from this family, falling back to the
 *  VTC's own message. */
export function approverErrorMessage(err: unknown): string {
  const e = err as (ApiError & { details?: { attemptsRemaining?: unknown } }) | null;
  const text = e?.code ? CODE_TEXT[e.code] : undefined;
  if (text) {
    const left = e?.details?.attemptsRemaining;
    return typeof left === "number" ? `${text} ${left} attempt${left === 1 ? "" : "s"} left.` : text;
  }
  if (err && typeof err === "object" && "message" in err) {
    const m = (err as { message: unknown }).message;
    if (typeof m === "string" && m) return m;
  }
  return String(err);
}
