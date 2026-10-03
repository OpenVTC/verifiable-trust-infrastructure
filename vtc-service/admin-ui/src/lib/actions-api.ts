// The administrator action list — `vtc/admin/actions/{list,show,cancel,
// acknowledge}` and the approver's `task-consent/decision/0.2`
// (docs/05-design-notes/vtc-action-list.md §6, §7).
//
// The console speaks the 0.2 wire. Three categories share the list. An
// `approval` waits for other administrators' decisions. A `coolingOff`
// (VTI-APV-019's two-administrator rule) has nobody to consent to it: it lands
// by itself at `landsAt` unless its requester cancels it, and its subject sees
// it (`callerRole: subject`) but can neither decide nor cancel. An
// `acknowledge` item is an operator's offline write (VTI-VTC-023): already in
// effect, it needs each administrator to record that they have seen it, and
// acknowledging changes nothing.
//
// Reads, cancel and acknowledge are signed with this browser's console key, like every
// other administrator read. A **decision** is not: an approval's proof is the
// approver's authorization, so it is signed by the approver's own DID through
// the wallet (`signTrustTask({asDid})`, the VTA holds the key) — exactly as
// `auth/signing-key/enroll/0.2`'s authorization is (`console-keys-api.ts`).
// The VTC refuses a decision signed by a delegated console key, so this module
// never offers one: with no wallet, the console shows the `cnm` command.
//
// A decision may carry `evidence`, an additional factor beside that proof: the
// administrator's step-up **approver device** (`approverSigned`, the VTA
// browser plugin's `approveDecision`) or a console passkey (`webauthn`).

import {
  addressedDocument,
  postSignedDocument,
  postSignedRead,
  postSignedTrustTask,
  vtcDid,
  type ApiError,
} from "./api";
import { wireDigest } from "./action-summary";
import type { ActionSummaryWire } from "./action-summary";
import type { SignedTrustTaskDocument } from "./console-key";
import { ACTIONS_SHOW_TASK } from "./parked-action";
import { fetchApprovers } from "./step-up-approvers";
import {
  approveDecisionWithWallet,
  isWalletDecisionApproverAvailable,
  isWalletSigningAvailable,
  signWithWallet,
  walletApproverIdentity,
  type ApproverSignedEvidence,
} from "./wallet";
import { serializeAssertion } from "./webauthn";

export const ACTIONS_LIST_TASK = "https://trusttasks.org/spec/vtc/admin/actions/list/0.2";
export { ACTIONS_SHOW_TASK };
export const ACTIONS_CANCEL_TASK = "https://trusttasks.org/spec/vtc/admin/actions/cancel/0.2";
export const ACTIONS_ACKNOWLEDGE_TASK =
  "https://trusttasks.org/spec/vtc/admin/actions/acknowledge/0.2";
export const DECISION_TASK = "https://trusttasks.org/spec/task-consent/decision/0.2";

/** The longest `reason` a decision or cancel carries. */
export const MAX_REASON_LEN = 500;

// ── Wire shapes ─────────────────────────────────────────────────────

export type ActionStatus = "open" | "completed" | "declined" | "expired" | "cancelled" | "failed";

export type ClosedReason =
  | "thresholdMet"
  | "declined"
  | "expired"
  | "cancelledByRequester"
  | "invalidated"
  | "failedRecheck"
  /** An operator's offline write every expected administrator acknowledged. */
  | "acknowledged"
  /** A cooling-off reached `landsAt` uncancelled and its operation ran. */
  | "landedAfterCoolingOff";

/** `acknowledger`: an operator's offline write waits for this caller's
 *  acknowledgement (VTI-VTC-023). `subject`: the administrator a cooling-off
 *  acts on — shown it so they see it coming, but can neither decide nor
 *  cancel it (VTI-APV-019). */
export type CallerRole = "approver" | "requester" | "observer" | "acknowledger" | "subject";

/** `queue` is in the 0.2 wire but the VTC raises none yet. */
export type ActionCategory = "approval" | "acknowledge" | "queue" | "coolingOff";

export type ActionsView = "waitingForMe" | "requestedByMe" | "history" | "all";

export interface ActionApproval {
  subject: string;
  at: string;
}

/** A reduction of an unrestricted administrator that nobody but the requester
 *  and the subject could consent to (VTI-APV-019): it lands by itself at
 *  `landsAt` unless the requester cancels it. Read off the 0.2 action's own
 *  fields by [`coolingOffOf`]. */
export interface CoolingOff {
  landsAt: string;
  /** The administrator it acts on, when the verified summary's `subject`
   *  field names one (the action has no top-level subject). */
  subject?: string;
  /** The caller is the administrator it reduces (`callerRole: subject`) —
   *  who sees it coming but cannot block it. */
  againstYou: boolean;
  /** The caller may withdraw it now: its requester, while it is open. */
  cancellableByMe: boolean;
}

/** A step-up approver enrolment invite for the new administrator a completed
 *  grant made, shown to its requester once (`show`, then dropped). */
export interface ApproverInviteResult {
  inviteId: string;
  url: string;
  claimCode: string;
  expiresAt: string;
}

export interface ActionExt {
  approverCount?: number;
  requesterRecentActions?: number;
  burst?: boolean;
  closedMessage?: string;
  closedBy?: string;
  /** What the completed act returned — an invite's `installUrl` and
   *  `claimCode`, which `show` hands the requester once. */
  result?: Record<string, unknown>;
  /** `acknowledge` items: always `critical`. */
  severity?: "critical";
  /** `acknowledge` items: whether this caller has acknowledged it. */
  acknowledgedByMe?: boolean;
  approverInvite?: ApproverInviteResult;
  /** Present on an operation single-administrator mode let through on the
   *  requester's own gesture, nobody else being eligible to consent
   *  (VTI-APV-022). Completed at once; it carries no threshold. */
  consentWaived?: ConsentWaived;
}

/** How an action's consent was waived (VTI-APV-022). */
export interface ConsentWaived {
  mode: "singleAdministrator";
  /** The requirement whose consent was waived (`VTI-APV-018`, …). */
  requirement: string;
}

export interface Action {
  actionId: string;
  category: ActionCategory;
  kind: string;
  typeUri: string;
  requester: string;
  status: ActionStatus;
  createdAt: string;
  /** Absent on an `acknowledge` item and on a cooling-off: neither lapses. */
  expiresAt?: string;
  /** `coolingOff` only — and always there: when it lands unless cancelled. */
  landsAt?: string;
  /** Who may cancel it while open; on every open `coolingOff`, `requester`. */
  cancellableBy?: "requester";
  closedAt?: string;
  closedReason?: ClosedReason;
  approvals: ActionApproval[];
  approversRemaining?: number;
  callerRole: CallerRole;
  /** Present only when this caller may decide now. */
  challenge?: string;
  payload: Record<string, unknown>;
  payloadDigest: string;
  /** Absent on an `acknowledge` item. */
  requesterOpenActions?: number;
  /** Absent on an `acknowledge` item and on a cooling-off: no approval is
   *  needed, and a published threshold cannot say zero. */
  threshold?: number;
  summary: ActionSummaryWire;
  ext?: { "org.openvtc"?: ActionExt };
}

export interface ActionCounts {
  waitingForMe: number;
  requestedByMe: number;
}

/** A cooling-off reducing the caller's own authority (VTI-APV-019). */
export interface CoolingOffAgainstMe {
  actionId: string;
  requester: string;
  landsAt: string;
}

/** The list response's `ext["org.openvtc"]` — computed over every action, not
 *  only the page, so the shell's banners can read it off the badge's read. */
export interface ActionsListExt {
  /** Action ids of operator writes waiting for the caller's acknowledgement. */
  operatorWritesUnacknowledged?: string[];
  coolingOffAgainstMe?: CoolingOffAgainstMe[];
  /** Whether the community runs in single-administrator mode (VTI-APV-022)
   *  — reported to every administrator in every session while it does. */
  singleAdminMode?: boolean;
}

export interface ActionsListResponse {
  actions: Action[];
  counts: ActionCounts;
  nextCursor?: string;
  ext?: { "org.openvtc"?: ActionsListExt };
}

/** What the shell shows outside the Actions page: the badge count and the
 *  two Critical banners. */
export interface ActionsAttention {
  waiting: number;
  operatorWritesUnacknowledged: string[];
  coolingOffAgainstMe: CoolingOffAgainstMe[];
  /** Single-administrator mode is in effect (VTI-APV-022). */
  singleAdminMode: boolean;
}

/** Whether `action` is an operator's offline write (VTI-VTC-023). */
export function isAcknowledgeItem(action: Action): boolean {
  return action.category === "acknowledge";
}

/** How `action`'s consent was waived, if single-administrator mode let it
 *  through (VTI-APV-022). */
export function consentWaivedOf(action: Action): ConsentWaived | null {
  const w = actionExt(action).consentWaived;
  return w && typeof w.requirement === "string" ? w : null;
}

/** The cooling-off `action` waits out, if it is one (VTI-APV-019): a 0.2
 *  `coolingOff` action and its top-level `landsAt`. */
export function coolingOffOf(action: Action): CoolingOff | null {
  if (action.category !== "coolingOff" || typeof action.landsAt !== "string") return null;
  const subject = action.summary?.fields?.subject?.value;
  return {
    landsAt: action.landsAt,
    ...(typeof subject === "string" ? { subject } : {}),
    againstYou: action.callerRole === "subject",
    cancellableByMe:
      action.status === "open" &&
      action.callerRole === "requester" &&
      action.cancellableBy === "requester",
  };
}

/** The readable command an operator's offline write ran, by its
 *  `vtc/operator/offline-write/0.1` `command`. */
export const OPERATOR_COMMAND_TEXT: Readonly<Record<string, string>> = Object.freeze({
  aclAdd: "vtc acl add",
  aclRemove: "vtc acl remove",
  adminInvite: "vtc admin invite",
  createDidKeyAdmin: "vtc create-did-key --admin",
  enrolApprover: "vtc admin enrol-approver",
  emergencyBootstrap: "vtc admin emergency-bootstrap",
});

/** The command an operator's offline write ran, readable, or `null`. */
export function operatorCommandOf(action: Action): string | null {
  const command = (action.payload as { command?: unknown }).command;
  if (typeof command !== "string") return null;
  return OPERATOR_COMMAND_TEXT[command] ?? command;
}

export interface ActionsListQuery {
  view: ActionsView;
  /** 1..100, default 25. */
  limit?: number;
  cursor?: string;
  /** `history` only. */
  since?: string;
}

export type DecisionStatus = "granted" | "pending" | "denied";

export interface DecisionResponse {
  status: DecisionStatus;
  payloadDigest: string;
  approvals?: number;
  needed?: number;
  actionId: string;
  ext?: {
    "org.openvtc"?: { actionStatus?: "completed" | "failed"; closedMessage?: string };
  };
}

/** `decision/0.2`'s `evidence` member — an additional factor, never the proof. */
export interface WebauthnEvidence {
  kind: "webauthn";
  assertion: unknown;
}

export type { ApproverSignedEvidence };

/** Either kind of decision evidence. */
export type DecisionEvidence = WebauthnEvidence | ApproverSignedEvidence;

/** The action's own `ext["org.openvtc"]`, or `{}`. */
export function actionExt(action: Action): ActionExt {
  return action.ext?.["org.openvtc"] ?? {};
}

// ── Reads + cancel (console key) ────────────────────────────────────

export function listActions(query: ActionsListQuery): Promise<ActionsListResponse> {
  const payload: Record<string, unknown> = { view: query.view };
  if (query.limit !== undefined) payload.limit = query.limit;
  if (query.cursor) payload.cursor = query.cursor;
  if (query.since && query.view === "history") payload.since = query.since;
  return postSignedRead<ActionsListResponse>(ACTIONS_LIST_TASK, payload);
}

/** How many actions wait for this administrator — the badge. */
export async function fetchWaitingCount(): Promise<number> {
  return (await fetchActionsAttention()).waiting;
}

/**
 * The badge count and the list's ext, from one `waitingForMe` read of one
 * row: the ext covers every action regardless of the page.
 */
export async function fetchActionsAttention(): Promise<ActionsAttention> {
  const body = await listActions({ view: "waitingForMe", limit: 1 });
  const ext = body.ext?.["org.openvtc"] ?? {};
  return {
    waiting: body.counts?.waitingForMe ?? 0,
    operatorWritesUnacknowledged: Array.isArray(ext.operatorWritesUnacknowledged)
      ? ext.operatorWritesUnacknowledged.filter((id) => typeof id === "string")
      : [],
    coolingOffAgainstMe: Array.isArray(ext.coolingOffAgainstMe)
      ? ext.coolingOffAgainstMe.filter(
          (c) => !!c && typeof c.actionId === "string" && typeof c.landsAt === "string",
        )
      : [],
    singleAdminMode: ext.singleAdminMode === true,
  };
}

export async function showAction(actionId: string): Promise<Action> {
  return (await postSignedRead<{ action: Action }>(ACTIONS_SHOW_TASK, { actionId })).action;
}

/** Withdraw one of your own open actions. The console key may sign this. */
export async function cancelAction(actionId: string, reason?: string): Promise<Action> {
  const trimmed = reason?.trim();
  const payload: Record<string, unknown> = { actionId };
  if (trimmed) payload.reason = trimmed.slice(0, MAX_REASON_LEN);
  return (await postSignedTrustTask<{ action: Action }>(ACTIONS_CANCEL_TASK, payload)).action;
}

/**
 * Record that you have seen an operator's offline write (VTI-VTC-023). It is
 * already in effect; acknowledging changes nothing. The console key may sign
 * this, as it may a read or a cancel.
 */
export async function acknowledgeAction(actionId: string): Promise<Action> {
  return (await postSignedTrustTask<{ action: Action }>(ACTIONS_ACKNOWLEDGE_TASK, { actionId }))
    .action;
}

// ── Deciding (the approver's own DID, through the wallet) ───────────

/** Whether this browser can sign a decision as the administrator. */
export function canDecideHere(): boolean {
  return isWalletSigningAvailable();
}

/** What to run instead when there is no wallet. */
export function cnmApproveCommand(actionId: string): string {
  return `cnm consent approve --action ${actionId}`;
}

export function cnmDenyCommand(actionId: string): string {
  return `cnm consent deny --action ${actionId} --reason "..."`;
}

export const NO_WALLET_MESSAGE =
  "Approving needs your own DID's signature. Use: cnm consent approve --action <actionId>";

/**
 * Run a passkey ceremony over the decision's challenge and return it as
 * `evidence`. The challenge is the UTF-8 bytes of `action.challenge`; user
 * verification is required, as for a step-up. No `rpId` is passed, so the
 * browser uses this origin's — the one the console's passkeys are registered
 * under.
 */
export async function passkeyEvidence(
  challenge: string,
  credentials: Pick<CredentialsContainer, "get"> = navigator.credentials,
): Promise<WebauthnEvidence> {
  const publicKey: PublicKeyCredentialRequestOptions = {
    challenge: new TextEncoder().encode(challenge),
    userVerification: "required",
  };
  const credential = (await credentials.get({ publicKey })) as PublicKeyCredential | null;
  if (!credential) throw new Error("the passkey ceremony returned no credential");
  return { kind: "webauthn", assertion: serializeAssertion(credential) };
}

export interface DecideArgs {
  action: Action;
  decision: "approve" | "deny";
  /** The signed-in administrator's DID — the proof must name it. */
  approverDid: string;
  reason?: string;
  evidence?: DecisionEvidence;
}

/** Build the `decision/0.2` payload for `args` (exported for its test). */
export async function decisionPayload(args: DecideArgs): Promise<Record<string, unknown>> {
  const { action } = args;
  if (!action.challenge) {
    throw new Error("This action is not waiting for your decision.");
  }
  const payload: Record<string, unknown> = {
    challenge: action.challenge,
    payloadDigest: await wireDigest(action.typeUri, action.payload, action.challenge),
    decision: args.decision,
    actionId: action.actionId,
  };
  const reason = args.reason?.trim();
  if (reason) payload.reason = reason.slice(0, MAX_REASON_LEN);
  if (args.evidence) payload.evidence = args.evidence;
  return payload;
}

/**
 * Approve or decline `action`, signed as `approverDid` through the wallet.
 * Never the console key: a delegated key is not an approver.
 */
export async function decideAction(args: DecideArgs): Promise<DecisionResponse> {
  if (!canDecideHere()) throw new Error(NO_WALLET_MESSAGE.replace("<actionId>", args.action.actionId));
  return sendDecision(await decisionPayload(args), args.approverDid);
}

/** Sign `payload` as `approverDid` through the wallet and send it. */
async function sendDecision(
  payload: Record<string, unknown>,
  approverDid: string,
): Promise<DecisionResponse> {
  const unsigned = await addressedDocument(DECISION_TASK, payload, approverDid);
  const signed = await signWithWallet({ ...unsigned }, approverDid);
  return postSignedDocument<DecisionResponse>(signed as unknown as SignedTrustTaskDocument);
}

// ── Deciding with the approver device ───────────────────────────────

/**
 * Whether the signed-in administrator can answer a decision here with their
 * step-up **approver device**: the wallet plugin exposes `approveDecision`,
 * and `auth/step-up/approver/list/0.1` (the caller's own, console-key read)
 * lists at least one live approver. When the plugin also says which approver
 * it holds for this VTC (`approverIdentity`), that one must be among them —
 * an approver bound from another browser cannot answer from this one.
 */
export async function approverDeviceHere(): Promise<boolean> {
  if (!isWalletDecisionApproverAvailable()) return false;
  const { approvers } = await fetchApprovers();
  if (!Array.isArray(approvers) || approvers.length === 0) return false;
  let held: string | null = null;
  try {
    held = await walletApproverIdentity(await vtcDid());
  } catch {
    held = null;
  }
  return held === null || approvers.some((a) => a.approverDid === held);
}

/**
 * The decision payload with the approver device's `approverSigned` evidence.
 *
 * The payload is built once ([`decisionPayload`]) and the very same values —
 * challenge, the salted wire `payloadDigest`, decision, trimmed reason,
 * actionId — are what `approveDecision` is shown, so the wallet recognises the
 * `signTrustTask` that follows as the decision it approved and does not prompt
 * again. Throws when the plugin declined, was dismissed or answered with
 * something else; nothing has been sent then.
 */
export async function approverDecisionPayload(
  args: Omit<DecideArgs, "evidence">,
): Promise<Record<string, unknown>> {
  const payload = await decisionPayload(args);
  const { action } = args;
  const decision: {
    challenge: string;
    payloadDigest: string;
    decision: "approve" | "deny";
    reason?: string;
  } = {
    challenge: payload.challenge as string,
    payloadDigest: payload.payloadDigest as string,
    decision: args.decision,
  };
  if (typeof payload.reason === "string") decision.reason = payload.reason;
  const { statement } = await approveDecisionWithWallet({
    audience: await vtcDid(),
    subject: args.approverDid,
    action: {
      type: action.typeUri,
      payload: action.payload,
      actionId: action.actionId,
      summary: action.summary,
    },
    decision,
  });
  const evidence: ApproverSignedEvidence = { kind: "approverSigned", statement };
  return { ...payload, evidence };
}

/** Approve or decline `action` with the approver device's evidence, signed as
 *  `approverDid` through the wallet. */
export async function decideWithApproverDevice(
  args: Omit<DecideArgs, "evidence">,
): Promise<DecisionResponse> {
  return sendDecision(await approverDecisionPayload(args), args.approverDid);
}

/** Send a payload [`approverDecisionPayload`] prepared, unchanged. */
export function sendPreparedDecision(
  payload: Record<string, unknown>,
  approverDid: string,
): Promise<DecisionResponse> {
  return sendDecision(payload, approverDid);
}

/** The sentence a decision's answer is reported with. */
export function describeDecision(resp: DecisionResponse): string {
  const ext = resp.ext?.["org.openvtc"];
  if (ext?.closedMessage) return ext.closedMessage;
  switch (resp.status) {
    case "granted":
      return ext?.actionStatus === "failed"
        ? "Approved, but the action failed when it ran."
        : "Approved — the action has completed.";
    case "pending":
      return resp.approvals !== undefined && resp.needed !== undefined
        ? `Approved — ${resp.approvals} of ${resp.needed} approvals so far.`
        : "Approved — waiting for further approvals.";
    case "denied":
      return "Declined — the action is closed.";
  }
}

/** The refusal code without its task prefix. */
function codeTail(e: unknown): string | null {
  const code = (e as ApiError | null)?.code;
  if (typeof code !== "string") return null;
  return code.slice(code.lastIndexOf(":") + 1);
}

/** What to tell an approver whose decision failed. */
export function explainDecisionError(e: unknown): string {
  if ((e as Error | null)?.name === "NotAllowedError") {
    return "The passkey prompt was dismissed or timed out.";
  }
  switch (codeTail(e)) {
    case "noPending":
      return "This action is no longer waiting for a decision — it has closed or expired. Refresh to see where it stands.";
    case "challengeMismatch":
      return "This action changed since it was loaded. Refresh and check it again before deciding.";
    case "notAnApprover":
      return "You are not one of the administrators who can approve this action.";
    case "requesterExcluded":
      return "You raised this action, so you cannot approve it — another administrator has to.";
    case "actionMismatch":
      return "The decision did not match this action. Refresh and try again.";
    case "evidenceInvalid":
      return "The VTC did not accept the confirmation (passkey or approver device). Try again, or send the decision without it.";
    case "unavailable":
    case "rateLimited":
      return "Too many decisions in a short time (at most 10 a minute). Wait a moment and try again.";
    default:
      return (e as Error | null)?.message ?? String(e);
  }
}

/** What to tell a requester whose cancel failed. */
export function explainCancelError(e: unknown): string {
  switch (codeTail(e)) {
    case "notFound":
      return "That action no longer exists.";
    case "notRequester":
      return "Only the administrator who raised an action can cancel it.";
    case "notOpen":
      return "That action has already closed.";
    default:
      return (e as Error | null)?.message ?? String(e);
  }
}

/** Whether `e` says the caller had already acknowledged the item — not a
 *  failure: the earlier acknowledgement stands. */
export function isAlreadyAcknowledged(e: unknown): boolean {
  return codeTail(e) === "alreadyAcknowledged";
}

/** What to tell an administrator whose acknowledgement failed. */
export function explainAcknowledgeError(e: unknown): string {
  switch (codeTail(e)) {
    case "notFound":
      return "That item no longer exists.";
    case "notAcknowledgeable":
      return "This is not an operator's change waiting for your acknowledgement.";
    case "alreadyAcknowledged":
      return "You have already acknowledged this; your earlier acknowledgement stands.";
    default:
      return (e as Error | null)?.message ?? String(e);
  }
}

/** What to tell an administrator whose list or show failed. */
export function explainReadError(e: unknown): string {
  switch (codeTail(e)) {
    case "notAdministrator":
      return "Only community administrators can see the action list.";
    case "notFound":
      return "That action does not exist, or is no longer kept.";
    case "invalidCursor":
      return "The list changed while it was being paged. Reload it.";
    case "invalidFilter":
      return "The VTC did not accept that filter.";
    default:
      return (e as Error | null)?.message ?? String(e);
  }
}

// ── Countdowns ──────────────────────────────────────────────────────

/** "2 d 4 h", "3 h 10 m" or "12 m" for a positive span of `ms`. */
function span(ms: number): string {
  const minutes = Math.floor(ms / 60_000);
  const days = Math.floor(minutes / 1440);
  const hours = Math.floor((minutes % 1440) / 60);
  const mins = minutes % 60;
  if (days > 0) return `${days} d${hours ? ` ${hours} h` : ""}`;
  if (hours > 0) return `${hours} h${mins ? ` ${mins} m` : ""}`;
  return `${Math.max(mins, 1)} m`;
}

/** "expires in 2 d 4 h", from now until `expiresAt`. */
export function timeLeft(expiresAt: string, now: number = Date.now()): string {
  const ms = Date.parse(expiresAt) - now;
  if (Number.isNaN(ms)) return expiresAt;
  if (ms <= 0) return "expired";
  return `expires in ${span(ms)}`;
}

/** "lands in 2 d 4 h", from now until a cooling-off's `landsAt`; "landing
 *  now" once it is due (the VTC runs it on its next sweep). */
export function landsIn(landsAt: string, now: number = Date.now()): string {
  const ms = Date.parse(landsAt) - now;
  if (Number.isNaN(ms)) return landsAt;
  if (ms <= 0) return "landing now";
  return `lands in ${span(ms)}`;
}
