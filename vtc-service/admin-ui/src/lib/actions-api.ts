// The administrator action list — `vtc/admin/actions/{list,show,cancel}` and
// the approver's `task-consent/decision/0.2`
// (docs/05-design-notes/vtc-action-list.md §6, §7).
//
// Reads and cancel are signed with this browser's console key, like every
// other administrator read. A **decision** is not: an approval's proof is the
// approver's authorization, so it is signed by the approver's own DID through
// the wallet (`signTrustTask({asDid})`, the VTA holds the key) — exactly as
// `auth/signing-key/enroll/0.2`'s authorization is (`console-keys-api.ts`).
// The VTC refuses a decision signed by a delegated console key, so this module
// never offers one: with no wallet, the console shows the `cnm` command.

import {
  addressedDocument,
  postSignedDocument,
  postSignedRead,
  postSignedTrustTask,
  type ApiError,
} from "./api";
import { wireDigest } from "./action-summary";
import type { ActionSummaryWire } from "./action-summary";
import type { SignedTrustTaskDocument } from "./console-key";
import { ACTIONS_SHOW_TASK } from "./parked-action";
import { isWalletSigningAvailable, signWithWallet } from "./wallet";
import { serializeAssertion } from "./webauthn";

export const ACTIONS_LIST_TASK = "https://trusttasks.org/spec/vtc/admin/actions/list/0.1";
export { ACTIONS_SHOW_TASK };
export const ACTIONS_CANCEL_TASK = "https://trusttasks.org/spec/vtc/admin/actions/cancel/0.1";
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
  | "failedRecheck";

export type CallerRole = "approver" | "requester" | "observer";

export type ActionsView = "waitingForMe" | "requestedByMe" | "history" | "all";

export interface ActionApproval {
  subject: string;
  at: string;
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
}

export interface Action {
  actionId: string;
  category: "approval";
  kind: string;
  typeUri: string;
  requester: string;
  status: ActionStatus;
  createdAt: string;
  expiresAt: string;
  closedAt?: string;
  closedReason?: ClosedReason;
  approvals: ActionApproval[];
  approversRemaining?: number;
  callerRole: CallerRole;
  /** Present only when this caller may decide now. */
  challenge?: string;
  payload: Record<string, unknown>;
  payloadDigest: string;
  requesterOpenActions: number;
  threshold: number;
  summary: ActionSummaryWire;
  ext?: { "org.openvtc"?: ActionExt };
}

export interface ActionCounts {
  waitingForMe: number;
  requestedByMe: number;
}

export interface ActionsListResponse {
  actions: Action[];
  counts: ActionCounts;
  nextCursor?: string;
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
  const body = await listActions({ view: "waitingForMe", limit: 1 });
  return body.counts?.waitingForMe ?? 0;
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
  evidence?: WebauthnEvidence;
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
  const payload = await decisionPayload(args);
  const unsigned = await addressedDocument(DECISION_TASK, payload, args.approverDid);
  const signed = await signWithWallet({ ...unsigned }, args.approverDid);
  return postSignedDocument<DecisionResponse>(signed as unknown as SignedTrustTaskDocument);
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
      return "The VTC did not accept the passkey confirmation. Try again, or send the decision without it.";
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
