// A consent-gated act the VTC accepted and parked as an administrator action
// (docs/05-design-notes/vtc-action-list.md §7.3).
//
// Making, widening or removing an unrestricted administrator, lowering the
// consent threshold and changing an authority policy all need the approval of
// other administrators (VTI-APV-014, -019, -020, VTI-VTC-022). Once the
// requester's own passkey step-up is answered, the VTC does not refuse such an
// act any more: it records it as an action on the Actions list and answers
// HTTP 202 with a `trust-task-next-step` document. The act completes on its
// own when the N-th approval lands; nobody re-sends anything.
//
// The signed door (`lib/api.ts` `postDocument`) recognises that reply and
// **throws** a [`ParkedAction`]. Thrown, not returned, deliberately: every
// caller of a gated write expects the operation's own response (`entry`,
// `applied`, `policy`), and a parked act has none — returning it as `T` would
// let a caller read `undefined` as a completed write (a `config/patch` would
// go on to `config/reload`, a policy upload to activation). It is still a
// success, so it is never shown as one: `toast.pushFromError` and
// `<ErrorOrParked>` render it as a success notice linking to the action.

/** The `type` of the VTC's reply to a parked act. */
export const NEXT_STEP_TYPE = "https://trusttasks.org/spec/trust-task-next-step/0.1";

/** The task the next-step reply names as what to do next. */
export const ACTIONS_SHOW_TASK = "https://trusttasks.org/spec/vtc/admin/actions/show/0.1";

/** Where the console shows one action. */
export function actionPath(actionId: string): string {
  return `/actions?action=${encodeURIComponent(actionId)}`;
}

interface NextStepPayload {
  continuation?: unknown;
  expects?: { typeUri?: unknown; hint?: { actionId?: unknown }; reason?: unknown }[];
  inResponseTo?: { id?: unknown; typeUri?: unknown };
  message?: unknown;
  ext?: { "org.openvtc"?: Record<string, unknown> };
}

const str = (v: unknown): string | undefined => (typeof v === "string" ? v : undefined);
const num = (v: unknown): number | undefined =>
  typeof v === "number" && Number.isFinite(v) ? v : undefined;

/**
 * The act was accepted and is waiting on other administrators' approval.
 * `message` is the VTC's own sentence ("Sent for approval — 1 of 2 …").
 */
export class ParkedAction extends Error {
  readonly actionId: string;
  readonly kind?: string;
  /** Approvals needed. */
  readonly threshold?: number;
  /** Administrators eligible to approve. */
  readonly approvers?: number;
  /** Approvals so far. */
  readonly approvals?: number;
  readonly expiresAt?: string;
  /** The task that was parked. */
  readonly typeUri?: string;

  constructor(fields: {
    actionId: string;
    message?: string;
    kind?: string;
    threshold?: number;
    approvers?: number;
    approvals?: number;
    expiresAt?: string;
    typeUri?: string;
  }) {
    super(fields.message ?? parkedSentence(fields));
    this.name = "ParkedAction";
    this.actionId = fields.actionId;
    this.kind = fields.kind;
    this.threshold = fields.threshold;
    this.approvers = fields.approvers;
    this.approvals = fields.approvals;
    this.expiresAt = fields.expiresAt;
    this.typeUri = fields.typeUri;
  }

  /** Where the console shows this action. */
  get path(): string {
    return actionPath(this.actionId);
  }
}

/** The notice when the VTC sent no `message` of its own. */
function parkedSentence(f: {
  threshold?: number;
  approvers?: number;
  expiresAt?: string;
}): string {
  const k = f.threshold;
  const n = f.approvers;
  const who =
    k !== undefined && n !== undefined
      ? ` — ${k} of ${n} unrestricted administrator(s) must approve`
      : "";
  const when = f.expiresAt ? ` before ${new Date(f.expiresAt).toLocaleString()}` : "";
  return `Sent for approval${who}${when}.`;
}

/**
 * The [`ParkedAction`] a reply document describes, or `null` when it is not a
 * next-step reply naming an action.
 */
export function parkedActionFromDocument(doc: unknown): ParkedAction | null {
  if (!doc || typeof doc !== "object") return null;
  const d = doc as { type?: unknown; payload?: unknown };
  if (d.type !== NEXT_STEP_TYPE) return null;
  const p = (d.payload ?? {}) as NextStepPayload;
  const ext = p.ext?.["org.openvtc"] ?? {};
  const expected = Array.isArray(p.expects)
    ? p.expects.find((e) => e?.typeUri === ACTIONS_SHOW_TASK)
    : undefined;
  const actionId = str(ext.actionId) ?? str(expected?.hint?.actionId);
  if (!actionId) return null;
  return new ParkedAction({
    actionId,
    message: str(p.message),
    kind: str(ext.kind),
    threshold: num(ext.threshold),
    approvers: num(ext.approvers),
    approvals: num(ext.approvals),
    expiresAt: str(ext.expiresAt),
    typeUri: str(p.inResponseTo?.typeUri),
  });
}

/** `e` as a [`ParkedAction`], or `null`. */
export function parkedOf(e: unknown): ParkedAction | null {
  return e instanceof ParkedAction ? e : null;
}
