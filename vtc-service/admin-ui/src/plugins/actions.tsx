// Actions — the administrator action list
// (docs/05-design-notes/vtc-action-list.md §7.2).
//
// Three tabs: what waits for *you*, what *you* asked for, and what has closed.
// Every card's summary is re-derived from the action's payload and refused
// outright when it does not match (`lib/action-summary.ts`, VTI-APV-011/-013).
//
// Approving or declining signs a `task-consent/decision/0.2` as **your own
// DID** through the wallet; the console key is never used for it, and with no
// wallet the card shows the `cnm` command instead (`lib/actions-api.ts`).
// Evidence beside that proof, in order of preference: your step-up approver
// device (the VTA browser plugin's `approveDecision`), else a console passkey
// on approve, else none.
//
// `?action=<id>` shows one action (`vtc/admin/actions/show`) — where a parked
// act's success notice links, and where a completed invite's install URL and
// claim code, or a new administrator's approver invite, are shown to its
// requester.
//
// Two further shapes share the cards: an operator's offline write
// (`category: acknowledge`, VTI-VTC-023), Critical, with an Acknowledge button
// signed by the console key like cancel; and a cooling-off (`category:
// coolingOff`, VTI-APV-019) — no threshold, no expiry — that lands by itself
// at `landsAt` unless its requester cancels it, and that its subject
// (`callerRole: subject`) can see but not block.

import { useEffect, useState } from "react";
import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useSearchParams } from "react-router-dom";
import { AlertTriangle, RefreshCw } from "lucide-react";

import { CopyButton } from "@/components/CopyButton";
import { NamedDid } from "@/components/NamedDid";
import {
  SUMMARY_REFUSED_MESSAGE,
  SummaryRefusal,
  matchCode,
  verifySummary,
  type VerifiedSummary,
} from "@/lib/action-summary";
import { WAITING_COUNT_KEY } from "@/lib/action-badge";
import {
  MAX_REASON_LEN,
  acknowledgeAction,
  actionExt,
  approverDecisionPayload,
  approverDeviceHere,
  canDecideHere,
  cancelAction,
  coolingOffOf,
  consentWaivedOf,
  explainAcknowledgeError,
  isAcknowledgeItem,
  isAlreadyAcknowledged,
  type ApproverInviteResult,
  cnmApproveCommand,
  cnmDenyCommand,
  decideAction,
  decisionLabels,
  describeDecision,
  isQueueItem,
  explainCancelError,
  explainDecisionError,
  explainReadError,
  listActions,
  operatorCommandOf,
  passkeyEvidence,
  landsIn,
  sendPreparedDecision,
  showAction,
  timeLeft,
  type Action,
  type ActionsView,
  type ClosedReason,
  type WebauthnEvidence,
} from "@/lib/actions-api";
import { formatIso } from "@/lib/format";
import { useNameBook, type NameBook } from "@/lib/names";
import { useToast } from "@/lib/toast";
import { useConfirm } from "@/components/ConfirmDialog";
import { useViewerAmr, useViewerDid } from "@/lib/viewer";

const TABS: { view: ActionsView; label: string }[] = [
  { view: "waitingForMe", label: "Waiting for me" },
  { view: "requestedByMe", label: "Requested by me" },
  { view: "history", label: "History" },
];

const PAGE_SIZE = 25;

/** Every query this page reads, for invalidation after a change. */
const ACTIONS_KEY = ["actions"] as const;

export function Actions() {
  const [params, setParams] = useSearchParams();
  const actionId = params.get("action");
  const tab = (params.get("tab") as ActionsView | null) ?? "waitingForMe";
  const view = TABS.some((t) => t.view === tab) ? tab : "waitingForMe";

  if (actionId) {
    return (
      <section className="page">
        <h2>Actions</h2>
        <p>
          <Link to="/actions">Back to all actions</Link>
        </p>
        <ActionDetail actionId={actionId} />
      </section>
    );
  }

  return (
    <section className="page">
      <h2>Actions</h2>
      <p className="lead">
        Changes to who holds authority here wait for other administrators to
        approve them. Each one completes by itself once enough have. A change the
        operator made offline is already in effect and waits only for each
        administrator to acknowledge it.
      </p>
      <ActionList view={view} onView={(v) => setParams({ tab: v })} />
    </section>
  );
}

function ActionList({ view, onView }: { view: ActionsView; onView: (v: ActionsView) => void }) {
  const query = useInfiniteQuery({
    queryKey: [...ACTIONS_KEY, "list", view],
    queryFn: ({ pageParam }) =>
      listActions({ view, limit: PAGE_SIZE, ...(pageParam ? { cursor: pageParam } : {}) }),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (last) => last.nextCursor ?? undefined,
  });
  const counts = query.data?.pages[0]?.counts;
  const actions = query.data?.pages.flatMap((p) => p.actions) ?? [];

  return (
    <>
      <div className="action-tabs" role="tablist" aria-label="Action lists">
        {TABS.map((t) => {
          const count =
            t.view === "waitingForMe"
              ? counts?.waitingForMe
              : t.view === "requestedByMe"
                ? counts?.requestedByMe
                : undefined;
          return (
            <button
              key={t.view}
              type="button"
              role="tab"
              aria-selected={view === t.view}
              className={view === t.view ? "on" : ""}
              onClick={() => onView(t.view)}
            >
              {t.label}
              {count !== undefined && count > 0 && (
                <span className="nav-badge" aria-label={`${count} open`}>
                  {count}
                </span>
              )}
            </button>
          );
        })}
        <button
          type="button"
          className="link"
          onClick={() => void query.refetch()}
          disabled={query.isFetching}
          aria-label="Refresh"
          title="Refresh"
        >
          <span className="button-icon" aria-hidden="true">
            <RefreshCw />
          </span>
        </button>
      </div>

      {query.error && (
        <section className="card error">
          <h3>Could not load the actions</h3>
          <p>{explainReadError(query.error)}</p>
        </section>
      )}
      {query.isPending && <p className="lead">Loading…</p>}
      {!query.isPending && !query.error && actions.length === 0 && (
        <p className="lead">{emptyText(view)}</p>
      )}

      <div className="action-list">
        {actions.map((a) => (
          <ActionCard key={a.actionId} action={a} />
        ))}
      </div>

      {query.hasNextPage && (
        <button
          type="button"
          className="secondary"
          onClick={() => void query.fetchNextPage()}
          disabled={query.isFetchingNextPage}
        >
          {query.isFetchingNextPage ? "Loading…" : "Load more"}
        </button>
      )}
    </>
  );
}

function emptyText(view: ActionsView): string {
  switch (view) {
    case "waitingForMe":
      return "Nothing is waiting for your approval.";
    case "requestedByMe":
      return "You have no open requests.";
    default:
      return "No closed actions are kept yet.";
  }
}

function ActionDetail({ actionId }: { actionId: string }) {
  // `show` returns a completed invite's install URL and claim code once, so
  // the answer is kept for the life of the page rather than refetched.
  const query = useQuery({
    queryKey: [...ACTIONS_KEY, "show", actionId],
    queryFn: () => showAction(actionId),
    staleTime: Infinity,
    refetchOnMount: false,
  });
  if (query.isPending) return <p className="lead">Loading…</p>;
  if (query.error) {
    return (
      <section className="card error">
        <h3>Could not load the action</h3>
        <p>{explainReadError(query.error)}</p>
      </section>
    );
  }
  return <ActionCard action={query.data} detail />;
}

// ── One card ────────────────────────────────────────────────────────

type SummaryState =
  | { state: "checking" }
  | { state: "ok"; summary: VerifiedSummary }
  | { state: "refused"; refusal: SummaryRefusal };

function useVerifiedSummary(action: Action): SummaryState {
  const [state, setState] = useState<SummaryState>({ state: "checking" });
  useEffect(() => {
    let cancelled = false;
    setState({ state: "checking" });
    void verifySummary({
      kind: action.kind,
      typeUri: action.typeUri,
      payload: action.payload,
      summary: action.summary,
      payloadDigest: action.payloadDigest ?? "",
    }).then((out) => {
      if (cancelled) return;
      setState(
        out instanceof SummaryRefusal
          ? { state: "refused", refusal: out }
          : { state: "ok", summary: out },
      );
    });
    return () => {
      cancelled = true;
    };
  }, [action]);
  return state;
}

export function ActionCard({ action, detail = false }: { action: Action; detail?: boolean }) {
  const summary = useVerifiedSummary(action);
  const book = useNameBook();
  const ext = actionExt(action);
  const code = matchCode(action.payloadDigest);
  const open = action.status === "open";
  const ack = isAcknowledgeItem(action);
  const cooling = coolingOffOf(action);
  const waived = consentWaivedOf(action);

  return (
    <article
      className={`card action-card${ack ? " action-critical" : ""}`}
      aria-label={`Action ${action.actionId}`}
    >
      {ack && (
        <p className="action-severity">
          <span className="chip danger">Critical</span>{" "}
          <strong>The operator changed access control offline</strong>
        </p>
      )}
      {waived && (
        <p className="action-severity">
          <span className="chip warning">Consent waived</span>{" "}
          <strong>Single-administrator mode</strong> — nobody but the requester could consent,
          so their passkey gesture bound to this operation authorized it ({waived.requirement},
          VTI-APV-022).
        </p>
      )}
      {summary.state === "checking" && <p className="lead">Checking this action…</p>}
      {summary.state === "refused" && (
        <section className="card error" role="alert">
          <h3>Summary refused</h3>
          <p>{SUMMARY_REFUSED_MESSAGE}</p>
        </section>
      )}
      {summary.state === "ok" && <SummaryView summary={summary.summary} />}

      <dl className="action-facts">
        <dt>Code</dt>
        <dd>
          <code className="action-code">Code: {code ?? "unavailable"}</code>
        </dd>
        {ack ? (
          <>
            {/* The operator acts as the community: the requester is the
                VTC's own DID (VTI-VTC-023). */}
            <dt>Written by</dt>
            <dd>
              The operator, acting as the community (<NamedDid book={book} did={action.requester} />)
            </dd>
            {operatorCommandOf(action) && (
              <>
                <dt>Command</dt>
                <dd>
                  <code>{operatorCommandOf(action)}</code>
                </dd>
              </>
            )}
            <dt>Recorded</dt>
            <dd>{formatIso(action.createdAt)}</dd>
            <dt>Acknowledged by</dt>
            <dd>
              {action.approvals.length === 0 ? "Nobody yet" : <ApprovalList action={action} book={book} />}
            </dd>
            {open && action.approversRemaining !== undefined && (
              <>
                <dt>Still to acknowledge</dt>
                <dd>
                  {action.approversRemaining} administrator
                  {action.approversRemaining === 1 ? "" : "s"}
                </dd>
              </>
            )}
          </>
        ) : (
          <>
            <dt>Requested by</dt>
            <dd>
              <NamedDid book={book} did={action.requester} />
            </dd>
            <dt>Created</dt>
            <dd>{formatIso(action.createdAt)}</dd>
            {waived ? (
              <>
                <dt>Approvals</dt>
                <dd>None — consent waived by single-administrator mode.</dd>
              </>
            ) : isQueueItem(action) ? (
              <>
                <dt>Decision</dt>
                <dd>
                  One administrator holding what it is about decides it, either way. It does not
                  expire: it waits here until someone does.
                  {action.approvals.length > 0 && <ApprovalList action={action} book={book} />}
                </dd>
              </>
            ) : cooling ? (
              <>
                <dt>Approvals</dt>
                <dd>
                  None needed — nobody but the requester and the administrator it reduces
                  can consent to it.
                </dd>
              </>
            ) : (
              <>
                <dt>Approvals</dt>
                <dd>
                  {action.threshold !== undefined
                    ? `${action.approvals.length} of ${action.threshold}`
                    : action.approvals.length}
                  {action.approvals.length > 0 && <ApprovalList action={action} book={book} />}
                </dd>
              </>
            )}
            {open && cooling && (
              <>
                <dt>Cooling-off</dt>
                <dd>
                  Lands by itself at <strong>{formatIso(cooling.landsAt)}</strong> unless{" "}
                  <NamedDid book={book} did={action.requester} /> cancels it.
                </dd>
                <dt>Lands</dt>
                <dd className="action-countdown">{landsIn(cooling.landsAt)}</dd>
              </>
            )}
            {open && !cooling && action.expiresAt && (
              <>
                <dt>Time left</dt>
                <dd>{timeLeft(action.expiresAt)}</dd>
              </>
            )}
            {open && action.requesterOpenActions !== undefined && (
              <>
                <dt>Requester's open actions</dt>
                <dd>{action.requesterOpenActions}</dd>
              </>
            )}
          </>
        )}
        {!open && <ClosedFacts action={action} book={book} />}
      </dl>

      {open && cooling?.againstYou && (
        <p className="action-burst" role="note">
          <span className="button-icon" aria-hidden="true">
            <AlertTriangle />
          </span>
          This is against you: it reduces your own authority, and you cannot approve or block
          it. Only <NamedDid book={book} did={action.requester} /> can stop it, by cancelling
          it before {formatIso(cooling.landsAt)}.
        </p>
      )}

      {ext.burst && (
        <p className="action-burst" role="status">
          <span className="button-icon" aria-hidden="true">
            <AlertTriangle />
          </span>
          The requester raised {ext.requesterRecentActions ?? "several"} actions in the last 10
          minutes. Check each one carefully.
        </p>
      )}

      {action.status === "completed" && action.callerRole === "requester" && ext.result && (
        <ActionResult result={ext.result} />
      )}

      {action.status === "completed" &&
        action.callerRole === "requester" &&
        ext.approverInvite && <ApproverInviteView invite={ext.approverInvite} />}

      {ack ? (
        <AcknowledgeButton action={action} summaryOk={summary.state === "ok"} />
      ) : (
        <ActionButtons action={action} summaryOk={summary.state === "ok"} />
      )}

      {!detail && (
        <p className="action-link">
          <Link to={`/actions?action=${encodeURIComponent(action.actionId)}`}>Open</Link>
        </p>
      )}
    </article>
  );
}

function SummaryView({ summary }: { summary: VerifiedSummary }) {
  return (
    <div className="action-summary">
      <p className="action-title">
        <strong>{summary.title}</strong>
      </p>
      {summary.effect && <p className="action-effect">{summary.effect}</p>}
      {summary.fields.length > 0 && (
        <dl className="action-fields">
          {summary.fields.map((f) => (
            <div key={f.name}>
              <dt>{f.name}</dt>
              <dd>{f.format === "did" ? <code>{f.text}</code> : f.text}</dd>
            </div>
          ))}
        </dl>
      )}
    </div>
  );
}

const CLOSED_REASON_TEXT: Record<ClosedReason, string> = {
  thresholdMet: "Enough administrators approved",
  declined: "An administrator declined",
  expired: "It expired before enough approved",
  cancelledByRequester: "The requester cancelled it",
  invalidated: "Something it depended on changed",
  failedRecheck: "It no longer passed its checks when it ran",
  acknowledged: "Every administrator acknowledged it",
  landedAfterCoolingOff: "It landed after its cooling-off, uncancelled",
};

function ApprovalList({ action, book }: { action: Action; book: NameBook }) {
  return (
    <ul className="action-approvers">
      {action.approvals.map((a) => (
        <li key={a.subject}>
          <NamedDid book={book} did={a.subject} /> <small>{formatIso(a.at)}</small>
        </li>
      ))}
    </ul>
  );
}

/**
 * The step-up approver invite for the administrator a completed grant made,
 * shown to its requester once: the VTC drops it after this `show`.
 */
function ApproverInviteView({ invite }: { invite: ApproverInviteResult }) {
  return (
    <section className="card success" aria-label="Approver invite for the new administrator">
      <h3>Approver invite for the new administrator</h3>
      <p>
        <strong>Shown once.</strong> The new administrator enrols a step-up approver with this
        invite. Send them the link and the claim code by <strong>separate channels</strong> —
        the link by one (email, chat), the code by another (in person, a call, a different
        messenger). Either alone is useless.
      </p>
      <dl className="action-fields">
        <div>
          <dt>Invite link</dt>
          <dd>
            <code>{invite.url}</code> <CopyButton value={invite.url} label="Copy invite link" />
          </dd>
        </div>
        <div>
          <dt>Claim code</dt>
          <dd>
            <code>{invite.claimCode}</code>{" "}
            <CopyButton value={invite.claimCode} label="Copy claim code" />
          </dd>
        </div>
        <div>
          <dt>Expires</dt>
          <dd>{formatIso(invite.expiresAt)}</dd>
        </div>
      </dl>
    </section>
  );
}

// ── Acknowledging an operator's offline write (VTI-VTC-023) ─────────

function AcknowledgeButton({ action, summaryOk }: { action: Action; summaryOk: boolean }) {
  const qc = useQueryClient();
  const toast = useToast();
  const ext = actionExt(action);

  const acknowledge = useMutation({
    mutationFn: () => acknowledgeAction(action.actionId),
    onSuccess: () => {
      toast.push("success", "Acknowledged — your acknowledgement is recorded.");
    },
    onError: (err) => {
      // Not a failure: an acknowledgement from another tab or device stands.
      if (isAlreadyAcknowledged(err)) {
        toast.push("info", explainAcknowledgeError(err));
        return;
      }
      toast.push("error", explainAcknowledgeError(err));
    },
    onSettled: () => {
      void qc.invalidateQueries({ queryKey: ACTIONS_KEY });
      void qc.invalidateQueries({ queryKey: WAITING_COUNT_KEY });
    },
  });

  if (action.status !== "open") return null;
  if (ext.acknowledgedByMe || (acknowledge.isSuccess && !acknowledge.isPending)) {
    return (
      <p className="action-acknowledged" role="status">
        You have acknowledged this.
      </p>
    );
  }
  if (action.callerRole !== "acknowledger") return null;
  if (!summaryOk) return null;
  return (
    <div className="action-buttons">
      <p>
        This change is already in effect. Acknowledging records that you have seen it, and
        changes nothing.
      </p>
      <div className="form-actions">
        <button
          type="button"
          className="primary"
          disabled={acknowledge.isPending}
          aria-busy={acknowledge.isPending}
          onClick={() => acknowledge.mutate()}
        >
          {acknowledge.isPending ? "Signing…" : "Acknowledge"}
        </button>
      </div>
    </div>
  );
}

const STATUS_CHIP: Record<Action["status"], string> = {
  open: "accent",
  completed: "success",
  declined: "danger",
  expired: "warning",
  cancelled: "warning",
  failed: "danger",
};

function ClosedFacts({ action, book }: { action: Action; book: NameBook }) {
  const ext = actionExt(action);
  return (
    <>
      <dt>Outcome</dt>
      <dd>
        <span className={`chip ${STATUS_CHIP[action.status]}`}>{action.status}</span>
      </dd>
      {action.closedReason && (
        <>
          <dt>Why it closed</dt>
          <dd>
            {consentWaivedOf(action)
              ? "Consent waived — single-administrator mode (VTI-APV-022)"
              : isQueueItem(action) && action.closedReason === "thresholdMet"
                ? `Decided: ${decisionLabels(action).approve}`
                : isQueueItem(action) && action.closedReason === "declined"
                  ? `Decided: ${decisionLabels(action).decline}`
                  : (CLOSED_REASON_TEXT[action.closedReason] ?? action.closedReason)}
          </dd>
        </>
      )}
      {ext.closedMessage && (
        <>
          <dt>Message</dt>
          <dd>{ext.closedMessage}</dd>
        </>
      )}
      {ext.closedBy && (
        <>
          <dt>Closed by</dt>
          <dd>
            <NamedDid book={book} did={ext.closedBy} />
          </dd>
        </>
      )}
      {action.closedAt && (
        <>
          <dt>Closed</dt>
          <dd>{formatIso(action.closedAt)}</dd>
        </>
      )}
    </>
  );
}

/** A completed act's result, shown to its requester (an invite's URL + code). */
function ActionResult({ result }: { result: Record<string, unknown> }) {
  const entries = Object.entries(result).filter(
    ([, v]) => typeof v === "string" || typeof v === "number" || typeof v === "boolean",
  );
  if (entries.length === 0) return null;
  return (
    <section className="card success">
      <h3>Result</h3>
      <p>Shown once. Copy what you need now.</p>
      <dl className="action-fields">
        {entries.map(([k, v]) => (
          <div key={k}>
            <dt>{k}</dt>
            <dd>
              <code>{String(v)}</code> <CopyButton value={String(v)} label={`Copy ${k}`} />
            </dd>
          </div>
        ))}
      </dl>
    </section>
  );
}

// ── Deciding + cancelling ───────────────────────────────────────────

function ActionButtons({ action, summaryOk }: { action: Action; summaryOk: boolean }) {
  const qc = useQueryClient();
  const toast = useToast();
  const confirm = useConfirm();
  const approverDid = useViewerDid();
  const amr = useViewerAmr();
  const [declining, setDeclining] = useState(false);
  const [cancelling, setCancelling] = useState(false);
  const [reason, setReason] = useState("");

  const refresh = () => {
    void qc.invalidateQueries({ queryKey: ACTIONS_KEY });
    void qc.invalidateQueries({ queryKey: WAITING_COUNT_KEY });
  };

  // Whether this administrator holds a step-up approver device this browser's
  // plugin can answer a decision with (`approverDeviceHere`). Asked only of an
  // action waiting for this caller's decision, and only when the plugin has
  // `approveDecision` at all; a failed read counts as "no device".
  const decidable = !!action.challenge && canDecideHere();
  const device = useQuery({
    queryKey: [...ACTIONS_KEY, "approver-device", approverDid],
    queryFn: async () => {
      try {
        return await approverDeviceHere();
      } catch {
        return false;
      }
    },
    enabled: decidable,
    staleTime: 60_000,
  });

  const decide = useMutation({
    mutationFn: async (args: { decision: "approve" | "deny"; reason?: string }) => {
      if (!approverDid) throw new Error("No signed-in administrator to sign as.");
      const base = {
        action,
        decision: args.decision,
        approverDid,
        ...(args.reason ? { reason: args.reason } : {}),
      };
      // (a) The approver device: the plugin's approver signs an
      // `approverSigned` statement over this decision (approve or decline),
      // and the wallet then signs the identical payload without a second
      // prompt. If it does not complete, say so and let the administrator
      // choose to go on without it — never downgrade silently.
      if (device.data) {
        let prepared: Record<string, unknown> | null = null;
        try {
          prepared = await approverDecisionPayload(base);
        } catch {
          const without = await confirm({
            title: "Approver device not confirmed",
            message:
              "Your step-up approver device did not confirm this decision. Send it without the approver device, or cancel and try again.",
            confirmLabel: "Send without approver device",
            cancelLabel: "Cancel",
          });
          if (!without) return null;
        }
        if (prepared) return sendPreparedDecision(prepared, approverDid);
      }
      // (b) A console passkey, on approve only: the assertion over the
      // decision's challenge, as `webauthn` evidence.
      let evidence: WebauthnEvidence | undefined;
      if (args.decision === "approve" && amr?.includes("passkey")) {
        try {
          evidence = await passkeyEvidence(action.challenge!);
        } catch {
          // Evidence is an additional factor, never the proof: the operator
          // may retry (cancel and press Approve again) or send without it.
          const without = await confirm({
            title: "Passkey not confirmed",
            message:
              "The passkey confirmation did not complete. Send the approval signed by your DID alone, or cancel and try the passkey again.",
            confirmLabel: "Send without passkey",
            cancelLabel: "Cancel",
          });
          if (!without) return null;
        }
      }
      // (c) The wallet signature alone. (d) With no wallet there is no
      // button at all: the card shows the `cnm` commands.
      return decideAction({ ...base, ...(evidence ? { evidence } : {}) });
    },
    onSuccess: (resp) => {
      if (!resp) return;
      toast.push(resp.status === "denied" ? "info" : "success", describeDecision(resp));
      setDeclining(false);
      setReason("");
      refresh();
    },
    onError: (err) => toast.push("error", explainDecisionError(err)),
  });

  const cancel = useMutation({
    mutationFn: (why: string) => cancelAction(action.actionId, why),
    onSuccess: () => {
      toast.push("success", "Cancelled — the action is closed.");
      setCancelling(false);
      setReason("");
      refresh();
    },
    onError: (err) => toast.push("error", explainCancelError(err)),
  });

  // A cooling-off says outright who may cancel it (`cancellableBy`); any other
  // open action of yours you may withdraw. A cooling-off's subject never can.
  const cooling = coolingOffOf(action);
  // A queue item is decided, never withdrawn — not even by the party it is
  // about (`vtc-action-list.md` §8.2).
  const canCancel =
    action.callerRole === "requester" &&
    action.status === "open" &&
    !isQueueItem(action) &&
    (action.category !== "coolingOff" || !!cooling?.cancellableByMe);
  if (!action.challenge && !canCancel) return null;

  const busy = decide.isPending || cancel.isPending || (decidable && device.isPending);
  // What each answer does: a grants review re-affirms or withdraws; a queue
  // item runs the operation that always decided it (ratify / revoke, approve
  // / reject, keep the member / start removal).
  const labels = decisionLabels(action);
  const approveLabel = labels.approve;
  const declineLabel = labels.decline;

  return (
    <div className="action-buttons">
      {action.challenge && !canDecideHere() && (
        <div className="action-cnm" role="note">
          <p>
            Approving needs your own DID's signature, and this browser has no
            wallet to make it. Use:
          </p>
          <pre>
            <code>{cnmApproveCommand(action.actionId)}</code>
          </pre>
          <p>or, to decline:</p>
          <pre>
            <code>{cnmDenyCommand(action.actionId)}</code>
          </pre>
        </div>
      )}

      {action.challenge && canDecideHere() && !declining && (
        <div className="form-actions">
          {summaryOk && (
            <button
              type="button"
              className="primary"
              disabled={busy}
              aria-busy={decide.isPending}
              onClick={() => decide.mutate({ decision: "approve" })}
            >
              {decide.isPending ? "Signing…" : approveLabel}
            </button>
          )}
          <button
            type="button"
            className="secondary destructive"
            disabled={busy}
            onClick={() => {
              setCancelling(false);
              setDeclining(true);
            }}
          >
            {declineLabel}
          </button>
        </div>
      )}

      {declining && (
        <ReasonForm
          label={labels.declineReason}
          required={labels.declineReasonRequired}
          submitLabel={decide.isPending ? "Signing…" : `Send: ${declineLabel}`}
          busy={busy}
          reason={reason}
          onReason={setReason}
          onSubmit={() => decide.mutate({ decision: "deny", reason })}
          onCancel={() => {
            setDeclining(false);
            setReason("");
          }}
        />
      )}

      {canCancel && !cancelling && !declining && (
        <div className="form-actions">
          <button
            type="button"
            className="secondary"
            disabled={busy}
            onClick={() => setCancelling(true)}
          >
            Cancel request
          </button>
        </div>
      )}

      {cancelling && (
        <ReasonForm
          label="Reason (optional)"
          submitLabel={cancel.isPending ? "Cancelling…" : "Cancel this action"}
          busy={busy}
          reason={reason}
          onReason={setReason}
          onSubmit={() => cancel.mutate(reason)}
          onCancel={() => {
            setCancelling(false);
            setReason("");
          }}
        />
      )}
    </div>
  );
}

function ReasonForm(props: {
  label: string;
  required?: boolean;
  submitLabel: string;
  busy: boolean;
  reason: string;
  onReason: (v: string) => void;
  onSubmit: () => void;
  onCancel: () => void;
}) {
  const empty = props.reason.trim().length === 0;
  return (
    <form
      className="action-reason"
      onSubmit={(e) => {
        e.preventDefault();
        if (props.required && empty) return;
        props.onSubmit();
      }}
    >
      <label className="field">
        <span className="field-label">{props.label}</span>
        <textarea
          rows={3}
          maxLength={MAX_REASON_LEN}
          value={props.reason}
          onChange={(e) => props.onReason(e.target.value)}
        />
      </label>
      <div className="form-actions">
        <button type="button" className="secondary" onClick={props.onCancel} disabled={props.busy}>
          Back
        </button>
        <button
          type="submit"
          className="primary"
          disabled={props.busy || (props.required && empty)}
        >
          {props.submitLabel}
        </button>
      </div>
    </form>
  );
}

// The countdowns live with the wire shapes so the shell banners can use them.
export { landsIn, timeLeft };
