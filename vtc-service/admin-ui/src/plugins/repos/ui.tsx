// Small pieces the Repos screens share: where things live, status chips, the
// four-dot bootstrap indicator, and the dialog that signs and sends a change —
// or hands it to the administrator where this browser cannot sign.

import { Fragment, useEffect, useRef, useState, type ReactNode, type RefObject } from "react";
import { Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Fingerprint, KeyRound, ShieldAlert, SquareTerminal, Siren, UserCheck } from "lucide-react";

import { CopyButton } from "@/components/CopyButton";
import { useSingleAdminMode } from "@/lib/action-badge";
import { signingAvailable, SigningUnavailableError } from "@/lib/api";
import { answerableAtAll, answerStepUp, operationOf } from "@/lib/bound-step-up";
import { useNameBook } from "@/lib/names";
import { useToast } from "@/lib/toast";
import type { GitNsBreakGlassMark, GitNsNamespaceRow, GitNsRepoRow } from "@/lib/wire-types";

import {
  CONSENT_LABEL,
  documentPreview,
  sendSigned,
  sendTask,
  type SignedTask,
  StepUpNeeded,
} from "./actions";
import { gitNsKeys } from "./api";
import {
  BOOTSTRAP_STEP_EXPLAINED,
  BREAK_GLASS_STATE_LABEL,
  bootstrapSteps,
  bootstrapView,
  bootstrapViewSummary,
  breakGlassState,
  type StepState,
  type GitNsSelfGrantWaived,
  type Tone,
} from "./model";

/** Where the plugin is mounted (`src/plugins/index.ts`). */
export const REPOS_PATH = "/repos";

/** A repository's page. The resource carries slashes, so it travels as one
 *  encoded segment rather than as a path the router would split. */
export const repoPath = (resource: string) =>
  `${REPOS_PATH}/repo/${encodeURIComponent(resource)}`;
export const namespacePath = (id: string) =>
  `${REPOS_PATH}?namespace=${encodeURIComponent(id)}`;
export const BIND_PATH = `${REPOS_PATH}/bind`;
export const DEPARTED_PATH = `${REPOS_PATH}/departed`;
/** Every break-glass record, and what is waiting for a decision. */
export const BREAK_GLASS_PATH = `${REPOS_PATH}/break-glass`;
export const memberPath = (did: string) => `/members/${encodeURIComponent(did)}`;
/** The ceremonies plugin opens a purpose's policy from `?purpose=`. */
export const POLICY_PATH = "/ceremonies?purpose=gitNamespace";

const CHIP: Record<Tone, string> = {
  success: "chip success",
  warning: "chip warning",
  danger: "chip danger",
  accent: "chip accent",
  neutral: "chip",
};

export function ToneChip({
  tone,
  title,
  children,
}: {
  tone: Tone;
  title?: string;
  children: ReactNode;
}) {
  return (
    <span className={CHIP[tone]} title={title}>
      {children}
    </span>
  );
}

/**
 * The flag every self-granted right carries wherever it is shown
 * (`git-ns/right/break-glass`): loud until another administrator ratifies or
 * revokes it, quiet history after.
 */
export function BreakGlassChip({ mark }: { mark: GitNsBreakGlassMark | null | undefined }) {
  const state = breakGlassState(mark);
  if (!mark || !state) return null;
  const title =
    state === "ratified"
      ? `Self-granted ${formatDay(mark.at)}, ratified ${formatDay(mark.ratifiedAt)}`
      : `Self-granted ${formatDay(mark.at)} — awaiting another administrator's ratification or revocation. Justification: ${mark.justification}`;
  return (
    <span className={state === "ratified" ? "chip" : "chip danger gitns-breakglass"} title={title}>
      <Siren aria-hidden="true" size={12} /> {BREAK_GLASS_STATE_LABEL[state]}
    </span>
  );
}

/**
 * The mark a right recorded under single-administrator mode's waiver of
 * separation of duties carries wherever it is shown (VTI-APV-022). Unlike a
 * break-glass it awaits nobody — there was nobody else — so it is a quiet
 * chip, with what happened on hover.
 */
export function SelfGrantWaivedChip({ mark }: { mark: GitNsSelfGrantWaived | null | undefined }) {
  if (!mark) return null;
  return (
    <span
      className="chip warning gitns-self-grant-waived"
      title={`Self-granted ${formatDay(mark.at)} under single-administrator mode: nobody else could grant it, so separation of duties was waived for this one operation, on the administrator's passkey, and recorded as a critical audit event.`}
    >
      <UserCheck aria-hidden="true" size={12} /> self-granted (single-admin)
    </span>
  );
}

/** Whether a task's answer says single-administrator mode waived separation
 *  of duties for it (`ext.org.openvtc.selfGrantWaived`). */
export function selfGrantWaivedIn(response: unknown): boolean {
  const ext = (response as { ext?: { "org.openvtc"?: { selfGrantWaived?: unknown } } } | null)?.ext;
  const w = ext?.["org.openvtc"]?.selfGrantWaived;
  return !!w && typeof w === "object";
}

/**
 * Shown where a form builds an elevated self-grant on a community in
 * single-administrator mode (VTI-APV-022): the console does not block it, the
 * VTC decides — it waives separation of duties only when nobody else could
 * make the grant, and refuses it (`git-ns:selfGrantNotAllowed`) otherwise.
 */
export function SingleAdminSelfGrantNotice() {
  return (
    <div className="finding warn gitns-single-admin-waiver" role="status">
      <strong>
        <UserCheck aria-hidden="true" size={14} /> Single-administrator mode: this self-grant
        will be waived, recorded as a critical audit event, and needs your passkey.
      </strong>
      <span className="muted">
        The VTC waives separation of duties only when nobody else could make this grant. If
        another administrator, or a member whose git rights cover it, could, it refuses — ask
        them instead. The record is marked as self-granted wherever it is listed.
      </span>
    </div>
  );
}

/** What the operator can do about a refusal the VTC gave, where the code says.
 *  `singleAdmin`: the community runs in single-administrator mode, where a
 *  self-grant is refused only because somebody else could make it. */
export function refusalHint(err: unknown, singleAdmin = false): string | null {
  const code = (err as { code?: unknown } | null)?.code;
  if (code === "git-ns:selfGrantNotAllowed" && singleAdmin) {
    return "Single-administrator mode waives separation of duties only when nobody else could make this grant — and here somebody else can: another administrator, or a member whose git rights cover it. Ask them to grant it. If nobody else can act in time, break the glass, which is recorded, announced and flagged until another administrator ratifies or revokes it.";
  }
  if (code === "git-ns:selfGrantNotAllowed") {
    return "Separation of duties: nobody grants themselves namespace admin, repo creator or owner. Ask another administrator to grant it — or, if nobody else can, break the glass, which is recorded, announced to every administrator and flagged until one of them ratifies or revokes it.";
  }
  if (code === "git-ns/right/break-glass:disabled") {
    return "This community's git-namespace policy does not allow break-glass here. Another administrator must grant the right.";
  }
  if (code === "git-ns/right/ratify:recordChanged") {
    return "The break-glass changed since this page read it. Reload and read its justification again before ratifying.";
  }
  return null;
}

export function formatDay(iso: string | null | undefined): string {
  if (!iso) return "—";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleDateString();
}

/** The code of a signed read's refusal, where the answer was a
 *  `trust-task-error` document. */
function errorCode(err: unknown): string | undefined {
  if (err && typeof err === "object" && "code" in err) {
    const code = (err as { code: unknown }).code;
    if (typeof code === "string") return code;
  }
  return undefined;
}

/**
 * The daemon refused an administrator's read (`git-ns/namespace/list`,
 * `git-ns/repo/list`, `git-ns/view` with `scope: administrator`) because
 * this DID administers no namespace it covers — or, from an older daemon's
 * bearer view, a 403.
 */
export function isNotAdministrator(err: unknown): boolean {
  return errorStatus(err) === 403 || (errorCode(err)?.endsWith(":notAdministrator") ?? false);
}

export function errorMessage(err: unknown): string {
  if (err instanceof SigningUnavailableError) {
    return "these reads are signed, and this browser cannot sign yet — enable console signing on the Console keys page";
  }
  if (errorCode(err)?.endsWith(":notAdministrator")) {
    return "shown to a namespace's administrators — a community administrator, or git.ns.admin on the namespace — and this session's DID is neither";
  }
  if (errorCode(err)?.endsWith(":notCommunityAdministrator")) {
    return "only a community administrator (an admin not limited to some contexts) can read this";
  }
  if (err && typeof err === "object" && "message" in err) {
    const message = (err as { message: unknown }).message;
    if (typeof message === "string" && message) return message;
  }
  return String(err);
}

export function errorStatus(err: unknown): number | undefined {
  if (err && typeof err === "object" && "status" in err) {
    const status = (err as { status: unknown }).status;
    if (typeof status === "number") return status;
  }
  return undefined;
}

/**
 * Why a read failed, for the reads a scoped administrator cannot make.
 *
 * `git-ns/right/list`, `git-ns/right/issued-by-departed`,
 * `git-ns/projection/show` and `git-ns/account/list` need the
 * community-administrator capability — an admin whose access is not limited
 * to some contexts — because they span every namespace; each is refused with
 * its own `:notCommunityAdministrator`, which [`errorMessage`] already turns
 * into this same copy. The `errorStatus(err) === 403` branch is dead against
 * this daemon and stays only for a bearer 403 during a rolling upgrade past
 * an older one that answered these as REST.
 */
export function readErrorMessage(err: unknown): string {
  if (errorStatus(err) === 403) {
    return "only a community administrator (an admin not limited to some contexts) can read this";
  }
  return errorMessage(err);
}

const STEP_STATE_LABEL: Record<StepState, string> = {
  done: "in place",
  missing: "missing",
  failed: "failed",
  notApplicable: "not applicable",
};

/**
 * Workflow · keyring · variables · required check, as four dots: filled in
 * place, hollow missing, dashed not used by this repository's setup, red
 * failed.
 *
 * Shape as well as colour carries the state, the group carries a label naming
 * every step's state, and each dot its own title saying what the step is and
 * why it stands where it does — so it survives a screen reader and a
 * colour-blind reader alike.
 */
export function BootstrapDots({ ns, repo }: { ns: GitNsNamespaceRow; repo: GitNsRepoRow }) {
  const steps = bootstrapView(ns, repo);
  return (
    <span className="gitns-dots" role="img" aria-label={bootstrapViewSummary(steps)}>
      {steps.map((s) => (
        <span
          key={s.key}
          className={`gitns-dot ${s.state}`}
          title={`${s.label}: ${STEP_STATE_LABEL[s.state]}. ${s.why}\n\n${BOOTSTRAP_STEP_EXPLAINED[s.key]}`}
        />
      ))}
    </span>
  );
}

/** What the dots mean, beside the table that shows them. */
export function BootstrapLegend() {
  const steps = bootstrapSteps({ workflow: false, keyring: false, variables: false, requiredCheck: false });
  return (
    <span className="gitns-legend gitns-small" aria-label="Commit trust legend">
      <span className="muted">Commit trust, in order:</span>{" "}
      {steps.map((s, i) => (
        <span key={s.key} title={BOOTSTRAP_STEP_EXPLAINED[s.key]} className="gitns-legend-step">
          {i + 1}. {s.label.toLowerCase()}
        </span>
      ))}
      <span className="gitns-legend-key">
        <span className="gitns-dot done" aria-hidden="true" /> in place
      </span>
      <span className="gitns-legend-key">
        <span className="gitns-dot missing" aria-hidden="true" /> missing
      </span>
      <span className="gitns-legend-key">
        <span className="gitns-dot notApplicable" aria-hidden="true" /> not applicable
      </span>
      <span className="gitns-legend-key">
        <span className="gitns-dot failed" aria-hidden="true" /> failed
      </span>
    </span>
  );
}

const CONSENT_MEANS: Record<SignedTask["consent"], string> = {
  normal: "Authorized by the signer's git rights alone.",
  elevated:
    "Design §6 asks for a step-up here. A signed document carries no session to step up, so this VTC stands in for it with `elevated_requires_admin`: it accepts this only from a community administrator who also holds the right.",
  destructive:
    "Design §6 asks for a step-up and a confirmation here. A signed document carries no session to step up, so this VTC stands in for it with `elevated_requires_admin`: it accepts this only from a community administrator who also holds the right.",
};

/** Where an operator enables signing in this browser (`plugins/index.ts`). */
export const CONSOLE_KEYS_PATH = "/console-keys";

/**
 * The modal contract every Repos dialog keeps, as the confirmation dialog
 * does: focus moves in on open (the first field or button), Tab and Shift-Tab
 * stay inside, Escape closes — unless `locked`, while something is in flight —
 * and focus goes back to whatever opened the dialog when it closes.
 */
export function useModal(
  surfaceRef: RefObject<HTMLElement | null>,
  onClose: () => void,
  locked = false,
) {
  const lockedRef = useRef(locked);
  lockedRef.current = locked;
  const closeRef = useRef(onClose);
  closeRef.current = onClose;

  useEffect(() => {
    const opener = document.activeElement as HTMLElement | null;
    surfaceRef.current
      ?.querySelector<HTMLElement>("select, input, textarea, button")
      ?.focus();
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.preventDefault();
        if (!lockedRef.current) closeRef.current();
        return;
      }
      if (e.key !== "Tab") return;
      const tabbable = surfaceRef.current?.querySelectorAll<HTMLElement>(
        "button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), a[href], summary, [tabindex]:not([tabindex='-1'])",
      );
      if (!tabbable || tabbable.length === 0) return;
      const first = tabbable[0]!;
      const last = tabbable[tabbable.length - 1]!;
      if (e.shiftKey && document.activeElement === first) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && document.activeElement === last) {
        e.preventDefault();
        first.focus();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => {
      window.removeEventListener("keydown", onKey);
      if (opener && opener.isConnected) opener.focus();
    };
  }, [surfaceRef]);

  /** For the scrim: a click on it closes, unless locked. */
  return () => {
    if (!lockedRef.current) closeRef.current();
  };
}

/**
 * A change the console has built, to sign and send from this browser — or,
 * where it cannot sign, to hand to the administrator. See `actions.ts`.
 *
 * Who the change is about and what it acts on are in the body, named and in
 * full, before anything can be signed: the collapsed command is not where an
 * operator should discover whose DID they are about to grant ownership to.
 * A destructive task needs its confirmation box ticked before it sends, and
 * the dialog cannot be dismissed while a send is in flight.
 */
export function SignTaskDialog({
  task,
  onClose,
  onSent,
  onHandedOff,
  children,
}: {
  task: SignedTask;
  onClose: () => void;
  /** Called with the task's `#response` payload after the VTC accepts it.
   *  Without it, the dialog closes and the screen refreshes. */
  onSent?: (response: Record<string, unknown>) => void;
  /** Called when the operator says they sent it from a terminal. Without it,
   *  the dialog closes and the screen refreshes. */
  onHandedOff?: () => void;
  /** Anything the flow adds under the hand-over — the bind flow's next step. */
  children?: ReactNode;
}) {
  const surfaceRef = useRef<HTMLDivElement>(null);
  const queryClient = useQueryClient();
  const toast = useToast();
  const book = useNameBook();
  const [confirmed, setConfirmed] = useState(false);
  // A create on a personal account answers with the steps only the account
  // holder can take; those stay on screen rather than vanish with the dialog.
  const [manualSteps, setManualSteps] = useState<string[] | null>(null);
  const canSign = useQuery({ queryKey: ["console-signing"], queryFn: signingAvailable });
  // Set when the VTC asked for a passkey gesture bound to the document it was
  // sent (`lib/bound-step-up.ts`). The confirmation is its own click: the
  // gesture is consent to the act the request names, taken with it on screen.
  const [stepUp, setStepUp] = useState<StepUpNeeded | null>(null);
  const accepted = (response: Record<string, unknown>) => {
    void queryClient.invalidateQueries({ queryKey: gitNsKeys.all });
    toast.push(
      "success",
      selfGrantWaivedIn(response)
        ? `${task.title}: accepted — single-administrator waiver applied`
        : `${task.title}: accepted`,
    );
    const steps = (response as { manualSteps?: unknown }).manualSteps;
    if (onSent) onSent(response);
    else if (Array.isArray(steps) && steps.length > 0) {
      setManualSteps(steps.filter((x): x is string => typeof x === "string"));
    } else onClose();
  };
  const send = useMutation({
    mutationFn: () => sendTask(task),
    onSuccess: accepted,
    onError: (e) => {
      if (e instanceof StepUpNeeded) setStepUp(e);
      // The key went away between opening and sending (forgotten in another
      // tab, storage cleared). Not a refusal: say so, and fall back to the
      // hand-over, which is below.
      if (e instanceof SigningUnavailableError) {
        void queryClient.invalidateQueries({ queryKey: ["console-signing"] });
      }
    },
  });
  // Answer the step-up, then send the *same* signed document again: the
  // gesture is bound to it, and a freshly signed one would be a second act.
  const confirm = useMutation({
    mutationFn: async (needed: StepUpNeeded) => {
      await answerStepUp(needed.request, undefined, operationOf(needed.signed));
      return sendSigned(needed.signed);
    },
    onSuccess: accepted,
    onError: (e) => {
      // The gesture lapsed before the re-send, or was spent: the VTC has
      // parked a fresh ceremony, so offer that one.
      if (e instanceof StepUpNeeded) setStepUp(e);
    },
  });
  const busy = send.isPending || confirm.isPending;
  const dismiss = useModal(surfaceRef, onClose, busy);

  const doc = documentPreview(task);
  const signing = canSign.data === true;
  const destructive = task.consent === "destructive";
  const unavailable = send.error instanceof SigningUnavailableError;
  const refusal = confirm.isError ? confirm.error : send.isError && !stepUp ? send.error : null;
  const singleAdmin = useSingleAdminMode();
  const hint = refusal ? refusalHint(refusal, singleAdmin) : null;

  return (
    <div
      className="confirm-scrim"
      onClick={(e) => {
        if (e.target === e.currentTarget) dismiss();
      }}
    >
      <div
        ref={surfaceRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby="gitns-sign-title"
        aria-busy={busy || undefined}
        className="confirm-dialog gitns-sign"
      >
        <h3 id="gitns-sign-title">{task.title}</h3>
        <p>{task.effect}</p>

        <dl className="gitns-parties">
          <dt>Resource</dt>
          <dd>
            <code>{task.resource}</code>
          </dd>
          {task.parties.map((p, i) => (
            <Fragment key={`${p.role}-${i}`}>
              <dt>{p.role}</dt>
              <dd>
                {book.nameOf(p.did) && <span className="gitns-party-name">{book.nameOf(p.did)}</span>}
                <code className="gitns-party-did">{p.did}</code>
              </dd>
            </Fragment>
          ))}
        </dl>

        <div className={`finding ${task.consent === "normal" ? "" : "warn"}`}>
          <strong>
            {task.consent === "normal" ? (
              <KeyRound aria-hidden="true" size={14} />
            ) : (
              <ShieldAlert aria-hidden="true" size={14} />
            )}{" "}
            Consent class: {CONSENT_LABEL[task.consent]}
          </strong>
          <span className="muted">{task.consentNote ?? CONSENT_MEANS[task.consent]}</span>
        </div>

        {task.singleAdminWaiver && <SingleAdminSelfGrantNotice />}

        {signing ? (
          <p>
            This browser holds a console signing key. Sending signs a{" "}
            <code>git-ns</code> Trust Task as you; the VTC authorizes it by your own
            git rights, not by this session.
          </p>
        ) : (
          <p>
            This is a signed <code>git-ns</code> Trust Task, authorized by the
            signer's own git rights.{" "}
            {canSign.isPending ? (
              "Checking whether this browser can sign…"
            ) : (
              <>
                This browser cannot sign one, so sign it as the community profile
                that holds the right — or{" "}
                <Link to={CONSOLE_KEYS_PATH}>enable signing in this browser</Link>.
              </>
            )}
          </p>
        )}

        {signing && destructive && !unavailable && (
          <label className="gitns-radio">
            <input
              type="checkbox"
              checked={confirmed}
              onChange={(e) => setConfirmed(e.target.checked)}
            />
            <span>I understand this is destructive and want to sign it.</span>
          </label>
        )}

        {stepUp && !confirm.isSuccess && (
          <div className="finding warn gitns-stepup" role="status">
            <strong>
              <Fingerprint aria-hidden="true" size={14} /> Confirm with your passkey
            </strong>
            <span>
              The VTC checked this and will act on it once you confirm, with a passkey
              registered to you, this one document. Nothing is elevated: the gesture is
              spent by this operation and nothing else.
            </span>
            <span>
              It asks: <q>{stepUp.request.reason}</q>
            </span>
            {stepUp.request.boundTo && (
              <span className="muted gitns-small">
                Bound to <code>{stepUp.request.boundTo}</code>
              </span>
            )}
            {!answerableAtAll(stepUp.request, operationOf(stepUp.signed)) && (
              <span>This console holds no passkey or step-up approver to answer that step-up with.</span>
            )}
          </div>
        )}

        {refusal &&
          (unavailable ? (
            <div className="finding warn" role="alert">
              <strong>This browser can no longer sign</strong>
              <span>
                {errorMessage(refusal)}. Nothing was sent. Sign it from a terminal
                instead, below.
              </span>
            </div>
          ) : (
            <div className="finding error" role="alert">
              <strong>
                {confirm.isError ? "The passkey confirmation did not go through" : "The VTC refused it"}
              </strong>
              <span>{errorMessage(refusal)}</span>
              {hint && <span>{hint}</span>}
            </div>
          ))}

        <details className="gitns-doc" open={(!signing && !canSign.isPending) || unavailable}>
          <summary>{signing ? "Or sign it from a terminal" : "Sign it from a terminal"}</summary>
          <div className="gitns-command">
            <span className="field-label">
              <SquareTerminal aria-hidden="true" size={14} /> cnm
            </span>
            <div className="gitns-command-row">
              <pre aria-label="Command">{task.command}</pre>
              <CopyButton value={task.command} label="Copy command" />
            </div>
            <span className="field-label">Document</span>
            <div className="gitns-command-row">
              <pre aria-label="Document">{doc}</pre>
              <CopyButton value={doc} label="Copy document" />
            </div>
          </div>
        </details>

        {children}

        {manualSteps && (
          <div className="finding ok" role="status">
            <strong>Reserved. The account holder finishes it:</strong>
            <ol className="gitns-steps-list">
              {manualSteps.map((step, i) => (
                <li key={i}>
                  <code>{step}</code>
                </li>
              ))}
            </ol>
          </div>
        )}

        <div className="form-actions">
          <button type="button" className="secondary" onClick={onClose} disabled={busy}>
            Close
          </button>
          {manualSteps ? null : stepUp && answerableAtAll(stepUp.request, operationOf(stepUp.signed)) ? (
            <button
              type="button"
              className="primary"
              disabled={busy}
              onClick={() => confirm.mutate(stepUp)}
            >
              {confirm.isPending ? "Waiting for your passkey…" : "Confirm with passkey and send"}
            </button>
          ) : signing && !unavailable ? (
            <button
              type="button"
              className={destructive ? "secondary destructive" : "primary"}
              disabled={send.isPending || (destructive && !confirmed)}
              onClick={() => send.mutate()}
            >
              {send.isPending ? "Sending…" : "Sign and send"}
            </button>
          ) : (
            <button
              type="button"
              className="primary"
              onClick={() => {
                void queryClient.invalidateQueries({ queryKey: gitNsKeys.all });
                if (onHandedOff) onHandedOff();
                else onClose();
              }}
            >
              I have sent it — refresh
            </button>
          )}
        </div>
      </div>
    </div>
  );
}
