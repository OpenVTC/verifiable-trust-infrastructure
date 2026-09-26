// Small pieces the Repos screens share: where things live, status chips, the
// four-dot bootstrap indicator, and the dialog that signs and sends a change —
// or hands it to the administrator where this browser cannot sign.

import { Fragment, useEffect, useRef, useState, type ReactNode, type RefObject } from "react";
import { Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Fingerprint, KeyRound, ShieldAlert, SquareTerminal, Siren } from "lucide-react";

import { CopyButton } from "@/components/CopyButton";
import { signingAvailable, SigningUnavailableError } from "@/lib/api";
import { answerableHere, answerStepUp } from "@/lib/bound-step-up";
import { useNameBook } from "@/lib/names";
import { useToast } from "@/lib/toast";
import type { GitNsBootstrapStatus, GitNsBreakGlassMark } from "@/lib/wire-types";

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
  BREAK_GLASS_STATE_LABEL,
  bootstrapSteps,
  bootstrapSummary,
  breakGlassState,
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

/** What the operator can do about a refusal the VTC gave, where the code says. */
export function refusalHint(err: unknown): string | null {
  const code = (err as { code?: unknown } | null)?.code;
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

export function errorMessage(err: unknown): string {
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
 * Rights, drift, the registry mirror, linked accounts and the departed-grants
 * review need a *community* administrator — an admin session whose access is
 * not limited to some contexts — because they span every namespace. A 403
 * there is that, and saying so is more use than the daemon's bare refusal.
 */
export function readErrorMessage(err: unknown): string {
  if (errorStatus(err) === 403) {
    return "only a community administrator (an admin not limited to some contexts) can read this";
  }
  return errorMessage(err);
}

/**
 * Workflow · keyring · variables · required check, as four dots.
 *
 * Colour is never the only signal: the group carries a label naming what is
 * and is not in place, and each dot its own title, so the state survives a
 * screen reader and a colour-blind reader alike.
 */
export function BootstrapDots({ bootstrap }: { bootstrap: GitNsBootstrapStatus }) {
  return (
    <span className="gitns-dots" role="img" aria-label={bootstrapSummary(bootstrap)}>
      {bootstrapSteps(bootstrap).map((s) => (
        <span
          key={s.key}
          className={s.done ? "gitns-dot done" : "gitns-dot"}
          title={`${s.label}: ${s.done ? "in place" : "missing"}`}
        />
      ))}
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
    toast.push("success", `${task.title}: accepted`);
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
      await answerStepUp(needed.request);
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
  const hint = refusal ? refusalHint(refusal) : null;

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
            {!answerableHere(stepUp.request) && (
              <span>This console cannot answer that step-up with a passkey.</span>
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
          {manualSteps ? null : stepUp && answerableHere(stepUp.request) ? (
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
