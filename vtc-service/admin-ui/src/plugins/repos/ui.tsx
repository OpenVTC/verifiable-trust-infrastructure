// Small pieces the Repos screens share: where things live, status chips, the
// four-dot bootstrap indicator, and the dialog that signs and sends a change —
// or hands it to the administrator where this browser cannot sign.

import { useEffect, useRef, useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { KeyRound, ShieldAlert, SquareTerminal } from "lucide-react";

import { CopyButton } from "@/components/CopyButton";
import { signingAvailable } from "@/lib/api";
import { useToast } from "@/lib/toast";
import type { GitNsBootstrapStatus } from "@/lib/wire-types";

import { CONSENT_LABEL, documentPreview, sendTask, type SignedTask } from "./actions";
import { gitNsKeys } from "./api";
import { bootstrapSteps, bootstrapSummary, type Tone } from "./model";

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
 * A change the console has built, to sign and send from this browser — or,
 * where it cannot sign, to hand to the administrator. See `actions.ts`.
 *
 * Modal, with the confirmation dialog's contract: Escape and the scrim close
 * it, focus starts on the first control, and Tab stays inside while it is
 * open. A destructive task needs its confirmation box ticked before it sends.
 */
export function SignTaskDialog({
  task,
  onClose,
  onSent,
  children,
}: {
  task: SignedTask;
  onClose: () => void;
  /** Called with the task's `#response` payload after the VTC accepts it.
   *  Without it, the dialog closes and the screen refreshes. */
  onSent?: (response: Record<string, unknown>) => void;
  /** Anything the flow adds under the hand-over — the bind flow's next step. */
  children?: ReactNode;
}) {
  const surfaceRef = useRef<HTMLDivElement>(null);
  const queryClient = useQueryClient();
  const toast = useToast();
  const [confirmed, setConfirmed] = useState(false);
  // A create on a personal account answers with the steps only the account
  // holder can take; those stay on screen rather than vanish with the dialog.
  const [manualSteps, setManualSteps] = useState<string[] | null>(null);
  const canSign = useQuery({ queryKey: ["console-signing"], queryFn: signingAvailable });
  const send = useMutation({
    mutationFn: () => sendTask(task),
    onSuccess: (response) => {
      void queryClient.invalidateQueries({ queryKey: gitNsKeys.all });
      toast.push("success", `${task.title}: accepted`);
      const steps = (response as { manualSteps?: unknown }).manualSteps;
      if (onSent) onSent(response);
      else if (Array.isArray(steps) && steps.length > 0) {
        setManualSteps(steps.filter((x): x is string => typeof x === "string"));
      } else onClose();
    },
  });

  useEffect(() => {
    surfaceRef.current?.querySelector<HTMLElement>("button, input")?.focus();
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.preventDefault();
        onClose();
        return;
      }
      if (e.key !== "Tab") return;
      const tabbable = surfaceRef.current?.querySelectorAll<HTMLElement>(
        "button:not([disabled]), input:not([disabled]), a[href], summary, [tabindex]:not([tabindex='-1'])",
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
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  const doc = documentPreview(task);
  const signing = canSign.data === true;
  const destructive = task.consent === "destructive";

  return (
    <div
      className="confirm-scrim"
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div
        ref={surfaceRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby="gitns-sign-title"
        className="confirm-dialog gitns-sign"
      >
        <h3 id="gitns-sign-title">{task.title}</h3>
        <p>{task.effect}</p>

        <div className={`finding ${task.consent === "normal" ? "" : "warn"}`}>
          <strong>
            {task.consent === "normal" ? (
              <KeyRound aria-hidden="true" size={14} />
            ) : (
              <ShieldAlert aria-hidden="true" size={14} />
            )}{" "}
            Consent class: {CONSENT_LABEL[task.consent]}
          </strong>
          <span className="muted">{CONSENT_MEANS[task.consent]}</span>
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
            {canSign.isPending
              ? "Checking whether this browser can sign…"
              : <>
                  This browser cannot sign one, so sign it as the community profile
                  that holds the right — or{" "}
                  <Link to={CONSOLE_KEYS_PATH}>enable signing in this browser</Link>.
                </>}
          </p>
        )}

        {signing && destructive && (
          <label className="gitns-radio">
            <input
              type="checkbox"
              checked={confirmed}
              onChange={(e) => setConfirmed(e.target.checked)}
            />
            <span>I understand this is destructive and want to sign it.</span>
          </label>
        )}

        {send.isError && (
          <div className="finding error" role="alert">
            <strong>The VTC refused it</strong>
            <span>{errorMessage(send.error)}</span>
          </div>
        )}

        <details className="gitns-doc" open={!signing && !canSign.isPending}>
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
          <button type="button" className="secondary" onClick={onClose}>
            Close
          </button>
          {manualSteps ? null : signing ? (
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
                onClose();
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
