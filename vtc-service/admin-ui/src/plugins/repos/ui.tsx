// Small pieces the Repos screens share: where things live, status chips, the
// four-dot bootstrap indicator, and the dialog that hands a change to the
// administrator to sign.

import { useEffect, useRef, type ReactNode } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { KeyRound, ShieldAlert, SquareTerminal } from "lucide-react";

import { CopyButton } from "@/components/CopyButton";
import type { GitNsBootstrapStatus } from "@/lib/wire-types";

import { CONSENT_LABEL, documentPreview, type SignedTask } from "./actions";
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
    "Design §6 asks for a step-up and a confirmation here. A signed document carries no session to step up, so this VTC stands in for it with `elevated_requires_admin`: it accepts this only from a community administrator who also holds the right. Signing it is the confirmation.",
};

/**
 * The hand-over: a change the console has built, for the administrator to
 * sign. See `actions.ts` for why the console does not send it itself.
 *
 * Modal, with the same contract as the confirmation dialog: Escape and the
 * scrim close it, focus starts on the command's copy button (or Close), and
 * Tab stays inside while it is open.
 */
export function SignTaskDialog({
  task,
  onClose,
  children,
}: {
  task: SignedTask;
  onClose: () => void;
  /** Anything the flow adds under the command — the bind flow's next step. */
  children?: ReactNode;
}) {
  const surfaceRef = useRef<HTMLDivElement>(null);
  const queryClient = useQueryClient();

  useEffect(() => {
    surfaceRef.current?.querySelector<HTMLElement>("button")?.focus();
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.preventDefault();
        onClose();
        return;
      }
      if (e.key !== "Tab") return;
      const tabbable = surfaceRef.current?.querySelectorAll<HTMLElement>(
        "button:not([disabled]), a[href], summary, [tabindex]:not([tabindex='-1'])",
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

        <p>
          This is a signed <code>git-ns</code> Trust Task. It is authorized by the
          signer's own git rights, not by this session, and the console cannot sign
          one yet — so sign it as the community profile that holds the right.
        </p>

        {task.command ? (
          <div className="gitns-command">
            <span className="field-label">
              <SquareTerminal aria-hidden="true" size={14} /> Sign and send with cnm
            </span>
            <div className="gitns-command-row">
              <pre aria-label="Command">{task.command}</pre>
              <CopyButton value={task.command} label="Copy command" />
            </div>
          </div>
        ) : (
          <p className="muted">
            <code>cnm git</code> has no command for this task yet. Sign the document
            below with a Trust-Task client (<code>vtc-client</code>'s{" "}
            <code>git_ns_task</code>) and send it to <code>POST /v1/trust-tasks</code>.
          </p>
        )}

        <details className="gitns-doc" open={!task.command}>
          <summary>Document to sign</summary>
          <div className="gitns-command-row">
            <pre aria-label="Document">{doc}</pre>
            <CopyButton value={doc} label="Copy document" />
          </div>
        </details>

        {children}

        <div className="form-actions">
          <button type="button" className="secondary" onClick={onClose}>
            Close
          </button>
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
        </div>
      </div>
    </div>
  );
}
