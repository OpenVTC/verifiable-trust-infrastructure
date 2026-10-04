// A confirmation that must be typed, for the one act the console makes
// deliberately awkward: removing an administrator now, without the
// cooling-off, in single-administrator mode (vtc-action-list.md §8.5).
//
// The confirm button stays disabled until what was typed matches; the VTC
// checks it again, and then asks for a passkey gesture bound to the immediate
// removal. Same a11y contract as `ConfirmDialog`: modal, Escape and the scrim
// cancel, focus starts in the input.

import { ReactNode, useEffect, useRef, useState } from "react";

export interface TypedConfirmProps {
  title: string;
  message: ReactNode;
  /** What the input asks for, e.g. "Type the subject's DID to confirm". */
  prompt: string;
  /** Whether `typed` is an accepted confirmation. */
  matches: (typed: string) => boolean;
  confirmLabel: string;
  busy?: boolean;
  onConfirm: (typed: string) => void;
  onCancel: () => void;
}

export function TypedConfirmDialog(props: TypedConfirmProps) {
  const [typed, setTyped] = useState("");
  const inputRef = useRef<HTMLInputElement>(null);
  const ok = props.matches(typed);

  useEffect(() => {
    inputRef.current?.focus();
  }, []);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.preventDefault();
        props.onCancel();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [props]);

  return (
    <div
      className="confirm-scrim"
      onClick={(e) => {
        if (e.target === e.currentTarget) props.onCancel();
      }}
    >
      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby="typed-confirm-title"
        className="confirm-dialog"
      >
        <h3 id="typed-confirm-title">{props.title}</h3>
        <div>{props.message}</div>
        <form
          onSubmit={(e) => {
            e.preventDefault();
            if (ok && !props.busy) props.onConfirm(typed.trim());
          }}
        >
          <label className="field">
            <span className="field-label">{props.prompt}</span>
            <input
              ref={inputRef}
              aria-label={props.prompt}
              value={typed}
              autoComplete="off"
              spellCheck={false}
              onChange={(e) => setTyped(e.target.value)}
            />
          </label>
          <div className="form-actions">
            <button type="button" className="secondary" onClick={props.onCancel}>
              Cancel
            </button>
            <button
              type="submit"
              className="secondary destructive"
              disabled={!ok || props.busy}
            >
              {props.confirmLabel}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
