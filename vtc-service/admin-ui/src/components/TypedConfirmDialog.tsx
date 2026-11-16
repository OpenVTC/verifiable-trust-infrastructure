// A confirmation that must be typed, for the one act the console makes
// deliberately awkward: removing an administrator now, without the
// cooling-off, in single-administrator mode (vtc-action-list.md §8.5).
//
// The confirm button stays disabled until what was typed matches; the VTC
// checks it again, and then asks for a passkey gesture bound to the immediate
// removal. Same a11y contract as `ConfirmDialog` (`useModal`): modal, Tab
// trapped, Escape and the scrim cancel, focus starts in the input and returns
// to the opener.

import { ReactNode, useRef, useState } from "react";

import { Field } from "@/components/Field";
import { Protected } from "@/components/Protected";
import { useModal } from "@/components/useModal";

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

function TypedConfirmDialogSurface(props: TypedConfirmProps) {
  const [typed, setTyped] = useState("");
  const inputRef = useRef<HTMLInputElement>(null);
  const surfaceRef = useRef<HTMLDivElement>(null);
  const ok = props.matches(typed);
  // The shared modal contract (#2610): focus starts in the input, Tab stays
  // inside — the page behind holds the very controls this dialog guards —
  // Escape and the scrim cancel unless a send is in flight, and focus goes
  // back to the opener on close.
  const dismiss = useModal(surfaceRef, props.onCancel, {
    locked: props.busy,
    initialFocus: inputRef,
  });

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
          <Field label={props.prompt}>
            <input
              ref={inputRef}
              aria-label={props.prompt}
              value={typed}
              autoComplete="off"
              spellCheck={false}
              onChange={(e) => setTyped(e.target.value)}
            />
          </Field>
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

/** TypedConfirmDialog, out of the community theme's reach (`vtc/community/theme/show/0.1`, client item 2). */
export function TypedConfirmDialog(props: Parameters<typeof TypedConfirmDialogSurface>[0]) {
  return (
    <Protected ground="none">
      <TypedConfirmDialogSurface {...props} />
    </Protected>
  );
}
