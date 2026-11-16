// Modal confirmation dialog. Replaces `window.confirm` across every
// plugin's destructive-action path. Hand-rolled (no Radix dep) but
// honours the same a11y contract (`useModal`, shared by every dialog):
//
// - Focus trap inside the dialog while open.
// - Escape closes (treated as cancel).
// - Click on the scrim closes.
// - Auto-focus the cancel button on open so a misclick on Enter
//   doesn't fire the destructive action.
// - Focus returns to the control that opened the dialog.
// - aria-modal + role="dialog" + aria-labelledby tying the heading
//   to the dialog.
//
// Usage:
//
// ```tsx
// const confirm = useConfirm();
// const ok = await confirm({
//   title: "Revoke session?",
//   message: "You'll be signed out of this tab.",
//   confirmLabel: "Revoke",
//   destructive: true,
// });
// if (ok) revokeMutation.mutate(id);
// ```
//
// One <ConfirmDialogProvider> wraps the App so the hook can reach
// the surface. The hook returns a promise that resolves when the
// operator picks one button, so calling code reads linearly.

import {
  createContext,
  ReactNode,
  useCallback,
  useContext,
  useId,
  useMemo,
  useRef,
  useState,
} from "react";

import { Protected } from "@/components/Protected";
import { useModal } from "@/components/useModal";

export interface ConfirmOptions {
  title: string;
  message?: ReactNode;
  confirmLabel?: string;
  cancelLabel?: string;
  /** Style the confirm button as destructive (red border + hover). */
  destructive?: boolean;
}

type Resolver = (ok: boolean) => void;

interface ConfirmCtx {
  request: (options: ConfirmOptions) => Promise<boolean>;
}

const Ctx = createContext<ConfirmCtx | null>(null);

/**
 * Which stylesheet the dialog is drawn with: the console's (`components.css`)
 * or the member portal's (`members.css`, `signin.css`), whose buttons are
 * `.btn`s. The portal bundle imports this component, not the console shell.
 */
export type ConfirmLook = "console" | "portal";

const BUTTONS: Record<ConfirmLook, { cancel: string; confirm: string; destructive: string }> = {
  console: { cancel: "secondary", confirm: "primary", destructive: "secondary destructive" },
  portal: { cancel: "btn btn-secondary", confirm: "btn btn-primary", destructive: "btn btn-danger" },
};

export function ConfirmDialogProvider({
  children,
  look = "console",
}: {
  children: ReactNode;
  look?: ConfirmLook;
}) {
  const [pending, setPending] = useState<
    (ConfirmOptions & { resolve: Resolver }) | null
  >(null);

  const request = useCallback(
    (options: ConfirmOptions) =>
      new Promise<boolean>((resolve) => {
        setPending({ ...options, resolve });
      }),
    [],
  );

  const close = useCallback(
    (ok: boolean) => {
      if (pending) {
        pending.resolve(ok);
        setPending(null);
      }
    },
    [pending],
  );

  const api = useMemo<ConfirmCtx>(() => ({ request }), [request]);

  return (
    <Ctx.Provider value={api}>
      {children}
      {pending && (
        // A destructive confirmation is drawn out of the theme's reach
        // (`vtc/community/theme/show/0.1`, client item 2).
        <Protected ground="none">
          <Dialog options={pending} onClose={close} look={look} />
        </Protected>
      )}
    </Ctx.Provider>
  );
}

export function useConfirm(): (options: ConfirmOptions) => Promise<boolean> {
  const ctx = useContext(Ctx);
  if (!ctx) {
    throw new Error("useConfirm must be used inside <ConfirmDialogProvider>");
  }
  return ctx.request;
}

function Dialog({
  options,
  onClose,
  look,
}: {
  options: ConfirmOptions;
  onClose: (ok: boolean) => void;
  look: ConfirmLook;
}) {
  const cancelRef = useRef<HTMLButtonElement>(null);
  const confirmRef = useRef<HTMLButtonElement>(null);
  const surfaceRef = useRef<HTMLDivElement>(null);
  const titleId = useId();

  // The shared modal contract (`useModal`): focus starts on the safer
  // (cancel) button so an Enter keypress doesn't fire the destructive
  // action by accident, Tab stays inside, Escape cancels, and focus goes
  // back to the control that opened the dialog when it closes (#2610).
  const dismiss = useModal(surfaceRef, () => onClose(false), { initialFocus: cancelRef });

  const confirmLabel = options.confirmLabel ?? "Confirm";
  const cancelLabel = options.cancelLabel ?? "Cancel";
  const buttons = BUTTONS[look];

  return (
    <div
      className="confirm-scrim"
      onClick={(e) => {
        // Only treat clicks *on the scrim itself* as a dismiss —
        // a click that bubbled up from inside the surface (e.g.
        // text-selection mouse-up that ends outside) shouldn't
        // close.
        if (e.target === e.currentTarget) dismiss();
      }}
    >
      <div
        ref={surfaceRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        className="confirm-dialog"
      >
        <h3 id={titleId}>{options.title}</h3>
        {options.message && <p>{options.message}</p>}
        <div className="form-actions">
          <button
            ref={cancelRef}
            type="button"
            className={buttons.cancel}
            onClick={() => onClose(false)}
          >
            {cancelLabel}
          </button>
          <button
            ref={confirmRef}
            type="button"
            className={options.destructive ? buttons.destructive : buttons.confirm}
            onClick={() => onClose(true)}
          >
            {confirmLabel}
          </button>
        </div>
      </div>
    </div>
  );
}
