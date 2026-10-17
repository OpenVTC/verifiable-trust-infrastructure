// Modal confirmation dialog. Replaces `window.confirm` across every
// plugin's destructive-action path. Hand-rolled (no Radix dep) but
// honours the same a11y contract:
//
// - Focus trap inside the dialog while open.
// - Escape closes (treated as cancel).
// - Click on the scrim closes.
// - Auto-focus the cancel button on open so a misclick on Enter
//   doesn't fire the destructive action.
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
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";

import { Protected, activeElementOf } from "@/components/Protected";

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

export function ConfirmDialogProvider({ children }: { children: ReactNode }) {
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
          <Dialog options={pending} onClose={close} />
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
}: {
  options: ConfirmOptions;
  onClose: (ok: boolean) => void;
}) {
  const cancelRef = useRef<HTMLButtonElement>(null);
  const confirmRef = useRef<HTMLButtonElement>(null);
  const surfaceRef = useRef<HTMLDivElement>(null);

  // Auto-focus the safer (cancel) button so an Enter keypress
  // doesn't fire the destructive action by accident.
  useEffect(() => {
    cancelRef.current?.focus();
  }, []);

  // Escape closes; treat as cancel. Trap Tab inside the dialog so
  // focus never escapes back to the underlying page while modal.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.preventDefault();
        onClose(false);
        return;
      }
      if (e.key !== "Tab") return;
      const surface = surfaceRef.current;
      if (!surface) return;
      const tabbable = surface.querySelectorAll<HTMLElement>(
        "button:not([disabled]), [tabindex]:not([tabindex='-1'])",
      );
      const first = tabbable[0];
      const last = tabbable[tabbable.length - 1];
      if (!first || !last) return;
      const active = activeElementOf(surface);
      if (e.shiftKey && active === first) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && active === last) {
        e.preventDefault();
        first.focus();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => {
      window.removeEventListener("keydown", onKey);
    };
  }, [onClose]);

  const confirmLabel = options.confirmLabel ?? "Confirm";
  const cancelLabel = options.cancelLabel ?? "Cancel";

  return (
    <div
      className="confirm-scrim"
      onClick={(e) => {
        // Only treat clicks *on the scrim itself* as a dismiss —
        // a click that bubbled up from inside the surface (e.g.
        // text-selection mouse-up that ends outside) shouldn't
        // close.
        if (e.target === e.currentTarget) onClose(false);
      }}
    >
      <div
        ref={surfaceRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby="confirm-dialog-title"
        className="confirm-dialog"
      >
        <h3 id="confirm-dialog-title">{options.title}</h3>
        {options.message && <p>{options.message}</p>}
        <div className="form-actions">
          <button
            ref={cancelRef}
            type="button"
            className="secondary"
            onClick={() => onClose(false)}
          >
            {cancelLabel}
          </button>
          <button
            ref={confirmRef}
            type="button"
            className={
              options.destructive ? "secondary destructive" : "primary"
            }
            onClick={() => onClose(true)}
          >
            {confirmLabel}
          </button>
        </div>
      </div>
    </div>
  );
}
