// Toast/notification surface.
//
// One toaster instance lives at the App root. Any plugin (built-in
// or third-party) emits via `useToast().push(...)`. The same API is
// re-exported on `window.VtcPluginApi.toast` so script-tag plugins
// can fire toasts without importing this module.
//
// Toasts are intentionally simple: a list of (id, kind, message)
// rendered as a stack in the bottom-right. They auto-dismiss after
// `DEFAULT_DISMISS_MS` unless the kind is "error" (which sticks until
// the operator dismisses it manually — error context is worth
// reading carefully). The `pushFromError` helper extracts a clean
// message from our `ApiError` shape.

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

import type { ApiError } from "@/lib/api";
import { messageOf } from "@/lib/messages";
import { parkedOf } from "@/lib/parked-action";

export type ToastKind = "success" | "info" | "error";

/** A link a toast carries: `href` is a console path under `/admin`. */
export interface ToastLink {
  readonly href: string;
  readonly label: string;
}

export interface Toast {
  readonly id: number;
  readonly kind: ToastKind;
  readonly message: string;
  readonly link?: ToastLink;
  /** Shown on hover only: the HTTP status, which means nothing to most
   *  readers but helps whoever reports the problem (#2617). */
  readonly title?: string;
}

/** How a toast is shown, beyond its words. */
interface ToastOptions {
  readonly link?: ToastLink;
  readonly title?: string;
  /** Stays until dismissed, as an error does. */
  readonly sticky?: boolean;
}

export interface ToastApi {
  push: (kind: ToastKind, message: string, link?: ToastLink) => void;
  /**
   * Show `err`. A [`ParkedAction`] (`lib/parked-action.ts`) is not an error —
   * the act was accepted and is waiting on other administrators — so it is
   * shown as a success linking to the action, without `prefix`.
   */
  pushFromError: (err: unknown, prefix?: string) => void;
  dismiss: (id: number) => void;
}

const ToastContext = createContext<ToastApi | null>(null);

const DEFAULT_DISMISS_MS = 4500;
/** A toast with a link stays long enough to be followed. */
const LINK_DISMISS_MS = 12_000;

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<ReadonlyArray<Toast>>([]);
  const nextId = useRef(1);

  const dismiss = useCallback((id: number) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  }, []);

  const show = useCallback(
    (kind: ToastKind, message: string, options: ToastOptions = {}) => {
      const id = nextId.current++;
      const { link, title, sticky } = options;
      setToasts((prev) => [
        ...prev,
        { id, kind, message, ...(link ? { link } : {}), ...(title ? { title } : {}) },
      ]);
      // Auto-dismiss success + info; errors, and what is asked to, stick.
      if (kind !== "error" && !sticky) {
        setTimeout(() => dismiss(id), link ? LINK_DISMISS_MS : DEFAULT_DISMISS_MS);
      }
    },
    [dismiss],
  );

  const push = useCallback(
    (kind: ToastKind, message: string, link?: ToastLink) => show(kind, message, { link }),
    [show],
  );

  const pushFromError = useCallback(
    (err: unknown, prefix?: string) => {
      const parked = parkedOf(err);
      if (parked) {
        // Kept until dismissed: a requester's own parked request is not in
        // their "waiting for you" count, so on a screen that toasts rather
        // than draws `<ErrorOrParked>` this is its only trace (#2617).
        show("success", parked.message, {
          link: { href: parked.path, label: "View the action" },
          sticky: true,
        });
        return;
      }
      const apiErr = err as Partial<ApiError> | undefined;
      const detail = messageOf(err);
      // The bare status ("(403)") means nothing to a community administrator;
      // it stays on hover for whoever reports the problem (#2617).
      const title = apiErr?.status ? `HTTP ${apiErr.status}` : undefined;
      show("error", prefix ? `${prefix}: ${detail}` : detail, { title });
    },
    [show],
  );

  const api = useMemo<ToastApi>(
    () => ({ push, pushFromError, dismiss }),
    [push, pushFromError, dismiss],
  );

  // Expose to third-party plugins via the shared API surface. Re-bind
  // when `api` changes so the global always sees the live callbacks.
  useEffect(() => {
    if (typeof window === "undefined") return;
    // `registerPlugin` is set by `plugin-api.ts` at module load —
    // in normal app boot order it's already present here, but we
    // keep an inert fallback so the type stays satisfied if the
    // shell is ever booted without that module.
    const existing = window.VtcPluginApi;
    if (existing) {
      window.VtcPluginApi = { ...existing, toast: api };
    }
  }, [api]);

  return (
    <ToastContext.Provider value={api}>
      {children}
      <ToastViewport toasts={toasts} dismiss={dismiss} />
    </ToastContext.Provider>
  );
}

export function useToast(): ToastApi {
  const ctx = useContext(ToastContext);
  if (!ctx) {
    throw new Error("useToast must be used inside <ToastProvider>");
  }
  return ctx;
}

function ToastViewport({
  toasts,
  dismiss,
}: {
  toasts: ReadonlyArray<Toast>;
  dismiss: (id: number) => void;
}) {
  // Always mounted, even empty: screen readers announce changes to a live
  // region that is already there, and may miss one mounted with its first
  // message (#2617).
  return (
    <div
      className="toast-viewport"
      role="region"
      aria-label="Notifications"
      aria-live="polite"
    >
      {toasts.map((t) => (
        <div
          key={t.id}
          className={`toast toast-${t.kind}`}
          role={t.kind === "error" ? "alert" : "status"}
          title={t.title}
        >
          <span className="toast-message">
            {t.message}
            {t.link && (
              <>
                {" "}
                <a
                  className="toast-link"
                  href={`/admin${t.link.href}`}
                  onClick={(e) => followInConsole(e, t.link!.href)}
                >
                  {t.link.label}
                </a>
              </>
            )}
          </span>
          <button
            type="button"
            className="toast-dismiss"
            aria-label="Dismiss notification"
            onClick={() => dismiss(t.id)}
          >
            ×
          </button>
        </div>
      ))}
    </div>
  );
}


/**
 * Follow a toast link without reloading the console. The toaster sits outside
 * the router (`main.tsx`), so it cannot use `<Link>`; pushing the history
 * entry and announcing it is what `BrowserRouter` listens for. A modified
 * click (new tab, new window) keeps the browser's own behaviour.
 */
function followInConsole(e: React.MouseEvent<HTMLAnchorElement>, href: string): void {
  if (e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
  e.preventDefault();
  try {
    window.history.pushState({}, "", `/admin${href}`);
    window.dispatchEvent(new PopStateEvent("popstate"));
  } catch {
    window.location.assign(`/admin${href}`);
  }
}
