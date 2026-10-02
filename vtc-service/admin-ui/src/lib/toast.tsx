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

  const push = useCallback(
    (kind: ToastKind, message: string, link?: ToastLink) => {
      const id = nextId.current++;
      setToasts((prev) => [...prev, link ? { id, kind, message, link } : { id, kind, message }]);
      // Auto-dismiss success + info; errors stick.
      if (kind !== "error") {
        setTimeout(() => dismiss(id), link ? LINK_DISMISS_MS : DEFAULT_DISMISS_MS);
      }
    },
    [dismiss],
  );

  const pushFromError = useCallback(
    (err: unknown, prefix?: string) => {
      const parked = parkedOf(err);
      if (parked) {
        push("success", parked.message, { href: parked.path, label: "View the action" });
        return;
      }
      const apiErr = err as Partial<ApiError> | undefined;
      const detail = apiErr?.message ?? (err instanceof Error ? err.message : String(err));
      const status = apiErr?.status ? ` (${apiErr.status})` : "";
      const message = prefix ? `${prefix}: ${detail}${status}` : `${detail}${status}`;
      push("error", message);
    },
    [push],
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
  if (toasts.length === 0) return null;
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
