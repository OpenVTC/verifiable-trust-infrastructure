import { Component, type ErrorInfo, type ReactNode } from "react";

/**
 * Catches a render-time throw in its subtree and draws a fallback in its
 * place, so one screen's bad row does not unmount the whole app (#2605).
 *
 * Without one, React unmounts the root on an uncaught render error: the
 * operator or member is left with an empty page, no navigation and nothing to
 * say what happened. The console wraps each plugin screen (the top bar and
 * the sidebar survive) and the root as a last resort; the member portal wraps
 * each signed-in page and its root.
 *
 * `resetKey`: when it changes, a caught error is cleared and the subtree is
 * rendered again — pass the route, so navigating away recovers. It does not
 * remount a subtree that has not failed.
 *
 * Shared by both bundles: it imports nothing from the console shell.
 */
export interface ErrorBoundaryProps {
  children: ReactNode;
  /** Clears a caught error when it changes (the route, typically). */
  resetKey?: unknown;
  /** What the fallback says failed: "This screen", "This page". */
  what?: string;
  /** The fallback's look: the console's error card, or the portal's alert. */
  variant?: "card" | "alert";
}

interface State {
  error: Error | null;
}

export class ErrorBoundary extends Component<ErrorBoundaryProps, State> {
  state: State = { error: null };

  static getDerivedStateFromError(error: unknown): State {
    return { error: error instanceof Error ? error : new Error(String(error)) };
  }

  componentDidCatch(error: unknown, info: ErrorInfo): void {
    // Kept in the console for whoever opens the developer tools; the page
    // shows only the message.
    console.error("render error", error, info.componentStack);
  }

  componentDidUpdate(prev: ErrorBoundaryProps): void {
    if (this.state.error && !Object.is(prev.resetKey, this.props.resetKey)) {
      this.setState({ error: null });
    }
  }

  render(): ReactNode {
    const { error } = this.state;
    if (!error) return this.props.children;
    return (
      <ErrorFallback
        error={error}
        what={this.props.what ?? "This page"}
        variant={this.props.variant ?? "card"}
      />
    );
  }
}

function ErrorFallback({
  error,
  what,
  variant,
}: {
  error: Error;
  what: string;
  variant: "card" | "alert";
}) {
  const where = typeof window === "undefined" ? "" : window.location.pathname + window.location.hash;
  const body = (
    <>
      <p>{error.message || "An unexpected error occurred."}</p>
      {where && (
        <p className="muted">
          At <code>{where}</code>
        </p>
      )}
      <div>
        <button
          type="button"
          // The console's button classes, or the portal's (`signin.css`).
          className={variant === "alert" ? "btn btn-secondary btn-sm" : "secondary sm"}
          onClick={() => window.location.reload()}>
          Reload this page
        </button>
      </div>
    </>
  );
  if (variant === "alert") {
    return (
      <div className="alert" role="alert">
        <p className="alert-title">{what} couldn't be shown.</p>
        {body}
      </div>
    );
  }
  return (
    <section className="card error" role="alert">
      <h3>{what} couldn't be shown</h3>
      {body}
    </section>
  );
}
