// What a list or panel shows when there is nothing in it.
//
// - The full form (in a card of its own, or where a table would be): an
//   icon, a title saying what is absent, an optional sentence on why or what
//   to do, and an optional action.
// - `compact`: one muted line inside a card that has other content ("None
//   enrolled."), in the same voice and colour.
//
// The title is the text a test or a screen reader finds; keep it a sentence
// ("No active sessions", "Nothing is waiting for your approval.").

import type { ComponentType, ReactNode } from "react";

export function EmptyState({
  icon: Icon,
  title,
  children,
  action,
  compact,
  className,
}: {
  /** A lucide-react icon component. */
  icon?: ComponentType<{ "aria-hidden"?: boolean | "true" | "false" }>;
  title: ReactNode;
  /** One or two sentences under the title. */
  children?: ReactNode;
  action?: ReactNode;
  compact?: boolean;
  className?: string;
}) {
  if (compact) {
    return (
      <p className={`empty-state compact${className ? ` ${className}` : ""}`}>
        {Icon && (
          <span className="empty-icon" aria-hidden="true">
            <Icon aria-hidden="true" />
          </span>
        )}
        <span>{title}</span>
      </p>
    );
  }
  return (
    <div className={`empty-state${className ? ` ${className}` : ""}`}>
      {Icon && (
        <span className="empty-icon" aria-hidden="true">
          <Icon aria-hidden="true" />
        </span>
      )}
      <h4>{title}</h4>
      {children && <p>{children}</p>}
      {action && <div className="empty-action">{action}</div>}
    </div>
  );
}
