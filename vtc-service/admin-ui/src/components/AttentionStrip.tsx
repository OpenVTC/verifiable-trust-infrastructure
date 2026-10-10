// The attention strip: one place above every page for what the operator must
// know, instead of a stack of separate banners.
//
// Each item keeps its own markup, wording, links and ARIA role — the strip
// only orders them, counts them and decides which are visible:
//
// - Items are shown most severe first: critical (an operator's offline write,
//   a cooling-off against you, break-glass and its cannot-check variant), then
//   standing conditions (single-administrator mode), then warnings (this
//   browser's signing key expiring), then information (actions waiting).
// - **Pinned** items are always visible and carry no dismiss control: every
//   critical item, and single-administrator mode, which VTI-APV-022 requires on
//   every page. Each still clears only when what it reports does.
// - Of the rest, the most severe is shown and the others sit behind a
//   "Show N more" control, with a count of everything in the strip.
//
// The actions-waiting item keeps its own "Dismiss for this session" button
// (`lib/action-badge.ts`); dismissing it removes it from the strip.

import { useState, type ReactNode } from "react";
import { ChevronDown, ChevronUp } from "lucide-react";

export type AttentionSeverity = "critical" | "standing" | "warning" | "info";

export interface AttentionItem {
  /** Stable key, unique within the strip. */
  readonly key: string;
  readonly severity: AttentionSeverity;
  /** The item's own element, carrying its role (`alert` / `status`). */
  readonly node: ReactNode;
}

const RANK: Record<AttentionSeverity, number> = {
  critical: 0,
  standing: 1,
  warning: 2,
  info: 3,
};

/** Critical and standing items are never folded away. */
export function isPinned(item: AttentionItem): boolean {
  return item.severity === "critical" || item.severity === "standing";
}

/** Most severe first; equal severities keep the order they were given in. */
export function orderAttention(items: readonly AttentionItem[]): AttentionItem[] {
  return items
    .map((item, i) => ({ item, i }))
    .sort((a, b) => RANK[a.item.severity] - RANK[b.item.severity] || a.i - b.i)
    .map(({ item }) => item);
}

/** Which items the strip shows when collapsed: every pinned item, plus the
 *  most severe of the others. */
export function collapsedView(ordered: readonly AttentionItem[]): {
  shown: AttentionItem[];
  folded: number;
} {
  const pinned = ordered.filter(isPinned);
  const rest = ordered.filter((i) => !isPinned(i));
  return { shown: [...pinned, ...rest.slice(0, 1)], folded: Math.max(0, rest.length - 1) };
}

function countSentence(n: number): string {
  return n === 1 ? "1 thing needs attention" : `${n} things need attention`;
}

export function AttentionStrip({ items }: { items: readonly AttentionItem[] }) {
  const [expanded, setExpanded] = useState(false);
  if (items.length === 0) return null;

  const ordered = orderAttention(items);
  const { shown, folded } = collapsedView(ordered);
  const visible = expanded ? ordered : shown;
  const top = ordered[0]!.severity;

  return (
    <section
      className={`attention-strip attention-strip--${top}`}
      aria-label="Needs attention"
      data-testid="attention-strip"
    >
      {items.length > 1 && (
        <div className="attention-summary">
          <strong>{countSentence(items.length)}</strong>
          {(folded > 0 || expanded) && (
            <button
              type="button"
              className="link attention-toggle"
              aria-expanded={expanded}
              onClick={() => setExpanded((v) => !v)}
            >
              {expanded ? "Show less" : `Show ${folded} more`}
              <span className="button-icon" aria-hidden="true">
                {expanded ? <ChevronUp /> : <ChevronDown />}
              </span>
            </button>
          )}
        </div>
      )}
      <div className="attention-items">
        {visible.map((item) => (
          <div key={item.key} className="attention-slot">
            {item.node}
          </div>
        ))}
      </div>
    </section>
  );
}
