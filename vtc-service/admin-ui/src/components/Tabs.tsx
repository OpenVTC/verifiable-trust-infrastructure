// One tab component for the whole console, in two looks:
//
// - `underline` (the default): a row of tabs over the content, the selected
//   one underlined in the brand colour, each with an optional count. For
//   switching between lists or sections (Actions' "Waiting for me",
//   Policies' ceremonies, Vetting's sections).
// - `segmented`: a compact pill group for switching how one thing is shown
//   (Plain English / Flow / Rego).
//
// Two behaviours:
//
// - **Buttons** (`value` + `onChange`): an ARIA tablist. The selected tab is
//   `aria-selected` and the only one in the Tab order; the arrow keys, Home
//   and End move between tabs.
// - **Links** (items with `to`): a `<nav>` of router links, for tabs that are
//   routes (Vetting's sections). The current one is `aria-current="page"`.

import { useRef, type KeyboardEvent, type ReactNode } from "react";
import { NavLink } from "react-router-dom";

export interface TabItem<T extends string = string> {
  readonly id: T;
  readonly label: ReactNode;
  /** A count shown after the label; hidden when 0 or absent unless
   *  `showZero`. */
  readonly count?: number;
  /** How the count reads aloud ("2 open"); defaults to the number. */
  readonly countLabel?: string;
  /** Something shown before the label (a status dot). */
  readonly icon?: ReactNode;
  /** A small second line or suffix (a ceremony's nature). */
  readonly hint?: ReactNode;
  readonly disabled?: boolean;
  /** Route for a link tab (see `TabLinks`). */
  readonly to?: string;
  /** For a link tab: match the route exactly. */
  readonly end?: boolean;
}

function TabInner({ item }: { item: TabItem }) {
  return (
    <>
      {item.icon}
      <span className="tab-label">{item.label}</span>
      {item.hint && <small className="tab-hint">{item.hint}</small>}
      {item.count !== undefined && item.count > 0 && (
        <span className="tab-count" aria-label={item.countLabel}>
          {item.count}
        </span>
      )}
    </>
  );
}

export function Tabs<T extends string>({
  items,
  value,
  onChange,
  label,
  variant = "underline",
  end,
  className,
}: {
  items: readonly TabItem<T>[];
  value: T;
  onChange: (id: T) => void;
  /** The tablist's accessible name. */
  label?: string;
  variant?: "underline" | "segmented";
  /** Controls after the tabs (a refresh button). */
  end?: ReactNode;
  className?: string;
}) {
  const refs = useRef<(HTMLButtonElement | null)[]>([]);
  const enabled = items.map((t, i) => (t.disabled ? -1 : i)).filter((i) => i >= 0);

  const onKeyDown = (e: KeyboardEvent<HTMLButtonElement>, index: number) => {
    const at = enabled.indexOf(index);
    let next: number | undefined;
    if (e.key === "ArrowRight") next = enabled[(at + 1) % enabled.length];
    else if (e.key === "ArrowLeft") next = enabled[(at - 1 + enabled.length) % enabled.length];
    else if (e.key === "Home") next = enabled[0];
    else if (e.key === "End") next = enabled[enabled.length - 1];
    if (next === undefined) return;
    e.preventDefault();
    refs.current[next]?.focus();
    onChange(items[next]!.id);
  };

  return (
    <div className={`tabs tabs--${variant}${className ? ` ${className}` : ""}`}>
      <div className="tabs-list" role="tablist" aria-label={label}>
        {items.map((t, i) => {
          const selected = t.id === value;
          return (
            <button
              key={t.id}
              ref={(el) => {
                refs.current[i] = el;
              }}
              type="button"
              role="tab"
              aria-selected={selected}
              tabIndex={selected ? 0 : -1}
              disabled={t.disabled}
              className={`tab${selected ? " on" : ""}`}
              onClick={() => onChange(t.id)}
              onKeyDown={(e) => onKeyDown(e, i)}
            >
              <TabInner item={t} />
            </button>
          );
        })}
      </div>
      {end && <div className="tabs-end">{end}</div>}
    </div>
  );
}

/** Tabs that are routes: a `<nav>` of links styled as underline tabs. */
export function TabLinks({
  items,
  label,
  className,
}: {
  items: readonly TabItem[];
  /** The nav's accessible name. */
  label: string;
  className?: string;
}) {
  return (
    <nav className={`tabs tabs--underline${className ? ` ${className}` : ""}`} aria-label={label}>
      <div className="tabs-list">
        {items.map((t) => (
          <NavLink key={t.id} to={t.to ?? t.id} end={t.end} className="tab">
            <TabInner item={t} />
          </NavLink>
        ))}
      </div>
    </nav>
  );
}
