// The header every console screen starts with: a breadcrumb placing it in
// the navigation (group / page), the title with an optional count, a slot
// for the screen's primary action, and an optional lead paragraph.
//
//   Membership / Members
//   Members 248                                   [Invite a member]
//   Who belongs to this community, and what they hold.
//
// The breadcrumb comes from the plugin being rendered (`PluginHost` provides
// it, `lib/plugin-context.ts`), so a screen only names what is particular to
// it. A sub-page (one member, one repository) passes `trail`, and its title is
// the sub-page's own.
//
// The title is the page's `<h2>`, as before: the count sits beside it, not in
// it, so the heading's accessible name stays the page's name.

import type { ReactNode } from "react";
import { Link } from "react-router-dom";

import { groupLabelOf, useCurrentPlugin } from "@/lib/plugin-context";

export interface Crumb {
  readonly label: ReactNode;
  /** A route under `/admin`; absent for the current page. */
  readonly to?: string;
}

export function PageHeader({
  title,
  count,
  countLabel,
  trail,
  actions,
  lead,
  crumbs,
}: {
  /** The page title. Defaults to the plugin's nav label. */
  title?: ReactNode;
  /** A number shown beside the title — the size of the list below. */
  count?: number | string | null;
  /** How the count reads aloud ("248 members"); defaults to the number. */
  countLabel?: string;
  /** Crumbs after the plugin's own, for a sub-page. */
  trail?: readonly Crumb[];
  /** The primary action(s), right-aligned. */
  actions?: ReactNode;
  /** One short paragraph under the title. */
  lead?: ReactNode;
  /** Replace the breadcrumb entirely (a page outside any plugin). */
  crumbs?: readonly Crumb[];
}) {
  const plugin = useCurrentPlugin();
  const path: Crumb[] = crumbs
    ? [...crumbs]
    : plugin
      ? [
          { label: groupLabelOf(plugin) },
          { label: plugin.label, to: plugin.path },
          ...(trail ?? []),
        ]
      : [...(trail ?? [])];

  return (
    <header className="page-header">
      <div className="page-header-text">
        {path.length > 0 && (
          <nav className="breadcrumb" aria-label="Breadcrumb">
            <ol>
              {path.map((c, i) => {
                const last = i === path.length - 1;
                return (
                  <li key={i}>
                    {c.to && !last ? (
                      <Link to={c.to}>{c.label}</Link>
                    ) : (
                      <span aria-current={last ? "page" : undefined}>{c.label}</span>
                    )}
                  </li>
                );
              })}
            </ol>
          </nav>
        )}
        <div className="page-title-row">
          <h2 className="page-title">{title ?? plugin?.label}</h2>
          {count !== undefined && count !== null && (
            <span className="page-count" aria-label={countLabel}>
              {count}
            </span>
          )}
        </div>
        {lead && <p className="lead">{lead}</p>}
      </div>
      {actions && <div className="page-actions">{actions}</div>}
    </header>
  );
}
