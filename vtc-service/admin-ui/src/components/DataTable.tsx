// The console's table: `data-table` styling, a header that stays in view
// under the top bar while the rows scroll, and sortable columns through
// `SortableHeader` — a column with a `sortKey` sorts, one without is a plain
// heading.
//
// The rows are the caller's: `DataTable` draws the head and wraps whatever
// `<tr>`s it is given, so a screen keeps full control of its cells. Sorting is
// the caller's too — `useSortedRows` below is the usual way — because only the
// screen knows what a column's value is (a member's name may come from the
// name book, a date from a field).

import { useState, type ReactNode } from "react";

import { InfoTip } from "@/components/InfoTip";
import { SortableHeader } from "@/components/SortableHeader";
import {
  compareValues,
  nextSort,
  type SortDir,
  type SortState,
  type SortValue,
} from "@/lib/table-sort";

export interface Column<K extends string = string> {
  /** Stable key for React. */
  readonly key: string;
  /** Column heading. A sortable column's label must be text: it also names
   *  the sort button ("Sort by name"). */
  readonly label: ReactNode;
  /** Makes the column sortable by this key. */
  readonly sortKey?: K;
  /** What the column means, shown on hover or focus. */
  readonly tip?: ReactNode;
  readonly className?: string;
}

export function DataTable<K extends string = string>({
  columns,
  sort = null,
  onSort,
  caption,
  className,
  children,
  "aria-label": ariaLabel,
}: {
  columns: readonly Column<K>[];
  sort?: SortState<K> | null;
  onSort?: (key: K) => void;
  /** Read by assistive technology only. */
  caption?: ReactNode;
  className?: string;
  /** The `<tr>` rows. */
  children: ReactNode;
  "aria-label"?: string;
}) {
  return (
    <table
      className={`data-table${className ? ` ${className}` : ""}`}
      aria-label={ariaLabel}
    >
      {caption && <caption className="visually-hidden">{caption}</caption>}
      <thead>
        <tr>
          {columns.map((c) =>
            c.sortKey && onSort ? (
              <SortableHeader
                key={c.key}
                label={typeof c.label === "string" ? c.label : String(c.sortKey)}
                sortKey={c.sortKey}
                sort={sort}
                onSort={onSort}
                tip={c.tip}
                className={c.className}
              />
            ) : (
              <th key={c.key} scope="col" className={c.className}>
                {c.tip ? (
                  <span className="sortable-th-wrap">
                    <span>{c.label}</span>
                    <InfoTip label={`About ${typeof c.label === "string" ? c.label : c.key}`} side="bottom">
                      {c.tip}
                    </InfoTip>
                  </span>
                ) : (
                  c.label
                )}
              </th>
            ),
          )}
        </tr>
      </thead>
      <tbody>{children}</tbody>
    </table>
  );
}

/**
 * Client-side sorting for a list read whole. Rows keep the order they were
 * given until a header is clicked; a click sorts by that column (`initialDir`
 * per key, ascending otherwise) and a second click flips it. Empty values sort
 * last either way.
 */
export function useSortedRows<R, K extends string>(
  rows: readonly R[],
  valueOf: (row: R, key: K) => SortValue,
  options: { initial?: SortState<K> | null; initialDir?: Partial<Record<K, SortDir>> } = {},
): { rows: R[]; sort: SortState<K> | null; onSort: (key: K) => void } {
  const [sort, setSort] = useState<SortState<K> | null>(options.initial ?? null);
  // Recomputed each render: `valueOf` usually closes over other state (the
  // name book), and the lists are small enough that memoising would only risk
  // a stale order.
  const sorted = !sort
    ? [...rows]
    : rows
        .map((row, i) => ({ row, i }))
        .sort(
          (a, b) =>
            compareValues(valueOf(a.row, sort.key), valueOf(b.row, sort.key), sort.dir) ||
            a.i - b.i,
        )
        .map(({ row }) => row);
  const initialDir = options.initialDir;
  return {
    rows: sorted,
    sort,
    onSort: (key: K) => setSort((s) => nextSort(s, key, initialDir?.[key] ?? "asc")),
  };
}
