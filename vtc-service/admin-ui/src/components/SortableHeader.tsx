// A column header that sorts its table: the button toggles, the `<th>`
// carries `aria-sort` for assistive technology. An optional explanation sits
// beside the button, not inside it — a button cannot hold another button.

import type { ReactNode } from "react";
import { ArrowDown, ArrowUp, ArrowUpDown } from "lucide-react";

import { InfoTip } from "@/components/InfoTip";
import type { SortState } from "@/lib/table-sort";

export function SortableHeader<K extends string>({
  label,
  sortKey,
  sort,
  onSort,
  tip,
  className,
}: {
  label: string;
  sortKey: K;
  sort: SortState<K> | null;
  onSort: (key: K) => void;
  /** What the column means, shown on hover or focus. */
  tip?: ReactNode;
  className?: string;
}) {
  const active = sort?.key === sortKey;
  const ariaSort = !active ? "none" : sort.dir === "asc" ? "ascending" : "descending";
  const Icon = !active ? ArrowUpDown : sort.dir === "asc" ? ArrowUp : ArrowDown;
  return (
    <th scope="col" aria-sort={ariaSort} className={className}>
      <span className="sortable-th-wrap">
        <button
          type="button"
          className="sortable-th"
          title={`Sort by ${label.toLowerCase()}`}
          onClick={() => onSort(sortKey)}
        >
          <span>{label}</span>
          <Icon size={12} aria-hidden="true" />
        </button>
        {tip && (
          <InfoTip label={`About ${label}`} side="bottom">
            {tip}
          </InfoTip>
        )}
      </span>
    </th>
  );
}
