// Every trust record under this community's authority — memberships and git
// rights alike — searchable, filterable and sortable.
//
// The list is read whole (`fetchAllRegistryRecords`) and filtered here: the
// operator's question is usually "what does the registry say about this DID?"
// or "who holds rights on this repository?", and both are a search over all of
// it, not one page.

import { useMemo, useState } from "react";
import { Filter, X } from "lucide-react";

import { DidText } from "@/components/DidText";
import { InfoTip } from "@/components/InfoTip";
import { DataTable, type Column } from "@/components/DataTable";
import { EmptyState } from "@/components/EmptyState";
import { Field } from "@/components/Field";
import { useNameBook } from "@/lib/names";
import {
  compareValues,
  didHandle,
  matchScore,
  nextSort,
  searchTerms,
  type SortDir,
  type SortState,
  type SortValue,
} from "@/lib/table-sort";
import type { RegistryRecordRow } from "@/lib/wire-types";

import { RECOGNISE_ACTION, recordKind, recordKindLabel, recordMeaning, type RecordKind } from "./records";

type SortKey = "entity" | "action" | "resource" | "kind" | "assertion";

const INITIAL_DIR: Record<SortKey, SortDir> = {
  entity: "asc",
  action: "asc",
  resource: "asc",
  kind: "asc",
  assertion: "desc",
};

const COLUMN_TIPS: Record<SortKey, string> = {
  entity: "Who the record is about: a member, or a holder of a git right.",
  action: "What the record says the entity may do — `recognise` on the trust graph is membership; `git.*` are git rights.",
  resource: "What the action applies to: the community's trust graph, a forge namespace, or one repository.",
  kind: "Recognition records say the community recognises the entity (membership). Authorization records say it authorises an action on a resource (git rights).",
  assertion: "What the record asserts. A recognition record carries `recognized`, an authorization record `authorized`; a missing value is no assertion either way, not a refusal.",
};

type AssertionFilter = "all" | "yes" | "no";

/** What the record asserts: `recognized` on a recognition record,
 *  `authorized` on an authorization one. Absent is no assertion, not `false`. */
function assertionOf(r: RegistryRecordRow): boolean | null {
  if (typeof r.recognized === "boolean") return r.recognized;
  if (typeof r.authorized === "boolean") return r.authorized;
  return null;
}

export function TrustRecords({
  items,
  source,
}: {
  items: RegistryRecordRow[];
  /** Which view answered: `registry` or `local`. */
  source: string;
}) {
  const book = useNameBook();
  const [search, setSearch] = useState("");
  const [kind, setKind] = useState<RecordKind | "all">("all");
  const [action, setAction] = useState("all");
  const [assertion, setAssertion] = useState<AssertionFilter>("all");
  const [sort, setSort] = useState<SortState<SortKey> | null>(null);

  const actions = useMemo(() => [...new Set(items.map((r) => r.action))].sort(), [items]);
  const kinds = useMemo(() => [...new Set(items.map(recordKind))].sort(), [items]);
  const authorities = useMemo(() => [...new Set(items.map((r) => r.authorityId))], [items]);
  const oneAuthority = authorities.length === 1 ? authorities[0]! : null;

  const rows = useMemo(() => {
    const terms = searchTerms(search);
    const scored: { r: RegistryRecordRow; score: number }[] = [];
    for (const r of items) {
      if (kind !== "all" && recordKind(r) !== kind) continue;
      if (action !== "all" && r.action !== action) continue;
      const a = assertionOf(r);
      if (assertion === "yes" && a !== true) continue;
      if (assertion === "no" && a !== false) continue;
      const score = matchScore(terms, {
        short: [book.nameOf(r.entityId) ?? "", didHandle(r.entityId), r.action, recordKindLabel(recordKind(r))],
        long: [r.entityId, r.resource, r.authorityId],
      });
      if (score !== null) scored.push({ r, score });
    }
    const value = (r: RegistryRecordRow, key: SortKey): SortValue => {
      switch (key) {
        case "entity":
          return book.nameOf(r.entityId) ?? r.entityId;
        case "action":
          return r.action;
        case "resource":
          return r.resource;
        case "kind":
          return recordKindLabel(recordKind(r));
        case "assertion": {
          const a = assertionOf(r);
          return a === null ? null : a ? 1 : 0;
        }
      }
    };
    const natural = (a: RegistryRecordRow, b: RegistryRecordRow) =>
      compareValues(value(a, "entity"), value(b, "entity"), "asc") ||
      compareValues(a.action, b.action, "asc") ||
      compareValues(a.resource, b.resource, "asc");
    scored.sort((a, b) =>
      sort
        ? compareValues(value(a.r, sort.key), value(b.r, sort.key), sort.dir) || natural(a.r, b.r)
        : b.score - a.score || natural(a.r, b.r),
    );
    return scored.map((s) => s.r);
  }, [items, search, kind, action, assertion, sort, book]);

  const filtered = search !== "" || kind !== "all" || action !== "all" || assertion !== "all";
  const clear = () => {
    setSearch("");
    setKind("all");
    setAction("all");
    setAssertion("all");
  };
  const onSort = (key: SortKey) => setSort((s) => nextSort(s, key, INITIAL_DIR[key]));
  const column = (key: SortKey, label: string): Column<SortKey> => ({
    key,
    label,
    sortKey: key,
    tip: COLUMN_TIPS[key],
  });
  const columns: Column<SortKey>[] = [
    column("entity", "Entity"),
    ...(oneAuthority ? [] : [{ key: "authority", label: "Authority" }]),
    column("action", "Action"),
    column("resource", "Resource"),
    column("kind", "Type"),
    column("assertion", "Asserts"),
  ];

  return (
    <>
      <div className="toolbar records-toolbar">
        <Field label="Search" inline className="records-search">
          <input
            type="search"
            placeholder="Name, DID, action or repository"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </Field>
        <Field label="Type" inline>
          <select value={kind} onChange={(e) => setKind(e.target.value as RecordKind | "all")}>
            <option value="all">All types</option>
            {kinds.map((k) => (
              <option key={k} value={k}>
                {recordKindLabel(k)}
              </option>
            ))}
          </select>
        </Field>
        <Field label="Action" inline>
          <select value={action} onChange={(e) => setAction(e.target.value)}>
            <option value="all">All actions</option>
            {actions.map((a) => (
              <option key={a} value={a}>
                {a === RECOGNISE_ACTION ? "recognise (membership)" : a}
              </option>
            ))}
          </select>
        </Field>
        <Field label="Asserts" inline>
          <select value={assertion} onChange={(e) => setAssertion(e.target.value as AssertionFilter)}>
            <option value="all">Anything</option>
            <option value="yes">Yes (recognised / authorised)</option>
            <option value="no">No (not recognised / not authorised)</option>
          </select>
        </Field>
        {filtered && (
          <button type="button" className="secondary sm" onClick={clear}>
            <X size={12} aria-hidden="true" /> Clear filters
          </button>
        )}
      </div>

      {oneAuthority && (
        <p className="muted gitns-small">
          Every record is asserted by <DidText did={oneAuthority} />
          <InfoTip label="About the authority">
            The authority is who makes the assertion — this community. Anyone can ask the
            Trust Registry whether this authority recognises or authorises a DID.
          </InfoTip>
        </p>
      )}

      <div className="table-scroll">
        <DataTable
          columns={columns}
          sort={sort}
          onSort={onSort}
          caption={<>Trust records from {source}</>}
          className="records-table"
        >
          {rows.length === 0 && (
            <tr>
              <td colSpan={oneAuthority ? 5 : 6}>
                <EmptyState
                  title="No record matches."
                  action={
                    <button type="button" className="link" onClick={clear}>
                      Clear the filters
                    </button>
                  }
                />
              </td>
            </tr>
          )}
          {rows.map((r) => {
            const a = assertionOf(r);
            const which =
              typeof r.recognized === "boolean"
                ? "recognised"
                : typeof r.authorized === "boolean"
                  ? "authorised"
                  : null;
            const name = book.nameOf(r.entityId);
            return (
              <tr key={`${r.entityId}|${r.action}|${r.resource}`}>
                <td>
                  {name && <div className="records-name">{name}</div>}
                  <span className="records-entity">
                    <DidText did={r.entityId} />
                    <button
                      type="button"
                      className="copy-icon-btn"
                      aria-label="Show only records for this DID"
                      title="Show only records for this DID"
                      onClick={() => setSearch(r.entityId)}
                    >
                      <Filter size={13} strokeWidth={1.75} aria-hidden="true" />
                    </button>
                  </span>
                </td>
                {!oneAuthority && (
                  <td>
                    <DidText did={r.authorityId} />
                  </td>
                )}
                <td>
                  <code>{r.action}</code>
                  <div className="muted gitns-small">{recordMeaning(r)}</div>
                </td>
                <td>
                  <code className="records-resource">{r.resource}</code>
                </td>
                <td>{recordKindLabel(recordKind(r))}</td>
                <td>
                  {which === null ? (
                    <span className="muted">— no assertion</span>
                  ) : (
                    <span className={a ? "chip success" : "chip danger"}>{a ? which : `not ${which}`}</span>
                  )}
                </td>
              </tr>
            );
          })}
        </DataTable>
      </div>
      <p className="muted" aria-live="polite">
        {rows.length === items.length
          ? `${items.length} record${items.length === 1 ? "" : "s"}`
          : `${rows.length} of ${items.length} records`}{" "}
        from <code>{source}</code>.
      </p>
    </>
  );
}
