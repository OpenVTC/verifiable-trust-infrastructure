// Withdrawals — statements their vetters have taken back, and the admissions
// that counted them.
//
// `needsReview` is advisory: nothing records that an admin reviewed an
// admission, and a withdrawal suspends no one. The panel says so, and links
// straight to the join requests and members an admin has to look at.

import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { Undo2 } from "lucide-react";

import { CopyButton } from "@/components/CopyButton";
import { DataTable, useSortedRows, type Column } from "@/components/DataTable";
import { EmptyState } from "@/components/EmptyState";
import { NamedDid } from "@/components/NamedDid";
import { formatIso, shorten } from "@/lib/format";
import { useNameBook } from "@/lib/names";
import { withdrawalReason } from "@/lib/vetting";
import type { RevocationReviewState, VettingRevocationRow } from "@/lib/wire-types";

import { fetchRevocations, vettingKeys } from "./api";
import { FormField, joinRequestPath, LoadError, memberPath, ToneChip } from "./ui";

type WithdrawalSortKey = "recorded" | "vetter" | "review";

const WITHDRAWAL_COLUMNS: readonly Column<WithdrawalSortKey>[] = [
  { key: "recorded", label: "Recorded", sortKey: "recorded" },
  { key: "vetter", label: "Vetter", sortKey: "vetter" },
  { key: "statement", label: "Statement" },
  { key: "reason", label: "Reason" },
  { key: "review", label: "Review", sortKey: "review" },
  { key: "affected", label: "Affected" },
];

export function WithdrawalsPanel() {
  const book = useNameBook();
  const query = useQuery({
    queryKey: vettingKeys.revocations,
    queryFn: fetchRevocations,
  });
  const [review, setReview] = useState<RevocationReviewState | "all">("all");

  const all = query.data ?? [];
  const rows = all.filter((r) => review === "all" || r.reviewState === review);
  // The notices are read whole, so their columns sort here.
  const sorted = useSortedRows(
    rows,
    (row: VettingRevocationRow, key: WithdrawalSortKey) => {
      switch (key) {
        case "recorded":
          return Date.parse(row.recordedAt) || null;
        case "vetter":
          return book.nameOrDid(row.issuer);
        case "review":
          return row.reviewState;
      }
    },
    { initialDir: { recorded: "desc" } },
  );
  const needing = all.filter((r) => r.reviewState === "needsReview").length;

  return (
    <section className="card" aria-labelledby="withdrawals-title">
      <h3 id="withdrawals-title">Withdrawn statements</h3>
      <p className="lead">
        A vetter can withdraw a statement they signed. When a current member was
        admitted with that statement counted, decide whether their admission
        still stands: withdrawing a statement does not suspend anyone, and
        nothing here records that you reviewed it.
      </p>

      {needing > 0 && (
        <p className="finding warn">
          <strong>
            {needing} {needing === 1 ? "withdrawal touches" : "withdrawals touch"}{" "}
            a current membership.
          </strong>
          <span className="muted">
            Open each affected member and join request below to review the
            admission.
          </span>
        </p>
      )}

      <div className="toolbar">
        <FormField id="withdrawals-review" label="Show" inline>
          <select
            id="withdrawals-review"
            value={review}
            onChange={(e) =>
              setReview(e.target.value as RevocationReviewState | "all")
            }
          >
            <option value="all">All withdrawals</option>
            <option value="needsReview">Needs review</option>
            <option value="noAdmission">No current member affected</option>
          </select>
        </FormField>
      </div>

      {query.error && <LoadError what="the withdrawal notices" error={query.error} />}

      <div className="table-scroll">
        <DataTable columns={WITHDRAWAL_COLUMNS} sort={sorted.sort} onSort={sorted.onSort}>
          {query.isPending && (
            <tr>
              <td colSpan={6}>Loading…</td>
            </tr>
          )}
          {query.data && rows.length === 0 && (
            <tr>
              <td colSpan={6}>
                <EmptyState
                  icon={Undo2}
                  title={
                    all.length === 0
                      ? "No vetter has withdrawn a statement"
                      : "No withdrawal matches this filter"
                  }
                >
                  {all.length === 0
                    ? "Withdrawals appear here when a vetter takes back a statement they signed."
                    : "Show all withdrawals to see the rest."}
                </EmptyState>
              </td>
            </tr>
          )}
          {sorted.rows.map((row) => (
            <tr key={`${row.issuer}|${row.statementId}`}>
              <td>{formatIso(row.recordedAt)}</td>
              <td>
                <NamedDid book={book} did={row.issuer} />
              </td>
              <td>
                <code title={row.statementId}>{shorten(row.statementId, 16, 6)}</code>
                <CopyButton
                  value={row.statementId}
                  label="Copy statement id"
                  successMessage="Statement id copied"
                />
                <details>
                  <summary className="muted">Digest</summary>
                  <code>{row.statementDigestMultibase}</code>
                </details>
              </td>
              <td>
                <span title={row.reason ?? undefined}>{withdrawalReason(row)}</span>
              </td>
              <td>
                {row.reviewState === "needsReview" ? (
                  <ToneChip tone="warn" title="needsReview">
                    Needs review
                  </ToneChip>
                ) : (
                  <ToneChip tone="neutral" title="noAdmission">
                    No current member affected
                  </ToneChip>
                )}
              </td>
              <td>
                {row.affectedJoinRequests.length === 0 ? (
                  <span className="muted">No approved join request counted it</span>
                ) : (
                  <ul className="vet-list">
                    {row.affectedJoinRequests.map((id) => (
                      <li key={id}>
                        <Link to={joinRequestPath(id)}>
                          Join request <code>{id.slice(0, 8)}</code>
                        </Link>
                      </li>
                    ))}
                    {row.affectedMembers.map((did) => (
                      <li key={did}>
                        <Link to={memberPath(did)}>
                          Member <NamedDid book={book} did={did} />
                        </Link>
                      </li>
                    ))}
                  </ul>
                )}
              </td>
            </tr>
          ))}
        </DataTable>
      </div>
    </section>
  );
}
