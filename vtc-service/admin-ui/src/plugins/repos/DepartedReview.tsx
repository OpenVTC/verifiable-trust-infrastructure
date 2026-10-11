// Grants issued by members who have since left (design §5.4).
//
// They stay valid on purpose: they were issued under the community's
// authority, not the granter's, and a departure that silently took every
// committer they ever added with it would punish the people they added. So
// they are listed for an owner or admin to look at, one decision each, unless
// the policy sets `cascade_on_departure` — in which case the daemon revokes
// them and this list only shows what is still on its way out.
//
// Revoking one is an ordinary signed `git-ns/right/revoke`, authorized by the
// signer's rights on the resource like any other.

import { useState } from "react";
import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { UserX } from "lucide-react";

import { type Column, DataTable, useSortedRows } from "@/components/DataTable";
import { EmptyState } from "@/components/EmptyState";
import { NamedDid } from "@/components/NamedDid";
import { PageHeader } from "@/components/PageHeader";
import { useNameBook } from "@/lib/names";
import type { GitNsRight, GitNsRightRow } from "@/lib/wire-types";

import type { SignedTask } from "./actions";
import { RevokeDialog } from "./dialogs";
import { fetchIssuedByDeparted, fetchRepos, gitNsKeys } from "./api";
import { isRight, rightLabel, shortName } from "./model";
import { formatDay, readErrorMessage, repoPath, SignTaskDialog, ToneChip } from "./ui";

export function DepartedReview() {
  const book = useNameBook();
  const q = useQuery({ queryKey: gitNsKeys.departed, queryFn: fetchIssuedByDeparted });
  const reposQ = useQuery({ queryKey: gitNsKeys.repos, queryFn: fetchRepos });
  const [task, setTask] = useState<SignedTask | null>(null);
  const [revoking, setRevoking] = useState<GitNsRightRow | null>(null);
  const isRepo = (resource: string) =>
    (reposQ.data?.repos ?? []).some((r) => r.resource === resource);

  return (
    <>
      <PageHeader
        trail={[{ label: "Issued by departed members" }]}
        title="Issued by departed members"
        lead={
          q.data
            ? q.data.cascadeOnDeparture
              ? "The active policy revokes grants a departed member issued (cascade_on_departure). Anything listed here is still on its way out."
              : "These grants stay valid — they were issued under the community's authority — until someone decides otherwise. Keep a grant by leaving it; revoke one with a signed revoke."
            : undefined
        }
      />

      {q.isPending && (
        <section className="card">
          <p>Reading grants…</p>
        </section>
      )}
      {q.isError && (
        <section className="card error">
          <h3>Grants could not be read</h3>
          <p>{readErrorMessage(q.error)}. This is a failure to ask, not an empty list.</p>
        </section>
      )}

      {q.data && q.data.granters.length === 0 && (
        <section className="card">
          <EmptyState icon={UserX} title="Nothing to review">
            No live grant was issued by someone who has since left.
          </EmptyState>
        </section>
      )}

      {q.data?.granters.map((g) => (
        <section key={g.granter} className="card" aria-label={`Grants issued by ${book.nameOf(g.granter) ?? g.granter}`}>
          <h3>
            Issued by <NamedDid did={g.granter} book={book} /> · {g.rights.length}{" "}
            {g.rights.length === 1 ? "grant" : "grants"}
          </h3>
          <GrantsTable rights={g.rights} isRepo={isRepo} onRevoke={setRevoking} />
        </section>
      ))}

      {revoking && (
        <RevokeDialog
          subject={revoking.subject}
          subjectName={book.nameOf(revoking.subject) ?? undefined}
          right={revoking.right as GitNsRight}
          resource={revoking.resource}
          initialReason="Issued by a departed member"
          onClose={() => setRevoking(null)}
          onBuilt={(t) => {
            setRevoking(null);
            setTask(t);
          }}
        />
      )}
      {task && <SignTaskDialog task={task} onClose={() => setTask(null)} />}
    </>
  );
}

type SortKey = "holder" | "right" | "resource" | "granted";

const COLUMNS: readonly Column<SortKey>[] = [
  { key: "holder", label: "Holder", sortKey: "holder" },
  { key: "right", label: "Right", sortKey: "right" },
  { key: "resource", label: "Resource", sortKey: "resource" },
  { key: "granted", label: "Granted", sortKey: "granted" },
  { key: "actions", label: <span className="visually-hidden">Actions</span> },
];

/** One departed granter's grants. The list is read whole, so it sorts here;
 *  rows keep the daemon's order until a header is clicked. */
function GrantsTable({
  rights,
  isRepo,
  onRevoke,
}: {
  rights: readonly GitNsRightRow[];
  isRepo: (resource: string) => boolean;
  onRevoke: (row: GitNsRightRow) => void;
}) {
  const book = useNameBook();
  const sorted = useSortedRows<GitNsRightRow, SortKey>(
    rights,
    (r, key) => {
      switch (key) {
        case "holder":
          return book.nameOf(r.subject) ?? r.subject;
        case "right":
          return rightLabel(r.right);
        case "resource":
          return r.resource;
        case "granted":
          return r.grantedAt ?? null;
      }
    },
    { initialDir: { granted: "desc" } },
  );
  return (
    <div className="table-scroll">
      <DataTable columns={COLUMNS} sort={sorted.sort} onSort={sorted.onSort}>
        {sorted.rows.map((r) => (
          <tr key={`${r.subject}|${r.right}|${r.resource}`}>
            <td>
              <NamedDid did={r.subject} book={book} />
              {!r.subjectMember && (
                <div>
                  <ToneChip tone="warning">External signer</ToneChip>
                </div>
              )}
            </td>
            <td>
              <ToneChip tone="neutral" title={r.right}>
                {rightLabel(r.right)}
              </ToneChip>
            </td>
            <td>
              {isRepo(r.resource) ? (
                <Link to={repoPath(r.resource)} className="gitns-mono">
                  {shortName(r.resource)}
                </Link>
              ) : (
                <code>{r.resource}</code>
              )}
            </td>
            <td>
              {formatDay(r.grantedAt)}
              {r.expiresAt && (
                <div className="muted gitns-small">expires {formatDay(r.expiresAt)}</div>
              )}
              {r.reason && <div className="muted gitns-small">“{r.reason}”</div>}
            </td>
            <td>
              {isRight(r.right) && (
                <button
                  type="button"
                  className="secondary sm destructive"
                  aria-label={`Revoke ${rightLabel(r.right)} on ${shortName(r.resource)} from ${book.nameOf(r.subject) ?? r.subject}`}
                  onClick={() => onRevoke(r)}
                >
                  Revoke
                </button>
              )}
            </td>
          </tr>
        ))}
      </DataTable>
    </div>
  );
}
