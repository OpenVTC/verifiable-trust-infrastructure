// A member's git rights and linked forge accounts, for the Members page
// (design §7.1: "Member detail gains a *Git rights* section and the linked
// GitHub account").
//
// Read from the same two signed Trust Tasks the Repos plugin renders —
// `git-ns/right/list/0.1` and `git-ns/account/list/0.1` — under the same
// query keys, so the two pages share one cache and one refresh. Both span
// every namespace and answer the community-administrator capability alone; a
// scoped administrator is told that rather than shown an empty column.
//
// Only *recorded* rights (and role-derived v0.1 grants, marked as such) are
// listed. Implied rights — an owner's commit right, a namespace admin's
// ownership of every repository — are not records, and are not repeated here.

import { Fragment, useMemo } from "react";
import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";

import { NamedDid } from "@/components/NamedDid";
import { useNameBook } from "@/lib/names";
import type {
  GitNsAccountList,
  GitNsAccountRow,
  GitNsRightList,
  GitNsRightRow,
} from "@/lib/wire-types";

import { fetchAccounts, fetchDrift, fetchRights, gitNsKeys } from "../repos/api";
import {
  expiresWithin,
  type GitNsSelfGrantWaived,
  rightLabel,
  rightRank,
  shortName,
  waiverFor,
} from "../repos/model";
import {
  BreakGlassChip,
  formatDay,
  readErrorMessage,
  repoPath,
  SelfGrantWaivedChip,
  ToneChip,
} from "../repos/ui";

/** A grant this close to its expiry is flagged. */
const EXPIRY_WARNING_DAYS = 14;

/** Rights and linked accounts, keyed by member DID. */
export interface MemberGitIndex {
  rights: Map<string, GitNsRightRow[]>;
  accounts: Map<string, GitNsAccountRow[]>;
}

/** Group both lists by DID: rights strongest first, then by resource;
 *  accounts by forge host. */
export function indexMemberGit(
  rights: GitNsRightList | undefined,
  accounts: GitNsAccountList | undefined,
): MemberGitIndex {
  const byRight = new Map<string, GitNsRightRow[]>();
  for (const r of rights?.rights ?? []) {
    const list = byRight.get(r.subject) ?? [];
    list.push(r);
    byRight.set(r.subject, list);
  }
  for (const list of byRight.values()) {
    list.sort(
      (a, b) => rightRank(a.right) - rightRank(b.right) || a.resource.localeCompare(b.resource),
    );
  }
  const byAccount = new Map<string, GitNsAccountRow[]>();
  for (const a of accounts?.accounts ?? []) {
    const list = byAccount.get(a.member) ?? [];
    list.push(a);
    byAccount.set(a.member, list);
  }
  for (const list of byAccount.values()) {
    list.sort((a, b) => a.account.forge.localeCompare(b.account.forge));
  }
  return { rights: byRight, accounts: byAccount };
}

/** Both reads, indexed. `error` is the first of them to fail. */
export function useMemberGit() {
  const rightsQ = useQuery({ queryKey: gitNsKeys.rights, queryFn: fetchRights });
  const accountsQ = useQuery({ queryKey: gitNsKeys.accounts, queryFn: fetchAccounts });
  const index = useMemo(
    () => indexMemberGit(rightsQ.data, accountsQ.data),
    [rightsQ.data, accountsQ.data],
  );
  return {
    index,
    isPending: rightsQ.isPending || accountsQ.isPending,
    error: rightsQ.error ?? accountsQ.error,
  };
}

/** `@bob-builds`, the forge id on hover: the id is authoritative,
 *  the login display only — logins are renamed and re-registered. */
function AccountLabel({ account }: { account: GitNsAccountRow }) {
  return (
    <span title={`${account.account.forge} id ${account.account.id}`}>
      <strong>@{account.account.login}</strong>
    </span>
  );
}

/** The Members list's "Git" cell: the member's strongest right and how many
 *  they hold, and the forge logins they linked. */
export function MemberGitCell({ did, index }: { did: string; index: MemberGitIndex }) {
  const rights = index.rights.get(did) ?? [];
  const accounts = index.accounts.get(did) ?? [];
  if (rights.length === 0 && accounts.length === 0) {
    return <span className="muted">—</span>;
  }
  const top = rights[0];
  const parts = [
    ...(top
      ? [
          <span
            key="rights"
            title={rights.map((r) => `${rightLabel(r.right)} · ${r.resource}`).join("\n")}
          >
            {rightLabel(top.right)}
            {rights.length > 1 && <span className="muted"> +{rights.length - 1}</span>}
          </span>,
        ]
      : []),
    ...accounts.map((a) => (
      <span key={a.account.forge} className="muted" title={`${a.account.forge} id ${a.account.id}`}>
        @{a.account.login}
      </span>
    )),
  ];
  return (
    <span>
      {parts.map((p, i) => (
        <Fragment key={p.key}>
          {i > 0 && " · "}
          {p}
        </Fragment>
      ))}
    </span>
  );
}

function RightRow({
  row,
  waived,
}: {
  row: GitNsRightRow;
  /** The records single-administrator mode's waiver made (VTI-APV-022). */
  waived?: readonly GitNsSelfGrantWaived[];
}) {
  const book = useNameBook();
  // A repository resource is host/owner/name; a namespace's is host/owner.
  const isRepo = row.resource.split("/").length >= 3;
  const soon = expiresWithin(row, EXPIRY_WARNING_DAYS);
  return (
    <tr>
      <td>
        {rightLabel(row.right)}
        {row.breakGlass && (
          <>
            {" "}
            <BreakGlassChip mark={row.breakGlass} />
          </>
        )}
        {waiverFor(waived, row) && (
          <>
            {" "}
            <SelfGrantWaivedChip mark={waiverFor(waived, row)} />
          </>
        )}
      </td>
      <td>
        {isRepo ? (
          <Link to={repoPath(row.resource)} title={row.resource}>
            {shortName(row.resource)}
          </Link>
        ) : (
          <span title={row.resource}>{shortName(row.resource)}</span>
        )}
      </td>
      <td>
        {row.origin === "roleDerived" ? (
          <span className="muted">Role-derived · configuration</span>
        ) : row.grantedBy ? (
          <>
            <NamedDid did={row.grantedBy} book={book} />
            {row.granterDeparted && (
              <>
                {" "}
                <ToneChip tone="warning" title="The granter has left the community">
                  departed
                </ToneChip>
              </>
            )}
          </>
        ) : (
          <span className="muted">—</span>
        )}
        {row.grantedAt && <span className="muted"> · {formatDay(row.grantedAt)}</span>}
      </td>
      <td>
        {row.expiresAt ? (
          soon ? (
            <ToneChip tone="warning" title={row.expiresAt}>
              {formatDay(row.expiresAt)}
            </ToneChip>
          ) : (
            formatDay(row.expiresAt)
          )
        ) : (
          <span className="muted">never</span>
        )}
      </td>
    </tr>
  );
}

/** The member page's "Git rights" card. */
export function MemberGitCard({ did }: { did: string }) {
  const { index, isPending, error } = useMemberGit();
  // The administrator's `git-ns/view`, shared with the Repos plugin's drift
  // read: it lists the self-grants single-administrator mode waived. A
  // failure only leaves them unflagged.
  const viewQ = useQuery({ queryKey: gitNsKeys.drift, queryFn: fetchDrift, retry: false });
  const rights = index.rights.get(did) ?? [];
  const accounts = index.accounts.get(did) ?? [];

  return (
    <section className="card" aria-labelledby="member-git-heading">
      <h3 id="member-git-heading">Git rights</h3>
      <p className="muted">
        Recorded rights in the community's git namespaces. Implied rights — an
        owner's commit right, a namespace admin's ownership of every repository —
        are not records and are not repeated here.
      </p>
      {isPending && <p className="muted">Loading…</p>}
      {error && <p className="muted">Could not load git rights: {readErrorMessage(error)}</p>}
      {!isPending && !error && (
        <>
          {rights.length === 0 ? (
            <p className="muted">Holds no git right.</p>
          ) : (
            <table className="data-table">
              <thead>
                <tr>
                  <th>Right</th>
                  <th>Resource</th>
                  <th>Granted by</th>
                  <th>Expires</th>
                </tr>
              </thead>
              <tbody>
                {rights.map((r) => (
                  <RightRow
                    key={`${r.right} ${r.resource} ${r.origin}`}
                    row={r}
                    waived={viewQ.data?.waived}
                  />
                ))}
              </tbody>
            </table>
          )}

          <h4>Linked forge accounts</h4>
          {accounts.length === 0 ? (
            <p className="muted">
              None linked. The member links one with{" "}
              <code>cnm git link --forge &lt;host&gt;</code>; until then they get no
              forge role, and contribute by fork pull requests.
            </p>
          ) : (
            <dl>
              {accounts.map((a) => (
                <Fragment key={a.account.forge}>
                  <dt>{a.account.forge}</dt>
                  <dd>
                    <AccountLabel account={a} />
                    <span className="muted">
                      {" "}
                      · id <code>{a.account.id}</code>
                      {a.linkedAt && <> · linked {formatDay(a.linkedAt)}</>}
                    </span>
                    {!a.memberCurrent && (
                      <>
                        {" "}
                        <ToneChip
                          tone="warning"
                          title="The member's access has lapsed: the account stays theirs, but it gets no forge role"
                        >
                          not current — no forge role
                        </ToneChip>
                      </>
                    )}
                  </dd>
                </Fragment>
              ))}
            </dl>
          )}
          {accounts.length > 0 && (
            <p className="muted">
              Only the member can unlink an account — the link is theirs, and this
              console cannot sign as them. They run{" "}
              <code>cnm git unlink --forge &lt;host&gt;</code>; the bridge then
              withdraws the forge roles it gave that account, and their rights stay.
            </p>
          )}
          <p className="muted">
            Rights are granted and revoked on the <Link to="/repos">Repos</Link> page.
          </p>
        </>
      )}
    </section>
  );
}
