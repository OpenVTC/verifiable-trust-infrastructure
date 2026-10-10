// Members plugin — list + detail (read-only).
//
// The list reads every page of `vtc/members/list/0.1` and searches, filters
// and sorts it in the browser (`members/list.ts`); the detail view reads
// `vtc/members/show/0.1`.
//
// The detail view also answers "what does this member hold from us, and what
// have they published?" — which nothing in this console could answer before.
// Two sources, because `members/show/0.1` cannot be the one:
//
//   - the trust graph (`relationships/graph/0.2`) for whether this member's
//     membership edge is complete. The graph already computes it, so reading it
//     here keeps one definition of "complete" rather than a second one drifting
//     alongside the first.
//   - `relationships/list/0.2` for the relationship credentials naming this
//     member, bodies included.
//
// The membership credential, role VAC and member-issued VMC *bodies* come from
// a third source, `members/credentials/0.1` (#1215): the `members/show/0.1`
// response is `additionalProperties: false` and its own text says "The
// credential body is not echoed here", so the bodies needed a task of their
// own rather than a field added to the shared row. That task also states
// `memberVmcBound`, and where it is false the Credentials card lays out the
// evidence — which grant is on record, which digest the acknowledgement names —
// so the operator can see why before reaching for "Request member VMC".
//
// The list and the detail view also show each member's git rights and linked
// forge accounts (design §7.1, `members/MemberGit.tsx`), read from the Repos
// plugin's console projections under its query keys.

import { useMemo, useState } from "react";
import {
  useMutation,
  useQuery,
  useQueryClient,
} from "@tanstack/react-query";
import { Route, Routes, useNavigate, useParams } from "react-router-dom";
import {
  ArrowLeft,
  ArrowRight,
  Check,
  Minus,
  Ticket,
  Trash2,
  Users as UsersIcon,
} from "lucide-react";

import {
  fetchMemberRelationships,
  fetchRelationshipsGraph,
  postSignedRead,
  postSignedTrustTask,
  type MemberRelationship,
  type RelationshipsGraph,
} from "@/lib/api";
import { CopyButton } from "@/components/CopyButton";
import { DidText } from "@/components/DidText";
import { DataTable, useSortedRows, type Column } from "@/components/DataTable";
import { EmptyState } from "@/components/EmptyState";
import { Field } from "@/components/Field";
import { PageHeader } from "@/components/PageHeader";
import { ErrorOrParked } from "@/components/ParkedNotice";
import { useConfirm } from "@/components/ConfirmDialog";
import { formatIso as formatDate, shortenDid } from "@/lib/format";
import { changeAclRole } from "@/lib/acl";
import { adminRemoveMember } from "@/lib/member-removal";
import { gestureFromConfirm, type ConfirmGesture } from "@/lib/signed-act";

const TRUST_TASK_LIST =
  "https://trusttasks.org/spec/vtc/members/list/0.1";
const TRUST_TASK_SHOW =
  "https://trusttasks.org/spec/vtc/members/show/0.1";
// Promotion is a **role transition**, so it goes to the task defined for role
// transitions. `vtc/members/update` declares `adminRoleForbidden` and refuses
// `role: admin` outright (#1645): it is a metadata update, and the step-up it
// used to carry bounded that one route while `acl/change-role` reached the
// same ACL row with none. The gate now sits on the transition — a host
// invariant in the role-change ceremony — and the passkey gesture below is
// what satisfies it. It is sent by `changeAclRole` (`lib/acl.ts`).
const TRUST_TASK_REMOVED =
  "https://trusttasks.org/spec/vtc/members/removed/0.1";
const TRUST_TASK_PURGE =
  "https://trusttasks.org/spec/vtc/members/purge/0.1";
const TRUST_TASK_CREDENTIALS =
  "https://trusttasks.org/spec/vtc/members/credentials/0.1";
const TRUST_TASK_REQUEST_VMC =
  "https://trusttasks.org/spec/vtc/members/solicit-vmc/0.1";
// Naming a vetter issues a revocable vetter role credential; it is withdrawn
// like any endorsement, so listing and revoking reuse those tasks.
const TRUST_TASK_VETTER_GRANT =
  "https://trusttasks.org/spec/vtc/vetting/vetters/grant/0.1";
const TRUST_TASK_ENDORSEMENT_LIST =
  "https://trusttasks.org/spec/vtc/endorsements/list/0.1";
const TRUST_TASK_ENDORSEMENT_REVOKE =
  "https://trusttasks.org/spec/vtc/endorsements/revoke/0.1";
// A vetter grant's row in the endorsement list: its `typeUri` is the VAC
// action the grant confers (the credential itself is a community-issued VAC).
const VETTER_GRANT_ROW_TYPE = "role:vetter";
const VETTER_ROLE = "vetter";
// The endorsement list has no subject filter; walking it stops here.
const MAX_ENDORSEMENT_PAGES = 50;

import { useNameBook } from "@/lib/names";
import { MemberGitCard, MemberGitCell, useMemberGit } from "@/plugins/members/MemberGit";
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
import { rightLabel, rightRank } from "@/plugins/repos/model";
import { ApproverDevicesCard } from "@/plugins/members/StepUpApprovers";
import { StepUpPasskeysCard } from "@/plugins/members/StepUpPasskeys";
import { readErrorMessage } from "@/plugins/repos/ui";
import {
  claimedDigest,
  credentialDocuments,
  credentialId,
  unboundReason,
} from "@/lib/member-credentials";
import type {
  EndorsementRow,
  EndorsementsPage,
  MemberCredentials,
  MemberEnvelope,
  MemberRow,
  MembersPage,
  RemovedMemberRow,
  RemovedMembersResponse,
  RequestVmcResponse,
  VetterGrantResponse,
} from "@/lib/wire-types";

/** This member's vetter grants, revoked ones included — picked out of the
 * endorsement list, which cannot filter by subject. */
async function fetchVetterGrants(did: string): Promise<EndorsementRow[]> {
  const grants: EndorsementRow[] = [];
  let cursor: string | null = null;
  for (let page = 0; page < MAX_ENDORSEMENT_PAGES; page++) {
    const body: EndorsementsPage = await postSignedRead<EndorsementsPage>(
      TRUST_TASK_ENDORSEMENT_LIST,
      { limit: 200, ...(cursor ? { cursor } : {}) },
    );
    grants.push(
      ...body.items.filter(
        (e) =>
          e.typeUri === VETTER_GRANT_ROW_TYPE &&
          e.subjectDid === did &&
          (e.claim as { role?: unknown } | null)?.role === VETTER_ROLE,
      ),
    );
    cursor = body.nextCursor ?? null;
    if (!cursor) break;
  }
  return grants;
}

/** A grant still in force: not revoked and not past its `validUntil`. */
function isLiveGrant(grant: EndorsementRow): boolean {
  if (grant.revokedAt) return false;
  const expires = grant.issued.expiresAt;
  return !expires || new Date(expires).getTime() > Date.now();
}

async function grantVetterRole(did: string): Promise<VetterGrantResponse> {
  return postSignedTrustTask<VetterGrantResponse>(TRUST_TASK_VETTER_GRANT, {
    memberDid: did,
  });
}

async function revokeVetterRole(endorsementId: string): Promise<void> {
  await postSignedTrustTask<unknown>(TRUST_TASK_ENDORSEMENT_REVOKE, {
    endorsementId,
  });
}
async function fetchMembers(params: {
  cursor: string | null;
  role: string | null;
  limit: number;
}): Promise<MembersPage> {
  return postSignedRead<MembersPage>(TRUST_TASK_LIST, {
    limit: params.limit,
    ...(params.cursor ? { cursor: params.cursor } : {}),
    ...(params.role ? { role: params.role } : {}),
  });
}

async function fetchMember(did: string): Promise<MemberRow> {
  const body = await postSignedRead<MemberEnvelope>(TRUST_TASK_SHOW, { did });
  return body.member;
}

/** The membership pair's bodies for one member. Admin-only, and audited
 * server-side: every call records that an administrator read them. A signed
 * read, from this browser's console key. */
async function fetchMemberCredentials(did: string): Promise<MemberCredentials> {
  return postSignedRead<MemberCredentials>(TRUST_TASK_CREDENTIALS, { did });
}

/** Ask an active member to issue + send their reciprocal VMC (member →
 * community half of the pair). The member answers asynchronously over the
 * `members/vmc/1.0` DIDComm surface; this only dispatches the request. */
async function requestMemberVmc(did: string): Promise<RequestVmcResponse> {
  return postSignedTrustTask<RequestVmcResponse>(TRUST_TASK_REQUEST_VMC, { memberDid: did });
}

async function promoteToAdmin(args: {
  did: string;
  fromRole: string;
  confirmGesture: ConfirmGesture;
}): Promise<void> {
  // A signed `acl/change-role`. The VTC asks for a passkey gesture bound to
  // this one promotion, which the operator confirms as its own click.
  // `fromRole` is a compare-and-swap guard, not decoration: the role we render
  // is a read, and the daemon refuses the change if the row has moved since.
  // A promotion that needs other administrators' approval is parked, and
  // `changeAclRole` throws it as a `ParkedAction`.
  await changeAclRole(
    { subject: args.did, fromRole: args.fromRole, toRole: "admin" },
    args.confirmGesture,
  );
}

// A signed document (the payload carries `did`). Removing an administrator
// takes a passkey gesture, and another unrestricted administrator a third
// administrator's consent (VTI-APV-019) — see `lib/member-removal.ts`.
const adminRemove = (args: {
  did: string;
  reason: string;
  confirmGesture: ConfirmGesture;
}): Promise<void> =>
  adminRemoveMember({ did: args.did, reason: args.reason }, args.confirmGesture);

async function fetchRemovedMembers(): Promise<RemovedMemberRow[]> {
  const body = await postSignedRead<RemovedMembersResponse>(TRUST_TASK_REMOVED, {});
  return body.removed;
}

async function purgeMember(did: string): Promise<void> {
  // Super-admin only, checked against the signer's ACL row resolved *now*
  // — so an operator demoted since sign-in is refused.
  await postSignedTrustTask<unknown>(TRUST_TASK_PURGE, { did });
}

type RemovedSortKey = "did" | "removed" | "slot";

const REMOVED_COLUMNS: readonly Column<RemovedSortKey>[] = [
  { key: "did", label: "DID", sortKey: "did" },
  { key: "removed", label: "Removed", sortKey: "removed" },
  { key: "slot", label: "Revocation slot", sortKey: "slot" },
  { key: "actions", label: "" },
];

function removedValue(m: RemovedMemberRow, key: RemovedSortKey): SortValue {
  switch (key) {
    case "did":
      return m.did;
    case "removed":
      return Date.parse(m.removedAt) || null;
    case "slot":
      return m.statusListIndex ?? null;
  }
}

/// Departed members whose Member row was kept as a tombstone (Tombstone /
/// Historical disposition). They have no ACL, so they don't show in the active
/// list — surfaced here so operators can see who left and permanently purge the
/// lingering rows. Purge is super-admin only (the button 403s otherwise).
function RemovedMembers() {
  const queryClient = useQueryClient();
  const confirm = useConfirm();
  const query = useQuery({
    queryKey: ["members-removed"],
    queryFn: fetchRemovedMembers,
  });

  const purgeMutation = useMutation({
    mutationFn: purgeMember,
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["members-removed"] });
      void queryClient.invalidateQueries({ queryKey: ["members"] });
    },
  });

  const rows = query.data ?? [];
  const sorted = useSortedRows(rows, removedValue, { initialDir: { removed: "desc" } });
  if (query.isPending || rows.length === 0) {
    // Hide the section entirely when there are no departed members.
    return null;
  }

  return (
    <section className="card">
      <h3>Removed members</h3>
      <p className="muted">
        Departed members whose record was retained (tombstone). They are no
        longer members; permanently delete the row to clean up.
      </p>
      <DataTable columns={REMOVED_COLUMNS} sort={sorted.sort} onSort={sorted.onSort}>
        {sorted.rows.map((m) => (
          <tr key={m.did}>
            <td>
              <code>{m.did}</code>
            </td>
            <td>{formatDate(m.removedAt)}</td>
            <td>{m.statusListIndex ?? "—"}</td>
            <td>
              <button
                type="button"
                className="secondary destructive"
                disabled={purgeMutation.isPending}
                onClick={async () => {
                  const ok = await confirm({
                    title: "Permanently delete member?",
                    message: `This removes the retained record for ${m.did}. This cannot be undone.`,
                    confirmLabel: "Delete permanently",
                    destructive: true,
                  });
                  if (ok) purgeMutation.mutate(m.did);
                }}
              >
                <Trash2 size={16} strokeWidth={1.75} /> Delete permanently
              </button>
            </td>
          </tr>
        ))}
      </DataTable>
      {purgeMutation.error && (
        <p className="error">
          {(purgeMutation.error as Error).message}
        </p>
      )}
    </section>
  );
}


export function Members() {
  return (
    <Routes>
      <Route index element={<MembersList />} />
      <Route path=":did" element={<MemberDetail />} />
    </Routes>
  );
}

/** Members read per page, and the most pages read: the list is searched and
 *  sorted in the browser, so it reads the whole community up to this cap. */
const MEMBERS_PAGE = 200;
const MAX_MEMBER_PAGES = 25;
/** Rows rendered per page of the (already filtered and sorted) table. */
const ROWS_PER_PAGE = 50;

/** Every current member, page by page, and whether the cap cut it short. */
async function fetchAllMembers(): Promise<{ items: MemberRow[]; truncated: boolean }> {
  const items: MemberRow[] = [];
  let cursor: string | null = null;
  for (let page = 0; page < MAX_MEMBER_PAGES; page++) {
    const body = await fetchMembers({ cursor, role: null, limit: MEMBERS_PAGE });
    items.push(...body.items);
    cursor = body.nextCursor ?? null;
    if (!cursor) return { items, truncated: false };
  }
  return { items, truncated: true };
}

type MemberSortKey = "name" | "did" | "role" | "joined" | "personhood" | "git";

/** Joined and personhood read best newest / asserted first. */
const INITIAL_DIR: Record<MemberSortKey, SortDir> = {
  name: "asc",
  did: "asc",
  role: "asc",
  joined: "desc",
  personhood: "desc",
  git: "asc",
};

/** What each column means, on hover of its (i). */
const MEMBER_COLUMN_TIPS: Partial<Record<MemberSortKey, string>> = {
  name: "The member's label in this community: set by an administrator, or by the member for themselves. Not an identity claim.",
  did: "The member's decentralized identifier. The abbreviation drops the opaque hash and long host subdomains, never the path; hover for the whole DID, or copy it, or show it as a QR code for a phone.",
  role: "The member's community role — what they may do here. Administrative authority is on the Access control page.",
  joined: "When the member was admitted.",
  personhood:
    "Whether the member presented a personhood credential this community accepts (a proof that a unique person stands behind the DID). A dash means none was asserted.",
  git: "The member's strongest git right in any namespace this community governs, how many more they hold, and the forge accounts they linked.",
};

function MembersList() {
  const [search, setSearch] = useState("");
  const [roleFilter, setRoleFilter] = useState("");
  // `null`: no column chosen — newest first, or best match while searching.
  const [sort, setSort] = useState<SortState<MemberSortKey> | null>(null);
  const [page, setPage] = useState(0);
  const book = useNameBook();

  const query = useQuery({
    queryKey: ["members", "all"],
    queryFn: fetchAllMembers,
  });

  // Git rights and linked forge accounts (design §7.1). Read once for the
  // whole community and indexed by DID, rather than once per row; a failure
  // (a scoped administrator cannot read them) drops the column and says why.
  const git = useMemberGit();
  const showGit = !git.error;
  const columns = showGit ? 6 : 5;

  const all = useMemo(() => query.data?.items ?? [], [query.data]);
  const roles = useMemo(() => [...new Set(all.map((m) => m.role))].sort(), [all]);

  const rows = useMemo(() => {
    const terms = searchTerms(search);
    const nameOf = (m: MemberRow) => m.label ?? book.nameOf(m.did) ?? null;
    const scored: { m: MemberRow; score: number }[] = [];
    for (const m of all) {
      if (roleFilter && m.role !== roleFilter) continue;
      const rights = git.index.rights.get(m.did) ?? [];
      const accounts = git.index.accounts.get(m.did) ?? [];
      const score = matchScore(terms, {
        short: [
          nameOf(m) ?? "",
          m.role,
          didHandle(m.did),
          ...accounts.map((a) => a.account.login),
          ...rights.map((r) => rightLabel(r.right)),
        ],
        long: [m.did, ...rights.map((r) => r.resource)],
      });
      if (score !== null) scored.push({ m, score });
    }
    const value = (m: MemberRow, key: MemberSortKey): SortValue => {
      switch (key) {
        case "name":
          return nameOf(m);
        case "did":
          return m.did;
        case "role":
          return m.role;
        case "joined":
          return Date.parse(m.joinedAt) || null;
        case "personhood":
          return m.personhood ? 1 : 0;
        case "git": {
          const top = git.index.rights.get(m.did)?.[0];
          return top ? rightRank(top.right) : null;
        }
      }
    };
    const byJoined = (a: MemberRow, b: MemberRow) =>
      compareValues(value(a, "joined"), value(b, "joined"), "desc");
    scored.sort((a, b) =>
      sort
        ? compareValues(value(a.m, sort.key), value(b.m, sort.key), sort.dir) || byJoined(a.m, b.m)
        : b.score - a.score || byJoined(a.m, b.m),
    );
    return scored.map((s) => s.m);
  }, [all, roleFilter, search, sort, git.index, book]);

  const pages = Math.max(1, Math.ceil(rows.length / ROWS_PER_PAGE));
  const current = Math.min(page, pages - 1);
  const visible = rows.slice(current * ROWS_PER_PAGE, (current + 1) * ROWS_PER_PAGE);
  const onSort = (key: MemberSortKey) => {
    setSort((s) => nextSort(s, key, INITIAL_DIR[key]));
    setPage(0);
  };
  // Name leads: it is what an operator is looking for. The DID stays in its
  // own column rather than being replaced by the name — a member you cannot
  // check against an identifier is a member you cannot audit.
  const column = (key: MemberSortKey, label: string): Column<MemberSortKey> => ({
    key,
    label,
    sortKey: key,
    tip: MEMBER_COLUMN_TIPS[key],
    className: key === "did" ? "members-did" : undefined,
  });
  const tableColumns: Column<MemberSortKey>[] = [
    column("name", "Name"),
    column("did", "DID"),
    column("role", "Role"),
    column("joined", "Joined"),
    column("personhood", "Personhood"),
    ...(showGit ? [column("git", "Git")] : []),
  ];

  return (
    <section className="page">
      <PageHeader
        title="Members"
        count={query.isSuccess ? all.length : undefined}
        countLabel={
          query.isSuccess ? `${all.length} member${all.length === 1 ? "" : "s"}` : undefined
        }
      />

      <section className="card">
        <div className="toolbar members-toolbar">
          <Field label="Search" inline className="members-search">
            <input
              type="search"
              placeholder="Name, DID, role or forge login"
              value={search}
              onChange={(e) => {
                setSearch(e.target.value);
                setPage(0);
              }}
            />
          </Field>
          <Field label="Role" inline>
            <select
              value={roleFilter}
              onChange={(e) => {
                setRoleFilter(e.target.value);
                setPage(0);
              }}
            >
              <option value="">All roles</option>
              {roles.map((r) => (
                <option key={r} value={r}>
                  {r}
                </option>
              ))}
            </select>
          </Field>
        </div>
      </section>

      {query.error && (
        <section className="card error">
          <h3>Failed to load members</h3>
          <p>{(query.error as Error).message}</p>
        </section>
      )}

      <section className="card">
        {git.error && (
          <p className="muted">
            Git rights are not shown: {readErrorMessage(git.error)}.
          </p>
        )}
        {query.data?.truncated && (
          <p className="muted">
            Only the first {MEMBERS_PAGE * MAX_MEMBER_PAGES} members were read; search and sort
            cover those.
          </p>
        )}
        <div className="table-scroll">
          <DataTable columns={tableColumns} sort={sort} onSort={onSort}>
            {query.isPending && (
              <tr>
                <td colSpan={columns}>Loading…</td>
              </tr>
            )}
            {query.isSuccess && rows.length === 0 && (
              <tr>
                <td colSpan={columns}>
                  {all.length === 0 ? (
                    <EmptyState icon={UsersIcon} title="No members yet">
                      Members appear here once join requests are approved.
                    </EmptyState>
                  ) : (
                    <EmptyState icon={UsersIcon} title="No members match">
                      Clear the search or choose another role to widen the result.
                    </EmptyState>
                  )}
                </td>
              </tr>
            )}
            {visible.map((m) => (
              <tr key={m.did}>
                <td>
                  {m.label ?? book.nameOf(m.did) ?? <span className="muted">—</span>}
                  {m.joinedViaInvitation && (
                    <Ticket
                      size={14}
                      strokeWidth={1.75}
                      aria-label="Joined via invitation"
                      className="status-icon ok members-invited"
                    />
                  )}
                </td>
                <td className="members-did">
                  <DidText did={m.did} to={encodeURIComponent(m.did)} />
                </td>
                <td>
                  <code>{m.role}</code>
                </td>
                <td>{formatDate(m.joinedAt)}</td>
                <td>
                  {m.personhood ? (
                    <Check
                      size={16}
                      strokeWidth={1.75}
                      aria-label="Asserted"
                      className="status-icon ok"
                    />
                  ) : (
                    <Minus
                      size={16}
                      strokeWidth={1.75}
                      aria-label="Not asserted"
                      className="status-icon muted"
                    />
                  )}
                </td>
                {showGit && (
                  <td>
                    {git.isPending ? (
                      <span className="muted">…</span>
                    ) : (
                      <MemberGitCell did={m.did} index={git.index} />
                    )}
                  </td>
                )}
              </tr>
            ))}
          </DataTable>
        </div>

        {query.isSuccess && (
          <div className="pagination">
            <span className="muted" aria-live="polite">
              {rows.length === all.length
                ? `${all.length} member${all.length === 1 ? "" : "s"}`
                : `${rows.length} of ${all.length} members`}
              {pages > 1 &&
                ` · showing ${current * ROWS_PER_PAGE + 1}–${Math.min(rows.length, (current + 1) * ROWS_PER_PAGE)}`}
            </span>
            {pages > 1 && (
              <>
                <button
                  type="button"
                  className="secondary"
                  disabled={current === 0}
                  onClick={() => setPage(current - 1)}
                >
                  <ArrowLeft size={12} aria-hidden="true" /> Previous
                </button>
                <button
                  type="button"
                  className="secondary"
                  disabled={current >= pages - 1}
                  onClick={() => setPage(current + 1)}
                >
                  Next <ArrowRight size={12} aria-hidden="true" />
                </button>
              </>
            )}
          </div>
        )}
      </section>

      <RemovedMembers />
    </section>
  );
}

/** A stored credential, collapsed, with its JSON one click away — the same
 * `<details>` + copy pattern the published-relationships list uses. */
function CredentialBody({ label, doc }: { label: string; doc: unknown }) {
  const json = JSON.stringify(doc, null, 2);
  const id = credentialId(doc);
  return (
    <li>
      <strong>{label}</strong>
      {id && (
        <span className="muted">
          {" "}
          · <code>{id}</code>
        </span>
      )}
      <CopyButton
        value={json}
        label="Copy credential JSON"
        successMessage="Credential copied"
      />
      <details>
        <summary className="muted">Credential</summary>
        <pre className="member-credential-json">{json}</pre>
      </details>
    </li>
  );
}

/** The bodies from `members/credentials/0.1`, and — where the acknowledgement
 * is not bound to the grant — the evidence for why. */
function MemberCredentialDocuments({
  query,
}: {
  query: { isPending: boolean; isError: boolean; data?: MemberCredentials };
}) {
  if (query.isPending) return <p className="muted">Loading credentials…</p>;
  if (query.isError || !query.data) {
    return <p className="muted">Could not load this member's credentials.</p>;
  }
  const c = query.data;
  const docs = credentialDocuments(c);
  const reason = unboundReason(c);
  const digest = claimedDigest(c.memberVmc);
  const grantId = credentialId(c.membershipCredential);

  return (
    <>
      <h4>Documents</h4>
      {docs.length === 0 ? (
        <EmptyState compact title="This community holds no credential documents for this member." />
      ) : (
        <ul className="member-credential-list">
          {docs.map((d) => (
            <CredentialBody key={d.key} label={d.label} doc={d.doc} />
          ))}
        </ul>
      )}

      {reason && (
        <div className="finding warn">
          <strong>Why the acknowledgement is not bound to the grant</strong>
          <dl>
            <dt>Grant on record</dt>
            <dd>
              {c.membershipCredential ? (
                <code>{grantId ?? "(credential without an id)"}</code>
              ) : (
                <span className="muted">
                  none — this grant was issued before credential bodies were
                  kept, so there is nothing to check an acknowledgement against
                </span>
              )}
            </dd>
            <dt>Acknowledgement names</dt>
            <dd>
              {!c.memberVmc ? (
                <span className="muted">no acknowledgement received</span>
              ) : digest ? (
                <>
                  <code>{digest.value}</code>
                  <span className="muted"> in {digest.property}</span>
                </>
              ) : (
                <span className="muted">
                  no digest — the member's client predates the digest
                  requirement, so it does not say which grant it acknowledges
                </span>
              )}
            </dd>
          </dl>
          <span className="muted">
            {reason === "no-acknowledgement" &&
              "The member has not sent their half of the pair. Request it below."}
            {reason === "no-digest" &&
              "Without a digest the acknowledgement cannot be tied to this grant. Request a fresh one below; a current client binds it."}
            {reason === "no-grant" &&
              "The acknowledgement names a digest, but no grant body was held to check it against when it arrived. Request a fresh one below to check it against the grant on record."}
            {reason === "unchecked" &&
              "The acknowledgement arrived before its grant's body was kept, so the digest was never checked. Request a fresh one below."}
          </span>
        </div>
      )}
    </>
  );
}

function MemberDetail() {
  const { did = "" } = useParams<{ did: string }>();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const confirm = useConfirm();
  const decoded = decodeURIComponent(did);
  const [removeReason, setRemoveReason] = useState("");
  const book = useNameBook();

  const query = useQuery({
    queryKey: ["member", decoded],
    queryFn: () => fetchMember(decoded),
    enabled: decoded.length > 0,
  });

  // Whether this member's membership edge is complete comes from the graph
  // rather than being recomputed here. One definition, one answer — a second
  // one living in this file would be free to disagree with the graph the
  // operator is looking at on the next page.
  const graph = useQuery<RelationshipsGraph>({
    queryKey: ["relationships-graph"],
    queryFn: fetchRelationshipsGraph,
    enabled: decoded.length > 0,
  });

  const credentials = useQuery<MemberCredentials>({
    queryKey: ["member-credentials", decoded],
    queryFn: () => fetchMemberCredentials(decoded),
    enabled: decoded.length > 0,
  });

  const relationships = useQuery<{ items: MemberRelationship[] }>({
    queryKey: ["member-relationships", decoded],
    queryFn: () => fetchMemberRelationships(decoded),
    enabled: decoded.length > 0,
  });

  // The membership edge is the one joining this member to the community. The
  // community is the endpoint that is not the member — no need to know its DID
  // separately, and it stays right if the community ever rotates its own.
  const membershipEdge = graph.data?.edges.find(
    (e) =>
      e.endpoints.includes(decoded) &&
      e.halves.some((h) => h.issuerDid !== decoded && h.subjectDid === decoded),
  );

  // The name the Members list shows for this member, else its DID shortened.
  const displayName =
    query.data?.label ?? book.nameOf(decoded) ?? shortenDid(decoded);

  const confirmGesture = gestureFromConfirm(confirm);
  const promoteMutation = useMutation({
    mutationFn: (args: { did: string; fromRole: string }) =>
      promoteToAdmin({ ...args, confirmGesture }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["member", decoded] });
      void queryClient.invalidateQueries({ queryKey: ["members"] });
    },
  });

  const removeMutation = useMutation({
    mutationFn: (args: { did: string; reason: string }) =>
      adminRemove({ ...args, confirmGesture }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["members"] });
      navigate("..");
    },
  });

  const requestVmcMutation = useMutation({
    mutationFn: requestMemberVmc,
  });

  const vetterGrants = useQuery({
    queryKey: ["member-vetter-grants", decoded],
    queryFn: () => fetchVetterGrants(decoded),
    enabled: decoded.length > 0,
  });
  const liveGrant = vetterGrants.data?.find(isLiveGrant);

  const invalidateVetterGrants = () => {
    void queryClient.invalidateQueries({
      queryKey: ["member-vetter-grants", decoded],
    });
  };
  const grantVetterMutation = useMutation({
    mutationFn: grantVetterRole,
    onSuccess: invalidateVetterGrants,
  });
  const revokeVetterMutation = useMutation({
    mutationFn: revokeVetterRole,
    onSuccess: invalidateVetterGrants,
  });

  return (
    <section className="page">
      <button type="button" className="link" onClick={() => navigate("..")}>
        <ArrowLeft size={14} aria-hidden="true" /> Back to members
      </button>
      <PageHeader trail={[{ label: displayName }]} title={displayName} />

      {query.isPending && <p>Loading…</p>}
      {query.error && (
        <section className="card error">
          <h3>Failed to load member</h3>
          <p>{(query.error as Error).message}</p>
        </section>
      )}

      {query.data && (
        <>
          <section className="card">
            <h3>Identity</h3>
            <dl>
              <dt>DID</dt>
              <dd>
                <code>{query.data.did}</code>
              </dd>
              <dt>Role</dt>
              <dd>
                <code>{query.data.role}</code>
              </dd>
              <dt>Label</dt>
              <dd>{query.data.label ?? "—"}</dd>
              <dt>Joined</dt>
              <dd>
                <code>{query.data.joinedAt}</code>
              </dd>
            </dl>
          </section>

          <section className="card">
            <h3>Personhood</h3>
            <dl>
              <dt>Asserted</dt>
              <dd>{query.data.personhood ? "Yes" : "No"}</dd>
              {query.data.personhoodAssertedAt && (
                <>
                  <dt>Asserted at</dt>
                  <dd>
                    <code>{query.data.personhoodAssertedAt}</code>
                  </dd>
                </>
              )}
            </dl>
          </section>

          <section className="card">
            <h3>Credentials</h3>
            <dl>
              <dt>Status-list index</dt>
              <dd>
                {query.data.statusListIndex === null
                  ? "—"
                  : query.data.statusListIndex}
              </dd>
              <dt>Current VMC</dt>
              <dd>
                {query.data.currentVmcId ? (
                  <code>{query.data.currentVmcId}</code>
                ) : (
                  "—"
                )}
              </dd>
              <dt>Current role VAC</dt>
              <dd>
                {query.data.currentRoleVacId ? (
                  <code>{query.data.currentRoleVacId}</code>
                ) : (
                  "—"
                )}
              </dd>
              <dt>Member VMC (member → VTC)</dt>
              <dd>
                {query.data.memberVmcId ? (
                  <>
                    <code>{query.data.memberVmcId}</code>
                    {query.data.memberVmcReceivedAt && (
                      <span className="muted">
                        {" "}
                        · received {formatDate(query.data.memberVmcReceivedAt)}
                      </span>
                    )}
                  </>
                ) : (
                  <span className="muted">
                    not received — the member hasn't sent their reciprocal VMC
                  </span>
                )}
              </dd>
              <dt>Membership edge</dt>
              <dd>
                {graph.isPending ? (
                  <span className="muted">…</span>
                ) : membershipEdge?.complete ? (
                  <>
                    <Check size={14} aria-hidden="true" /> complete — both
                    credentials stand
                  </>
                ) : query.data.memberVmcId ? (
                  <span className="muted">
                    incomplete — the member's credential is stored, but its{" "}
                    <code>digest</code> was not verified against the membership
                    credential we issued. It may predate that binding, or the
                    grant may have been re-issued since. Request a fresh one
                    below.
                  </span>
                ) : (
                  <span className="muted">
                    half-edge — this community has asserted the membership and
                    the member has not acknowledged it
                  </span>
                )}
              </dd>
            </dl>

            <MemberCredentialDocuments query={credentials} />

            {/* The action belongs to the row above it, not to Admin
             * actions where it used to sit. Membership edge is the thing
             * this button changes, and its own copy already says "request
             * a fresh one below" — which was pointing four cards down,
             * past Published relationships, Disposition and Vetter role,
             * to a block otherwise about promoting and removing people.
             * Asking a member for their half of the pair is neither. */}
            <div className="form-actions">
              <button
                type="button"
                className="secondary"
                disabled={requestVmcMutation.isPending}
                title="Ask this member to issue and send their reciprocal VMC (member → VTC half of the membership pair)"
                onClick={() => requestVmcMutation.mutate(decoded)}
              >
                {requestVmcMutation.isPending
                  ? "Requesting…"
                  : query.data.memberVmcId
                    ? "Re-request member VMC"
                    : "Request member VMC"}
              </button>
            </div>

            {requestVmcMutation.error && (
              <div className="finding error" role="alert">
                <strong>Request failed</strong>
                <p>{(requestVmcMutation.error as Error).message}</p>
              </div>
            )}
            {requestVmcMutation.isSuccess && (
              <p className="muted">
                Requested the member's reciprocal VMC. They'll send it back
                asynchronously; refresh to see it above.
              </p>
            )}
          </section>

          <section className="card">
            <h3>Published relationships</h3>
            <p className="muted">
              Relationship credentials (VRCs) naming this member, in either
              direction. These are the member's own edges to other members —
              separate from their membership edge with this community.
            </p>
            {relationships.isPending && <p className="muted">Loading…</p>}
            {relationships.isError && (
              <p className="muted">Could not load this member's credentials.</p>
            )}
            {relationships.data &&
              (relationships.data.items.length === 0 ? (
                <EmptyState
                  compact
                  title="None published. A member's relationships are private to them until they publish an edge here."
                />
              ) : (
                <ul className="member-credential-list">
                  {relationships.data.items.map((r) => (
                    <li key={r.id}>
                      <code>{shortenDid(r.issuerDid)}</code> →{" "}
                      <code>{shortenDid(r.subjectDid)}</code>
                      <span className="muted"> · {formatDate(r.createdAt)}</span>
                      <CopyButton
                        value={JSON.stringify(r.vrcJsonld, null, 2)}
                        label="Copy credential JSON"
                        successMessage="Credential copied"
                      />
                      <details>
                        <summary className="muted">Credential</summary>
                        <pre className="member-credential-json">
                          {JSON.stringify(r.vrcJsonld, null, 2)}
                        </pre>
                      </details>
                    </li>
                  ))}
                </ul>
              ))}
          </section>

          <MemberGitCard did={decoded} />

          <StepUpPasskeysCard did={decoded} />

          <ApproverDevicesCard did={decoded} />

          <section className="card">
            <h3>Disposition + consent</h3>
            <dl>
              <dt>Publish consent</dt>
              <dd>{query.data.publishConsent ? "Yes" : "No"}</dd>
              <dt>Departure preference</dt>
              <dd>
                <code>{query.data.departurePreference}</code>
              </dd>
            </dl>
          </section>

          <section className="card">
            <h3>Vetter role</h3>
            <p className="muted">
              A vetter's identity-vetting statements count toward an
              applicant's admission. Granting issues this member a revocable
              vetter role credential, which they show to applicants.
            </p>
            {vetterGrants.isPending && <p className="muted">Loading…</p>}
            {vetterGrants.isError && (
              <p className="muted">Could not load this member's grants.</p>
            )}
            {vetterGrants.data &&
              (liveGrant ? (
                <dl>
                  <dt>Credential</dt>
                  <dd>
                    <code>{liveGrant.issued.credentialId}</code>
                  </dd>
                  <dt>Granted</dt>
                  <dd>
                    {liveGrant.issued.issuedAt
                      ? formatDate(liveGrant.issued.issuedAt)
                      : "—"}
                  </dd>
                  <dt>Valid until</dt>
                  <dd>
                    {liveGrant.issued.expiresAt
                      ? formatDate(liveGrant.issued.expiresAt)
                      : "—"}
                  </dd>
                  <dt>Revocation slot</dt>
                  <dd>{liveGrant.statusListIndex}</dd>
                </dl>
              ) : (
                <EmptyState compact title="Not a vetter." />
              ))}

            {grantVetterMutation.error && (
              <section className="card error">
                <h3>Grant failed</h3>
                <p>{(grantVetterMutation.error as Error).message}</p>
              </section>
            )}
            {revokeVetterMutation.error && (
              <section className="card error">
                <h3>Revoke failed</h3>
                <p>{(revokeVetterMutation.error as Error).message}</p>
              </section>
            )}

            <div className="form-actions">
              {liveGrant ? (
                <button
                  type="button"
                  className="secondary destructive"
                  disabled={revokeVetterMutation.isPending}
                  onClick={async () => {
                    const ok = await confirm({
                      title: "Revoke vetter role?",
                      message: `${query.data.did} stops being a vetter. Statements they have already signed stop counting toward joins decided from now on.`,
                      confirmLabel: "Revoke vetter role",
                      destructive: true,
                    });
                    if (ok) revokeVetterMutation.mutate(liveGrant.endorsementId);
                  }}
                >
                  {revokeVetterMutation.isPending
                    ? "Revoking…"
                    : "Revoke vetter role"}
                </button>
              ) : (
                <button
                  type="button"
                  className="primary"
                  disabled={
                    !vetterGrants.data || grantVetterMutation.isPending
                  }
                  onClick={async () => {
                    const ok = await confirm({
                      title: "Grant vetter role?",
                      message: `${query.data.did} will be issued a vetter role credential, valid for a year. Their vetting statements will count toward admissions.`,
                      confirmLabel: "Grant vetter role",
                    });
                    if (ok) grantVetterMutation.mutate(decoded);
                  }}
                >
                  {grantVetterMutation.isPending
                    ? "Granting…"
                    : "Grant vetter role"}
                </button>
              )}
            </div>
          </section>

          <section className="card">
            <h3>Admin actions</h3>
            <p className="lead">
              Promoting to admin requires a fresh user-verification
              ceremony — your authenticator will prompt for biometric
              or PIN even if you already signed in this session.
              Admin-remove DELETEs the member's ACL + member row;
              the member can re-apply via the join flow.
            </p>

            {/* A promotion or removal that needs other administrators'
                approval arrives as a parked action, shown as a success. */}
            <ErrorOrParked title="Promote failed" error={promoteMutation.error} />
            <ErrorOrParked title="Remove failed" error={removeMutation.error} />

            <div className="form-actions">
              <button
                type="button"
                className="primary"
                disabled={
                  query.data.role === "admin" ||
                  promoteMutation.isPending ||
                  removeMutation.isPending
                }
                onClick={async () => {
                  const ok = await confirm({
                    title: "Promote to admin?",
                    message: `${query.data.did} will gain admin role. You'll need to verify with your passkey first.`,
                    confirmLabel: "Promote",
                  });
                  if (ok)
                    promoteMutation.mutate({
                      did: decoded,
                      fromRole: query.data.role,
                    });
                }}
              >
                {promoteMutation.isPending
                  ? "Verifying…"
                  : query.data.role === "admin"
                    ? "Already admin"
                    : "Promote to admin"}
              </button>
            </div>

            <hr />

            <Field label="Removal reason (optional)">
              <input
                type="text"
                placeholder="left the community / policy violation / …"
                value={removeReason}
                onChange={(e) => setRemoveReason(e.target.value)}
              />
            </Field>
            <div className="form-actions">
              <button
                type="button"
                className="secondary destructive"
                disabled={
                  promoteMutation.isPending || removeMutation.isPending
                }
                onClick={async () => {
                  const ok = await confirm({
                    title: "Remove member?",
                    message: `${query.data.did} loses access immediately. Their member + ACL rows are deleted.`,
                    confirmLabel: "Remove member",
                    destructive: true,
                  });
                  if (ok) {
                    removeMutation.mutate({
                      did: decoded,
                      reason: removeReason,
                    });
                  }
                }}
              >
                {removeMutation.isPending ? "Removing…" : "Remove member"}
              </button>
            </div>
          </section>
        </>
      )}
    </section>
  );
}

