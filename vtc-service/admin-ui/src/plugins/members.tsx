// Members plugin — list + detail (read-only).
//
// Reads `GET /v1/members` (paginated, optional role filter) and
// `GET /v1/members/{did}` for the detail view. Mutations (promote,
// admin-remove) land in a follow-up commit; this is the read
// surface only.

import { useState } from "react";
import {
  useMutation,
  useQuery,
  useQueryClient,
} from "@tanstack/react-query";
import { Link, Route, Routes, useNavigate, useParams } from "react-router-dom";
import {
  ArrowLeft,
  ArrowRight,
  Check,
  Minus,
  Ticket,
  Trash2,
  Users as UsersIcon,
} from "lucide-react";

import { deleteJson, getJson, postJson } from "@/lib/api";
import { useConfirm } from "@/components/ConfirmDialog";
import { formatIso as formatDate } from "@/lib/format";
import {
  decodePublicKeyOptions,
  serializeAssertion,
  type JsonPublicKeyOptions,
} from "@/lib/webauthn";

const TRUST_TASK_LIST =
  "https://trusttasks.org/openvtc/vtc/members/list/1.0";
// `members/show/1.0` covers GET + PATCH + DELETE on `/members/{did}`
// today (TrustTaskRouter limitation). Server-side resolves the
// actual operation by method; the header just needs to match the
// router's registered task.
const TRUST_TASK_SHOW =
  "https://trusttasks.org/openvtc/vtc/members/show/1.0";
const TRUST_TASK_PROMOTE =
  "https://trusttasks.org/openvtc/vtc/members/promote-to-admin/1.0";
const TRUST_TASK_REMOVED =
  "https://trusttasks.org/openvtc/vtc/members/removed/1.0";
const TRUST_TASK_PURGE =
  "https://trusttasks.org/openvtc/vtc/members/purge/1.0";
const TRUST_TASK_REQUEST_VMC =
  "https://trusttasks.org/openvtc/vtc/members/request-vmc/1.0";

interface MemberRow {
  did: string;
  role: string;
  label: string | null;
  joinedAt: string;
  publishConsent: boolean;
  departurePreference: string;
  statusListIndex: number | null;
  currentVmcId: string | null;
  currentRoleVecId: string | null;
  extensions: unknown;
  personhood: boolean;
  personhoodAssertedAt: string | null;
  joinedViaInvitation: boolean;
  /** Top-level `id` of the member-issued reciprocal VMC, once received. */
  memberVmcId?: string | null;
  /** When the member's reciprocal VMC was received + stored. */
  memberVmcReceivedAt?: string | null;
}

interface MembersPage {
  items: MemberRow[];
  next_cursor: string | null;
  total_estimate?: number;
}

async function fetchMembers(params: {
  cursor: string | null;
  role: string | null;
  limit: number;
}): Promise<MembersPage> {
  const q = new URLSearchParams();
  if (params.cursor) q.set("cursor", params.cursor);
  if (params.role) q.set("role", params.role);
  q.set("limit", String(params.limit));
  return getJson<MembersPage>(`/v1/members?${q.toString()}`, {
    trustTask: TRUST_TASK_LIST,
  });
}

async function fetchMember(did: string): Promise<MemberRow> {
  return getJson<MemberRow>(`/v1/members/${encodeURIComponent(did)}`, {
    trustTask: TRUST_TASK_SHOW,
  });
}

interface RequestVmcResponse {
  memberDid: string;
  requested: boolean;
  threadId: string;
}

/** Ask an active member to issue + send their reciprocal VMC (member →
 * community half of the pair). The member answers asynchronously over the
 * `members/vmc/1.0` DIDComm surface; this only dispatches the request. */
async function requestMemberVmc(did: string): Promise<RequestVmcResponse> {
  return postJson<RequestVmcResponse>(
    `/v1/members/${encodeURIComponent(did)}/request-vmc`,
    {},
    { trustTask: TRUST_TASK_REQUEST_VMC },
  );
}

interface PromoteStartResponse {
  registrationId: string;
  options: { publicKey: JsonPublicKeyOptions };
}

async function promoteToAdmin(targetDid: string): Promise<void> {
  // Step-up UV: call /start to get a WebAuthn assertion challenge
  // against the caller's own passkeys, run navigator.credentials.get
  // for the operator's user-verification gesture, post the assertion
  // back to /finish.
  const start = await postJson<PromoteStartResponse>(
    `/v1/members/${encodeURIComponent(targetDid)}/promote-to-admin/start`,
    undefined,
    { trustTask: TRUST_TASK_PROMOTE },
  );

  const publicKey = decodePublicKeyOptions(
    start.options.publicKey,
  ) as PublicKeyCredentialRequestOptions;
  const credential = (await navigator.credentials.get({
    publicKey,
  })) as PublicKeyCredential | null;
  if (!credential) throw new Error("Passkey ceremony returned no credential");

  await postJson<unknown>(
    `/v1/members/${encodeURIComponent(targetDid)}/promote-to-admin/finish`,
    {
      registration_id: start.registrationId,
      uv_response: serializeAssertion(credential),
    },
    { trustTask: TRUST_TASK_PROMOTE },
  );
}

async function adminRemove(args: {
  did: string;
  reason: string;
}): Promise<void> {
  // DELETE accepts an optional `{reason}` body on the server.
  // `/members/{did}` collapses GET + PATCH + DELETE under the single
  // `members/show/1.0` Trust Task at the router (per-method selectors are
  // deferred infra), so the DELETE must send that task — sending
  // `members/admin-remove/1.0` trips the exact-match soft-gate
  // (`TrustTaskMismatch`, 415). The standalone admin-remove Trust Task still
  // exists on disk for the soft-gate surface.
  await deleteJson<unknown>(`/v1/members/${encodeURIComponent(args.did)}`, {
    trustTask: TRUST_TASK_SHOW,
    body: { reason: args.reason || null },
  });
}

interface RemovedMemberRow {
  did: string;
  removedAt: string;
  statusListIndex: number | null;
  status: string;
}

async function fetchRemovedMembers(): Promise<RemovedMemberRow[]> {
  return getJson<RemovedMemberRow[]>("/v1/members/removed", {
    trustTask: TRUST_TASK_REMOVED,
  });
}

async function purgeMember(did: string): Promise<void> {
  await deleteJson<unknown>(
    `/v1/members/${encodeURIComponent(did)}/purge`,
    { trustTask: TRUST_TASK_PURGE },
  );
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
      <table className="data-table">
        <thead>
          <tr>
            <th>DID</th>
            <th>Removed</th>
            <th>Revocation slot</th>
            <th />
          </tr>
        </thead>
        <tbody>
          {rows.map((m) => (
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
        </tbody>
      </table>
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

function MembersList() {
  const [roleFilter, setRoleFilter] = useState<string>("");
  const [cursor, setCursor] = useState<string | null>(null);
  const limit = 50;

  const query = useQuery({
    queryKey: ["members", roleFilter, cursor, limit],
    queryFn: () =>
      fetchMembers({
        cursor,
        role: roleFilter || null,
        limit,
      }),
    placeholderData: (prev) => prev,
  });

  return (
    <section className="page">
      <h2>Members</h2>

      <section className="card">
        <div className="toolbar">
          <label className="field inline">
            <span className="field-label">Filter by role</span>
            <input
              type="search"
              placeholder="admin / moderator / custom:editor"
              value={roleFilter}
              onChange={(e) => {
                setRoleFilter(e.target.value);
                setCursor(null);
              }}
            />
          </label>
        </div>
      </section>

      {query.error && (
        <section className="card error">
          <h3>Failed to load members</h3>
          <p>{(query.error as Error).message}</p>
        </section>
      )}

      <section className="card">
        <table className="data-table">
          <thead>
            <tr>
              <th>DID</th>
              <th>Role</th>
              <th>Label</th>
              <th>Joined</th>
              <th>Personhood</th>
            </tr>
          </thead>
          <tbody>
            {query.isPending && (
              <tr>
                <td colSpan={5}>Loading…</td>
              </tr>
            )}
            {query.data?.items.length === 0 && (
              <tr>
                <td colSpan={5}>
                  <div className="empty-state">
                    <span className="empty-icon" aria-hidden="true">
                      <UsersIcon />
                    </span>
                    <h4>No members match this filter</h4>
                    <p>
                      Adjust the role filter to widen the result, or
                      wait for join requests to be approved.
                    </p>
                  </div>
                </td>
              </tr>
            )}
            {query.data?.items.map((m) => (
              <tr key={m.did}>
                <td>
                  <Link to={encodeURIComponent(m.did)}>
                    <code className="truncate">{m.did}</code>
                  </Link>
                  {m.joinedViaInvitation && (
                    <Ticket
                      size={14}
                      strokeWidth={1.75}
                      aria-label="Joined via invitation"
                      className="status-icon ok"
                      style={{ marginLeft: 6, verticalAlign: "middle" }}
                    />
                  )}
                </td>
                <td>
                  <code>{m.role}</code>
                </td>
                <td>{m.label ?? "—"}</td>
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
              </tr>
            ))}
          </tbody>
        </table>

        <div className="pagination">
          <button
            type="button"
            className="secondary"
            disabled={cursor === null}
            onClick={() => setCursor(null)}
          >
            First page
          </button>
          <button
            type="button"
            className="secondary"
            disabled={!query.data?.next_cursor}
            onClick={() => setCursor(query.data?.next_cursor ?? null)}
          >
            Next page <ArrowRight size={12} aria-hidden="true" />
          </button>
          {query.data?.total_estimate !== undefined && (
            <span className="muted">
              ~{query.data.total_estimate} total
            </span>
          )}
        </div>
      </section>

      <RemovedMembers />
    </section>
  );
}

function MemberDetail() {
  const { did = "" } = useParams<{ did: string }>();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const confirm = useConfirm();
  const decoded = decodeURIComponent(did);
  const [removeReason, setRemoveReason] = useState("");

  const query = useQuery({
    queryKey: ["member", decoded],
    queryFn: () => fetchMember(decoded),
    enabled: decoded.length > 0,
  });

  const promoteMutation = useMutation({
    mutationFn: promoteToAdmin,
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["member", decoded] });
      void queryClient.invalidateQueries({ queryKey: ["members"] });
    },
  });

  const removeMutation = useMutation({
    mutationFn: adminRemove,
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["members"] });
      navigate("..");
    },
  });

  const requestVmcMutation = useMutation({
    mutationFn: requestMemberVmc,
  });

  return (
    <section className="page">
      <button type="button" className="link" onClick={() => navigate("..")}>
        <ArrowLeft size={14} aria-hidden="true" /> Back to members
      </button>
      <h2>Member detail</h2>

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
              <dt>Current role VEC</dt>
              <dd>
                {query.data.currentRoleVecId ? (
                  <code>{query.data.currentRoleVecId}</code>
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
            </dl>
          </section>

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
            <h3>Admin actions</h3>
            <p className="lead">
              Promoting to admin requires a fresh user-verification
              ceremony — your authenticator will prompt for biometric
              or PIN even if you already signed in this session.
              Admin-remove DELETEs the member's ACL + member row;
              the member can re-apply via the join flow.
            </p>

            {promoteMutation.error && (
              <section className="card error">
                <h3>Promote failed</h3>
                <p>{(promoteMutation.error as Error).message}</p>
              </section>
            )}
            {removeMutation.error && (
              <section className="card error">
                <h3>Remove failed</h3>
                <p>{(removeMutation.error as Error).message}</p>
              </section>
            )}

            {requestVmcMutation.error && (
              <section className="card error">
                <h3>Request failed</h3>
                <p>{(requestVmcMutation.error as Error).message}</p>
              </section>
            )}
            {requestVmcMutation.isSuccess && (
              <p className="muted">
                Requested the member's reciprocal VMC. They'll send it back
                asynchronously; refresh to see it under Credentials.
              </p>
            )}

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
                  if (ok) promoteMutation.mutate(decoded);
                }}
              >
                {promoteMutation.isPending
                  ? "Verifying…"
                  : query.data.role === "admin"
                    ? "Already admin"
                    : "Promote to admin"}
              </button>
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

            <hr />

            <label className="field">
              <span className="field-label">Removal reason (optional)</span>
              <input
                type="text"
                placeholder="left the community / policy violation / …"
                value={removeReason}
                onChange={(e) => setRemoveReason(e.target.value)}
              />
            </label>
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

