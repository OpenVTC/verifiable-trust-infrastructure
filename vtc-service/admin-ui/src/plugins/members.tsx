// Members plugin — list + detail (read-only).
//
// Reads `GET /v1/members` (paginated, optional role filter) and
// `GET /v1/members/{did}` for the detail view. Mutations (promote,
// admin-remove) land in a follow-up commit; this is the read
// surface only.
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
// The membership credential + role VEC *bodies* are not here: the
// `members/show/0.1` response is `additionalProperties: false` and its own text
// says "The credential body is not echoed here", so surfacing them needs a task
// authored upstream rather than a field added locally. Their ids and receipt
// state are shown, which is what that schema does carry.

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

import {
  deleteJson,
  fetchMemberRelationships,
  fetchRelationshipsGraph,
  getJson,
  patchJson,
  postJson,
  type MemberRelationship,
  type RelationshipsGraph,
} from "@/lib/api";
import { CopyButton } from "@/components/CopyButton";
import { useConfirm } from "@/components/ConfirmDialog";
import { formatIso as formatDate, shortenDid } from "@/lib/format";
import {
  decodePublicKeyOptions,
  serializeAssertion,
  type JsonPublicKeyOptions,
} from "@/lib/webauthn";

const TRUST_TASK_LIST =
  "https://trusttasks.org/spec/vtc/members/list/0.1";
// `members/show/1.0` covers GET + PATCH + DELETE on `/members/{did}`
// today (TrustTaskRouter limitation). Server-side resolves the
// actual operation by method; the header just needs to match the
// router's registered task.
const TRUST_TASK_SHOW =
  "https://trusttasks.org/spec/vtc/members/show/0.1";
// DELETE /members/{did} is its own canonical task now that each verb on
// the shared mount carries its own descriptor.
const TRUST_TASK_ADMIN_REMOVE =
  "https://trusttasks.org/spec/vtc/members/admin-remove/0.1";
// Promotion to admin is a PATCH like any other role change — what makes it
// special is the step-up elevation it demands, not a task of its own. The
// fused `openvtc/vtc/members/promote-to-admin/1.0` pair is retired.
const TRUST_TASK_UPDATE =
  "https://trusttasks.org/spec/vtc/members/update/0.1";
const TRUST_TASK_PASSKEY_STEP_UP_START =
  "https://trusttasks.org/spec/auth/passkey/login/start/0.2";
const TRUST_TASK_PASSKEY_STEP_UP_FINISH =
  "https://trusttasks.org/spec/auth/passkey/login/finish/0.2";
const TRUST_TASK_REMOVED =
  "https://trusttasks.org/spec/vtc/members/removed/0.1";
const TRUST_TASK_PURGE =
  "https://trusttasks.org/spec/vtc/members/purge/0.1";
const TRUST_TASK_REQUEST_VMC =
  "https://trusttasks.org/spec/vtc/members/solicit-vmc/0.1";

import type {
  MemberEnvelope,
  MemberRow,
  MembersPage,
  RemovedMemberRow,
  RemovedMembersResponse,
  RequestVmcResponse,
} from "@/lib/wire-types";
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
  const body = await getJson<MemberEnvelope>(
    `/v1/members/${encodeURIComponent(did)}`,
    { trustTask: TRUST_TASK_SHOW },
  );
  return body.member;
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

// As on the sign-in path: `login/start/0.2` sends the inner WebAuthn options,
// not webauthn-rs's `{publicKey: …}` wrapper (#1112).
interface StepUpStartResponse {
  authId: string;
  options: JsonPublicKeyOptions;
}

/** Elevate this session with a passkey user-verification gesture.
 *
 * Independent of what it authorises: the daemon stamps a bounded window on the
 * session, and any operation gated on a fresh step-up can spend it while it is
 * open. Promotion is simply the first caller. */
async function stepUpSession(): Promise<void> {
  const start = await postJson<StepUpStartResponse>(
    "/v1/auth/passkey-login/start",
    { purpose: "stepUp" },
    {
      trustTask: TRUST_TASK_PASSKEY_STEP_UP_START,
      requires: ["authId", "options.challenge"],
    },
  );

  const publicKey = decodePublicKeyOptions(
    start.options,
  ) as PublicKeyCredentialRequestOptions;
  const credential = (await navigator.credentials.get({
    publicKey,
  })) as PublicKeyCredential | null;
  if (!credential) throw new Error("Passkey ceremony returned no credential");

  await postJson<unknown>(
    "/v1/auth/passkey-login/finish",
    {
      auth_id: start.authId,
      credential: serializeAssertion(credential),
    },
    { trustTask: TRUST_TASK_PASSKEY_STEP_UP_FINISH },
  );
}

async function promoteToAdmin(targetDid: string): Promise<void> {
  // Step up first, then promote. Doing it unconditionally (rather than
  // promoting, catching `step_up_required`, and retrying) keeps the operator's
  // passkey gesture tied to the click that asked for it — which is the whole
  // point of requiring a *recent* second factor.
  await stepUpSession();
  await patchJson<unknown>(
    `/v1/members/${encodeURIComponent(targetDid)}`,
    { role: "admin" },
    { trustTask: TRUST_TASK_UPDATE },
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
    trustTask: TRUST_TASK_ADMIN_REMOVE,
    body: { reason: args.reason || null },
  });
}

async function fetchRemovedMembers(): Promise<RemovedMemberRow[]> {
  const body = await getJson<RemovedMembersResponse>("/v1/members/removed", {
    trustTask: TRUST_TASK_REMOVED,
  });
  return body.removed;
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
              {/* Name leads: it is what an operator is looking for. The DID
                  stays in its own column rather than being replaced by the
                  name — a member you cannot check against an identifier is a
                  member you cannot audit. */}
              <th>Name</th>
              <th>DID</th>
              <th>Role</th>
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
                  {m.label ?? <span className="muted">—</span>}
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
                  <Link to={encodeURIComponent(m.did)}>
                    <code className="truncate" title={m.did}>
                      {shortenDid(m.did)}
                    </code>
                  </Link>
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
            disabled={!query.data?.nextCursor}
            onClick={() => setCursor(query.data?.nextCursor ?? null)}
          >
            Next page <ArrowRight size={12} aria-hidden="true" />
          </button>
          {query.data?.totalEstimate !== undefined && (
            <span className="muted">
              ~{query.data.totalEstimate} total
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

  // Whether this member's membership edge is complete comes from the graph
  // rather than being recomputed here. One definition, one answer — a second
  // one living in this file would be free to disagree with the graph the
  // operator is looking at on the next page.
  const graph = useQuery<RelationshipsGraph>({
    queryKey: ["relationships-graph"],
    queryFn: fetchRelationshipsGraph,
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
                <p className="muted">
                  None published. A member's relationships are private to them
                  until they publish an edge here.
                </p>
              ) : (
                <ul style={{ paddingLeft: "1.1em", margin: 0 }}>
                  {relationships.data.items.map((r) => (
                    <li key={r.id} style={{ marginBottom: "var(--space-3)" }}>
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
                        <pre
                          style={{
                            overflowX: "auto",
                            fontSize: "var(--text-sm)",
                          }}
                        >
                          {JSON.stringify(r.vrcJsonld, null, 2)}
                        </pre>
                      </details>
                    </li>
                  ))}
                </ul>
              ))}
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

