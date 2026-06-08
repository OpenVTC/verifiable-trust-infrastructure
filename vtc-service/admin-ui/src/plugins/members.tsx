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

