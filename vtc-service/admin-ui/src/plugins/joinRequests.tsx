// Join requests plugin — pending inbox + approve/reject.
//
// Lists pending applications by default (the operator's work
// queue), with a status filter for inspecting historical state.
// Each row links to a detail view that shows the VP claims +
// extensions and offers Approve / Reject buttons.

import { useState } from "react";
import {
  useMutation,
  useQuery,
  useQueryClient,
} from "@tanstack/react-query";
import { Link, Route, Routes, useNavigate, useParams } from "react-router-dom";
import { ArrowLeft, ArrowRight, Inbox } from "lucide-react";

import { getJson, postJson } from "@/lib/api";
import { useConfirm } from "@/components/ConfirmDialog";
import { formatIso as formatDate } from "@/lib/format";

const TRUST_TASK_SUBMIT =
  "https://trusttasks.org/spec/vtc/join-requests/list/0.1";
const TRUST_TASK_SHOW =
  "https://trusttasks.org/spec/vtc/join-requests/show/0.1";
const TRUST_TASK_APPROVE =
  "https://trusttasks.org/spec/vtc/join-requests/approve/0.1";
const TRUST_TASK_REJECT =
  "https://trusttasks.org/spec/vtc/join-requests/reject/0.1";

type JoinStatus = "pending" | "approved" | "rejected" | "withdrawn" | "deferred";

interface JoinRequestRow {
  id: string;
  applicantDid: string;
  vp: unknown;
  vpClaims: unknown;
  submittedAt: string;
  status: JoinStatus;
  policyDecision: unknown;
  registryConsent: boolean;
  extensions: unknown;
}

interface JoinRequestsPage {
  items: JoinRequestRow[];
  next_cursor: string | null;
  total_estimate?: number;
}

interface DecideResponse {
  request: JoinRequestRow;
  member?: unknown;
  vmc?: unknown;
  roleVec?: unknown;
}

async function fetchJoinRequests(params: {
  status: JoinStatus;
  cursor: string | null;
  limit: number;
}): Promise<JoinRequestsPage> {
  const q = new URLSearchParams();
  q.set("status", params.status);
  if (params.cursor) q.set("cursor", params.cursor);
  q.set("limit", String(params.limit));
  // POST + GET share the same router mount; the registered task is
  // `submit/1.0` (TrustTaskRouter per-method selectors land later).
  // GET works against the same header.
  return getJson<JoinRequestsPage>(`/v1/join-requests?${q.toString()}`, {
    trustTask: TRUST_TASK_SUBMIT,
  });
}

async function fetchJoinRequest(id: string): Promise<JoinRequestRow> {
  return getJson<JoinRequestRow>(`/v1/join-requests/${id}`, {
    trustTask: TRUST_TASK_SHOW,
  });
}

async function approve(id: string): Promise<DecideResponse> {
  return postJson<DecideResponse>(
    `/v1/join-requests/${id}/approve`,
    undefined,
    { trustTask: TRUST_TASK_APPROVE },
  );
}

async function reject(args: {
  id: string;
  reason: string;
}): Promise<DecideResponse> {
  return postJson<DecideResponse>(
    `/v1/join-requests/${args.id}/reject`,
    { reason: args.reason || null },
    { trustTask: TRUST_TASK_REJECT },
  );
}


export function JoinRequests() {
  return (
    <Routes>
      <Route index element={<JoinRequestsList />} />
      <Route path=":id" element={<JoinRequestDetail />} />
    </Routes>
  );
}

function JoinRequestsList() {
  const [status, setStatus] = useState<JoinStatus>("pending");
  const [cursor, setCursor] = useState<string | null>(null);
  const limit = 50;

  const query = useQuery({
    queryKey: ["join-requests", status, cursor, limit],
    queryFn: () => fetchJoinRequests({ status, cursor, limit }),
    placeholderData: (prev) => prev,
  });

  return (
    <section className="page">
      <h2>Join requests</h2>

      <section className="card">
        <div className="toolbar">
          <label className="field inline">
            <span className="field-label">Status</span>
            <select
              value={status}
              onChange={(e) => {
                setStatus(e.target.value as JoinStatus);
                setCursor(null);
              }}
            >
              <option value="pending">Pending</option>
              <option value="approved">Approved</option>
              <option value="rejected">Rejected</option>
              <option value="withdrawn">Withdrawn</option>
              <option value="deferred">Deferred</option>
            </select>
          </label>
        </div>
      </section>

      {query.error && (
        <section className="card error">
          <h3>Failed to load join requests</h3>
          <p>{(query.error as Error).message}</p>
        </section>
      )}

      <section className="card">
        <table className="data-table">
          <thead>
            <tr>
              <th>Applicant DID</th>
              <th>Submitted</th>
              <th>Registry consent</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {query.isPending && (
              <tr>
                <td colSpan={4}>Loading…</td>
              </tr>
            )}
            {query.data?.items.length === 0 && (
              <tr>
                <td colSpan={4}>
                  <div className="empty-state">
                    <span className="empty-icon" aria-hidden="true">
                      <Inbox />
                    </span>
                    <h4>No {status} join requests</h4>
                    <p>
                      Switch the status filter to inspect historical
                      requests, or wait for a new applicant to submit.
                    </p>
                  </div>
                </td>
              </tr>
            )}
            {query.data?.items.map((r) => (
              <tr key={r.id}>
                <td>
                  <Link to={r.id}>
                    <code className="truncate" title={r.applicantDid}>
                      {r.applicantDid}
                    </code>
                  </Link>
                </td>
                <td>{formatDate(r.submittedAt)}</td>
                <td>
                  {r.registryConsent ? (
                    "Yes"
                  ) : (
                    <span className="muted">No</span>
                  )}
                </td>
                <td>
                  <Link to={r.id}>
                    Review <ArrowRight size={12} aria-hidden="true" />
                  </Link>
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
        </div>
      </section>
    </section>
  );
}

function JoinRequestDetail() {
  const { id = "" } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const confirm = useConfirm();
  const [rejectReason, setRejectReason] = useState("");

  const query = useQuery({
    queryKey: ["join-request", id],
    queryFn: () => fetchJoinRequest(id),
    enabled: id.length > 0,
  });

  const approveMutation = useMutation({
    mutationFn: approve,
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["join-requests"] });
      void queryClient.invalidateQueries({ queryKey: ["join-request", id] });
    },
  });

  const rejectMutation = useMutation({
    mutationFn: reject,
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["join-requests"] });
      void queryClient.invalidateQueries({ queryKey: ["join-request", id] });
    },
  });

  return (
    <section className="page">
      <button type="button" className="link" onClick={() => navigate("..")}>
        <ArrowLeft size={14} aria-hidden="true" /> Back to join requests
      </button>
      <h2>Join request detail</h2>

      {query.isPending && <p>Loading…</p>}
      {query.error && (
        <section className="card error">
          <h3>Failed to load request</h3>
          <p>{(query.error as Error).message}</p>
        </section>
      )}

      {query.data && (
        <>
          <section className="card">
            <h3>Summary</h3>
            <dl>
              <dt>Applicant DID</dt>
              <dd>
                <code>{query.data.applicantDid}</code>
              </dd>
              <dt>Submitted</dt>
              <dd>
                <code>{query.data.submittedAt}</code>
              </dd>
              <dt>Status</dt>
              <dd>
                <code>{query.data.status}</code>
              </dd>
              <dt>Registry consent</dt>
              <dd>{query.data.registryConsent ? "Yes" : "No"}</dd>
            </dl>
          </section>

          {query.data.status === "pending" && (
            <section className="card">
              <h3>Decide</h3>
              <p className="lead">
                Approve creates the member + ACL row atomically and
                fires the VMC + role-VEC issuance. Reject closes the
                request with the supplied reason; the applicant may
                resubmit.
              </p>

              {approveMutation.error && (
                <section className="card error">
                  <h3>Approve failed</h3>
                  <p>{(approveMutation.error as Error).message}</p>
                </section>
              )}
              {rejectMutation.error && (
                <section className="card error">
                  <h3>Reject failed</h3>
                  <p>{(rejectMutation.error as Error).message}</p>
                </section>
              )}

              <div className="form-actions">
                <button
                  type="button"
                  className="primary"
                  disabled={
                    approveMutation.isPending || rejectMutation.isPending
                  }
                  onClick={async () => {
                    const ok = await confirm({
                      title: "Approve join request?",
                      message: `${query.data.applicantDid} gets an ACL + member row, and credentials (VMC + role VEC) are issued.`,
                      confirmLabel: "Approve",
                    });
                    if (ok) approveMutation.mutate(id);
                  }}
                >
                  {approveMutation.isPending ? "Approving…" : "Approve"}
                </button>
              </div>

              <hr />

              <label className="field">
                <span className="field-label">Reject reason (optional)</span>
                <input
                  type="text"
                  placeholder="missing VRC / failed policy check / …"
                  value={rejectReason}
                  onChange={(e) => setRejectReason(e.target.value)}
                />
              </label>
              <div className="form-actions">
                <button
                  type="button"
                  className="secondary destructive"
                  disabled={
                    approveMutation.isPending || rejectMutation.isPending
                  }
                  onClick={async () => {
                    const ok = await confirm({
                      title: "Reject join request?",
                      message: `${query.data.applicantDid} will be told the application was declined. They may resubmit.`,
                      confirmLabel: "Reject",
                      destructive: true,
                    });
                    if (ok) rejectMutation.mutate({ id, reason: rejectReason });
                  }}
                >
                  {rejectMutation.isPending ? "Rejecting…" : "Reject"}
                </button>
              </div>
            </section>
          )}

          <section className="card">
            <h3>VP claims</h3>
            <pre>{JSON.stringify(query.data.vpClaims, null, 2)}</pre>
          </section>

          {query.data.extensions !== null &&
            query.data.extensions !== undefined && (
              <section className="card">
                <h3>Extensions</h3>
                <pre>{JSON.stringify(query.data.extensions, null, 2)}</pre>
              </section>
            )}

          {query.data.policyDecision !== null &&
            query.data.policyDecision !== undefined && (
              <section className="card">
                <h3>Policy decision</h3>
                <pre>
                  {JSON.stringify(query.data.policyDecision, null, 2)}
                </pre>
              </section>
            )}
        </>
      )}
    </section>
  );
}

