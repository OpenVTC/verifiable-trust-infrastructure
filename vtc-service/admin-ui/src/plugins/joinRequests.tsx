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

import { postSignedRead, postSignedTrustTask } from "@/lib/api";
import { useConfirm } from "@/components/ConfirmDialog";
import { WAITING_COUNT_KEY } from "@/lib/action-badge";
import { formatIso as formatDate } from "@/lib/format";
import { useNameBook } from "@/lib/names";
import { DataTable } from "@/components/DataTable";
import { EmptyState } from "@/components/EmptyState";
import { Field } from "@/components/Field";
import { NamedDid } from "@/components/NamedDid";
import { PageHeader } from "@/components/PageHeader";
import { factsHeadline } from "@/lib/vetting";
import {
  JoinRequestVettingCard,
  useJoinRequestVetting,
} from "@/plugins/vetting/JoinRequestVetting";

const TRUST_TASK_LIST =
  "https://trusttasks.org/spec/vtc/join-requests/list/0.1";
const TRUST_TASK_SHOW =
  "https://trusttasks.org/spec/vtc/join-requests/show/0.1";
const TRUST_TASK_DECIDE =
  "https://trusttasks.org/spec/vtc/join-requests/decide/0.1";

type JoinStatus = "pending" | "approved" | "rejected" | "withdrawn" | "deferred";

import type {
  DecideResponse,
  JoinRequestEnvelope,
  JoinRequestRow,
  JoinRequestsPage,
} from "@/lib/wire-types";
async function fetchJoinRequests(params: {
  status: JoinStatus;
  cursor: string | null;
  limit: number;
}): Promise<JoinRequestsPage> {
  return postSignedRead<JoinRequestsPage>(TRUST_TASK_LIST, {
    status: params.status,
    limit: params.limit,
    ...(params.cursor ? { cursor: params.cursor } : {}),
  });
}

async function fetchJoinRequest(id: string): Promise<JoinRequestRow> {
  const body = await postSignedRead<JoinRequestEnvelope>(TRUST_TASK_SHOW, { id });
  return body.request;
}

// One decision task (`decide/0.1`) carries both outcomes as
// `{ id, decision, reason? }`, sent as a signed document.
async function approve(id: string): Promise<DecideResponse> {
  return postSignedTrustTask<DecideResponse>(TRUST_TASK_DECIDE, {
    id,
    decision: "approved",
  });
}

async function reject(args: {
  id: string;
  reason: string;
}): Promise<DecideResponse> {
  // `reason` is omitted rather than sent as `null`: the schema types it as an
  // optional string.
  return postSignedTrustTask<DecideResponse>(TRUST_TASK_DECIDE, {
    id: args.id,
    decision: "rejected",
    ...(args.reason ? { reason: args.reason } : {}),
  });
}


const JOIN_REQUEST_COLUMNS = [
  { key: "applicant", label: "Applicant DID" },
  { key: "submitted", label: "Submitted" },
  { key: "consent", label: "Registry consent" },
  { key: "review", label: "" },
] as const;

export function JoinRequests() {
  return (
    <Routes>
      <Route index element={<JoinRequestsList />} />
      <Route path=":id" element={<JoinRequestDetail />} />
    </Routes>
  );
}

function JoinRequestsList() {
  const nameBook = useNameBook();
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
      <PageHeader />

      <section className="card">
        <div className="toolbar">
          <Field label="Status" inline>
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
          </Field>
          {/* The VTC filters before paging, so this counts every request in
              this status, and each page holds only them. */}
          {typeof query.data?.totalEstimate === "number" && (
            <span className="muted" role="status">
              {query.data.totalEstimate} {status}
            </span>
          )}
        </div>
        {status === "pending" && (
          <p className="muted">
            Each pending request is also in Actions, where anyone holding vtc.join.decide
            can approve or reject it. Both show the same decision.
          </p>
        )}
      </section>

      {query.error && (
        <section className="card error">
          <h3>Failed to load join requests</h3>
          <p>{(query.error as Error).message}</p>
        </section>
      )}

      <section className="card">
        {/* Server-paged: no column sorts, since sorting one page would
            misrepresent the whole list. */}
        <DataTable columns={JOIN_REQUEST_COLUMNS}>
          {query.isPending && (
            <tr>
              <td colSpan={4}>Loading…</td>
            </tr>
          )}
          {query.data?.items.length === 0 && (
            <tr>
              <td colSpan={4}>
                <EmptyState icon={Inbox} title={`No ${status} join requests`}>
                  Switch the status filter to inspect historical
                  requests, or wait for a new applicant to submit.
                </EmptyState>
              </td>
            </tr>
          )}
          {query.data?.items.map((r) => (
            <tr key={r.id}>
              <td>
                <Link to={r.id}>
                  <NamedDid book={nameBook} did={r.applicantDid} />
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
        </DataTable>

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
      // The decision closes the request's item in the action list too.
      void queryClient.invalidateQueries({ queryKey: ["actions"] });
      void queryClient.invalidateQueries({ queryKey: WAITING_COUNT_KEY });
    },
  });

  // Read here as well as in the card (react-query shares the one request) so
  // the approval prompt can say when vetting is not met.
  const vetting = useJoinRequestVetting(id);
  const vettingFacts = vetting.data?.vetting;
  const vettingNote =
    vettingFacts && !vettingFacts.satisfied
      ? ` Vetting is not met: ${factsHeadline(vettingFacts).title.toLowerCase()}.`
      : "";

  const rejectMutation = useMutation({
    mutationFn: reject,
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["join-requests"] });
      void queryClient.invalidateQueries({ queryKey: ["join-request", id] });
      // The decision closes the request's item in the action list too.
      void queryClient.invalidateQueries({ queryKey: ["actions"] });
      void queryClient.invalidateQueries({ queryKey: WAITING_COUNT_KEY });
    },
  });

  return (
    <section className="page">
      <PageHeader
        title="Join request detail"
        trail={[{ label: "Join request detail" }]}
      />
      <button type="button" className="link" onClick={() => navigate("..")}>
        <ArrowLeft size={14} aria-hidden="true" /> Back to join requests
      </button>

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

          <JoinRequestVettingCard id={id} />

          {query.data.status === "pending" && (
            <section className="card">
              <h3>Decide</h3>
              <p className="lead">
                Approve creates the member + ACL row atomically and
                fires the VMC + role-VAC issuance. Reject closes the
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
                      message: `${query.data.applicantDid} gets an ACL + member row, and credentials (VMC + role VAC) are issued.${vettingNote}`,
                      confirmLabel: "Approve",
                    });
                    if (ok) approveMutation.mutate(id);
                  }}
                >
                  {approveMutation.isPending ? "Approving…" : "Approve"}
                </button>
              </div>

              <hr />

              <Field label="Reject reason (optional)">
                <input
                  type="text"
                  placeholder="missing VRC / failed policy check / …"
                  value={rejectReason}
                  onChange={(e) => setRejectReason(e.target.value)}
                />
              </Field>
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

