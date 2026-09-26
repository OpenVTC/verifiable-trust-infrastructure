// `/admin/step-up#request=…` — answering, in this browser, a passkey step-up a
// signed document sent from a terminal was refused for.
//
// `cnm` cannot run a WebAuthn ceremony, so when the VTC refuses its document
// with `details.stepUpRequest` (an operation-bound step-up,
// `auth/step-up/approve-request/0.3` with `boundTo`), it prints this page's
// URL with the request in the fragment — which the browser never sends to a
// server — and waits. The operator reads here what they are consenting to,
// answers with their passkey, and goes back to the terminal, where `cnm` sends
// the *same* document again and the VTC spends the gesture on it.
//
// Nothing here trusts the fragment for anything but display and the WebAuthn
// options: what the gesture authorizes is the VTC's own record of the refusal,
// keyed by the challenge, never this page's copy of it.

import { useMemo, useState } from "react";
import { useLocation } from "react-router-dom";
import { useMutation } from "@tanstack/react-query";
import { Fingerprint } from "lucide-react";

import { postSignedTrustTask } from "@/lib/api";
import {
  answerableHere,
  answerStepUp,
  APPROVE_RESPONSE_URI,
  decodeStepUpRequest,
} from "@/lib/bound-step-up";
import { useViewerDid } from "@/lib/viewer";

function message(err: unknown): string {
  if (err && typeof err === "object" && "message" in err) {
    const m = (err as { message: unknown }).message;
    if (typeof m === "string" && m) return m;
  }
  return String(err);
}

export function StepUpPage() {
  const { hash } = useLocation();
  const request = useMemo(() => decodeStepUpRequest(hash), [hash]);
  const viewer = useViewerDid();
  const [declined, setDeclined] = useState(false);

  const approve = useMutation({ mutationFn: () => answerStepUp(request!) });
  const decline = useMutation({
    mutationFn: () =>
      postSignedTrustTask(APPROVE_RESPONSE_URI, {
        subject: request!.subject,
        challenge: request!.challenge,
        decision: "denied",
        deniedReason: "declined in the admin console",
      }),
    onSuccess: () => setDeclined(true),
  });

  if (!request) {
    return (
      <section className="page">
        <h2>Confirm with your passkey</h2>
        <section className="card error">
          <p>
            This link carries no step-up request this console can read. Copy the whole
            URL <code>cnm</code> printed, including everything after <code>#</code>.
          </p>
        </section>
      </section>
    );
  }

  const wrongPerson = !!viewer && viewer !== request.subject;
  const done = approve.isSuccess || declined;

  return (
    <section className="page">
      <h2>Confirm with your passkey</h2>
      <section className="card">
        <p className="lead">A document you sent from a terminal is waiting for this.</p>
        <dl className="gitns-parties">
          <dt>It asks</dt>
          <dd>
            <q>{request.reason}</q>
          </dd>
          <dt>As</dt>
          <dd>
            <code className="gitns-party-did">{request.subject}</code>
          </dd>
          {request.boundTo && (
            <>
              <dt>Bound to</dt>
              <dd>
                <code className="gitns-party-did">{request.boundTo}</code>
              </dd>
            </>
          )}
          {request.ttl && (
            <>
              <dt>Expires</dt>
              <dd>{Math.round(request.ttl / 60)} minutes after it was asked</dd>
            </>
          )}
        </dl>
        <p className="muted">
          The gesture authorizes that one document and nothing else: no session is
          elevated, and the VTC spends it when the terminal sends the document again.
        </p>

        {wrongPerson && (
          <div className="finding warn" role="alert">
            <strong>You are signed in as someone else</strong>
            <span>
              Only a passkey registered to <code>{request.subject}</code> can answer this.
              This session is <code>{viewer}</code>.
            </span>
          </div>
        )}
        {!answerableHere(request) && (
          <div className="finding error" role="alert">
            <strong>This console cannot answer it</strong>
            <span>The VTC did not ask for a passkey.</span>
          </div>
        )}
        {approve.isSuccess && (
          <div className="finding ok" role="status">
            <strong>Recorded</strong>
            <span>
              Go back to your terminal and continue: <code>cnm</code> sends the same
              document again, and the VTC acts on it.
            </span>
          </div>
        )}
        {declined && (
          <div className="finding ok" role="status">
            <strong>Declined</strong>
            <span>Nothing was authorized. If the document is sent again, the VTC asks again.</span>
          </div>
        )}
        {(approve.isError || decline.isError) && (
          <div className="finding error" role="alert">
            <strong>That did not go through</strong>
            <span>{message(approve.error ?? decline.error)}</span>
          </div>
        )}

        {!done && (
          <div className="form-actions">
            <button
              type="button"
              className="secondary"
              disabled={approve.isPending || decline.isPending}
              onClick={() => decline.mutate()}
            >
              Decline
            </button>
            <button
              type="button"
              className="primary"
              disabled={!answerableHere(request) || approve.isPending || decline.isPending}
              onClick={() => approve.mutate()}
            >
              <Fingerprint aria-hidden="true" size={14} />{" "}
              {approve.isPending ? "Waiting for your passkey…" : "Confirm with passkey"}
            </button>
          </div>
        )}
      </section>
    </section>
  );
}
