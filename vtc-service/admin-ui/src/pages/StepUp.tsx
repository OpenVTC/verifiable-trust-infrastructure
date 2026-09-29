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
//
// Every answer is signed by the approver. A browser holding a console key
// signs it here. One that holds none — a member answering with a step-up
// passkey — runs the ceremony and shows an **answer code** instead, which the
// member pastes back into `cnm` to be signed with their own key: the passkey
// is in addition to that signature, never instead of it.

import { useMemo, useState } from "react";
import { useLocation } from "react-router-dom";
import { useMutation, useQuery } from "@tanstack/react-query";
import { Fingerprint } from "lucide-react";

import { postSignedTrustTask, signingAvailable } from "@/lib/api";
import {
  answerableHere,
  answerCodeOf,
  answerStepUp,
  APPROVE_RESPONSE_URI,
  decodeStepUpRequest,
  runStepUpCeremony,
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

  const canSign = useQuery({ queryKey: ["console-signing"], queryFn: signingAvailable });
  const signing = canSign.data === true;
  const approve = useMutation({ mutationFn: () => answerStepUp(request!) });
  // No console key here: the gesture only, for `cnm` to sign.
  const handOver = useMutation({
    mutationFn: async () => answerCodeOf(await runStepUpCeremony(request!)),
  });
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
  const done = approve.isSuccess || declined || handOver.isSuccess;
  const pending = approve.isPending || decline.isPending || handOver.isPending;

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
        {handOver.isSuccess && (
          <div className="finding ok" role="status">
            <strong>Paste this answer code into your terminal</strong>
            <span>
              <code>cnm</code> is waiting for it. It signs the answer with your own key and
              sends the same document again. The code is good for this one request only,
              and useless without your signature.
            </span>
            <textarea
              className="answer-code"
              readOnly
              rows={4}
              value={handOver.data}
              aria-label="Answer code"
              onFocus={(e) => e.currentTarget.select()}
            />
            <button
              type="button"
              onClick={() => void navigator.clipboard?.writeText(handOver.data)}
            >
              Copy
            </button>
          </div>
        )}
        {declined && (
          <div className="finding ok" role="status">
            <strong>Declined</strong>
            <span>Nothing was authorized. If the document is sent again, the VTC asks again.</span>
          </div>
        )}
        {(approve.isError || decline.isError || handOver.isError) && (
          <div className="finding error" role="alert">
            <strong>That did not go through</strong>
            <span>{message(approve.error ?? decline.error ?? handOver.error)}</span>
          </div>
        )}

        {!done && canSign.isSuccess && (
          <div className="form-actions">
            {signing ? (
              <button
                type="button"
                className="secondary"
                disabled={pending}
                onClick={() => decline.mutate()}
              >
                Decline
              </button>
            ) : (
              <p className="muted">
                To decline, do not answer: the request lapses in a few minutes.
              </p>
            )}
            <button
              type="button"
              className="primary"
              disabled={!answerableHere(request) || pending}
              onClick={() => (signing ? approve.mutate() : handOver.mutate())}
            >
              <Fingerprint aria-hidden="true" size={14} />{" "}
              {approve.isPending || handOver.isPending
                ? "Waiting for your passkey…"
                : "Confirm with passkey"}
            </button>
          </div>
        )}
      </section>
    </section>
  );
}
