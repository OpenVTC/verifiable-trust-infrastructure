// `/admin/enrol-approver#token=…` — redeeming an administrator's invite to
// bind a **step-up approver** (`auth/step-up/approver/redeem/{start,finish}/0.1`).
//
// Reached without signing in: the invited subject may be a wallet
// administrator with no factor at all here, which is why they were invited.
// The fragment carries the invite token and is never sent to a server; the
// claim code arrived on another channel and is typed here.
//
// Every step is signed by the VTA wallet **as the invited subject's own DID**
// — never a console key — and the plugin's approver proves possession of its
// key with an enrolment statement over the challenge `redeem/start` returns.
// Three things together bind it: the invite, the claim code and the subject's
// own signature; none is enough alone (VTI-APV-016).

import { useEffect, useMemo, useState } from "react";
import { useLocation } from "react-router-dom";
import { useMutation } from "@tanstack/react-query";
import { ShieldCheck } from "lucide-react";

import {
  approverErrorMessage,
  redeemApproverFinish,
  redeemApproverStart,
  type ApproverBound,
} from "@/lib/step-up-approvers";
import { tokenFromHash } from "@/lib/step-up-passkeys";
import { isWalletApproverEnrolmentAvailable, walletPersonaDid } from "@/lib/wallet";
import { Field } from "@/components/Field";

function Frame({ children }: { children: React.ReactNode }) {
  return (
    <main className="content">
      <section className="page">
        <h2>Enrol a step-up approver</h2>
        {children}
      </section>
    </main>
  );
}

export function EnrolApproverPage() {
  const { hash } = useLocation();
  const token = useMemo(() => tokenFromHash(hash), [hash]);
  const [did, setDid] = useState("");
  const [code, setCode] = useState("");
  const [label, setLabel] = useState("");
  const walletReady = isWalletApproverEnrolmentAvailable();

  // The persona this community knows the user as, if the wallet can say.
  useEffect(() => {
    if (!walletReady) return;
    let cancelled = false;
    walletPersonaDid()
      .then((d) => {
        if (!cancelled && d) setDid((cur) => cur || d);
      })
      .catch(() => {});
    return () => {
      cancelled = true;
    };
  }, [walletReady]);

  const redeem = useMutation({
    mutationFn: async (): Promise<ApproverBound> => {
      const subject = did.trim();
      const started = await redeemApproverStart(subject, token!, code);
      return redeemApproverFinish(subject, started, label.trim() || undefined);
    },
  });

  if (!token) {
    return (
      <Frame>
        <section className="card error">
          <p>
            This link carries no invite. Open the whole link your administrator sent,
            including everything after <code>#</code>.
          </p>
        </section>
      </Frame>
    );
  }

  if (!walletReady) {
    return (
      <Frame>
        <section className="card">
          <p className="lead">
            A community administrator invited you to enrol a step-up approver — the key your
            VTA browser plugin keeps behind a gesture, which this community will ask you to
            confirm with before it acts on certain documents you sign.
          </p>
          <div className="finding warn" role="alert">
            <strong>The VTA browser plugin is needed</strong>
            <span>
              Open this link in the browser where your VTA wallet plugin is installed — a build
              with step-up approver support. It signs the enrolment as your DID and holds the
              approver key.
            </span>
          </div>
        </section>
      </Frame>
    );
  }

  return (
    <Frame>
      <section className="card">
        <p className="lead">
          A community administrator invited you to enrol a step-up approver. It never signs you
          in; it answers the confirmation this community asks for before an act that confers
          authority.
        </p>
        {redeem.data ? (
          <div className="finding ok" role="status">
            <strong>Enrolled</strong>
            <span>
              Approver <code className="gitns-party-did">{redeem.data.approver.approverDid}</code>{" "}
              is bound to <code className="gitns-party-did">{redeem.data.approver.subject}</code>.
              When the console asks you to confirm an act, your plugin answers it.
            </span>
          </div>
        ) : (
          <form
            className="form-stack"
            onSubmit={(e) => {
              e.preventDefault();
              redeem.mutate();
            }}
          >
            <Field label="Your DID">
              <input
                value={did}
                onChange={(e) => setDid(e.target.value)}
                placeholder="did:webvh:…"
                required
              />
            </Field>
            <Field label="Claim code">
              <input
                value={code}
                onChange={(e) => setCode(e.target.value)}
                placeholder="the code the administrator sent you separately"
                autoComplete="off"
                required
              />
            </Field>
            <Field label="Label (optional)">
              <input
                value={label}
                maxLength={64}
                onChange={(e) => setLabel(e.target.value)}
                placeholder="Browser plugin — work laptop"
              />
            </Field>
            <p className="muted">
              Your wallet asks you twice: to sign the redemption as your DID, and to unlock the
              approver so it can prove it holds its key.
            </p>
            {redeem.isError && (
              <p className="error" role="alert">
                {approverErrorMessage(redeem.error)}
              </p>
            )}
            <div className="form-actions">
              <button
                type="submit"
                className="primary"
                disabled={redeem.isPending || !did.trim().startsWith("did:") || !code.trim()}
              >
                <ShieldCheck aria-hidden="true" size={14} />{" "}
                {redeem.isPending ? "Waiting for your wallet…" : "Enrol the approver"}
              </button>
            </div>
          </form>
        )}
      </section>
    </Frame>
  );
}
