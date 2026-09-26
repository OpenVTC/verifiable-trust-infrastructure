// `/admin/enrol-step-up` — a member enrolling a **step-up passkey** from a
// community administrator's invite (`auth/passkey/enroll/redeem/{start,finish}/0.1`).
//
// Reached without signing in: the member may be no console user at all. Two
// fragments land here, and the browser sends neither to a server:
//
// - `#token=…` — the invite link the administrator sent. An invite redeems
//   only for the DID it names, so `redeem/start` must be signed by that
//   member's own key, which this browser does not hold: the page shows the
//   `cnm` command that does it.
// - `#enrollment=…` — the link `cnm` prints once the member's signed start is
//   accepted. The passkey is created here, and the finish sent from here: its
//   authority is the ceremony that start opened.
//
// The passkey this creates never signs anyone in. It only answers the passkey
// gesture the community asks of this member for one signed act, such as a git
// break-glass, and always beside the member's own signature on the answer.

import { useMemo, useState } from "react";
import { useLocation } from "react-router-dom";
import { useMutation } from "@tanstack/react-query";
import { Fingerprint } from "lucide-react";

import {
  enrollmentFromHash,
  redeemCommand,
  redeemFinish,
  tokenFromHash,
} from "@/lib/step-up-passkeys";

function message(err: unknown): string {
  if (err && typeof err === "object" && "message" in err) {
    const m = (err as { message: unknown }).message;
    if (typeof m === "string" && m) return m;
  }
  return String(err);
}

function Frame({ children }: { children: React.ReactNode }) {
  return (
    <main className="content">
      <section className="page">
        <h2>Enrol a step-up passkey</h2>
        {children}
      </section>
    </main>
  );
}

export function EnrolStepUpPage() {
  const { hash } = useLocation();
  const token = useMemo(() => tokenFromHash(hash), [hash]);
  const started = useMemo(() => enrollmentFromHash(hash), [hash]);
  const [label, setLabel] = useState("");

  const finish = useMutation({
    mutationFn: () => redeemFinish(started!, label.trim() || undefined),
  });

  if (started) {
    return (
      <Frame>
        <section className="card">
          <p className="lead">
            Create the passkey this community will ask you for before it acts on certain
            documents you sign — breaking the glass on a git right, for one. It never signs
            you in.
          </p>
          {!finish.data && (
            <>
              <dl className="gitns-parties">
                <dt>For</dt>
                <dd>
                  <code className="gitns-party-did">{started.subject}</code>
                </dd>
              </dl>
              <p className="muted">
                Check this is your DID before you continue.
                {started.uvOptions &&
                  " You already hold a step-up passkey: confirm with it first, then create the new one."}
              </p>
              <label>
                Label{" "}
                <input
                  value={label}
                  maxLength={256}
                  onChange={(e) => setLabel(e.target.value)}
                  placeholder={started.deviceLabel ?? "This laptop"}
                />
              </label>{" "}
              <button
                type="button"
                disabled={finish.isPending}
                onClick={() => finish.mutate()}
              >
                <Fingerprint aria-hidden="true" size={14} /> Create the passkey
              </button>
              {finish.isError && (
                <p className="error" role="alert">
                  {message(finish.error)}
                </p>
              )}
            </>
          )}
          {finish.data && (
            <div className="finding ok" role="status">
              <strong>Enrolled</strong>
              <span>
                When the community asks you for a passkey gesture — <code>cnm</code> prints
                a link to its step-up page — answer it with this passkey, and paste the
                answer code back into <code>cnm</code>.
              </span>
            </div>
          )}
        </section>
      </Frame>
    );
  }

  if (token) {
    const command = redeemCommand(window.location.href.split("#")[0] + `#token=${token}`);
    return (
      <Frame>
        <section className="card">
          <p className="lead">
            A community administrator invited you to enrol a passkey this community will ask
            you for before it acts on certain documents you sign. It never signs you in.
          </p>
          <p>
            The invite redeems only for your DID, so start it where your key is: run this in
            your terminal, and type the claim code the administrator sent you separately.
          </p>
          <textarea
            className="answer-code"
            readOnly
            rows={3}
            value={command}
            aria-label="Command to run"
            onFocus={(e) => e.currentTarget.select()}
          />
          <button type="button" onClick={() => void navigator.clipboard?.writeText(command)}>
            Copy
          </button>
          <p className="muted">
            <code>cnm</code> then prints a link back to this page, where your browser creates
            the passkey.
          </p>
        </section>
      </Frame>
    );
  }

  return (
    <Frame>
      <section className="card error">
        <p>
          This link carries no invite. Open the whole link your administrator sent, or the
          one <code>cnm</code> printed, including everything after <code>#</code>.
        </p>
      </section>
    </Frame>
  );
}
