// `/admin/enrol-step-up#token=…` — a member redeeming a community
// administrator's invite to enrol a **step-up passkey**
// (`auth/passkey/enroll/redeem/{start,finish}/0.1`).
//
// Reached without signing in: the member may be no console user at all. The
// token rides in the fragment, which the browser never sends to a server; the
// claim code came separately and is typed here. The passkey this creates never
// signs anyone in — it only answers the passkey gesture the community asks of
// this member for one signed act, such as a git break-glass.

import { useMemo, useState } from "react";
import { useLocation } from "react-router-dom";
import { useMutation } from "@tanstack/react-query";
import { Fingerprint } from "lucide-react";

import { redeemFinish, redeemStart, tokenFromHash } from "@/lib/step-up-passkeys";

function message(err: unknown): string {
  if (err && typeof err === "object" && "message" in err) {
    const m = (err as { message: unknown }).message;
    if (typeof m === "string" && m) return m;
  }
  return String(err);
}

export function EnrolStepUpPage() {
  const { hash } = useLocation();
  const token = useMemo(() => tokenFromHash(hash), [hash]);
  const [code, setCode] = useState("");
  const [label, setLabel] = useState("");

  const start = useMutation({ mutationFn: () => redeemStart(token!, code) });
  const finish = useMutation({
    mutationFn: () => redeemFinish(start.data!, label.trim() || undefined),
  });

  if (!token) {
    return (
      <main className="content">
        <section className="page">
          <h2>Enrol a step-up passkey</h2>
          <section className="card error">
            <p>
              This link carries no invite. Open the whole link your administrator
              sent, including everything after <code>#</code>.
            </p>
          </section>
        </section>
      </main>
    );
  }

  return (
    <main className="content">
      <section className="page">
        <h2>Enrol a step-up passkey</h2>
        <section className="card">
          <p className="lead">
            A community administrator invited you to enrol a passkey this community
            will ask you for before it acts on certain documents you sign — breaking
            the glass on a git right, for one. It never signs you in.
          </p>

          {!start.data && (
            <form
              onSubmit={(e) => {
                e.preventDefault();
                start.mutate();
              }}
            >
              <label>
                Claim code — the administrator sent it separately from this link{" "}
                <input
                  value={code}
                  onChange={(e) => setCode(e.target.value)}
                  autoComplete="one-time-code"
                  maxLength={64}
                  required
                />
              </label>{" "}
              <button type="submit" disabled={start.isPending || !code.trim()}>
                Continue
              </button>
              {start.isError && (
                <p className="error" role="alert">
                  {message(start.error)}
                </p>
              )}
            </form>
          )}

          {start.data && !finish.data && (
            <>
              <dl className="gitns-parties">
                <dt>For</dt>
                <dd>
                  <code className="gitns-party-did">{start.data.subject}</code>
                </dd>
              </dl>
              <p className="muted">
                Check this is your DID before you continue.
                {start.data.uvOptions &&
                  " You already hold a step-up passkey: confirm with it first, then create the new one."}
              </p>
              <label>
                Label{" "}
                <input
                  value={label}
                  maxLength={256}
                  onChange={(e) => setLabel(e.target.value)}
                  placeholder={start.data.deviceLabel ?? "This laptop"}
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
                When the community asks you for a passkey gesture — <code>cnm</code>{" "}
                prints a link to its step-up page — answer it with this passkey.
              </span>
            </div>
          )}
        </section>
      </section>
    </main>
  );
}
