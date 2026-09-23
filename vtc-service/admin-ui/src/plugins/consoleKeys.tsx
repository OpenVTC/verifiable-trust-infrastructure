// Console signing keys — enable signing for this browser, see the other
// browsers you have enabled it for, and disown one.
//
// Beside "My passkeys" on purpose, because it is the same kind of thing: a
// console key is a credential of your admin DID, enrolled by you behind a
// passkey gesture, listed, and individually revocable. It confers no role of
// its own — authority stays your ACL row, read afresh on every document — so
// enabling a second browser is not a second administrator.
//
// What it is *not* is a second factor. The passkey is possession of an
// authenticator plus user verification; this is possession of a browser
// profile. Every admin-conferring operation still runs the step-up.

import { useCallback, useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { PenLine, ShieldOff } from "lucide-react";

import { useConfirm } from "@/components/ConfirmDialog";
import { formatIso as formatDate } from "@/lib/format";
import { ed25519Available, loadConsoleKey } from "@/lib/console-key";
import {
  enrolThisBrowser,
  isStepUpRequired,
  listConsoleKeys,
  revokeConsoleKey,
  type ConsoleKey,
} from "@/lib/console-keys-api";

/** What this browser holds, and whether it could hold one at all. */
interface LocalState {
  supported: boolean;
  consoleDid: string | null;
}

function useLocalKey(): [LocalState | null, () => void] {
  const [state, setState] = useState<LocalState | null>(null);
  const [epoch, setEpoch] = useState(0);
  useEffect(() => {
    let live = true;
    void (async () => {
      const supported = await ed25519Available();
      const key = supported ? await loadConsoleKey() : null;
      if (live) setState({ supported, consoleDid: key?.consoleDid ?? null });
    })();
    return () => {
      live = false;
    };
  }, [epoch]);
  // Enrolling generates the key and revoking this browser's forgets it, so
  // both change what the screen should say about *this* browser. Without the
  // re-read an operator enrols successfully and the page goes on offering to
  // enrol until they reload.
  return [state, useCallback(() => setEpoch((e) => e + 1), [])];
}

export function ConsoleKeys() {
  const queryClient = useQueryClient();
  const confirm = useConfirm();
  const [local, rereadLocalKey] = useLocalKey();
  const [label, setLabel] = useState("");

  const query = useQuery({
    queryKey: ["console-keys"],
    queryFn: listConsoleKeys,
  });

  const enrol = useMutation({
    mutationFn: () => enrolThisBrowser(label),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["console-keys"] });
      setLabel("");
      rereadLocalKey();
    },
  });

  const revoke = useMutation({
    mutationFn: revokeConsoleKey,
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["console-keys"] });
      rereadLocalKey();
    },
  });

  const keys = query.data ?? [];
  // The server computes `active`; this console does not re-derive it. The two
  // disagreeing is how a page shows a key as working after it stopped.
  const thisBrowser: ConsoleKey | undefined = local?.consoleDid
    ? keys.find((k) => k.consoleDid === local.consoleDid)
    : undefined;
  const enrolled = thisBrowser?.active === true;

  const enrolError = enrol.error as Error | null;

  return (
    <section className="page">
      <h2>Console signing keys</h2>
      <p className="lead">
        A signing key lets this browser author Trust Task documents in your
        name — signed by a key that never leaves it, and authorised by your own
        access-control entry, read at the moment each document runs. It grants
        no role of its own, and you can disown any browser here at any time.
      </p>

      {local && !local.supported && (
        <section className="card">
          <h3>This browser cannot sign</h3>
          <p>
            Signing needs WebCrypto Ed25519 — Chrome 137 or later, Firefox 130
            or later, or Safari 17 or later. The console works normally
            without it; operations that can be signed simply take the older
            route instead.
          </p>
        </section>
      )}

      {local?.supported && !enrolled && (
        <section className="card">
          <h3>Enable signing for this browser</h3>
          <p className="lead">
            {local.consoleDid && !thisBrowser
              ? "This browser holds a key that has not been enrolled — enrolling it is the step below. "
              : local.consoleDid && thisBrowser && !thisBrowser.active
                ? "This browser's key was revoked. Enrolling generates a fresh one: a revoked key can never be re-enrolled. "
                : ""}
            Your browser will prompt for your passkey. That gesture is what
            stops a stolen session leaving a signing key behind.
          </p>
          <form
            onSubmit={(e) => {
              e.preventDefault();
              enrol.mutate();
            }}
            className="form-stack"
          >
            <label className="field">
              <span className="field-label">Label (optional)</span>
              <input
                type="text"
                placeholder="e.g. ‘Work laptop — Chrome’"
                value={label}
                onChange={(e) => setLabel(e.target.value)}
              />
            </label>

            {enrolError && (
              <section className="card error">
                <h3>Could not enable signing</h3>
                <p>
                  {isStepUpRequired(enrolError)
                    ? "Your passkey verification did not complete, or it has since lapsed. Try again and complete the prompt."
                    : enrolError.message}
                </p>
              </section>
            )}

            <div className="form-actions">
              <button
                type="submit"
                className="primary"
                disabled={enrol.isPending}
              >
                <PenLine size={14} aria-hidden="true" />{" "}
                {enrol.isPending ? "Verifying…" : "Enable signing here"}
              </button>
            </div>
          </form>
        </section>
      )}

      {enrolled && (
        <section className="card">
          <h3>This browser signs</h3>
          <p>
            Documents this console sends are signed by{" "}
            <code>{thisBrowser?.consoleDid}</code>. The key stays in this
            browser profile and survives signing out; clearing site data, or
            revoking it below, ends it. Another machine, another browser or a
            private window each need their own.
          </p>
        </section>
      )}

      {query.error && (
        <section className="card error">
          <h3>Failed to load console keys</h3>
          <p>{(query.error as Error).message}</p>
        </section>
      )}

      {revoke.error && (
        <section className="card error">
          <h3>Revoke failed</h3>
          <p>{(revoke.error as Error).message}</p>
        </section>
      )}

      <section className="card">
        <table className="data-table">
          <thead>
            <tr>
              <th>Label</th>
              <th>Key</th>
              <th>Status</th>
              <th>Enrolled</th>
              <th>Last used</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {query.isPending && (
              <tr>
                <td colSpan={6}>Loading…</td>
              </tr>
            )}
            {!query.isPending && keys.length === 0 && (
              <tr>
                <td colSpan={6}>
                  <div className="empty-state">
                    <span className="empty-icon" aria-hidden="true">
                      <PenLine />
                    </span>
                    <h4>No signing keys enrolled</h4>
                    <p>
                      Nothing is wrong — the console works without one. Enable
                      signing above to have this browser author signed
                      documents instead of relying on its session cookie.
                    </p>
                  </div>
                </td>
              </tr>
            )}
            {keys.map((k) => (
              <tr key={k.consoleDid}>
                <td>
                  {k.label ?? <span className="muted">—</span>}
                  {k.consoleDid === local?.consoleDid && (
                    <>
                      {" "}
                      <span className="muted">(this browser)</span>
                    </>
                  )}
                </td>
                <td>
                  <code className="truncate" title={k.consoleDid}>
                    {k.consoleDid}
                  </code>
                </td>
                <td>
                  {k.active ? (
                    "Active"
                  ) : k.revokedAt ? (
                    <span className="muted">
                      Revoked {formatDate(k.revokedAt)}
                    </span>
                  ) : (
                    <span className="muted">Expired</span>
                  )}
                </td>
                <td>{formatDate(k.createdAt)}</td>
                <td>
                  {k.lastUsedAt ? (
                    formatDate(k.lastUsedAt)
                  ) : (
                    <span className="muted">never</span>
                  )}
                </td>
                <td>
                  {k.active && (
                    <button
                      type="button"
                      className="secondary destructive"
                      disabled={revoke.isPending}
                      onClick={async () => {
                        const ok = await confirm({
                          title: k.label
                            ? `Revoke “${k.label}”?`
                            : "Revoke this signing key?",
                          message:
                            k.consoleDid === local?.consoleDid
                              ? "This browser stops signing immediately and forgets its key. You stay signed in, and the console keeps working on its older route. Enabling signing again generates a new key — a revoked one cannot come back."
                              : "That browser stops signing on its very next document. A revoked key cannot be re-enrolled; that browser generates a new one if you enable it again.",
                          confirmLabel: "Revoke",
                          destructive: true,
                        });
                        if (ok) revoke.mutate(k.consoleDid);
                      }}
                    >
                      <ShieldOff size={14} aria-hidden="true" /> Revoke
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
    </section>
  );
}
