// A member's step-up passkeys, on their page (`crate::step_up_passkey`).
//
// A step-up passkey answers one thing only: an operation-bound step-up issued
// to this member — the passkey gesture a git break-glass always needs. It
// never signs anyone in. A member who is no console user can get one only
// through a community administrator's invite, so this card is where it
// starts: the administrator steps their own session up, issues the invite,
// and delivers the URL and the claim code to the member **over two different
// channels**. The administrator also revokes one here — verifying with their
// own passkey — when the member has lost it.

import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Fingerprint } from "lucide-react";

import { useConfirm } from "@/components/ConfirmDialog";
import { stepUpSession } from "@/lib/step-up";
import {
  fetchStepUpPasskeys,
  inviteStepUpPasskey,
  revokeStepUpPasskey,
  stepUpPasskeyKeys,
} from "@/lib/step-up-passkeys";
import type { StepUpPasskeyInvite } from "@/lib/wire-types";

import { formatDay, readErrorMessage } from "../repos/ui";

export function StepUpPasskeysCard({ did }: { did: string }) {
  const qc = useQueryClient();
  const confirm = useConfirm();
  const list = useQuery({
    queryKey: stepUpPasskeyKeys.of(did),
    queryFn: () => fetchStepUpPasskeys(did),
  });
  const [label, setLabel] = useState("");
  const [issued, setIssued] = useState<StepUpPasskeyInvite | null>(null);

  const invite = useMutation({
    mutationFn: async () => {
      // The gesture is tied to this click: issuing an invite lets someone
      // bind a second factor to a member, which is an act of authority.
      await stepUpSession();
      return inviteStepUpPasskey(did, label.trim() || undefined);
    },
    onSuccess: (inv) => {
      setIssued(inv);
      setLabel("");
    },
  });
  const revoke = useMutation({
    mutationFn: (credentialId: string) => revokeStepUpPasskey(did, credentialId),
    onSuccess: () => qc.invalidateQueries({ queryKey: stepUpPasskeyKeys.of(did) }),
  });

  const creds = list.data?.credentials ?? [];
  return (
    <section className="card" aria-labelledby="member-step-up-heading">
      <h3 id="member-step-up-heading">Step-up passkeys</h3>
      <p className="muted">
        A step-up passkey only answers a passkey gesture this community asks of
        this member for one signed act — a git break-glass, for instance. It never
        signs anyone in. Without one, a member who is no console user cannot break
        the glass.
      </p>
      {list.isPending && <p className="muted">Loading…</p>}
      {list.error && <p className="muted">Could not load: {readErrorMessage(list.error)}</p>}
      {!list.isPending && !list.error && (
        <>
          {creds.length === 0 ? (
            <p className="muted">None enrolled.</p>
          ) : (
            <table className="data-table">
              <thead>
                <tr>
                  <th>Label</th>
                  <th>Enrolled</th>
                  <th>Last used</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {creds.map((c) => (
                  <tr key={c.credentialId}>
                    <td title={c.credentialId}>
                      {c.deviceLabel ?? <span className="muted">unlabelled</span>}
                    </td>
                    <td>{formatDay(c.registeredAt)}</td>
                    <td>{c.lastUsedAt ? formatDay(c.lastUsedAt) : <span className="muted">never</span>}</td>
                    <td>
                      <button
                        type="button"
                        className="danger"
                        disabled={revoke.isPending}
                        onClick={async () => {
                          const ok = await confirm({
                            title: "Revoke this step-up passkey?",
                            message:
                              "You verify with your own passkey. The member can no longer answer a step-up with it — including one they have already been asked for — until they enrol another through a new invite.",
                            confirmLabel: "Revoke",
                            destructive: true,
                          });
                          if (ok) revoke.mutate(c.credentialId);
                        }}
                      >
                        Revoke
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          {revoke.error && (
            <p className="error" role="alert">
              Could not revoke: {readErrorMessage(revoke.error)}
            </p>
          )}

          <h4>Invite to enrol one</h4>
          {issued ? (
            <div className="finding warn" role="status">
              <p>
                <strong>Send these two over different channels</strong> — the link
                by one (email, chat), the code by another (in person, a call, a
                different app). Either alone is useless; both in one message
                throws that protection away. The code is shown only now.
              </p>
              <p>
                Link: <code className="gitns-party-did">{issued.invite.url}</code>
              </p>
              <p>
                Claim code: <code>{issued.claimCode}</code>
              </p>
              <p className="muted">
                Valid until {formatDay(issued.expiresAt)} ({issued.expiresAt}). Five
                wrong codes and it is void.
              </p>
              <button type="button" onClick={() => setIssued(null)}>
                Done
              </button>
            </div>
          ) : (
            <form
              onSubmit={(e) => {
                e.preventDefault();
                invite.mutate();
              }}
            >
              <label>
                Suggested label (optional){" "}
                <input
                  value={label}
                  maxLength={256}
                  onChange={(e) => setLabel(e.target.value)}
                  placeholder="Carol's laptop"
                />
              </label>{" "}
              <button type="submit" disabled={invite.isPending}>
                <Fingerprint aria-hidden="true" size={14} /> Invite…
              </button>
              <p className="muted">
                Confirms with your passkey first. The member opens the link, types
                the code and creates the passkey on their own device.
              </p>
              {invite.error && (
                <p className="error" role="alert">
                  Could not invite: {readErrorMessage(invite.error)}
                </p>
              )}
            </form>
          )}
        </>
      )}
    </section>
  );
}
