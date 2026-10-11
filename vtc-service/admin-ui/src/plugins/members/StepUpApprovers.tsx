// Approver devices — a subject's **step-up approvers** (`auth/step-up/approver/*`).
//
// A step-up approver is the VTA browser plugin's approver `did:key`, bound
// here to one subject as their step-up factor: it answers the bound step-up
// the community asks of them before an act that confers authority, after a
// user gesture unlocks it. It never signs anyone in and confers nothing.
//
// Two places render this card:
//
// - **My passkeys** (`self`): the operator's own approvers, revocable, and —
//   when the wallet plugin can enrol its approver — added self-service, on the
//   evidence of a factor already held (`enroll/0.1`).
// - **Members → member**: an administrator's view of a member's, revocable on
//   their behalf, and the **invite** that lets a member with no factor enrol
//   their first (`invite/0.1`). Never offered for oneself: a factor is never
//   bound on the strength of one's own signing key.

import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ShieldCheck } from "lucide-react";

import { useConfirm } from "@/components/ConfirmDialog";
import { DataTable } from "@/components/DataTable";
import { EmptyState } from "@/components/EmptyState";
import { SigningUnavailableError } from "@/lib/api";
import { gestureFromConfirm } from "@/lib/signed-act";
import {
  approverErrorMessage,
  approverKeys,
  DEFAULT_INVITE_TTL_SECS,
  enrolApproverSelfService,
  ENROLLED_VIA_LABEL,
  fetchApprovers,
  inviteApprover,
  revokeApprover,
  type ApproverInvite,
} from "@/lib/step-up-approvers";
import { useViewerDid } from "@/lib/viewer";
import { isWalletApproverEnrolmentAvailable } from "@/lib/wallet";

import { formatDay } from "../repos/ui";

function loadError(e: unknown): string {
  return e instanceof SigningUnavailableError
    ? "this browser holds no console signing key; enrol one under Settings first."
    : approverErrorMessage(e);
}

export function ApproverDevicesCard({ did, self = false }: { did: string; self?: boolean }) {
  const qc = useQueryClient();
  const confirm = useConfirm();
  const gesture = gestureFromConfirm(confirm);
  const viewer = useViewerDid();
  const key = approverKeys.of(self ? null : did);
  const list = useQuery({
    queryKey: key,
    queryFn: () => fetchApprovers(self ? undefined : did),
  });
  const refresh = () => qc.invalidateQueries({ queryKey: key });

  const [label, setLabel] = useState("");
  const [issued, setIssued] = useState<ApproverInvite | null>(null);

  const revoke = useMutation({
    mutationFn: (approverDid: string) =>
      revokeApprover({ approverDid, ...(self ? {} : { subject: did }) }, gesture),
    onSuccess: refresh,
  });
  const invite = useMutation({
    mutationFn: () =>
      inviteApprover(
        { subject: did, label: label.trim() || undefined, ttl: DEFAULT_INVITE_TTL_SECS },
        gesture,
      ),
    onSuccess: (inv) => {
      setIssued(inv);
      setLabel("");
    },
  });
  const enrol = useMutation({
    mutationFn: () => enrolApproverSelfService({ subject: did, label: label.trim() || undefined }, gesture),
    onSuccess: () => {
      setLabel("");
      void refresh();
    },
  });

  const approvers = list.data?.approvers ?? [];
  const canInvite = !self && !!viewer && viewer !== did;
  const canEnrol = self && isWalletApproverEnrolmentAvailable();

  return (
    <section className="card" aria-labelledby={`approvers-heading-${self ? "self" : "member"}`}>
      <h3 id={`approvers-heading-${self ? "self" : "member"}`}>Approver devices</h3>
      <p className="muted">
        A step-up approver is the VTA browser plugin&apos;s approver key, bound here as{" "}
        {self ? "your" : "this member's"} step-up factor. It answers the confirmation this
        community asks for before an act that confers authority — after a gesture unlocks it —
        and never signs anyone in. Once one is held, ordinary console passkeys no longer count
        for that confirmation.
      </p>
      {list.isPending && <p className="muted">Loading…</p>}
      {list.error && <p className="muted">Could not load: {loadError(list.error)}</p>}
      {!list.isPending && !list.error && (
        <>
          {approvers.length === 0 ? (
            <EmptyState compact title="None enrolled." />
          ) : (
            <DataTable
              columns={[
                { key: "label", label: "Label" },
                { key: "approver", label: "Approver" },
                { key: "via", label: "Bound via" },
                { key: "enrolled", label: "Enrolled" },
                { key: "used", label: "Last used" },
                { key: "actions", label: "" },
              ]}
            >
              {approvers.map((a) => (
                <tr key={a.approverDid}>
                  <td>{a.label ?? <span className="muted">unlabelled</span>}</td>
                  <td>
                    <code className="truncate" title={a.approverDid}>
                      {a.approverDid}
                    </code>
                  </td>
                  <td>{ENROLLED_VIA_LABEL[a.enrolledVia] ?? a.enrolledVia}</td>
                  <td>{formatDay(a.enrolledAt)}</td>
                  <td>
                    {a.lastUsedAt ? formatDay(a.lastUsedAt) : <span className="muted">never</span>}
                  </td>
                  <td>
                    <button
                      type="button"
                      className="danger"
                      disabled={revoke.isPending}
                      onClick={async () => {
                        const ok = await confirm({
                          title: "Revoke this approver?",
                          message:
                            "It can never be bound again. The community asks you to confirm with a step-up factor you hold first. Revoking the last one is allowed: it removes the ability to step up with it, not any authority, and another can be enrolled by invite.",
                          confirmLabel: "Revoke",
                          destructive: true,
                        });
                        if (ok) revoke.mutate(a.approverDid);
                      }}
                    >
                      Revoke
                    </button>
                  </td>
                </tr>
              ))}
            </DataTable>
          )}
          {revoke.error && (
            <p className="error" role="alert">
              Could not revoke: {approverErrorMessage(revoke.error)}
            </p>
          )}

          {canInvite && (
            <>
              <h4>Invite to enrol an approver</h4>
              {issued ? (
                <div className="finding warn" role="status">
                  <p>
                    <strong>Send these two over different channels</strong> — the link by
                    one (email, chat), the code by another (in person, a call, a different
                    app). Either alone is useless; both in one message throws that
                    protection away. The code is shown only now.
                  </p>
                  <p>
                    Link: <code className="gitns-party-did">{issued.url}</code>
                  </p>
                  <p>
                    Claim code: <code>{issued.claimCode}</code>
                  </p>
                  <p className="muted">
                    Valid until {formatDay(issued.expiresAt)} ({issued.expiresAt}). Five wrong
                    codes and it is void.
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
                      maxLength={64}
                      onChange={(e) => setLabel(e.target.value)}
                      placeholder="Browser plugin — work laptop"
                    />
                  </label>{" "}
                  <button type="submit" disabled={invite.isPending}>
                    <ShieldCheck aria-hidden="true" size={14} /> Invite…
                  </button>
                  <p className="muted">
                    Signed by this browser&apos;s console key and confirmed with your own
                    step-up. The member opens the link in the browser with their VTA wallet,
                    types the code, and their wallet signs the enrolment as their own DID.
                  </p>
                  {invite.error && (
                    <p className="error" role="alert">
                      Could not invite: {approverErrorMessage(invite.error)}
                    </p>
                  )}
                </form>
              )}
            </>
          )}

          {self && (
            <>
              <h4>Add this browser&apos;s approver</h4>
              {canEnrol ? (
                <form
                  onSubmit={(e) => {
                    e.preventDefault();
                    enrol.mutate();
                  }}
                >
                  <label>
                    Label (optional){" "}
                    <input
                      value={label}
                      maxLength={64}
                      onChange={(e) => setLabel(e.target.value)}
                      placeholder="Browser plugin — this laptop"
                    />
                  </label>{" "}
                  <button type="submit" disabled={enrol.isPending}>
                    <ShieldCheck aria-hidden="true" size={14} />{" "}
                    {enrol.isPending ? "Enrolling…" : "Add approver"}
                  </button>
                  <p className="muted">
                    Your wallet signs the enrolment as your own DID, and you confirm it with a
                    step-up factor you already hold.
                  </p>
                  {enrol.isSuccess && (
                    <p className="finding ok" role="status">
                      Approver enrolled.
                    </p>
                  )}
                  {enrol.error && (
                    <p className="error" role="alert">
                      Could not enrol: {approverErrorMessage(enrol.error)}
                    </p>
                  )}
                </form>
              ) : (
                <p className="muted">
                  Adding an approver needs the VTA browser plugin with approver support. With
                  no step-up factor yet, ask another community administrator to invite you
                  (Members → you → &quot;Invite to enrol an approver&quot;), or have the
                  operator run <code>vtc admin enrol-approver --did {did}</code> on the host.
                </p>
              )}
            </>
          )}
        </>
      )}
    </section>
  );
}
