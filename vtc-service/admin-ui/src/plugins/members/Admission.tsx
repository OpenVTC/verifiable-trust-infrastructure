// Direct admission in the console (`lib/member-admission.ts`):
//
//  - `<AddMemberForm>` — the Members page's **Add a member**: a DID, a role
//    (default Member) and an optional label, admitted without a join request.
//  - `<MakeMembershipButton>` — **Make this a membership**, on an
//    access-control entry with no member record.
//  - `<EntriesWithoutMembership>` — the Members page's list of such entries,
//    so a bootstrap administrator who cannot sign in to the member portal sees
//    why and what to do.
//
// The community's `admission` policy decides both: either is admitted at once,
// refused, or sent to another administrator for approval — a parked action,
// shown as `<ParkedNotice>` / a toast linking to it, never as an error.

import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { UserCheck } from "lucide-react";

import { useConfirm } from "@/components/ConfirmDialog";
import { DataTable } from "@/components/DataTable";
import { DidText } from "@/components/DidText";
import { Field } from "@/components/Field";
import { ErrorOrParked } from "@/components/ParkedNotice";
import { fetchAllAcl, type AclEntry } from "@/lib/acl";
import {
  ADMIT_ROLES,
  admitMember,
  admittedSentence,
  canMakeMembership,
  makeMembership,
  type AdmittedMember,
} from "@/lib/member-admission";
import { parkedOf } from "@/lib/parked-action";
import { gestureFromConfirm } from "@/lib/signed-act";
import { useToast } from "@/lib/toast";

/** Where the community's admission policy is read and changed. */
export const ADMISSION_POLICY_PATH = "/ceremonies?purpose=admission";

/** Re-read what a direct admission changes. */
function useAdmissionInvalidation() {
  const queryClient = useQueryClient();
  return () => {
    for (const key of ["members", "acl", "actions"]) {
      void queryClient.invalidateQueries({ queryKey: [key] });
    }
  };
}

/** The sentence every direct-admission control carries: it skips the join
 *  criteria, and the community's policy may send it for approval. */
export function GovernedNote() {
  return (
    <p className="muted field-hint">
      This skips the join criteria and vetting. Depending on this community's{" "}
      <Link to={ADMISSION_POLICY_PATH}>admission policy</Link>, it is admitted at once or sent to
      another administrator for approval on the Actions page.
    </p>
  );
}

export function AddMemberForm({ onClose }: { onClose: () => void }) {
  const confirm = useConfirm();
  const toast = useToast();
  const invalidate = useAdmissionInvalidation();
  const [subject, setSubject] = useState("");
  const [role, setRole] = useState("member");
  const [label, setLabel] = useState("");
  const [reason, setReason] = useState("");
  const [done, setDone] = useState<AdmittedMember | null>(null);

  const mutation = useMutation({
    mutationFn: () =>
      admitMember({ subject, role, label, reason }, gestureFromConfirm(confirm)),
    onSuccess: (m) => {
      setDone(m);
      toast.push("success", admittedSentence(m));
      invalidate();
    },
    onError: (err) => {
      // Parked for approval: a success, shown in place below.
      if (parkedOf(err)) invalidate();
    },
  });

  const validDid = subject.trim().startsWith("did:");
  const roleHint = ADMIT_ROLES.find((r) => r.id === role)?.hint;

  return (
    <section className="card" aria-labelledby="add-member-title">
      <h3 id="add-member-title">Add a member</h3>
      <GovernedNote />
      <form
        className="form-stack"
        onSubmit={(e) => {
          e.preventDefault();
          setDone(null);
          mutation.mutate();
        }}
      >
        <Field label="DID" hint="The identity to admit. It must not hold an access-control entry already.">
          <input
            required
            placeholder="did:key:z6Mk…"
            value={subject}
            onChange={(e) => setSubject(e.target.value)}
          />
        </Field>
        <Field label="Role" hint={roleHint}>
          <select value={role} onChange={(e) => setRole(e.target.value)}>
            {ADMIT_ROLES.map((r) => (
              <option key={r.id} value={r.id}>
                {r.title}
              </option>
            ))}
          </select>
        </Field>
        <Field label="Label" hint="Optional. How this member is named in the console.">
          <input maxLength={256} value={label} onChange={(e) => setLabel(e.target.value)} />
        </Field>
        <Field label="Reason" hint="Optional. Recorded in the audit trail and shown to approvers.">
          <input maxLength={1024} value={reason} onChange={(e) => setReason(e.target.value)} />
        </Field>
        <div className="form-actions">
          <button type="submit" className="primary" disabled={!validDid || mutation.isPending}>
            {mutation.isPending ? "Adding…" : "Add member"}
          </button>
          <button type="button" className="secondary" onClick={onClose}>
            Close
          </button>
        </div>
      </form>
      {done && (
        <p className="success" role="status">
          {admittedSentence(done)}
        </p>
      )}
      <ErrorOrParked title="Could not add the member" error={mutation.error} />
    </section>
  );
}

export function MakeMembershipButton({ entry }: { entry: AclEntry }) {
  const confirm = useConfirm();
  const toast = useToast();
  const invalidate = useAdmissionInvalidation();
  const mutation = useMutation({
    mutationFn: () => makeMembership(entry.subject, gestureFromConfirm(confirm)),
    onSuccess: (m) => {
      toast.push("success", admittedSentence(m));
      invalidate();
    },
    onError: (err) => {
      // A parked act is a success: the toast links to the action.
      toast.pushFromError(err, "Make this a membership failed");
      if (parkedOf(err)) invalidate();
    },
  });
  return (
    <button
      type="button"
      className="secondary"
      disabled={mutation.isPending}
      title="Issue a member record and membership credentials for this entry, keeping its role and authority"
      onClick={async () => {
        const ok = await confirm({
          title: "Make this a membership?",
          message:
            `${entry.subject} keeps the role and authority its entry holds and becomes a member, ` +
            "with membership credentials, without a join request. Depending on this community's " +
            "admission policy it happens at once or is sent to another administrator for approval.",
          confirmLabel: "Make a membership",
        });
        if (ok) mutation.mutate();
      }}
    >
      <UserCheck size={14} aria-hidden="true" /> Make this a membership
    </button>
  );
}

/**
 * Access-control entries with no member record — administrators and
 * integrations who hold access but cannot sign in to the member portal. Hidden
 * when there are none, or when the viewer may not read the ACL.
 */
export function EntriesWithoutMembership() {
  const query = useQuery({
    queryKey: ["acl", "all", "membership"],
    queryFn: () => fetchAllAcl(),
  });
  const entries = (query.data ?? []).filter(canMakeMembership);
  if (query.isError || entries.length === 0) return null;
  return (
    <section className="card" aria-labelledby="no-membership-title">
      <h3 id="no-membership-title">Access without a membership</h3>
      <p className="muted">
        These entries hold access to this community but have no member record, so they cannot sign
        in to the member portal. Making one a membership keeps its role and authority.
      </p>
      <DataTable
        columns={[
          { key: "did", label: "DID" },
          { key: "role", label: "Community role" },
          { key: "label", label: "Label" },
          { key: "actions", label: "" },
        ]}
      >
        {entries.map((e) => (
          <tr key={e.subject}>
            <td>
              <DidText did={e.subject} />
            </td>
            <td>
              <code>{e.ext?.["org.openvtc"]?.communityRole ?? "member"}</code>
            </td>
            <td>{e.label ?? <span className="muted">—</span>}</td>
            <td>
              <MakeMembershipButton entry={e} />
            </td>
          </tr>
        ))}
      </DataTable>
    </section>
  );
}
