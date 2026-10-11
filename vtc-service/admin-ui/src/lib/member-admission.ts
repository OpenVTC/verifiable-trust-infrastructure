// Direct admission — an administrator admitting a DID without a join request
// (`vtc-service/src/ceremony/admission.rs`):
//
//  - **Add a member** (`vtc/members/admit/0.1`): a DID with no access-control
//    entry is admitted at a role — the entry, the member record and the
//    membership credentials, as a completed join leaves them.
//  - **Make this a membership** (`vtc/members/make-membership/0.1`): an entry
//    with no member record (a bootstrap administrator, typically) gets the
//    member record and credentials at the role it already holds.
//
// Both bypass the join criteria, so the community's `admission` policy decides
// them (Policies → Other policies → admission). It may admit at once, refuse,
// or refer the act to another holder of `vtc.members.manage`: then the act is
// parked as an administrator action after a passkey gesture bound to it, and
// the signed door throws a `ParkedAction` (`lib/parked-action.ts`) — a
// success, shown as one, that completes itself when it is approved. A role
// carrying administrative authority asks for that gesture even when the
// policy admits at once.

import { postSignedWithStepUp, type ConfirmGesture } from "./signed-act";
import type { AclEntry } from "./acl";

export const MEMBERS_ADMIT_TASK = "https://trusttasks.org/spec/vtc/members/admit/0.1";
export const MEMBERS_MAKE_MEMBERSHIP_TASK =
  "https://trusttasks.org/spec/vtc/members/make-membership/0.1";

/** The community roles *Add a member* offers. `admin` is never one: add a
 *  member, then promote them on Access control. */
export const ADMIT_ROLES: readonly { id: string; title: string; hint: string }[] = [
  { id: "member", title: "Member", hint: "No administrative authority." },
  {
    id: "moderator",
    title: "Moderator",
    hint: "Manages members, join requests and invitations. Needs vtc.roles.assign, and a passkey gesture.",
  },
  {
    id: "issuer",
    title: "Issuer",
    hint: "Issues and revokes credentials. Needs vtc.roles.assign, and a passkey gesture.",
  },
];

export interface AdmitRequest {
  subject: string;
  role: string;
  label?: string;
  reason?: string;
}

/** The membership as admitted (both tasks answer it). */
export interface AdmittedMember {
  subject: string;
  role: string;
  label?: string;
  status: "admitted";
  returning: boolean;
  approval: "policyAllowed" | "approved" | "waived";
  statusListIndex: number;
  vmc: unknown;
  roleVac: unknown;
}

/** Drop the optional members that are blank: the payload is
 *  `deny_unknown_fields` with them optional strings, so `""` and `null` are
 *  not "none". */
function compact(req: AdmitRequest): AdmitRequest {
  const out: AdmitRequest = { subject: req.subject.trim(), role: req.role };
  const label = req.label?.trim();
  const reason = req.reason?.trim();
  if (label) out.label = label;
  if (reason) out.reason = reason;
  return out;
}

/** `vtc/members/admit/0.1`. Throws a `ParkedAction` when the policy refers it. */
export function admitMember(
  req: AdmitRequest,
  confirmGesture: ConfirmGesture,
): Promise<AdmittedMember> {
  return postSignedWithStepUp<AdmittedMember>(MEMBERS_ADMIT_TASK, compact(req), confirmGesture);
}

/** `vtc/members/make-membership/0.1`. Throws a `ParkedAction` when the policy
 *  refers it. */
export function makeMembership(
  subject: string,
  confirmGesture: ConfirmGesture,
  reason?: string,
): Promise<AdmittedMember> {
  const r = reason?.trim();
  return postSignedWithStepUp<AdmittedMember>(
    MEMBERS_MAKE_MEMBERSHIP_TASK,
    r ? { subject, reason: r } : { subject },
    confirmGesture,
  );
}

/** What the ACL listing says of an entry's membership
 *  (`ext["org.openvtc"].membership`); `undefined` from a VTC that predates it. */
export type Membership = "active" | "none" | "removed";

export function membershipOf(e: AclEntry): Membership | undefined {
  return e.ext?.["org.openvtc"]?.membership;
}

/** Whether *Make this a membership* applies to `e`: it has no member record,
 *  and is not an `application` entry (git rights held by a non-member, which
 *  joins through the join flow). */
export function canMakeMembership(e: AclEntry): boolean {
  return membershipOf(e) === "none" && e.ext?.["org.openvtc"]?.communityRole !== "application";
}

/** What a completed admission's notice says. */
export function admittedSentence(m: AdmittedMember): string {
  const how =
    m.approval === "waived"
      ? " (single-administrator mode waived the approval)"
      : m.approval === "approved"
        ? " after approval"
        : "";
  return `${m.subject} is now a member (${m.role})${how}${m.returning ? ", re-admitted" : ""}.`;
}
