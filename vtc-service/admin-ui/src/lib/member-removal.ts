// `vtc/members/admin-remove/0.1` — an administrator removing another member,
// as a signed document.
//
// Removing a member whose entry is an administrator needs a passkey gesture
// bound to this one removal, and removing another unrestricted administrator
// also needs the approval of an administrator who is neither of you
// (VTI-APV-019). The VTC asks for the first as `details.stepUpRequest`, which
// `postSignedWithStepUp` answers; for the second it parks the removal as an
// administrator action, thrown as a `ParkedAction` (`lib/parked-action.ts`).
// Removing an ordinary member asks for neither.

import { postSignedWithStepUp, type ConfirmGesture } from "./signed-act";

export const MEMBERS_ADMIN_REMOVE_TASK =
  "https://trusttasks.org/spec/vtc/members/admin-remove/0.1";

export async function adminRemoveMember(
  args: { did: string; reason: string },
  confirmGesture: ConfirmGesture,
): Promise<void> {
  // `reason` is omitted rather than sent as `null` — the payload is
  // `deny_unknown_fields` with `reason` an optional string, so `null` is a
  // parse failure rather than "no reason".
  await postSignedWithStepUp<unknown>(
    MEMBERS_ADMIN_REMOVE_TASK,
    args.reason ? { did: args.did, reason: args.reason } : { did: args.did },
    confirmGesture,
  );
}
