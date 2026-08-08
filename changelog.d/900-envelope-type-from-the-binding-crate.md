### vta-service 0.14.11 — the DIDComm envelope type comes from the binding crate (#900)

A consent request pushed to an approver device was delivered, acked, and then
discarded unread. The DIDComm message carried the **task** type
(`task-consent/request/0.1`) where the binding requires the **envelope** type
(`binding/didcomm/0.1/envelope`) with the `TrustTask` in the body. A conformant
peer rejects that — and rejects it *silently*, because "not an envelope" is
indistinguishable from "not addressed to me".

The symptom was a week of nothing: the request arrived on the approver's inbox,
verified, de-duplicated, and vanished. No prompt, no log, no decision, and the
mediator's queued copy already deleted by the ack.

## Why it drifted

The envelope URI was hand-written in **four** places across the workspace, each
with a comment explaining it was a local copy "to avoid taking a dependency on
the binding crate for one constant". Nothing connected `consent_request.rs` to
the binding it was supposed to implement, so it used the task type and no
compiler, test, or reviewer noticed.

`trust-tasks-didcomm` is now a real dependency and
`trust_tasks_didcomm::ENVELOPE_TYPE` is the single source; the four copies are
gone. The crate that defines the wire format defines the constant.

## TSP is deliberately untouched

The envelope is a property of the **DIDComm binding**, not of the task. TSP
carries the Trust-Task bytes directly with no wrapper, and the TSP branch of
`push_one` was always correct. Applying the envelope unconditionally would have
broken the working transport to fix the broken one — the fix is confined to the
two DIDComm sites (the mediator buffer and the guaranteed send).

## The test was pinning the defect

`a_resubmit_re_asks_nobody` asserted `message_type == TASK_CONSENT_REQUEST_0_1`
— the task type on the wire, which is exactly what a conformant peer refuses. It
now asserts the envelope on the message and the task type inside the document,
which is the actual invariant.

## Known remaining, not in this change

Same defect, same peer, to be fixed together: `push_granted`
(`TASK_CONSENT_GRANTED_0_1`) and `maybe_push_step_up`
(`STEP_UP_APPROVE_REQUEST_TYPE`) — **step-up approvals to a device are broken
identically** and have not been noticed. `consent.rs`'s
`CONSENT_APPROVE_REQUEST_TYPE` needs its family confirmed.

Separately, `webvh_didcomm.rs` sends bare task types to the webvh host and
*works*, so that peer accepts them. Converting it is a cross-repo wire migration,
not a cleanup, and must not be swept in.
