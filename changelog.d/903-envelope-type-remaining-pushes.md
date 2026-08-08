### vta-service 0.14.13 — the last three device pushes carry the envelope type (#903)

#901 fixed the consent-request push and named three sites it had not reached.
This is those three. Same defect, same binding rule, same silence: the DIDComm
message carried the **task** type where `trust_tasks_didcomm::ENVELOPE_TYPE` is
required with the `TrustTask` in the body, and a conformant peer rejects that
without saying so — "not an envelope" is indistinguishable from "not addressed
to me".

| site | protocol family | what the breakage cost |
|---|---|---|
| `push_granted` | `task-consent/*` | a requester waits for its next poll instead of re-submitting at once |
| `maybe_push_step_up` | `auth/step-up/*` | **delegated step-up approvals never reached the device** |
| `maybe_wake_consent_approver` | `consent/*` | a `wake`-routed approver is never roused |

## The one that mattered

`maybe_push_step_up` had been broken the entire time and nothing surfaced it.
The reject still carries the `approveRequest` as a relay fallback, so the
ceremony completes by the slow route while the proactive push lands in a void —
delivered, acked, unreadable. A push whose only failure mode is *latency* is a
push nobody notices is dead.

## Protocol family, confirmed rather than assumed

`consent/approve-request/0.1` belongs to **`spec/consent/*`** — the conversation
consent family (`request` / `decision` / `revoke` / `list`, all `1.0`) — not to
`spec/task-consent/*`, which is the per-task RP→wallet family `consent_request.rs`
serves. The distinction does not change the fix: neither family puts its task
type on the DIDComm envelope, because the envelope belongs to the binding, not
the task.

## Also

`STEP_UP_APPROVE_REQUEST_TYPE` was the DIDComm message type *and* the document
type. Now it is only the document type — and `mint_pending_step_up` reads the
constant instead of repeating the literal, so the two cannot drift. Its
`#[cfg(feature = "didcomm")]` gate came off with that move: the mint site is not
DIDComm-specific.

TSP is untouched, deliberately. It carries the document bytes directly
(`serde_json::to_vec(doc)` → `send_routed`), so the wrapper is a property of the
DIDComm binding. Every `ENVELOPE_TYPE` import is `#[cfg]`-gated to the feature
combination that actually sends over DIDComm, so reduced builds neither break nor
carry an unused import.

## Tests

Four new tests, each asserting the **envelope on the message** and the **task
type inside the document** — the shape #901 established when it un-pinned
`a_resubmit_re_asks_nobody`. Verified to actually catch the defect: reinstating
the old `message_type` on the step-up push fails
`delegated_step_up_push_is_an_envelope` with the task URI on the left and the
envelope URI on the right.

`vta-service` compiles clean at `--no-default-features` and with each of
`didcomm`, `rest`, `tsp`, `didcomm,tsp`, `rest,didcomm,webvh,tsp`.
