### vti-common 0.11.34 / vta-service 0.14.10 — see what a Guaranteed send actually did (#899)

A durable send that never reached its mediator was indistinguishable, from the
outside, from one that arrived. `send_guaranteed` returns the moment the outbox
entry is written; the three delivery loops that move it afterwards
(`drain_loop`, `outbox_drain_loop`, `confirmation_loop`) logged nothing. So the
whole state machine — `Queued → Sent → Delivered | Unconfirmed | Failed` — ran
in silence, and a message that settled `Unconfirmed` after its `deliver_by`
elapsed produced no output at all.

This is not hypothetical. Diagnosing a live "the approver is never notified"
report reached the point where the sender logged a correct push (#898: right
approver, right mediator, right transport), the recipient's inbox was confirmed
listening on the right DID, and the message still never appeared. Establishing
that it had never reached the mediator took manually SHA-256'ing DIDs to match
the mediator's hashed recipient records against the VTA's plaintext ones.

## What changed

**`VtiOutboxStore::put` logs every transition.** It is the single point every
state change passes through, so one log site covers the entire lifecycle.
`Unconfirmed` and `Failed` are `warn` — they mean the send is over without
confirmed delivery — and the rest are `info`. An operator scanning for trouble
should not have to know the state machine to spot a message that never arrived.

Each line carries `dest_hash = sha256(dest_did)` alongside the plaintext DID.
The mediator records recipients as hashed DIDs, so this is the field that makes
a sender log line greppable against a mediator one, instead of the hand-hashing
described above.

**`send_guaranteed` stops discarding the message id.** It was bound as
`_msg_id`, leaving nothing to correlate a send against — not the outbox entry,
not the mediator's record, not the recipient's. It now logs `msg_id`,
recipient, type, `deliver_by` and idempotency key *before* the enqueue, so an
enqueue that fails still names what was being sent and to whom.

## Note on expiry

Deliberately unchanged: neither transport carries a message expiry. DIDComm's
`expires_time` is not set (see the comment in `send_guaranteed` — `deliver_by`
bounds hop-retry, not content validity, because a held push must stay
collectable until the request's own `expiresAt`), and the TSP envelope has no
expiry field at all. Expiry for consent requests is application-level:
`task-consent/request/0.1` carries `expiresAt`, and the executor holds the
authoritative `PENDING_TTL_SECS`.

## Scope

Instrumentation only — no behaviour change, no wire types, no config. Same
sends, same recipients, same delivery semantics; the difference is that the
outcome is now on the record.
