### vta-service 0.14.16 — an approver need not hold VTA authority to answer (#907)

A `task-consent/decision` is authorized by the document — the approver's
Data-Integrity proof, checked against the policy-named approver set.
`handle_decision` does not read its `AuthClaims` at all, and the PDP gate already
exempts ceremony tasks from re-gating. But the ACL check every intrinsic-sender
transport (DIDComm, TSP) runs before dispatch did not know that, and refused
those senders outright.

That inverts the model. An approver device holds no authority to *act* — the
whole point of the `approve_scope` axis — so it has no reason to hold an ACL
entry, and the consent subsystem is built for exactly that: both
`compute_delegated_contexts` and the gate's eligibility count read "absent from
the ACL" as *confers nothing*, never as *cannot speak*. Only the transport gate
disagreed, and it disagreed first, before any of the code written to accommodate
that approver could run.

It failed silently in both directions. The VTA replies with a `permissionDenied`
envelope an approver wallet has no reason to recognise, and logs nothing — the
`trust-task received` line and every `consent.decision` audit row live past the
gate. So a decision a human gave and a wallet sent looked, from either end,
exactly like one that was never delivered, while the requester re-submitted into
a pending that could never be granted.

The ceremony predicate now lives in `trust_tasks::ceremony`, shared by the PDP
gate and both transports so the two cannot disagree about what a ceremony task
is. When — and only when — the ACL turns a sender away and the envelope names a
ceremony task, `messaging::auth::auth_for_trust_task_envelope` dispatches on the
proven sender DID over `Role::Monitor` with no contexts: authorized nowhere, and
no session row minted. It is a fallback, not an override — an enrolled sender
keeps the claims its entry earns it, an expired grant does not resurrect its
role, every non-ceremony task from an unenrolled DID is refused as before, and an
unparseable body is not a ceremony task.

The carve-out is floored on approver-set membership for consent decisions, since
a decision citing an unknown digest writes a durable audit row and retention is
time-based rather than size-capped. That keeps the write to DIDs the operator
actually named, without narrowing the population the feature serves. Step-up
`approve-response` is deliberately unfiltered: its authorized signer is
`pending.approver`, recorded at mint and not required to hold an ACL entry (the
delegated phone-as-authorizer), and it writes no audit row on an unknown
challenge.

Both transports now name the sender and type URI when they refuse a trust task,
and a refused ceremony task says which of the two enrolments — approver set or
ACL — is missing.

**Operator note.** An approver device needs to be in the approver set the policy
names; it no longer additionally needs an ACL entry to deliver its decision. An
ACL entry granted purely to get an approver past the transport (e.g.
`--role reader --approve-contexts …` with no act scope) is still honoured and
still what you want when the approver must *confer* a context the requester
lacks — approve-authority for delegation is resolved from live ACL state at the
moment the grant is minted, and is unchanged by this release.
