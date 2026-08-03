### vta-service 0.14.9 — say when an approver is not notified (#898)

A consent request the VTA decides not to push produced **no output on a normal
deployment**. The skip was `tracing::debug!`, so at INFO the log showed a
perfectly healthy sequence — `pending:raised`, requests minted and signed, a 422
back to the caller — with nothing to indicate that no device had been told.

From the outside that is indistinguishable from a device that is simply asleep,
and the two have opposite fixes: one is a config error on the VTA, the other is
a client that needs to reconnect. Diagnosing a real "nothing pops up" report
against production logs came down to guessing between them, because the one line
that decides it was compiled to a level nobody runs.

## What changed

- The no-route skip is now `warn`, and says what it means: the approver will not
  learn of this request unless the **requester** relays it — which a CLI cannot
  do to a browser extension. It also reports the configured mediator, since a
  `did:key` approver routes via the VTA's own `[messaging] mediator_did` and an
  unset one is the most likely cause.
- A successful push logs at `info` with the approver DID, the mediator and the
  transport. "Who did we notify, and how?" was previously unanswerable from a
  normal log — the approver DID appeared nowhere, so an approver-set entry
  pointing at a stale device DID looked identical to a working push.

The push log is emitted *before* the enqueue rather than after. The enqueue is
the last thing this service controls; beyond it the message is the mediator's to
hold and the device's to collect, and silence there is not ours to claim either
way. What must be on the record is that we tried, to which DID, over which
mediator — so a missing prompt can be attributed to a side instead of argued
about.

## Not changed

`push_granted`'s equivalent skip stays at `debug`. That notice is explicitly
best-effort and non-load-bearing — the requester re-submits regardless and the
single-use grant is the real gate — so a lost one costs a poll cycle, not an
approval. Raising it would add noise without adding a decision anyone acts on.

No behaviour changes: the same requests are pushed to the same approvers by the
same routes. This only makes the existing decision visible.
