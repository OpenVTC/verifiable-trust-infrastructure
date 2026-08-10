### vtc-service 0.11.55 — one credential's failure no longer abandons the rest (#918)

`deliver_credentials` was a `for` loop ending in `push_to_holder(..).await?`, so
the first failure returned and every **remaining** credential was silently
dropped.

Admission delivers two — the MembershipCredential and the role
EndorsementCredential — as independent one-way deposits. A transient failure on
the first therefore meant the member never received their role credential, and
never would: `send_to_member` enqueues with `Delivery::Guaranteed`, so the
retry-until-delivered machinery lives *behind* the very call that was skipped.
Nothing was queued, so nothing was retried.

The caller only `warn!`s — correctly, since the credentials are already issued
and persisted and a delivery failure must not unwind the decision that issued
them. The result was a member admitted into the community with a credential
missing from their wallet and a single log line to say so.

Independent deposits have no reason to share a fate. Each credential is now
attempted regardless of what happened to the others, and the error names every
one that failed, by credential *type* rather than position — "the
EndorsementCredential did not go" is actionable where "credential 2 of 2" is a
puzzle. A per-credential `warn!` fires as each failure happens, so the log shows
which ones went and which did not rather than only the first casualty.

#### Tests

`a_failed_credential_does_not_abandon_the_rest` drives delivery with messaging
deliberately not running, so every push fails identically, and asserts the error
names **both** credentials. Under the old short-circuit it names only the first;
verified by re-introducing the early return, which fails the test.

#### Not the `join_didcomm` flake

This was found while investigating
`didcomm_join_round_trips_…_vmc_delivery`, which intermittently fails with "1 of
2 credentials delivered". It is **not** the cause, and this change does not fix
it:

- In that failure the *second* push is the one that goes missing, so
  short-circuiting after it abandons nothing. The outcome is identical before
  and after this change.
- The CI log for the failing run carries **no** VTC delivery-failure warning —
  and that test defaults its subscriber to `warn`, so one would have printed.
  Both sends succeeded.

That places the loss on the receive side (the client's pickup loop or the
mediator), not on the VTC's send. Recorded here so the next investigation starts
from that, rather than re-examining a send path now known to be sound.

Local reproduction was attempted and failed — 30 runs under CPU contention, all
green — so the next CI occurrence is the only chance to observe it. To keep that
chance from being wasted a fourth time, the test's default log filter now runs
`affinidi_messaging_delivery` at `debug`, which prints `drain_once`'s per-tick
`sent` / `retried` / `failed` report. A passing run shows `sent=2`; a failing run
showing `sent=1` puts the loss in the sender's outbox, and `sent=2` puts it at
the mediator or below. Three counters per 2s tick, printed only for a failing
test — it costs nothing until it is needed, and it turns the next occurrence
into evidence instead of another round of inference.
