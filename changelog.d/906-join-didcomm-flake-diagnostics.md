### vtc-service 0.11.52 — make the join_didcomm credential-delivery failure diagnosable (#906)

`didcomm_join_round_trips_submit_manifest_status_approve_and_vmc_delivery` has
failed on CI at least three times across unrelated PRs (#903, #904 — one of them
with a diff that was purely DIDComm framing in another crate). Every failure
produced the same line and no way to act on it:

```
panicked at vtc-service/tests/join_didcomm.rs:288:14:
admission credential delivered over DIDComm
```

**This changes no production behaviour and does not attempt a fix.** It removes
the reasons the failure has never been attributable.

## What the investigation ruled out

- **R1.1 silent drop.** `send_to_member` uses `Delivery::Guaranteed` — durable
  outbox with retries. Not a bare send.
- **Idempotency-key collision.** `deliver_credentials` mints a fresh UUID per
  credential and `push_to_holder` uses it as the message id, so the two pushes
  cannot dedup against each other.
- **Arrival-order race.** Already handled; the test collects both and searches.
- **Runner slowness — the explanation the test itself gives.** It does not fit.
  The bound is already **60s** on a test that completes in ~23s on CI, and the
  client polls every 300ms, so a failure means ~200 consecutive empty polls.
  That is a message that is not there, not one that is late.

Six local runs did not reproduce it. No root cause is claimed here.

## Three blind spots, all removed

**No tracing subscriber.** These tests installed none, so the service's
`warn!("membership-credential delivery failed on approve…")` — the *only* report
of a failed push, and deliberately non-fatal because the credentials are already
issued and returned inline — went nowhere. `init_tracing()` installs one, with
`lsm_tree` filtered out: its temp-dir teardown emits a screenful of harmless
cleanup warnings exactly when a test fails, which would bury the line that
matters.

**The assertion could not distinguish "got 0" from "got 1".** `deliver_credentials`
is a sequential loop with `?`, so a failure on the first push sends **zero** and a
failure on the second sends **one** — different bugs, identical symptom. The
panic now names the index, the timeout, how many arrived, and which of the two
explanations applies.

**`recv_matching` discarded every pickup error.** `if let Ok(Some(..)) = next`
swallowed up to ~200 `Err`s per failure, so a broken socket and an unsent message
looked the same. Errors are now counted and reported on timeout — still
non-fatal, since a transient pickup error is expected and retrying is the point.

## Verified

The new panic path was exercised rather than assumed (timeout shortened, loop
extended by one) and produces:

```
admission credential 3/2 not delivered over DIDComm within 3s (2 already received).
The first arrived and the second did not, so the VTC either failed on the second
`push_to_holder` (again warn-only) or the frame was lost between the mediator and
this client.
```

with no `lsm_tree` noise around it. Restored to 60s / two credentials; the suite
passes.
