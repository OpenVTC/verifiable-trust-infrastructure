### vta-sdk 0.21.17 / vta-service 0.14.30 — the #888 fold reaches `consent/*` (#928)

Same shape as #925, applied to the last family that had unset optional members
going out through an inline `json!` plus a conditional insert each.

New `protocols::consent_management` carries canonical bodies for request,
decision, revoke, list, approver-set and approver-list, each with
`skip_serializing_if` on its optionals. The null census then sees them — it
walks structs under `protocols/` and an inline map is invisible to it — and the
six witnesses are built from the producer's body rather than transcribed.

**Teeth checked, not assumed.** Reverting the skips on `ConsentRequestBody` and
`ConsentListBody` fails the sweep with `null is not of type "string"`. The old
fixtures set those members, so they could not have caught it.

The witnesses are minimal on purpose: `consent/list` and `consent/approver-list`
are now bare `{}` (the unfiltered call), and request sets neither hint. A
witness that fills every member leaves nothing unset, which is exactly where
this defect class lives.

**The count was wrong, and is now measured.** #925's note said 21 witnesses
still transcribed; the real figure was 20 — arithmetic rather than a count. The
module now states **14**, counted from the table, and more usefully splits them
into three situations of which only one is unfinished work:

- **5** (`auth/*`, `task-consent/decision`) — the VTA is the consumer; no
  producer of ours sends these, so a fixture is the honest witness and nothing
  is owed.
- **8** (`vault/*`, `device/list`) — the caller supplies the whole payload as a
  `Value`; the SDK is a pass-through. An API decision, not a test change.
- **1** (`messaging/ping`) — a producer exists, but the payload is a single
  required `nonce`. A body struct would guard nothing today: this defect class
  lives in *unset optional* members and ping has none. Worth folding the day it
  gains a second member, not before.

So the fold is complete for every family that could exhibit the defect. What is
left is one design question and a handful of witnesses that are already correct.
