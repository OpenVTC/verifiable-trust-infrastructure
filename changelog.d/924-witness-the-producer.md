### vta-sdk 0.21.15 / vta-service 0.14.28 — witness the producer, not a transcription of it (#924)

The conformance sweep (#857) checks a *witness* per task — a request/response
pair — against that task's schema. 26 of its 70 witnesses build their request
from a hand-written `json!` literal rather than from the type the producer
actually sends. A transcription only proves someone can type valid JSON: it
stops tracking the producer the moment the producer changes, and stays green
while live traffic fails.

`vta/webvh/dids/update/1.0` is the worked example, and the reason to start
there: its witness was transcribed, and #895 shipped anyway — every unset member
went out as `null`, so `pnm did-mgmt dids edit --label x` could not run at all.

**The root cause was an API boundary, not laziness.** The request shape for that
family lives in `flatten_with_did` — body members flattened beside `did` — and
that function was private to `vta-sdk`. From another crate the shape was
literally unassertable except by hand-writing it. So `flatten_with_did` is now
`pub` (re-exported as `vta_sdk::client::flatten_with_did`) and the witness is
built by the producer's own shaping.

The witness is deliberately a **one-member** update — `label` and nothing else,
which is the invocation that could not run. A witness that set most members
would leave almost nothing unset and so would not exercise the defect at all;
this was caught while checking the conversion had teeth, because the first
version of it set five members and passed happily with the fix reverted.
Reverting a `skip_serializing_if` now reproduces #895 exactly:

```text
vta/webvh/dids/update/1.0: request fails its own payload schema:
payload failed schema validation: null is not of type "integer"
```

**The remaining 25 are documented accurately for the first time.** The module
claimed they were transcribed because "the slice's wire type is module-private
(consent, task-consent, vault)". That is no longer true — 21 of the 26 name a
`vta-sdk` client method that exists today. The honest position, now recorded per
family:

- **5** (`auth/{whoami,sessions-list,step-up/approve-response}`,
  `task-consent/decision`) — the VTA is the consumer; no producer of ours sends
  these, so a fixture is the correct witness and needs no further work.
- **13** (`consent/*`, `device/*`, `messaging/ping`) — a producer exists but
  builds its payload as an inline `json!` with a conditional insert per optional
  member. There is no type to witness. Converting these means first giving those
  producers canonical body structs — the #888 fold, applied to the families it
  did not reach.
- **7** (`vault/*`) — the SDK is a pass-through over a caller-supplied `Value`
  and contributes at most one member. No SDK type exists, and inventing one is
  an API change rather than a test change.

So the outstanding work is one producer fold plus one API decision, not "rewrite
26 fixtures" — which is a materially smaller and better-shaped job than the
previous comment implied, and the reason to write it down rather than leave it
as a count.
