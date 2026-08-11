### vta-sdk 0.21.16 / vta-service 0.14.29 — the #888 fold reaches `device/*` (#925)

The `device/*` client methods built their payloads as an inline `json!` plus a
conditional insert per optional member:

```rust
let mut payload = json!({ "consumerKind": …, "displayName": … });
if let Some(p) = platform { payload["platform"] = json!(p); }
```

That shape is not wrong — the conditional insert is exactly what kept `null` off
the wire — but it is **unguarded and untestable**, and both matter:

- **Unguarded.** The invariant lives in the shape of an `if let`, so nothing
  checks it. `vta-sdk`'s null census (#921) walks structs under `protocols/` and
  would have caught `keys/create` (#919); it cannot see an inline map. The next
  person who reaches for a struct here — as #888 did for `keys/create` —
  reintroduces the defect with nothing to stop them.
- **Untestable.** A conformance witness has no type to point at, so it
  hand-writes the JSON and stops tracking the producer the moment the producer
  changes.

New `protocols::device_management` carries canonical bodies for register,
heartbeat, disable, wipe and set-wake, each with `skip_serializing_if` on its
optionals. Both properties then fall out for free: the census enforces the
invariant, and the five witnesses are **built** rather than transcribed.

**The conversion has teeth, checked rather than assumed.** Reverting the skips on
`DeviceHeartbeatBody` now fails the sweep:

```text
device/heartbeat/0.1: request fails its own payload schema:
payload failed schema validation: null is not of type "string";
null is not of type "integer"
```

The old fixture set both members and so could not have caught it — the same trap
that made #924's first webvh conversion pass vacuously.

**The witnesses got smaller on purpose.** The old device fixtures set members no
producer here sends — `keyCustody`, `attestation`, `pushPlatform`, `issuedAt`.
A witness asserting members we never emit proves nothing about our wire form,
and leaves almost nothing unset, which is where this class of defect lives. The
heartbeat witness is now a bare `{}` — the "still here" call — and register sets
neither optional.

Only what the client can actually send is modelled: `attestation` and
`keyCustody` are in the schema but have no producer, and a field nothing sets is
a claim the type should not make.

`device/list` is **not** folded. Like `vault/*`, it takes a caller-supplied
`Value` filter object and the SDK is a pass-through; giving it a type is an API
change, not a test change. It stays a transcription, now recorded as such.

The conformance module's per-family account is updated: 21 witnesses still
transcribe (from 26), of which 5 are consumer-only and correct as they stand,
7 (`consent/*` + `messaging/ping`) await this same fold, and 8 are
pass-throughs awaiting an API decision.
