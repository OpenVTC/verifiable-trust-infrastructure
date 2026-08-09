### vta-policy 0.2.0 / vta-service 0.14.19 / vtc-service 0.11.53 / vta-mobile-core 0.6.18 — trust-tasks 0.4, and the consent digest becomes `digestMultibase` (#911)

Moves the workspace onto `trust-tasks-rs` 0.4.0 (from 0.2.60), now that
`affinidi-messaging-sdk` 0.19.3 depends on it. Before that release the bump
resolved to **two** copies of `trust-tasks-rs` in one graph and broke
`vta-sdk::acl_setup` on a `MediatorAcl` type mismatch; there is now exactly one.

**This carries a wire change.** 0.4 moves `payloadDigest` to the shared
`DigestMultibase` type — a multibase-encoded multihash matching
`^[zumbfF][A-Za-z0-9+/=_-]+$` — and states that "a bare hex string or a
`sha-256:`-style prefix hard-codes one algorithm into the wire contract and is
non-conforming". `vta-policy::consent` emitted bare hex, and because the
dispatcher validates payloads against the published schema, on 0.4 the VTA would
have started **rejecting its own approvers' decisions**. Migrating is not
optional at this version.

- `vta_policy::consent::{payload_digest, wire_digest}` now emit base58btc over
  the sha2-256 multihash (`0x12 0x20` || digest), matching the `did:key` /
  `did:webvh` convention already used by `vta_sdk::did_key`.
- `vta-mobile-core` **parses** the draft digest into `DigestMultibase` rather
  than passing a string through, so a stale hex digest fails at the device that
  would otherwise sign a decision the VTA could never match.
- `TrustTask` gained `parentThreadId`; the two unrouted parse-failure errors pass
  `None` (no thread to name, for the same reason there is no issuer).

**Operators and integrators:** any approver stack that computes the digest
independently — the browser plugin, anything built on an older
`vta-mobile-core` — must move in lockstep. A mismatched pair produces an
approval that is given, accepted by the human, and then silently never takes
effect. In-flight pendings and grants are invalidated by the encoding change;
they are TTL'd at 900s, so the window is short.

**The operator's match code keeps its entropy.** `vta-mobile-core` derives the
6-character comparison code from the digest; slicing the *encoded* string would
have spent three of those six on the constant `zQm` (base58btc marker plus
sha2-256 multihash prefix), leaving ~17.6 bits where the operator believes they
are comparing ~35 — and still looking like six random characters, which is what
would have made it dangerous rather than merely wasteful. `match_code_from_digest`
now decodes and strips the multihash prefix first.

Because the digest is still SHA-256, this reproduces **exactly** the code the
screen showed when the wire carried bare hex (`hex(digest)[..6]` either way), so
the encoding migration is invisible on the approver screen. The pre-existing
assertion `assert_eq!(r.match_code, "3b0c7f")` — written against the hex format —
passes verbatim against multibase, which is the property in evidence rather than
in argument. A stale hex digest is now refused outright rather than silently
producing a code.
