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

**Known follow-up, not fixed here:** `vta-mobile-core` derives the operator's
6-character match code from the first characters of the digest. Under
multibase+multihash the first three are always `zQm` — the sha2-256 signature,
not entropy — so the code now carries ~17.6 bits where it carried ~35. It is
left alone deliberately: the value has to agree with whatever the requesting
screen renders, and that implementation is not in this repository. The
principled fix (derive from the decoded digest bytes, skipping the 2-byte
multihash prefix) should ride the same coordinated release as the digest change
itself, since both touch the approver screen.
