### vta-service 0.14.26 — mediator-backed DIDComm + TSP transports for `MockVta` (#920)

- **`MockVta::start_with_transports`** (new `transport-harness` feature) starts
  a mock VTA reachable over **DIDComm and TSP** as well as REST: an embedded
  `affinidi-messaging-test-mediator`, a `did:peer:2` identity advertising
  `DIDCommMessaging` + `TSPTransport` at it, and the **production** inbound loop
  — so a Trust Task on either transport reaches the same
  `dispatch_trust_task_core` spine the REST route uses. The REST-only mock could
  not express this: a `did:key` carries no service block, so a client could only
  ever choose REST. A `did:peer:2` resolves offline in the **consumer's own**
  resolver with nothing seeded, which is what makes the harness usable from
  another process.
- **Watch the DID size.** Every `DIDCacheClient` refuses a DID over
  `max_did_size_in_bytes` (default 1000) before parsing, and neither side says
  so: the client fails the websocket connect as `isActive? command timed out`,
  the mediator answers `403` with `authcrypt requires sender public key`. Only
  `affinidi_did_authentication` logs the real reason. The harness therefore
  embeds the mediator DID in one service, points `#tsp` at the mediator URL
  (test-scoped; production `did:webvh` keeps the mediator-DID convention), and
  asserts the length at mint time.
- CI now **runs** the harness — `transport-harness` is not a default feature, so
  `cargo test --workspace` never compiled it.
