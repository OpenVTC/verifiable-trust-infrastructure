# vta-test-support

A mock Verifiable Trust Agent for other crates' tests.

- **`MockVta`**: a real VTA (the production router over in-memory state) serving on
  `127.0.0.1:<random port>`, shut down on drop. `start`, `start_provisionable` (a
  self-resolving `did:key` VTA with the keys `provision/integration` needs) and
  `start_with_webvh_host` (plus a stub DID hosting service, so a server-managed
  `did:webvh` round-trips).
- **`transport-harness`** (feature): `MockVta::start_with_transports` — an embedded
  mediator, a `did:peer:2` VTA advertising DIDComm and TSP at it, and the production
  inbound loop, so a test drives a Trust Task over either transport.
- Everything in `vta_service::test_support` (the in-memory store, `build_test_app`,
  `TestAppContext`, the signing helpers), re-exported.

Test-only — never a production dependency.

```toml
[dev-dependencies]
vta-test-support = { version = "0.1", features = ["transport-harness"] }
```

```rust,no_run
# async fn demo() {
let mock = vta_test_support::MockVta::start().await;
let base = mock.base_url();
mock.shutdown().await;
# }
```

Until #2570 this lived in `vta_service::test_support`; a consumer moves from
`vta_service::test_support::MockVta` to `vta_test_support::MockVta`. The fixtures
`vta-service`'s own unit tests use stay in `vta-service`, because a unit test cannot
take a fixture from a crate that depends on the crate under test.
