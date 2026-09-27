# vta-webvh

The VTA's local `did:webvh` store, extracted from `vta-service` so the
`did:webvh` DID-lifecycle subsystem and its other consumers can depend on it
without pulling in the whole service.

- **`webvh_store`** — the local `did:webvh` DID-record + hosting-server record
  store (fjall `webvh` keyspace).

The client to a DID hosting service is `vta_service::webvh_host`: every call is
a Trust Task over the transport the host advertises (TSP, DIDComm or HTTPS).
`vta-service` re-exports this module as `crate::webvh_store` (behind its
`webvh` feature).

Part of the [Verifiable Trust Infrastructure](https://github.com/OpenVTC/verifiable-trust-infrastructure)
workspace. Apache-2.0.
