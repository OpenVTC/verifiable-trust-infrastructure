# vta-webvh

WebVH hosting infrastructure for the VTA, extracted from `vta-service` so the
`did:webvh` DID-lifecycle subsystem and its other consumers can depend on it
without pulling in the whole service.

- **`webvh_store`** — the local `did:webvh` DID-record + server-record store
  (fjall `webvh` keyspace).
- **`webvh_client`** — the HTTP client to a remote `did:webvh` hosting server.
- **`webvh_auth`** — the DID-auth handshake the client uses against that host.

Each depends only on `vti-common`, `vta-keyspaces`, `vta-sdk`, and
`affinidi-tdk`. `vta-service` re-exports each as `crate::<module>` (behind its
`webvh` feature), so existing call sites are unchanged.

Part of the [Verifiable Trust Infrastructure](https://github.com/OpenVTC/verifiable-trust-infrastructure)
workspace. Apache-2.0.
