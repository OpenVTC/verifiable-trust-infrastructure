# vta-signing

The VTA's signing core: the one place that turns a key and a request into
signed bytes, shared by the VTA (`vta-service`, `vta-keys`) and by any service
that signs with keys of its own.

It holds only what is the same wherever a key signs:

- **Keys** — [`SigningSecret`] holds an Ed25519 seed or a P-256 scalar,
  zeroizes it on drop, and signs a message (EdDSA, ES256).
- **JWS** — the header rules (`alg` is the custodian's, `crit`/`b64`/`jwk`/
  `jku`/`x5u` are never signed), the RFC 8785 signing input, and the compact
  serialisation.
- **Data Integrity** — the `eddsa-jcs-2022` proof configuration, its hash data
  and the finished proof.

It holds no storage, no access control, no audit and no transport: those are
what the VTA wraps *around* a signature, and what a service that signs with its
own keys does not need. It has no async code and no I/O, and depends on
nothing in this workspace, so it builds in seconds and pulls in none of the
service's dependencies.

A fix to how a signature is made lands here once, and every signer gets it.

Part of the [Verifiable Trust Infrastructure](https://github.com/OpenVTC/verifiable-trust-infrastructure)
workspace. Apache-2.0.
