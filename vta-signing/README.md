# vta-signing

The VTA's signing core: the one place that turns a key and a request into
signed bytes, shared by the VTA (`vta-service`, `vta-keys`) and by any service
that signs with keys of its own.

It holds everything that is the same wherever a key signs:

- **Keys** — `SigningSecret` holds an Ed25519 seed or a P-256 scalar, zeroizes
  it on drop and signs; `PublicKey` verifies and converts to and from a
  `did:key`; the `Signer` trait is what a hardware or remote key implements.
- **Framing** — what a signature over bytes the signer did not build means
  (`SigningDomain`, the opaque-signing domain tag).
- **JWS** (`keys/sign-jws/0.1`) — the header rules (`alg` is the custodian's;
  `crit`/`b64`/`jwk`/`jku`/`x5u` are never signed), the RFC 8785 signing input,
  the compact serialisation, and verification.
- **Data Integrity** (`keys/sign-document/0.1`) — the `eddsa-jcs-2022` proof
  configuration, hash data, proof and verification.
- **SSHSIG** (`keys/sign-sshsig/0.1`) — the statement an SSH signature covers.
- **Signer rules** — which key may sign as which DID, read from a DID document.

Every format is built in phases so a signer that wraps the signature in its own
gates (the VTA's access control, key custody, quota and audit) and one that holds
the key build the same bytes: `prepare_*` builds what is signed, the signature
is made however the key is held, `finish_*` builds the artefact. `sign_*` is the
three in one call for a `Signer`.

It holds no storage, no access control, no audit and no transport: those are
what the VTA wraps *around* a signature, and what a service that signs with its
own keys does not need. It has no async code and no I/O, and depends on nothing
in this workspace, so it builds in seconds and pulls in none of the service's
dependencies.

A fix to how a signature is made lands here once, and every signer gets it.

## Not yet here

Signing code the VTA still keeps for itself, each moved deliberately in a later
change rather than here:

- **Certificate signing requests** (`keys/sign-csr/0.1`): the DER builders take
  the generated wire types and an X.509 encoder.
- **Trust Task proofs, holder presentations and consent receipts**, which sign
  through `affinidi-data-integrity` over its own key type.
- **Room, voting and witness signatures**, and the `did:webvh` log updates.

Part of the [Verifiable Trust Infrastructure](https://github.com/OpenVTC/verifiable-trust-infrastructure)
workspace. Apache-2.0.
