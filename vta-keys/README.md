# vta-keys

The VTA's **key management** — master-seed storage, BIP-32 hierarchical key
derivation, key wrapping (AES-GCM), imported-key handling, and the seed-store
backend selection (`create_seed_store`).

Extracted from `vta-service` as a subsystem crate. It depends only on the
shared core (`vta-config`, `vta-keyspaces`, `vti-common`, `vti-secrets`,
`vta-sdk`) — never on `vta-service` — so the key-derivation and seed-store logic
is reusable and independently testable. `vta-service` re-exports it as
`vta_service::keys`, so every `crate::keys::…` reference is unchanged.

This is a security-sensitive crate: seed material is held in `zeroize`-guarded
buffers and private keys never leave the derivation/wrapping layer as plaintext
beyond their intended use.

## Features

Seed-store backend selection — each activates the matching `vti-secrets`
backend: `aws-secrets`, `azure-secrets`, `gcp-secrets`, `vault-secrets`,
`k8s-secrets`, `config-seed`, `keyring`, `tee`. Off by default (the local/dev
VTA uses the keyring or a config seed; the enclave enables `tee`).

Part of the [Verifiable Trust Infrastructure](https://github.com/OpenVTC/verifiable-trust-infrastructure)
workspace. Apache-2.0.
