# vta-tee

The VTA's TEE (Trusted Execution Environment) bootstrap subsystem, extracted
from `vta-service`. Only the `vta-enclave` binary exercises it at runtime; the
local/dev VTA builds it behind the `tee` feature.

- **`provider` / `nitro` / `sev_snp` / `simulated` / `detect`** — attestation
  provider abstraction and the concrete backends.
- **`kms_bootstrap`** — KMS attest/decrypt, JWT-fingerprint check, storage-key
  derivation, and the CMS unwrap (`aws-lc-rs`).
- **`anchor`** — the DynamoDB-backed anti-rollback anchor MAC.
- **`admin_bootstrap`** — Mode-B first-boot admin provisioning + the single-use
  carve-out.
- **`did_autogen`** — first-boot DID autogeneration.
- **`mnemonic_guard`** — the one-shot, timed, zeroized mnemonic export window.

Depends only on the extracted leaf/foundation crates (`vti-common`,
`vta-keyspaces`, `vta-config`, `vta-keys`, `vta-support`) plus the AWS SDK /
crypto stack — never on `vta-service`. `vta-service` re-exports it as
`crate::tee` (behind the `tee` feature), so `vta_service::tee::…` keeps
resolving for `vta-enclave` and every existing call site.

Part of the [Verifiable Trust Infrastructure](https://github.com/OpenVTC/verifiable-trust-infrastructure)
workspace. Apache-2.0.
