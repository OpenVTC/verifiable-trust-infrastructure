# vta-backup

The VTA's backup/restore subsystem, extracted from `vta-service`.

- **`ops`** — encrypted full-state export/import (Argon2id KDF + AES-256-GCM),
  the `vta_did` compatibility check, and the two-phase descriptor flow for the
  `backup/*` trust tasks.
- **`backup_bundle_store`** — the sealed backup-bundle store (bundle records +
  on-disk blobs).
- **`backup_bundle_sweeper`** — TTL sweep of expired backup bundles.

The operations take narrow dependencies (keyspace handles, config, a
`vta_keyspaces::Keyspaces` bundle) rather than a `&AppState`. Two
`vta-service`-specific glue points are inverted and stay in `vta-service`:

- `DescriptorDeps` / `apply_import` are borrowed from `AppState` there via free
  constructors (`operations::descriptor_deps_from_app_state`).
- TEE KMS re-encryption during import is injected through the
  `BootstrapReEncryptor` trait, whose one implementation wraps `vta-service`'s
  `tee::kms_bootstrap::re_encrypt_bootstrap_secrets`.

`vta-service` re-exports the crate as `crate::operations::backup` +
`crate::{backup_bundle_store,backup_bundle_sweeper}`, so existing call sites are
unchanged.

Part of the [Verifiable Trust Infrastructure](https://github.com/OpenVTC/verifiable-trust-infrastructure)
workspace. Apache-2.0.
