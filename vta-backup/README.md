# vta-backup

The VTA's backup/restore subsystem, extracted from `vta-service`.

- **`ops`** — encrypted full-state export (every `BACKED_UP` keyspace, row for
  row; Argon2id KDF + AES-256-GCM), the import that *stages* a restore, the
  `vta_did` compatibility check, and the two-phase descriptor flow for the
  `backup/*` trust tasks.
- **`restore`** — applying a staged restore at boot, under the storage key the
  restored seed yields. A backup restores into a plain, hardened or TEE VTA from
  any of them.
- **`backup_bundle_store`** — the sealed backup-bundle store (bundle records +
  on-disk blobs).
- **`backup_bundle_sweeper`** — TTL sweep of expired backup bundles.

The operations take narrow dependencies (a `BackupTarget` — the store, its
at-rest key and the kind of deployment — plus config) rather than a `&AppState`.
Two `vta-service`-specific glue points are inverted and stay in `vta-service`:

- `DescriptorDeps` are borrowed from `AppState` there via a free constructor
  (`operations::descriptor_deps_from_app_state`).
- How a deployment adopts a restored seed is injected through the
  `RestoreCommitter` trait: `SeedStoreCommitter` here for plain and hardened
  VTAs, and `vta-service`'s enclave committer, which seals the seed under KMS
  and reserves the anti-rollback counter.

Design: `docs/05-design-notes/backup-restore-portability.md`.

`vta-service` re-exports the crate as `crate::operations::backup` +
`crate::{backup_bundle_store,backup_bundle_sweeper}`, so existing call sites are
unchanged.

Part of the [Verifiable Trust Infrastructure](https://github.com/OpenVTC/verifiable-trust-infrastructure)
workspace. Apache-2.0.
