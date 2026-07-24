# vta-config

The VTA's configuration types — the `AppConfig` TOML shape and its sub-configs
(`PolicyConfig`, and under the `tee` feature `TeeConfig` / `TeeKmsConfig` /
`TeeMode`). It composes the shared config types from `vti-common`
(`AuthConfig`, `LogConfig`, `StoreConfig`, `MessagingConfig`, `AuditConfig`,
`VaultConfig`) and `vti-secrets` (`SecretsConfig`), re-exporting them so a
consumer names everything through one crate.

Extracted from `vta-service` as a near-leaf so the subsystem crates
(`vta-keys`, `vta-tee`, `vta-backup`, …) can depend on the VTA's config shape
without depending on `vta-service`. `vta-service` re-exports it as
`vta_service::config`, so every `crate::config::…` reference is unchanged.

## Features

- `tee` — the TEE deployment config (`TeeConfig`, `TeeKmsConfig`, `TeeMode`,
  and the `AppConfig.tee` field). Off by default; the enclave binary enables it.

Part of the [Verifiable Trust Infrastructure](https://github.com/OpenVTC/verifiable-trust-infrastructure)
workspace. Apache-2.0.
