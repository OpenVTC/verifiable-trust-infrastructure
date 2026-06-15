# vti-secrets

Pluggable **secret-store backends** + the **integration onboarding flow** for
the Verifiable Trust Infrastructure (VTI) workspace, shared by first-party
services *and* external integrations.

These backends + the `create_seed_store` factory previously lived inside
`vta-service`, so an external integration (e.g. a messaging-platform bridge)
could not reuse them without depending on the whole service binary crate. This
crate lifts them out so an integration can persist its identity seed and
per-connector credentials via the exact same backends the VTA uses, and onboard
the exact same way.

## What it provides

- `SeedStore` — the storage trait (re-exported from `vti-common`).
- Concrete backends, each behind its own feature flag:
  `aws-secrets`, `gcp-secrets`, `azure-secrets`, `vault-secrets`,
  `k8s-secrets`, `keyring`, `config-seed`, `tee` (in-enclave KMS), and the
  always-available plaintext dev fallback.
- `create_seed_store(&secrets, &data_dir)` — the feature-aware factory.
- `SecretsConfig` — the `[secrets]` config shape.
- *(feature `onboarding`)* `IntegrationOnboarding` — the ephemeral-`did:key`
  → context-scoped ACL grant → auto-rotate-on-first-connect cold-start flow,
  wrapping `vta-sdk`'s `SessionStore`.

## Example

```rust,ignore
use vti_secrets::{SecretsConfig, create_seed_store, SeedStore};

let secrets = SecretsConfig { /* k8s_secret_name: Some(...), ... */ ..Default::default() };
let store = create_seed_store(&secrets, std::path::Path::new("./data"))?;
let seed = store.get().await?;
```

See `docs/02-vta/secret-backends.md` for the full backend reference.
