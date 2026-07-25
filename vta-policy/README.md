# vta-policy

The VTA's policy subsystem, extracted from `vta-service`.

- **`engine`** — the [regorus](https://crates.io/crates/regorus) (Rego) policy
  engine: compile + evaluate.
- **`defaults`** — the default policy bundle + config-driven consent reconcile.
- **`consent`** — the DTTE consent model (approvals, guards, delegation).
- **`input`** / **`types`** / **`effects`** — policy input construction, the
  shared decision types, and effect/state-pin descriptors.
- **`storage`** — policy + active-policy keyspace storage.

Depends only on `vti-common`, `vta-config`, and `vta-keyspaces` — never on
`vta-service`. `vta-service` re-exports it as `crate::policy`, so every existing
`crate::policy::…` path is unchanged.

Part of the [Verifiable Trust Infrastructure](https://github.com/OpenVTC/verifiable-trust-infrastructure)
workspace. Apache-2.0.
