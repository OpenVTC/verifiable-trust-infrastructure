# vta-support

Shared mid-layer services for the VTA, extracted from `vta-service` so the
subsystem crates can depend on them without depending on the whole service.

- **`contexts`** — trust-context storage (the BIP-32 key-hierarchy roots).
- **`seal`** — the sealed-transfer producer-side seal helper.
- **`sealed_nonce_store`** — the sealed-bootstrap anti-replay nonce store.

Each is a self-contained near-leaf, depending only on `vti-common`,
`vta-config`, `vta-keyspaces`, and `vta-sdk`. `vta-service` re-exports each as
`crate::<module>`, so existing call sites are unchanged.

Part of the [Verifiable Trust Infrastructure](https://github.com/OpenVTC/verifiable-trust-infrastructure)
workspace. Apache-2.0.
