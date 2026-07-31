### vta-sdk 0.21.0 / vta-keys 0.2.0 / vta-service 0.14.0 — the workspace moves to curve25519-dalek 5 (#887)

`ed25519-dalek` 2 → 3, `x25519-dalek` 2 → 3, `curve25519-dalek` 4 → 5 and `hpke`
0.13 → 0.14. These shipped together on 2026-07-06 (hpke on 07-09) and bring the
next-generation RustCrypto stack with them: rand_core 0.10, signature 3,
ed25519 3, aead 0.6.

`vta-sdk` was the single reason `curve25519-dalek` 4 could not leave the
affinidi-tdk-rs graph. It pinned `curve25519-dalek = "4"` directly, plus
ed25519-dalek 2, x25519-dalek 2 and hpke 0.13, and every TDK consumer inherits
that through the mediator.

- **`vta-sdk`**: **breaking.** Dalek types sit in public signatures —
  `protocols::acl_management::swap::build_swap_presentation` takes
  `&ed25519_dalek::SigningKey` — so callers must move to ed25519-dalek 3 in
  step. `sealed_transfer::hpke` loses its hand-rolled `OsCsprng` adapter, which
  existed only to bridge `getrandom` onto hpke 0.13's rand_core 0.9 traits;
  hpke 0.14 ships OS-CSPRNG variants of `single_shot_seal` / `gen_keypair`
  backed by `UnwrapErr(SysRng)`, the same panic-on-CSPRNG-failure posture the
  adapter documented. **The sealed-transfer wire format is unchanged** and the
  randomness posture is unchanged.
- **`vta-keys`**: ephemeral X25519 wrapping-key generation moves to
  `rand::rng()`. rand 0.10 renamed `OsRng` → `SysRng` *and* made it fallible
  (`TryRng<Error = SysError>`), so it no longer satisfies dalek's `CryptoRng`
  bound; `rand_core` 0.10 has no `OsRng` at all.
- **`vta-service`**: two sites passed an `ed25519-dalek-bip32` `SigningKey`
  straight into a workspace slot. That crate (0.3, last released 2023-08) still
  pins ed25519-dalek 2 and has no v3, so its `SigningKey` is now a *different
  type* — they cross the boundary as raw bytes, which is what every other
  derivation site here already did.

**`ed25519-dalek-bip32` keeps a dalek-2 subtree** in vta-service, vta-keys and
didcomm-test. It is contained: the crate is absent from `vta-sdk`'s dependency
tree, so it never reaches TDK consumers. Removing it means reimplementing
SLIP-0010 ed25519 derivation — security-sensitive, and tracked separately
rather than folded into a dependency bump.

**Version-pin fan-out.** `vta-sdk`'s minor bump moves the `version = "0.20"`
requirement every dependent carries, and a changed requirement has to publish or
the registry keeps resolving the old one. Those crates are otherwise untouched —
their own APIs do not change — so they take patch bumps: **cnm-cli 0.11.14**,
**pnm-cli 0.11.17**, **vta-audit 0.1.2**, **vta-backup 0.1.5**,
**vta-cli-common 0.10.23**, **vta-support 0.2.3**, **vta-tee 0.1.5**,
**vta-vault 0.1.2**, **vta-webvh 0.1.3**, **vtc-client 0.3.1**,
**vtc-service 0.11.50**, **vti-common 0.11.32**, **vti-secrets 0.1.9**.

**Sequencing for consuming repos.** `curve25519-dalek` 4 does not fully leave
this workspace on merge. The `affinidi-*` crates are the other dalek-2 source
inside `vta-sdk`'s own tree, so the order is: affinidi-tdk-rs publishes its leaf
crypto crates on dalek 3 (with `affinidi-crypto` going to 0.3.0 — a public
break, since `PrivateKeyAgreement::X25519` holds an `x25519_dalek::StaticSecret`)
→ `vta-sdk` 0.21.0 publishes → `affinidi-messaging-mediator` moves its
`vta-sdk ^0.20.0` requirement to `^0.21` and publishes → the lockfile here drops
the registry `vta-sdk` node, and dalek 4 with it. Until that third step lands,
`[patch.crates-io] vta-sdk` no longer applies (mediator 0.18.0 requires
`^0.20.0`) and the registry copy stays in `Cargo.lock`.
