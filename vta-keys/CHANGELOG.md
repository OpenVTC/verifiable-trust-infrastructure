# Changelog

Notable changes to the published crates. Generated from conventional commits by
[git-cliff](https://git-cliff.org) when a release is cut — do not edit by hand.
## [0.3.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-keys-v0.2.9...vta-keys-v0.3.0) — 2026-08-26


### Chore

- **deps**: Bring every dependency to latest, collapsing two duplicates ([#1055](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1055))

`cargo outdated` reported 13 direct dependencies behind and `cargo update`
  had 36 compatible updates waiting. Both are now clear: `cargo outdated`
  reports "All dependencies are up to date".

  Two of these were not cosmetic.

  **p256 was duplicated in the build.** Our crates declared `0.13` while
  `affinidi-crypto` — reached through `affinidi-data-integrity` and the TDK —
  already pulled `0.14`, so the graph carried two copies of a curve
  implementation. The lock now holds a single `p256 0.14.0`. The bump brings
  `elliptic-curve` 0.14 and `ecdsa` 0.17, which rename the SEC1 family:
  `EncodedPoint` -> `Sec1Point`, `From/ToEncodedPoint` -> `From/ToSec1Point`.
  Renamed across `vta-keys`, `vta-service` and `vti-webauthn`.

  **tokio-tungstenite was load-bearing, not incidental.** `vta-mobile-core`
  depends on it solely as a feature enabler: iOS has no native trust store, so
  `rustls-tls-webpki-roots` has to be on graph-wide or the mediator WebSocket
  fails with "no native root CA certificates found". Features unify per major
  version, so the declaration only works while it matches the version
  `affinidi-messaging-sdk` pulls — and the SDK moved to 0.30 in this refresh.
  Updating everything *except* this one would have stranded the enabler and
  broken iOS `wss://` silently.

  The rest:

  - `rcgen` 0.13 -> 0.14 (dev). `signed_by` takes an `Issuer` rather than a
    `(certificate, key)` pair, and `self_signed` borrows instead of consuming.
    The mdoc IACA test helper builds its issuer with `Issuer::from_params`,
    which is also a more direct statement of what it wanted.
  - `syn` 2 -> 3 (dev). No source change; syn 3 was already in the graph via
    `trust-tasks-rs`.
  - `rmcp` 1.7 -> 3.1.4. Two majors, one rename: `Content` -> `ContentBlock`.
    The `#[tool_router]` / `#[tool_handler]` macro surface the crate is built
    on is unchanged.
  - 36 lockfile updates, including `trust-tasks-rs` 0.11.3 (the corrected
    `vta/app-state` error taxonomy from dtgwg-trust-tasks-tf#253) and the AWS
    SDK set. `rustls-pemfile`, one of the unmaintained crates `cargo audit`
    flags, drops out of the graph entirely.

  Two deliberate choices where the shortest path was worse:

  `vti-webauthn` keeps parse-then-validate rather than collapsing to the
  one-shot `PublicKey::from_sec1_bytes`. That call merges "malformed SEC1
  encoding" and "valid encoding, point not on the curve" into one error, and
  those say different things to whoever reads the log — a broken client versus
  a point somebody chose.

  BIP-32 P-256 derivation replaces the now-deprecated `FieldBytes::from_slice`
  with `TryFrom` and a real error arm. The input is a fixed 32-byte window of a
  SHA-512 HMAC so it cannot fail, but the length check is now explicit rather
  than resting on a panic inside a deprecated helper.

  Unchanged and still suppressed: the four `cargo audit` advisories ignored in
  `deny.toml`, all transitive through the AWS SDK's hyper 0.14 / rustls 0.21
  path. `cargo deny check advisories` passes.



## [0.2.9](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-keys-v0.2.8...vta-keys-v0.2.9) — 2026-08-22


## [0.2.8](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-keys-v0.2.7...vta-keys-v0.2.8) — 2026-08-21


## [0.2.7](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-keys-v0.2.6...vta-keys-v0.2.7) — 2026-08-20


## [0.2.6](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-keys-v0.2.5...vta-keys-v0.2.6) — 2026-08-18


## [0.2.5](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-keys-v0.2.4...vta-keys-v0.2.5) — 2026-08-17


### Added

- **vta-keys**: Add non-extractable internal signing keys ([#995](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/995))

An ordinary VTA key is BIP-32 derived, so anyone holding the 24-word mnemonic
  can reconstruct it offline. That is what makes the VTA recoverable, and equally
  what makes "the operator cannot obtain this key" false — the second limb of what
  eIDAS calls sole control.

  An internal key is generated from the system CSPRNG, has no derivation path, and
  is never returned by any surface. The VTA acts only as a signing oracle for it.

  Deliberately not a flag on the imported-key path. That path wraps its secrets
  under a KEK derived from the master seed (derive_kek(seed, salt)), so a
  non-extractable flag on it would be decorative: the boundary it claims to
  enforce has already been walked around. Internal keys get their own keyspace,
  INTERNAL_KEYS, with no seed involvement at any point, and that keyspace is in
  EXCLUDED_FROM_BACKUP by design — a backup carrying it would be an export of keys
  the VTA promises never to export, and restoring it elsewhere would clone a
  signer.

  Refused for did:webvh log entries, enforced in code rather than left to
  guidance. WebVH is append-only and each entry is authorised by the update key
  the previous entry named; an unrecoverable update key means that if storage is
  lost the DID can never be updated again by anyone, permanently, and every
  integration pinned to it is stranded. Credentials can be re-issued, an
  append-only identity log cannot. Internal keys remain fine as a signing
  verificationMethod inside a published document, where loss costs the ability to
  produce new signatures rather than control of the identity.

  The export refusal is not a permission check — admin is not a bypass, because
  the value of the origin is that no caller holds this power. There are two
  refusals (an early return and an in-match arm); removing either leaves the other,
  and removing both does not compile, since the match over KeyOrigin becomes
  non-exhaustive. An export path cannot silently reopen.

  Operator surfaces carry the cost prominently: `pnm keys create --internal`
  prints what is lost and requires the operator to type a confirmation phrase
  rather than mash y, the response repeats the warning, and docs/02-vta/
  internal-keys.md covers when to use one, what actually protects it (enclave
  measurement + KMS, not a mnemonic), and the two things that genuinely destroy
  it.



## [0.2.4](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-keys-v0.2.3...vta-keys-v0.2.4) — 2026-08-16


## [0.2.3](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-keys-v0.2.2...vta-keys-v0.2.3) — 2026-08-16


## [0.2.2](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-keys-v0.2.1...vta-keys-v0.2.2) — 2026-08-13


### Added

- **release**: Publish vta-service and its closure again ([#962](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/962))

* feat(release): publish vta-service and its closure again

  #938 unpublished `vta-service` and the twelve subsystem crates behind it,
  on the finding that nothing external depended on them. The audit read
  normal dependencies. `openvtc-core` depends on `vta-service` as a
  **dev-dependency**, for `test_support::MockVta` — an in-process VTA its
  end-to-end tests run against. That harness boots the real service, so no
  client crate can stand in for it.

  Unpublishing did not merely freeze the crate. It broke it.

  `vti-common` re-exports `vta_sdk::acl::{ActScope, ApproveScope,
  ContextDirection}` as its own public API, so **a re-export makes the
  re-exported crate's version part of your public API**: any graph
  combining `vti-common` with another `vta-sdk` consumer must resolve one
  `vta-sdk`. The frozen `vta-service` 0.14.37 asks for `vta-sdk ^0.21`
  while `vti-common` has moved to `^0.23`. A downstream `cargo update`
  resolves both and `vta-service` fails to compile with

    expected `vti_common::acl::ApproveScope`,
       found `vta_sdk::acl::ApproveScope`

  at ten call sites — which is how this surfaced, in openvtc #213. Nothing
  downstream can fix that; only a release that moves the requirements
  together can.

  So the thirteen manifests go back to the workspace default. The cost is
  the closure — twelve subsystem crates return to crates.io, which is
  exactly what #938 set out to stop. Taken deliberately over the
  alternatives: yanking the published copies breaks OpenVTC's tests with no
  replacement, and leaving them up ships a crate on the registry that
  cannot be built.

  **On release ordering.** `cargo publish --dry-run -p vta-service` fails
  today, and will until the closure is on the registry: packaging strips
  path deps, so `vta-keys = "0.2"` resolves the *published* 0.2.1, which
  still asks for `vta-sdk ^0.21` — two nodes, same error. That resolves
  itself in the release, which publishes in dependency order: every
  subsystem crate in this workspace already requires `vta-sdk = "0.23"`, so
  once they upload, `vta-service` verifies against them. Crates whose
  dependencies are all published already dry-run clean (verified on
  `vta-keyspaces` and `vta-config`).

  Docs updated to match: CLAUDE.md, RELEASING.md and the release-plz.toml
  header all said 7-of-21. They now say 20-of-26, name the six that stay
  internal, and record the rule the audit missed — check dev-dependencies,
  in sibling repos, before unpublishing anything.



### Build & CI

- **release**: Adopt release-plz, publish 7 crates instead of 21 ([#938](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/938))

Merging and releasing were the same act. publish.yml fired on every push to
  main and shipped whatever versions were newly present, and a CI guard required
  the version bump to live in the feature PR — so every PR was a release
  decision, taken by whoever opened it, days before it merged. Two open PRs
  touching one crate wrote the same number into the same line of the same
  Cargo.toml, and the second to merge had to rebase, renumber, and fix a
  changelog entry that had gone stale. #932/#936/#937 hit it three times in one
  afternoon.


