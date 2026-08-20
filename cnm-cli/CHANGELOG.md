# Changelog

Notable changes to the published crates. Generated from conventional commits by
[git-cliff](https://git-cliff.org) when a release is cut — do not edit by hand.
## [0.11.24](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/cnm-cli-v0.11.23...cnm-cli-v0.11.24) — 2026-08-20


## [0.11.23](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/cnm-cli-v0.11.22...cnm-cli-v0.11.23) — 2026-08-18


## [0.11.22](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/cnm-cli-v0.11.21...cnm-cli-v0.11.22) — 2026-08-17


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



## [0.11.21](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/cnm-cli-v0.11.20...cnm-cli-v0.11.21) — 2026-08-16


## [0.11.20](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/cnm-cli-v0.11.19...cnm-cli-v0.11.20) — 2026-08-16


## [0.11.19](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/cnm-cli-v0.11.18...cnm-cli-v0.11.19) — 2026-08-14


## [0.11.18](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/cnm-cli-v0.11.17...cnm-cli-v0.11.18) — 2026-08-14


## [0.11.17](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/cnm-cli-v0.11.16...cnm-cli-v0.11.17) — 2026-08-12


## [0.11.16](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/cnm-cli-v0.11.15...cnm-cli-v0.11.16) — 2026-08-12


## [0.11.15](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/cnm-cli-v0.11.14...cnm-cli-v0.11.15) — 2026-08-12

