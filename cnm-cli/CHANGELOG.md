# Changelog

Notable changes to the published crates. Generated from conventional commits by
[git-cliff](https://git-cliff.org) when a release is cut — do not edit by hand.
## [0.13.6](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/cnm-cli-v0.13.5...cnm-cli-v0.13.6) — 2026-09-06


## [0.13.5](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/cnm-cli-v0.13.4...cnm-cli-v0.13.5) — 2026-09-06


## [0.13.4](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/cnm-cli-v0.13.3...cnm-cli-v0.13.4) — 2026-09-06


## [0.13.3](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/cnm-cli-v0.13.2...cnm-cli-v0.13.3) — 2026-09-01


## [0.13.2](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/cnm-cli-v0.13.1...cnm-cli-v0.13.2) — 2026-08-29


## [0.13.1](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/cnm-cli-v0.13.0...cnm-cli-v0.13.1) — 2026-08-29


## [0.13.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/cnm-cli-v0.12.2...cnm-cli-v0.13.0) — 2026-08-28


### Fixed

- **sdk**: Give every authenticated client its identity, and adopt provision/integration 0.3 ([#1147](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1147))

#1146 made every producer sign, and left seven production paths building
  clients that cannot. Each authenticates, takes the token, and drops the DID and
  key on the floor — so every task they dispatch is refused for a missing
  `recipient` and `proof`. `SessionStore::connect` was fixed; nothing else was,
  because no test drives those paths against an enforcing VTA.



### Chore

- **sdk**: Release vta-sdk 0.30.0 for the added CreateKeyBody field ([#1156](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1156))

`CreateKeyBody` gained a `key_id` field while the crate stayed at 0.29.0.
  The struct is exhaustively constructible through the public API, so an
  existing literal no longer compiles — a breaking change under 0.x rules,
  which the semver report has been flagging as its one real finding
  (195 pass, 1 fail) since the field landed.

  Bumps the crate and the nineteen intra-workspace requirements that pin it,
  so `cargo check --workspace` still resolves the path copy and a consumer
  resolving from the registry gets a version that admits the break.



## [0.12.2](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/cnm-cli-v0.12.1...cnm-cli-v0.12.2) — 2026-08-26


## [0.12.1](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/cnm-cli-v0.12.0...cnm-cli-v0.12.1) — 2026-08-22


## [0.12.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/cnm-cli-v0.11.24...cnm-cli-v0.12.0) — 2026-08-21


### Fixed

- **sdk/cli**: A credential store that cannot be opened must not read as "never logged in" ([#1032](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1032))

All four binaries treated an unavailable OS credential store as a warning
  and carried on. What happened next was worse than a silent fallback:
  `KeyringBackend` stayed registered, every `Entry::new` returned
  `NoDefaultStore`, and `SessionBackend::load` swallowed it and returned
  `None` — so the tool behaved exactly as though the user had never logged
  in. A silent fallback at least stores something; this silently forgets.
  OpenVTC hit the user-facing end of it: a profile kept in the Linux kernel
  keyring did not survive a reboot, and the error told the user to check
  their network.

  The four call sites are byte-identical, but their consequences are not,
  so the fix is not:

  - `pnm` and `cnm` keep their session — the admin DID and its private key
    — in the credential store and nowhere else. They now exit at startup
    via `keyring_init::install_default_store_or_exit`, which is the whole
    point: there is nothing they can usefully do next.
  - `vta` and `vtc` never construct an SDK `SessionStore`; they use the
    fjall-backed `KeyspaceSessionStore`, and their keyring use is the seed
    store, one of eight `[secrets] backend` options. Which one is in play
    is not known until config loads, long after `main` starts, so hard
    failing there would break every deployment on aws/gcp/azure/vault/k8s
    running on a host with no credential store — the normal server shape.
    They get `warn_store_unavailable`, and `KeyringSeedStore` — which
    already failed closed — now says which subsystem broke rather than
    "failed to create keyring entry".

  The second half is `FileBackend`. `default_backend` ended in an
  `#[allow(unreachable_code)]` fallback into it whenever no backend feature
  was enabled, writing the admin private key to `sessions.json` as
  plaintext at the process umask, announced by a WARNING on every access —
  which is to say, invisible. `pnm`'s own bootstrap-secrets path has always
  used 0600; the inconsistency was inside one tool.

  That fallback is gone. A build with no session store gets `RefusingBackend`,
  which refuses to save rather than inventing somewhere to put a private
  key. `FileBackend` is now reachable only by explicit choice — the
  `config-session` feature, or `VTI_SECURE_STORE=file` at runtime — and
  creates its file at 0600 inside a 0700 directory *before* writing, since
  writing and then hardening leaves a window at the umask. An existing
  world-readable file from an older build is re-hardened on the next write.

  The runtime override exists because requiring a rebuild to run on a
  headless host creates pressure to disable the check rather than make a
  choice. It parses strictly: `os` or `file`, and anything else — including
  a near-miss like `plaintext` — resolves to neither and refuses. Asking
  for `os` on a build with no `keyring` feature refuses too, rather than
  quietly substituting a file.

  One explanation now serves every tool, in `vta_sdk::secure_store`, taking
  the error as `Display` so it is available without the `keyring` feature —
  OpenVTC renders the same text and honours the same override, which was
  the stated goal: identical secret handling across vta, pnm, openvtc and
  vtc, hard failure rather than a fallback to open text files.



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

