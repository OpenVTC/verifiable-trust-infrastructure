# Changelog

Notable changes to the published crates. Generated from conventional commits by
[git-cliff](https://git-cliff.org) when a release is cut — do not edit by hand.
## [0.4.1](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-secrets-v0.4.0...vti-secrets-v0.4.1) — 2026-09-22


## [0.4.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-secrets-v0.3.17...vti-secrets-v0.4.0) — 2026-09-22


### Fixed

- **vta**: Contexts/secrets requires KeyExport (VTI-VTA-003) ([#1634](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1634))

`vta/contexts/secrets/1.0` (`get_context_secrets`) released a context DID's
  private keys to any `Application`-role caller in that context. Its only gate
  was the role floor (`require_write`, which also admits `Initiator`) plus the
  context scope. VTI-VTA-003 says an export of derived key material "MUST be
  gated by a capability distinct from the capability to use the key, and MUST
  be audited". The audit was already there; the separate capability was not.
  An `Application` can *use* its context's keys through the signing oracle, and
  under the old gate that also let it *take* them. That is the case the
  requirement exists for: keys that were taken stay with the caller after its
  authority is withdrawn.

  ## The gate

  `get_context_secrets` now requires `Capability::KeyExport`, the same
  capability `keys/export-secret` requires. It reads the caller's **entry**,
  like `ensure_may_mint` ([#1619](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1619)), so a narrowing that removes `key-export` from
  an admin stops the next fetch. With no entry, the role decides. A store error
  refuses the call. The gate replaces the `require_write` role floor. The
  existing `require_context` scope check and the per-key `key.secret_export`
  audit are unchanged.

  `KeyExport` stays exactly as #1619 left it: derived by `admin` alone, and not
  grantable to any other role. So the service that operates a context's DID
  must be an admin **scoped to that context**. Integrations onboarded through
  `provision-integration` already have that grant: the mediator, did-hosting
  and the VTC. They are not affected.

  ## Who is affected

  Any `application` or `initiator` entry that fetches its context's secrets
  through `VtaClient::fetch_did_secrets_bundle` or
  `vta_sdk::integration::startup`. The known one is **room-host**, whose
  enrolment instructions granted `--role application`. After upgrading, such a
  caller gets `permissionDenied`, which the SDK surfaces as
  `VtaError::Forbidden` on REST, DIDComm and TSP. The message names the command
  that fixes it for that caller's entry:

  - an existing non-admin scoped to the context:
    `pnm acl change-role --did <did> --from application --to admin`
    (this keeps the entry's contexts);
  - an entry with no contexts: `pnm acl update <did> --contexts <CONTEXT>`
    first. The fix never suggests promoting an unscoped entry, because that
    would mint a super-admin;
  - an admin narrowed without `key-export`:
    `pnm acl update <did> --capabilities <existing>,key-export`
    (the narrowing is restated, never `--capabilities-all`);
  - no entry: `pnm acl create --did <did> --role admin --contexts <CONTEXT>`.

  ## Also changed

  - room-host's `grant_instructions` and its missing-DID help now grant a
    context-scoped admin (`vta import-did --role admin --context <C>` /
    `pnm acl create --role admin --contexts <C>`).
  - `vti-secrets` gains `OnboardingTicket::admin_import_did_command`. Its module
    docs now separate integrations that only call the VTA (`application`) from
    those that load their DID's keys (context-scoped `admin`).
  - Doc comments on the task constant, the handler, the SDK method and
    `get_context_secrets`. `docs/02-vta/integration-guide.md` gains a
    "Who may fetch a context's secrets" section.

  ## Tests (VTI-VTA-003)

  - The `operations/export.rs` tests that asserted the old loosening are
    rewritten.
  - New tests cover these cases: an Application is refused, an Initiator is
    refused, a context admin gets the bundle, an admin narrowed without
    `key-export` is refused, an admin of another context is refused, an
    unscoped non-admin is told to scope first, and a reader is refused. The
    entitlement-before-existence non-leak test now runs against both gates.
  - A handler-level test checks that the refusal is `permissionDenied` and
    carries the fix command.



## [0.3.17](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-secrets-v0.3.16...vti-secrets-v0.3.17) — 2026-09-21


## [0.3.16](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-secrets-v0.3.15...vti-secrets-v0.3.16) — 2026-09-21


## [0.3.15](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-secrets-v0.3.14...vti-secrets-v0.3.15) — 2026-09-21


## [0.3.14](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-secrets-v0.3.13...vti-secrets-v0.3.14) — 2026-09-20


## [0.3.13](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-secrets-v0.3.12...vti-secrets-v0.3.13) — 2026-09-18


## [0.3.12](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-secrets-v0.3.11...vti-secrets-v0.3.12) — 2026-09-17


## [0.3.11](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-secrets-v0.3.10...vti-secrets-v0.3.11) — 2026-09-16


## [0.3.10](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-secrets-v0.3.9...vti-secrets-v0.3.10) — 2026-09-16


## [0.3.9](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-secrets-v0.3.8...vti-secrets-v0.3.9) — 2026-09-16


## [0.3.8](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-secrets-v0.3.7...vti-secrets-v0.3.8) — 2026-09-15


### Fixed

- **deps**: Bound aws-smithy-types below 1.7, which breaks aws-smithy-json 0.63 ([#1485](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1485))

A fresh dependency resolution stopped compiling:

      error[E0308]: expected `DocumentObject`, found `HashMap<String, Document>`
        --> aws-smithy-json-0.63.0/src/codec/deserializer.rs:707:37
      error[E0004]: non-exhaustive patterns: `&_` not covered
        --> aws-smithy-json-0.63.0/src/serialize.rs:36:15

  `aws-smithy-types` 1.7.0 changed `Document::Object` from
  `HashMap<String, Document>` to a new `DocumentObject`, and added a variant
  to an enum that is `#[non_exhaustive]` — a breaking change shipped as a
  MINOR bump. `aws-smithy-json` 0.63.0 declares `aws-smithy-types = "^1.6.1"`,
  which admits 1.7.0 and then does not compile against it.

  Cargo unifies `aws-smithy-types` to one version across the graph but keeps
  both `aws-smithy-json` 0.63 and 0.64 — 0.x minors are incompatible majors —
  so the two coexist and only the 0.63 copy breaks. We have both because
  `aws-sdk-secretsmanager` 1.116.0 moved to json `^0.64.0` while `aws-config`
  1.12.0, its newest release, still wants `^0.63.0`. Both reach us:
  `vti-secrets` behind `aws-secrets`, and `vta-tee` unconditionally, so a
  plain `cargo build --workspace` is affected as well as the secrets path.

  Cargo.lock already held 1.6.3, so committed builds were never affected and
  only a lockless resolution broke — which is what `cargo install --path`
  does unless given `--locked`. That is how this was met:

      cargo install --path vtc-service --no-default-features \
        --features setup,website,admin-ui,aws-secrets,tsp

  `--locked` remains the right flag for a reproducible install. This bound is
  what keeps `cargo update` and a lockless build honest too.

  The bound is declared once in `[workspace.dependencies]` with the
  reasoning, and referenced from the two crates that pull `aws-config` —
  Cargo only honours a version requirement from a crate that declares it, so
  a workspace entry alone would constrain nothing. Neither crate calls it.

  `>= 1.6.1, < 1.7` rather than `= 1.6.3`: 1.6.1 is aws-smithy-json 0.63.0's
  own floor, and the upper bound excludes the break without freezing out
  patch releases in the working line. **Remove it when `aws-config` ships a
  release on json 0.64.**

  Verified, on this branch:

    - without the bound, a lockless resolve picks aws-smithy-types 1.7.0 with
      aws-smithy-json 0.63.0 AND 0.64.0 — the failing combination
    - with it, a lockless resolve picks 1.6.3, json 0.63.0 alone, and backs
      aws-sdk-secretsmanager off to 1.115.0
    - Cargo.lock moves by two lines, both dependency edges; no version churn
    - `cargo check -p vti-secrets --no-default-features --features aws-secrets`
      and `cargo check -p vtc-service --no-default-features --features
      setup,website,admin-ui,aws-secrets,tsp` both pass



## [0.3.7](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-secrets-v0.3.6...vti-secrets-v0.3.7) — 2026-09-12


## [0.3.6](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-secrets-v0.3.5...vti-secrets-v0.3.6) — 2026-09-10


## [0.3.4](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-secrets-v0.3.3...vti-secrets-v0.3.4) — 2026-09-09


## [0.3.3](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-secrets-v0.3.2...vti-secrets-v0.3.3) — 2026-09-07


## [0.3.2](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-secrets-v0.3.1...vti-secrets-v0.3.2) — 2026-09-07


## [0.3.1](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-secrets-v0.3.0...vti-secrets-v0.3.1) — 2026-08-29


## [0.3.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-secrets-v0.2.2...vti-secrets-v0.3.0) — 2026-08-28


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



## [0.2.2](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-secrets-v0.2.1...vti-secrets-v0.2.2) — 2026-08-26


## [0.2.1](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-secrets-v0.2.0...vti-secrets-v0.2.1) — 2026-08-22


## [0.2.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-secrets-v0.1.16...vti-secrets-v0.2.0) — 2026-08-21


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



## [0.1.16](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-secrets-v0.1.15...vti-secrets-v0.1.16) — 2026-08-20


## [0.1.15](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-secrets-v0.1.14...vti-secrets-v0.1.15) — 2026-08-18


## [0.1.14](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-secrets-v0.1.13...vti-secrets-v0.1.14) — 2026-08-17


## [0.1.13](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-secrets-v0.1.12...vti-secrets-v0.1.13) — 2026-08-16


## [0.1.12](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-secrets-v0.1.11...vti-secrets-v0.1.12) — 2026-08-16


## [0.1.11](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-secrets-v0.1.10...vti-secrets-v0.1.11) — 2026-08-12


## [0.1.10](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-secrets-v0.1.9...vti-secrets-v0.1.10) — 2026-08-12

