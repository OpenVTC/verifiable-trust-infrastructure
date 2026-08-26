# Changelog

Notable changes to the published crates. Generated from conventional commits by
[git-cliff](https://git-cliff.org) when a release is cut — do not edit by hand.
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

