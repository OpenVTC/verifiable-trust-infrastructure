# Changelog

Notable changes to the published crates. Generated from conventional commits by
[git-cliff](https://git-cliff.org) when a release is cut — do not edit by hand.
## [0.4.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-external-v0.3.0...vta-external-v0.4.0) — 2026-10-13


## [0.3.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-external-v0.2.0...vta-external-v0.3.0) — 2026-10-12


## [0.2.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-external-v0.1.0...vta-external-v0.2.0) — 2026-10-11


## [0.1.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/releases/tag/vta-external-v0.1.0) — 2026-10-11


### Added

- **vta**: External accounts — short-lived provider credentials with no inbound surface ([#2016](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2016))

* feat(vta): external-accounts capabilities and keyspaces

  Adds the two capabilities the external/* family (trust-tasks-tf #740) gates on: external-accounts-manage, derived by admin alone, and external-auth-use, derived by every role that holds sign (the account's binding, not the role, bounds a consumer). Both are non-additive members of the non-exhaustive Capability enum.

  Registers two keyspaces: external_accounts (settings, bindings, state) in BACKED_UP, and external_secrets (wrapped provider secrets) in EXCLUDED_FROM_BACKUP, so a portable password-protected backup is never a way to take a provider secret away. DID deletion: an account's binding names its consumer, so external_accounts blocks; external_secrets is unrelated.

  The device-binding Capability registry (device/_shared 0.2) does not list the two yet, so device listings carry them under ext until it does.


