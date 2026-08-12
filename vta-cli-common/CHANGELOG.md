# Changelog

Notable changes to the published crates. Generated from conventional commits by
[git-cliff](https://git-cliff.org) when a release is cut — do not edit by hand.
## [0.10.29](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-cli-common-v0.10.28...vta-cli-common-v0.10.29) — 2026-08-12


### Fixed

- **vault**: Send entryId on vault release, from both the CLI and the MCP bridge ([#948](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/948))

* fix(vault): use entryId instead of id in vault release payload

  cmd_vault_release was constructing the vault/release/0.1 Trust Task
  payload with key `id`, which fails schema validation. The schema
  requires `entryId` (matching VaultReleaseBody's camelCase
  serialisation on the server side).


