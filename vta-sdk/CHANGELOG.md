# Changelog

Notable changes to the published crates. Generated from conventional commits by
[git-cliff](https://git-cliff.org) when a release is cut — do not edit by hand.
## [0.22.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-sdk-v0.21.21...vta-sdk-v0.22.0) — 2026-08-12


### Fixed

- **vault**: Send entryId on vault release, from both the CLI and the MCP bridge ([#948](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/948))

* fix(vault): use entryId instead of id in vault release payload

  cmd_vault_release was constructing the vault/release/0.1 Trust Task
  payload with key `id`, which fails schema validation. The schema
  requires `entryId` (matching VaultReleaseBody's camelCase
  serialisation on the server side).

- **provisioning**: Relay the holder's bootstrap VP as raw JSON ([#949](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/949))

A relayer is usually not the holder — the air-gap onboarding flow exists
  precisely so it isn't — so `pnm bootstrap provision-integration` forwards
  a document some other process signed. It parsed that document into a
  typed `BootstrapRequest` and let serde re-render it on the way out, so
  the maintainer verified bytes the holder never signed. Both transports,
  every relayed request.

  Same defect as #946 one layer up, and with the same trigger: #917 moved
  `ask.type` to the 0.2 camelCase tag, so a holder on vta-sdk < 0.21.11
  (did-hosting `VTI-Cypress-RC-1` among them) has its own valid signature
  rewritten in transit and rejected as a forgery at the far end. #946 fixed
  the two maintainer-side surfaces that re-serialised; this is the client
  side of the same rule, and the two together close the flow.

  `ProvisionIntegrationRequest.request` and `provision_integration_didcomm`
  now take `serde_json::Value`. **Breaking** for anything constructing that
  struct. Callers that signed the VP themselves — every SDK runner — go
  through the new `BootstrapRequest::to_signed_wire_value`, where serde
  output and signed bytes are the same document by construction; pnm keeps
  a typed view purely to read `contextHint` and relays the raw JSON.

  `provision_integration_didcomm`'s doc comment already promised the VP was
  "left byte-identical either way". It now is.

  The existing relay tests could not have caught this: they assert the body
  carries `serde_json::to_value(&vp)`, which is the SDK's rendering
  compared against itself and true however badly the relayer mangles a
  foreign document. The new test starts from a VP this crate did not
  render, relays it under both spec versions, and requires it to arrive
  byte-for-byte and still verify. It also asserts the fixture actually
  diverges from this crate's serde output, so it fails loudly rather than
  going quietly vacuous if the casings ever converge.

- **provisioning**: Verify the bootstrap VP as received, not re-serialised ([#946](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/946))

`vta bootstrap provision-integration` and `POST /bootstrap/provision-integration`
  rejected a validly-signed request from any holder on vta-sdk < 0.21.11:

      Error: verify BootstrapRequest: proof verification failed:
      verify VP: signature invalid for cryptosuite EddsaJcs2022

  Both called `BootstrapRequest::verify()`, which re-serialises the typed
  struct and re-imposes this crate's casing on the bytes the holder signed.
  #917 flipped `ask.type` to the 0.2 camelCase tag (`templateBootstrap`),
  so a 0.1 holder's `TemplateBootstrap` — accepted on the way in by the
  serde alias, then re-emitted camelCase on the way to the verifier — no
  longer matched its own signature. The failure is indistinguishable from
  a forgery, which is what makes it expensive to diagnose in the field.
  did-hosting `VTI-Cypress-RC-1` pins vta-sdk 0.21.9 and hits this on
  every offline provision.

  #917 fixed exactly this defect at the Trust-Task handler and the DIDComm
  handler already did the right thing; the offline CLI and the REST route
  were the two surfaces left behind. Both now go through `verify_value`
  over the bytes as received, which is what its own docs require of any
  surface taking a request from elsewhere. The REST body consequently
  carries `request` as raw JSON — deserialising it into the typed struct
  at the extractor is what discarded the signed bytes. `deny_unknown_fields`
  still rejects smuggled fields, one layer in, inside `verify_value`.

  Tests cover the direction that was missing. #917's fixture signed the
  0.2 casing against a 0.2 maintainer; nothing exercised an *older* holder
  against a current one, which is the far commoner deployment shape. Added
  a PascalCase-signed fixture at both layers, plus a test pinning that
  `verify()` breaks such a request — so a call site reverting to it fails
  rather than shipping.

  Note for follow-up: the relayer has the same defect one layer up.
  `ProvisionIntegrationRequest.request` is a typed `BootstrapRequest`, so
  `pnm bootstrap provision-integration` re-serialises a request file before
  sending it (both transports), and the maintainer never sees the signed
  bytes. `provision_integration_didcomm`'s doc comment already claims the
  VP is "left byte-identical either way", which the code does not honour.
  Fixing it changes a published vta-sdk struct field, so it is deliberately
  not bundled here.


