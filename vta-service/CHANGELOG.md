# Changelog

Notable changes to the published crates. Generated from conventional commits by
[git-cliff](https://git-cliff.org) when a release is cut — do not edit by hand.
## [0.15.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-service-v0.14.37...vta-service-v0.15.0) — 2026-08-13


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

- **did-webvh**: Let a minted DID advertise TSP at the VTA's mediator ([#959](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/959))

A VTA-minted DID could never advertise TSP, whatever the VTA's own config
  said. `add_mediator_service` publishes the VTA's mediator as a
  `DIDCommMessaging` service and nothing else, so a caller wanting `#tsp`
  had to hand-build the service entry and pass it through
  `additional_services` — which means knowing the mediator DID, the one
  thing `add_mediator_service` exists so a caller does not have to know.
  Nobody did, so every persona-shaped identity is DIDComm-only by
  construction, and the both-ends transport rule can never resolve to TSP
  for one. TSP could be enabled end to end and the intersection would still
  be DIDComm.

  Surfaced by OpenVTC #211, where a join failed at the mediator and the
  applicant persona's document turned out to carry exactly one service
  entry.

  Adds `add_tsp_service` to the create-DID wire, honoured by
  `with_tsp_service` in `did_webvh/document.rs`. The entry points at the
  same mediator the DIDComm entry names — TSP advertises a mediator DID,
  not a transport URL (D8) — using the fragment and type the setup path and
  the runtime `services tsp enable` patcher already emit, so a document
  minted here, minted at setup, or patched later are the same shape.

  Two gates, neither redundant. The caller's flag is opt-in and
  deliberately not implied by `add_mediator_service`: a DID advertising a
  transport its holder cannot decode is unreachable over that transport,
  and only the caller knows whether the client behind the DID reads TSP
  frames. Ours is `[services] tsp` plus a configured mediator: a VTA whose
  own stack does not run TSP must not mint documents claiming it does,
  which is the failure this prevents rather than spreads. A caller-supplied
  `TSPTransport` entry wins over the injected one — matched on the service
  `type`, never the `#id` fragment.

  Additive on the wire in both directions: `skip_serializing_if` on the
  request and `Option` on the body, so an unset field serialises exactly as
  before and a VTA that predates it ignores the key.

- **vta-service**: Add --mediator-did to create-did-peer for DID-routing mediators ([#952](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/952))

`vta create-did-peer` could only advertise a URL-style DIDComm service, built
  from `--mediator-url`. A new `--mediator-did` produces the **DID-style** shape
  instead — a single `DIDCommMessaging` service whose `serviceEndpoint.uri` is
  the mediator's own DID.

- **vta-service**: Import an external Ed25519 key for a deterministic did:key ([#953](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/953))

`vta create-did-key` always derived a fresh key from the VTA seed off a
  counter-allocated BIP-32 path, so the resulting `did:key` changed on every run.
  A new `--private-key-file` imports caller-supplied Ed25519 key material
  instead, making the `did:key` deterministic in those bytes: a redeploy onto a
  fresh volume reproduces the SAME DID. That is what lets a vault signing entry
  stay bound to a persona DID whose key is held off-box.

  The key is stored exactly like any other imported key — `KeyOrigin::Imported`,
  no derivation path, secret encrypted at rest under the VTA seed via
  `keys::imported::store_secret`. `key_id` is derived from the key material, so a
  re-run overwrites the same record with the same value rather than conflicting.

  Handling of the secret follows the discipline
  `vta_sdk::protocols::backup_management` already applies to this material:

  * It is read from a **file**, not an argv flag value. A secret on the command
    line is visible in `ps`, in shell history, and in container / CI process
    listings.
  * The file text, the decoded bytes, and the 32-byte key are all `Zeroizing`, so
    none of them outlive the import.
  * A group- or world-readable key file warns (mode is printed); it does not fail,
    since the operator may be mid-pipeline.

  With `--admin` this grants admin to a DID whose private key lives outside the
  VTA, so the flag help says so plainly. The command remains behind the existing
  `check_seal` gate.

  Tests cover the determinism property the feature exists for, and the file
  reader's accept/reject paths (trailing newline, wrong length, bad hex, missing
  file).

  Split out of #843 (third of three), rebased onto current main. Reworked from
  the original `--private-key-hex` flag per review: file input, zeroization,
  permission warning, and coverage of the import path rather than only the pure
  id-derivation helper.



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



### Fixed

- **vta-service**: Share one key derivation with the interactive DID preview ([#954](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/954))

`vta create-did-webvh` without `--url` still minted a DID advertising keys
  the store could not sign with. #945 fixed that for `--url` by dropping the
  preview; interactive cannot drop it, because the operator has to see and
  edit the document before it is created.

  So both sides derived. `derive_entity_keys` allocates a fresh BIP-32 path
  index per call, and `create_did_webvh` derives unconditionally whenever
  `signing_key_id` is `None` — before the `did_document` match, regardless of
  a caller-supplied document. The preview took indices n, n+1 and built its
  document from them; the operation then took n+2, n+3 and stored those. The
  published DID named one key, `get_key_secret` served another, and nothing
  noticed until a verifier rejected a signature.

- **vta-service**: Stop create-did-webvh minting a DID whose keys the store doesn't hold ([#945](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/945))

* fix(vta-service): prevent double key derivation in non-interactive create-did-webvh

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


