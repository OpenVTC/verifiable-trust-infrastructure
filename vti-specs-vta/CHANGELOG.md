# Changelog

Notable changes to the published crates. Generated from conventional commits by
[git-cliff](https://git-cliff.org) when a release is cut — do not edit by hand.
## [0.2.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-specs-vta-v0.1.0...vti-specs-vta-v0.2.0) — 2026-10-30


### Added

- **vta**: Serve vta/webvh/dids/update/1.1 — list or remove an existing log's did:scid alias ([#2354](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2354))

* feat(vta)!: serve vta/webvh/dids/update/1.1 — list or remove an existing log's did:scid alias

  Every did:webvh log is also `did:scid:vh:1:<scid>`; the two forms are one
  subject only while the did:webvh document lists
  `did:scid:vh:1:<scid>?src=<source>` in `alsoKnownAs` (VTI-KEY-164).
  create/1.2 lists it at creation. update/1.1 (trustoverip/dtgwg-trust-tasks-tf#992)
  adds `scidAlsoKnownAs` so an operator can list or remove it on a log that
  already exists, without building the DID URL or sending a whole document.

  VTA (one handler serves 1.0 and 1.1; 1.1 extends 1.0):
  - `<source>` derived by `vta_sdk::did_scid::scid_forms` (`:` -> `/`,
    percent-encoding kept), applied to `document` or the current document.
    `true` appends unless listed and replaces a stale `src` in place; `false`
    removes every did:scid entry for the SCID.
  - `scidAliasRequired` when the VTA presents the identity as its did:scid
    (VTI-KEY-166): the `presented` flag create/1.2 records on the did:scid
    identity (`webvh_store::ScidIdentity`), or `vta_did` being this log's
    did:scid. Also refuses a supplied `document` that drops the alias, under
    1.0 too (as a validation error).
  - `noChange` when the resulting document and parameters equal the latest
    entry's: nothing published, no rotation.
  - Otherwise a document change: publishes and rotates the update key, so the
    task stays Destructive. The response reports `scidAlsoKnownAs` and
    `scidDidUrl`; 1.0 and rotate-keys responses are unchanged.
  - The did:scid identity record follows the published document, so the
    did:scid DID addresses the log exactly while the alias is listed.



## [0.1.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/releases/tag/vti-specs-vta-v0.1.0) — 2026-10-30


### Added

- **specs**: Generate the Trust Task wire types VTI pins, with trust-tasks-build ([#2340](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2340))

* feat(specs): generate the Trust Task wire types VTI pins, with trust-tasks-build

  trust-tasks-rs 0.36 deprecates every prebuilt trust_tasks_rs::specs module.
  Five new crates generate the versions VTI uses instead:

  - vti-specs-rooms, vti-specs-vta, vti-specs-vtc, vti-specs-core: each
    build.rs runs trust-tasks-build (.index(true)) over its own
    trust-tasks.lock and vendored bundles. Each version is pinned in exactly
    one crate, so a type is the same type across the workspace. rooms stands
    alone so vti-rooms-wasm compiles nothing else.
  - vti-specs: re-exports every family at its trust_tasks_rs::specs path and
    merges the four Type URI indexes (type_index::lookup) into a drop-in
    schema_index, plus is_pinned. Framework specs fall through to
    trust_tasks_rs::schema_index.
  - vta-sdk re-exports it as vta_sdk::specs.

  664 versions are pinned: every version module the workspace names, plus the
  Type URIs it sends or serves as strings (registry/*, did-management/*,
  push/provision, ...).

  spec_pin_census in vta-service and vtc-service fails on a dispatched,
  served, sent or TASK_* Type URI no crate pins: an unpinned URI answers None
  from the index, and the gates that read None as nothing to check fail open.

  Nothing moves to the new crates yet; the import rewrite follows.


