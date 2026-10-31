# Changelog

Notable changes to the published crates. Generated from conventional commits by
[git-cliff](https://git-cliff.org) when a release is cut — do not edit by hand.
## [0.2.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-specs-rooms-v0.1.0...vti-specs-rooms-v0.2.0) — 2026-10-30


### Added

- **rooms**: Files in open rooms — serve rooms/records/put/0.4 and rooms/keys/act/0.9 ([#2348](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2348))

An open room could hold notes and nothing else: a file's manifest only
  travelled inside a sealed body, and its key could only be derived from a
  storage key an open room does not have. rooms/records/put/0.4
  (trust-tasks-tf #987) puts the manifest in cleartext.file, with the random
  key its blob is sealed under in fileKey; rooms/keys/act/0.9 ([#990](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/990)) adds put
  0.4 to the closed table a member's VTA completes.

  Hosts (room-host, vtc-service, through vti-rooms):
  - Serve rooms/records/put/0.4 beside 0.3. The cleartext, file included, is
    stored and served as received (Host item 13).
  - On an open room, refuse as malformedRequest a record whose blobs is not
    exactly [cleartext.file.blobRef], or whose file has no fileKey — before
    blobNotFound and before anything changes (Host item 12). 0.3 is unchanged.



## [0.1.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/releases/tag/vti-specs-rooms-v0.1.0) — 2026-10-30


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


