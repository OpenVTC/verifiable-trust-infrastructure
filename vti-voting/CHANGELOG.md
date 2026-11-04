# Changelog

Notable changes to the published crates. Generated from conventional commits by
[git-cliff](https://git-cliff.org) when a release is cut — do not edit by hand.
## [0.11.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-voting-v0.9.0...vti-voting-v0.11.0) — 2026-11-04


## [0.9.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-voting-v0.8.0...vti-voting-v0.9.0) — 2026-11-04


## [0.8.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-voting-v0.7.0...vti-voting-v0.8.0) — 2026-11-03


### Added

- **voting**: Credential rolls proven at the ticket claim, and elections shown only to whom they concern (VTI-VOT-015 – 018, VTI-VOT-025 – 029) ([#2395](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2395))

* build(specs): pin the credential-roll and election-privacy task versions

  voting/_shared/0.4 and every task carrying it (dtgwg-trust-tasks-tf #1008,
  #1010, #1011): voting/election/register/0.4, show/0.4;
  vtc/elections/create/0.5, show/0.6, list/0.5, tickets/issue/0.3;
  vta/pcs/voter/register/0.5, voter/read/0.6, vote/0.4, vote-encrypted/0.5,
  trustee/{deal,justify,keys}/0.5, enrol/0.4, read/0.4. Older versions stay
  pinned.



## [0.7.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-voting-v0.6.1...vti-voting-v0.7.0) — 2026-11-02


### Added

- **voting**: TextReleaseThreshold may be as low as 1, disclosed below 10 (VTI-VOT-065) ([#2379](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2379))

* build(specs): pin voting/election register+show 0.3, vta/pcs voter/vote/trustee next versions, vtc/elections create 0.4 + show 0.3

  The voting/_shared/0.3 manifest lets textReleaseThreshold be as low as 1
  (VTI-VOT-065); every task carrying the manifest moves a version. The old
  versions stay pinned; their bundles take the registry's deprecation note.



## [0.6.1](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-voting-v0.6.0...vti-voting-v0.6.1) — 2026-11-01


### Added

- **cnm**: Offline election manifest init and check ([#2365](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2365))

`cnm elections manifest init --ballot-box <DID>` writes a starting manifest
  for the community (one yes/no question, open voting by its members for a
  week from tomorrow); `cnm elections manifest check <file>` checks one as the
  community will and prints its digest. Neither opens a session: the
  community's DID comes from --vtc-did or the profile.

  check validates against the pinned vtc/elections/create/0.3 schema, then
  runs vti_voting::rules::check_new_manifest, a new shared entry point for
  everything a community checks that needs only the manifest and the clock:
  the current 0.2 shape, check_manifest's cross-field rules (VTI-VOT-010,
  VTI-VOT-060 – 064) and voting not already closed. The VTC's check_create now
  calls the same function, so the offline check and the community cannot
  drift; a 0.1-shaped manifest is refused by name at create instead of as a
  missing field. What needs the community itself (trusted ballot box,
  VTI-VOT-082; unused identifier) still waits for create.

  An invalidManifest refusal from create now suggests the offline check.



## [0.6.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-voting-v0.4.0...vti-voting-v0.6.0) — 2026-10-30


### Changed

- **specs**: Take every Trust Task wire type from the generated vti-specs crates ([#2343](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2343))

Every `trust_tasks_rs::specs::<family>` path becomes `vti_specs::<family>`
  (`vti_specs_rooms::rooms` in vti-rooms, which stays wasm-light), and every
  `trust_tasks_rs::schema_index::*` call becomes `vti_specs::schema_index::*`,
  which answers for exactly the versions the vti-specs-* locks pin. The
  framework's own specs are re-exported from vti_specs unchanged.

  No crate turns a trust-tasks-rs spec family on any more: the workspace
  compiles none of the deprecated prebuilt modules, only `validate`.

  The generated types are the same generator's output at the same module paths,
  but they are distinct Rust types from the prebuilt ones: a downstream crate
  that passes a `trust_tasks_rs::specs` value into a vta-sdk API must move its
  import to `vta_sdk::specs` (a find-and-replace).

  CLAUDE.md's rule now points at the generated crates and says how to pin a
  version; the SPEC FAMILIES notes in Cargo.toml are replaced.



### Fixed

- **voting,witness,persona**: Board read at voting/board/read 0.2, witness evidence at witness/session 0.2 only, the persona timeline answer at 1.1 ([#2334](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2334))

trust-tasks-rs marks voting/board/read/0.1, witness/session/0.1,
  witness/session/submit/0.1 and persona/profile/timeline/1.0 superseded.
  Every party to each is in this workspace or has already moved, so each moves
  to its current version alone.

  voting/board/read 0.1 -> 0.2. A lifecycle entry's (opened, closed,
  closedEarly, cancelled) instant is `occurredAt`, as voting/_shared/0.2 and
  its CONVENTIONS §1 name it, not `at`.
  - The ballot box writes lifecycle entries with `occurredAt`, serves
    board/read at 0.2 only (0.1 is `unsupportedVersion`), and reads
    `occurredAt` when it replays its journal.
  - The VTC sends board/read at 0.2; the auditor (vti_voting::audit and its
    encrypted levels) reads `occurredAt`.
  - A leaf hash is over the entry's member names, so an entry journalled with
    `at` cannot be renamed without changing the board. Like a 0.1 manifest
    ([#2317](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2317)) it is refused by name: the ballot box will not restore a journal
    holding one, and the auditor reports it as unreadable rather than as
    "voting opened before votingOpensAt". Finish or cancel open elections
    before upgrading.

  witness/session 0.1 and submit 0.1. vti-witness and the VTA already serve
  only 0.2 ([#2147](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2147)), and openvtc main sends 0.2. The VTC no longer pairs outcome
  evidence from a 0.1 session with a submit/0.1 response: such evidence pairs
  with nothing.

  persona/profile/timeline 1.0 -> 1.1. The SDK already sent 1.1 but parsed the
  answer as the 1.0 response, whose events require `at`; a 1.1 answer names it
  `occurredAt`, so it failed to parse. `VtaClient::persona_profile_timeline`
  now returns the 1.1 response.



## [0.4.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-voting-v0.3.0...vti-voting-v0.4.0) — 2026-10-28


### Added

- **voting**: Register and show elections at voting/election 0.2, and serve vtc/elections create 0.3, list 0.3, show 0.2 ([#2317](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2317))

* feat(voting)!: register and show elections at voting/election 0.2, and serve vtc/elections create 0.3, list 0.3, show 0.2

  trust-tasks-rs 0.35 deprecates every superseded Trust Task version and
  withdraws each about 90 days later. Every party to an election is in this
  workspace, so all of them move to the current versions together, and the old
  ones are refused `unsupportedVersion`. Every current version is already in
  trust-tasks-rs 0.35.3.

  | Task | Was | Now | What changed on the wire |
  |---|---|---|---|
  | voting/election/register | 0.1 | 0.2 | the manifest (voting/_shared/0.2) names its instants `registrationOpensAt`, `votingOpensAt`, `votingClosesAt` |
  | voting/election/show | 0.1 | 0.2 | the same manifest in the answer |
  | vtc/elections/create | 0.1 | 0.3 | the 0.2 manifest; a parked binding election's next step expects `vtc/admin/actions/show/0.3` |
  | vtc/elections/list | 0.1 | 0.3 | `next` is `nextCursor` (0.2); items' `votingOpens`/`votingCloses` are `votingOpensAt`/`votingClosesAt` (0.3) |
  | vtc/elections/show | 0.1 | 0.2 | the 0.2 manifest |
  | vta/pcs/voter/register | 0.1 | 0.2 | the 0.2 manifest |
  | vta/pcs/voter/read | 0.1 | 0.2 | signs `vtc/elections/list/0.3` or `show/0.2` |
  | vta/pcs/vote | 0.1 | 0.2 | the 0.2 manifest |
  | vta/pcs/vote-encrypted | 0.2 | 0.3 | the 0.2 manifest |
  | vta/pcs/trustee/enrol | 0.1 | 0.2 | the 0.2 manifest |
  | vta/pcs/trustee/{deal,keys,justify} | 0.2 | 0.3 | the 0.2 manifest |
  | vta/pcs/trustee/read | 0.1 | 0.2 | an `election` read signs `voting/election/show/0.2` |

  - vti-voting reads the 0.2 manifest throughout (rules, tally, audit, the
    encrypted levels, the voter's checks).
  - vti-voting-service (the ballot box) dispatches by version: register and show
    at 0.2, every other voting/* task at 0.1, its current version. A known task
    at another version is refused `unsupportedVersion` naming the one served
    (was `unsupportedType`).
  - The VTC sends register 0.2 and serves the elections tasks above. The VTA's
    voter and trustee tasks (`vta/pcs/*`) carry the manifest too, so they move
    in the same change: a 0.2 manifest does not parse in the 0.1 task. `cnm`,
    `pnm`, vta-sdk, vta-mobile-core, vtc-client and the admin console move with
    them.
  - Action summaries: a template for `vtc/elections/create/0.3` (pointers
    `/manifest/votingOpensAt` and `/manifest/votingClosesAt`), pinned in the
    build and in the console. The 0.1 template stays so a binding election
    parked under it still renders in the history.

  **Elections registered before this build are not carried over.** A manifest's
  digest — which every ticket, cast and certification is bound to — is over its
  member names, so a 0.1 manifest cannot be re-read as 0.2 without becoming a
  different election. Rather than fail as a manifest "missing
  registrationOpensAt", every reader refuses it by name with
  `vti_voting::rules::require_current_manifest`:

  - the ballot box will not start while its journal holds such an election
    (restore fails, as for any journal entry that no longer parses), with
    "election <id> was registered under voting/election/register/0.1 … this
    build reads only the 0.2 manifest and cannot carry it over. Finish or cancel
    it on the previous release, or remove it";
  - the VTC's `vtc/elections/show` answers that election with the same message
    and its audit and decryption steps fail it the same way.
    `vtc/elections/list` still lists it.

  Finish or cancel open elections before upgrading.



### Build & CI

- **deps**: Compile only the trust-tasks-rs spec families each crate uses ([#2326](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2326))

The workspace `trust-tasks-rs` entry enabled `all-specs`, so every crate that
  depends on it, and every consumer of a published VTI crate, compiled all 34
  generated spec families (~70 MB of Rust, 14 GB peak rustc RSS). The workspace
  entry now enables `validate` only, and each crate lists the families it names:
  a `trust_tasks_rs::specs::<family>` path, or a Type URI it sends, serves or
  looks up in `schema_index`.

  The workspace union is 29 families. The five dropped (chat, process-attestation,
  sync, vrc, webvh) appear nowhere in VTI: no path, no Type URI, no handler. A
  received document of one of those types was already refused as unsupported;
  it is now dispatched to that refusal without a schema check first.

  What shrinks: `vti-rooms-wasm` compiles `rooms` alone (trust-tasks-rs dev
  build 14.2 GB / 174 s -> 1.5 GB / 7 s). Everything that depends on vta-sdk
  still needs 23-29 families, so the workspace, service and mobile builds are
  roughly unchanged (mobile `check` 12.9 -> 11.1 GB); the swap safety nets stay.



## [0.3.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-voting-v0.2.0...vti-voting-v0.3.0) — 2026-10-27


### Chore

- **deps**: Trust-tasks-rs 0.35 (affinidi-messaging-sdk 0.41, affinidi-tdk 0.33, mediator 0.46) ([#2300](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2300))

* chore(deps)!: trust-tasks-rs 0.35 (affinidi-messaging-sdk 0.41, affinidi-tdk 0.33, mediator 0.46)

  trust-tasks-rs, -proof, -https, -didcomm, -tsp and -capability-client
  0.34 -> 0.35 (0.35.3), in lockstep with affinidi-messaging-sdk 0.41,
  affinidi-tdk 0.33 (affinidi-tdk-rs #975) and the mediator crates 0.46,
  which are built on them. One trust-tasks-rs in the graph.

  0.35 brings the lowerCamelCase registry/* versions with record validity
  windows (trust-tasks-tf #925), which the VTC's registry client needs
  ([#2287](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2287)), and marks every superseded spec version deprecated
  (trust-tasks-tf #921). VTI still names many superseded versions while it
  moves to the current ones, so `deprecated` is allowed for the workspace
  (and in room-host, vti-rooms, vti-voting and vti-witness, which do not
  inherit its lints), with a note to remove it when that move is done and
  before those versions are withdrawn.

  0.35's Type URI parser accepts any scheme but `http`, case-insensitively,
  for third-party registries (trust-tasks-tf #922, #934), and keeps the
  authority as written. `HTTPS://trusttasks.org/...` now parses, as a
  lookalike authority rather than an unparseable string; the proof-purpose
  classifier still gives it Authentication, never the attestation purpose.
  The classifier test moves it to the lookalike list.



## [0.2.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-voting-v0.1.0...vti-voting-v0.2.0) — 2026-10-26


### Fixed

- **voting**: The ballot box registers only the communities it serves, checks casts off its lock, and pages reads by size ([#2283](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2283))

Three gaps from the community-voting threat model:

  - Registrations: any DID could register elections until the box's store was full. The service
    config gains `[communities]` — `allowed` community DIDs, or `allow_any = true` for an open box;
    without it nothing registers — and `max_unfinished` (default 20) elections per community not
    yet tallied or cancelled. Another community's registration is `permissionDenied`; one past the
    quota is `unavailable`, which the VTC delivers again until one finishes. A repeat of a
    registration already held is never refused.
  - Locking: a cast's costly checks (the attestation's pairing, a tallied ballot's proofs) ran
    under the one lock over every box, so a flood of casts stalled every other community.
    `BallotBox::cast_check` / `cast_encrypted_check` take the cheap checks and what the costly ones
    need; `CastCheck::run` proves the cast without the box, on a blocking thread (at most one per
    core); `cast_verified` / `cast_encrypted_verified` re-run the cheap checks under the lock and
    admit that one cast. `cast` and `cast_encrypted` still do it all in place.
  - Board reads: a `voting/board/read` page carries at most 256 KiB of entries (always at least
    one), fewer than `limit` where entries are large (read item 4).


