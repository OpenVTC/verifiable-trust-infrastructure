# Changelog

Notable changes to the published crates. Generated from conventional commits by
[git-cliff](https://git-cliff.org) when a release is cut — do not edit by hand.
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


