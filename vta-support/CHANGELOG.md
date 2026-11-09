# Changelog

Notable changes to the published crates. Generated from conventional commits by
[git-cliff](https://git-cliff.org) when a release is cut — do not edit by hand.
## [0.37.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-support-v0.36.0...vta-support-v0.37.0) — 2026-11-09


### Added

- **contexts**: Context-create capability so an agent gateway can provision sub-contexts ([#2302](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2302))

* feat(keys): keys/sign-jws/0.1 — a VTA-built compact JWS walled off to JWT types

  Add a `keys/sign-jws/0.1` Trust Task that produces a compact JWS (a JWT) over
  a caller-supplied JOSE header and claims set, signed by a stored key. Unlike
  `keys/sign/0.1` it is not a general signing oracle: the VTA assembles the
  `b64url(header).b64url(payload)` signing input itself and signs it under
  `SigningDomain::ProtocolDefined`, so the result verifies as a JWS rather than
  as a VTA opaque-signing payload.

  The task is walled off so it can never be pointed at producing a credential or
  issuer artifact:

  - the finalized protected header's `typ` must be on a small allow-list of JWT
    profiles (`JWT`, `at+jwt`, `oauth-id-jag+jwt`, `dpop+jwt`, `logout+jwt`);
    anything else — e.g. a Verifiable Credential media type — is refused before
    the key is touched;
  - the VTA, not the caller, sets `alg` from the key, so a caller cannot request
    a signature under an algorithm the key does not implement or mislabel one;
  - the payload must be a JSON object (a JWT claims set); raw bytes still go
    through the opaque oracle, not here.

  Authorized exactly as `keys/sign` is — per the key's context — so the same
  context separation that walls off a signer's identities applies. Added to the
  dispatch table with the spec's (none / none / actsAsSubject) class, and
  acknowledged in `UNSPECCED_DISPATCHED_URIS` pending an upstream spec in
  trustoverip/dtgwg-trust-tasks-tf (dispatched unvalidated like any
  unknown-schema task until then).

  Enables the Agent Gateway to delegate JWT signing (STS access tokens, ID-JAG)
  to the VTA while keeping the JWT-signing path structurally separate from
  credential signing.



## [0.36.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-support-v0.35.0...vta-support-v0.36.0) — 2026-11-05


## [0.35.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-support-v0.34.0...vta-support-v0.35.0) — 2026-11-05


## [0.34.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-support-v0.33.0...vta-support-v0.34.0) — 2026-11-05


## [0.33.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-support-v0.32.0...vta-support-v0.33.0) — 2026-11-04


## [0.32.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-support-v0.31.0...vta-support-v0.32.0) — 2026-11-04


## [0.31.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-support-v0.30.0...vta-support-v0.31.0) — 2026-11-04


### Fixed

- **contexts**: Purge every context-scoped record on delete ([#2419](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2419))

vta/contexts/delete removed a context's keys, DIDs, ACL scope, DID
  templates, app state and memory ([#2415](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2415)), but every other store that holds
  data for a context kept its rows. Most are keyed by the context id, or by a
  digest of it, so a context later created under the same id inherited them.

  Seen with OpenVTC: a context deleted and recreated under the same id failed
  vta/pcs/root-request with memberMismatch. The vetter engine record
  (pcs_engine vetter:<sha256(ctx, community)>) had survived, still pinned to
  the old member DID and to a derivation path under the old context's base.

  delete_context now purges, for every context in the subtree:

  - pcs_engine: vetter, applicant, voter and trustee records whose contextId
    is the context, with the wrapped state beside each (secret:<key>, and a
    voter's secret:voter-casts:<digest>). The keys are digests, so the purge
    scans each record prefix and matches the record's own contextId.
  - persona: every context-scoped prefix (pb, pc, pcr, pca, pcl, pd, plp, plb),
    driven from PREFIX_SCOPES so a new context-scoped prefix is purged without
    anyone remembering to; and the agent-scoped face-value edges that name one
    of the context's local profiles.
  - vault: credentials in the context's custody (with their index rows) and
    vault entries, hard-deleted whatever their lifecycle state.
  - notifications: held records with their dedup and bound rows (the sweep's
    removal, factored out and shared).
  - consent: grants decided in, and pending requests scoped to, the context;
    consent_approvers: its approver bindings.
  - external_accounts / external_secrets: each live account deleted the way
    external/accounts/delete deletes one (secret gone, id retired).
  - contexts: the daily quota counters (quota:<ctx>:...).
  - imported_secrets / internal_keys: the material of each key record the
    purge removes, as revoke_key does for an imported key.

  Each store purges itself next to the code that writes it, and the counts go
  in the deletion's log line. As in #2415 none of this is in the not-empty
  gate: the gate must agree with preview-delete, whose wire shape has no
  member for these, so surfacing them needs a spec revision.

  Kept on purpose: the audit log; issued credentials (revoked through the DID
  cascade, never deleted); operator policy; room groups and invitations (keyed
  by persona DID / credential id, unreachable from a recreated context); and
  external accounts' retired: tombstones, which hold no data and stop a
  recreated context reusing an account id a provider-side trust policy may
  still name.

  The census is now a claim the code is held to:

  - vta_keyspaces::context_delete_effect classifies every keyspace for a
    context deletion (Purged / Retained / Lapses / Unrelated), and
    context_delete_labels_match_the_cascade ties the Purged set to the
    cascade's own list.
  - did_delete_effect labelled most keyspaces Cascade (and five Blocks) though
    the DID deletion reaches only keys, webvh, acl, sessions, issued
    credentials and contexts. Those labels are now Orphaned, with the intended
    effect beside each, and did_delete_labels_match_the_cascade holds
    Cascade / Blocks / Revoke to DID_DELETE_REACHES.



## [0.30.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-support-v0.29.0...vta-support-v0.30.0) — 2026-11-03


## [0.29.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-support-v0.28.0...vta-support-v0.29.0) — 2026-11-03


## [0.28.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-support-v0.27.0...vta-support-v0.28.0) — 2026-11-02


## [0.27.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-support-v0.26.0...vta-support-v0.27.0) — 2026-10-30


## [0.26.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-support-v0.25.0...vta-support-v0.26.0) — 2026-10-30


## [0.25.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-support-v0.24.0...vta-support-v0.25.0) — 2026-10-28


## [0.24.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-support-v0.23.0...vta-support-v0.24.0) — 2026-10-27


## [0.23.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-support-v0.22.0...vta-support-v0.23.0) — 2026-10-26


### Fixed

- **vta-support**: The versionTime wait budgets whole-millisecond sleeps ([#2262](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2262))

wait_until_not_future charged each sleep as the exact time remaining, but
  Tokio's timer sleeps in whole milliseconds. Once the clock sat microseconds
  short of the target, every pass slept 1ms and was charged microseconds, so the
  total sleep could run past MAX_WAIT_SECONDS. Under paused time this showed up
  as waits_for_rapid_back_to_back_calls failing intermittently with
  elapsed=5.252s against the 5s budget.

  Each sleep is now rounded up to a whole millisecond and counted as such, so
  the budget matches what is slept. A new test drives a clock that creeps by a
  microsecond per pass and fails on the old accounting.



## [0.22.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-support-v0.21.0...vta-support-v0.22.0) — 2026-10-18


## [0.21.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-support-v0.20.0...vta-support-v0.21.0) — 2026-10-18


## [0.20.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-support-v0.19.0...vta-support-v0.20.0) — 2026-10-16


## [0.19.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-support-v0.18.0...vta-support-v0.19.0) — 2026-10-15


## [0.18.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-support-v0.17.0...vta-support-v0.18.0) — 2026-10-13


## [0.17.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-support-v0.16.0...vta-support-v0.17.0) — 2026-10-12


## [0.16.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-support-v0.15.0...vta-support-v0.16.0) — 2026-10-11


## [0.15.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-support-v0.14.0...vta-support-v0.15.0) — 2026-10-11


### Performance

- **vta-service**: Fewer storage reads per keys/sign without widening key custody ([#2001](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2001))

* perf(vta-service): read the caller's ACL entry once per keys/sign

  sign_payload read the caller's ACL entry twice: once for the sign
  capability (gate 0) and again for the allowed-keys filter (gate 4). The
  entry from gate 0 is now passed to gate 4, which reads it itself only when
  gate 0 did not run (protocol-defined signing input). Both gates still run,
  in the same order, and now see the same version of the entry.

  One storage round trip fewer per keys/sign.



## [0.14.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-support-v0.13.0...vta-support-v0.14.0) — 2026-10-06


## [0.13.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-support-v0.12.0...vta-support-v0.13.0) — 2026-10-06


## [0.12.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-support-v0.11.0...vta-support-v0.12.0) — 2026-10-05


## [0.11.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-support-v0.10.0...vta-support-v0.11.0) — 2026-10-04


## [0.10.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-support-v0.9.0...vta-support-v0.10.0) — 2026-10-02


## [0.9.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-support-v0.8.0...vta-support-v0.9.0) — 2026-10-02


## [0.8.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-support-v0.7.0...vta-support-v0.8.0) — 2026-10-01


## [0.7.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-support-v0.6.0...vta-support-v0.7.0) — 2026-10-01


## [0.6.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-support-v0.5.8...vta-support-v0.6.0) — 2026-09-30


## [0.5.8](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-support-v0.5.7...vta-support-v0.5.8) — 2026-09-30


## [0.5.7](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-support-v0.5.6...vta-support-v0.5.7) — 2026-09-27


## [0.5.6](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-support-v0.5.5...vta-support-v0.5.6) — 2026-09-27


## [0.5.5](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-support-v0.5.4...vta-support-v0.5.5) — 2026-09-26


## [0.5.4](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-support-v0.5.3...vta-support-v0.5.4) — 2026-09-26


## [0.5.3](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-support-v0.5.2...vta-support-v0.5.3) — 2026-09-24


## [0.5.2](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-support-v0.5.1...vta-support-v0.5.2) — 2026-09-23


## [0.5.1](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-support-v0.5.0...vta-support-v0.5.1) — 2026-09-23


## [0.5.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-support-v0.4.2...vta-support-v0.5.0) — 2026-09-22


### Added

- **backup**: A backup is the whole agent, and restores between plain, hardened and TEE VTAs ([#1655](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1655))

A backup now carries every row of every keyspace in vta_keyspaces::BACKED_UP
  (format vta-backup-v2) and restores into a plain, hardened or Nitro-enclave
  VTA from any of them. VTI-VTA-001, VTI-VTA-050, VTI-VTA-051, VTI-KEY-033.



## [0.4.2](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-support-v0.4.1...vta-support-v0.4.2) — 2026-09-22


## [0.4.1](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-support-v0.4.0...vta-support-v0.4.1) — 2026-09-21


## [0.4.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-support-v0.3.15...vta-support-v0.4.0) — 2026-09-21


### Fixed

- **did-webvh**: Serialize versionTime log updates ([#1599](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1599))

* fix(did-webvh): serialize versionTime log updates

  Use one current-time policy for TEE genesis and runtime did:webvh
  updates. Wait for the next valid whole-second boundary, rechecking
  after wall-clock rollback, instead of backdating entries.

  Serialize same-DID log appends within a VTA process and add regression
  coverage for rapid updates, concurrent appends, legacy timestamps, and
  TEE genesis followed by an immediate validated update.



## [0.3.15](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-support-v0.3.14...vta-support-v0.3.15) — 2026-09-21


## [0.3.14](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-support-v0.3.13...vta-support-v0.3.14) — 2026-09-20


## [0.3.13](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-support-v0.3.12...vta-support-v0.3.13) — 2026-09-18


## [0.3.12](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-support-v0.3.11...vta-support-v0.3.12) — 2026-09-17


## [0.3.11](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-support-v0.3.10...vta-support-v0.3.11) — 2026-09-16


## [0.3.10](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-support-v0.3.9...vta-support-v0.3.10) — 2026-09-16


## [0.3.9](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-support-v0.3.8...vta-support-v0.3.9) — 2026-09-16


## [0.3.8](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-support-v0.3.7...vta-support-v0.3.8) — 2026-09-14


### Fixed

- **webvh**: Clamp versionTime against the previous log entry ([#1456](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1456))

* fix(tee): backdate WebVH genesis versionTime

  The TEE genesis path used the library's current-time default while
  runtime updates used PR #600's backdated timestamps. This caused the
  first update to have a lower versionTime than genesis, making the DID
  unresolvable.

  Apply the shared PR #600 backdating policy to TEE genesis and move the
  helper into vta-support so both TEE and service paths use one implementation.



## [0.3.7](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-support-v0.3.6...vta-support-v0.3.7) — 2026-09-12


## [0.3.6](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-support-v0.3.5...vta-support-v0.3.6) — 2026-09-10


## [0.3.4](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-support-v0.3.3...vta-support-v0.3.4) — 2026-09-09


## [0.3.3](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-support-v0.3.2...vta-support-v0.3.3) — 2026-09-07


## [0.3.2](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-support-v0.3.1...vta-support-v0.3.2) — 2026-09-07


## [0.3.1](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-support-v0.3.0...vta-support-v0.3.1) — 2026-08-29


## [0.3.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-support-v0.2.12...vta-support-v0.3.0) — 2026-08-28


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



## [0.2.12](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-support-v0.2.11...vta-support-v0.2.12) — 2026-08-26


## [0.2.11](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-support-v0.2.10...vta-support-v0.2.11) — 2026-08-22


## [0.2.10](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-support-v0.2.9...vta-support-v0.2.10) — 2026-08-21


## [0.2.9](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-support-v0.2.8...vta-support-v0.2.9) — 2026-08-20


## [0.2.8](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-support-v0.2.7...vta-support-v0.2.8) — 2026-08-18


## [0.2.7](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-support-v0.2.6...vta-support-v0.2.7) — 2026-08-17


## [0.2.6](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-support-v0.2.5...vta-support-v0.2.6) — 2026-08-16


## [0.2.5](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-support-v0.2.4...vta-support-v0.2.5) — 2026-08-16


## [0.2.4](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-support-v0.2.3...vta-support-v0.2.4) — 2026-08-13


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


