# Changelog

Notable changes to the published crates. Generated from conventional commits by
[git-cliff](https://git-cliff.org) when a release is cut — do not edit by hand.
## [0.2.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-webvh-v0.1.14...vta-webvh-v0.2.0) — 2026-08-28


### Fixed

- **vta**: Re-case the extended error codes the Trust Tasks registry moved ([#1122](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1122))

* fix(vta)!: emit the re-cased extended error codes the registry now declares

  trustoverip/dtgwg-trust-tasks-tf#279 re-cased 200 extended error-code local
  parts to lowerCamelCase per SPEC §4.10 rule 4 — only the part after the `:`
  moved, the namespace is unchanged. This service still produced the snake_case
  spellings for 32 of them, so every one of those rejects carried a code the
  registry no longer defines and no conforming consumer can branch on.

  Every site here is an **emitter**: this repo decides what to send, and the
  registry decides what is correct to send, so each moves to the new spelling
  with no compatibility arm. The matcher side — where this repo reads a code a
  peer produced and cannot control that peer's deploy order — is handled
  separately in the following commit.

  Three of the vault emitters build their namespace by interpolation
  (`vault/{verb}:not_found`, `vault/{verb}:version_conflict`,
  `vault/{op}:not_found` in `vault_not_found`, `check_expected_version` and
  `refuse_if_not_active`), so the codes they produce do not appear as literals
  anywhere. Those helpers cover `vault/delete:{notFound,versionConflict}` and the
  `notFound` conflation the three consumer-facing use paths rely on for
  enumeration resistance.



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



## [0.1.14](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-webvh-v0.1.13...vta-webvh-v0.1.14) — 2026-08-26


## [0.1.13](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-webvh-v0.1.12...vta-webvh-v0.1.13) — 2026-08-22


## [0.1.12](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-webvh-v0.1.11...vta-webvh-v0.1.12) — 2026-08-21


## [0.1.11](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-webvh-v0.1.10...vta-webvh-v0.1.11) — 2026-08-20


## [0.1.10](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-webvh-v0.1.9...vta-webvh-v0.1.10) — 2026-08-18


### Fixed

- **webvh**: Read agent-name createdAt in both shapes the host sends ([#999](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/999))

* fix(webvh): read agent-name createdAt in both shapes the host sends

  A DID with at least one agent name could not be listed over DIDComm. The
  whole task failed with `agent-name list response parse error: invalid
  type: string "2026-08-18T08:58:13Z", expected u64`, which reached the
  operator as an internal error from a `set` that had in fact succeeded —
  the name was already in the DID document while the UI reported failure
  and showed an empty registry.

  `AgentNameEntryWire` is documented as the shape of the REST
  `GET /api/dids/{mnemonic}` `agentNames` array, where `createdAt` is Unix
  seconds as a number, and `webvh_didcomm::list_agent_names` reuses it to
  parse the DIDComm listing — where it is not. The published payload
  schema for `did-management/agent-name/list/0.1` types `createdAt` as
  `"string"` with `"format": "date-time"`, and the host projects it that
  way (affinidi-webvh-service, `did-hosting-control/src/messaging.rs`).

  Both producers are right. The same host emits *both* shapes: its DID
  record projection serialises the stored registry (numbers) while the
  list verb answers to the spec (strings), so one shape cannot simply be
  declared wrong. The consumer is the single place that sees both, so the
  wire type now accepts either and normalises to seconds — the VTA relays
  a `u64` outward in the canonical `AgentNameEntry`, so an RFC3339 input
  is converted rather than propagated. A third shape is a genuine contract
  break and still fails, quoting what arrived so it can be told apart from
  an unreachable host (R6.4).

  `chrono` moves from dev-dependencies to dependencies for the conversion.
  It was already in the build graph via `vta-service`.



## [0.1.9](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-webvh-v0.1.8...vta-webvh-v0.1.9) — 2026-08-17


## [0.1.8](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-webvh-v0.1.7...vta-webvh-v0.1.8) — 2026-08-16


## [0.1.7](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-webvh-v0.1.6...vta-webvh-v0.1.7) — 2026-08-16


## [0.1.6](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-webvh-v0.1.5...vta-webvh-v0.1.6) — 2026-08-14


### Added

- **webvh**: Find DIDs a host serves that this VTA has no record of ([#976](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/976))

A DID can exist on a hosting server and nowhere in the VTA that owns it. The
  delete path says so out loud: `delete_did_webvh` calls the host first and, when
  that call fails, logs "continuing local cleanup but DID is now orphaned on the
  daemon" and removes the local record anyway. The host keeps serving a DID whose
  controller has discarded its keys, and nothing since then could tell you.

  Found the hard way: the hosting UI listed a DID, a delegated edit against it was
  refused with `did not found: SCID … not found`, and from the outside that reads
  as lost keys rather than an orphan.

      pnm did-mgmt dids reconcile --server primary

  Read-only, and repairs nothing on purpose — a host-only entry wants removing at
  the host, a local-only entry wants its publish retrying, and neither is safe to
  infer from a list. Naming them is the job.

  **Only the VTA can answer it.** The operator holds no credentials for the
  hosting server; the host has no view of the VTA's records. So the VTA
  authenticates with its own credentials, reads `GET /api/dids?owner=<its own
  DID>`, and compares against its local records.

  Three decisions worth the reviewer's attention:

  - **`owner` is always sent**, though the endpoint allows omitting it. A VTA that
    administers its own host *is* an admin caller, and the host answers an admin
    who names no owner with every DID on the server — reporting every other
    tenant's DID as missing locally.
  - **Matched on the host's slot id, not the DID.** A slot reserved but never
    published to has no DID at all and is exactly as orphaned as one that was.
    Pinned by a test.
  - **Super-admin, and DIDComm-only registrations are refused.** The host has no
    notion of VTA contexts, so its listing cannot be filtered by
    `has_context_access` the way `dids list` filters local records — and scoping
    the *result* instead would hide orphans from everyone, since an orphan has no
    local record to carry a context. The host's listing is REST-only, so against a
    DIDComm-only server this errors rather than returning an empty diff: "nothing
    to report" is the one wrong answer available, because it is the answer an
    operator stops looking after.

  ## The registry cost, stated plainly

  This adds one URI — `vta/webvh/servers/dids/0.1` — that the published registry
  has no spec for, so it lands on **both** drift registers: the per-family census
  in `vtc-service` (spec/vta 36 → 37) and the per-URI
  `UNSPECCED_DISPATCHED_URIS` in this crate, whose own rule reads "author the spec
  upstream — growing the allowlist is the wrong fix".

  It is added knowingly. The spec cannot come first from inside this repo: it
  needs a PR to trustoverip/dtgwg-trust-tasks-tf and a `trust-tasks-rs` release
  before the URI resolves, which is how every entry on that list arrived. The
  disposition is **spec under `vta/`**, recorded in `registry-drift-triage.md`
  beside `servers/{list,register,remove}` and for the same reason: the subject is
  the VTA's own view of a host it uses, and `did-management/did/list/0.1` is the
  host's listing rather than the comparison against local records. The nearest
  sibling shows the way out — `servers/domains/0.1` relays the same host's domain
  view, went upstream as dtgwg-trust-tasks-tf#171, and is on neither list as a
  result.

  The alternatives were weighed and are worse: a REST-only route is unreachable
  from a TSP-transport CLI, and folding this onto `webvh/dids/list/1.0` makes a
  local read do network I/O and grows a response shape most callers never want.

  The `did-hosting-ui` half — the warning beside the delegated-edit button, and
  the hint that names this command when the agent answers "not found" — is
  affinidi/affinidi-webvh-service#163.



## [0.1.5](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-webvh-v0.1.4...vta-webvh-v0.1.5) — 2026-08-13


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


