# Changelog

Notable changes to the published crates. Generated from conventional commits by
[git-cliff](https://git-cliff.org) when a release is cut — do not edit by hand.
## [0.12.4](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-cli-common-v0.12.3...vta-cli-common-v0.12.4) — 2026-09-06


### Added

- **persona**: The operator surface, and a preview built to be read ([#1257](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1257))

* feat(persona): SDK wire types and client methods for the persona family

  Twenty-four request bodies under `protocols::persona` and the client
  methods that dispatch them, against the specs merged in
  trustoverip/dtgwg-trust-tasks-tf#360.

  Responses come back as `Value`, as they do for `app-state`: these are the
  shapes a caller must get right to be understood, and a response is read
  by whatever renders it.

  **Hand-written here, generated in the service.** `vta-service` builds
  these payloads from `trust-tasks-rs` directly, because a mirror is a
  second definition of one contract and free to drift. This crate cannot do
  the same: `trust-tasks-rs` is an optional dependency here and the `client`
  feature does not enable it, so a types-only consumer must not be made to
  pull the generated tree in. Two source-level censuses cover the gap —
  `payload_ext_census` and `payload_null_census`.

  **The boundary is in the types.** `LocalProfileEntry` is a separate type
  from `ProfileEntry` rather than the same type with variants unused,
  because the published schema for `persona/local/profile/put/1.0` closes
  its entries to a single `inline` member. A profile built inside a trust
  context has nowhere to name an attribute in the agent-scoped pool. That
  closure is load-bearing rather than incidental, which is why it is
  mirrored as a distinct type instead of a shared one used carefully.

  **Three census exemptions, and why they are not the easy way out.**
  `OverrideValue`, `InlineValue` and `LocalProfileEntry` deny unknown fields
  and carry no `ext`, which `payload_ext_census` flags. Adding one would be
  wrong: the published schemas close all three with
  `additionalProperties: false` and declare no `ext` slot, and
  `trust-tasks-rs` generates them with `deny_unknown_fields` and no `ext`
  for the same reason — so the field would make this crate emit documents
  the VTA's own `validate_payload` rejects. They join
  `IssuedCredentialSummary` in `NO_EXT_BY_DESIGN`, which exists for exactly
  this case: a member of a payload rather than a payload.

  `ProfileEntry` carries `untagged` **and** `deny_unknown_fields`, with the
  variants in reading order, for the reason recorded on the store-side type:
  the clause is the only thing keeping the four forms apart, so a test can
  prove it is working.

- **pnm-cli**: Add memory command group ([#1222](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1222))

* feat(pnm-cli): add memory command group

  Add `pnm memory` for CRUD over the VTA's per-context agent memory
  (`spec/vta/memory/{put,list,delete}/0.1`): plant, recall, forget, wipe.
  Context-scoped via `--context` (default `default`); `--json` supported.



### Fixed

- **sdk**: Accept the `ext` member every payload schema declares ([#1231](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1231))

SPEC §4.5.1 gives every Trust Task payload an `ext` slot, and the published
  schemas declare it — `acl/list/0.1` lists `ext` among its properties, as do
  `policy/list/0.2`, every `vta/memory/*` body, `app-state` writes, config show
  and patch, and both credential-issuance bodies.

  Sixteen `deny_unknown_fields` structs had no field for it, so a producer doing
  exactly what the schema permits had its whole document rejected:

      malformed request: payload parse: unknown field `ext`, expected one of
      `role`, `scope`, `direction`, `subjectPrefix`, `pageSize`, `cursor`

  Seven sibling structs already carry `ext`, with the reasoning written out on
  each; this completes that work rather than starting it. `deny_unknown_fields`
  stays: carrying `ext` explicitly is what keeps a *typo* refused, which is the
  guard that clause was there for, while letting through the one member the spec
  says is always allowed.

  Found from a browser-based VTA management console: its Access and Policy panes
  died outright, and the operator was shown a parse error naming a field the
  spec had told the client it could send. Nothing caught it earlier because
  whether a caller trips this is decided entirely by whether it populates `ext`
  — the conformance table exercises the members its fixtures set, and this
  defect lives in the member they leave unset.

  So the guard is a census over the source rather than another fixture:
  `payload_ext_census.rs` fails on any `deny_unknown_fields` type under
  `protocols/` that carries no `ext`, with an exceptions list that has to state
  a reason. Verified to fail by reverting one struct.



## [0.12.3](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-cli-common-v0.12.2...vta-cli-common-v0.12.3) — 2026-09-01


### Fixed

- **vta**: Keep not-found, conflict and gone typed across the Trust-Task boundary ([#1219](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1219))

`pnm approvals list` failed on a VTA that had never had an approval rule:

      Protocol error: trust task failed [taskFailed]:
      task failed: not found: policy `approvals` not found

  A VTA with no approval rule has no `approvals` policy row — that is the
  shipping default, and the CLI is written for it: `load()` maps a missing
  row to an empty model. The arm could never fire.

  The Trust-Task framework defines no `notFound` / `conflict` / `gone`
  standard code, so `app_error_to_reject` sent all three out as `taskFailed`
  with `details: None`. The SDK had nothing to key on and fell through to
  `VtaError::Protocol(String)`, so the `Err(VtaError::NotFound(_))` arm in
  the approvals CLI was dead code on the only transport that surface uses
  (it is Trust-Task-only; no `/policies` REST route exists).

  The blast radius is the whole surface, not just `list`: every `pnm
  approvals` subcommand reads the row through the same `load()`, `require`
  included. Since `require` must read before it writes, the *first* rule was
  uncreatable — DTTE could not be configured on a fresh VTA at all.

  REST keeps this distinction in an HTTP status (`from_http`) and DIDComm
  protocol-messages keep it in a problem-report code (`from_problem_report`).
  The Trust-Task path was the only one that lost it, against the workspace
  rule to preserve type information across every transport.

  `taskFailed` remains the correct wire code — there is no other. The
  discriminator goes in `details.reason`, the channel the consent gate
  already established for exactly this reason, with the values defined once
  in `vta_sdk::protocols::trust_task_reject_reasons` so both sides derive
  from one definition. `VtaClient::trust_task_error` maps them back to
  `NotFound` / `Conflict` / `Gone`.

  Fixing `Conflict` alongside `NotFound` also restores the CLI's
  suggest-the-fix guidance, which switches on the typed variant.

  A `taskFailed` with no `details` stays `Protocol` — that is both a genuine
  failure and the shape an older VTA emits, so a new client does not misread
  every pre-upgrade failure as typed. Against such a VTA the workarounds are
  `pnm policy list` or the offline `vta approvals list`, both documented.



## [0.12.2](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-cli-common-v0.12.1...vta-cli-common-v0.12.2) — 2026-08-29


### Fixed

- **vta**: Refuse a malformed DID instead of reporting it missing ([#1195](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1195))

`pnm did-mgmt dids delete <did>` answered `webvh DID not found` for a DID
  that was sitting in the registry. The argument was the problem: it had been
  copied out of the `dids list` table, which elides the middle of the SCID, so
  it carried a literal `…` (U+2026). The store was asked for a DID that does not
  exist and said so, accurately.

  Accurately, and misleadingly. "Not found" is a claim about the world — it says
  the DID is not here — so it sends the reader looking for something deleted
  rather than at what they typed. It cost two people an hour and a wrong
  diagnosis each: one concluded an earlier command had removed the DID, the
  other that the VTA had never hosted it. Neither was true.



## [0.12.1](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-cli-common-v0.12.0...vta-cli-common-v0.12.1) — 2026-08-29


## [0.12.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-cli-common-v0.11.5...vta-cli-common-v0.12.0) — 2026-08-28


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



## [0.11.5](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-cli-common-v0.11.4...vta-cli-common-v0.11.5) — 2026-08-26


## [0.11.4](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-cli-common-v0.11.3...vta-cli-common-v0.11.4) — 2026-08-22


## [0.11.3](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-cli-common-v0.11.2...vta-cli-common-v0.11.3) — 2026-08-21


## [0.11.2](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-cli-common-v0.11.1...vta-cli-common-v0.11.2) — 2026-08-20


### Fixed

- **tee**: Bootstrap 410 and vsock enotconn ([#1003](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1003))

* fix(tee): retry transient ENOTCONN on first vsock config-overlay read

  tokio-vsock can report a stream connected just before Nitro finishes the
  nonblocking handshake, so the very first read on a fresh vsock:5800
  connection to the parent config server can return ENOTCONN even though
  the parent is listening and ready. Retry only that specific transient
  error kind with a short delay; any other I/O error still fails closed
  immediately, and the existing overall READ_TIMEOUT deadline still
  bounds the whole fetch.

  Adds positive (retries ENOTCONN then succeeds) and negative (does not
  retry PermissionDenied) unit tests against the inner read loop.



## [0.11.1](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-cli-common-v0.11.0...vta-cli-common-v0.11.1) — 2026-08-18


## [0.11.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-cli-common-v0.10.33...vta-cli-common-v0.11.0) — 2026-08-17


### Added

- **vta-keys**: Add non-extractable internal signing keys ([#995](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/995))

An ordinary VTA key is BIP-32 derived, so anyone holding the 24-word mnemonic
  can reconstruct it offline. That is what makes the VTA recoverable, and equally
  what makes "the operator cannot obtain this key" false — the second limb of what
  eIDAS calls sole control.

  An internal key is generated from the system CSPRNG, has no derivation path, and
  is never returned by any surface. The VTA acts only as a signing oracle for it.

  Deliberately not a flag on the imported-key path. That path wraps its secrets
  under a KEK derived from the master seed (derive_kek(seed, salt)), so a
  non-extractable flag on it would be decorative: the boundary it claims to
  enforce has already been walked around. Internal keys get their own keyspace,
  INTERNAL_KEYS, with no seed involvement at any point, and that keyspace is in
  EXCLUDED_FROM_BACKUP by design — a backup carrying it would be an export of keys
  the VTA promises never to export, and restoring it elsewhere would clone a
  signer.

  Refused for did:webvh log entries, enforced in code rather than left to
  guidance. WebVH is append-only and each entry is authorised by the update key
  the previous entry named; an unrecoverable update key means that if storage is
  lost the DID can never be updated again by anyone, permanently, and every
  integration pinned to it is stranded. Credentials can be re-issued, an
  append-only identity log cannot. Internal keys remain fine as a signing
  verificationMethod inside a published document, where loss costs the ability to
  produce new signatures rather than control of the identity.

  The export refusal is not a permission check — admin is not a bypass, because
  the value of the origin is that no caller holds this power. There are two
  refusals (an early return and an in-match arm); removing either leaves the other,
  and removing both does not compile, since the match over KeyOrigin becomes
  non-exhaustive. An export path cannot silently reopen.

  Operator surfaces carry the cost prominently: `pnm keys create --internal`
  prints what is lost and requires the operator to type a confirmation phrase
  rather than mash y, the response repeats the warning, and docs/02-vta/
  internal-keys.md covers when to use one, what actually protects it (enclave
  measurement + KMS, not a mnemonic), and the two things that genuinely destroy
  it.



## [0.10.33](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-cli-common-v0.10.32...vta-cli-common-v0.10.33) — 2026-08-16


## [0.10.32](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-cli-common-v0.10.31...vta-cli-common-v0.10.32) — 2026-08-16


## [0.10.31](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-cli-common-v0.10.30...vta-cli-common-v0.10.31) — 2026-08-14


### Fixed

- **cli**: Make `dids list` show the DID, and plan errors say what failed ([#967](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/967))

Two unrelated fixes to the same delegated-update path, found chasing a
  `webvh/dids/update` that failed after its consent gate passed.

  **`pnm dids list` rendered a wide name beside an unreadable DID.** A
  ratatui `Table` lays out exactly as many columns as it has width
  constraints — a widths list shorter than the row is not padded, it
  truncates. `dids list` builds its header and its rows with a conditional
  Name column but built the widths without one, so every width landed a
  column to the left: Name inherited the DID's flexing `Min`, the DID
  inherited Context's fixed 16 (`did:webvh:Qm0M8Cr`, cut mid-SCID) and
  `Created` fell off the right-hand end. The servers table above it had the
  same shape of bug from the other direction — its widths were written
  against a different column order, and their own comments still said so.

  Header and widths are now returned together from `did_list_columns`, so
  the two cannot drift, and the DID column starts at 46 columns: `shorten_did`
  abbreviates only the SCID and keeps host and path in full, which is what
  makes the value copyable.

  **Every webvh dry-run failure became `internalError`.** The planner runs
  on the consent path and only there, so that flattening applied to exactly
  the report an approver-gated update produces: a DID the VTA does not hold,
  a context the requester cannot act in, and a genuine signing bug all
  arrived as one opaque internal error — while the *ungated* execution of
  the very same task answered `taskFailed: did not found: …`. Turning
  consent on made the diagnosis worse than leaving it off.

  Dry-run failures now route through the existing
  `From<UpdateDidWebvhError> for AppError`, so plan and execute answer with
  the same variant for the same cause, with `webvh update dry-run:` framing
  the message. The Forbidden-collapses-to-NotFound rule that stops a
  dry-run being used to probe for DIDs in unseen contexts is preserved, and
  pinned by a test.



## [0.10.30](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-cli-common-v0.10.29...vta-cli-common-v0.10.30) — 2026-08-12


### Added

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



## [0.10.29](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-cli-common-v0.10.28...vta-cli-common-v0.10.29) — 2026-08-12


### Fixed

- **vault**: Send entryId on vault release, from both the CLI and the MCP bridge ([#948](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/948))

* fix(vault): use entryId instead of id in vault release payload

  cmd_vault_release was constructing the vault/release/0.1 Trust Task
  payload with key `id`, which fails schema validation. The schema
  requires `entryId` (matching VaultReleaseBody's camelCase
  serialisation on the server side).


