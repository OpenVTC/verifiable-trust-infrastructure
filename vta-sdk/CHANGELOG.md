# Changelog

Notable changes to the published crates. Generated from conventional commits by
[git-cliff](https://git-cliff.org) when a release is cut — do not edit by hand.
## [0.53.1](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-sdk-v0.53.0...vta-sdk-v0.53.1) — 2026-09-26


### Security

- **vta-sdk**: A consent request must be signed under authentication ([#1766](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1766))


## [0.53.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-sdk-v0.52.0...vta-sdk-v0.53.0) — 2026-09-26


### Added

- **cnm**: Answer the community's consent requests from the CLI (VTI-APV-014) ([#1759](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1759))

Making or widening an unrestricted administrator at the VTC needs another
  unrestricted administrator's consent (VTI-APV-014), but only a device
  enrolled to handle the task-consent push could answer. An approver with a
  cnm profile had no way to sign a decision.

  `cnm consent {show,approve,deny} <file|->` takes the request the
  requester relays (the refusal body, its `details`, or a bare request
  document), picks the one addressed to this profile, and verifies it. The
  VTC must have signed it, it must be addressed to this approver, and it
  must not have expired. Approving requires typing the requester's match
  code (or `--match-code`); a mismatch sends nothing. The decision is
  signed with the profile's key under assertionMethod and posted to the
  document endpoint.

  The approver's shared half is a new `vta_sdk::task_consent` module:
  `match_code`, `ConsentRequest::verify` returning a
  `VerifiedConsentRequest` (the only type a decision can be built from),
  and `decision`. `vtc-client` gains `decide_task_consent`.

  It also fixes a mismatch between the two screens: the requester prompt
  in `vta_cli_common::consent` printed the whole `zQm…` digest as the
  "code", while approver devices show six hex characters of the decoded
  digest. Both now call `vta_sdk::task_consent::match_code`, and so does
  `vta-mobile-core`, which drops its copy.

  Tested end to end in `unrestricted_admin_consent`: a real VTC-signed
  request verifies through the SDK, is refused when it is addressed to
  someone else, comes from another issuer, or has been tampered with, and
  the decision built from it grants the consent.

- **vtc-service**: Git-ns drift/resolve, namespace/reseat, view 0.2 ([#1703](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1703))

* feat(vtc-service): git-ns drift/resolve, namespace/reseat, view 0.2

  Implements the git-ns tasks added in trust-tasks #625 and #627, on
  trust-tasks-rs 0.22.5.

  - git-ns/drift/resolve 0.1: an owner adopts a forge-side role as the
    git-ns/right/grant it is (same fixed rules, policy, consent class), or
    reverts a forge-side change through the bridge. Items are selected by
    type, account (role items) and observed (required to adopt). Every
    declared code: driftNotFound, notAdoptable, accountNotLinked,
    noMatchingRight, notRevertible, plus the family's codes.
  - git-ns/bridge/job 0.2: sent only for the revert of a roleAdded item
    (projectRoles with removeAccounts), in-line, so a bridge implementing
    only 0.1 is answered notRevertible; every other job stays 0.1.
  - git-ns/namespace/reseat 0.1: a community administrator grants a
    permanent git.ns.admin on a headless namespace to a current member,
    atomically with the headless check; notHeadless otherwise. The audit
    record keeps the statement and how earlier admin records ended.
  - git-ns/view 0.2 (served beside 0.1): the caller's own linked forge
    accounts, narrowed to the resource's forge.
  - git-ns/bridge/event 0.2 (served beside 0.1, same handler): a transfer
    detaches wherever it goes; an event any of whose resources, drift items
    included, lies outside its namespace is refused before anything is
    applied.
  - cnm: `cnm git drift resolve`, `cnm git reseat`; `cnm git view` asks for
    view 0.2. vtc-client gains the matching methods.
  - Default gitNamespace policy: namespace.reseat receives a right;
    drift.revert documented.



### Changed

- **vti-common**: Share the durable Trust Task push engine between nodes ([#1760](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1760))

#1754 gave the VTC a push engine that picks TSP > DIDComm > REST by what the
  recipient's DID document advertises. It records each push durably, queues one
  outbox attempt per transport, settles on delivery evidence and escalates when
  an attempt yields none (VTI-TRN-030, -040, -041, -042). The VTA's own pushes
  (`consent_request::push_one`) are still best-effort TSP followed by DIDComm,
  and to adopt the same model the engine has to live somewhere both nodes can
  reach.

  It moves unchanged to `vti_common::trust_task_push`. The node lends it what is
  its own through a `PushContext`: the records keyspace, the outbox, the
  resolver, its messaging handle and whether it can send TSP. The REST transport
  takes its HTTP client, so each node supplies its foreign-fetch profile.
  `vtc-service::member_push` is now that adapter, and its call sites are
  unchanged.

  The outbox transport ids keep their `member-push-*` values, so attempts queued
  before an upgrade still drain after it. `vti-common`'s `tsp` feature now also
  enables `affinidi-tdk/tsp` and `vta-sdk/tsp` for the TSP transport. That
  exposed two items in `vta-sdk` gated on `tsp` but used only with `client`,
  which are now gated on both.

  The VTA moving onto the engine is a follow-up.



### Fixed

- **vta-service**: Close the key-material follow-ups from the export audit ([#1743](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1743))

* fix(vta-service): apply the key-export and sign capability checks on every transport

  The KeyExport capability was checked only by the keys/export-secret
  Trust-Task handler, so GET /keys/{id}/secret and DIDComm get-key-secret
  released private keys to an admin whose entry was narrowed without
  key-export. Capability::Sign was checked nowhere.

  Both checks now live in the operation layer (VTI-VTA-003, VTI-VTA-007):

  - get_key_secret requires key-export before any lookup, refuses a
    hop-by-hop channel (keys/export-secret/0.1 requires a channel
    confidential to the two parties), keeps the internal-key and
    non-exportable refusals, and writes the key.secret_export audit row
    durably before releasing the material, refusing if it cannot.
  - The Trust-Task binding (https, didcomm, tsp) is recorded at the three
    entry points and named in the export's audit channel.
  - vta/contexts/secrets and provision-integration use the same gate.
  - sign_payload requires sign for opaque caller bytes; derive-and-sign
    and derive-and-sign-document require sign.
  - The legacy REST and DIDComm key routes now consult the policy gate
    with the matching Trust-Task URI.
  - The TEE mnemonic export writes a durable audit row before release.

- **vta-service**: Require a document proof bound to the sender on every DIDComm and TSP trust task ([#1739](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1739))


### Security

- **vta-sdk**: Verify a proof's key against its proofPurpose (VTI-KEY-022) ([#1752](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1752))

* security(vta-sdk)!: verify a proof's key against its proofPurpose (VTI-KEY-022)

  A verifier accepted any key the signer's DID document listed under
  verificationMethod, whatever the proof declared it was for. A key published
  only for keyAgreement, or authorised only to authenticate, could make an
  assertionMethod proof.

  vta-sdk adds ProofPurpose, PurposeVmResolver and PurposeBound.
  TrustTaskVmResolver now resolves a method only for one purpose, and only
  when all of these hold:
  - the resolved document is the DID's own;
  - the method is listed under the relationship the purpose names, by
    absolute DID URL, by relative fragment, or embedded. A reference resolves
    only against the top-level verificationMethod set;
  - the method's controller is the DID.

- **vta-service**: Require assertionMethod on an approver's decision ([#1757](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1757))

* fix(vta-service)!: require a document proof bound to the sender on every DIDComm and TSP trust task

  A Trust Task that reaches the VTA or the VTC over an intrinsic-sender
  transport (DIDComm, TSP) is now accepted only when the document carries a
  Data Integrity proof that verifies as its `issuer`, and that issuer is the
  transport-reported sender. The transport's sender alone no longer
  authorizes anything (VTI-OPS-021/093).

- **resolver**: One bounded DID-document cache per node, re-resolved once before a verification fails (VTI-KEY-134) ([#1737](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1737))

* security(resolver)!: one bounded DID-document cache per node, re-resolved once before a verification fails (VTI-KEY-134)

  The VTC ran two DID-document caches: the app resolver built in
  `init_auth`, and a second one the messaging TDK built for itself
  because it was given none. Both used the SDK defaults of a 300 s TTL and
  100 entries. Every DIDComm and TSP message on the mediator socket was
  checked against a cache the REST and Trust Task paths could not see or
  evict. Neither cache was ever refreshed when a verification failed, so
  a peer that rotated was refused as a forger until its entry aged out.

  Bounded TTL (key-roles, dtgwg-vti-spec #42: VTI-KEY-060/062/122/123/134):

  - A new `[did_cache]` section (`vti_common::config::DidCacheConfig`)
    holds `ttl_secs` (default 60, refused outside 1..=300) and `capacity`
    (default 1000). The VTA and the VTC read the same type.
  - The TTL is what bounds how long a key revoked for compromise keeps
    verifying: VTI-KEY-123 allows no overlap, and nothing else notices a
    removal. A new key does not wait on the TTL, because of the refresh
    below. 60 s caps the revocation window at a minute, for one resolution
    per active DID per minute. 300 s, the SDK default and the old
    behaviour, is the ceiling.
  - `vta_sdk::resolver::build_verifier_did_cache_config` builds it, with
    the webvh host policy the VTA already used. The VTC now uses that
    policy too, so the private-host opt-in reaches it as well.

  One cache:

  - The VTC messaging TDK is handed the app resolver.
  - The VTA already shared its resolver. Its fallback when there is no
    app resolver now gets the same bounds, not the SDK defaults.

  Re-resolve once, then fail closed (`vta_sdk::did_refresh`):

  - `resolve_for_vm`: when a cached document does not list the method a
    proof names, re-resolve it fresh once. This covers every Trust Task
    proof on both nodes (`TrustTaskVmResolver`) and the VTC credential/VP
    resolver (`DidVmResolver`).
  - `verify_trust_task_proof_with`: when verification fails and the
    signer's document came from the cache, evict it and verify once more.
    This covers a key id kept with its material replaced.
  - `unpack_refreshing_sender`: when an authcrypt unpack fails, evict the
    sender named in the protected header (`skid`) and retry once. It is
    used on the REST DIDComm auth and refresh paths of both nodes.
  - Each forced refresh is rate-limited per DID (5 s, with at most 4096
    DIDs tracked). A failing proof is something anyone can send, and
    without the limit each one would make this node fetch a third party's
    document.

- **vta**: Key custody — seed and key material only through audited, scope-checked doors (FTL-29904) ([#1715](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1715))

Every key the VTA holds is a pure function of the master seed and a BIP-32
  path, so choosing a path is holding a key. FTL-29904 reported that a
  context-scoped admin could list and rotate the instance-wide seed; the review
  found the same mistake, a gate asking about the caller's role or context and
  never about the path or key it named, in five more places:

  - seeds list/rotate: gated on the admin role on REST, Trust Task AND DIDComm
    (the report named two transports). Now super-admin, enforced once in the
    operation so all three share one audited refusal (VTI-ACL-022, VTI-ACL-092).
  - keys/create accepted any derivationPath and recorded the key under the
    caller's own context, so keys/export-secret released it: another tenant's
    key or the VTA's own did:webvh update key. Only a super-admin may choose a
    path, and the path must belong to the record's context (VTI-KEY-030/032).
  - keys/derive-and-sign(-document) signed as any path for any admin. Now
    super-admin only and confined to the delegated-identity subtree m/26'/9';
    every signature is audited with a digest of what was signed (VTI-VTA-006).
  - vault/sign-trust-task and vault/proxy-login loaded the entry's signingKeyId
    under InternalAuthority with no scope check, so an entry naming
    {vta_did}#key-0 made the VTA sign as itself (reachable by `initiator`). The
    key must now be in the entry's context subtree, at use and at upsert.
  - credentials/issue and credentials/revoke (VTA-signed VCs over caller-chosen
    claims) required only the admin role. Now super-admin.
  - vault/credentials/receive could bind an mdoc to a context-less key without
    super-admin.

- **workspace**: No type derives Debug over secret material ([#1711](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1711))

A derived `Debug` prints every field, so on a type holding a private key, a
  seed or mnemonic, a bearer or refresh token or a password it puts the secret
  into anything that formats the value — a `tracing` field, an `unwrap` or
  `expect` on an enclosing type, a test failure, a panic message. About 55 types
  across twelve crates did exactly that. It surfaced when `vtc-client` began
  holding an operator's key in a `HolderKey`, whose derived `Debug` printed it.

  Each now has a hand-written `Debug` that reports the secret as `<redacted>` —
  presence kept visible for an `Option` — and prints every other field as
  before, the idiom the workspace already used where someone had thought of it.
  Among them: `HolderKey`, `Session`, `ClientIdentity`, `CredentialBundle`,
  `SecretEntry`, `AgentConfig`, `AgentConnect`, `AuthResult`, the key-import and
  seed-rotation requests (mnemonic), `SeedRecord`, `MnemonicExportResponse`,
  `SecretsConfig` (seed, Vault token, AppRole secret id), `VaultSecret`, its
  `CustomField` values and secure notes, `TotpSeed`, the VTC install flow's
  ephemeral signing keys, setup tokens and install JWT, the VTC backup's signing
  bundle and password, mobile-core's X25519 and Ed25519 private keys, auth tokens
  and push tokens (including the Web Push auth secret), and vta-mcp's
  `--agent-key`/`--holder-key`/`--agent-secrets`.

  `Zeroizing<T>` is not a redaction — its `Debug` prints the inner value — so the
  fields wrapped in it were redacted too.

  `vta-sdk/tests/secret_debug_census.rs` keeps the class closed. It parses every
  workspace crate with `syn` and fails on a `#[derive(Debug)]` struct or enum
  whose field has a secret-sounding name (`*_key`, `*token*`, `*secret*`,
  `seed*`, `password`, `mnemonic`, `jwt`, and `secret_id` despite its `_id`)
  and a raw type (`String`, bytes, `Zeroizing<_>`, optionally in an `Option` or
  behind a reference). A field whose type is another workspace type inherits that
  type's `Debug`, which is checked where it is defined. What the name rule
  catches and is not a secret — a claim-type vocabulary token, a webvh path
  called `mnemonic`, the name of an entry in a secret store — is on a
  shrink-only list with what the field holds, and the census also refuses a
  stale entry and a walk that has stopped finding types.

  Not an API change: every type still implements `Debug`; only what it prints
  differs, and no test asserted on the old output.



## [0.52.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-sdk-v0.51.0...vta-sdk-v0.52.0) — 2026-09-24


### Chore

- **deps**: Messaging-sdk 0.27.1 + trust-tasks-rs 0.22.3; answer a mutual TSP cancel the SDK could not (Keyring VTI-38) ([#1693](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1693))

Raises the floors on top of #1690's 0.22.1 / 0.27.0 move: trust-tasks-rs and
  -proof to 0.22.3 (the git-ns family, enabled by all-specs; the rest of the
  trust-tasks-* line resolves to 0.22.3 too), affinidi-messaging-sdk to 0.27.1.
  The graph holds exactly one copy of each.

  `affinidi-messaging-sdk` becomes a workspace dependency (floor 0.27.1) in
  place of five hand-kept per-crate literals.

  SDK 0.27.1 answers a peer's §7.3 cancellation of a mutual relationship
  itself, and `reply_expected` now means "the answer is still owed", which is
  true only when that send failed. The VTA's and VTC's `handle_tsp_control`
  retried with `cancel_relationship`, which refuses `SendCancel` out of `None`
  (the relationship is already forgotten). That is the exact VTI-38 failure.
  They now use `TspOps::answer_cancellation`.



## [0.51.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-sdk-v0.50.0...vta-sdk-v0.51.0) — 2026-09-23


### Added

- **persona**: Worlds on the wire, and a narrow read of one attribute ([#1690](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1690))

Takes trust-tasks-rs 0.22, which has been unreachable since 0.21.21:
  affinidi-messaging-sdk required ^0.21.20 and `MediatorAcl` crosses that
  SDK's API, so a graph holding both versions failed to compile rather than
  merely carrying a duplicate. affinidi/affinidi-tdk-rs#885 moved the
  messaging crates; this takes the line they are now on. One
  `trust-tasks-rs`, one `affinidi-messaging-sdk`, one `affinidi-tdk`.

  **Worlds.** `persona/facet/*` is `persona/world/*`, `facetId` is
  `worldId`, and `correlation/analyze` takes a 1.1 for its three renamed
  members. `face` and `facet` shared a stem while naming different things —
  a projection of the pool, and an arrangement of those projections — and
  every UI had already resolved it by saying "world" on screen, which left
  the collision live for anyone reading both.

  The retired spellings stay routable for a release and answer in their own
  words: `facetId` for `worldId`, `facets` for `worlds`, `crossesFacets`
  for `crossesWorlds`. A document already issued against one still
  validates, and refusing it would break a caller for a rename that costs
  it nothing. The whole alias is marked for deletion in one commit.

  **`persona/attribute/get`.** Reading one value meant
  `persona/attribute/list` with a type prefix, filtered by the caller — so
  revealing one email address decrypted every email address the holder has,
  and the audit row recorded a listing of the pool rather than a decision
  about one fact. `PersonaStore::get_attribute` applies exactly what a
  listing applies: visibility, retention, credential re-derivation.
  `versionPurged` is distinct from `notFound` because the attribute is
  still there, and `retainedVersions` lets a holder see what purging would
  take away rather than deciding blind.

  Two latent defects, both found by the new tests:

  - `correlation/analyze/1.0` was already answering with 1.1's member
    names. Nothing noticed because 1.1 did not exist.
  - A world with no faces and no attributes serialised without `faceIds`
    and `attributeIds`, which its own response schema requires, so listing
    an empty one returned a 500. `skip_serializing_if` on a required
    member; no test had made an empty one.

  The `pf:` storage prefix is unchanged — it is an opaque key prefix, not
  the noun, and renaming it would orphan every world already stored.



## [0.50.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-sdk-v0.49.0...vta-sdk-v0.50.0) — 2026-09-23


### Added

- **vtc**: A by-DID vetter status lookup ([#1671](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1671))

The vetter listing omits a vetter with no published profile and one whose
  grant was revoked in exactly the same way: both are simply absent. An
  applicant whose vetter went quiet could not tell which had happened, and a
  vetter could not check their own standing at all (Keyring VTI-Q3, #1651).

  `vtc/vetting/vetters/show/0.1` answers by DID with `live`, `revoked`,
  `expired` or `none`, the grant's id, the timestamp that ended or will end it,
  and — for a live grant — whether the vetter is listed. That last member is
  what separates "unlisted by choice" from "not a vetter".

  Served over `/v1/trust-tasks`, DIDComm and TSP for applicants and members,
  and as `POST /v1/vetting/vetters/show` for the console. `vtc-client` gains
  `show_vetter`.

  The live case goes through the same `live_grant` lookup the listing and every
  grant check use, so "live here" cannot drift from "live there". Where a grant
  is both revoked and expired the answer is `revoked`: the community
  withdrawing trust and a grant lapsing are different statements, and a vetter
  told `expired` would reasonably ask for a renewal.

  `CheckShape` on the response enforces what one object's schema cannot — which
  members belong to which status. A response saying `revoked` while carrying
  `validUntil` and no `revokedAt` reads as an expiry to a client branching on
  members rather than status.

  Requires trust-tasks-rs 0.21.21, which publishes the spec merged as
  trustoverip/dtgwg-trust-tasks-tf#603.

- **cli**: Pnm reaches worlds and the claim-type registry ([#1663](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1663))

`persona/facet/{put,list,delete}` and `persona/claim-types/list` had no
  method on `VtaClient` at all, so `pnm` could not reach them even though
  both graphical clients do. The SDK gains the four, built from the
  generated specification types rather than hand-written bodies, and
  decoding their responses into the generated `Response` — a shape the
  specification does not describe is then an error at the call rather than
  a `None` three screens later.

  `pnm persona world {list,put,delete}` and `pnm persona claim-types`
  follow. Both id lists on a put replace: the specification is explicit
  that a member whose absence meant "keep" would make emptying a world
  impossible, so the CLI passes them through as given and says so.

  The colour is a ValueEnum whose mapping to the specification's tokens is
  written out rather than derived, pinned from both sides — `pnm-cli` does
  not depend on the generated types and `vta-cli-common` does not know the
  CLI's enum, so the pair of tests is what holds the wire value end to end.



### Fixed

- Use shared_tdk_config for unified DID resolution ([#1661](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1661))


### Security

- **persona**: The correlation answer on a local write is the holder's ([#1676](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1676))

Two defects in one task, found while writing a test for the first.

  **The oracle.** `persona/local/profile/put` is context-scoped, and its
  response carried `correlation.matchesPoolValue` — a yes/no on "does the
  holder hold this exact value anywhere", computed from the agent-wide
  index. A caller that can write is a caller that can guess, so any
  application authorized in one context had an unbounded oracle over the
  whole pool: one guess per write, each answer confirming or eliminating
  one. No value crosses the boundary and none needs to — for a name, an
  address or a date of birth, confirmation is disclosure.

  The member is now told only to a caller that passes the holder test, and
  omitted rather than softened: a coarser signal is still an oracle, only a
  slower one. The holder still learns it, through the audit row (which
  records it whoever asked) and `persona/correlation/analyze`. Conditional
  by the specification too, as of dtgwg-trust-tasks-tf#609.

  **The unsendable payload.** Writing that test showed the agent refusing
  its own SDK's request: `LocalProfileEntry` reused the pool's
  `InlineValue`, whose `provenance` is required, and the schema has no such
  member for a context-local entry and sets `additionalProperties: false`.
  So every local-profile write this SDK could build was rejected —
  `persona_local_profile_put` could not express a conforming payload at
  all. `LocalInlineValue` is that type without the member, which is the
  boundary rather than an omission: a credentialBacked provenance names a
  credentialId and a claimPath, and a context has nowhere to put either.

  The rule against hand-writing a payload type for a task that has a
  generated module exists for exactly this; the generated type never had
  the member.



## [0.49.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-sdk-v0.48.0...vta-sdk-v0.49.0) — 2026-09-22


### Added

- **backup**: A backup is the whole agent, and restores between plain, hardened and TEE VTAs ([#1655](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1655))

A backup now carries every row of every keyspace in vta_keyspaces::BACKED_UP
  (format vta-backup-v2) and restores into a plain, hardened or Nitro-enclave
  VTA from any of them. VTI-VTA-001, VTI-VTA-050, VTI-VTA-051, VTI-KEY-033.

- **persona**: Wear a face here without naming a persona DID ([#1654](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1654))

Implements trustoverip/dtgwg-trust-tasks-tf#589 (design note
  persona-context-first.md §9.7).

  binding/set takes an omitted `personaDid`, and profile/compose takes
  `wear: true`: the agent uses the persona the holder already uses in the
  context — the one DID with a binding record there, current or cleared —
  and names it in the response. None is refused (`noPersonaHere`),
  several are refused (`personaAmbiguous`, naming them), and compose
  refuses `wear` beside a `personaDid` (`wearAndPersona`). Neither task
  mints a persona: a DID has a lifecycle of its own, and a write that could
  half-create one would leave a published identity nobody holds.

- **vtc**: Deliver an invitation to the DID it admits — pushed as an offer, or as a QR ([#1648](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1648))

Keyring VTI-21 and VTI-32. `vtc/invitations/issue` returned the signed
  invitation to the inviter once and nothing carried it further, and the
  credential was too large for a QR code (the console said so).

  `vtc/invitations/deliver/0.1` (`POST /v1/invitations/deliver`, inviter
  roles) records a single-use OID4VCI offer for the invitation, bound to the
  invited DID and withdrawing any earlier one, then either sends it to that
  DID as a `credential-exchange/offer` over DIDComm (`message`; `noRoute`,
  422, when the DID advertises no DIDComm service) or returns it (`offer`).
  The offer names the credential rather than containing it, so it fits a QR
  code as an `openid-credential-offer://` link.

  The invitation is released only through `credential-exchange/request` with
  a key-binding proof by the invited DID's key, so a photographed code admits
  no one else. Two things that required:

  - Key-binding proofs now verify for a holder of any DID method: the `kid`
    resolves through the community's DID resolver (`DidVmResolver`), where
    the verifier refused anything but a `did:key`. `redeem` and
    `issue_on_request` take the resolver.
  - `POST /v1/credential-exchange/request` redeems over HTTPS, for an invitee
    with no messaging service. Unauthenticated, on the rate-limited unauth
    chain: the proof is the authority. It answers with the
    `credential-exchange/issue` payload a messaging binding sends on-thread.

  The signed invitation is kept on its registry row so it can be delivered
  later (never listed). Invitations issued before this cannot be delivered
  and say to reissue. The admin console gets Send and QR-offer buttons on
  each live invitation. AuditEvent::InvitationDelivered.



## [0.48.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-sdk-v0.47.0...vta-sdk-v0.48.0) — 2026-09-22


### Added

- **persona**: Derived provenance, and endorsements as inventory ([#1639](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1639))

* feat(persona)!: derived provenance, and endorsements as inventory

  Implements trustoverip/dtgwg-trust-tasks-tf#582 (design note
  docs/05-design-notes/persona-context-first.md §5.7).

- **persona**: Where a face may be worn, where it is, and what it has done ([#1635](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1635))

Implements trustoverip/dtgwg-trust-tasks-tf#577 (design note
  docs/05-design-notes/persona-context-first.md §5.4, §9.6).

  Face reach. A pool face carries `reach` — FaceReach::Anywhere (default)
  or Only { context_ids } — an enum rather than a context list, so
  unrestricted and nowhere cannot be confused (#746/#769/#770).
  binding/set refuses a face outside its reach (`outsideReach`);
  profile/put refuses to narrow it past a context the face is worn in
  (`boundOutsideReach`, naming them). An omitted reach on profile/put keeps
  the face's current one: a client written before reach existed must not
  lift a restriction by saving an edit.

  persona/profile/usage — where a face is worn now, each binding's
  `until`, and the reach beside them.

  persona/profile/timeline — one face's history, oldest first: composed,
  worn, unworn, expired, disclosed, valueChanged, promoted, retired,
  reinstated. A binding taken off left no trace, so each face now has an
  append-only event log (`pft:`, agent-scoped, ULID-keyed so recording
  never takes the write lock), written after the change it describes and
  never failing it; the timeline joins it with the disclosure records. A
  face from before the log reports its composition from createdAt. A
  promoted face keeps its log; a deleted one loses it. FaceEvent has no
  member a value or label could go in, and a test holds that none reaches
  the wire.

  profile/compose takes `until` (`untilNotFuture`).

  `pnm persona profile usage|timeline`, `put --reach-only/--reach-anywhere`,
  `compose --until`. Takes trust-tasks-rs 0.21.14.

- **vtc**: A self-hosted community installs its own DID log over did-management/did/register ([#1632](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1632))

Keyring VTI-35. A community whose DID is `did:webvh:<scid>:<host>` serves
  its own did.jsonl, but the VTA holds the keys that extend it and cannot
  reach the community's copy, and the VTC keeps no VTA credential after
  setup. So an entry the VTA appends later — a TSP transport added to the
  community's services, a key rotated — had no way to the community except
  an operator copying the file by hand. (A community on a DID host needs
  none of this: the VTA publishes each entry to the host itself.)

  The VTC now answers `did-management/did/register/0.1` — the task a DID
  owner sends a DID host, where a second register with a longer log is an
  update — for its own DID at the root slot `.well-known`, over
  `POST /v1/admin/did/register` (super-admin). Before serving, it verifies
  the whole log (every entry's proof under the update keys in force, SCID,
  hash chain), that it is the community's own DID, and that every served
  entry survives unchanged as a prefix; then swaps the file atomically,
  with no restart. So an administrator's authority covers delivery only: a
  log the key holder did not sign, or one that moves the served log
  backwards, is refused whoever delivers it. The prefix rule is stricter
  than `register` alone and carries a consumer-minted code (SPEC §8.5).

  - `cnm did-log install --file did.jsonl`, fed by `pnm did-mgmt dids
    get-log`. It authenticates to the community directly, with the
    community's DID as the audience (`VtcClient::connect`), not through the
    profile's VTA session, whose audience is the VTA's DID — a VTC refuses
    that. The community DID comes from the log; the URL from its host.
  - `VtcClient::install_did_log`; `MockVtc::start_with` for a test VTC with
    a self-hosted DID; a live test authenticates and installs over HTTP.
  - AuditEvent::CommunityDidLogInstalled.
  - The redeploy hint for a DID the VTA manages but does not serve names
    the new command.

- **vtc**: Serve a member's credential bodies and show them in the admin console ([#1631](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1631))

`GET /v1/members/{did}/credentials`, bound to the now-published
  `vtc/members/credentials/0.1` (trustoverip/dtgwg-trust-tasks-tf#336,
  already in the locked trust-tasks-rs 0.21.11). AdminAuth. It reads the
  four fields #1213 keeps on the member row (`current_vmc`,
  `current_role_vec`, `member_vmc`, `member_vmc_bound`): no new storage and
  no new verification. `memberVmcBound` is the answer recorded at receipt,
  never recomputed.

  The response is the generated `specs::vtc::members::credentials::v0_1`
  type, documented through a new `vta_sdk::openapi::MemberCredentials01Response`
  wrapper. Bodies are carried as stored. `memberVmcReceivedAt` is only sent
  alongside `memberVmc`, because the spec says a maintainer MUST NOT send one
  without the other, and a row from before #1213 has the receipt time but no
  body.

  An unknown member gets a 404 whose body carries the spec's declared code,
  `vtc/members/credentials:notFound`, next to the usual `error` member.
  "Unknown" means what it means for `members/show`: no member row, or no ACL
  row, so a tombstoned member counts. A member who holds nothing gets a 200
  with every document absent and `memberVmcBound: false`, as the spec
  requires.

  The spec says a maintainer SHOULD record that the read happened, so every
  successful read writes a new `MemberCredentialsRead` audit event. The event
  names which documents were disclosed and never includes their contents.
  The audit write happens before the response. `AuditEvent` is
  `#[non_exhaustive]`, so the new variant does not break any consumer.

  A conformance witness checks the task. It builds its response with the
  handler's own `credentials_response`, over a row filled by the real
  `record_issued_credentials` / `record_member_vmc`, so it tests what the
  service sends rather than a hand-typed fixture.

- **persona**: Retire a face, warn before deleting one, and let a binding end on its own ([#1628](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1628))

Implements trustoverip/dtgwg-trust-tasks-tf#570 (design note
  docs/05-design-notes/persona-context-first.md §9.4, §9.5).

  persona/profile/retire and persona/profile/reinstate, for pool and
  context-local faces. Retire marks the face before clearing its bindings,
  so an interrupted retire leaves a face that cannot be newly worn and a
  repeat finishes the clearing; the cleared bindings come back in
  `unbound`. binding/set and local/binding/set refuse a retired face
  (`profileRetired`), profile/list leaves retired faces out unless
  `includeRetired`. Reinstate binds nothing. Profile gains `status` and
  `retiredAt`.

  Binding `until` on binding/set and local/binding/set, returned by
  binding/get and binding/list; `untilNotFuture` refuses one in the past or
  on a cleared binding. A lapsed binding reads as cleared at once — every
  binding read decodes through BindingRecord::into_read, and present
  refuses a preview whose persona no longer wears a face — whether or not
  the sweeper has run. The storage-thread sweeper (expire_bindings,
  audited as persona.binding.expire) makes the clear durable and retires a
  face the expiry left worn nowhere; never one still worn elsewhere, and
  never deletes.

  profile/get and profile/delete return `disclosedTo` {partyCount,
  contextCount}; `pnm persona profile delete` says "deleting does not
  un-tell them". Disclosure records now carry the face they were made
  through; an older record is attributed through its binding where that
  still wears the face.

  `pnm persona profile retire|reinstate`, `list --include-retired`,
  `binding set --until`, `local binding set --until`. Retire is
  Destructive for the MCP guard (it withdraws access everywhere at once),
  reinstate Mutating; both RetrySafe.

  Takes trust-tasks-rs 0.21.12.

- **persona**: Compose a face where it is asked for, and promote a local value ([#1623](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1623))

* feat(persona)!: compose a face where it is asked for, and promote a local value

  Implements persona/profile/compose/1.0 and persona/attribute/promote/1.0
  (trustoverip/dtgwg-trust-tasks-tf#569; design note
  docs/05-design-notes/persona-context-first.md §2.1, §5.3).

  compose — a face for one context, from values typed now and attributes
  already held, optionally worn there in the same act. Local by default: a
  typed value is carried inline and enters no pool unless the claim says
  `share: pool`, when a self-asserted pool attribute holding exactly that
  type and value is referenced, and created only if none exists. Where the
  face lives follows from its claims — all local makes a context-local
  face, anything pooled or held a pool face. Everything is validated before
  anything is written (unresolvedReference, duplicateSlot,
  labelWithoutPersona), and a later failure removes the attributes the
  compose created.

  promote — named entries of a context-local face become pool attributes
  and the face moves into the pool with its id, name, order, slots and
  wearers unchanged. One-way. The pool face is written and the bindings
  moved before the local face is removed, so an interrupted promote leaves
  the local face worn and a retry finishes it, reusing what it made.
  versionConflict and entryOutOfRange refuse a stale or out-of-range read.

  Both holder-only (Reach::Holder), classified Keyed for retry, Mutating
  for the MCP guard. `pnm persona profile compose` and `pnm persona
  attribute promote`. The design note records what the built form changed:
  the `profile` noun, no inline findings (analyze with `candidate` is the
  pre-write warning), no facetId, self-asserted-only reuse, and §9.7's
  DID minting left for its own design.



### Fixed

- **cnm**: Vetting, audit and backup authenticate to a VTC with its own DID as audience ([#1637](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1637))

`cnm vetting`, `cnm audit verify` and `cnm backup` could not sign in to a
  VTC. All three took a token from `SessionStore::ensure_authenticated`, whose
  audience is not a parameter: it is always the session's bound *VTA* DID, and
  the DIDComm authenticate envelope it builds is encrypted to that DID's
  key-agreement key. A VTC holds only its own keys, cannot open the envelope,
  and refuses the login. `cnm vetting` then also built its `VtcClient` with the
  VTA's DID as the community's DID. main connected to the VTA first, so without
  `--url` the requests went to the VTA's REST URL too.

  They now authenticate the way `cnm did-log install` does ([#1632](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1632)):
  `VtcClient::connect(base, vtc_did, client_did, key)` with the profile's DID
  and key, and the VTC's DID as the audience. They are exempt from
  `requires_auth`, so no VTA connection is made first.

  Where the VTC's DID comes from: `--vtc-did` (env `CNM_VTC_DID`), else a new
  optional `vtc_did` on the community profile, set with
  `cnm community set-vtc <did>`. The DID is never read from the server (for
  example the VTC's `/health`): it is the audience the sign-in is signed for,
  and a server allowed to name it could name another community's DID and
  relay the signed document there. Discovery runs from DID to URL, as it does
  for a VTA: `--url` if given, otherwise the `VTCRest` service in the DID's
  document, matched on `type` and checked by the same endpoint guard as a
  VTA's advertised REST URL.

  The root cause is a generic "token for this base URL" helper sitting on a
  session bound to one audience. `cnm`'s `auth::ensure_authenticated` wrapper
  is removed, so nothing in `cnm` can reach the VTC through the VTA session
  again, and `SessionStore::ensure_authenticated` now documents that it
  authenticates to the session's VTA only. Nothing else in the workspace
  used `SessionStore` against a VTC.

  When the VTC refuses the sign-in, `cnm` prints the fix with the DID filled
  in: `vtc --config <config.toml> acl add --did <DID> --role admin --label cnm`,
  or Access control, Add entry in the console. A VTC answers every
  authentication failure the same way (VTI-SES-007), so the message names the
  usual cause rather than claiming it.

  Routing these through a live VTC exposed two more faults on the same paths,
  fixed here:
  - `cnm backup export` saved the `{ envelope }` response (the export shape
    since #1059) instead of the envelope, so the file printed `(none)` for
    its source DID and could not be imported. `VtcClient::export_backup`
    returns the envelope, and accepts a pre-#1059 bare one.
  - `cnm audit verify` read the signed-checkpoint result from the top level,
    but #1110 moved it under `ext["org.openvtc"]`. Every report therefore
    looked like it had no checkpoint result, and a truncated log that the
    community key contradicts passed as long as its hash chain did. It reads
    both places now, and fails on any checkpoint status it does not know
    rather than passing it.

  vtc-client gains `audit_verify`, `export_backup`, `import_backup`,
  `REST_SERVICE_TYPE` and `api_base_from_did_document`, plus the three task
  URIs. All are additive.

- **vta**: Contexts/secrets requires KeyExport (VTI-VTA-003) ([#1634](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1634))

`vta/contexts/secrets/1.0` (`get_context_secrets`) released a context DID's
  private keys to any `Application`-role caller in that context. Its only gate
  was the role floor (`require_write`, which also admits `Initiator`) plus the
  context scope. VTI-VTA-003 says an export of derived key material "MUST be
  gated by a capability distinct from the capability to use the key, and MUST
  be audited". The audit was already there; the separate capability was not.
  An `Application` can *use* its context's keys through the signing oracle, and
  under the old gate that also let it *take* them. That is the case the
  requirement exists for: keys that were taken stay with the caller after its
  authority is withdrawn.

  ## The gate

  `get_context_secrets` now requires `Capability::KeyExport`, the same
  capability `keys/export-secret` requires. It reads the caller's **entry**,
  like `ensure_may_mint` ([#1619](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1619)), so a narrowing that removes `key-export` from
  an admin stops the next fetch. With no entry, the role decides. A store error
  refuses the call. The gate replaces the `require_write` role floor. The
  existing `require_context` scope check and the per-key `key.secret_export`
  audit are unchanged.

  `KeyExport` stays exactly as #1619 left it: derived by `admin` alone, and not
  grantable to any other role. So the service that operates a context's DID
  must be an admin **scoped to that context**. Integrations onboarded through
  `provision-integration` already have that grant: the mediator, did-hosting
  and the VTC. They are not affected.

  ## Who is affected

  Any `application` or `initiator` entry that fetches its context's secrets
  through `VtaClient::fetch_did_secrets_bundle` or
  `vta_sdk::integration::startup`. The known one is **room-host**, whose
  enrolment instructions granted `--role application`. After upgrading, such a
  caller gets `permissionDenied`, which the SDK surfaces as
  `VtaError::Forbidden` on REST, DIDComm and TSP. The message names the command
  that fixes it for that caller's entry:

  - an existing non-admin scoped to the context:
    `pnm acl change-role --did <did> --from application --to admin`
    (this keeps the entry's contexts);
  - an entry with no contexts: `pnm acl update <did> --contexts <CONTEXT>`
    first. The fix never suggests promoting an unscoped entry, because that
    would mint a super-admin;
  - an admin narrowed without `key-export`:
    `pnm acl update <did> --capabilities <existing>,key-export`
    (the narrowing is restated, never `--capabilities-all`);
  - no entry: `pnm acl create --did <did> --role admin --contexts <CONTEXT>`.

  ## Also changed

  - room-host's `grant_instructions` and its missing-DID help now grant a
    context-scoped admin (`vta import-did --role admin --context <C>` /
    `pnm acl create --role admin --contexts <C>`).
  - `vti-secrets` gains `OnboardingTicket::admin_import_did_command`. Its module
    docs now separate integrations that only call the VTA (`application`) from
    those that load their DID's keys (context-scoped `admin`).
  - Doc comments on the task constant, the handler, the SDK method and
    `get_context_secrets`. `docs/02-vta/integration-guide.md` gains a
    "Who may fetch a context's secrets" section.

  ## Tests (VTI-VTA-003)

  - The `operations/export.rs` tests that asserted the old loosening are
    rewritten.
  - New tests cover these cases: an Application is refused, an Initiator is
    refused, a context admin gets the bundle, an admin narrowed without
    `key-export` is refused, an admin of another context is refused, an
    unscoped non-admin is told to scope first, and a reader is refused. The
    entitlement-before-existence non-leak test now runs against both gates.
  - A handler-level test checks that the refusal is `permissionDenied` and
    carries the fix command.



## [0.47.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-sdk-v0.46.0...vta-sdk-v0.47.0) — 2026-09-21


### Added

- **vtc**: A community can ask an applicant to tell it about themselves ([#1614](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1614))

Implements trustoverip/dtgwg-trust-tasks-tf#543 (trust-tasks-rs 0.21.9),
  design note docs/05-design-notes/persona-context-first.md §5.2. A join
  manifest could ask only for credentials, so a community wanting a
  display name had nothing to put on the "what's required" screen, and
  nothing connected the join ceremony to an applicant's persona.

  - Requested attributes are one community-level row beside the branding
    (`community/requested-attributes`, backed up with it), managed with
    admin GET/PUT /v1/community/requested-attributes (audited:
    CommunityRequestedAttributesUpdated, types added/removed only), and
    published as `requestedAttributes` on join-requests/manifest/0.2.
  - join-requests/submit/0.2 accepts `attributes`. Before anything is
    stored -- before the open-request dedup -- the answers are checked:
    a required type unanswered is attributesMissing, a type the manifest
    does not request is attributesUnrequested (refused, not trimmed), both
    with details.types. Accepted answers are stored on the request and
    returned by show/list as `attributes`. They are self-asserted and are
    never fed to the join policy.
  - Only the Trust Task form carries them: the legacy REST submit's holder
    signature covers a fixed member set that does not include them, so an
    answer there would be unsigned. A community that requires one refuses
    that route with attributesMissing.
  - VtcClient::requested_attributes / set_requested_attributes, and
    `cnm vetting ask show|set --require/--optional/--purpose/--nothing`.
  - vta_sdk::openapi gains JoinManifest02RequestedAttribute, rendered from
    the specification's own schema by JSON pointer (`Name@<pointer>`),
    because the spec declares the item inline; admin-ui openapi.json and
    wire.ts regenerated.



### Fixed

- **sdk**: The vtc-host template advertises the REST base the VTC actually serves ([#1615](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1615))

Keyring finding VTI-15. A VTC's DID document published

      { "type": "VTCRest", "serviceEndpoint": "{URL}" }

  but `vtc-service` serves its API under `/v1`, so every request a client derived
  from the document answered 405. Its sibling `VTCStatusList` has always carried
  `{URL}{STATUS_LIST_PATH}`; `VTCRest` never got the equivalent.

  ## Why we never saw it

  Nothing in this workspace consumes a `VTCRest` entry — `rest_url_from_did_doc`
  looks for `vta-rest`. It exists for third parties, so a wrong value is invisible
  here and costs only the integrator who trusts it. Keyring found it for that
  reason, and it (with VTI-14, fixed in #1601) is why their repository carries its
  own admin client.

  That also corrects our remediation plan, which promised to "accept both forms on
  the resolver side for DIDs already minted". There is no resolver side to make
  tolerant.

  ## The fix

  `REST_PATH`, an optional template variable defaulting to `/v1`, exactly as
  `STATUS_LIST_PATH` already works — so a deployment serving the API elsewhere, or
  at the root (empty string), can say so. The VTC setup wizard already passes
  `URL` as the host base precisely to avoid a double `/v1` in the status-list
  endpoint; its comment now covers both variables.

  ## Already-minted communities

  A VTC's `did.jsonl` is write-once — it cannot re-sign its own log — so this
  fixes new communities only. An existing one needs a VTA-side `dids edit` to
  correct its `VTCRest` entry and a redelivered log. That is an operator action,
  not something code here can do for them.

  ## Tests

  The existing test pinned the bare URL; it now asserts `/v1` and says why, so the
  value is not quietly reverted. A new test covers the override and the empty
  root case, and that an empty `REST_PATH` leaves no trailing slash.

- **trust-tasks**: Name an upstream failure as one, not as an internal error ([#1609](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1609))

A `ServiceError` at 502/504 — a DID-hosting server or other peer that did
  not answer or refused — fell into the catch-all arm and went out as an
  opaque `internalError`. An openvtc join that failed because the hosting
  server's replies were refused by its mediator (`e.p.limits.queue.sender`)
  showed the user "internal error: the consumer could not complete this
  task", pointing at their own VTA.

  It now goes out as `taskFailed` with `details.reason` =
  `upstream_unavailable` and fixed text. The cause (peer, URL, its body)
  stays in the operator's log, as the framework requires. The SDK recovers
  the reason as `VtaError::Server { status: 502 }`, the variant REST
  already produces for the same failure.



## [0.46.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-sdk-v0.45.1...vta-sdk-v0.46.0) — 2026-09-21


### Added

- **persona**: Keep a pinned value through an edit, and let the holder purge it ([#1606](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1606))

Implements the retention half of trustoverip/dtgwg-trust-tasks-tf#538
  (design note docs/05-design-notes/persona-context-first.md §9.1).

  A pin ({ref, pinVersion}) is for the counterparty who verified a value
  and must keep being shown it -- after a name change, the bank that has
  not been told yet. The store did not keep the version an edit replaced,
  so a pin resolved stale from the first edit onward: pinning worked only
  until the one event it exists for.

  Retained by reference (new vta-persona `retention` module, `pav:` keys):
  - An edit keeps the version it replaces when a face pins it, and a pin
    is served from that copy.
  - A kept version is reaped the moment no face pins it (after profile put
    and delete); an edit nothing pins keeps nothing.
  - Deleting the attribute drops every kept version with it.
  - Attribute.retained_versions lists what is kept and the faces pinning
    it, on attribute/list; filled on read, never stored.
  - A face pinning a kept version still presents that value, so the
    correlation index counts it among what the face carries, and a face's
    own analysis treats such a pin as carried rather than as the live
    attribute.

  The holder's override: persona/attribute/purge-version/1.0 removes kept
  versions (named, or all), re-pushes and names every face that pinned one
  (stalePins). Those faces present the entry as stale -- never the current
  value, which the holder did not choose for that counterparty. The current
  version is refused (currentVersion); that is attribute/delete. New
  PersonaStore::purge_versions, VtaClient::persona_attribute_purge_version,
  `pnm persona attribute purge-version`.

  profile/put now refuses a pin to a version neither current nor kept with
  the spec's pinnedVersionUnavailable code, naming the pins, instead of
  storing a face that presents nothing for that entry.

- **persona**: Say which entry is a face's name — entry slots ([#1605](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1605))

* build: require trust-tasks-rs 0.21.8 for persona slots and kept versions

  0.21.8 publishes trustoverip/dtgwg-trust-tasks-tf#538: the optional
  ProfileEntry and ResolvedClaim `slot`, Attribute.retainedVersions, the
  duplicateSlot codes, and persona/attribute/purge-version/1.0.



## [0.45.1](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-sdk-v0.45.0...vta-sdk-v0.45.1) — 2026-09-21


### Fixed

- **sdk**: A task's declared `:notFound` is VtaError::NotFound ([#1602](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1602))

#1580 made the contexts family answer its specification's error codes,
  so a missing context now arrives as `vta/contexts/get:notFound`. The
  client recovered NotFound only from the `details.reason` marker, which
  those codes do not carry, so the rejection became a flat
  Protocol("trust task failed [vta/contexts/get:notFound]: …").

  Every Trust-Task caller that treats an absent context as a normal state
  -- look it up, create it if missing -- therefore failed instead. OpenVTC's
  community_context_e2e tests are the ones that caught it, on the bump to
  vta-sdk 0.45 (OpenVTC/openvtc#362). The same applies to app-state's and
  the persona family's declared :notFound.

  Match the local part `notFound` on any extended code, as the client
  already does for `transportUnavailable`. A different local code that
  merely contains the word (`parentNotFound`) stays a Protocol error.

- **sdk**: Honour an explicit --url on every transport, not only forced REST ([#1601](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1601))

Keyring finding VTI-14: pointing `cnm` at a host had no effect, because the
  community was resolved from the DID document instead. With VTI-15 this made
  the CLI unusable against their stack, and is why their repository carries its
  own admin client — an adoption cost, not just a bug.

  ## The cause is a layer below where it is felt

  The finding is filed against `cnm`'s vetting subcommands, and that is where an
  operator meets it: `vetting::connect` builds its `VtcClient` from
  `VtaClient::rest_url()`, so a discarded override sends it to the host the DID
  document advertises while the operator watches the host they named stay idle.

  But the discard happens in `session::connect_with_transport`. `url_override`
  was honoured on exactly two paths — forced `--transport rest`, and the
  priority-1 config `mediator_did` hint. The priority-2 path, which is what a
  DID with an advertised endpoint actually takes, destructured `rest_url` out of
  `resolve_vta_endpoint` and threaded that through, dropping `--url` on the
  floor. So this affected **every** authenticated command that later reads
  `rest_url()`, not only vetting.

  ## The fix, and what it deliberately does not do



## [0.45.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-sdk-v0.44.0...vta-sdk-v0.45.0) — 2026-09-21


### Added

- **persona**: Say who holds an old value, where an edit landed, and what a context may call a face ([#1597](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1597))
- **vtc**: Implement vtc/join-requests/supplement/0.1 — answer a deferral in place ([#1593](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1593))

Closes the second half of Keyring's KR-03, the one `join-requests/withdraw`
  ([#1591](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1591)) left open. A community that cannot decide a request on what it was
  given defers it and says what more it needs — and the applicant had nowhere to
  put the answer. The request stays open, the dedup guard refuses a second
  application, and the only exits were withdrawing (losing your place) or waiting
  for a retention sweep neither party controls. A deferral was a dead end dressed
  as a question.

  Spec'd upstream first (dtgwg-trust-tasks-tf #526, corrected by #531, shipped in
  trust-tasks-rs 0.21.6) and implemented here against the generated types.

  ## Submit and supplement now share one definition of every verdict effect

  `apply_verdict_to_request` is extracted out of `realize_join_verdict`, which
  could not be reused as-is because it opens with `JoinRequest::new` — it decides
  a request it is creating, and a supplement decides one that already exists. The
  extraction is the point rather than a tidy-up: an admission granted by a
  supplement must mean exactly what one granted by a submission means, and two
  copies of the effect table would eventually disagree.

  The response needs no such care because it is already shared —
  `outcome_to_verdict` and `verdict_response` are submit's, and a supplement's
  `{requestId, verdict}` *is* a submission's. A client reads both with one code
  path, which is why the spec chose that shape.

  ## Vetting travels in the presentation, and the first draft of the spec said otherwise

  `vetting_facts` reads attestations out of the VP's `verifiableCredential`
  array (`vetting_credentials(vp)`). The per-request `StoredVettingFacts` row
  looks like it contradicts that — it is keyed by request id and written on every
  submit — but nothing reads it into a decision: it serves the admin view, the
  vetter sweep, and tracing a withdrawn statement to the admissions it counted
  toward.

  So a supplement that omits the attestations is one with no vetting, and this
  implementation does not quietly carry the superseded ones forward. Doing so
  would decide the request on evidence the applicant is no longer presenting —
  the same defect as merging the two presentations, by a different route. #526
  asserted the opposite; I found it writing this code, and #531 corrected the
  specification.

  ## Other decisions

  **Only a deferred request.** A `Pending` one waits on the community, not the
  applicant; accepting evidence into it would replace what a maintainer is
  mid-review on, leaving the document they were reading no longer the one they
  were asked to decide. `notAwaitingEvidence`, with an annex naming the request.

  **An invitation presented now counts.** The policy re-runs over the whole new
  presentation, and a VIC in it is part of that presentation. Consumption routes
  through the extracted applier, so the burn happens once and on the same path a
  submission's does.

  **`JoinRequestSupplemented`, not `JoinRequestSubmitted`.** Nothing was
  submitted. Conflating them would make a community's audit trail report more
  applications than it received, and lose that an admission was granted on the
  second set of evidence. `AuditEvent` is `#[non_exhaustive]`, so additive.

  ## Tests

  Five, including a dispatcher-level one pinning all three spec-declared codes.
  The deferred-only guard was verified to fail its test when removed. The
  ownership test asserts the *rendered messages* of "not yours" and "does not
  exist" are equal, not merely that both refuse — equality is what makes the task
  useless as an id oracle.



### Fixed

- **vtc**: Name the open request when a duplicate submit is refused ([#1592](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1592))

Keyring finding KR-04, the other half of the withdraw work in #1591. When the
  dedup guard refuses a second application, the refusal now says *which* request
  is in the way and what state it is in, as a typed code with a machine-readable
  annex rather than English prose on a bare `taskFailed`.

  The applicant's actual question is "wait, or withdraw?", and it is not
  answerable without the status. A `pending` request is waiting on the community
  and will resolve on its own; a `deferred` one is waiting on the applicant, so
  "await its decision" is advice that would never come true. That is the position
  Keyring's applicants were left in.

  ## The code is consumer-minted, not a spec change

  `vtc/join-requests/submit` declares no code for this. SPEC.md §8.5 permits a
  consumer — not only the spec author — to mint a namespaced code for an
  invariant the specification did not enumerate, provided the namespace is the
  slug of the request being processed. The same section's fallback rule means a
  client that does not recognise the code reads it as `taskFailed`, so this is
  additive for every existing caller and needs no upstream round-trip.

  (#1591's body claimed this half was blocked on an upstream change. That was
  wrong — §8.5 covers it.)

  ## Why a typed refusal rather than a re-read

  `submit_inner` now returns `SubmitRefusal`, whose `AlreadyOpen` variant carries
  the request id and status the dedup guard already held at the moment it fired.
  The alternative — have the Trust Task handler re-read the open request to
  describe it — would race a concurrent decision on the very request being
  described, and would report a status that was never the one the guard matched.

  `From<SubmitRefusal> for AppError` is what keeps one wording for one refusal:
  the prose lives there, and the handler renders it through the conversion rather
  than restating it.

  Both live submit surfaces move together, and deliberately so. Submit is
  reachable only as a Trust Task — over HTTPS (`post_tt`) and over DIDComm — and
  both now carry the code, which is why the two existing dedup tests changed.
  Worth recording for whoever reads those test names: the one called
  `rest_submit_dedups_...` posts a Trust Task document over HTTPS, so "REST"
  there means the transport binding, not a flat-JSON route.

  There is a flat-JSON `routes::join_requests::submit::submit` handler that
  answers 409, and it is **not mounted on any router** — `read`, `manifest`,
  `decide` and `present` are registered in `routes/mod.rs`, submit is not. It
  is dead code, left alone here because deleting it is separate scope.

  `AppError` was the obvious place for this and is the wrong one: it is not
  `#[non_exhaustive]`, so a structured variant there would be a breaking change
  to published `vti-common` for a refusal that concerns one task.

  ## Tests



## [0.44.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-sdk-v0.43.1...vta-sdk-v0.44.0) — 2026-09-20


### Added

- **vtc**: Add vtc/join-requests/withdraw/0.1 — the applicant closes their own request ([#1591](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1591))

Keyring finding KR-03. An applicant could open a join request and then had no
  way to close it. A `deferred` request — the community answered `requestMore` —
  was the sharp case: it stays open forever, the dedup guard in `submit_inner`
  keeps matching the row so no resubmission is possible, and the only exit was
  to ask a community admin to reject it, which records the wrong outcome for
  what is actually the applicant changing their mind. Nothing but the retention
  sweeper ever closed it, on a schedule neither party controls.

  The task was spec'd upstream first (dtgwg-trust-tasks-tf #518, shipped in
  trust-tasks-rs 0.21.5) and is implemented here against the generated types.
  Payload, response and the `withdrawn` status all come from
  `trust_tasks_rs::specs::vtc::join_requests::withdraw` — never a local copy.

  ## Authorization is ownership, not membership

  An applicant holds neither a role nor a capability; that is what they are
  applying for. So the entitlement is that the proven caller is the applicant
  recorded on the request. `resolve_holder` supplies the proof — authcrypt
  sender on DIDComm, document proof signer on REST — exactly as `self-remove`
  does.

  ## The two refusals are shaped differently on purpose

    * A request that does not exist and one belonging to somebody else both
      answer `notFound`. Separating them would let a caller probe whether a
      given request id exists on this community — the same enumeration-
      resistance reasoning the vault read paths use.
    * An already-decided request answers `alreadyDecided`, because the applicant
      is entitled to the outcome of their own request and no retry changes it.

  Both go out as the extended codes the spec declares rather than through the
  generic `AppError` → reject mapping, which flattens `NotFound` and `Gone` into
  a bare `taskFailed` carrying only English. Telling "nothing to withdraw" apart
  from "already decided" without parsing prose is the whole reason the spec
  declares two codes, so a dispatcher-level test pins them.

  ## requestId is optional

  For the same reason it is optional on the status poll: an applicant whose
  submit response was lost never received one, and the id-less form is all they
  have. A supplied id is preferred over inferring from the caller, as the spec
  requires.

  ## Where the applicant's reason goes

  To the audit log, not onto the row. `JoinRequest` is a canonically-typed wire
  shape with no member for it, and `decision` means *refusal* — writing it there
  would make a withdrawn request read as rejected.
  `AuditEvent::JoinRequestWithdrawn` carries the reason alongside the previous
  status, and is the one join event whose actor and subject are the same party.
  `AuditEvent` is `#[non_exhaustive]`, so the new variant is additive.

  ## Also, partially, KR-04

  The same defect seen from the other side: the duplicate-submit `Conflict` said
  "withdraw or await its decision" while naming neither the status nor any
  withdraw mechanism. It now names both — `pending` is waiting on the community
  and will move on its own, `deferred` is waiting on the applicant and is the
  case this task exists for.

  KR-04's remaining half is not in this PR and needs an upstream change first:
  making that refusal a *typed* answer requires a `requestAlreadyOpen` code on
  `vtc/join-requests/submit`, which declares no such code today. Likewise the
  second half of KR-03 — letting a deferred applicant supplement the existing
  request rather than open a second one — is a task that does not exist yet.
  Both are follow-ups.

  ## Dependency

  The `trust-tasks-rs` workspace requirement moves 0.21.4 -> 0.21.5 because
  `vta-sdk` re-exports the generated module in its public API, so a consumer
  resolving 0.21.4 would not build. The three unrelated lines in Cargo.lock
  (`syn`, two `base64`) are pre-existing drift between the committed lock and
  what cargo resolves — any `cargo update` of any package rewrites them.

  A conformance witness is added in `trust_tasks/conformance.rs`, projected
  through the same generated builder the handler returns through rather than
  transcribed.

- **vta**: Report the subtree and the host copies a context delete could not remove ([#1577](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1577))

Takes trust-tasks 0.21.4, which added the two members the context-delete work
  needed and had nowhere to put (trustoverip/dtgwg-trust-tasks-tf#513).

  `subContexts` on `vta/contexts/preview-delete/1.0`. The preview already
  measured the subtree — #1576 made every array the union over it — but could
  not say which contexts those arrays covered, so both CLIs and the browser
  console each derived the list from `contexts/list` and matched paths
  themselves. Three copies of the agent's own cascade rule, none authoritative,
  in front of a destructive prompt. The agent decides what the cascade reaches;
  it now says so, and the consumers read it.

  `daemonCleanupErrors` on `vta/contexts/delete/1.0`. A DID whose hosting server
  would not confirm removing the published log left the deletion reported as a
  plain success, with the orphan visible only in the agent's own logs — which is
  the shape of the defect this whole change set started from. It is the
  subtree-wide form of the `daemonCleanupError` that `webvh/dids/delete/1.0`
  already reports for one DID, and both CLIs now print it after the deletion
  rather than letting a partial success read as a complete one.



### Fixed

- **tsp**: Take the SDK's re-establish fix and drop the local copy ([#1588](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1588))

#1582 worked around a race inside `TspOps::send_reestablishing`: its readiness
  read and its `SendInvite` are two separate awaits on the relationship store, and
  the peer can move our half between them — its own invite arrives, `None` +
  `ReceiveInvite` leaves us `InviteReceived`, and `SendInvite` is legal only from
  `None`. The refused invite took the payload down with it, and the D6 recovery
  reported a peer that "did not answer" a request it had never been sent.

  The workaround was a local copy of the SDK's three steps with the tolerance
  added. `affinidi-messaging-sdk` 0.26.12 (affinidi-tdk-rs#838) does that re-read
  itself, so `TspTransport::send_reestablishing` delegates again and the local
  `invite_refusal_is_benign` and its tests are gone — one owner for the decision
  rather than two that can drift.

  Two things this bump settles beyond the deletion:

  - **`vtc-service` is fixed by it.** Its registry client
    (`registry::messaging::send_tsp`) calls the SDK's form directly and never had
    the workaround. #1582 left it alone because the syncer's backoff — the one
    retry owner on that path — re-sent through the transient failure, so it
    self-healed on the next attempt. Now it does not fail in the first place.
  - **The requirement names the patch: `0.26.12`, not `0.26`.** Every
    `affinidi-messaging-sdk` requirement in the workspace moves, because on `^0.26`
    a lockfile resolving 0.26.11 would put the race back with nothing local left to
    catch it. A floor that is load-bearing rather than tidy.

  What stays from #1582 is the part the SDK cannot fix: `recover_send_tsp` telling
  `Timeout`, `Cancelled` and `SendFailed(reason)` apart instead of reporting all
  three as a silent peer, and the `AnsweringPeer` harness recording what it
  received and sent. That is what made the upstream defect readable in one CI run,
  and it is VTA-side either way.

  Design note `tsp-relationship-recovery.md` D6a updated to say where the fix now
  lives.

- **vtc**: Return the generated endorsement-type delete response, not a copy of it ([#1587](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1587))

`main` is red. #1584 renamed this route's hand-written response struct out
  of a three-way `DeleteResponse` collision and, in doing so, gave it a doc
  comment naming the task it restates — which is exactly what
  `vta-sdk/tests/generated_wire_types_census.rs` looks for. The type had
  been violating that census all along; it was invisible only because it
  carried no doc comment saying so.

  The census does not take new baseline entries, and it is right not to:
  `trust_tasks_rs::specs::vtc::endorsement_types::delete::v0_1::Response` is
  the published shape, and a local `{ typeUri }` beside it is a second
  definition that can drift. The handler now returns the generated type and
  builds it through its builder, so a response that does not match the
  schema is a construction error rather than a struct literal that compiles
  and lies.

- **resolver**: Take the shared DID resolver instead of building one ([#1581](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1581))

* fix(resolver): take the shared DID resolver instead of building one

  Twelve call sites across `vta-service`, `cnm-cli` and `vtc-service` each
  constructed their own `DIDCacheClient`. A client owns its cache, so the
  same DID was fetched once per construction rather than once per process,
  and a `did:webvh` host saw a burst of requests for what is one logical
  operation — enough to earn a 429 from its own rate limiter.

  Every one of them built
  `DIDCacheConfigBuilder::default().with_host_policy(webvh_host_policy())`,
  which is byte-for-byte what `build_did_cache_config(None)` produces, so
  taking `shared_did_resolver_from_env()` preserves behaviour and collapses
  twelve caches into the one the SDK already keeps per runtime, sidecar URL
  and host policy.

  It also fixes a second problem those sites had: by calling
  `DIDCacheClient::new` directly they never read `PNM_RESOLVER_URL`, so an
  operator who had configured a resolver sidecar — the documented mitigation
  for exactly this load — did not get it on any of these paths. The env var
  existed to spare the SDK's public API, and these call sites went around
  it.

  Three sites are deliberately left alone, and each looks convertible:

  - `vtc-service/src/server.rs` and `room-host/src/main.rs` build a plain
    default with no host policy. Converting them would add
    `webvh_host_policy()` and change which hosts are permitted — a
    security-relevant change, not a caching one, and not one to make inside
    this change.
  - `pnm-cli/src/bootstrap.rs` passes `None` on purpose. Bootstrap resolves
    the DID locally so the operator verifies the SCID and signed log on
    their own machine rather than trusting a sidecar; that `None` is the
    trust boundary, not an oversight.

  Adds the test that was missing for the property all of this now rests on:
  that two callers on one runtime get one resolver. Sharing could have
  broken and every converted site would have quietly gone back to a private
  cache with nothing failing.

  Reported as VTI-19 by the Keyring wallet team, who saw one command fetch
  `/.well-known/did.jsonl` forty times in five minutes.



## [0.43.1](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-sdk-v0.43.0...vta-sdk-v0.43.1) — 2026-09-18


### Fixed

- **trust-tasks**: Let the spine decide what an inbound document is ([#1567](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1567))

* fix(trust-tasks): let the spine decide what an inbound document is

  Authorization happened in each transport, before the spine saw the
  document. That defeated the ordering the spine documents and relies on --
  'a reply carries no authority and asks for nothing' -- because a reply
  was already refused at the door by the time the spine could recognise it
  as one.

  Under DIDComm the transport's own thid correlation hid it. Under TSP,
  whose binding has no request/response of its own, a DID hosting server's
  answer to a task the VTA had itself sent came back and was ACL-refused as
  though it were unsolicited. From the outside that reads as a missing ACL
  entry, and granting one would hand a peer standing to send requests when
  all it ever needed was to answer.

  A second failure was the same missing idea: an error document was
  dispatched as a request, failed validation, and was answered with another
  error -- which the peer then did too. Neither side recognised the other's
  error as terminal, so one failure became a permanent exchange that
  stopped only when the mediator began rate-limiting.

  So a transport now hands over two things, the document and the VID it
  proved, and makes no policy decision at all. accept_from_proven_sender
  asks what the document is and only then decides: an error is terminal and
  answered with nothing; a threaded document goes to its waiter if one
  holds that thread; everything else reaches the ACL as a request.

  Threading alone deliberately does not make a reply. A step-up
  approve-response and a task-consent/decision both thread to the request
  that provoked them and are still requests -- they carry the approval --
  so the waiter decides, and with nobody waiting the document falls through
  to the normal pipeline. Treating threading as proof would have stranded
  every ceremony waiting on a human.

- **budget**: Derive a client's Trust Task budget from the VTA's own timeout ([#1566](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1566))

A client's budget and the VTA's were two unrelated literals in two crates,
  and they inverted. create_did_webvh allowed 60s; the VTA, relaying the mint
  to a DID hosting server, spends up to TSP_REPLY_TIMEOUT_SECS on the first
  send and the same again on the 7.2.2 self-repair resend. Observed live:
  60.27s and 60.58s. The caller stopped listening a few hundred milliseconds
  before the real error arrived, on every attempt, so the operator saw a bare
  timeout and never the diagnosis.

  Neither number was wrong alone. What was missing was anything relating them,
  so nothing could notice they had crossed.

  vta-sdk gains a budget module holding the shared TSP_REPLY_TIMEOUT_SECS --
  vta-service now reads it instead of keeping a second copy that can drift --
  plus the derived floor and the list of tasks the VTA answers by calling a
  third party. dispatch_trust_task raises a relaying task's budget to clear
  that floor, at the one point every transport and every caller passes
  through, including consumers outside this workspace.

  The list is conservative: a task that relays under any payload is listed,
  because a URI cannot tell that services/enable is didcomm-kind or that a
  webvh DID is server-managed. Over-listing costs a slower report of a peer
  that is gone; under-listing costs the silent timeout this exists to prevent.

  create was not alone -- every webvh verb shipped at 30s or 60s, all below
  the floor, so delete, update, rotate-keys, register-with-server and the
  agent-name ops all carried the same latent inversion.



## [0.43.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-sdk-v0.42.1...vta-sdk-v0.43.0) — 2026-09-18


### Added

- **vtc**: A VTC provisioned from the v2 template issues hybrid credentials ([#1557](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1557))

* fix(did-templates): a key slot beyond the historical pair, and the literal it used to publish

  `slot_var`'s `{SLOT}_KEY_MB` rule is mechanical, and before this it was
  mechanical in one direction only. A `schemaVersion` 2 template could *declare* a
  third key slot — a post-quantum signing key beside the classical pair, which is
  the shape a hybrid-credential issuer needs — and then could not be loaded,
  because the placeholder that slot's own rule produces was rejected:

      Invalid("undeclared placeholder(s) { PQ_SIGNING_KEY_MB } in document
               — add them to requiredVars or optionalVars")

  Only `SIGNING_KEY_MB` and `KA_KEY_MB` were ambient, because only those two are
  in `RESERVED_VARS`. So `keys` at schemaVersion 2 ([#1530](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1530)) could express exactly
  the pair it was introduced to move beyond.

  ## Following the error's advice published a literal into a write-once log

  The advice is the defect. `optionalVars` supplies a **default**, and the
  renderer substitutes a default for any name the caller did not supply — and the
  minting flow does not supply a slot's key under a name it has never heard of.
  So declaring `PQ_SIGNING_KEY_MB` to get past the rejection passed validation
  *and rendered*:

      {
        "id": "did:webvh:x#key-2",
        "type": "Multikey",
        "publicKeyMultibase": "PLACEHOLDER-NEVER-SUBSTITUTED"
      }

  — inside `assertionMethod`, in a `did:webvh` log that is signed once and cannot
  be re-signed. `check_key_slots` already refuses a slot the document never
  publishes: a key minted and thrown away. This is the same failure wearing the
  other hat, a key published and never minted, and it arrived through the one door
  that check does not watch.

  ## What changes

  - `DidTemplate::slot_vars()` — the placeholder names the declared slots occupy,
    built from `key_slots()` rather than a second fixed list. For a v1 template it
    is exactly the two already in `RESERVED_VARS`, so v1 behaviour is untouched;
    it is what lets a v2 template name a third slot at all.
  - `check_placeholders_declared` treats those names as ambient. An author cannot
    declare a value they have no way to know.
  - `check_slot_vars_not_declared` refuses the reverse — a slot's placeholder in
    `requiredVars` or `optionalVars` — naming the slot and saying why. A v1
    template still gets `ReservedVar` from the check that runs first, unchanged.
  - An undeclared placeholder that is *shaped* like a slot's is told to declare a
    **slot**, not a variable. The generic advice pointed at exactly what the new
    check refuses; an error that recommends the defect is worse than no error.

  ## The state this leaves

  A third slot is expressible, and a VTA that cannot yet mint for it fails at
  render with `Unresolved` naming the placeholder — rather than emitting a
  document with a hole in it. Wiring derivation to the `keys` block is the next
  change; until then the loud failure is the correct one.

  Found while tracing what stands between a VTC and a second signing key: nothing
  in the chain from template to `LocalSigner::with_additional_key` could carry one.

- **sealed-transfer**: A template-bootstrap variant that can carry a second signing key ([#1556](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1556))

* fix(did-templates): a key slot beyond the historical pair, and the literal it used to publish

  `slot_var`'s `{SLOT}_KEY_MB` rule is mechanical, and before this it was
  mechanical in one direction only. A `schemaVersion` 2 template could *declare* a
  third key slot — a post-quantum signing key beside the classical pair, which is
  the shape a hybrid-credential issuer needs — and then could not be loaded,
  because the placeholder that slot's own rule produces was rejected:

      Invalid("undeclared placeholder(s) { PQ_SIGNING_KEY_MB } in document
               — add them to requiredVars or optionalVars")

  Only `SIGNING_KEY_MB` and `KA_KEY_MB` were ambient, because only those two are
  in `RESERVED_VARS`. So `keys` at schemaVersion 2 ([#1530](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1530)) could express exactly
  the pair it was introduced to move beyond.

  ## Following the error's advice published a literal into a write-once log

  The advice is the defect. `optionalVars` supplies a **default**, and the
  renderer substitutes a default for any name the caller did not supply — and the
  minting flow does not supply a slot's key under a name it has never heard of.
  So declaring `PQ_SIGNING_KEY_MB` to get past the rejection passed validation
  *and rendered*:

      {
        "id": "did:webvh:x#key-2",
        "type": "Multikey",
        "publicKeyMultibase": "PLACEHOLDER-NEVER-SUBSTITUTED"
      }

  — inside `assertionMethod`, in a `did:webvh` log that is signed once and cannot
  be re-signed. `check_key_slots` already refuses a slot the document never
  publishes: a key minted and thrown away. This is the same failure wearing the
  other hat, a key published and never minted, and it arrived through the one door
  that check does not watch.

  ## What changes

  - `DidTemplate::slot_vars()` — the placeholder names the declared slots occupy,
    built from `key_slots()` rather than a second fixed list. For a v1 template it
    is exactly the two already in `RESERVED_VARS`, so v1 behaviour is untouched;
    it is what lets a v2 template name a third slot at all.
  - `check_placeholders_declared` treats those names as ambient. An author cannot
    declare a value they have no way to know.
  - `check_slot_vars_not_declared` refuses the reverse — a slot's placeholder in
    `requiredVars` or `optionalVars` — naming the slot and saying why. A v1
    template still gets `ReservedVar` from the check that runs first, unchanged.
  - An undeclared placeholder that is *shaped* like a slot's is told to declare a
    **slot**, not a variable. The generic advice pointed at exactly what the new
    check refuses; an error that recommends the defect is worse than no error.

  ## The state this leaves

  A third slot is expressible, and a VTA that cannot yet mint for it fails at
  render with `Unresolved` naming the placeholder — rather than emitting a
  document with a hole in it. Wiring derivation to the `keys` block is the next
  change; until then the loud failure is the correct one.

  Found while tracing what stands between a VTC and a second signing key: nothing
  in the chain from template to `LocalSigner::with_additional_key` could carry one.



### Fixed

- **sealed-transfer**: A V1 bundle must still open, whatever its keys decode to ([#1561](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1561))

#1556 made the V1 -> V2 key-material lift **refuse** any key whose multicodec it
  could not classify, and argued for it: a key this build cannot classify is one it
  should not install. #1557 then pointed every runner at the V2 path.

  Together those apply the strictness to **every V1 bundle from every existing
  VTA** — rejecting, at open time, what the V1 path had always accepted, over a
  field the V1 path did not even have:

      WorkflowFailed("could not open returned bundle: sealed reply could not be
      decoded: key material for 'did:key:z6MkAdminMediator' carries a public key
      whose multicodec names no algorithm this build knows")

  This blocks the open Release PR ([#1552](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1552)), which is the only thing standing between
  `main` and a published `vta-sdk`.

  ## The reversal

  Each key's type now comes from its multicodec prefix when that classifies — the
  bytes are the ground truth about the bytes — and from what the V1 format
  **defines** the slot to be when it does not.

  That is not a default. `DidKeyMaterial` documents its two slots as an Ed25519
  signing keypair and an X25519 key-agreement keypair, and the format admits
  nothing else; "V1" *means* that pair. Reading the multicodec was only ever a
  cross-check on a format that already states the answer, and failing closed on it
  bought nothing:

  - Nobody acts on `key_type` for the classical pair. The consumer decodes the
    private half with its own explicit codec check
    (`VtcKeyBundle::ed25519_private_bytes`), so a mislabelled pair cannot reach a
    signer.
  - Refusing, by contrast, could fail provisioning outright for a bundle that
    worked yesterday.

  **An additional signing key is still never inferred.** Those exist only in a V2
  bundle, where the producer stated the algorithm outright — and there `key_type`
  *is* load-bearing, because it selects the cryptosuite. The inference is confined
  to the one place the format fixes the answer.

  ## How it was missed, which is the more useful half

  `cargo test -p vta-sdk --all-features` is a Feature combos step. It was not in
  the CI command list I worked from, so it was never run: `cargo test --workspace`
  takes default features and never compiles `provision_client_e2e` at all.
  `--all-features` was run for *clippy* only, which compiles the tests but does not
  execute them — so the regression was invisible to everything that did run.

  This is the trap CLAUDE.md and the PQC plan both name — "a feature-gated module
  is silently not compiled" — reached from the one angle neither spells out: the
  gate hiding a *test*, not a module.

  All fourteen Feature combos commands now pass locally, not just the two that
  failed.

- **did-templates**: A key slot beyond the historical pair, and the literal it used to publish ([#1554](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1554))

`slot_var`'s `{SLOT}_KEY_MB` rule is mechanical, and before this it was
  mechanical in one direction only. A `schemaVersion` 2 template could *declare* a
  third key slot — a post-quantum signing key beside the classical pair, which is
  the shape a hybrid-credential issuer needs — and then could not be loaded,
  because the placeholder that slot's own rule produces was rejected:

      Invalid("undeclared placeholder(s) { PQ_SIGNING_KEY_MB } in document
               — add them to requiredVars or optionalVars")

  Only `SIGNING_KEY_MB` and `KA_KEY_MB` were ambient, because only those two are
  in `RESERVED_VARS`. So `keys` at schemaVersion 2 ([#1530](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1530)) could express exactly
  the pair it was introduced to move beyond.

  ## Following the error's advice published a literal into a write-once log

  The advice is the defect. `optionalVars` supplies a **default**, and the
  renderer substitutes a default for any name the caller did not supply — and the
  minting flow does not supply a slot's key under a name it has never heard of.
  So declaring `PQ_SIGNING_KEY_MB` to get past the rejection passed validation
  *and rendered*:

      {
        "id": "did:webvh:x#key-2",
        "type": "Multikey",
        "publicKeyMultibase": "PLACEHOLDER-NEVER-SUBSTITUTED"
      }

  — inside `assertionMethod`, in a `did:webvh` log that is signed once and cannot
  be re-signed. `check_key_slots` already refuses a slot the document never
  publishes: a key minted and thrown away. This is the same failure wearing the
  other hat, a key published and never minted, and it arrived through the one door
  that check does not watch.

  ## What changes

  - `DidTemplate::slot_vars()` — the placeholder names the declared slots occupy,
    built from `key_slots()` rather than a second fixed list. For a v1 template it
    is exactly the two already in `RESERVED_VARS`, so v1 behaviour is untouched;
    it is what lets a v2 template name a third slot at all.
  - `check_placeholders_declared` treats those names as ambient. An author cannot
    declare a value they have no way to know.
  - `check_slot_vars_not_declared` refuses the reverse — a slot's placeholder in
    `requiredVars` or `optionalVars` — naming the slot and saying why. A v1
    template still gets `ReservedVar` from the check that runs first, unchanged.
  - An undeclared placeholder that is *shaped* like a slot's is told to declare a
    **slot**, not a variable. The generic advice pointed at exactly what the new
    check refuses; an error that recommends the defect is worse than no error.

  ## The state this leaves

  A third slot is expressible, and a VTA that cannot yet mint for it fails at
  render with `Unresolved` naming the placeholder — rather than emitting a
  document with a hole in it. Wiring derivation to the `keys` block is the next
  change; until then the loud failure is the correct one.

  Found while tracing what stands between a VTC and a second signing key: nothing
  in the chain from template to `LocalSigner::with_additional_key` could carry one.



## [0.42.1](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-sdk-v0.42.0...vta-sdk-v0.42.1) — 2026-09-17


### Added

- **vta-sdk**: Expose relate_tsp_trust_task_leg for the connect_auto + enable two-step ([#1547](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1547))

OpenVTC's `connect_auto` + `enable_tsp_trust_tasks` two-step attaches the TSP
  Trust-Task leg but has no public way to form the Rev 3 §7.2.2 relationship for
  it, so a Rev 3 VTA silently drops the consumer's first Trust Task. The only
  relate was `pub(crate) relate_trust_task_leg`, reachable only from inside the
  crate via `connect_didcomm_with_tsp` (which relates internally).

  Add a thin public wrapper, `relate_tsp_trust_task_leg`, over that existing
  idempotent (state-read guarded) internal relate. No behavior change: it forwards
  verbatim, so calling it after `enable_tsp_trust_tasks` forms the relationship,
  and it is a no-op when the Trust-Task surface is not on TSP.

- **vta-sdk**: A TSP client re-forms a dropped relationship and retries a safe task ([#1544](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1544))

TSP Rev 3 §7.2.2 is symmetric and silent: if the VTA loses its half of a
  relationship (idle eviction, key rotation, a fresh redeploy) it *drops* the
  peer's next frame with no reply. A fresh `pnm` process recovers on its own
  because it re-invites every run ([#1540](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1540)). A client whose relationship store still
  reads "related" — a long-lived process, or a durable store — never re-invites
  (`relate` short-circuits on the local state) and just times out, forever.

  This wires the client-side send-path self-repair — the first consumer of
  `affinidi-messaging-sdk`'s `reset_relationship` in this workspace, and design
  note `tsp-relationship-recovery.md`'s D4. `VtaClient::dispatch_trust_task` now
  treats a TSP reply-timeout as a possible §7.2.2 drop and, across all three leg
  shapes (pure, multiplexed, separate), re-forms the relationship — reset the
  local half to `None`, re-invite through the existing `relate` — leaning on D2's
  reconcile transition so the reset is safe even when the peer had not actually
  forgotten.

  The resend is gated on `vta_sdk::retry_safety`, because a §7.2.2 drop is
  indistinguishable from a lost reply and a blind resend is only safe when a second
  execution does no harm: a `ReadOnly`/`RetrySafe` task is resent once here; a
  `Keyed`/`KeyedSecret`/unknown task is *healed* (so the next attempt lands) but
  its resend is left to `VtaClient::idempotent`, the one retry owner that holds a
  stable key. So this never double-executes a mutation and never stacks a second
  retry loop on the idempotency one. It is the synchronous, per-call form — a
  single inline retry, no single-flight/backoff coordinator (that stays for the
  D6 outbox integration).

- **did-templates**: Clients carry a post-quantum template on the task version that can hold it ([#1542](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1542))

The last piece of Phase 2. A `keys` block now travels end to end: authored by an
  operator, sent on a task version that can express it, accepted by the VTA,
  minted with the right algorithm, recorded as what it is, published in the
  document, and read correctly by a verifier.

  ## The task version follows the template version

  `create` and `update` pick their URI from `template.schema_version` rather than
  always sending 3.0.

  Always sending 3.0 would break this client against every VTA deployed before
  3.0 existed, for templates those VTAs serve perfectly well. A `schemaVersion` 1
  template has nothing 2.0 cannot express, so demanding 3.0 buys nothing and costs
  compatibility. A `schemaVersion` 2 template genuinely cannot travel on 2.0, so
  demanding 3.0 turns a silent failure into `UnsupportedType` naming the version —
  and an older VTA could not mint the keys that template asks for either, so the
  refusal is the correct answer rather than an obstacle.

  Reads go to 3.0 unconditionally, because a 2.0 read now refuses to return a v2
  record: a client pinned to 2.0 could not see post-quantum templates at all.

  ## A gap #1538 left, closed here

  That PR's ceiling guarded what a caller could SEND and not what the service
  would RETURN. A `schemaVersion` 2 template fetched through a 2.0 read came back
  carrying a `keys` block, under a response schema that pins `schemaVersion` to
  `const: 1` and sets `additionalProperties: false` — the caller received a
  document its own specification says cannot exist.

  `list` refuses the whole listing rather than filtering. Quietly dropping v2
  templates would be worse than an error: an operator would see a list with the
  post-quantum templates missing and conclude they had never been created.

  ## Censuses, again

  `retry_safety` required the new URIs classified, and `ALL_URIS` required them
  registered before a classification was allowed to name them. Both are
  mechanical; recording them because the pair together is what stops a URI being
  served, retried or classified without the other two knowing.

  One e2e test failed correctly: its scripted responder answered `list/2.0` while
  the client had moved to 3.0, so it returned `no handler`. Moved, with a note —
  a future reader hitting that should find the reason rather than assume the
  responder is broken.

  Workspace and VTC suites clean; clippy clean under `-D warnings`; rustfmt clean.

- **did-templates**: The VTA accepts did-templates 3.0 alongside 2.0 ([#1538](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1538))

Registers `create`, `update`, `get` and `list` at 3.0 — the versions whose
  template schema can carry a `keys` block — and bumps `trust-tasks-rs` to 0.21.3,
  which is the release that publishes them.

  `delete` and `render` are deliberately absent. Neither carries a template shape,
  so neither gained a 3.0.

  ## Not a cutover, and not an ad-hoc dual-accept

  This surface's precedent is a clean cutover: the twelve 1.0 URIs were dropped in
  the change that introduced 2.0. That was right there — 1.0 carried two competing
  scope hierarchies, so keeping it meant keeping the ambiguity.

  It is wrong here. 2.0 has no defect; it simply cannot express a post-quantum
  template, and remains a correct way to manage a v1 one. A cutover would force
  every client to update in lockstep with the VTA for no safety gain.

  So this uses the mechanism the repository already has for exactly this:
  `SUPERSEDED_TASKS`. Both versions dispatch, a 2.0 response carries
  `supersededBy` so the caller learns where to go, and the usage counter lets
  removal wait on an observed zero rather than a guessed date. `every_dual_accepted_spec_marks_its_older_forms_superseded`
  already enforces the invariant I was otherwise about to assert by hand.

  ## The ceiling, which is the part nothing else would catch

  `parse_payload` is plain serde on a hand-rolled body type — there is no
  per-version schema validation at runtime, so the task URI is the ONLY thing
  carrying the spec version. Once 2.0 and 3.0 reach one handler they are
  indistinguishable inside it, and a 2.0 caller could send a `schemaVersion` 2
  template with a `keys` block that `vta/_shared/0.1` forbids by pinning
  `schemaVersion` to `const: 1`.

  That would leave this service quietly more permissive than the specification it
  publishes, and nothing would notice: the conformance fixtures check payload
  shapes, not which URI dispatched them.

  So the handler reads its own dispatching URI and holds the template to what that
  version can express. An unrecognised version gets the NARROW ceiling — defaulting
  permissive would mean a future version silently accepting templates it never
  promised to, invisibly.

  ## Three things the conformance census caught

  Worth recording, because each would have shipped:

  1. **Serving 3.0 URIs against a registry that did not know them.** VTI pinned
     `trust-tasks-rs` 0.21.1; the 3.0 specs are in 0.21.3.
  2. **A made-up spec URI in my own test fixture** — twice, including the bare
     stem, because the produced-URI census greps source for spec-URI literals. It
     is now derived from `TASK_DID_TEMPLATES_CREATE_3_0` by stripping the version,
     so no literal exists and the test survives the URI moving.
  3. **Four dispatched URIs with no witness.**

  On the third: the new witnesses carry a `schemaVersion` 2 template, not the
  existing v1 fixture. A 3.0 witness carrying a v1 template would pass while
  proving nothing about the `keys` block 3.0 exists for — and would keep passing if
  that block were dropped from the published schema. The fixture publishes both key
  slots, so it also exercises the rule that a declared slot whose placeholder never
  appears is refused.

  Workspace and VTC suites clean; clippy clean under `-D warnings`; rustfmt clean.



### Documentation

- Relocate root design notes into docs/, drop stray files ([#1541](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1541))

Move three design/review docs out of the workspace root into
  docs/05-design-notes/ where the rest of the design notes live:

  - sealed-bootstrap.md
  - phase5-cutover.md
  - AUDIT-TRAIL-REVIEW.md -> audit-trail-coverage-review.md (lowercase-kebab
    to match the directory convention)

  Update the four references to sealed-bootstrap.md accordingly (CLAUDE.md,
  docs/02-vta/cold-start.md, docs/05-design-notes/enterprise-fleet-management.md
  resolves same-dir, and the vta-sdk/src/sealed_transfer/mod.rs module comment).

  Remove affinidi-ai-agents-deck.html from the repo — it is a standalone
  presentation deck and now lives under ~/devel/publications/ with the other
  HTML decks. (tsp-rev3-relationships.html was untracked and moved there too;
  did.jsonl and .DS_Store were gitignored local artifacts, deleted from the
  working checkout.)

  No code behaviour changes.



### Fixed

- **vta-sdk**: The Auto connect path forms the TSP relationship it cannot reply without ([#1540](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1540))


## [0.42.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-sdk-v0.41.1...vta-sdk-v0.42.0) — 2026-09-17


### Added

- **keys**: An operator can create a post-quantum key, and see which axis it protects ([#1535](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1535))

Two gaps, one of which made everything upstream unusable in practice.

  ## `keys create` could not make a PQC key

  The VTA has been able to derive ML-DSA-44 and ML-DSA-65 since the BIP-32 work
  landed, and since the derived key started carrying its own algorithm it records
  them correctly too. But the CLI matched exactly three strings:

      "ed25519" | "x25519" | "p256" => ..., other => Err("unknown key type")

  So every post-quantum capability in the stack sat behind a front door that could
  not ask for it. `--key-type mldsa44` now works.

  `keys import` deliberately still refuses them, and says why. The VTA validates
  imported key material per algorithm and has no ML-DSA checker, so offering it
  here would take an operator's private key and fail at the far end. The refusal
  names the gap and points at `keys create`, rather than the generic "expected
  ed25519, x25519, or p256" — which reads as "no such algorithm" and would send
  someone looking in the wrong place.

  ## "Is this post-quantum?" has no single answer

  `QuantumPosture` makes that structural rather than a matter of remembering.
  Signature resistance and confidentiality resistance are separate facts, they
  migrate on different timetables, and today the second is false almost
  everywhere: an identity can sign with ML-DSA-44 while still agreeing keys with
  X25519.

  Collapsing those into one badge is wrong in the direction that matters. A reader
  shown "post-quantum" for such an identity has been told its recorded traffic is
  safe from harvest-now-decrypt-later, and it is not. So every label names its
  axis — `mldsa44 (post-quantum signing)`, `x25519 (classical key agreement)` —
  and a test holds them to it.

  There is deliberately no `PostQuantumKeyAgreement` variant. Nothing a DID
  document publishes can answer that axis affirmatively today: the hybrid KEM this
  stack uses lives in the TSP transport, not in a verification method. Adding the
  variant before that is true would let a renderer claim something nothing can do.

- **did-templates**: A template declares which algorithms its keys use ([#1530](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1530))

`schemaVersion` 2 adds a `keys` block: each slot says what it is for and which
  algorithms are acceptable, most preferred first.

      "keys": {
        "signing": { "purpose": "signing", "algorithms": ["mldsa44", "ed25519"] },
        "ka":      { "purpose": "keyAgreement", "algorithms": ["x25519"] }
      }

  A list rather than one algorithm because a fleet does not migrate atomically:
  this says *mint ML-DSA-44 if this VTA can, otherwise Ed25519*, so one template
  serves a VTA with post-quantum support and one without, and stops being a
  fallback the day the fleet finishes upgrading.

  ## v1 is v2 with the historical keys block

  The idea the whole change rests on. A `schemaVersion` 1 template has no `keys`
  block and is not thereby key-less — it means the pair this stack has always
  minted, which is exactly what its `{SIGNING_KEY_MB}` and `{KA_KEY_MB}`
  placeholders refer to. `DidTemplate::key_slots()` returns that, so a v1 and a v2
  template take one code path and raising `SCHEMA_VERSION_MAX` cannot change how a
  v1 template renders. A test asserts every built-in still declares exactly the
  Ed25519/X25519 pair, and fails by name when the default is perturbed.

  The slot-to-placeholder rule is mechanical — `{SLOT_UPPERCASE}_KEY_MB` — and was
  chosen so `signing` and `ka` produce the two names v1 already uses rather than
  being special-cased.

  ## What validation refuses, and why each would otherwise be silent

  - **A `keys` block on a v1 template.** Ignoring it means a template asking for
    ML-DSA gets Ed25519 without complaint — a deployment that believes it is
    post-quantum and is not.
  - **An empty algorithm list.** "No preference" would inherit whatever the
    implementation defaulted to, which is the same failure by another route.
  - **An algorithm that cannot serve its purpose** (X25519 signing, ML-DSA
    agreeing). The alternative is a well-formed DID document whose `keyAgreement`
    entry nothing can use.
  - **A declared slot the document never publishes.** The key is minted and not
    published, so every verifier still sees only the classical key while the
    operator believes otherwise — and a derivation path is consumed forever. This
    check caught this PR's own test fixture, which is the best argument for it.
  - **A slot placeholder no slot declares**, which would render as a literal.

  ## Breaking

  `DidTemplate` gains a field, so a struct literal no longer compiles — one
  conformance fixture in `vta-service`, fixed here. `DidTemplate` is deliberately
  NOT marked `#[non_exhaustive]`: that would break every external literal
  permanently to save one in-workspace call site, and templates are authored as
  JSON rather than built by hand.



### Fixed

- **proof**: A verification method's key type is read, not assumed ([#1528](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1528))

`TrustTaskVmResolver` ended both of its resolution paths with

      Ok(ResolvedKey::new(KeyType::Ed25519, bytes))

  regardless of what the DID document declared. That was never wrong, because
  every key this stack minted was Ed25519 — and it stops being true the moment a
  DID carries an ML-DSA key.

  The failure it produces is the bad kind. A PQC key is not rejected: it is
  extracted successfully and handed to the verifier **labelled Ed25519**, so
  "this proof uses a suite I must check differently" presents as "this Ed25519
  signature does not verify". That points an investigator at the signature, which
  is fine, rather than at the key, which is not. A hardcoded type cannot be wrong
  in a way anyone notices until it is wrong in a way nobody can debug.

  `get_public_key_bytes` cannot answer the question — it decodes the multikey and
  returns the payload, dropping the prefix that names the algorithm — so
  `declared_key_type` reads the `publicKeyMultibase` and matches its multicodec
  prefix against `KeyType::multicodec_public()`. That is this workspace's single
  codec table (VTI#1502), pinned against a named revision of the multicodec
  registry by affinidi-tdk-rs#798, so a wrong prefix is wrong in exactly one
  place and a test already says so.

  The match has no wildcard, deliberately. `#[non_exhaustive]` binds other
  crates, not the one defining the type, and this module is inside it — so adding
  a `KeyType` variant breaks this match on purpose, and whoever adds a key type
  is made to say how a verifier should read it rather than having it fall to a
  default. Defaulting is what caused this.

  ## The VTC half is a message, not a check

  `resolve_verifying_key`'s `[u8; 32]` coercion stays: that path builds an
  Ed25519 `VerifyingKey` and nothing else will do. What changed is what it says.

  "key is not 32 bytes" names the symptom and hides the cause. The realistic way
  to reach it is a verification method carrying a post-quantum key — ML-DSA-44 is
  1312 bytes, ML-DSA-65 is 1952 — and an operator reading "not 32 bytes" has
  every reason to suspect a truncated or corrupt key and none to suspect the
  algorithm. It now reports the actual length, names the likely algorithm, and
  says which path refused it.



## [0.41.1](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-sdk-v0.41.0...vta-sdk-v0.41.1) — 2026-09-16


### Fixed

- **vta-sdk**: A TSP client forms the relationship it cannot send without ([#1527](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1527))


## [0.41.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-sdk-v0.40.0...vta-sdk-v0.41.0) — 2026-09-16


### Added

- **backup**: Back up a DIDComm/TSP-only VTA with the chunkedTrustTask algorithm ([#1522](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1522))

* build(deps): trust-tasks-rs 0.21.1, the release carrying the chunked backup specs

  0.21.1 is the first release with `vta/backup/get-chunk/1.0`,
  `put-chunk/1.0`, `initiate-{export,import}/1.1` and
  `finalize-import/1.1` (trustoverip/dtgwg-trust-tasks-tf#474). A
  dispatched URI the registry has no schema for fails
  `every_served_uri_has_a_published_spec_or_is_tracked_debt`, so the floor
  moves with the tasks that need it.



### Fixed

- **webvh**: Refuse to delete a DID whose hosting server is unregistered ([#1518](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1518))

`dids delete` on a DID whose `server_id` was no longer registered deleted the
  local record and skipped the delete on the hosting server without reporting
  it. `get_server` returning `None` set no `daemon_cleanup_error`, so the published
  did.jsonl stayed live on the host, and the only credentials that could remove
  it (the record's mnemonic and the DID's keys) were deleted with the record.

  VTI R2.1 (Remote-First): no local commit before the remote effect. The deletion
  now refuses up front, before revoking or deleting anything, as a `Conflict`
  blocker on REST, DIDComm and TSP. The message names the fix: re-register the
  server with `servers add --id <id> --did <server-did>` and retry. The offline
  preview shows the same blocker. Serverless DIDs are unaffected.

  `vta did-mgmt dids delete --local-only` is the explicit opt-in for a host that
  is gone for good, where `servers add` cannot succeed because the server DID no
  longer resolves. It is honoured only for an unregistered server. For a
  registered or serverless DID it is refused. The result says the host copy
  remains. It is offline-only because the `vta/webvh/dids/delete/1.0` payload is
  generated from the specification with `additionalProperties: false`. An online
  opt-in needs a `localOnly` member in dtgwg-trust-tasks-tf first.

  `pnm did-mgmt dids delete` also discarded `daemonCleanupError`, the partial
  success the specification says a consumer MUST surface, because the SDK's
  `delete_did_webvh` returns `()`. The new
  `VtaClient::delete_did_webvh_with_outcome` returns the generated response type,
  and the CLI prints the warning.

  Library additions: `DeleteDidOptions`, `delete_did_webvh_with`,
  `plan_did_deletion_with`, and `MockVta::webvh_host_deletes`.



## [0.40.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-sdk-v0.39.0...vta-sdk-v0.40.0) — 2026-09-16


### Added

- **tsp**: Adopt Rev 3, and give a TSP session a way to form a relationship ([#1512](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1512))

* docs(tsp): inventory what Rev 3 costs this repository

  Trust Spanning Protocol Rev 3 changed the crypto mode, the version byte,
  the long count-code prefix, the ciphertext code and layout, the `-E`
  count's meaning, the signature code and every payload layout at once.
  There is no compatibility mode: nothing a Rev 2 peer packs can be
  unpacked by a Rev 3 one, in either direction. So the stack flips
  together, and this repository is the last part of it with no plan
  written down.

  The inventory was produced by reading the `tsp-rev3` branch of
  affinidi-tdk-rs against this repository's own call sites, so it names
  files rather than describing intentions. Three things worth knowing
  without reading it:

  **The functional change is one arm.** §7.2.2 says an endpoint SHOULD
  drop an application message from a VID it holds no relationship with,
  and the SDK gates on that by default. SDK 0.22's `unpack_message`
  returns an `InboundTsp` enum instead of a payload, and its `Control`
  variant is what `handle_tsp` has to grow: record the invite, then decide
  whether to accept it. `affinidi-messaging-didcomm-service`'s listener is
  a worked reference for the shape.

  **It fails silently.** A dropped message answers nothing, so a VTA that
  does not answer invites looks from every client like a transport that
  accepts connections and never replies. The wallet already sends the
  invite and waits five seconds before sending anyway, which means an
  unmigrated VTA that does not gate keeps working and one that does goes
  quiet — and neither state produces an error anyone can see. That is the
  reason this is written down before the work rather than during it.

  **There is an authorization decision to take.** Whether the VTA accepts
  an invite from any authenticated sender, or only from one the ACL
  already knows. The narrow reading breaks provisioning — a wallet talks
  to the VTA *in order to* be provisioned — so the broad one is almost
  certainly right, but it should be a decision rather than whatever the
  first implementer assumes.

  No code change. The work is blocked on an `affinidi-tdk` release
  carrying `affinidi-tsp` 0.2.0, and this workspace deliberately has no
  `[patch.crates-io]` to get ahead with — the note at the bottom of
  Cargo.toml records the duplicate-`vta-sdk` incident that removed it.

- **sdk**: Type rate-limit refusals and say who sent them ([#1511](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1511))

A 429 became VtaError::Other("429: Too Many Requests"), with no hint and
  the Retry-After header discarded; through the boxed session auth path it
  became VtaError::Auth, telling the operator to re-authenticate.

  Add VtaError::RateLimited { limited_by, retry_after, limiter, url } with a
  non_exhaustive RateLimitSource (Vta, Vtc, Mediator, DidHost, Upstream) read
  from the x-rate-limit-source header; an unlabelled 429 is Upstream (proxy,
  load balancer, or older VTA). Every VTA HTTP status mapping in the SDK now
  reads headers. idempotent retries a rate limit whose wait fits
  MAX_RETRY_AFTER and surfaces a longer one at once. The CLI renders who
  refused, how long to wait, and which knob to turn; every key name lives in
  vta_sdk::rate_limit.



### Fixed

- **backup**: Typed refusals for backup on a DIDComm/TSP-only VTA ([#1516](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1516))

The descriptor flow (`pnm backup export|import`) is REST-only: its
  `stream` algorithm moves the bytes over the VTA's HTTPS blob endpoint.
  A DIDComm/TSP-only VTA could not be backed up remotely, and every layer
  reported that badly.

  - SDK: `post_trust_task` refused DIDComm/TSP clients with `Validation`
    ("your request is wrong") although the same request succeeds over
    REST. It now returns `VtaError::UnsupportedTransport` naming
    `--transport rest`, as do `download_blob`/`upload_blob` when a client
    has no REST leg (their 429 → `RateLimited` mapping is unchanged). A
    DIDComm client's `rest_url` is still not used: it can come from the
    caller rather than from an advertised `VTARest` service, and the flow
    must not downgrade past what the peer advertises.
  - Server: a VTA with no `public_url` answered `initiate-*` with an opaque
    `internalError`, after already staging the bundle. It now refuses up
    front with the code `vta/backup/initiate-{export,import}/1.0` declare,
    `<slug>:transportUnavailable`, and the client maps that to
    `UnsupportedTransport`.
  - CLI: `--use-rest-legacy` on a DIDComm client silently sent the whole
    envelope as one mediator message (refused above 1 MiB, seen as a
    timeout). It now warns with the size caveat and `--transport rest`.
    Import no longer uploads the bytes twice: the commit finalizes the
    previewed bundle (new `VtaClient::backup_finalize_import`), and
    re-uploads only when the slot was already collected (not-found). A
    conflict is surfaced rather than retried, because it may mean "already
    committed" and commit is not idempotent.
  - retry_safety: initiate-export's reply carries the secret
    `transportToken`, not complete-export's; the classifications were
    swapped to match (initiate-export → KeyedSecret, complete-export →
    Keyed) so the token is never cached in the dedup store.
  - Docs: stale status line, non-existent offline `vta backup` command,
    the appstate note's claim that blobs work for DIDComm clients, the SDK
    "works on every transport" claim, and an operator note on backup for a
    DIDComm/TSP-only VTA. The planned transfer algorithm is renamed
    `chunkedTrustTask` (SPEC §4.10 casing) and specified upstream in
    trustoverip/dtgwg-trust-tasks-tf#474.



## [0.39.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-sdk-v0.38.2...vta-sdk-v0.39.0) — 2026-09-16


### Added

- **keys**: ML-DSA key types, and one codec table instead of two ([#1502](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1502))
- **vtc**: Verify a Trust Task's proof in the spine, where the bytes still exist ([#1501](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1501))

* feat(vtc): verify a Trust Task's proof in the spine, where the bytes still exist

  A proof covers the document as it was **sent**. `rooms/*` handlers verified it
  themselves, from the `TrustTask<Value>` they were handed — which works only
  while they are handed the document verbatim.

  They cannot keep doing that. Keying dispatch on the payload type hands a handler
  `TrustTask<P>`, and re-deriving the signed bytes from a parsed payload is sound
  only if `P` round-trips losslessly. None does: parse a document into a type that
  does not know one of its members and the member is gone, so the canonicalisation
  differs and a valid proof is refused. Pinned by
  `vta-sdk/tests/typed_proof_verify.rs`.

  So verification moves to `dispatch_trust_task_core`, which is the last point at
  which the received bytes exist, and the verified signer travels on
  `JoinAuthCtx`.

  ## Gated on the specification, so nothing existing moves

  The spine verifies when — and only when — `Payload::IS_PROOF_REQUIRED` says to,
  read through `schema_index::spec_policy_for` from the same generated bindings
  the schemas come from. That is framework §7.2 item 8 rather than a new rule, and
  it is a no-op for every task whose specification does not require a proof, so no
  request this service accepts today starts being refused.

  Two tests hold both halves: every `rooms/*` URI must declare the requirement
  (otherwise the handlers below would receive an empty presenter), and at least
  one dispatched task must *not*, or the condition would be indistinguishable from
  verifying unconditionally and the change would stop being additive.

  ## The rooms handlers keep invariant I5

  They take the verified signer and no context. That is not a weakening: a signer
  is a cryptographic fact about the request, not an authority this service
  confers. A room operation is still authorized by the authority chain the room
  itself issued — never by this service's ACL, roster or session.

  Ten call sites of `presenter_and_verifier` collapse to a synchronous, infallible
  call, and `handle_create`'s own verification block goes with them.

  ## The tests still prove what they proved

  A test that called a handler with a presenter of its own choosing would assert
  nothing about the signature — only that the handler uses the argument it was
  given. So the test module shadows each handler with a shim that verifies the
  document exactly as the spine does and passes the resulting signer. The call
  sites are untouched, and what they demonstrate is unchanged: the identity a room
  operation is authorized against is the one that signed the request.

  Rebased onto `main` after #1500 merged; `verify.rs` is identical to what landed
  there, so only this change remains.

- **sdk**: Verify a Trust Task proof against the typed document ([#1500](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1500))

`verify_trust_task_proof_with` took `&TrustTask<Value>`. That constrained
  nothing cryptographically — `eddsa-jcs-2022` canonicalises whatever serialises,
  and the payload's Rust shape is not part of the proof — while forcing every
  typed caller to convert first.

  The conversion is the hazard, not the cost. Re-serialising a document *before*
  checking its signature is the one step in the path that can change what was
  signed; `vta_sdk::tsp_binding::wrap_envelope` hand-rolls its JSON rather than
  reparse-and-reserialise for exactly this reason, on the carriage side.

  ## Why now

  Keying dispatch on the type (`trust_tasks_rs::AsyncDispatcher`, the mechanism
  chosen for the VTC/openvtc carriage work) hands a handler `TrustTask<P>`. Every
  proof-checking handler would then have had to round-trip back to `Value` purely
  to satisfy this signature — a mandatory reserialise, immediately before the
  signature check, in the part of the system where that is least acceptable.

  ## Scope



## [0.38.2](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-sdk-v0.38.1...vta-sdk-v0.38.2) — 2026-09-15


### Added

- **vtc**: Retry and discard a failed sync job from the console ([#1493](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1493))

The queue became visible in #1487 and comparable against the registry in #1489,
  and in both the answer to "so fix it" was: stop the daemon and run a CLI. The
  mutation could not be a route, because binding a `spec/vtc/registry/…` Trust
  Task URI ahead of its upstream specification is what `trust_task_manifest.rs`
  refuses.

  trustoverip/dtgwg-trust-tasks-tf#460 specified the family and trust-tasks-rs
  0.20.6 publishes it, so the four tasks bind and the buttons work:

  - `GET  /v1/registry/sync-jobs`         `…/sync-jobs/list/0.1`
  - `POST /v1/registry/sync-jobs/retry`   `…/sync-jobs/retry/0.1`
  - `POST /v1/registry/sync-jobs/discard` `…/sync-jobs/discard/0.1`
  - `GET  /v1/registry/records`           `…/records/list/0.1`

  The offline `vtc sync-jobs` CLI stays. It is the break-glass path for a daemon
  that will not start, which is exactly when an HTTP route is no use, and both
  surfaces go through `sync_jobs_cli::requeue` and the same eligibility rule, so
  "only a Failed row may move" is written once.

  Where the two deliberately differ is in how they refuse. Retry *reports* an
  ineligible row (`skipped`, with `notFailed` or `notFound`) rather than failing,
  so one row the reconciler picked up cannot defeat a bulk retry, and a job swept
  between the page load and the click is an ordinary race. Discard *raises*
  409/404, because the request names exactly one job and there is no partial
  outcome to describe. Bulk retry is `allFailed: true` rather than an omitted
  `jobId` — a client bug that drops the identifier must not become a bulk
  operation — and discard has no bulk form at all.

  Two census gates caught real defects on the way, both worth recording:

  - `generated_wire_types_census` rejected the two query structs I had written
    by hand. It was right: they restated `…/list/0.1`'s payload. The handlers now
    take the generated `Payload` as the `Query` extractor, and the OpenAPI
    parameters are declared inline rather than derived from a mirror.
  - `every_bound_published_uri_has_a_witness` required a conformance fixture per
    bound URI. Added four, transcribed from what the handlers build — including
    that a failed job carries no `nextAttemptAt`, because it has no schedule and
    claiming one would be the response asserting something untrue.

  Every `#[non_exhaustive]` generated enum is matched with an explicit refusal
  rather than a catch-all that guesses. A future spec release naming a fourth
  retry target must not be silently read as one of the existing two.



### Fixed

- **tsp**: Every client seals Trust Tasks in the binding envelope ([#1488](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1488))

#1478 gave the VTA's TSP receiver the published `trust-tasks-tsp` binding and
  cut the browser wallet over with it. Every Rust client kept sealing the bare
  document, so the VTA refused all of them:

      refused a TSP frame that is not a binding envelope
        reason=TSP payload is not a `…/binding/tsp/0.1/envelope` envelope
               (got `…/spec/messaging/ping/0.1`)

  A TSP trust ping, and `keys/export-secret/0.1` from openvtc, are the two that
  were reported; the cause is one missing call, in the send funnels every TSP
  client in this workspace goes through — `TspSession::send_document` (so
  `announce`, `request`, and the mobile approver), `DIDCommSession::
  send_tsp_document` (so `request_tsp`, so every `VtaClient` trust task on TSP),
  and the two `TspPingSession` probes behind `pnm health`.

  ## The binding is now one module, not one per crate



## [0.38.1](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-sdk-v0.38.0...vta-sdk-v0.38.1) — 2026-09-14


### Fixed

- **webvh**: Key records follow the document's verification-method ids, and a repair for the ones that don't ([#1466](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1466))

* fix(webvh): name a created DID's key records after the document it published

  A key record's id **is** a verification-method id. `save_entity_key_records`
  says so in its own name, and `vta_sdk::did_secrets::select_secret_kid` rule 1
  depends on it: the kid a mediator matches inbound JWE recipients against is the
  record id, on the reasoning that "the DID document decided what the key is
  called".

  Create never read the document to find out. It named the records `{did}#key-0`
  and `{did}#key-1` while the document was whatever the caller or the template
  said — and the `room` and `room-host` built-in templates number their methods
  from `#key-1`. So on every room and every room host this VTA has ever minted:

  - the document's `#key-1` is the **signing** key and the keystore's `#key-1` is
    the **x25519** one. One name, two keys, no error anywhere. Hand the id the
    document publishes to `keys/sign` — the natural thing to do, having read it
    off the document — and the oracle fetches an x25519 record for an EdDSA
    signature;
  - the document's `keyAgreement` (`#key-2`) matches no record at all, so an
    authcrypt message addressed to it finds no local secret. That is the storm.ws
    outage of #337 reached from the other side: there a decorative label
    overwrote the right kid, here the right kid was never stored;
  - `next_fragment_id` was stored as the constant 2, so the DID's first rotation
    allocates `#key-2` — over the id its key-agreement method is already
    published under.

  Room credentials still verify, which is why this stayed quiet: `RoomKeySigner`
  hardcodes `{room_did}#key-1` to match the template, and the public keys line up
  positionally, so the proof names a method that resolves to the key that signed
  it. Everything that addresses a key *by name* is what breaks.

  ## The fix reads the document rather than renumbering the templates

- **pnm-cli**: Anchor TEE bootstrap connect by DID and PCR0 ([#1454](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1454))

* fix(pnm-cli): anchor TEE bootstrap connect by DID and PCR0

  Add mutually exclusive --vta-did and --vta-url targets. Resolve WebVH locally without guessing a URL on failure, preserve the advertised REST endpoint, and reject credentials for a different VTA DID.

  Accept a pinned PCR0 as the online connect trust anchor without requiring the server-generated digest or an opt-out warning. Preserve explicit digest opt-out warnings, conflicting-flag errors, and mandatory offline digest verification.

  Add regression tests for target selection, strict endpoint resolution, credential identity checks, and anchor combinations. Update the PNM quick start and TEE bootstrap guide.



## [0.38.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-sdk-v0.37.0...vta-sdk-v0.38.0) — 2026-09-12


### Security

- **resolver**: Refuse did:webvh resolution to non-public hosts by default ([#1448](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1448))


## [0.37.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-sdk-v0.36.0...vta-sdk-v0.37.0) — 2026-09-10


### Security

- **keys**: Domain-separate the opaque signing oracle ([#1417](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1417))

The generic signing operation signs an octet string a caller supplies,
  under a key the caller names. Authorization bounds which key signs — by
  context, by the context's signable-keys policy, by the entry's own key
  narrowing — and says nothing about what the bytes will be taken to
  mean. A caller authorized to sign for one purpose could obtain a
  signature that verifies as something else: an assertion in another
  protocol, a token, a proof over a document the principal never saw.

  Payloads the VTA cannot parse are now framed under a domain tag before
  signing, so the signature verifies as a VTA opaque-signing payload and
  as nothing else. This does not make signing arbitrary bytes safe; it
  makes the result unusable outside the domain it was requested in.

  The domain is an argument rather than a blanket prefix because one
  caller must not be framed: the data-integrity proof signer builds bytes
  whose meaning its own specification has already established, and
  framing those again would produce a proof a conforming verifier
  rejects. Each call site now states which case it is in, and the two are
  not interchangeable.



## [0.35.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-sdk-v0.34.1...vta-sdk-v0.35.0) — 2026-09-09


### Added

- **rooms**: Cut over to present/0.2 and issue-authority/0.2 ([#1365](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1365))

The consuming half of trustoverip/dtgwg-trust-tasks-tf#415 and #418, unblocked
  by affinidi/affinidi-tdk-rs#784.

  `trust-tasks-rs` 0.19 carries both new spec versions, but this workspace could
  not take it: `affinidi-messaging-sdk 0.22.0` required 0.18, so pinning 0.19 put
  two `trust-tasks-rs` nodes in the graph and broke `vta-sdk` on `expected
  MediatorAcl, found a different MediatorAcl`. TDK #784 moved the messaging family
  to 0.19 and 0.23.0.

  Taking it exposed pins that had drifted apart underneath: `vta-sdk` was on
  messaging-sdk 0.22 while `vta-service` and the e2e tests were on 0.21, and three
  `trust-tasks-rs` versions were resolving at once. All of it is now consolidated:
  the lockfile holds exactly ONE `trust-tasks-rs` and ONE `affinidi-messaging-sdk`,
  where before it held three of each.

  `rooms/keys/present` 0.1 -> 0.2 and `rooms/owner/issue-authority` 0.1 -> 0.2.
  Both 0.1s are retired upstream. Neither is dual-accepted, deliberately: for
  `present`, 0.1's extra members are exactly the two nothing could honour; for
  `issue-authority`, accepting 0.1 means accepting a request with no `validUntil`,
  which is the thing 0.2 exists to refuse.

  The hand-rolled `validUntil` guard in `room_owner.rs` is deleted. 0.2 makes the
  member REQUIRED, so the generated payload types it as a `DateTime` and the
  envelope schema rejects a request without one before dispatch. Same rule, one
  layer up, which is where a shape constraint belongs.

  `every_witnessed_task_round_trips_through_its_generated_types` refused two
  witnesses that had been green for as long as they existed:

  1. The `issue-authority` witness carried no `validUntil` — a chain root with no
     expiry, the exact request 0.2 forbids, and one this service could have sent.
  2. The `present` witness carried `"audience": "did:key:z6MkHost"` — a HOST DID,
     the precise shape #414 reported as impossible to satisfy, since the field
     named the party that had to PRESENT the credential.

  `room_oracle` emitted `membership` and `authority[]` as JSON **objects**;
  `AuthorityPresentation` types both as strings, and the host's opener reads
  base64url or bare JSON text. So the oracle's output could not deserialize at a
  host at all — `rooms/keys/present` had never worked end to end. It went unseen
  because 0.1's response typed `presentation` as an opaque object; 0.2 names the
  shared component, which turned a runtime refusal nothing exercised into a type
  error. The oracle now serialises each credential. That is the first half of
  have caught all three of these years earlier.

- **sdk**: A no-I/O verifier resolves did:peer too ([#1364](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1364))
- **sdk**: The client verifies the replies it receives ([#1341](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1341))

Completes the arc #1334 and #1335 began. Both services sign their responses;
  until now nothing checked one, so the signature was decorative. This is the
  surface that matters most — the CLI, cierge and the services all dispatch
  Trust Tasks through `VtaClient`.

  A reply is bytes off a socket. Nothing else in this path establishes who
  produced them: the transport proves a connection, and over REST not even
  that beyond TLS to a host name. Without the proof an intermediary can
  rewrite an ACL listing, flip a policy decision, or answer for an agent that
  never spoke, and every check downstream passes — because the checks
  downstream are about shape.

  Two checks, and the second is the one easy to omit: the proof must verify,
  **and its proven signer must be the agent this client is talking to**. A
  proof by somebody else's key verifies perfectly well, so skipping the
  binding turns "signed by somebody" into "signed by the agent". The expected
  signer is `ClientIdentity::vta_did`, which the client already holds.

  A client with no identity does not verify, because there is nothing to bind
  against — such a client cannot produce a conforming request either and is
  refused at the agent for a missing `recipient`. A loopback client likewise:
  its sink answers ahead of the transport and returns a value rather than a
  signed document.

  Error documents are exempt, from the specification rather than for
  convenience: `trust-task-error`'s own proof requirement is RECOMMENDED
  (SPEC §8.1), so demanding one would make every conforming refusal
  unreadable, including the ones carrying the reason a caller needs.

  `trusting_unsigned_replies()` is a staging control, not a preference. An
  agent that predates #1334/#1335 sends nothing to verify, so a client
  upgraded ahead of its agent would refuse every answer; this exists so that
  ordering can be chosen rather than endured. It weakens the check to almost
  nothing while set — an attacker who can rewrite a reply can also strip its
  proof — so a present proof is still verified and still bound.

  The resolver is built once per client and shared by clones. A
  `DIDCacheClient` is a cache; one per call would defeat it.

- **persona**: Serve persona/facet — the holder's arrangement of their identity ([#1338](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1338))

Implements the three tasks specified in dtgwg-trust-tasks-tf#405, published
  in trust-tasks-rs 0.18.9.

  A holder who uses this model for a while ends up with twenty profiles, and a
  flat list of twenty is a list nobody reads. A facet is the arrangement over
  them — "Work", "Home", "Play" — and it is agent-scoped, like the pool and
  the profiles it groups.

  **An arrangement, not a container.** Nothing is stored inside a facet, and
  `delete_facet` touches no profile and no attribute. There is no cascading
  form because there is no cascading form of the idea: a grouping that could
  take its members with it is a folder, and a holder who reads it as a folder
  is right to be afraid of it. `releasedFaces` reports what now belongs
  nowhere, which is what a screen needs to say what it will look like
  afterwards. `deleting_a_facet_deletes_nothing_it_named` pins it.

  **Membership lives on the facet.** A `facet_id` on `Attribute` would be the
  obvious alternative and is the wrong shape: `attribute/put` REPLACES, and a
  well-behaved consumer does not hold the values it would have to resend —
  `attribute/list` withholds `sensitivity: high` plaintext unless asked by
  name. It would either request every sensitive value the holder owns to
  perform an arrangement that has nothing to do with values, or send a put
  without one and destroy them.



### Changed

- **sdk**: Move the Trust-Task proof verifier down from vti-common ([#1340](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1340))

Pure move plus re-exports; no behaviour changes. It exists so the next
  change can be small: `VtaClient` needs to verify the responses it receives,
  and the verifier it needs already exists one layer up where a client cannot
  reach it.

  `vti-common` was the right home while services verifying their *inbound*
  requests were the only consumer. A client verifying its *replies* is the
  same operation over the same document shape, and `vta-sdk` is the layer both
  can see.

  **The part worth not duplicating is the verification-method resolver.**
  Resolving one looks trivial and is not: a DID document may name its methods
  absolutely (`did:webvh:…:glenn#key-0`) or relatively (`#key-0`), while a
  proof always names them absolutely, so a resolver accepting only the
  spelling it expects refuses perfectly good documents from conforming peers.
  A second copy would drift, and drift in a verifier means refusing honest
  documents or accepting dishonest ones. Writing that copy is what this move
  avoids.

  Behind a new `proof-verify` feature rather than `client`, because
  `vti-common` takes `vta-sdk` with `default-features = false` and must not
  acquire reqwest to keep verifying. It adds no dependency to `vti-common` —
  that crate already depended on `affinidi-data-integrity` and the DID
  resolver directly. `client` enables it: a client that cannot verify its
  replies is the gap being closed.

  The resolver rides in the feature deliberately. Verification is only as good
  as the party it resolves — a `did:key` signer needs no I/O, and a
  `did:webvh` one, which is what a real agent is, cannot be verified without
  resolving its document.

  Call sites that used the module path (`vti_common::auth::di_proof::…`) now
  use the flat re-export, so there is one canonical path rather than an alias
  to go stale. Two doc comments naming the old location updated with them.

  `cargo clippy --workspace --all-targets` clean; `vta-service --lib` 1063
  passed; `vta-sdk` + `vti-common` suites pass, including the four resolver
  tests that moved with the code.



### Fixed

- **rooms**: A presentation is bound to its presenter — and dtg-credentials 0.6 → 0.9.1 ([#1356](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1356))

* fix(rooms): bind a presentation to its presenter, not to the host

  `pnm-cli rooms --host-did …` could never work. Every request it made was
  refused as `WrongAudience`, and omitting the flag "worked" only by
  skipping the check it exists to perform — so the flag's two states were
  broken and unprotected.

  `audience` is not who a presentation is addressed to.
  `dtg_credentials::authority::verify_chain` compares it to the PRESENTER —
  "the leaf must be presentable by whoever is presenting it" — so it is
  holder binding, and its whole job is to make a captured presentation
  worthless to whoever captured it. Filled with the host's DID it named a
  party no presenter can ever match.

  The value to bind to was already named a few lines away: `RoomSigner`'s
  doc says "a room request is signed by the party the presentation was
  minted for". This passes exactly that. There is no unbound case left, so
  the warning about one goes, and `--host-did` keeps its real job of naming
  the document's recipient.

  ## The spec says otherwise, and that is filed separately

  `rooms/keys/present/0.1` describes `audience` as "the party the
  presentation is for … a host's identifier, normally". The CLI implemented
  the spec faithfully; the spec and the credential library it runs on
  disagree, identically in dtg-credentials 0.6 and 0.7, so it is not
  version drift.

  This changes the CLI to match the verifier rather than the prose, because
  a presentation that cannot verify protects nobody while being wrong in
  the other direction. Which side should move is a working-group question —
  0.7's own notes point at upstream PR #41, "a key-control demonstration at
  invocation, which removes `audience` as redundant" — and is raised there.

  * fix(rooms)!: stop sending `audience` and `nonce` on rooms/keys/present

  Completes the previous commit, which repointed `audience` at the presenter so
  it would at least verify. It should not be sent at all, and neither should
  `nonce`. Both are removed from `rooms/keys/present` by spec 0.2.

  `audience` named the party that had to PRESENT a credential, not the one it was
  addressed to — so a host DID named somebody no presenter can ever be, and the
  host refused every request. That is now moot: dtg-credentials 0.8.0 removed the
  property and made the real rule explicit, which the VTA was already satisfying.
  The leaf grants to the DID this VTA authenticated, and a host refuses a chain
  whose leaf grants to anyone else. Who may present is established, not declared.

  `nonce` was written into the presentation object, which is closed and has no
  member for it — so a caller supplying one got a presentation the host rejects
  as malformed. It could not have been made to work: every signature in a
  presentation is an ISSUER's, never the presenter's, so a challenge inside it is
  unauthenticated and a replay copies it along with everything else. Freshness is
  the request's, via `issuedAt` and the duplicate-execution rule keyed on
  document `id`.

  ## A second live instance, found while doing this

  `rooms/keys/backfill` passed the caller-named host as the audience in
  `vta-service`, exactly as that spec's normative MUST instructed. Every backfill
  this VTA attempted was refused for the same reason. What actually makes a
  caller-named host safe is that the leaf grants to the VTA: naming a host
  transfers no standing. It does hand that host sight of the principal's
  credentials, which is a disclosure rather than an escalation, and the comment
  now says so.

  ## Nothing binds a presentation to a host, deliberately

  A chain is scoped to the ROOM. One rooted in a room confers nothing anywhere
  else, and any host serving that room would honour it — a room may have more
  than one host, and moving between them without reissuing credentials is the
  point. Binding a request to its destination is `recipient` on the document that
  carries the presentation, per SPEC.md §4.8.2, which its proof covers.

- **sdk**: A mock VTA has to sign, now that the client checks ([#1350](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1350))

* fix(sdk): the provisioning probe tolerates an unsigned reply again

  Main has been red since #1341 on
  `a_vta_on_the_previous_provision_version_is_named_before_minting`, and the
  test is right — the behaviour regressed.

  `verify_authorization` asks `trust-task-discovery/0.1` before anything is
  minted, and it is **a diagnostic, not a gate**. Its own module says why:
  refusing to provision a VTA that cannot answer it "would turn a diagnostic
  into an outage, which is the one way this module could be worse than not
  existing". Every failure of the probe is therefore swallowed into `Skipped`,
  except the two findings that name a concrete fix — no grant, and a version
  skew.

  #1341 added a new way for the probe to fail: the reply must now verify. That
  lands in the same catch-all, so an agent that does not sign its replies
  stopped producing *either* finding and produced "could not ask" instead. The
  skew then surfaced where it always used to — as a bare 404 from the mint
  call, naming the version the client wanted and never the one the VTA has,
  which is the exact failure this module was written to replace.

  `trusting_unsigned_replies` is the narrow tool for it, and it is #1341's own:
  a **present** proof is still verified and still bound to this VTA, so a
  rewritten reply is still refused. Only the *absence* of a proof is tolerated
  — which is what an agent predating #1334/#1335 sends, and precisely the case
  that method documents itself for. Every task that is not this advisory probe
  keeps the full check.

  A second test pins the half that matters: a reply carrying a **broken** proof
  must not steer the diagnostic. Without it the change reads exactly like
  "verification was turned off for the probe", and a forged task list would
  prove it had been.

  Also worth recording, because it is how this reached main green: `cargo test
  -p vta-sdk` runs 306 tests, the workspace run runs 741. The failing test is
  in the half a per-crate run does not compile, so "the vta-sdk suite is green"
  was true and insufficient.

  vta-sdk 741/741 under --all-features, and green under the default features CI
  actually runs. Clippy clean.

- **sdk**: The provisioning probe tolerates an unsigned reply again ([#1348](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1348))

Main has been red since #1341 on
  `a_vta_on_the_previous_provision_version_is_named_before_minting`, and the
  test is right — the behaviour regressed.

  `verify_authorization` asks `trust-task-discovery/0.1` before anything is
  minted, and it is **a diagnostic, not a gate**. Its own module says why:
  refusing to provision a VTA that cannot answer it "would turn a diagnostic
  into an outage, which is the one way this module could be worse than not
  existing". Every failure of the probe is therefore swallowed into `Skipped`,
  except the two findings that name a concrete fix — no grant, and a version
  skew.

  #1341 added a new way for the probe to fail: the reply must now verify. That
  lands in the same catch-all, so an agent that does not sign its replies
  stopped producing *either* finding and produced "could not ask" instead. The
  skew then surfaced where it always used to — as a bare 404 from the mint
  call, naming the version the client wanted and never the one the VTA has,
  which is the exact failure this module was written to replace.

  `trusting_unsigned_replies` is the narrow tool for it, and it is #1341's own:
  a **present** proof is still verified and still bound to this VTA, so a
  rewritten reply is still refused. Only the *absence* of a proof is tolerated
  — which is what an agent predating #1334/#1335 sends, and precisely the case
  that method documents itself for. Every task that is not this advisory probe
  keeps the full check.

  A second test pins the half that matters: a reply carrying a **broken** proof
  must not steer the diagnostic. Without it the change reads exactly like
  "verification was turned off for the probe", and a forged task list would
  prove it had been.

  Also worth recording, because it is how this reached main green: `cargo test
  -p vta-sdk` runs 306 tests, the workspace run runs 741. The failing test is
  in the half a per-crate run does not compile, so "the vta-sdk suite is green"
  was true and insufficient.

  vta-sdk 741/741 under --all-features, and green under the default features CI
  actually runs. Clippy clean.



## [0.34.1](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-sdk-v0.34.0...vta-sdk-v0.34.1) — 2026-09-08


### Added

- **rooms**: A VTA mints the credentials that make a room joinable ([#1329](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1329))

* feat(rooms): sign a room's credentials through the key oracle

  The seam the owner tasks need, and the one design question scoping this work
  flagged as its biggest unknown: how a VTA signs AS a room without holding the
  room's key in a way that breaks the property the rooms family rests on.

- **rooms**: The VTA seals records and lists the rooms it can open ([#1326](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1326))

* feat(rooms): the VTA seals records and lists the rooms it can open

  Implements rooms/keys/seal/0.1 and rooms/keys/list/0.1
  (dtgwg-trust-tasks-tf#399), which are the two gaps that made a room UI
  impossible.

  ## seal — the mirror of open

  A client could read a sealed room and not write to one, because sealing needs
  the epoch's storage key and the key never leaves the VTA. Plaintext in,
  ciphertext out.

  It does not write, and does not reach the room's host. The caller presents its
  own authority there. Sealing and being allowed to store are different questions
  asked of different parties — this VTA knows the key and nothing about the room's
  ACL; the host knows the credentials and cannot read a byte. Doing both here
  would make the VTA the party that decides what a room contains.

  ## list — where a roomId comes from

  Every other room task took an identifier the caller already knew.

  It restores each group to answer rather than reading the epoch out of the
  snapshot, because `earliestReadableEpoch` is only knowable by *walking* the
  chain — and a number derived two different ways is a number that will eventually
  disagree with itself.

  Custody, not membership: a room whose Welcome never arrived is absent even where
  a good VMC is held, and a VTA not yet told of a removal still lists a room it can
  open but can no longer write to. A caller MUST NOT read it as authority.

  ## Six census sites, located before writing any code

  The URI constants, ALL_URIS, retry_safety, dispatch, the conformance witnesses,
  and the vta-mcp guard. The last is invisible to a
  `grep TASK_ROOMS_KEYS_CHAIN_0_1` sweep because it classifies by SLUG — which is
  exactly how it was missed on #1320, so it was checked by name this time.

  `seal` is Sensitive there, beside `open`: it is the same exchange run the other
  way, and the one direction where cleartext room material travels INTO the
  oracle. `list` is ReadOnly, named rather than defaulted because what it returns
  is the principal's room membership as key custody sees it.

  trust-tasks-rs moves 0.18.6 → 0.18.7.

- **rooms**: A joined member's agent can read the room's history ([#1320](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1320))

* feat(rooms): a joined member's agent can read the room's history

  The last leg. `rooms/epoch/chain` ([#1314](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1314)) gets the rungs from the room's host to
  the member; this is `rooms/keys/chain/0.1`, which gets them from the member into
  their own VTA — the party that actually opens records for their agent.

  Until now a member who joined read the room's history in their client and their
  agent did not: `rooms/keys/open` resolves from the chain the VTA accrued by
  applying commits, and a joiner's was empty.

  ## The response is the interesting part

  `earliestReadableEpoch` is not a count of what arrived. A rung extends reach only
  if every rung above it is present too, so the number worth returning is the one
  this VTA can only get by walking what it holds. A host serving the same rungs
  could not have answered it — which is why the specification puts it here.

  A rung already held is never replaced, so a redelivery stores nothing and
  reports the same reachability. That is why it is `RetrySafe`.

  ## Five censuses

  Adding a task to `vta-service` owes all of them, and they were done up front
  rather than one CI run at a time: the URI constant, `ALL_URIS`, `retry_safety`,
  dispatch, and the conformance witness. No `vta-mcp` guard verb — this is
  inbound from the principal, like `commit` and `welcome`, not an agent-facing
  verb.

  An epoch outside `u32` is refused rather than saturated: clamping it to
  `u32::MAX` would store a rung under an epoch nobody will ever ask for, which is
  a delivery that reports success and extends nothing.

  trust-tasks-rs moves 0.18.5 → 0.18.6, the release carrying the spec.

- **auth/step-up**: Record a bound approval without elevating the session ([#1316](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1316))

* feat(auth/step-up): record a bound approval without elevating the session

  Closes the compromise #1304 stated and could not avoid: a `release: stepUp`
  approval marked the preview it was bound to AND raised the session's assurance,
  because 0.2's acknowledgement has exactly two statuses — `elevated` was untrue
  and `rejected` was worse, since the approval had been applied.

- **persona**: Serve the claim-type registry ([#1315](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1315))

* feat(persona): serve the claim-type registry

  The agent side of trust-tasks #390, now that trust-tasks-rs 0.18.5 is
  published. Bumps the pin and implements `persona/claim-types/list/1.0`.

  Served from `vta_persona::claim_types` — the same REGISTRY and UNREGISTERED
  that `defaults_for` resolves through — because the task's central MUST is that
  a maintainer serves the table it actually applies. A served table that differs
  from the enforced one is worse than serving nothing: a client would mask and
  gate by one rule while the agent disclosed by another, and nothing would report
  it. The end-to-end test asserts that behaviourally, not by comparison: the
  agent serves `payment.card: stepUp` and then refuses a `payment.card`
  disclosure for want of one.

  `strictness` is carried because §4 rule 3 is not computable without it. The
  orderings come from new MOST_PROTECTIVE_FIRST constants, which are hand-written
  — Rust cannot enumerate variants — so a unit test asserts each agrees with
  `Ord`, the ordering the module actually resolves by. A disagreement would be
  silent and served to every client as the rule.

  `minimumSet` and `oidc` are omitted: both optional, and this agent's table does
  not carry them. Transcribing them at the serving layer would be a second copy
  of data nothing here resolves against.

- **sdk**: Open the rotated DID's mediator account over TSP too ([#1312](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1312))

#1309 left the mediator-account pass DIDComm-only and documented why: the
  mediator's management dispatch (`MessageType::process` →
  `trust_tasks::process`) was `#[cfg(feature = "didcomm")]` and took a
  DIDComm `Message`, so a TSP message addressed to it was filed for pickup
  rather than answered. There was no packet a TSP-only client could send to
  set its own account ACL, over any transport.

  affinidi-tdk-rs#783 added the TSP wrapper. This is its client half, and
  it makes that documented limitation false — which is the point, since it
  would otherwise have quietly outlived the constraint that justified it.

  `acl_setup` gains `set_client_acl_over_tsp`, sending the same
  `messaging/account/update/0.1` task as a TSP Direct message addressed to
  the mediator. Same task, same allow-all ACL, same account key
  (`sha256(did)`), so whichever arm runs the account ends up authorised for
  both transports — the mediator keys its ACL on the DID, not the protocol.

  `rotate_key_over_client` now routes the pass by transport instead of
  skipping:

  - DIDComm available, including dual-transport → the DIDComm arm. It is
    what every deployed mediator understands, so on a VTA offering both it
    is the one certain to be acted on.
  - TSP-only → the TSP arm. Previously skipped, because it had to be.

  Two things it deliberately does not do.

  It never claims delivery. A TSP send resolving `Ok` means the mediator
  accepted the frame, not that it applied the ACL (R1.1), and a mediator
  predating #783 files it silently. The success log says what was *sent*,
  with delivery unconfirmed; a guard asserts the word "opened" never
  appears there.

  It does not wait for a reply. The mediator applies the ACL before
  responding, so a reply carries no information — the same reasoning that
  makes the DIDComm arm log its errors rather than propagate them — while
  waiting for one would stall for the full timeout against a mediator that
  is never going to send it. Against such a mediator this degrades to
  exactly the previous behaviour: the account keeps the `global_acl_default`
  it was created with at authentication.

  Also declares `dep:uuid` on the `acl-setup` feature. It was compiling
  only because another enabled feature happened to supply it, which builds
  in the workspace and fails under `cargo publish`'s isolated verification
  — a class this workspace has been bitten by before.

  Verified across all four relevant feature combinations rather than
  `--all-features` alone. A helper whose only caller sits behind a `cfg` is
  live in one build and dead in the other, and testing the first says
  nothing about the second; that exact miss failed CI on the mediator side
  of this pair an hour earlier.

  Not covered end-to-end: the workspace's transitive test-mediator is
  pinned at 0.20.11 and the TSP management arm ships in 0.22.3, so there is
  no live mediator here to exercise it against yet. The guards pin the
  routing and the honesty of the logging, not the wire exchange.

- **sdk**: One key rotation for every transport, TSP included ([#1309](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1309))

* feat(sdk): one key rotation for every transport, TSP included

  A `needs_rotation` session on a TSP-only VTA could never retire its temp
  did:key: rotation ran over DIDComm, and a VTA that advertises only `#tsp`
  has no DIDComm mediator to run it on. The cold-start temp DID is meant to
  be short-lived, so it stayed indefinitely.

  `acl/swap-key/0.1` is a dispatched Trust Task, and TSP carries the
  Trust-Task surface, so the VTA could already service this — TSP inbound
  reaches `dispatch_trust_task_core`, the same spine DIDComm uses. The gap
  was entirely client-side. Rather than add a third rotation path, this
  collapses the two that existed into one: `rotate_key_over_client` issues
  the swap through whatever transport the client holds, so REST, DIDComm
  and TSP share an implementation and TSP comes free.

  That also closes a divergence. REST rotated with the atomic
  `acl/swap-key`; DIDComm used create-then-delete, minting an entry for the
  new DID while the temp still held the same grant — the over-privilege
  window `acl/swap-key` exists to avoid. The old code said so in a comment
  and deferred it. One entry now exists at every instant.

  What the swap cannot prove is that the new DID can *reach* its mediator,
  and a rotation that commits to an unreachable DID is unrecoverable: the
  temp entry is gone. So the new DID is probed first, while a failure is
  still free. Two things kept separate there, because conflating them is a
  bug:

  - **Reachability** is proven over the transport the caller reconnects on.
    A DIDComm trust-ping against a TSP-only mediator proves the wrong thing
    and fails outright, which would have refused good DIDs on exactly the
    deployments this change is for. The TSP arm probes with
    `TspPingSession`.
  - **The mediator account** is keyed on `sha256(did)` rather than a
    protocol, so one pass authorises both transports — but it is issued
    through the ATM, so it needs a DIDComm mediator and is attempted only
    where one exists. Always best-effort: a closed account costs a dropped
    forwarded reply on the next connect, never a credential.

  Fatality follows need. A REST client never touches the mediator, so
  failing its rotation on one would make `--transport rest` depend on
  DIDComm infrastructure it does not use; there the probe is best-effort.

  Transport selection follows the workspace order — TSP where advertised,
  else DIDComm, else REST — so a dual-transport VTA rotates over TSP.

  Eight source-level guards pin the ordering and the transport matching,
  which live across several functions with nothing type-level holding them.
  They read this file's own source, truncated at the test module so a guard
  cannot match its own string literal. Six were mutation-checked to fail on
  exactly the regression they target; the seventh is redundant with the
  type system, which rejects the substitution outright.

  `docs/02-vta/cold-start.md` described the create-then-delete flow, which
  was already wrong for REST before this change.

  No public API changes: every function this touches is private, and
  `SessionStore::ensure_authenticated{,_didcomm}` and
  `connect_with_transport` keep their signatures. `cargo semver-checks`
  against the merge base reports no required update.



### Documentation

- **persona**: Say "attribute" on screen, not "fact" ([#1319](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1319))

`design-docs/persona-vocabulary.md` translated `attribute` to **fact** for
  everything a person reads. That was wrong in two independent ways.

  It asserts what the model cannot promise. What a holder keeps in the pool is
  self-asserted until a credential backs it, and a face exists so a person can
  choose what to show — an old value, a pinned version, a value overridden for one
  context, or a value that is simply not true. The step-up card said "Approve
  disclosing 1 fact" about exactly that.

  And the word was already spent: `fact` is the VTC ceremony engine's term for a
  *verified* policy input (`vtc-service/src/ceremony/facts.rs`, `Facts` assembly,
  every `.rego`) — very nearly the opposite meaning, in the same product.

  `detail` is the persona audit envelope's own field, `trait` is a keyword,
  `entry` names an entry in a face and `value` is the field inside an attribute,
  so the spec word comes to the screen instead and that row stops translating.
  Truth is carried by the provenance beneath the value, never by the noun.

  - step-up approval card: "1 fact" → "1 attribute" (the string an approver reads
    on their phone)
  - `pnm persona …` help text and `vta-cli-common` printed output: "Your facts:"
    → "Your attributes:", "Fact:" → "Attribute:", and the surrounding guidance
  - `vta-persona` doc comments that define the model in the old word

  Commands, flags, task URIs and wire records are untouched — they always said
  `attribute`. Nothing in `vtc-service/src/ceremony/` is touched; that `Facts` is
  the other meaning.

  vta-persona 88 tests and vta-service persona_trust_task 23 tests pass.



### Fixed

- **sdk**: Finish the rotation test's migration to the Trust-Task binding ([#1313](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1313))

main has been red since #1309, whose own Feature combos failed before it merged.
  Every PR opened since inherits it.

  #1309 moved rotation off a hand-rolled `POST /acl/swap` onto the dispatched
  `acl/swap-key`, and the test file's header already describes that world — but
  one of its four stubs never moved. The request went to an unmocked path and
  404'd.

  Two halves, and the second is why a permissive mock would have been worse than
  the red: the response shape also changed, because `AclEntryResponse` renames
  `subject` to `did` and `scopes` to `allowed_contexts`, so a stub written from
  the Rust field names decodes to "missing field `subject`". A mock matched on the
  path alone would have gone green while exercising neither half. This one matches
  on the document `type` and `payload.currentSubject`, as the correctly-migrated
  `config/show` stub in the same file already does.

  Both halves probed: pointing the matcher at another task type fails, and using
  the old REST field names fails. 24 passed, 0 failed.

- **sdk**: A bare key whose first bytes spell a multicodec prefix is not truncated ([#1308](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1308))

Both key decoders accept two encodings — a 2-byte multicodec prefix followed by
  32 key bytes, or 32 bare key bytes — and told them apart by looking at the
  leading bytes. A bare key is free to begin with any two bytes at all, including
  a prefix's, so such a key had its first two stripped and arrived as 30:
  `InvalidSeedLength`, for a key that was perfectly valid.

  For randomly generated keys that is 3 chances in 65536 (0x8026 Ed25519, 0x8226
  X25519, 0x8626 P256, plus 0xed01 on the public side) — rare enough to read as
  noise, frequent enough to fail CI. It did, on room-host's
  `a_member_without_a_nomination_cannot_claim`, which is what surfaced it. That
  test's fixture is not at fault: it encodes a bare seed, which both functions
  document as supported.

  Length is the only sound disambiguator, because the leading bytes carry no
  information a bare key is obliged to respect. A prefix is stripped only from a
  34-byte input.

  Both directions are pinned. Two tests fail without this change; two more pass
  with or without it and exist to stop the wrong fix — simply not stripping would
  satisfy the first pair and break every real caller.

  These are public `vta-sdk` functions, so the exposure was never limited to the
  test fixture: any caller storing a bare key could hit it.



## [0.34.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-sdk-v0.33.0...vta-sdk-v0.34.0) — 2026-09-07


### Added

- **rooms**: A member's CLI surface, driven through the oracle ([#1285](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1285))

Rooms had no CLI. Using one meant writing Rust against `vtc-client` or hand-
  building signed Trust Task documents, which is not a surface an operator has.
  `pnm rooms {create,list,get,put,curate,renew}` is that surface for a member.

  ## Two parties, never confused

  Every command talks to both and keeps them apart: the operator's **VTA** mints
  a presentation (`rooms/keys/present`) and opens sealed records
  (`rooms/keys/open`), and the room's **host** stores the bytes. The credentials
  the presentation is derived from and the group key that opens a record stay
  inside the VTA - this CLI holds neither at any point.

  That makes the CLI the oracle's first real consumer, and it works: a member
  who holds less than an action needs is refused by their own VTA, before
  anything reaches the host, which is the earlier and clearer of the two
  refusals.

  Each command mints its own presentation for exactly the action it performs -
  `read` for list/get, `write` for put, `curate` for curate, `admin` for renew.
  Caching one across commands would mean re-binding it (impossible without the
  VTA) or sending it unbound, which is a bearer token.

  ## Where the pieces had to live

  `vta-sdk` gains `room_present` / `room_open`, because those are calls to your
  own VTA. It cannot gain the room *wire types*: `vti-common` re-exports
  `vta_sdk::acl`, so `vta-sdk -> vti-rooms -> vti-common -> vta-sdk` is a cycle.
  So `vta-cli-common` takes `vtc-client`, which despite its name is the
  host-neutral room client - `room-host`'s own example drives itself with it. A
  second copy of the `rooms/*` wire types in the CLI is exactly the duplication
  that crate deleted.

  `vtc-client` gains `curate_record`, which nothing had implemented.

  ## What it deliberately cannot do

  **Write to a sealed room**: sealing needs the room's group key, and no task
  seals on a caller's behalf. **Issue credentials**: minting a VIC, VMC or VAC
  needs the room's own signing key, which is the owner's - a different party with
  different custody. Both are refused with the reason rather than half-served,
  and `get` translates the epoch-mismatch failure into "a commit has not been
  delivered", which is what it means and not what it reads like.

  Five tests on the two pure decisions: rebuilding a session from what the VTA
  minted (each missing member refused rather than defaulted, a subject binding
  surviving, a non-string chain link refused rather than silently shortening the
  chain), and the pin/unpin tri-state where absence must stay distinct from
  false.

- **acl**: Create an entry already narrowed, rather than narrowing it after ([#1280](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1280))

#1279 left `acl/grant` refusing a capability narrowing and pointing at
  `acl update`, because taking one meant a fifteenth positional parameter on
  `create_acl`. Refusing was honest but it leaves a real window: between the
  grant and the narrowing the entry holds everything its role implies, and a
  subject that authenticates inside that window is authorized by what it found
  there.

  `create_acl` now takes a `CreateAclParams` struct - the shape `update_acl`
  already had - so the narrowing is one more named field rather than a
  fourteenth argument nobody can read at the call site. Test call sites state
  the two or three members they care about and default the rest instead of
  spelling every one to reach the last.

  The rule is the update path's, applied where the entry is born: a name the
  role does not carry is refused rather than dropped, an unknown name is
  refused, and neither leaves a row behind. `pnm acl create --capabilities
  memory-read,room-present` is now the form to prefer, and the agent runbook
  says so.

  Also echoes the stored narrowing from `acl create` and `acl show`, so the
  restriction can be read back from wherever it was set.

- **acl**: Enforce an entry's capabilities, and give an operator a way to set them ([#1279](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1279))


## [0.33.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-sdk-v0.32.4...vta-sdk-v0.33.0) — 2026-09-07


### Added

- **vta-sdk**: Make AclEntry and AppStateWrite non-exhaustive ([#1271](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1271))

The last two types the semver report flagged, deferred out of #1270 because
  AclEntry looked like a 68-site migration through security-sensitive semantics.

  It was not. The compiler finds ONE construction site outside vta-sdk. The 68 came
  from a grep that conflated three different types — this wire `AclEntry`, the
  unrelated `vti_common::acl::AclEntry`, and vtc-service's own `VtcAclEntry` — and
  counted every `fn ... -> AclEntry {` body as a literal. The caution was right; the
  arithmetic behind it was not, and the compiler was the census that settled it.

  What the review did earn is the shape of the constructor. Both real fixtures set
  `allowed_keys` deliberately and say why in a comment: `trust_task_decode.rs` uses
  `Some(vec![])` because the empty vec must survive the wire as `"allowedKeys": []`,
  and `conformance.rs` uses a populated vec because only a present value proves the
  member survives under its canonical spelling. On this type `None` and `Some(∅)`
  are OPPOSITE grants — absent reaches every key the entry's scopes reach,
  present-but-empty reaches none.

  So `AclEntry::new` takes subject, role and scopes, and leaves `allowed_keys`
  absent — the meaning an entry predating the member already has. It defaults no
  grant whose empty case is not its neutral case, and the doc comment says so.
  Empty `scopes` has the same shape of hazard (unrestricted for an admin role,
  authorized nowhere for every other), which is why it is an argument rather than a
  default.

- **vta-sdk**: Make the growth-prone wire bodies non-exhaustive ([#1270](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1270))

Sixteen public request bodies gained an `ext` member in #1231 — under a `fix:`
  type, which derives the smallest bump there is — and every consumer building one
  with a struct literal stopped compiling. `vta-sdk` 0.32.4 shipped that as a patch
  release, which a caret requirement takes on a routine `cargo update`.

  `ext` is the framework's extension member (SPEC §4.5.1); these bodies gain
  members whenever the schema revises. So the fix is not to remember the `!` next
  time, it is for the addition to stop being breaking: fourteen of them are now
  `#[non_exhaustive]` with a `new()` taking the members the schema requires. The
  optional members stay public — set them on the returned value.

  Deliberately NOT applied to `AclEntry` or `AppStateWrite`, which the same report
  flagged. `AclEntry` has 68 construction sites, and its own doc comments record
  that `None` and `Some([])` on `allowed_keys` are OPPOSITE grants: absent means
  every key the entry's scopes reach, present-but-empty means no keys at all. A
  generated constructor defaulting that to `None`, migrated mechanically across 68
  sites, is precisely how the narrowest grant becomes the widest — the same class
  of mistake CLAUDE.md already attributes to #746, #769 and #770 on the adjacent
  `allowed_contexts` axis. That one wants per-site review, not a script, and it is
  better done on its own.

  The compiler was a better census than grep: I estimated 19 external construction
  sites and it found 21, across five files including integration tests, which count
  as outside the defining crate for this purpose.

  Two of my own automation passes needed correcting on the way, both worth naming
  because the second was nearly silent: the first brace matcher mis-parsed `//`
  comments sitting inside the literals, and the second dropped the comment attached
  to `authorization_context: None` while filtering out `None`-valued fields. That
  comment records that `authorizationContext` is a member the published schema does
  not define, so a producer cannot send it through the validated transport at all.
  It is restored against the constructor default.

  Breaking, so this wants the minor slot on vta-sdk. #1256's guard will say so if
  the release proposes otherwise.

- **persona**: Move to trust-tasks-rs 0.18 and resolve inline entries ([#1266](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1266))


## [0.32.4](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-sdk-v0.32.3...vta-sdk-v0.32.4) — 2026-09-06


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

- **persona**: The holder's own identity, and a boundary a context cannot read across ([#1255](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1255))

* feat(persona): register the persona keyspace

  Fourth holder store, beside the vault, agent memory and application state.
  It is distinct because disclosure control is its point, and app-state
  promises never to interpret its records — so it cannot host something whose
  whole job is deciding which members may leave.

  Two scopes share the keyspace and the split is a control, not filing: the
  pool and profiles are agent-scoped so the correlation index can see the same
  value presented by two personas in two contexts, which a per-context index
  cannot see by construction.

  BACKED_UP, because a restore without the holder's identity returns an agent
  that no longer knows who its holder is.

  Cascade on DID deletion, with the nuance the per-keyspace enum cannot
  express: only the context-scoped half is DID-keyed. Bindings and contacts
  cascade; the pool survives, because a profile may be bound to several
  personas and deleting one must not destroy facts presented through another.

  * feat(persona): vta-persona crate — models, key layout, correlation index

  The fourth holder store. Distinct from app-state because disclosure control
  is its point, and a store that promises never to interpret its records cannot
  gate what leaves them.

  model.rs carries the shapes the specs made normative. Two choices are
  load-bearing. ProofRung derives Ord so that 'the highest rung this format
  supports' is a max() rather than a hand-written table that can disagree with
  itself. And ProfileEntry::referenced() returns None only for inline entries,
  which is what makes a context-local profile checkable: one is valid exactly
  when no entry references the pool.

  storage.rs builds every key in one place, because the agent-scoped and
  context-scoped prefixes are a security boundary and a call site that formats
  its own key can put a record on the wrong side of it. scope_of() returns
  Option rather than defaulting — a key nobody recognises must not be assumed
  safe to serve a context-scoped caller. Local profiles get their own prefix
  rather than a flag, so a context-scoped scan reaches a space that
  structurally cannot hold a pool profile; a filter is a line of code that can
  be got wrong, an address space cannot.

  correlation.rs is keyed by HMAC over a canonicalised value, so exact-match
  lookup works with no plaintext index over the holder's PII — and prefix and
  substring search are out of scope by construction, which is the trade.
  Canonicalisation sorts object members, or two serialisations of one fact
  would hash differently and the guard would miss the reuse it exists to catch.
  Comparison is constant-time, or an attacker submitting candidates could use
  timing to learn what the holder holds.

  severity() encodes the inversion that is easy to get backwards: a credential
  presented WHOLE correlates more than a self-asserted value, because the
  issuer signature is identical at every verifier, while a derived proof
  correlates less because it differs every presentation. Scoring on provenance
  alone would rank an attested claim safer than a typed one and push holders
  toward the riskier option.

  * feat(persona): pin trust-tasks-rs 0.17.9 and assert the contract in tests

  The persona family is published, so the generated payload types are now the
  contract this crate stores against. Taken as a dev-dependency rather than a
  real one: storage needs none of it, and depending on it only in tests means a
  spec change that lands upstream without a matching change here fails a test
  instead of a production dispatch.

  Two assertions earn their place. The proof and issuedAt constants are how a
  dispatcher learns those were declared REQUIRED, so a relaxation upstream
  surfaces as a failing test rather than as an accepted unsigned write. And our
  ValueType is compared to the published enum on the wire, because a variant
  added upstream without a matching arm here would silently reject a value the
  spec calls legal.

  * feat(persona): attribute store — versions, preconditions, tombstones, indexes

  Read-modify-write is serialised by a process-local lock rather than a CAS,
  following the conclusion app-state reached: there is no reachable multi-writer
  topology, and a CAS would be atomic exactly where the lock already suffices
  while staying non-atomic on the vsock proxy that would need it.

  The version counter is reserved BEFORE the write it belongs to. A crash
  between reserving and writing leaks a number, which is harmless because
  versions are opaque and monotonic and never an edit count. The opposite order
  would reuse one, which is not.

  Index maintenance runs before the record write, deliberately. A crash then
  leaves an index entry with no record — a false positive in the correlation
  guard — rather than a record with no index entry, which would read as a false
  ALL-CLEAR. Over-warning is recoverable; under-warning is the failure the
  guard exists to prevent.

  A tombstone is not a live record, so expectedVersion 0 succeeds over one and
  the new record takes a later counter value. A repeat delete returns
  existed: false and takes NO version: had it taken one, every consumer
  watching the store would see a change that did not happen and delete could
  not be safely retried — asserted by a test that measures the counter either
  side.

  correlation_count returns a count and never identifiers, because returning
  them on a write would disclose the holder's other compositions to whatever
  tool made it.

  * feat(persona): profiles, resolution, and the reverse index

  put_profile validates every reference before taking a version, so a refused
  write consumes nothing, and refuses the whole composition on a dangling
  reference — a partially-resolved profile would disclose less than the holder
  composed and tell them nothing about it.

  The reverse index drops its old edges before adding new ones. Without that an
  attribute removed from a profile keeps a stale referrer, and its delete is
  refused for a reference that no longer exists.

  An override replaces value and label only; provenance is inherited. A pin
  naming a version the store no longer holds resolves stale with no value
  rather than silently serving the current one, which would defeat the entire
  point of pinning.

  Deleting a profile leaves the pool untouched. A profile references rather
  than owns, so removing a composition destroys no facts — the asymmetry with
  attribute deletion, where removal does change what compositions present.

  **Fixes a real serde defect the tests caught.** ProfileEntry is untagged, and
  untagged tries variants in declaration order while serde ignores unknown
  fields — so the permissive Ref variant was matching {ref, override} and
  {ref, pinVersion}, silently degrading an override into a live reference and a
  pin into an unpinned one. A disclosure changing behind the holder's back.
  deny_unknown_fields is not available on a variant, so the fix is declaration
  order with Ref last, documented at the enum and pinned by a test.

  * feat(persona): bindings — the push across the context boundary

  Setting a binding is the moment a composition crosses from agent scope into a
  context, and the crossing has a direction: the holder pushes a materialised
  projection down, and a context never pulls.

  MaterialisedClaim is a distinct type from ResolvedClaim rather than the same
  one with a field left empty. The difference IS the security property — a
  function handed a MaterialisedClaim cannot obtain a pool identifier, so no
  future edit leaks one across the boundary by forgetting to clear it. The
  compiler enforces what a reviewer would otherwise have to notice. Asserted on
  the serialised bytes, because what crosses the boundary is what was written.

  rematerialise() keeps 'edit once, everywhere' working without opening a read
  path: it is a write initiated ABOVE the boundary, never a pull from below.

  Binding to a missing profile is refused rather than written — a binding that
  appears configured and presents nothing is a failure the holder discovers
  from the other side. Clearing is a first-class state, not an absence: a
  persona with no profile is legitimate and common.

  A second persona on one profile is counted and returned, because that act
  makes them the same person by construction and no later narrowing undoes it.
  A count, not identifiers — the association between the holder's personas is
  exactly what an attacker wants.

  BindingSummary is what a context-scoped caller may learn: whether bound, the
  label, a claim count. It has nowhere to put a value, which is the point.

  * feat(persona): contacts — revisions, diffs, and reference-counted retention

  A contact is what a peer disclosed, appended as a revision and never
  overwritten. An address book that silently replaces a payment address is a
  phishing surface; one that reports what changed and when is a defence — which
  is what changed_claims and has_unreviewed_change exist for. A revision
  history nobody is shown is an archive, not a defence.

  Keyed on (context, subject, knownByPersona): the same peer met through two
  personas is two contacts. Collapsing them would correlate the holder's own
  personas inside their own address book, which is the one place nobody would
  think to look for that linkage.

  The diff counts a claim that VANISHED as changed. A diff reporting only
  mutations stays quiet when a peer stops disclosing their payment address,
  which is exactly when it should speak up.

  A reaped revision returns Gone, never NotFound. A caller comparing a current
  value against history must tell 'never existed' from 'no longer kept' —
  only the second means their comparison is unsound rather than mistaken, and
  collapsing them lets a producer conclude 'nothing changed' from an absence
  that means the opposite.

  Retention counts references rather than days. A revision cited by a
  disclosure record is evidence of what the holder was shown before they
  presented; a flat TTL would delete it precisely when it mattered. Deletion
  reports what it retained, because an incomplete erasure the holder believes
  is complete is worse than one they know about.

  The outgoing revision is archived BEFORE the new one lands, so a crash leaves
  a duplicate rather than a gap — and a gap in a history that exists to prove
  what changed is worse than a repeat.

  * feat(persona): the disclosure record, and the caller retention was built for

  Append-only, and written BEFORE the artifact is returned. A crash between
  signing and recording would release data the holder could never afterwards
  discover they had released; recording first can only produce a record of a
  disclosure that did not happen, which is a false positive they can
  investigate. One of those is recoverable.

  Records name claim TYPES and rungs, never values. Re-storing the values would
  double the exposure the record exists to describe, and put a second plaintext
  copy of the holder's data in a structure whose whole purpose is to be read
  later. The rung is recorded because the same claim type at two rungs is two
  very different disclosures.

  contexts_reached_by() pays the debt the scope split incurred. Putting the
  pool above the context boundary bought a correlation check that sees across
  contexts; the cost is that a holder can no longer tell from one context where
  a fact has gone. This answers it directly.

  record_disclosure cites the contact revisions a disclosure relied on — the
  caller reference-counted retention was built for, and until now had none.
  Citation happens after the record lands: a citation with no record retains a
  revision nobody needs, while a record with no citation would let the evidence
  behind it be reaped. Only one of those loses something.

  * feat(persona): task URIs and retry-safety classification

  Adding the 24 URIs to ALL_URIS made every_uri_is_classified fail until each
  was classified, which is the census working: a task cannot join the catalogue
  without someone deciding what a lost reply costs it.

  Writes are Keyed following the app-state precedent — without a precondition a
  replay writes twice and bumps the counter twice, so a watcher sees a change
  that never happened. Deletes are RetrySafe because they converge: a repeat
  finds a tombstone, returns existed: false, and takes no counter value.

  Two entries are worth reading twice. disclosure/preview looks like a read and
  is Keyed, because it mints the single-use token present consumes — a replayed
  preview hands out a second authorisation to disclose. And disclosure/present
  is Keyed because a replay is a second release of personal data to a third
  party and a second permanent record of it: the one task in this family where
  a lost reply must never be retried blind.

  * feat(persona): the authorization boundary, enforced and pinned by census

  The pool and profiles are agent-scoped; bindings, contacts and disclosure
  records are context-scoped. Nothing inside a context may read the pool. That
  is a rule about direction rather than a permission — an access-control failure
  over a readable pool discloses everything, while a pool no context can address
  has nothing to disclose.

  The gate is require_super_admin (Admin AND unrestricted scope), not a role
  check. A guard written as 'is this caller an administrator' PASSES for an
  administrator scoped to a single context, who would then read and write
  identity data belonging to every other one. vti-common's own act_scope docs
  warn about the same edge from the other side: an empty context list means
  unrestricted for Admin and nothing at all for every other role, so a call site
  testing is_empty() without the role gets one of the two backwards. Both halves
  are asserted.

  REACH classifies all 24 tasks and is exhaustive by test, so a task cannot join
  the family without someone deciding which side it is on — and an unknown URI
  is refused rather than defaulted, because defaulting to Context is exactly how
  a pool read becomes reachable from inside one.

  The test that matters is a_context_scoped_admin_is_refused_every_holder_task:
  it iterates every holder-only task and asserts an admin scoped to ctx-work is
  turned away. That is the conformance witness the design asked for, and the
  test that would have caught the trap.

- **rooms**: A VTA joins a room, keeps up, and opens what it holds ([#1250](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1250))

Implements rooms/keys/{key-package,welcome,commit,open} - the delivery
  flow specified in dtgwg-trust-tasks-tf#355 and the decryption oracle from
  #349, on the custody layer from #1248. This is the piece that makes a
  data room readable by an agent that never holds a key.

  Four tasks, four different gates, and only one is a capability. The
  delivery three are inbound - a room's owner reaching this VTA - and an
  ACL of ours has no opinion about who a room's owner is. commit in
  particular is authorized INSIDE the group: MLS authenticates the
  committer as a member of the group we already hold, and a list we kept
  would be this service deciding who may commit to a room it is not part
  of. Only open is our own principal's agent asking us to decrypt, which is
  what a capability is for - RoomOpen, registered upstream in #351.

  The invitation is what makes a Welcome acceptable. A Welcome carries a
  group's secrets, so anyone able to reach a VTA could otherwise push group
  state into it. Joining a room is already a two-party act and the VIC is
  already the consent artefact; this is where that stops being ceremonial.
  Five checks, none optional - it parses as an invitation, its proof
  verifies, the issuer is the room, the subject is us, and it is live and
  unspent - and dropping any one leaves a way in. VerifiedInvitation is
  constructible only by the verifier, so a caller cannot reach consumption
  with something nobody checked.

  The invitation is consumed only AFTER the join succeeds. Burning it on a
  Welcome that then failed to process would strand the member: invitation
  spent, not in the room.

  Joining twice is refused rather than merged. Two group states for one
  room is a condition nothing downstream can resolve - open has no way to
  choose, and choosing wrong returns 'did not open' for a record the member
  can plainly see.

  open reports which epoch the VTA holds when a record is sealed under a
  later one. A member who missed a commit is stuck at their last epoch, and
  the raw symptom is 'this record does not open', which reads like
  corruption; naming the epoch turns it into 'a commit has not been
  delivered', which an operator can act on.

  Two keyspaces, both Cascade on DID deletion: room_groups holds group
  secrets and belongs at the same protection level as the key store, and
  room_invitations outlives the groups it admitted - while the member
  exists, a consumed invitation MUST survive leaving a room, or the same
  invitation would work twice.

  Four censuses had something to say. The MCP guard, where open and welcome
  are Sensitive (plaintext out, key material in) while key-package and
  commit are ordinary mutations. Retry safety, which produced four
  different answers and is the better for it: open is ReadOnly, commit is
  RetrySafe because the spec made replay a no-op precisely so delivery
  could retry, and key-package and welcome are Keyed - one leaves a second
  private half behind, the other cannot tell a lost reply from a completed
  join. Then the conformance witnesses and the namespace list.

  trust-tasks-rs 0.17.8 landed mid-build carrying #351, #354 and #355, so
  all four request types are generated rather than hand-written.

- **rooms**: The presentation oracle, so an agent never holds its human's credentials ([#1247](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1247))

Implements rooms/keys/present/0.1. The data-rooms design turns on a member
  equipping their agent with strictly less than they hold - a chain one link
  longer, conferring read for four hours, bound to one host - and nothing
  minted one. A member wanting to give an agent access had two options: hand
  over their own credentials, which is the outcome attenuation exists to
  prevent, or mint an attenuation by hand, which nobody does.

  So the agent asks, and the VTA mints. The VTA already holds the member's
  keys and is already in their trusted computing base; a host is not, which
  is why the host only ever sees the result.

  Four things a caller cannot obtain by asking, and each closes a way this
  could have quietly become the credential hand-off it replaces:

    More than the principal holds fails in attenuate, which refuses to
    widen - not at a policy check somebody could forget to write.

    A presentation covering everything is unreachable: action is required
    and exactly one action is conferred.

    A presentation made out to somebody else is unreachable: the leaf grants
    to the DID the transport authenticated, never one named in the payload.
    One minted for A is worthless to B even if B obtains it, because the
    presenter binding refuses it on the far side.

    A long-lived leaf is unreachable: the lifetime is a constant, not a
    request parameter. A caller that could ask for a year would be asking
    for the standing credential the oracle exists not to hand over.

  Gated on Capability::RoomPresent - registered upstream as roomPresent in
  dtgwg-trust-tasks-tf#351 - and deliberately not on Sign. An agent that may
  ask for a scoped, audience-bound presentation is not thereby an agent that
  may sign anything at all with its principal's key, and gating an oracle on
  the generic signing oracle grants strictly more than the task needs.

  The credentials are found by issuer, because a room issues its own - the
  same property the host verifies against, so a credential that would not
  verify there is not one this will present. Two authority credentials from
  one room is refused rather than resolved: picking the broader one hands
  out more than necessary, picking the narrower produces a presentation that
  fails at the host for reasons the caller cannot see.

  Five censuses had something to say, and all five were right. The
  conformance witness. The retry-safety classification - RetrySafe, because
  the oracle stores nothing and a retry mints a second leaf conferring
  exactly what the first did, on the same expiry; keying it would buy a
  dedup record against a harmless duplicate at the price of failing a retry
  the caller needs. The MCP guard, where it joins 'authority, moved' beside
  vta/credentials/issue: an MCP host approves a tool, so a blanket vta_call
  approval must not silently cover minting a presentation over its
  principal's standing. And the canonical-namespace list, which gains
  spec/rooms/ for exactly one URI - most of that family is a host's surface,
  and this is the one member a VTA serves.

- **rooms**: Data rooms end to end — storage, dispatch, verification, MLS, and a host ([#1237](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1237))

* feat(rooms): the data-room storage layer

  A data room is a shared space whose access is governed by credentials the
  room itself issues. This lands the storage and its invariants; the
  Trust-Task dispatch that authorizes operations follows once rooms/* is
  published in the registry (trustoverip/dtgwg-trust-tasks-tf#346) - the
  dispatcher refuses a URI the published registry has no schema for, and
  growing the unspecced allowlist is the wrong fix.

  Written first so that the dispatch layer is a thin wrapper over settled
  behaviour rather than a place where storage decisions get made under time
  pressure.

  The row deliberately carries an owner, a visibility, an epoch and a
  retention period, and NO member list. Not omitted for now - there must not
  be one. The moment this service keeps a roster and consults it, three
  things stop being true at once: the room can no longer move to another
  host without reissuing credentials, this service becomes part of the
  room's membership definition, and a room whose contents we cannot read
  acquires a member list we can.

  Invariants enforced in the store rather than trusted to callers, each with
  a test:

  - An open room refuses ciphertext and a sealed room refuses cleartext, so
    a tier promise cannot be broken by a caller passing the wrong shape.
  - A private room refuses a recorded author: on that tier authorship
    belongs inside the sealed body where only members can read it.
  - A record sealed under a stale epoch is refused, because a reader holding
    the current key could not open it.
  - An epoch advances by exactly one. A gap would leave records sealed under
    an epoch nobody holds a key for; a repeat would let a removed member's
    key open material written after their removal, which is the whole point
    of advancing.
  - Versions are monotonic per room, not per record - one comparable number
    is what a sinceVersion watermark needs. A conflict carries the current
    version so a caller need not re-read, because between a bare rejection
    and the re-read the record can change again.
  - A listing returns tombstones to a watermark caller. Without that a
    puller learns of every create and update and never of a delete, so
    retracted records resurrect on its next full rebuild.
  - Retract and purge are separate verbs: a tombstone keeps the key, version
    and epoch so sync converges and the audit chain holds, and erasure is a
    distinct, higher-trust act.

  Keyspaces registered in ALL and BACKED_UP - the two must partition ALL
  exactly - with the census count moved to 27 and the matching AppState
  fields opened, so the documented ALL-matches-AppState invariant stays
  true rather than merely passing a length check.

- **vta**: Implement vta/credentials/list, and check the vault/credentials family ([#1235](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1235))

* feat(vta): implement vta/credentials/list, and check the vault/credentials family

  `vta/credentials` served `issue` and `revoke` and nothing else, so an issuer
  could not ask its own agent what it had issued. The `credentialId` that
  `revoke` is keyed on is returned exactly once, in the `issue` response; a
  caller that did not record it at that moment could not recover it at all.

  Specified upstream as `vta/credentials/list/0.1`
  (trustoverip/dtgwg-trust-tasks-tf#342). This implements it — a read over
  records that already exist. `IssuedCredentialRecord` carries the id, holder,
  both instants and the revocation instant and reason, and revocation is a
  tombstone rather than a delete, so a revoked credential is still there to list.
  No new storage.

  Bodies are never returned. `vault/list/0.1` states the rule this follows —
  list enumerates, release uses — and `summarise` is the one place the projection
  happens, so "a summary never carries the credential" is enforced rather than
  remembered. `status` is derived at read time with `revoked` beating `expired`:
  reporting a revoked credential as merely expired would hide that somebody
  acted, and a stored status is wrong one second after it is written.

  Gated on `require_manage`, not the Admin-plus-step-up its mutating siblings
  use. An operator who may read the ACL and the policy set may read what their
  own agent issued — same category of question — and a step-up that fires on
  every page of a list is one people learn to clear without reading. The read is
  audited anyway: "who enumerated the issuance log" is what an incident review
  asks, and nothing else would record it.

  ## Bumping trust-tasks-rs to 0.17.4 surfaced the vault/credentials family

  Those eight URIs have been dispatched since before they had a specification.
  Specifying them (#338, shipped in 0.17.4) made them *published*, which is what
  finally let the conformance sweep see them — and it found two real defects in
  shapes that had never been checked against anything:

  - **`ReceiveBody` serialized `credentialBase64: null`.** `#[serde(default)]`
    without `skip_serializing_if` leaves an unset member as `null`, and the
    schema's `oneOf` counts a null member as *present* — so the body matched
    neither branch. Same defect class as the sibling registry's
    `payload_null_census`.
  - **`force` was accepted by four verbs that ignore it.** `CredLifecycleBody`
    was shared across archive, unarchive, delete, restore and purge, but only
    `delete` reads `force`. A caller asking for something stronger than the verb
    it named got the weaker thing and a success. `delete` now has its own body;
    the other four refuse the member, as their schemas always said they should.

  Three debt ratchets moved in the right direction as a consequence, each
  discharged by specification rather than deletion: eight entries out of
  `UNSPECCED_DISPATCHED_URIS`, one out of the producer-payload census's
  `UNPUBLISHED` list (so that payload is now validated rather than skipped), and
  vtc-service's bound-URI count from 12 to 4 — what remains is the four
  *secrets*-store lifecycle verbs, which still have no spec.

  ## Tests

  `page_rows` is split out of `list_issued` and unit-tested because the cursor is
  where a bug hides: it is the last storage key of the previous page and
  resumption is strictly after it, so a credential issued mid-walk cannot shift a
  window and skip a row nobody has seen. That case is a test. So are the status
  precedence, an unreadable expiry reading as active rather than expired, and
  that a serialized summary contains no credential.

  `IssuedCredentialSummary` is the census's first `NO_EXT_BY_DESIGN` entry: it is
  a list row rather than a payload root, and its published schema declares no
  `ext` slot, so adding the field would make this crate emit documents the schema
  rejects — the inverse of the defect that census exists to catch.



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



## [0.32.3](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-sdk-v0.32.2...vta-sdk-v0.32.3) — 2026-09-01


### Fixed

- **provisioning**: Say which side is out of date, and check authorization before minting ([#1220](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1220))

An operator ran OpenVTC's setup wizard against a VTA and got:

      X Provision integration DID + admin credential — trust task failed
        [unsupportedType]: unsupported type:
        https://trusttasks.org/spec/provision/integration/0.3

  with a green tick on the row above it. Two things were wrong — no ACL grant
  for the setup DID on the VTA they had reached, and it was not the VTA they
  meant — and the run reported neither. It took an hour and a wrong diagnosis
  before anyone suspected the VTA rather than provisioning.

  Every fact needed was already on hand. The VTA was serving
  `provision/integration/0.2` two lines further down the dispatch table it had
  just failed to match. The wizard held the VTA's DID and the setup DID. Nothing
  put the two together, and the message that did reach the operator said only
  what could not be done.

  **The rejection now names what it can do.** `method_not_found` compares the
  unknown URI's family against `dispatched_uris()`; a family this VTA serves at
  another version is `unsupportedVersion` — SPEC's code for exactly this, "the
  consumer recognizes the type but not at this MAJOR.MINOR" — carrying the
  served versions in `message` and in `details.servedVersions`. A family it does
  not serve stays `unsupportedType`. Both now carry `details.requestedType`,
  because the framework puts the rejected URI only in prose and a client should
  not have to slice a sentence to recover it. Derived from the dispatch table,
  not a second list: a migration hint naming a version the VTA does not serve is
  worse than no hint.

  This half only helps the next skew, since the VTA that produced the bad message
  is by definition the old one. The other two halves help now.

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



## [0.32.2](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-sdk-v0.32.1...vta-sdk-v0.32.2) — 2026-08-29


### Fixed

- **vta**: Answer provision/integration under the version the body was rendered in ([#1202](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1202))

#1147 made 0.3 the only provision-integration version the DIDComm router
  accepts, and #1200 moved the client dispatch sites onto it. The reply's
  *type URI* stayed behind. `result_uri_for` tested for one version and fell
  through:

      if request_uri == CANONICAL_PROVISION_INTEGRATION_0_2 {
          CANONICAL_PROVISION_INTEGRATION_0_2_RESULT
      } else {
          CANONICAL_PROVISION_INTEGRATION_RESULT   // 0.1, for everything else
      }

  so 0.3 — the only URI that can now reach the handler — took the `else` arm.
  `CANONICAL_PROVISION_INTEGRATION_0_3_RESULT` was declared and never read.

  Two lines apart in `handle_provision_integration`, the result URI comes from
  `result_uri_for` and the body from `response_body_for_version`. The body was
  rendered 0.3; the URI said 0.1. Every DIDComm provisioning reply went out as
  a `digestMultibase` body labelled `provision/integration/0.1#response` — a
  message that cannot satisfy the schema it names, because 0.1's response
  requires a bare-hex `digest` and closes with `additionalProperties: false`.
  `ProvisionIntegrationResponse` has carried `digest_multibase` and no `digest`
  since #1147, so under that label the reply was unserveable by construction.

  Nothing in this workspace noticed, because both halves were wrong the same
  way: `provision_integration/didcomm.rs` computes the reply type it waits for
  with the same `result_uri_for`, so the Rust client asked for `0.1#response`
  and the server sent `0.1#response` and they agreed. It takes an independent
  client to see it — the browser wallet reads the URI from the trust-tasks
  registry bindings, expects `0.3#response`, and rejects the reply. What the
  operator sees is a provisioning run that has fully succeeded — bundle sealed,
  admin rolled over, secret written — reported as a failure, with the whole
  successful response body quoted back inside the error. The holder discards a
  bundle the VTA has already committed to.

  `result_uri_for` now resolves through `ProvisionSpecVersion`, which grows the
  two halves a reverse map needs: `ALL`, and `from_request_uri` as a search over
  it rather than a hand-written second table. This is the same correction
  `is_v0_1` already carries — a predicate about one version has to name that
  version, because a fall-through arm silently claims every version nobody has
  written yet. An unrecognised URI resolves to `CURRENT`, which is what
  `response_body_for_version` renders it as, so the label and the body agree
  even on the branch the router cannot reach.

  The router now dispatches on `CURRENT.request_uri()` instead of the 0.3
  constant, so the URI it accepts, the URI the handler answers under, and the
  URI the clients send are one knob rather than three that have now twice been
  moved separately.

  Guards, at the level that can actually catch this: asserting
  `result_uri_for(0.3) == 0.3#response` alone would pin the symptom, so the new
  tests assert the rule over `ALL` — every version's result URI is its request
  URI plus `#response` (SPEC.md §4.4.1), and `result_uri_for` agrees with the
  version the request URI names. Both fail on the old implementation, naming
  V0_3. The test they replace asserted the fallback *was* 0.1 and called the
  branch "unreachable in production, the router only advertises 0.1 and 0.2" —
  true when written, false since #1147, and it pinned the defect in place.

  Also corrects three comments that outlived their subject: the enum doc stopped
  at 0.2, `response_body_for_version` still named the removed `digest`, and the
  handler still described a "legacy FPN URI" retired several releases ago.



## [0.32.1](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-sdk-v0.32.0...vta-sdk-v0.32.1) — 2026-08-29


### Fixed

- **sdk**: Dispatch provision/integration 0.3 on every transport, not just REST ([#1200](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1200))

#1147 cut provision-integration over to 0.3 and removed 0.2 outright — 0.2
  requires a bare-hex `digest` and forbids the `digestMultibase` 0.3 requires, and
  both close their response with `additionalProperties: false`, so no single
  response satisfies the two. The server moved, the REST runner moved, and the
  response-parsing side moved. The other three dispatch sites did not:

  | site | asked for |
  |---|---|
  | `provision_client/runner_tsp` | `0.2` (trust-task spine) |
  | `provision_client/runner_didcomm` ×2 | `0.1` (DIDComm protocol message) |
  | `client/bootstrap` DIDComm arm | `0.1` |

  Each held its own literal, and each was correct on the day it was written — TSP
  and DIDComm genuinely addressed different versions of this operation before the
  cut-over collapsed them onto one URI. So nothing looked wrong, and nothing
  failed in CI: both halves were internally consistent. What shipped is a VTA that
  can only be provisioned over REST. Every TSP and DIDComm attempt returns

      trust task failed [unsupportedType]: unsupported type:
      https://trusttasks.org/spec/provision/integration/0.2

  against a VTA that is otherwise healthy — and it surfaces as a `PostAuthFailure`
  *after* auth succeeds, so the runner reports it as terminal and never falls back
  to the REST leg that would have worked. OpenVTC's setup wizard prefers TSP, so
  this is every fresh OpenVTC install.



## [0.32.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-sdk-v0.31.1...vta-sdk-v0.32.0) — 2026-08-29


### Added

- **sdk**: Any DID that names a key may sign a Trust Task ([#1193](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1193))

A Trust Task proof could only be made by a `did:key`. That was never a policy
  anyone chose — it was the shape of two helpers, and it meant a provisioned
  integration could not dispatch any of the 210 proof-requiring Trust Tasks, over
  any transport, because every DID this workspace provisions is a `did:webvh`.

  The rule is now the obvious one: **any DID that can name a key may sign**. The
  DID method is not the authorization; resolving the verification method and
  checking the signature is. `did:key:z6Mk…#z6Mk…`,
  `did:webvh:<scid>:example.com:glenn#key-0` and `did:web:example.com#key-1` are
  all ordinary holders.

  What actually stood in the way:

  The signer took `(holder_did, private_key)` and *derived* the verification
  method as `<did>#<multibase>`. That derivation exists only for `did:key`, whose
  key is its identifier — a `did:webvh` document decides what its keys are
  called, so nothing can guess `#key-0`. A signer that takes only a DID
  structurally cannot serve any other method. `HolderKey` now carries the
  verification method; `HolderKey::from_did_key` keeps the derivation for the one
  method that has one, and refuses to invent one for the others.

  The verifier used `DidKeyResolver`, which refuses everything else.
  `TrustTaskVmResolver` resolves `did:key` locally and any other method through
  the configured DID cache, matching a proof's absolute `verificationMethod`
  against a document that may name it relatively. It is hoisted from the
  equivalent the VTC already had for credential verification.

  `ClientIdentity` gains `verification_method`, and `connect_didcomm_bundle{,_on}`
  build an identity from the bundle's own Ed25519 `SecretEntry` — whose `key_id`
  *is* the verification method the DID document publishes, so nothing is guessed.
  Those constructors passed `identity: None` deliberately; that reason is gone.

  Every verifying call site now takes a resolver: the VTA's dispatch spine, REST
  login, step-up and consent; the VTC's dispatch, REST login and relationships.
  Threading it is the half that makes the signer change real.

- **device**: Let a device correct its display name on the heartbeat ([#1191](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1191))

`displayName` was written exactly once, at registration, and nothing in the
  device family could change it. `device/register` is intentionally not
  idempotent — a binding hangs off the caller's ACL entry, one per DID, and a
  second claim is refused with `device/register:alreadyRegistered` — so a
  renamed machine, or an install moved to another profile, kept announcing a
  name that no longer identified it. The spec is explicit that `displayName`
  exists "to help a human pick their own laptop out of a list", which is the
  thing that degrades.

  Heartbeat is where the spec already puts metadata drift: `platform` is
  defined there as "updated platform descriptor if it changed since
  registration". `ext` is the slot it provides for the rest, so a device now
  sends `org.openvtc.device-name: { displayName }` and the VTA applies it.

  Nothing about the register refusal moves. The binding, its `deviceId` and
  its `registeredAt` are untouched, no new binding can be claimed this way,
  and the entry `version` does not bump: a rename is metadata, and the spec
  forbids `displayName` being used as a security input by anything that
  renders it, so no policy decision can turn on it. The entry is fetched by
  `auth.did`, so a device can only correct the binding it authenticated as.

  A malformed extension is **ignored, not rejected**. A heartbeat's real job
  is refreshing `lastSeenAt`, and failing the call over a bad name would make
  a device with a client-side bug look offline — the more expensive error,
  because it is the one that sends an operator after a machine that is running
  fine. The 1..=128 bound the untyped `ext` slot cannot inherit from the
  register schema is enforced here instead.

  The extension key is defined once, in the SDK that produces it, and imported
  by the service that honours it — the two sides otherwise agree by string,
  and a typo on either would be a rename that silently never happens.

  `device_heartbeat_named` is a new method rather than a wider
  `device_heartbeat`: this crate is consumed across repositories, and
  widening a public signature would spend a breaking release on a diagnostic
  field. The new `ext` member on `DeviceHeartbeatBody` is still a public-field
  addition, so this is a **minor** for `vta-sdk`, not a patch — nothing in the
  workspace or in OpenVTC constructs that struct, but the semver report will
  name it and the release should follow it.

  A VTA that does not understand the extension ignores it (SPEC §4.5.1): the
  heartbeat still refreshes liveness and the name stays as it was.



### Fixed

- **sdk**: Stop rewriting the envelope a Trust Task proof covers ([#1192](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1192))

An operator running `pnm contexts create` against a production VTA got:

      Protocol error: trust task failed [proofRequired]: proof required but
      not present

  That is `SpecPolicy::enforce` on the VTA's dispatch spine refusing a document
  whose specification declares `proof` REQUIRED (SPEC §7.2 item 7a).

  The cause is the one #1184 fixed: `didcomm_transport` and `tsp_transport` built
  every client with `identity: None`, so `build_task_document` set no `issuer` or
  `recipient` and `signed_task_document` attached no proof. What is new here is
  why it reported itself as `proofRequired` rather than the `malformedRequest:
  … no in-band recipient` #1184's changelog describes. `address_trust_task`
  back-fills both members on the TSP paths, which satisfies item 5b — so a TSP
  document sails past the recipient check and lands on the proof check instead.
  Same defect, two names, depending on transport.

  It is released in vta-sdk 0.31.1; pnm-cli 0.14.0 was cut against 0.31.0 and has
  not been re-released, so an installed binary still carries it. Rebuilding, or
  `--transport rest`, is the operator's way out.

  Three things this changes.

  `address_trust_task` no longer assigns `issuer` and `recipient`
  unconditionally. A Data-Integrity proof covers every member but `proof`, so
  writing either one *after* signing turns a valid signature into `proofInvalid`
  at the far end — a failure that names the proof and says nothing about the
  rewrite that caused it. The values come from the same triple the identity was
  built from, so the assignment was a no-op; "it happens to be equal" is not
  something the next constructor has to keep true, and nothing was checking. It
  now fills only an absent member and refuses a disagreement, since neither
  answer is safe: honouring the transport breaks the proof, honouring the
  document sends it somewhere the caller did not ask for.

  A new test builds the document the SDK actually sends and runs it through
  `schema_index::spec_policy_for(uri).enforce(..)` — the same call the VTA makes.
  The existing tests checked `issuer`, `recipient` and `proof` by name and
  passed, because they were written from the same understanding as the code.
  Asserting against the registry means a new flag starts being checked without
  the test being edited. It covers a mutation and a read deliberately: the proof
  flag falls almost exactly along that line, so a client that only ever listed
  saw nothing wrong.

  The rationale on `signed_task_document` said "72 of the 109" specs require a
  proof. It is 210 of 344 in trust-tasks-rs 0.17 — and the number that actually
  justifies the hard error is `recipient`, which 343 of 344 require.

  `docs/05-design-notes/trust-task-envelope-conformance.md` records the
  diagnosis and the two instances of the same root cause still live on main: a
  `did:webvh` bundle holder cannot sign at all, because `trust_task_sign` refuses
  a non-`did:key` holder — so a provisioned integration cannot dispatch any of
  the 210 proof-requiring tasks; and `VtaClient::new` + `set_token_async` carries
  no identity, which is the documented `url + token` rung of the `AgentConnect`
  ladder. Neither is fixed here: the first needs a decision about how a
  `did:webvh` integration signs.

  Verified with `cargo fmt --all --check`, `cargo check --workspace
  --all-targets`, `cargo clippy --workspace --all-targets -- -D warnings`, and
  `cargo test -p vta-sdk` (298 passing).



## [0.31.1](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-sdk-v0.31.0...vta-sdk-v0.31.1) — 2026-08-28


### Fixed

- **sdk**: Carry the client identity on DIDComm and TSP clients ([#1184](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1184))

`didcomm_transport` and `tsp_transport` built every client with
  `identity: None`, so `build_task_document` set neither `issuer` nor
  `recipient` and `signed_task_document` attached no proof. A conforming
  VTA rejects that with `malformedRequest`:

      specification declares recipient REQUIRED but the document carries
      no in-band recipient

  which is what `integration::startup` hits on its first call after
  connecting over the DIDComm tier. The failure surfaces from
  `fetch_did_secrets_bundle`, past the transport fallback, so
  `TransportPreference::Auto` never downgrades to the REST tier — whose
  `from_credential` constructor is the only one that already set an
  identity.

  Both transport constructors now take the identity as a required
  argument, fed from the `did:key` triple their public `connect_*` callers
  already hold, so the next variant cannot forget it. The bundle
  constructors pass `None` deliberately: their holder is a `did:webvh` and
  `trust_task_sign` signs for `did:key` holders only.

  The guard meant to catch exactly this was gated on `has_token()`, which
  is false by construction for DIDComm and TSP — it covered the one
  transport whose constructor was already correct. It now fires for any
  identity-less client, so the fault is reported locally, and named, in
  place of a wire-level `malformedRequest` that reads like a payload bug.



## [0.31.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-sdk-v0.30.0...vta-sdk-v0.31.0) — 2026-08-28


### Added

- **credentials**: Move vta/credentials/issue to 0.2 ([#1159](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1159))

The last family behind its latest published spec. Checked against
  `website/registry.json` rather than the schema files on disk: every other
  implemented family is already on the newest published version.

  0.1 and 0.2 have identical payloads. The response differs only in how it is
  written — 0.2 composes it from `credentials/_shared/0.2`'s
  `IssuedCredentialBase` instead of restating the members inline, which is
  what stops the two drifting. The composition brings one new member,
  `issuedAt`.

  That member costs nothing to fill: `IssuedCredentialRecord` has carried
  `issued_at` since the family existed, and 0.1 simply had nowhere to put it,
  so the value was being computed, stored, and then dropped on the way out.
  It stays `Option` on our side because the shared definition declares it
  optional — a response without it is schema-valid and must still
  deserialize — but the VTA always sends it.

  The conformance sweep caught something on the way through, which is what it
  is for. Its drifted-witness check asserts the generated type rejects an
  unknown member, and 0.2's response type does not: closing a composed object
  requires `unevaluatedProperties` (`additionalProperties` is evaluated
  per-subschema and would reject the `allOf`-supplied members), and
  trust-tasks-codegen maps only `additionalProperties: false` onto
  `deny_unknown_fields`. So the generated struct is permissive where 0.1's
  was strict.

  The wire is unaffected — the schema itself is strict, so `validate_payload`
  still rejects the member. What is lost is the type-level guard, which makes
  the drifted-witness check pass vacuously. Recorded in
  `PERMISSIVE_GENERATED_TYPE` with its reason and skipped rather than left to
  give false assurance. The fix belongs in the codegen; deleting the entry
  re-arms the check.



## [0.29.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-sdk-v0.28.0...vta-sdk-v0.29.0) — 2026-08-26


### Added

- **sdk**: Extract the agent-side connect ladder into vta_sdk::agent_connect ([#1081](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1081))

* feat(sdk): extract the agent-side connect ladder into vta_sdk::agent_connect

  Every tool that runs beside a user and talks to their VTA on their behalf
  needs the same four ways in — did:webvh bundle, scoped did:key, bearer
  token, existing pnm session — in the same order, with the same fail-fast
  rules. That ladder existed only inside vta-mcp's main.rs, so the next
  bridge had to copy 110 lines or invent a fifth way in.

  `AgentConnect` is that ladder as SDK surface. `mode()` resolves the rung
  with no I/O, so a bridge can log it (and refuse a rung it does not
  support) before connecting; `connect()` returns the authenticated
  VtaClient. Session mode keeps TransportChoice::Auto, so it inherits the
  workspace preference order (TSP > DIDComm > REST) from what both DID
  documents advertise.

  Two rules are enforced rather than documented, both carried over from the
  vta-mcp original: the two DIDComm identity modes are mutually exclusive,
  and a half-configured rung errors naming the missing fields instead of
  falling through to session mode — a bridge silently authenticating as the
  operator rather than as its scoped agent identity is the failure that
  matters here. ConnectMode::is_dedicated_agent() makes the same
  distinction available to callers deciding whether to enroll as a device.

  vta-mcp is refactored onto it, which is what proves the extraction: its
  build_client is now a pure args -> AgentConnect mapping plus a connect,
  and its tests assert which rung a set of flags selects.

- **vtc**: Tell a member when the community removes them ([#1060](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1060))

Removal was the most consequential thing a community does to a member and the
  one it delivered with the least information — none. There was no outbound
  message on any removal path. The only signal a removed member could observe was
  a side effect: the revocation bit on their membership credential flipping. They
  inferred their own removal from a status list and learned nothing about why.

  `vtc/members/removal-notice/0.1` (published upstream as
  trustoverip/dtgwg-trust-tasks-tf#256) now goes out from both admin paths,
  carrying the deciding administrator, the moment the decision took effect, the
  resolved disposition, and the operator's reason.

  **Signed, because the recipient is not the audience.** Authcrypt already proves
  the sender to the member. But this is the one member-facing message whose value
  lies in showing it to somebody else — an appeal, a dispute, another community
  weighing a rejected applicant. Forwarded, an unsigned notice is an assertion
  anyone could have written. So it is a Trust Task document with a Data Integrity
  proof, packed in the trust-task envelope — note `TRUST_TASK_ENVELOPE_TYPE`, not
  the task URI, which is a mistake this workspace has made before and which a
  conformant peer rejects silently.

  **Thirty days, because there is no second route.** `resolve_auth_role` refuses
  any DID without an ACL row and removal hard-deletes it, so a removed member
  cannot authenticate at all: every authenticated route, including any poll that
  might have served the notice, closes at the moment the removal lands. The act
  this reports is the act that ends their ability to ask about it. `send_to_member`
  already had a durable outbox, so this needed a deadline parameter rather than
  new machinery — `send_to_member_by`, with the six existing callers keeping the
  24h default.

  A member offline beyond the window still never learns. No window fixes that; the
  honest fix is a retrieval path not gated on an ACL row, which is a larger design
  than this. Stated in the spec and in the constant's doc comment rather than left
  for someone to discover.

  **Never for a self-leave.** `remove_inner` serves both the admin path and the
  DIDComm self-leave. A member who chose to leave already has their receipt, and
  telling them they were "removed" is a different and worse thing to be told.

  **Best-effort.** The notice never fails the removal. That has already happened
  and is durable; refusing the operator's request because the notice could not be
  *queued* would leave the member removed and the operator believing they were
  not. Failures log loudly — and log "queued", not "sent", because a DIDComm `Ok`
  means the mediator accepted the frame and nothing more (R1.1).

  Seven tests. Four unit: payload shape, a blank reason omitted rather than sent
  as an empty string, the two codes distinguishable, and the payload validated
  against the *published* schema — the check that catches the implementation
  drifting from the spec it claims to implement.

  Three end-to-end over a real mediator, because only a peer holding the document
  demonstrates the feature: an admin removal arrives signed with its reason and
  deciding admin, a purge says it was a purge, and a self-leave sends nothing. Two
  of them first failed on `no active removal policy`, which was the paths
  differing exactly as specified — a purge deliberately skips the removal policy,
  which is why that one passed before the fixture seeded any.

- **app-state**: A third store for versioned, namespaced application state ([#1051](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1051))

Applications built on a VTA have had nowhere to keep versioned metadata.
  Adds `vta/app-state/{get,put,list,delete,get-many,put-many}/1.0` — a store
  beside the secrets vault and the credential vault, for JSON an application
  owns and the VTA does not interpret.

  Records are addressed `(contextId, namespace, key)`. The namespace scopes one
  application so several tools can share a context without colliding, and is the
  seam a per-namespace grant would later use — which is why it is part of the
  address rather than a prefix convention on the key. In 1.0 a namespace is
  collision avoidance and NOT a trust boundary: an application with write access
  to a context reaches every namespace in it, and the `put` and `delete` specs
  say so normatively. Isolation means separate contexts.

  Deliberately not built on `vta/memory/*`. `MemoryItem` is `{key, value}` with
  nothing to hang a precondition on, and its `list` returns the whole context —
  but the argument that settles it is that "forget everything" has to stay a safe
  thing to ask an agent, which it cannot be if account state lives there.

  Three properties are why this is a store rather than a field on an existing one.

  **One counter per `(contextId, namespace)`, not per record.** A record's
  `version` is the counter value its most recent write took, so one number is
  simultaneously the optimistic-concurrency token `expectedVersion` compares
  against and the watermark `sinceVersion` compares against. A per-record counter
  serves the first but cannot serve the second — two records' counters are not
  comparable, so no single number means "everything after this point" — and would
  have forced a second sequence kept consistent by hand. The cost is that a
  record's version jumps by whatever its neighbours consumed, which the wire
  contract states: versions are opaque and monotonic, never an edit count.

  **A failed precondition returns the current version AND value.** A bare
  rejection obliges a re-read, and the re-read races the next write; the pattern
  has no fixed point under contention. Returning the winner's view removes the
  race rather than narrowing it, and the spec makes it normative.

  **Delete leaves a versioned tombstone, and the tombstones are reaped.** Without
  one, a consumer pulling from a watermark learns of every create and update and
  never of a deletion, so deleted records resurrect on its next rebuild.
  Retention is `app_state.tombstone_retention_days` (default 30, matching the
  vault's `grace_days`) — a destructive window is an operator's choice, not a
  constant — and `list` advertises the configured value, since a consumer
  schedules against that number. The sweeper runs from the storage thread beside
  the ACL/consent/vault sweepers.

  The sweeper reaps a *prefix*, not a set: each namespace walks its tombstones in
  version order and stops at the first still inside the window. Reaping a later
  tombstone while leaving an earlier one would make the reap watermark
  unstateable — no single number would describe what survives, which is precisely
  what `watermarkTooOld` has to be able to say. `0` days disables reaping, and
  that is enforced at the call site rather than as a zero cutoff, which would mean
  the opposite.

  Version reservation is fsynced and re-seals the TEE integrity manifest, for the
  reason `vti_common::store::counter` gives for BIP-32 counters: a counter
  surviving only in the journal buffer can be re-derived after a crash and reissue
  a used value. Here a reused version means two records collide on one `appv:`
  index key, so one disappears from the change feed and every incremental consumer
  misses that change permanently, silently. A batch reserves a block and pays one
  fsync rather than N; writes that then fail leave gaps, which are safe and
  tested.

  Retry safety: reads are `ReadOnly`, `delete` is `RetrySafe` (a second delete
  finds a tombstone and deliberately takes no new version, so a watcher sees
  nothing), and `put`/`put-many` are `Keyed` — a `put` without `expectedVersion`
  does not converge, and the class is per URI, not per payload.

  Blobs are deliberately out of scope in 1.0; adding a `blobRef` is additive.

  Concurrency is a process-local lock per namespace, not a store-layer
  compare-and-swap. fjall takes an exclusive database lock so two processes cannot
  share a store, and the vsock protocol has no atomic opcode — its
  `insert_if_absent`/`swap` are already non-atomic fallbacks. A CAS today would be
  atomic exactly where the lock suffices and a warn-and-fallback exactly where it
  would need to be real. Recorded in the design note with what would change that.

  Schemas published upstream as trustoverip/dtgwg-trust-tasks-tf#252 and #253;
  this depends on the released trust-tasks-rs 0.11.2, pinned to a minimum patch so
  an older resolve fails as a stale dependency rather than as unspecced URIs.
  Conformance witnesses cover all six URIs, so nothing enters
  `UNSPECCED_DISPATCHED_URIS`.



### Changed

- Delete the Verifiable-prefixed credential tags that were never DTG types ([#1071](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1071))

`VerifiableMembershipCredential` and `VerifiableEndorsementCredential` are not
  DTG credential types and never were. The specification defines seven concrete
  subtypes; neither is among them, and nothing in this stack has ever issued
  either. They survived as a name, a pair of literals and a compatibility shim,
  and between them they broke cross-community recognition for every real
  presentation ([#1062](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1062)).

  Four places, one cause.

  **The SDK constant.** `VERIFIABLE_MEMBERSHIP_CREDENTIAL_TYPE` held the value
  `"MembershipCredential"`, with a doc comment explaining that the prefix in the
  name was historical and the tag did not have it. A constant whose name
  disagrees with its value is an invitation, and it was taken: someone reading
  the name hand-rolled `"VerifiableEndorsementCredential"` into the recognition
  path, where it matched nothing. Renamed to `MEMBERSHIP_CREDENTIAL_TYPE`, and
  `ENDORSEMENT_CREDENTIAL_TYPE` added beside it so the VEC tag has a home rather
  than being a literal at the point of use.

  **The compatibility shim.** #1063 added `LEGACY_TYPE_TAGS`, accepting both
  prefixed tags from peers predating the catalog adoption. Nothing is published,
  so no such peer exists — and a reference implementation that accepts a type the
  specification does not define reintroduces exactly the drift the function it
  sits in was written to prevent. Removed; the test that pinned the behaviour now
  pins its refusal.

  **The audit trail.** Emitted envelopes recorded `credential_type:
  "VerifiableMembershipCredential"` / `"VerifiableEndorsementCredential"` — tags
  no credential ever carried, in the one record meant to be authoritative after
  the fact. They now record what was issued.

  **The policy input.** `issuer_member` / `subject_member` were carried alongside
  `issuer` / `subject` for operator policies written against the pre-#1061 shape.
  There are no deployed operator policies to preserve, and two spellings of one
  concept is how the concept drifts. The duplicates are gone and the surviving
  fields carry `is_current`.



### Fixed

- **vta**: Three of the four responses the conformance layer found ([#1114](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1114))

Closes three of the four violations #1113 reported. The fourth is the vault
  pair, blocked on trust-tasks-rs 0.11.16 (dtgwg-trust-tasks-tf#268).

  `vta/webvh/dids/get/1.0` carried its record under `#[serde(flatten)]` since
  #849, to make the folded task a strict superset of the two shapes it replaced.
  That superset was readable by no conforming client: the response is
  `additionalProperties: false`, so a flattened record fails on all eleven
  members and the `ext` slot is unreachable. Its sibling settles which side
  moves — `dids/list` carries the same component nested under `dids` and has
  always conformed, so flattening made `get` the outlier in its own family.

  Both SDK client methods decoded the flat shape straight into
  `WebvhDidRecord`, so the workspace compiled clean while the wire broke. They
  now project the envelope. `webvh_get_did_round_trips_after_the_get_log_fold`
  predicted exactly this in its doc comment and caught it.

  `provision/integration/0.2` sent `null` for `adminTemplateName` and
  `webvhServerId`, the only two of five `Option<String>` members without
  `skip_serializing_if`.

- **vtc**: A null the schema forbids, and three fixtures that lied ([#1099](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1099))

Four entries close, and three of the four closed because the **ledger was
  wrong**, not because anything about the service changed. Drift **15 → 12**,
  with `join-requests/submit` narrowed from both sides to response-only.

  Found by making the conformance probe print the *actual* parse error for
  every drift entry rather than re-reading the notes — the same technique that
  surfaced the #1098 defect. The notes are prose and can be wrong in either
  direction; the schemas cannot.

  ## One real bug: a `null` where the schema says `object`

  `JoinRequest.policyDecision` is `Option<JsonValue>` with `#[serde(default)]`
  and no `skip_serializing_if`, so it went out as `"policyDecision": null` on
  every row that had no policy decision — which is every row in Phase 1.

  The component types it **`object`**, not `["object", "null"]` as it types the
  neighbouring `vpClaims` and `decision`. It is not required, so *absent* is
  how you say "no policy decision"; `null` is a type error. Now omitted.

  `JoinRequestSubmitBody.extensions` in `vta-sdk` had the identical shape — a
  bare `#[serde(default)]` `JsonValue` serialising `Value::Null` against a
  schema that types it `object`, so a minimal client's submit was
  non-conformant. The existing note had diagnosed this exactly and called it "a
  one-line fix in vta-sdk"; this is that line.

  Both are the null-into-`Option` class that shipped `keys/create/0.1` broken.

  ## Three fixtures that lied

  **`totalEstimate` was invented.** The `paginated()` helper hand-wrote
  `"totalEstimate": 12`. Nothing in the workspace ever sets `total_estimate` to
  `Some` — it is `skip_serializing_if = "Option::is_none"` and every producer
  passes `None`, so it has never reached the wire. The fixture made
  `endorsement-types/list` look non-conformant against a schema that simply
  does not define the member.

  **`endorsement-types/list`'s note blamed `createdByDid`**, which has been
  defined upstream since 0.11.8. The real error was the invented
  `totalEstimate`. Entry now `checked!`.

  **`community/profile/*`'s notes over-claimed.** `show` listed
  `relationshipIdentifierDefault` among its unspecced members — defined as of
  0.11.8. `update` claimed `fieldsChanged` was a divergence; the response
  schema defines it. That one is worth naming precisely, because it is a trap
  in how the probe reads: **a serde parse stops at the first unknown member and
  never reaches the rest**, so everything a note lists after the first is
  inference, not evidence. Both notes now say only what the schema actually
  refuses.

  ## What the remaining twelve are

  With the notes corrected, the residue is short and honest:

  - `communityDid` / `createdAt` on `CommunityProfile` — 2 entries, one change
  - `credential` / `expiresAt` not on the stored endorsement row — 2 entries,
    a storage decision (see #1098)
  - `factsTemplate`, `etag`, `deployedAt`/`sizeBytes`, the diagnostics
    transport half — 4 entries, service ahead of spec
  - `auth/recognise`, `install/claim/start`, `install/claim/finish`,
    `join-requests/submit` — 4 entries, genuine design questions

  ## Gates

  - `cargo clippy --workspace --all-targets -- -D warnings`
  - `cargo test --workspace --no-fail-fast` — the whole workspace, since this
    touches `vta-sdk`
  - `cargo fmt --all --check`

- **sdk**: Look for pnm sessions where pnm actually writes them ([#1087](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1087))
- **mcp**: Look the pnm session up under the key pnm actually writes ([#1083](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1083))

`vta-mcp --vta <slug>` — the invocation its own README documents — could
  never find a session. `pnm` stores every login under the keyring key
  `vta:<slug>` (`vta_keyring_key`, pnm-cli/src/config.rs), `cnm` uses
  `community:<slug>` for the same reason, and neither session backend adds
  a prefix on the way in or out. vta-mcp passed the bare slug, so the
  lookup missed and the operator was told they were not authenticated.

  That failure mode is worth naming: from the operator's side it is
  indistinguishable from an expired login. They run `pnm auth status`, are
  told they are fine, and are none the wiser.

  The rule now has one definition, `agent_connect::pnm_session_key`, next
  to the connect ladder both agent-side bridges share — a second consumer
  (the agent-memory service) hit exactly this. It is idempotent, so an
  operator who worked the bug out and passes `vta:mine` keeps working.

- **vtc**: Tell a rejected applicant why, on the one path built to recover it ([#1058](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1058))

`project_status` projected `needs` / `presentationDefinition` for a
  `Deferred` request and bare `{requestId, status}` for a `Rejected` one.
  The evidence existed on both rejection paths and neither reached the
  applicant through the poll.

  The correlated `VerdictResponse` was the only place a `{code, reason}`
  ever reached an applicant, which makes it a one-shot delivery: a socket
  that was down, a reply that was lost, or a rejection an admin took hours
  later, and the reason was unrecoverable. The poll is the natural recovery
  path and it was the one path that deliberately stripped it. An
  admin-rejected applicant could never learn why at all — `reject_pending`
  emits no message to them, and the operator's reason reached only the
  audit log, which no applicant can read.

  Both paths now write one `JoinRequest::decision` field — code, optional
  reason, and the decision's own timestamp — and the poll projects it. One
  field rather than two, because the whole failure was two producers of the
  same fact drifting apart. It is deliberately *not* `policy_decision`: an
  operator's decision is not a policy verdict, and recording it as one
  would make the audit trail lie about where the refusal came from. The
  admin path carries `ADMIN_REJECT_CODE` ("admin-reject"), which is what
  lets a client tell "the rules refused you, satisfy them and re-apply"
  from "a human refused you, re-applying changes nothing".

  `decidedAt` is separate from the response document's `issuedAt` because
  `issuedAt` is when *this document* was produced. For an admin reject the
  two diverge by however long the applicant takes to poll. The test proves
  the distinction the only way it can be proved: poll twice, and `issuedAt`
  moves while `decidedAt` names the same moment.

  Rows rejected before this existed are not abandoned. An auto-deny always
  wrote the serialized `Deny` verdict, so `decision_for_applicant` falls
  back to it — recovering the code and reason, and reporting `decided_at:
  None` rather than back-filling a timestamp that would tell the applicant
  they were rejected the instant they polled. A legacy *admin* reject has
  nothing to recover and answers exactly as it did before.

  Also adds `VerdictResponse::deny`, which the issue asked for alongside:
  the deny shape had `allow` and `refer` constructors but was hand-assembled
  at its one call site, and this change gave it a second producer.



### Chore

- **vtc**: Recognise and submit 0.2 — drift reaches zero ([#1105](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1105))

Retargets `auth/recognise` and `join-requests/submit` to the `0.2` versions
  published by trustoverip/dtgwg-trust-tasks-tf#264.

  **Drift 2 → 0.** Every Trust Task this service binds now speaks the schema it
  publishes, on both sides. It was 33 when the sweep landed yesterday.

  ## Why these two moved the spec rather than the service

  Both were recorded as "the service's shape is arguably stronger". Reading them
  properly, one was not arguable at all.

  **`auth/recognise/0.1` took `{vec, vmc}` — a replayable impersonation token.**
  Both credentials are bearer artifacts, so anyone who obtained the pair from a
  relayed join, an audit log, a backup or a compromised device held everything
  the payload required, and the recognising community could not distinguish the
  subject from someone holding a copy. No proof of key possession, no freshness,
  no audience binding: one captured pair worked at every community that
  recognised the issuer, indefinitely. This service has required a holder-signed
  presentation — nonce, `domain`, holder-is-subject — since P0.2. `0.2` publishes
  that.

  **`join-requests/submit/0.1` returned `status: const "pending"`** where a
  submission has four outcomes. `0.2` returns a verdict.

  ## One real find in the retarget

  `VerdictEffect` serialised **`request_more`**, but I had specced `requestMore`
  in #264, and SPEC §4.10 rule 4 is explicit that specification-defined decision
  values are lowerCamelCase. So the wire was wrong.

  The fix is not to change either vocabulary wholesale, because there are two of
  them and both are correct in their own language:

  - **Rego authors verdicts.** Operator-written policy returns
    `{"effect": "request_more", …}`, and snake_case is that language's idiom —
    `vtc-service/policies/default/join.rego` and every deployed policy alongside
    it. Re-casing there would break operator policies to satisfy a wire rule
    that does not govern them.
  - **The wire publishes `requestMore`**, per §4.10 and the new
    `vtc/_shared/0.1/ceremony#VerdictEffect`.

  `VerdictEffect` is the boundary: it now serialises camelCase and keeps
  `#[serde(alias = "request_more")]` so anything producing the policy spelling
  still deserialises. That is the same storage-versus-wire split `EndorsementRow`
  ([#1096](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1096)) and `GenerationRow` ([#1095](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1095)) draw, applied to a policy vocabulary
  instead of a keyspace.

  The test that caught it now demonstrates the boundary instead of hiding it —
  its inline Rego authors `request_more`, and it asserts the wire says
  `requestMore`, with a comment saying why both are right.

  ## The table at zero

  `KNOWN_DRIFT_COUNT` stays asserted at `0`. It can no longer shrink, so the only
  thing it can do is catch a regression — which is what an asserted count is for.
  A new task that diverges must add a `drift!` entry and raise it deliberately.

  The `drift!` macro, `Side`, and `Conformance::KnownDrift` are now unconstructed
  and kept with `#[allow(dead_code)]` rather than deleted. They are the
  vocabulary for *recording* a divergence, and a table with no way to say "this
  diverges, on this side, for this reason" invites the next author to leave a
  real divergence unrecorded rather than write the machinery back. Deleting them
  would make the zero look permanent instead of current.

  ## The header, rewritten

  It described a 33-entry backlog. It now records how the 33 actually closed,
  because the distribution is not what the sweep predicted:

  | | |
  |---|---|
  | **10** | by correcting this service's wire shapes |
  | **19** | on dependency bumps alone — the specs had moved and the notes had not |
  | **4** | by correcting the **specification**, once the published shape turned out to be the weaker one |

  That last group is the one worth remembering. A conformance table makes
  divergence visible and says nothing about which side is wrong, and *"the schema
  requires X and the service omits X"* reads as an accusation against the
  implementation. Twice it was the schema. Once — `install/claim` — the
  requirement had been built, found impossible in a browser, and removed two
  months **before** the specification demanding it was written, and this table
  recorded that as the service being behind on a security control.

  ## Gates

  - `cargo clippy --workspace --all-targets -- -D warnings`
  - `cargo test --workspace --no-fail-fast`
  - `cargo fmt --all --check`

- **deps**: Bring every dependency to latest, collapsing two duplicates ([#1055](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1055))

`cargo outdated` reported 13 direct dependencies behind and `cargo update`
  had 36 compatible updates waiting. Both are now clear: `cargo outdated`
  reports "All dependencies are up to date".

  Two of these were not cosmetic.

  **p256 was duplicated in the build.** Our crates declared `0.13` while
  `affinidi-crypto` — reached through `affinidi-data-integrity` and the TDK —
  already pulled `0.14`, so the graph carried two copies of a curve
  implementation. The lock now holds a single `p256 0.14.0`. The bump brings
  `elliptic-curve` 0.14 and `ecdsa` 0.17, which rename the SEC1 family:
  `EncodedPoint` -> `Sec1Point`, `From/ToEncodedPoint` -> `From/ToSec1Point`.
  Renamed across `vta-keys`, `vta-service` and `vti-webauthn`.

  **tokio-tungstenite was load-bearing, not incidental.** `vta-mobile-core`
  depends on it solely as a feature enabler: iOS has no native trust store, so
  `rustls-tls-webpki-roots` has to be on graph-wide or the mediator WebSocket
  fails with "no native root CA certificates found". Features unify per major
  version, so the declaration only works while it matches the version
  `affinidi-messaging-sdk` pulls — and the SDK moved to 0.30 in this refresh.
  Updating everything *except* this one would have stranded the enabler and
  broken iOS `wss://` silently.

  The rest:

  - `rcgen` 0.13 -> 0.14 (dev). `signed_by` takes an `Issuer` rather than a
    `(certificate, key)` pair, and `self_signed` borrows instead of consuming.
    The mdoc IACA test helper builds its issuer with `Issuer::from_params`,
    which is also a more direct statement of what it wanted.
  - `syn` 2 -> 3 (dev). No source change; syn 3 was already in the graph via
    `trust-tasks-rs`.
  - `rmcp` 1.7 -> 3.1.4. Two majors, one rename: `Content` -> `ContentBlock`.
    The `#[tool_router]` / `#[tool_handler]` macro surface the crate is built
    on is unchanged.
  - 36 lockfile updates, including `trust-tasks-rs` 0.11.3 (the corrected
    `vta/app-state` error taxonomy from dtgwg-trust-tasks-tf#253) and the AWS
    SDK set. `rustls-pemfile`, one of the unmaintained crates `cargo audit`
    flags, drops out of the graph entirely.

  Two deliberate choices where the shortest path was worse:

  `vti-webauthn` keeps parse-then-validate rather than collapsing to the
  one-shot `PublicKey::from_sec1_bytes`. That call merges "malformed SEC1
  encoding" and "valid encoding, point not on the curve" into one error, and
  those say different things to whoever reads the log — a broken client versus
  a point somebody chose.

  BIP-32 P-256 derivation replaces the now-deprecated `FieldBytes::from_slice`
  with `TryFrom` and a real error arm. The input is a fixed 32-byte window of a
  SHA-512 HMAC so it cannot fail, but the length check is now explicit rather
  than resting on a panic inside a deprecated helper.

  Unchanged and still suppressed: the four `cargo audit` advisories ignored in
  `deny.toml`, all transitive through the AWS SDK's hyper 0.14 / rustls 0.21
  path. `cargo deny check advisories` passes.



## [0.28.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-sdk-v0.27.0...vta-sdk-v0.28.0) — 2026-08-22


### Added

- **discovery**: Serve canonical capability negotiation, drop the parallel REST route ([#1042](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1042))

* feat(discovery)!: serve canonical capability negotiation, drop the parallel REST route

  Clients had no way to ask a VTA which Trust Tasks it serves. Calling one it does
  not is a 30-second DIDComm timeout with no explanation — the failure mode
  `didhosting-083-retired-task-uris` describes.

  The answer already existed and we were not serving it. `trust-task-discovery/0.1`
  is a published family in the dtgwg-trust-tasks-tf registry, carried by the
  `trust-tasks-rs` we already depend on: a client sends slug-glob patterns (`*`,
  `acl/*`, or an exact slug) and gets back the Type URIs the responder serves plus
  the framework version it targets. Nothing needed inventing, and — unusually for a
  new family — nothing needed specifying upstream first.

  The VTA answers **from its own dispatch table**. `dispatched_uris()` was already
  generated by `dispatch_table!` from the same declarations that build the match
  arms; it is now available at runtime rather than only under `cfg(test)`. A
  hand-maintained list would be a second source of truth, and an overstated
  discovery response is worse than none: a client believes a task is available and
  finds out on a live call.

  **What this does not do.** It answers "do we both know this task, at this
  version". It does not answer "do we agree how its payload is spelled" — two peers
  can both serve `contexts/create/1.0` and still disagree about `basePath` vs
  `base_path`, which is what #1033 was. Said plainly on the SDK method, because the
  obvious misreading is that discovery makes wire skew detectable.

  ## GET /capabilities is gone

  Nothing consumed it: `VtaClient::capabilities` goes over `rpc_tt` like every
  other task, and no doc or downstream reads the route. A REST route running
  parallel to a Trust Task is precisely the shape #1020 removed everywhere else —
  the Trust-Task surface is already reachable over REST at
  `POST <base>/trust-tasks`.

  Removing it also dissolved the reason #1034 deferred folding
  `CapabilitiesResponse`: the hesitation was re-casing a public discovery endpoint
  whose readers nobody can enumerate. With the endpoint gone the only consumers
  left decode this very struct, so the fold is free and taken here.

  ## Both remaining inert aliases folded

  `UpdateRetentionBody` too, so `audit/update-retention` stops taking a snake_case
  request and returning a camelCase response — an asymmetry nobody chose, in one
  file, one screen apart. This is a request body, so the risk runs the other way: a
  client on this version sends `retentionDays` and an agent predating the change
  rejects it. That is the same trade #1000 made for every request body it folded;
  it is taken deliberately rather than inherited.

  `INERT_BY_DECISION` in the census is now **empty**, which is the intended end
  state rather than a coincidence.

  ## Notes for review

  - The `openapi_spec_describes_registered_routes` assertion was pinned on
    `/capabilities` as "the first route migrated to OpenAPI-aware registration".
    Re-pinned on `/auth/challenge` rather than deleted: what it actually asserts is
    that `routes!()` registration still lands operations in the served document,
    and that property did not leave with the route.
  - The two `capabilities_*` integration tests now drive the Trust-Task surface.
    The properties they assert — authenticated, reports features — are unchanged;
    only the door is.
  - A wrong assumption caught by its own test: ACL folded to the **top-level**
    canonical family, so the slug is `acl/grant/0.1`, not `vta/acl/grant/0.1`. The
    first draft of both the handler test and the conformance witness used the
    VTA-namespaced form. It fails silently — a wrong pattern returns an empty list,
    not an error — so the corrected test asserts the negative case too.



### Changed

- **discovery**: Retire vta/discovery/capabilities — every member had a better home ([#1044](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1044))

* refactor(discovery)!: retire vta/discovery/capabilities — every member had a better home

  #1042 reduced this task to `version` + `webvhServers` + `didCreationModes` and
  left a question: does what remains still earn a task? Audited each member. No.

  - **`version`** — `GET /health/details` already reports it, at the same auth
    level and from the same `env!("CARGO_PKG_VERSION")`. A duplicate, though a
    benign one: both read the same constant, so they cannot disagree.

  - **`webvhServers`** — a *lossy* duplicate of `webvh/servers/list/1.0`.
    `WebvhServerInfo {id, label}` against `WebvhServerRecord {id, did, label,
    createdAt, updatedAt}`, from the same `webvh_store::list_servers` call. The
    obvious objection is auth — a cheap summary for callers who cannot see the
    full list — and it does not hold: `list_webvh_servers` is commented "Any
    authenticated user can list servers", the same gate. No production code read
    it from here; `vtc-service`'s setup wizard already called the dedicated task.

  - **`didCreationModes`** — dead, and misleading. No consumer in this repo or
    OpenVTC. Derived entirely from `cfg!(feature = "webvh")`, which is the same
    species as the `features` booleans #1042 removed. Its vocabulary —
    `vta-built` / `template` / `final` / `user-specified-keys` — appears nowhere
    else in the codebase; it dates to #22 in April and predates `WebvhPathMode`,
    which is the axis DID creation actually turns on. The fixtures "covering" it
    asserted `["webvh"]`, a fourth vocabulary again, so its test coverage was
    fiction of the same kind #1033 was about.

  So the task is gone, along with the `discovery/1.0/*` DIDComm protocol beside
  it — which was routed unauthenticated, worth noting on the way out.
  `trust-task-discovery/0.1` ([#1042](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1042)) answers the one question this surface should
  have been answering.

  This also discharges the `UNSPECCED_DISPATCHED_URIS` entry by deletion rather
  than by a spec, which is the cheaper way to shrink that list when the answer is
  "this should not exist".

  ## Consumers

  `vta-mcp`'s `vta_capabilities` was the only one, and it becomes
  `vta_supported_tasks`. Not a rename: the old tool promised four answers, three
  better held elsewhere and one describing nothing. What an agent needs before
  calling an operation is whether the VTA serves it, and the tool description now
  says so — including that calling an unserved task fails as a transport timeout
  rather than a clear error, which is the reason to ask first.

  ## On retiring rather than deprecating

  `deprecation.rs` sets this repo's practice for removing a REST route: mark it,
  count usage, delete on an observed zero rather than a guessed date. There is no
  equivalent for Trust Task URIs, so that path was not available. The
  justification here is the audit — zero consumers across both repos, plus a
  vocabulary that corresponds to nothing — rather than a metric. Worth saying
  plainly, because it is a weaker instrument than the one the REST routes get.

  While there: the `GET /capabilities` row in that same table was left dangling by
  #1042, matching a route that no longer exists. Nothing catches that — no test
  ties the table to the live router — so it is removed by hand.

- **sdk**: One wire, one type — decode the agent's own bodies ([#1037](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1037))

#1033 fixed eleven Trust-Task call sites where the client's decode type had
  drifted from the agent's body, breaking every `pnm contexts` command, four `pnm
  keys` commands, seed rotate/list and the MCP surface. It fixed them with `serde`
  aliases, which restores compatibility without removing the hazard: the wire still
  had two structs, and either could move alone again.

  The audit behind it found the correlation was total. Of 61 call sites, the 50
  decoding a shared `protocols::**` type were all fine and all 11 with a private
  type in `client/types.rs` were broken. Not a coincidence to test around — the
  defect itself.

  Each of the eight duplicates is now a `pub use` of the body the agent
  serializes. The client-facing names are kept, so `get_context` still returns
  something called `ContextResponse`; what changed is that the name now refers to
  `CreateContextResultBody` rather than a copy of it. Two ends cannot disagree when
  there is one end.

  Two things fell out that a field-by-field mirror had been hiding:

  - **`vta contexts create --parent x` rendered no parent.** `bootstrap_cli.rs`
    carried an adapter whose comment said the two types were "identical on the
    wire". They were not: the client struct had no `parent`, so the adapter dropped
    it silently on every offline context render. Deleting the adapter fixes it, and
    the compiler found it — `missing field `parent`` was the first error after the
    re-export landed.

  - **`{:?}` on a key-secret response printed the raw private key.** The client's
    `GetKeySecretResponse` derived `Debug`; the agent's `GetKeySecretResultBody`
    hand-writes it to redact `private_key_multibase`, precisely so a caller cannot
    tracing-log it by accident. Sharing the type inherits the redaction.

  The ACL pair deliberately stays two types. `AclEntryResponse` renames `subject`
  to `did` and `scopes` to `allowed_contexts` and converts RFC 3339 to the epoch
  seconds the CLI speaks — it is an adapter with real logic, not a mirror, and it
  cannot be re-exported. It keeps its seam cases, which matters more now: an
  adapter that computes can be wrong in ways a copy cannot.

  Request builders also stay local. `CreateKeyRequest` and friends exist for
  ergonomics and *produce* the wire shape rather than describing it, so they cannot
  drift the same way.

  ## The tests shrink, on purpose

  Nine cases in `trust_task_decode.rs` are deleted. They serialized the agent's
  body and decoded it into the client's type; with one type on both sides that now
  asserts `serde` round-trips a type through itself — true of every type
  everywhere, and no longer a fact about this codebase. Keeping them as
  reassurance would be keeping exactly the kind of vacuous assertion that let
  `acl/update` ship broken through three PRs.

  What remains is the part that is still real: the ACL adapter, and the legacy
  snake_case direction. That second one is arguably stronger than before — it now
  exercises the intake aliases on the **agent's** types, which is where every
  consumer's backward compatibility comes from, not just this client's.

  `COVERED_BY_SEAM_TEST` in the census drops from nine names to one. That is the
  shape the census was built for: the list shrinks as duplicates are removed rather
  than growing as they are papered over. The census itself is unchanged and was
  re-verified against an injected duplicate after the collapse — it still refuses a
  new client-private decode type.



### Fixed

- **sdk**: Finish the seeds/list fold, and make an inert alias fail the build ([#1040](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1040))

* fix(sdk): finish the seeds/list fold, and make an inert alias fail the build

  `seeds/list` emitted a body that disagreed with itself:

      {"seeds":[{"id":1,"status":"active","created_at":"…"}],"activeSeedId":1}

  #1000 folded Trust Task payloads to lowerCamelCase and gave 126 members an
  alias for the retired spelling. `SeedInfo` got the aliases and not the
  `rename_all` that gives them meaning, so it kept emitting snake_case with
  `alias = "created_at"` sitting on a member already called `created_at` — while
  `ListSeedsResultBody` around it moved. Adding the `rename_all` finishes that and
  activates the aliases, so a producer still sending snake_case keeps decoding.

  Safe to finish precisely because the containing body already moved: the same
  REST route (`GET /keys/seeds`) has emitted `activeSeedId` since #1000, and the
  client type is the agent's own since #1035, so both ends move together.

  ## The class, not the instances

  An alias equal to its member's serialized name accepts what would be accepted
  anyway. That is not untidiness — it is how this shipped. The code compiled,
  every test passed, and the attribute reads as though the fold happened; a
  reviewer seeing `alias = "created_at"` reasonably assumes the member is now
  `createdAt`. Both known instances were found by hand, months later, while
  auditing something else.

  `tests/inert_alias_census.rs` decides it from the source instead, for every wire
  type under `protocols/` at once. Verified non-vacuous in all three directions
  rather than assumed:

  - reverting this fix reports `SeedInfo.created_at` and `.retired_at` — it would
    have caught #1000's miss;
  - an alias injected into an already-folded struct is reported;
  - an exception entry for a type that no longer needs one is reported, so the
    allow-list cannot rot into a blanket excuse;
  - and floors on files scanned and aliases parsed, so a `syn` upgrade or a moved
    directory leaves it red rather than green over nothing.

  ## It immediately found a third instance

  `UpdateRetentionBody.retention_days`, which nobody knew about. One screen down in
  the same file its sibling `RetentionResultBody` IS folded, and even the empty
  `GetRetentionBody` carries `rename_all` — so `audit/update-retention` takes a
  snake_case request and returns a camelCase response. Plainly a miss.

  Deferred anyway, with `CapabilitiesResponse`, both recorded in
  `INERT_BY_DECISION` with their reasons and tracked in #1039. The line is whether
  the fold *completes* a change already made or *starts* a new one:

  - `SeedInfo`'s containing body already moved — finishing it removes an
    inconsistency.
  - `CapabilitiesResponse` has not moved at all, and is served on `GET
    /capabilities` as well as the task surfaces, so folding it is a fresh REST wire
    change of exactly the kind #1000 deferred.
  - `UpdateRetentionBody` is a *request* body. Folding changes what clients SEND,
    and an agent predating the change rejects the new spelling — the opposite
    direction from `SeedInfo`, where a new agent's output is absorbed by aliases
    the client already holds.

  Deleting an inert alias is the wrong repair in every case, and the census says
  so where someone would try it: the alias is the only thing that lets an older
  producer keep working once the fold lands.

  The `client_rest.rs` seeds fixture is re-cut. It carried a comment explaining
  that `seeds[]` was snake_case inside a camelCase `activeSeedId` because that was
  what the agent really emitted; that asymmetry is gone, so describing it would now
  be the fiction.



## [0.27.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-sdk-v0.26.0...vta-sdk-v0.27.0) — 2026-08-21


### Fixed

- **sdk**: Decode the Trust-Task responses the agent actually sends ([#1033](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1033))

`pnm contexts create` fails against any agent built since #1000:

      Protocol error: trust-task response decode: missing field `base_path`

  #1000 folded Trust Task payloads to lowerCamelCase per SPEC §4.10 and excluded
  `client/types.rs` as REST bodies whose casing "no published schema pins". The
  exclusion was drawn by file path, and the path was stale: `rpc_tt` carries the
  same Trust-Task document over REST, DIDComm and TSP alike, so `ContextResponse`
  is a Trust-Task decode target and a published schema does pin it. The agent moved
  to `basePath`; the client went on demanding `base_path`.

  Eleven call sites across eight types, every one a required field with no
  `default`, so they fail hard on every transport rather than degrading:

  - contexts create / get / update / update-did / list — all of `pnm contexts`
  - keys sign / rename / revoke / export-secret
  - seeds rotate / list (`activeSeedId` only)

  `vta-cli-common` and `vta-mcp` consume these, so `pnm`/`cnm` key management and
  the MCP tool surface are equally affected. The user who reported it hit contexts
  first and would have hit `keys sign` next.

  Aliases rather than `rename_all`: this is the same Postel fold #1000 used, it
  changes nothing about what the SDK emits, and it keeps working against an agent
  that has not taken the change. `SeedInfoResponse` gets aliases it does not yet
  need, because its counterpart `SeedInfo` is the one payload struct #1000 left
  unfolded — when that lands, this type should not be what breaks.

  The casing is the symptom. The defect is that one wire has two structs, so
  either end can move alone; the 50 Trust-Task call sites that did NOT break are
  exactly those where client and agent decode the same type. Collapsing each pair
  onto one type is the real repair and is not attempted here — it changes public
  type identity for two downstream crates. The module note records that.

  ## Why no test caught a total outage

  Three layers each stopped one step short of the join. The conformance harness
  checks the agent against the published schema — green, its witness correctly
  said `basePath`. The SDK's client tests check the client against a hand-written
  mock — also green, because the mock still said `base_path`. Nothing compared the
  two fixtures, so they disagreed for two days while both suites passed.

  `vta-sdk/tests/trust_task_decode.rs` is that missing seam: it constructs the
  agent's own body type, serializes it as the agent would, and requires the
  client's own decode type to accept the bytes. No JSON literal appears in the
  derived cases, so there is no third spelling to drift. Verified non-vacuous —
  with the aliases reverted, 9 of 9 derived cases fail, each naming the CLI surface
  that is broken and printing the exact wire.

  The stale fixtures are re-cut to what an agent really sends, including the
  asymmetry a uniform pass would have got wrong: `seeds[]` stays snake_case inside
  a camelCase `activeSeedId`, because that is what the half-folded type emits.
  Re-cutting them would have silently retired the only coverage of the snake_case
  intake aliases, so that direction is now asserted explicitly by name —
  `a_legacy_agent_snake_case_response_still_decodes` — rather than left implicit in
  a fixture someone would later tidy.

  Conformance witnesses stay hand-written: they anchor the types to the spec, and
  deriving them from the types they check would make them vacuous.

  Two adjacent findings, left alone as neither is a break: `CapabilitiesResponse`
  and `SeedInfo` both received `alias` attributes in #1000 without the
  `rename_all` that would give them meaning, so both still emit snake_case and
  their aliases are inert. Filed rather than folded in, since fixing them changes
  the wire.

- **sdk/cli**: A credential store that cannot be opened must not read as "never logged in" ([#1032](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1032))

All four binaries treated an unavailable OS credential store as a warning
  and carried on. What happened next was worse than a silent fallback:
  `KeyringBackend` stayed registered, every `Entry::new` returned
  `NoDefaultStore`, and `SessionBackend::load` swallowed it and returned
  `None` — so the tool behaved exactly as though the user had never logged
  in. A silent fallback at least stores something; this silently forgets.
  OpenVTC hit the user-facing end of it: a profile kept in the Linux kernel
  keyring did not survive a reboot, and the error told the user to check
  their network.

  The four call sites are byte-identical, but their consequences are not,
  so the fix is not:

  - `pnm` and `cnm` keep their session — the admin DID and its private key
    — in the credential store and nowhere else. They now exit at startup
    via `keyring_init::install_default_store_or_exit`, which is the whole
    point: there is nothing they can usefully do next.
  - `vta` and `vtc` never construct an SDK `SessionStore`; they use the
    fjall-backed `KeyspaceSessionStore`, and their keyring use is the seed
    store, one of eight `[secrets] backend` options. Which one is in play
    is not known until config loads, long after `main` starts, so hard
    failing there would break every deployment on aws/gcp/azure/vault/k8s
    running on a host with no credential store — the normal server shape.
    They get `warn_store_unavailable`, and `KeyringSeedStore` — which
    already failed closed — now says which subsystem broke rather than
    "failed to create keyring entry".

  The second half is `FileBackend`. `default_backend` ended in an
  `#[allow(unreachable_code)]` fallback into it whenever no backend feature
  was enabled, writing the admin private key to `sessions.json` as
  plaintext at the process umask, announced by a WARNING on every access —
  which is to say, invisible. `pnm`'s own bootstrap-secrets path has always
  used 0600; the inconsistency was inside one tool.

  That fallback is gone. A build with no session store gets `RefusingBackend`,
  which refuses to save rather than inventing somewhere to put a private
  key. `FileBackend` is now reachable only by explicit choice — the
  `config-session` feature, or `VTI_SECURE_STORE=file` at runtime — and
  creates its file at 0600 inside a 0700 directory *before* writing, since
  writing and then hardening leaves a window at the umask. An existing
  world-readable file from an older build is re-hardened on the next write.

  The runtime override exists because requiring a rebuild to run on a
  headless host creates pressure to disable the check rather than make a
  choice. It parses strictly: `os` or `file`, and anything else — including
  a near-miss like `plaintext` — resolves to neither and refuses. Asking
  for `os` on a build with no `keyring` feature refuses too, rather than
  quietly substituting a file.

  One explanation now serves every tool, in `vta_sdk::secure_store`, taking
  the error as `Display` so it is available without the `keyring` feature —
  OpenVTC renders the same text and honours the same override, which was
  the stated goal: identical secret handling across vta, pnm, openvtc and
  vtc, hard failure rather than a fallback to open text files.



## [0.26.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-sdk-v0.25.1...vta-sdk-v0.26.0) — 2026-08-20


### Added

- **service**: Retire an orphaned webvh slot, on evidence rather than assertion ([#1022](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1022))

`vta/webvh/servers/reconcile` names two divergences and repairs
  neither, deliberately — they want opposite remedies. This implements the
  remedy for one: the orphan, a slot a hosting server serves for this VTA
  that the VTA has no record of.

  Nothing could repair that state, and the reason is structural. Every
  delete addresses a DID through its local record, which is what says
  which server to talk to and which keys to sign with; an orphan is
  defined by that record's absence, so the lookup fails before a request
  leaves the VTA. Nor can the caller go around it — the VTA holds the host
  credentials. A slot both parties can see, and neither can remove.

- **service**: The vta/services task family, and the twenty routes it supersedes ([#1017](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1017))

* feat(service): the vta/services task family, one verb per task

  Eight handlers covering what twenty `/services/*` REST routes did. The
  operations are untouched — `operations::protocol::*` already implements each
  transport — so this is the parameterised door onto them, not new logic.

  `service` names the transport and `config` carries its settings, so the fan-out
  happens here rather than on the wire. That is what keeps a fifth transport to a
  config variant instead of four new specs.

  **The drain guard is the part that matters.** Tearing down a mediator discards
  whatever is in flight through it, so `disable`/`update`/`rollback` on didcomm
  pass a `DisableTransport` that decides whether the 1-hour floor applies. The
  REST route hardcodes `Rest` and the DIDComm handler hardcodes `Didcomm`,
  because each IS that path; a trust task is not, so it reads the arrival
  transport from the dispatch spine.

  The spine records confidentiality, not binding: DIDComm and TSP are both
  `EndToEnd` and it cannot tell them apart. `EndToEnd` therefore maps to
  `Didcomm`, which OVER-applies the floor to a TSP-carried disable that does not
  strictly need it. Deliberate: under-applying tears down the mediator a request
  arrived through and discards the reply to the very task asking for it, while
  over-applying only delays a teardown the operator can repeat. The ambiguous
  case takes the cheaper mistake.

  Three shapes the generated types forced, each documented where it lands:

  - `ServiceMutationResult` and `RollbackKind` are duplicated per family —
    identical shapes, distinct types. Mutation results round-trip through the wire
    form rather than being hand-copied three times; rollback kinds go through a
    macro that names the variants, so a divergence is a compile error.
  - Rollback may write nothing. Its `noOp` arm has no `logEntryVersionId`, which
    is why it has its own result type, and the witness uses exactly that arm.
  - `handshake_timeout_secs` is `NonZeroU64` — the schema's `minimum: 1` — so the
    default is constructed, not unwrapped.

  **Operation futures are boxed, and that is load-bearing.** These handlers fan
  out to four sizeable futures, awaited inside a dispatch match that already
  carries every other task's state machine. Inlining them grew the frame past the
  default 8 MiB stack and aborted an unrelated mock_vta test with a stack
  overflow — which reads as infinite recursion and is not.

- **sdk**: Hold one idempotency key across every attempt of an operation ([#1012](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1012))

The VTA deduplicates keyed Trust Tasks on an `idempotencyKey` ([#1011](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1011)).
  That only helps if the retry carries the *same* key as the attempt it is
  retrying — and a hand-rolled retry loop structurally cannot do that,
  because it re-invokes a client method that builds a fresh document each
  time. Minting the key inside the method has the identical problem the
  envelope id already has: attempt two gets a new one, the VTA sees an
  unrelated request, and the second durable effect happens anyway.

  So the key has to be scoped *outside* the call. `VtaClient::idempotent`
  mints one, holds it in a task-local for the duration of a closure, and
  retries transient faults inside that scope:

      let key = client.idempotent(|| client.create_key(req.clone())).await?;

  Every dispatch the closure makes carries the same key. A task-local
  rather than a parameter because it has to reach all twenty-odd typed
  methods without changing twenty signatures, and because it is genuinely
  ambient — it belongs to the operation, not the call.

  The key is attached only when the task is one a second execution would
  actually harm (`retry_safety`); attaching it to a read would cost the
  VTA a dedup record and buy nothing. It goes top-level beside `id`, where
  the VTA reads it from `TrustTask::extra` and a Data-Integrity proof
  covers it — so a relayer cannot rewrite it to split one operation
  into two.

  ## One retry owner

  Retry layers compose badly. The messaging delivery layer already retries
  a durable outbox with backoff underneath this, so an application loop on
  top multiplies attempts against a server that dedups at neither. This is
  the application-layer owner: bounded at 3 attempts, backed off, and
  honouring the server's `retryAfter` up to a 30s cap — an unbounded wait
  on a server-chosen value is a stall the server can trigger at will.

  Callers should use it *instead of* their own loop, not around one.

  ## BREAKING CHANGE

  `VtaError` gains an `Unavailable { retry_after }` variant (exhaustive
  enum), reported by cargo-semver-checks so the release moves the
  compatibility field rather than shipping it as a patch.

  It is typed rather than folded into `Protocol(String)` because it is the
  one wire rejection meaning "ask again" rather than "this failed" — the
  idempotency layer returns it while a first attempt on the same key is
  still running. A retry loop reading it as terminal gives up on precisely
  the answer it was told to wait for. The REST leg parses the error
  document before the status (R3.7), so without this the `unavailable`
  code collapsed to a string and its 503 never surfaced.

- **sdk**: Classify what a lost reply costs every Trust Task ([#1010](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1010))

A client that retries a timed-out request is doing the right thing — the
  dominant transport fault is a request that never arrived. The dangerous
  case is the other one, where the VTA processed it and only the reply was
  lost, and whether that is harmful depends entirely on the operation.
  Deleting an already-deleted DID is free; creating a second auto-assigned
  `did:webvh` is not, because the first stays published in the log with
  nobody holding a reference to it.

  Callers currently cannot tell those apart, so they guess. This adds the
  property as data: `RetrySafety` over all 148 URIs in `ALL_URIS`, with a
  census test that fails if a task joins the catalog unclassified — the
  same discipline that pins `REST_ROUTED_URIS`.

  Four classes, drawn around the question a retry layer actually asks:

  - `ReadOnly` — no durable effect.
  - `RetrySafe` — mutating, but a repeat is harmless: it either converges
    on the same end state (revoke, disable, delete) or leaves an inert,
    self-expiring duplicate (a spare auth challenge). Deliberately not
    named "idempotent", because the second half is not.
  - `Keyed` — non-convergent: a repeat leaves a second durable artefact
    that persists and matters. Needs an idempotency key.
  - `KeyedSecret` — as `Keyed`, but the response carries secret material,
    so the response must never be cached. Deduping the effect without
    turning a dedup store into a second place mnemonics and sealed
    bundles live.

  That last class is the one worth arguing about. Result-caching
  idempotency wants to replay the stored response, and for
  `seeds/export-mnemonic`, `backup/complete-export` and
  `provision/integration` that would mean persisting the secret a second
  time, indefinitely, to serve a retry. The effect is still deduped; only
  the replay is refused.

  Where convergence is not obvious from an operation's contract it is
  classified `Keyed` rather than `RetrySafe`. The asymmetry is nearly
  free — an over-classified task costs one dedup record, while an
  under-classified one loses the protection in exactly the rare case the
  table exists for.

  Classification alone gates nothing: it changes how a *keyed* request is
  handled, and a request carrying no key behaves exactly as it does today
  on every task in the table. Nothing consumes this yet; the VTA-side
  dedup store and the client-side key are the follow-ups.

- **service**: Signal every superseded REST route, from one layer ([#1007](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1007))


### Fixed

- **sdk,service**: Serve and use the Trust-Task path the binding asks for ([#1020](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1020))

`trust-tasks-https` POSTs to `<serviceEndpoint>/trust-tasks`, where
  `serviceEndpoint` is what a VTA advertises on its service entry. Every
  deployment example advertises an ORIGIN — `https://trust.example.com`,
  `http://localhost:3000` — so a client built from the published binding asked
  for `/trust-tasks` and got a 404. Ours worked only because `vta-sdk` hardcoded
  `/api/trust-tasks` and this service happened to serve the same prefix.

  Two implementations agreeing by convention is not a contract; it hides the
  absence of one from the only people who would notice — which is why this
  survived until someone read the binding rather than the code.

  The underlying defect was never the path. Nothing defined what the advertised
  endpoint DENOTES, so the two clients composed it differently and both could not
  be right: the SDK appended `/api/trust-tasks`, the binding appended
  `/trust-tasks`. Settled, per Glenn: **serviceEndpoint is the Trust-Task base**,
  and the binding's suffix is the contract.

  - **The service serves both.** `/trust-tasks` alongside `/api/trust-tasks`, one
    dispatcher. This is what makes the change safe: for an origin-advertising VTA
    the Trust-Task base IS the origin, so every existing advertisement becomes
    conformant with no operator touching anything.
  - **The SDK moved to `<base>/trust-tasks`.** That is the half that makes the
    contract real rather than aspirational, and it is safe against any VTA that
    has taken the change above.
  - **`/api/trust-tasks` is marked superseded**, so the metric that governs every
    other retired route decides when it goes. Its successor is a PATH, not a task
    URI — the one row in that table where the successor is not a
    `trusttasks.org` URI, because what replaced it is a spelling rather than an
    operation.

  Moving the SDK surfaced a second hand-built call site: `backup_descriptors.rs`
  formatted `{base}/api/trust-tasks` itself instead of going through `rpc_tt`,
  which is exactly why it kept the legacy prefix after the shared path moved.

  Tests pin that both spellings reach the same dispatcher AND fail identically
  when unauthenticated — a divergence there would mean a conformant client and
  ours behave differently, which is the thing being fixed. 26 mocks across
  client_rest and auth_light_rest move with the client.

  Still to do, and deliberately not here: specifying what the Trust-Task service
  entry means, so this is a contract rather than a second convention. That is a
  spec-registry change.

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

- **sdk/service**: Take trust-tasks-rs 0.11, and fix the four defects it exposes ([#1015](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1015))

* build(deps): move to trust-tasks-rs 0.11 and affinidi-messaging-sdk 0.19.9

  trust-tasks-rs 0.11 carries the vta/services/* families this branch implements.
  The move needed affinidi-messaging-sdk to go first — acl_setup hands a
  MediatorAcl to TrustTasks::account_update, so two semver-incompatible copies of
  trust-tasks-rs made that a type error rather than a link. That landed as
  affinidi-tdk-rs#717 and published as 0.19.9.

  vta-sdk builds clean on this. The workspace does NOT yet: vtc-service still
  hits a duplicated TrustTask<Value> because the trust-tasks sibling crates
  (trust-tasks-didcomm, -https, -proof, -tsp, -capability-client, -didcomm-v1)
  changed their requirement to 0.11 without moving their own versions, so
  crates.io still serves tarballs built against 0.9. dtgwg-trust-tasks-tf's
  release/siblings-on-0.11 fixes that; this branch waits on it.

- **sdk**: Build these two task payloads from their typed bodies ([#1005](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1005))

`get_key_secret` and `list_dids_webvh` were the last two `rpc_tt` call sites
  constructing their payload as a hand-written `serde_json::json!` literal, so
  they emitted `key_id`, `context_id` and `server_id` — snake_case, against a
  SPEC §4.10 contract that says lowerCamelCase.

  The earlier casing fold could not reach them by construction: it rewrote
  structs via `rename_all`, and a literal has no struct to fold. Nothing was
  broken, because `GetKeySecretBody` and `ListDidsWebvhBody` both carry
  `#[serde(alias = "…")]` for the old spelling — but the SDK was emitting a
  non-canonical spelling of its own published contract, and a consumer generated
  from the schemas would not have recognised it.

  Building the typed body instead means the wire spelling now comes from the same
  struct the schema is generated from, so the two cannot drift again. This is
  what the earlier fold's "known gap" note pointed at.

  `list_dids_webvh` gains a second, smaller correctness win: the literal emitted
  `"context_id": null` for an absent filter, while `ListDidsWebvhBody` carries
  `skip_serializing_if = "Option::is_none"` and omits the key entirely.

  `list_dids_webvh_filters_by_context` asserted the old spelling and now asserts
  `contextId`/`serverId` — the test is the proof the emitted wire actually
  changed, not just the source.

- **wire**: Emit canonical lowerCamelCase on Trust Task payloads, accept snake_case ([#1000](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1000))

* fix(wire)!: emit canonical lowerCamelCase on Trust Task payloads, accept snake_case

  SPEC §4.10 makes lowerCamelCase the wire contract for Trust Task payload
  members. 53 wire structs emitted snake_case, so every consumer generated from
  the published schemas disagreed with what this agent actually sends — and the
  disagreement was invisible until someone wrote a client against the spec.

  The fold is Postel's. `rename_all = "camelCase"` changes what is emitted;
  a per-field `alias` keeps the previous spelling accepted on intake, so a
  producer written against the old wire keeps working while it migrates. 126
  fields carry an alias.

  **Scope is deliberately narrow, and three exclusions are not oversights:**

  - **Config (`setup/from_toml.rs`)** is TOML, where snake_case is idiomatic and
    is not a wire at all.
  - **Persisted stores and the backup file format** (`backup_management/types.rs`,
    `drain_store.rs`) are read back from disk. Re-casing those would fail to read
    data already written — a worse bug than the one being fixed. Note that
    `WebvhDidRecord` *is* both wire and persisted: it is folded, and reads of
    existing snake_case records keep working precisely because of the aliases.
  - **`protocols/credential_exchange.rs`** carries OID4VCI and OID4VP structures
    (`vp_token`, `credential_offer`, `dcql_query`). §4.10 requires externally
    owned names to be carried verbatim, never re-cased. The conformance harness
    caught this when a first pass re-cased `vp_token`, which is exactly what that
    test is for.

  REST request/response bodies (`routes/`, `client/types.rs`, `protocol/`) are a
  further 54 structs with the same problem. They are left for a separate change:
  unlike task payloads, no published schema pins their casing, and changing what
  they emit breaks readers that have no alias to fall back on.

  Thirteen integration assertions read the old spelling and now read the new one.
  Full suite green: 823 lib, 119 api_integration, 90 conformance, plus the rest.

  * style: wrap the serde attributes the casing fold widened

  Adding a per-field `alias` pushed several `#[serde(...)]` attributes past the
  line width, so rustfmt wants them broken across lines. No semantic change —
  `cargo fmt --all` output, nothing hand-edited.



## [0.25.1](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-sdk-v0.25.0...vta-sdk-v0.25.1) — 2026-08-18


## [0.25.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-sdk-v0.24.0...vta-sdk-v0.25.0) — 2026-08-17


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

- **vta-service**: Present ISO mdoc credentials over OID4VP ([#993](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/993))

* feat(vta-service)!: present ISO mdoc credentials over OID4VP

  Completes mdoc support. A VTA could receive, verify and store an mdoc; it could
  not present one. This is the last piece, and it needed three things the other
  formats do not.

  An OID4VP session on the query wire. An mdoc's holder binding is a DeviceAuth
  signature over an ISO 18013-7 SessionTranscript, whose handover is
  [clientId, responseUri, nonce, mdocGeneratedNonce]. Two of those exist only in
  an OID4VP exchange, so a verifier that wants an mdoc supplies them; QueryBody
  gains an optional oid4vp_session carrying OID4VP's own field names, so a
  verifier can copy them out of its authorization request unrenamed.

  Absent, an mdoc is not offered at all rather than offered unbound. A DeviceAuth
  over invented handover values verifies nowhere and, worse, looks bound. The gate
  lives in match_held so matchable and presentable stay the same set: a
  matched-but-unpresentable credential bails the entire vp_token, not just itself,
  taking every other credential the verifier legitimately asked for with it. A
  mutation removing the gate fails the test that pins this.

  Holder identity that is key-shaped. ConsentGrant.holder_did becomes
  HolderIdentity::{Subject, DeviceKey}: every other format names a subject DID,
  while an mdoc names a device key discovered at receive. Both resolve to a
  did:key because ConsentRecord::verify_proof binds the proof's
  verificationMethod to the data subject — the variant records provenance that
  would otherwise be silently lost, not a different kind of value.

  A P-256 consent receipt. The device key signs its own receipt under
  ecdsa-jcs-2019 (affinidi-data-integrity 0.7.10), where every other format uses
  eddsa-jcs-2022. Signing the receipt with some other key would break the
  verificationMethod binding above; that is why the cryptosuite was added upstream
  rather than worked around here.

  Presentation itself is not a present_single arm: an mdoc vp_token entry is
  base64url CBOR of a DeviceResponse, not a W3C VP object, so present_mdoc sits
  beside it. Selective disclosure is by omission — only the [namespace, element]
  paths the query asked for are included.



## [0.24.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-sdk-v0.23.3...vta-sdk-v0.24.0) — 2026-08-16


### Added

- **vtc**: Let an applicant poll a join without knowing its request id ([#985](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/985))

The status poll exists so an applicant can find out what became of a join
  the community never volunteered an answer for. It could not be used for
  that.

  The id it takes is the *community's*, minted here on submit and learned by
  the applicant from the first correlated reply. An applicant that never
  received that reply — the exact failure the poll is meant to recover from
  — holds only the id of the document it sent, which this VTC has never
  heard of, and gets `not found` for it. So the poll worked whenever it was
  not needed and failed whenever it was.

  Downstream the two recovery paths shared the blind spot and failed
  together: OpenVTC gates polling on having a confirmed id, and its other
  recovery (collecting stored mail) is empty once the mail has been acked
  and deleted. The record then sits Pending forever with no way back —
  OpenVTC/openvtc#221, where the only fix was hand-editing a config file.

  `requestId` is now optional. Omitted, it means "what is my open request?",
  and the community resolves it from the authenticated applicant. That is
  safe and unambiguous for the same reason the dedup on submit is: at most
  one request per applicant is open at a time, and the applicant is already
  proven by the authcrypt sender over DIDComm/TSP. No new auth surface, no
  new route, no new domain tag — the id simply stops being the only way to
  name a request.

  The response has always carried `requestId`, so one id-less poll also
  repairs the applicant's record and every later poll can quote it. That is
  what turns this from a query into a recovery.

  `find_open_request` is now `pub(crate)`: it was the dedup's private
  helper, and it is the same invariant both callers rely on.

  REST keeps requiring the id — it is a path segment there, and the stranded
  case is a messaging one. Worth revisiting if a REST applicant ever hits it.



## [0.23.3](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-sdk-v0.23.2...vta-sdk-v0.23.3) — 2026-08-14


### Added

- **nitro**: Un-bake tenant config, deliver to the enclave over vsock ([#939](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/939))

* feat(nitro): un-bake tenant config, deliver to the enclave over vsock

  The Nitro enclave image no longer bakes tenant config.toml into the EIF, so one image (one PCR0) serves every tenant. The entrypoint fetches a versioned config envelope from the parent over vsock:5800 (bounded connect/read timeouts, 1 MB size cap, version check), fails closed unless VTA_ALLOW_DEFAULT_CONFIG=true, and writes /etc/vta/config.toml before start. Adds jq to the runtime; documents the KMS-policy isolation requirement and the tee-mode enforcement floor.



## [0.23.2](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-sdk-v0.23.1...vta-sdk-v0.23.2) — 2026-08-14


## [0.23.1](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-sdk-v0.23.0...vta-sdk-v0.23.1) — 2026-08-14


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



## [0.23.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-sdk-v0.22.0...vta-sdk-v0.23.0) — 2026-08-12


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


