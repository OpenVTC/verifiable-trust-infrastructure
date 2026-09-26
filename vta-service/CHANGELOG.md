# Changelog

Notable changes to the published crates. Generated from conventional commits by
[git-cliff](https://git-cliff.org) when a release is cut — do not edit by hand.
## [0.43.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-service-v0.42.0...vta-service-v0.43.0) — 2026-09-26


### Added

- **pnm**: Answer this VTA's consent requests from the CLI ([#1761](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1761))

A task under a `requires: consent` rule waits for its approver set, and only
  a device enrolled for the task-consent push could answer. `pnm` showed the
  requester the code and waited.

  `pnm consent {show,approve,deny} <file|->` is the approver's side. It takes
  the refusal the requester relays (the body, its `details`, or a bare request
  document) and picks the request addressed to this profile. It checks that
  this VTA signed it, that it is addressed to this approver and that it has
  not expired. Approving requires typing the requester's match code, or
  `--match-code`. The decision is dispatched as a Trust Task, which the client
  signs with the profile's key under assertionMethod.

  The operator-facing half is now shared with `cnm consent`: reading the
  input, what is shown, the code comparison, the report and the refusal
  hints, all in `vta_cli_common::consent_approve`. `cnm consent` moves onto
  it, keeping its VTC-specific hint for `permissionDenied`.

  Tested end to end in `delegated_consent_e2e`: a real VTA-signed request
  verifies through `vta_sdk::task_consent`. It is refused when it is
  addressed to someone else or has been tampered with, and the decision
  built from it is granted.



### Fixed

- **vti-common**: Bind the authcrypt sender key id to the key used, before trusting a DIDComm sender ([#1732](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1732))

An authcrypt (ECDH-1PU) JWE names its sender key twice in the protected
  header: `skid` and `apu` (the PartyUInfo the key derivation is bound to). A
  conforming packer writes the same key id into both. The direct-unpack callers
  now require that the two agree, and that the key the unpack metadata reports is
  that same key, before a sender is trusted.

  - New `vti_common::auth::verify_authcrypt_header(raw_jwe)`: for an ECDH-1PU
    outer layer (JSON or compact serialization) requires `skid` to be a DID URL
    with a key fragment, `apu` to be present, and `BASE64URL-decode(apu)` to be
    exactly the `skid` bytes. Any other `alg` is refused, so authcrypt nested
    inside anoncrypt is not accepted on these paths.
  - `bind_authcrypt_sender(raw_jwe, message, metadata)` now takes the raw
    envelope and requires: the header check; an `authcrypt(plaintext)` or
    `authcrypt(sign(plaintext))` wrapping; `encrypted_from_kid == Some(skid)`;
    and `DID(from) == DID(skid)`.
  - Callers updated: VTA `/auth/`, `/auth/refresh`, vault unseal; VTC
    `/v1/auth/`, `/v1/wallet/auth/` and refresh.
  - New `vti-common` `test-support` feature with builders for authcrypt
    envelopes with a caller-chosen protected header; route tests on both
    services.



### Security

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

- **vta**: Step-up approval, audit verify, policy reads and device management are scoped ([#1720](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1720))

The last four findings of the scope sweep that followed FTL-29904 (#1715,
  #1717). Each checked the caller's role and never what the caller acted on.

  - step-up/approve-request signed an approval with the VTA's own #key-0 for any
    authcrypt sender. An RP reads it as "this VTA approved a step-up for sub",
    so any DID anywhere could get that statement signed. The holder must now be
    a principal of this VTA (a live ACL entry; the rule VTI-SES-006 applies to
    issuing an auth challenge), through the testable
    `operations::step_up_approval::authorize_holder`. Refusals and issued
    approvals are both audited (VTI-VTA-006). The always-approve stub stays as
    the placeholder for user verification and is documented as not being the
    authorization control.
  - audit/verify needed only the admin role, although it reads the whole log,
    which audit/list reserves for a super-admin. It is now super-admin, and a
    verification and a refusal each leave an audit row (VTI-AUD-006).
  - policy/list and policy/get showed any admin or initiator every context's
    policy. A scoped caller now reads the rows that govern it (global rows and
    those naming a context it may act in); a row outside its reach answers
    NotFound on get, so it cannot be probed (VTI-CTX-002).
  - device/list, device/disable and device/wipe checked context visibility but
    not privilege, so an initiator could see, disable or wipe the device of an
    admin in its context. They now apply `acl/delete`'s rule (visibility and
    validate_role_assignment).

  Breaking in behaviour: non-principals lose step-up approvals; context-scoped
  admins lose audit/verify and other contexts' policy rows; initiators lose
  sight and control of more-privileged principals' devices.

- **vta**: Session and consent operations are scoped to the caller's authority ([#1717](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1717))

Found by the scope sweep that followed FTL-29904 ([#1715](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1715)). Both surfaces
  checked the caller's role and never the subject or datum it acted on.

  Sessions (VTI-SES-043, VTI-ACL-050). Any admin could list every session on
  the VTA and end any of them, a super-admin's included, via
  `DELETE /auth/sessions?did=`, `DELETE /auth/sessions/{id}` and
  `auth/revoke-session`; initiators could list them all. Session management now
  follows ACL management: `operations::acl::may_manage_subject` answers "may
  this caller act on this subject" with the rule `acl/delete` applies (the
  caller itself, a super-admin, or a managing role that can see the subject's
  entry and is at least as privileged). A super-admin's entry names no context,
  so a scoped admin never reaches it; a subject with no entry belongs to no
  context and only a super-admin reaches it. `GET /auth/sessions` lists only
  the subjects the caller may manage. `auth/revoke-session` keeps its
  no-disclosure answer (revokedCount 0) and now also records a durable `denied`
  row when the session existed. `auth/sessions/list` was already self-only.

  Consent (VTI-CTX-001, VTI-CTX-002). Grants carried no context, so any admin
  could write a standing Allow for any subject (a decision with no challenge)
  or withdraw anyone's grant. `ConsentGrant` now records the context of the
  request it answers. `consent/revoke` needs authority over that context, or
  super-admin for a grant with none. A decision with no challenge writes a
  context-less grant and so needs a super-admin. A challenged decision with no
  bound approver and an empty request context now needs a super-admin, where it
  skipped the context check. `consent/request`'s `contextHint` must be a context
  the caller may act in.

  Every refusal is audited with outcome `denied` (VTI-AUD-003) and logged with
  `security_alert = true`.

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



## [0.42.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-service-v0.41.0...vta-service-v0.42.0) — 2026-09-24


### Fixed

- **vtc**: OpenAPI schema names are unique, so each endpoint documents its own shape ([#1697](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1697)) ([#1701](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1701))

utoipa keys `components.schemas` by bare type name, and
  `OpenApiRouter::routes` merges each route's schemas with a plain map
  `extend`, so two `ToSchema` types with one name fail nothing: the last
  registered wins and every `$ref` to the name describes that one. The VTC
  document had 18 such names across vtc-service and vta-sdk, and six were
  wrong in the published document — `GET /v1/admin/passkeys` was described
  as the console-key list, `/v1/auth/challenge` as the personhood challenge,
  and five revoke endpoints as the endorsement revoke response.

  - vtc-service: the service-side types get distinct names with
    `#[schema(as = …)]`. Rust type names are unchanged, so no handler moves
    and `openapi_response_census` still compares like with like.
  - vta-service: `RollbackResponse` and `EnrollPasskeyChallengeBody` were
    field-for-field copies of vta-sdk's types registered under the same
    names. The shapes matched, so the document happened to be right; the
    copies are deleted in favour of the vta-sdk types.
  - `openapi_schema_names.rs` in both services: a source-scan census that
    fails when two `ToSchema` definitions in the crate or its path
    dependencies share a schema name, and when the scan finds too few names
    to prove anything.
  - admin-ui: `openapi.json` and `wire.ts` regenerated; `PasskeyListResponse`
    restored as a generated alias and used by `myPasskeys.tsx` in place of
    the local interface that let the drift go unnoticed.



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



## [0.41.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-service-v0.40.0...vta-service-v0.41.0) — 2026-09-23


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



### Fixed

- **vtc**: A Trust Task over DIDComm rides the binding envelope only (Keyring VTI-42) ([#1687](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1687))

The DIDComm binding (bindings/didcomm/0.2 §2-§5) makes the envelope
  https://trusttasks.org/binding/didcomm/0.1/envelope the only carriage for a
  Trust Task, and requires a consumer to refuse any other type at the DIDComm
  layer with no trust-task-error.

  The VTC router still carried twelve task-typed arms beside the envelope arm
  (join-requests submit/manifest 0.1+0.2/status, members/self-remove,
  members/vmc, six vtc/vetting URIs). Every other served verb answered
  'unsupported message type' when typed as itself. Two of the arms
  (self-remove, vmc) parsed bespoke bodies and bypassed
  dispatch_trust_task_core, so they skipped freshness, recipient and proof
  checks. All twelve are removed. Every one of these URIs is dispatched by the
  spine via the envelope.

  The VTC and VTA fallbacks now answer a https://trusttasks.org/spec/ type
  with a threaded problem-report that names the envelope type.

  Parity tests walk each dispatcher's own list (VTC DISPATCHED_URIS +
  ROOMS_DISPATCHED_URIS; VTA dispatched_uris()). An enveloped request is never
  answered 'unsupported message type'. A task-typed one gets the
  envelope-naming problem-report. The VTA's two remaining task-typed arms
  (acl/swap-key/0.1, provision/integration/0.3) are pinned in a shrink-only
  list.



## [0.40.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-service-v0.39.0...vta-service-v0.40.0) — 2026-09-23


### Added

- **vta**: Advertise TSP on a minted DID when the mediator carries it ([#1665](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1665))

A persona minted by a TSP-capable VTA advertised only `DIDCommMessaging`,
  so a Rev 3 peer reading its document kept the leg on DIDComm (Keyring
  VTI-Q11). The cause: `addTspService` defaulted to `false` at the mint, and a
  persona is minted by a caller that sends no such field — the SDK skips it
  when false — so the answer was always "no" however TSP-capable the stack was.

  `addTspService` becomes three-state. An explicit `true` or `false` is
  honoured exactly as before. Absent now means "decide from what this VTA and
  its mediator can actually carry": `services.tsp` on, a mediator configured,
  and that mediator's own document advertising `TSPTransport` — the same check
  VTA setup makes before advertising `#tsp` for the VTA itself.

  A mediator that does not resolve answers no, which is deliberately stricter
  than setup's warn-and-proceed. There the operator named the mediator and is
  told; here nobody asked for `#tsp` at all, so the quiet default must not
  publish a transport peers cannot reach.

  Every internal caller passes `Some(false)`, so no existing path changes.



### Fixed

- **vta-service**: Answer a TSP relationship request before its sender's later traffic ([#1675](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1675))

Keyring VTI-43. A phone sent a TSP relationship invite (XRFI) and, 16 ms
  later, a Trust Task. The VTA's inbound loop reads frames in order but spawns
  each onto its own task, so the two raced: the task's ~2 ms reply (a
  permissionDenied) was sent ~328 ms before the VTA finished answering the
  invite with XRFA (accept_relationship resolves the peer VID and POSTs; only
  then is the relationship Bidirectional). The phone admits application
  messages only on a bidirectional relationship, so it dropped the reply. When
  the accept happened to win, it worked.

  The fix orders inbound frames per authenticated sender, taken on the reader
  task (the only place that sees arrival order) before spawning:

  - a TSP relationship-control frame is a barrier: it runs after every earlier
    barrier from the same sender;
  - TSP application frames run after every earlier barrier from their sender,
    but not after each other, and a barrier does not wait for earlier
    application frames — so a Trust Task awaiting a later message from the same
    peer (a step-up approval) cannot deadlock on it, which a per-sender FIFO
    would;
  - different senders never wait for each other; DIDComm stays unordered.

  The bookkeeping map holds only senders with a barrier in flight (bounded by
  the loop's concurrency cap) and a wait is bounded at 15 s (R1.3): a hung
  accept degrades the frames behind it to the old unordered behaviour rather
  than stranding the peer. A barrier's handler releases its followers on drop,
  so a failure or panic releases them too.

  vtc-service needs no change: its inbound loop awaits each frame inline, so
  it already processes one sender's frames in arrival order.



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

- **persona**: Holder authority is granted, never inherited from a role ([#1673](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1673))

`persona-holder` exists because no role carries authority over the
  holder's pool — and super-admin carried it anyway. That left the premise
  true only of the roles nobody automates with: the unrestricted admin
  credential is the one most likely to be sitting in a script, and it read
  the attribute pool, the faces over it and the disclosure history without
  an ACL entry saying so.

  Now the grant is the only way in. A super-admin can still grant itself
  the capability, so this is not a boundary it cannot cross; it is the
  difference between crossing it and crossing it deliberately. The grant is
  an ACL write — audited, reviewable, revocable on its own — where the
  inherited form left no trace that the pool had been read by something
  that never asked for it.

  The refusal names the command that fixes it, because an operator refused
  against their own agent's own pool cannot guess at a capability they have
  never heard of.

  Operators upgrading: `pnm acl update --did <did> --capabilities
  persona-holder`, or `pnm contexts create --admin-holder` when
  provisioning a client that is the holder's own.

  §7 of the persona design note records this and the three other questions
  it left open, with the reasoning rather than only the outcome.



## [0.39.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-service-v0.38.0...vta-service-v0.39.0) — 2026-09-22


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



### Fixed

- **persona**: A credential-backed value follows its credential, and fails closed ([#1653](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1653))

Credential-backed attributes were never resolved against their
  credential: not at write (persona/attribute/put rule 3,
  `credentialNotFound`) and, worse, not on read, where the Provenance
  contract requires the maintainer to re-derive the value and fail closed
  once the credential is revoked, expired, archived or deleted. A revoked
  credential's value went on being presented.

  vta-persona gains `derive`: a `CredentialSource` hook the service
  implements over the vault, so the persona crate still does not depend
  on it. The store asks it wherever a credential-backed value is about to
  be believed:
  - put: resolves the credential and takes its value (the supplied one is
    a display cache the spec lets the maintainer overwrite); one it cannot
    back is refused. `credential_refusal` gives the dispatcher the code.
  - resolving a face (and so materialising a binding): the credential's
    current value, or nothing and `stale`.
  - listing the pool: `stale` with `staleReason`, no value; a withheld
    value stays withheld.
  - building a preview: re-derived from the context's copy, which carries
    the provenance; a withdrawn credential shows stale before approval.
  - presenting: checked again, so a credential revoked between preview
    and present is not presented.
  A pinned kept value is withheld too once its credential is withdrawn.

  vta-vault `receive::stored_claims`: the claims a stored credential
  carries — SD-JWT-VC re-verified against its issuer and reconstructed,
  Data-Integrity read as stored, mdoc refused. vta-service's
  `VaultCredentials` maps held/lifecycle/status/validity window/path to a
  value or a StaleReason; attribute/put maps a refusal to
  `persona/attribute/put:credentialNotFound`, and reads the stored value
  back for its correlation count.

- **auth**: A signed REST sign-in must be addressed to the service that receives it ([#1646](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1646))


## [0.38.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-service-v0.37.1...vta-service-v0.38.0) — 2026-09-22


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

- **vta**: TSP is on by default, and setup checks the mediator carries it ([#1622](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1622))

Keyring VTI-33. TSP is the preferred transport across the stack, but a
  default VTA build could not receive it. `tsp` joins vta-service's and
  vta-enclave's default features; the setup wizard pre-ticks TSP, and a setup
  file enables it unless it says `tsp = false` — including a `[services]`
  block given without a `tsp` key, which gets its own deserializer so the
  runtime `ServicesConfig` can keep its `false` default (a hand-written config
  that never mentions TSP must not start claiming it).

  On-by-default is only safe if the mediator `#tsp` names routes TSP, so setup
  now checks: a mediator it creates is created with `#tsp`; an existing one is
  resolved and its DID document read for a `TSPTransport` service (by type).
  Without one the wizard drops TSP and says so, and `--from` refuses, both
  before anything is minted. An unresolvable mediator gets a warning.

  Existing VTAs are unchanged; `pnm services tsp enable` adds TSP. CI's
  `tsp transport` step duplicated the default build and now builds without
  `tsp` instead.

  Behaviour change: a `--from` file whose existing mediator advertises no
  `TSPTransport` now fails setup unless it sets `services.tsp = false`.

- **acl**: `key-export` is its own capability, and minting a DID needs `KeyMint`, not admin ([#1619](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1619))

Keyring finding VTI-23: `webvh/dids/create` and `keys/export-secret` both checked
  for the admin role, so a least-privilege manager was impossible for the persona
  lifecycle — an `initiator` holds `KeyMint` and `Sign` and was refused both.

  ## Minting a DID: `KeyMint`

  Minting a DID mints its keys, which `initiator` is already trusted to do. The
  gate in `create_did_webvh` is now `KeyMint`, so a manager on `initiator` can mint
  personas. The context check is unchanged and still bounds *where*.

  It reads the caller's **entry**, so a narrowing that removes `KeyMint` stops the
  next call — the rule every capability gate has followed since #1279. That needs
  the ACL keyspace in `CreateDidWebvhDeps`, as `acl_ks: Option<&KeyspaceHandle>`:
  `Some` from both live constructors and from provisioning; `None` only for the
  offline CLI and first-boot setup, whose claims are synthesized under a DID that is
  deliberately in no ACL — so reading the store would find no entry and fall back to
  the role anyway. The gate is extracted as `ensure_may_mint` so it can be tested as
  the code that runs, rather than by a test that mirrors it.

  ## Exporting a key: a new `KeyExport` capability

  VTI-VTA-003 is normative here:

  > Where a VTA supports exporting derived key material, that export MUST be gated
  > by a capability distinct from the capability to use the key, and MUST be
  > audited.

  The admin-role check was not that. It coupled export to being an admin, so export
  could neither be granted below admin nor narrowed away from one. `KeyExport` is
  now the gate; scope and auditing inside `get_key_secret` are unchanged.

  **Only `admin` derives it.** That is deliberate, and it is the answer to the half
  of VTI-23 this does not grant. An `initiator` holds `Sign`, which is the signing
  oracle — its whole guarantee is that the key never leaves — and VTI-VTA-002 makes
  performing the operation the norm and exporting it the exception, because an
  exported key stays with whoever holds it after their authority is withdrawn. A
  manager that needs to act as a persona signs through the oracle.

  `KeyExport` is role-derived, not additive, so naming it on an `initiator` grants
  nothing. Making it both admin-derived *and* grantable would need a change to
  `effective_capabilities`' invariant (a capability is either derived or additive,
  never both), which was considered and not taken.

  ## One behaviour change to know about

  An admin who was **narrowed** under #1279 could export until now, because the
  role check ignored narrowing. Their stored set could not name `key-export` — it
  did not exist — so after this they cannot. That is the narrowing working as
  intended, closing the one power it could not previously restrict. Un-narrowed
  admins keep everything.

  `KeyExport` is not in the published `device/_shared/0.2` enum, and
  `PUBLISHED_CAPABILITIES` lists that enum positively, so it lands in `ext` as an
  ecosystem-local capability rather than leaking into a closed schema.

  ## Follow-up outside this repository

  The TS console keeps a hand-maintained copy of the role table
  (`acl-capabilities.json`, synced from this repo's `origin/main`). It must be
  re-synced after this merges, or it will under-report an admin's authority.

  ## Tests

  - Role table: admin derives `KeyExport`; no other role does; it narrows away
    from an admin; naming it on an initiator grants nothing.
  - `keys/export-secret`: an initiator is refused at the gate; an admin passes it;
    a narrowed admin is refused. The last is the one the old role floor would have
    let through — verified by restoring it.
  - `ensure_may_mint`: an initiator may mint; a reader may not; a narrowing
    without `KeyMint` stops the next mint — verified to fail when the entry is
    ignored; offline callers fall back to the role.



### Fixed

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

- **vta**: Warn at boot when approval rules exist but policy enforcement is off ([#1633](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1633))

Keyring KR-22 (Refs #1608). `policy.enforcement` defaults to false and stays
  that way: flipping it would turn every written-but-not-intended policy into a
  gate across existing deployments on upgrade. The defect was the silence — a
  rule written with `pnm approvals require` is stored, listed and explained, and
  then gates nothing, with no signal anywhere that enforcement is off.

  - vta-policy: `unenforced_policies()` (+ `#[non_exhaustive]`
    `UnenforcedPolicies`) reports the approval rules on the enabled declarative
    row and the ids of enabled hand-authored rows. The boot-installed baseline,
    disabled rows and a declarative row carrying only approver sets are not
    counted — none would gate a task with enforcement on.
  - vta-service: on boot with enforcement off, log a WARN naming what is being
    ignored and the exact change (`[policy] enforcement = true` + restart).
    Advisory only: a failure to read the rows is logged and never stops boot.
    The enforcement flag is copied out so the config lock is not held across
    the keyspace read.
  - docs/02-vta/approvals.md: state up front that approvals are opt-in and off
    by default, show the config snippet, and document the boot warning.

- **cli**: A self-hosted VTA is not told to redeploy the log it serves ([#1624](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1624))

Keyring VTI-36. After a service mutation on a self-hosted ("serverless")
  VTA, the CLI said to fetch the log and "redeploy did.jsonl to your host".
  But the VTA serves its own did.jsonl from its store at the DID's canonical
  path, read per request, so the new entry is already published — the host
  the operator was told to redeploy to is the VTA. The hint now says so,
  names the URL, and notes the resolver cache window; only a copy published
  elsewhere needs replacing. The offline `vta services` surface says the
  entry is served once the daemon starts.

  `dids edit` on a self-hosted DID the VTA manages for someone else (a
  community's) still gets the redeploy advice, which is right there, now
  without calling it "this VTA's DID".

- **vta**: Refuse `services.tsp = true` on a build without the `tsp` feature ([#1620](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1620))

* fix(vta): refuse `services.tsp = true` on a build without the `tsp` feature

  Keyring VTI-34. `tsp` is not a default feature, and on a build without it
  `services.tsp = true` was accepted and did nothing: there was no TSP
  receive path, while anything that had published `#tsp` sent peers into it
  under the stack's TSP-first preference. Nothing reported it.

  Startup now refuses the combination with an `AppError::Config` naming both
  fixes, and `enable_tsp` refuses before publishing on such a build. One
  `server::TSP_BUILT` definition feeds both. REST and DIDComm keep their
  silent `cfg! && config` AND, which the reduced CI builds rely on; TSP
  defaults to false, so `tsp = true` is always an explicit choice.

  Behaviour change: a VTA configured with `services.tsp = true` but built
  without `--features tsp` no longer starts.



## [0.37.1](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-service-v0.37.0...vta-service-v0.37.1) — 2026-09-21


### Fixed

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



## [0.37.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-service-v0.36.0...vta-service-v0.37.0) — 2026-09-21


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



### Fixed

- **did-webvh**: Serialize versionTime log updates ([#1599](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1599))

* fix(did-webvh): serialize versionTime log updates

  Use one current-time policy for TEE genesis and runtime did:webvh
  updates. Wait for the next valid whole-second boundary, rechecking
  after wall-clock rollback, instead of backdating entries.

  Serialize same-DID log appends within a VTA process and add regression
  coverage for rapid updates, concurrent appends, legacy timestamps, and
  TEE genesis followed by an immediate validated update.



## [0.36.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-service-v0.35.0...vta-service-v0.36.0) — 2026-09-21


### Added

- **persona**: Say who holds an old value, where an edit landed, and what a context may call a face ([#1597](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1597))


### Fixed

- **persona**: Carry the holder's label into resolved claims ([#1596](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1596))
- **persona**: Correlate values faces carry, and honour profileId ([#1594](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1594))


## [0.35.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-service-v0.34.1...vta-service-v0.35.0) — 2026-09-20


### Added

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

- **tsp**: A peer's invite landing mid-recovery must not lose the resend ([#1582](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1582))

The D6 reply-timeout recovery (`recover_send_tsp`) resets our half of the TSP
  relationship and re-establishes it with the payload riding behind the invite
  (§3.6). `TspOps::send_reestablishing` does that in three steps, and the first
  two are separate awaits on the relationship store: read the send readiness,
  then `SendInvite`. The peer can move our half in between — its own invite
  arrives, `None` + `ReceiveInvite` leaves us `InviteReceived`, and `SendInvite`
  is legal only from `None`. The invite is then refused with

      invalid transition: SendInvite in state InviteReceived

  and the payload is never sent.

  That is not a failed recovery. It is the outcome the invite existed to produce,
  reached from the other side: a relationship is on record again, and
  `admits_application_message()` is true for every state but `None`. And the
  collision is commonest exactly where recovery is — two endpoints repairing the
  same broken relationship at once is what a mediator restart or a VTA redeploy
  produces.

  So `TspTransport::send_reestablishing` spells the three steps out rather than
  calling the SDK's combined form, and answers a refused invite by re-reading the
  store rather than by matching on the error's text: our half no longer `None`
  means carry on to the payload; still `None` means the invite failed for its own
  reasons and that error stands. The payload is sent exactly once either way.
  `invite_refusal_is_benign` carries that decision as a pure function with its own
  tests — the race itself lives between two awaits inside the SDK and cannot be
  staged in a test, so the decision is what gets pinned.

  Found through `d6_recovers_a_reply_from_an_answering_peer`, which had failed six
  of the last ten `Test (workspace)` runs on main. The answering peer's
  spawn-time `relate` is the colliding invite and the window is two store reads,
  so it is a coin flip under load — and it never showed in the isolated
  `transport-harness` step, only in the full parallel suite.

  Two diagnosis defects made it unreadable, both fixed here:

  - `recover_send_tsp` collapsed `Timeout`, `Cancelled` and `SendFailed(reason)`
    into "`<peer>` did not answer over TSP after re-establishing the
    relationship", so a frame that never left this VTA was reported as a silent
    peer and sent every reader to the wrong endpoint. The steady-state `send_tsp`
    beside it already told the three apart.
  - The `AnsweringPeer` harness discarded every fault inside its loop — `Err(_) =>
    break` on the socket, `let _ = send_document(…)` on the reply. It now records
    what it received and sent, and the assertion prints it; `received 0
    document(s)` is what named the cause.

  The same race is open in `vtc-service`'s registry client, which calls the SDK's
  combined form. There it surfaces as a transient `Unreachable` and the syncer's
  backoff — the one retry owner on that path — re-sends into a store that by then
  reads `HandshakeInFlight`, so it self-heals on the next attempt. Left as is
  deliberately; a one-shot recovery has no such owner, which is why the VTA's arm
  could not.

  Design note: `docs/05-design-notes/tsp-relationship-recovery.md` D6a.

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

- **step-up**: Route delegated pushes to an approver's own mediator ([#1579](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1579))

* fix(step-up): route delegated pushes to an approver's own mediator

  `approver_mediator` returned `None` for any DID that was not `did:key`, so
  a `did:webvh` or `did:peer` approver was never pushed to. All four call
  sites give up at that point — `consent_request.rs` (approver and requester
  notices), `consent.rs` (wake) and `step_up.rs` (delegated step-up) — and
  each one sits upstream of everything that would otherwise reach the
  device: the TSP attempt, the DIDComm forward, and `trigger_gateway_wake`.
  One gate therefore starved three delivery paths at once, which is why the
  symptom presented from several directions: a consent request that stayed
  queued, an idle approver that was never roused, and a delegated step-up
  that fell back to the relay every time.

  The predicate now resolves the approver's DID document and reads the
  mediator from its `DIDCommMessaging` service, matching on service `type`
  per the workspace transport rules. `did:key` keeps its existing behaviour —
  it cannot advertise a service, so it routes through the VTA's configured
  mediator, where the holder registered it.

  A routable approver deliberately does **not** fall back to the configured
  mediator when its document names none. Forwarding to a mediator the
  approver is not registered with does not reach them, and spends a slot of
  this VTA's sender-queue allowance to do nothing; `None` (relay fallback)
  is the honest answer.

  Resolution is bounded by a 5s timeout. Every call site awaits this inline
  on a request path while the push it gates is documented as best-effort, so
  an approver whose DID host is slow must not hold the caller's response
  open. The shared `AppState::did_resolver` is used rather than a fresh
  resolver, so the cache absorbs repeat pushes to the same approver.

  The three call sites that read `[messaging] mediator_did` under the config
  read-lock now clone it and drop the lock first: the route decision is
  network I/O and holding the lock across it would stall config writers.

  Reported as VTI-26 and VTI-24 by the Keyring wallet team, who hit it with
  `did:webvh` phone approvers.

- **vta**: Answer the contexts family's declared error codes, and stop distinguishing "not yours" from "not there" ([#1580](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1580))

The `vta/contexts/*` specifications declare eight extended error codes. The
  VTA emitted none of them. Worse than the missing codes: the answers it gave
  instead leaked which context ids are real.

  ## The leak

  Every id-taking task checked scope and existence separately, and reported
  them separately:

      auth.require_context(id)?;                       // 403, names the id back
      get_context(..).ok_or(AppError::NotFound(..))?;  // 404

  So a caller scoped to one context learned, from the difference between the
  two refusals, exactly which other context ids exist. The captured refusal
  reads `permission denied: forbidden: no access to context: cov-real` — it
  confirms the id and hands it back. `create_context` had the same leak
  inverted: it looked the parent up *before* checking scope, so an
  unauthorised caller learned a parent was real before being told it could not
  use it.

  The specifications require the opposite, and say so. `vta/contexts/get`:
  "deliberately does not distinguish 'does not exist' from 'exists but not
  yours'". `update`, `update-did` and `delete` each repeat it as "whether or
  not it exists". `create` names its own code and ties it to `get`'s
  reasoning.

  ## What changed

  `reach_context` is the family's single answer to "does this caller get to
  act on this id" — scope, then existence, one `Unreachable` for both. Six
  operations go through it; `create` gets the same treatment for its parent.

  The operations return a typed `ContextError`, and one `reject_context_error`
  maps it to the code the calling task declares — the slug is read off the
  document, so `get:notFound`, `update:notFound`, `update-did:notFound`,
  `preview-delete:notFound`, `delete:notFound`, `delete:notEmpty` and
  `create:parentNotFound` are all the same match. `From`/`Into` keeps `?`
  working inside and converts back for the transports that carry a status
  rather than a Trust-Task code, so REST and DIDComm need no per-site changes.

- **vta**: Preview the whole subtree a context delete destroys ([#1576](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1576))

`preview_delete_context` collected the named context and nothing else, while
  `delete_context` cascades the whole subtree. Two functions answering
  different questions about the same act, and the preview's was the wrong one.

  A context whose own keyspaces were empty over children holding keys, DIDs
  and grants previewed as holding nothing. Every consumer decides from that
  preview whether the deletion needs `force`, so every consumer decided from
  the wrong set: send `force: false` and the agent refuses with nothing on
  screen explaining why, or — when the parent happens to hold one key — send
  `force: true` and destroy an entire unlisted subtree under a confirmation
  listing one key.

  `collect_subtree_resources` answers for the delete set, and is not a loop
  over the per-context collector. The difference is the ACL classification.
  The per-context question is "does this entry hold *only* this context?",
  which for a subtree gets it backwards: an entry scoped to both `acme` and
  `acme/eng` looks like it holds another context, so a loop reports it twice
  as merely narrowed — when deleting `acme` takes both scopes and the entry
  goes entirely. Asked once against the whole set it comes out as `removed`,
  which is also where the deletion's deepest-first cascade converges. Telling
  an operator that a subject keeps authority it is about to lose completely is
  the one error this preview must not make.

  Both CLI front-ends prompted off that preview and passed `force = true` to
  the deletion regardless, so `vta context delete acme` on a parent that held
  nothing itself took the subtree with no prompt at all. They now name the
  sub-contexts — derived locally, since the task has no member for them yet —
  and count them, and DID templates, toward "does this destroy anything".
  The renderer never printed `didTemplates` and never counted them, so a
  context whose only contents were templates skipped the prompt too.

  Both new tests were confirmed to fail against the old preview.

- **vta**: Delete a context's did:webvh DIDs off their hosting servers, not just locally

Deleting a context cascaded to its sub-contexts and dropped each DID's local record with webvh_store::delete_did plus its log key. That is not a smaller version of deleting the DID; it is a different outcome. The published log stayed on the hosting server, so the DID kept resolving for everyone except the agent that owned it. Credentials the VTA had issued naming it stayed valid, with the only records that could revoke them destroyed. Live sessions authenticated as it kept working. The operator was told the context was deleted, and nothing in the result distinguished the two outcomes.

  Every DID in the subtree now goes through delete_did_webvh_with — the same path pnm did-mgmt dids delete takes — so the host copy is removed, credentials revoked, sessions ended, and the full key-fragment range cleaned up. purge_context_resources no longer deletes DIDs at all: one path, not two, and the weaker one is gone.

  delete_context takes a ContextDidCleanup; None means the caller cannot reach a hosting server, and a context holding DIDs is then refused rather than having its records dropped behind their hosts' backs. DeleteDidOptions::contexts_being_deleted narrows the "a context acts as this DID" blocker to the contexts going away, so a DID some other context acts as is still refused. Blockers are collected across the whole subtree and refuse before anything is destroyed, rather than deleting three contexts' DIDs and refusing on the fourth.

  Ordering is remote-first (VTI R2.1): a local record removed before its host copy is the one state from which the host copy can never be removed.

  deleting_a_context_deletes_its_subtree_dids_on_the_hosting_server holds it, and was confirmed to fail against the old behaviour — webvh_host_deletes() is the only witness that separates the two outcomes, which is why an assertion on the local record let this survive.

- **vta**: Carry a holder grant through an admin rollover instead of deleting it ([#1573](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1573))

Onboarding a client tells the operator to grant `--admin-holder` on the
  ephemeral setup key. Provisioning then rolled that key over to a
  long-term admin DID, wrote the successor's ACL row from
  `CreateAclParams::default()`, and deleted the ephemeral's row in the same
  call. An empty capability list means "whatever the role implies", and
  `persona-holder` is implied by no role — that is the whole point of
  `ADDITIVE_CAPABILITIES` — so the grant the operator had just been told to
  make was destroyed by the operation meant to hand it over.

  Nothing said so. Everything context-scoped kept working, and the loss
  surfaced much later, on a different screen, as a refusal to read the
  holder's own attribute pool: "an administrator scoped to a context and
  holding neither is refused here exactly as an application would be." True,
  and no help at all in working out that a capability had gone missing at
  install time. There was no audit trace either, because nothing had decided
  to drop it.

  `retire_ephemeral_after_rollover` now carries the ephemeral's additive
  capabilities onto its successor before deleting the row. Both provisioning
  paths — `provision_integration` and `provision_admin_rotation` — already
  go through it.

  This is not a scoped admin conferring holder authority, and the guard that
  stops that (`a_scoped_admin_must_not_confer_holder_authority`) is
  untouched. That guard is about an operator *minting* authority over the
  holder's identity. Here the authority already exists, on a DID the same
  operator controls, and is being retired in this same call: the grant moves
  rather than multiplies, and the number of DIDs holding it does not grow.
  The self-service rotation that audits under the same `acl.swap` event
  already carries the whole capability list across (`swap_acl`); this path
  was the one that did not.

  Only additive capabilities are carried. A narrowing list is re-derivable
  from the role and is not lost by omission, and copying one would quietly
  reduce what existing deployments' successors can do — the same class of
  silent change, in the other direction.

  The move is audited as `acl.capabilities.carried` rather than folded into
  the `acl.swap` that follows: a capability moving between DIDs is the part
  a reviewer asks about, and it must be answerable without inferring it from
  two rows that no longer both exist.

- **rate-limit**: Key the per-IP limiter on trusted-proxy CIDRs, not a global XFF flag ([#1562](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1562))

* fix(rate-limit)!: key the per-IP limiter on trusted-proxy CIDRs, not a global XFF flag

  Replaces the boolean `trust_xff` flag with `trust_xff_cidrs: Vec<CIDR>` (VTA + VTC). The per-IP rate limiter now reads `X-Forwarded-For` only when the request's peer address falls inside an explicit trusted-proxy CIDR allowlist, keying on the rightmost entry.

  Fixes two issues with the old flag: an untrusted peer could forge a leading XFF entry to evade its own limit, and every request behind a trusted proxy shared one bucket — one client's burst could 429 unrelated clients.

  Breaking config change: replace `trust_xff = true/false` with `trust_xff_cidrs = ["<cidr>", ...]`.



## [0.34.1](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-service-v0.34.0...vta-service-v0.34.1) — 2026-09-18


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



## [0.34.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-service-v0.33.0...vta-service-v0.34.0) — 2026-09-18


### Added

- **vta-service**: Route a cross-mediator TSP send nested for metadata privacy ([#1559](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1559))

TSP's metadata-privacy benefit is realised only across mediators: with a nested
  send each intermediary sees only the next hop, never the final recipient. Until
  now every VTA outbound TSP send used the single-intermediary
  `send_routed([our_mediator, recipient])`, which names the recipient as a visible
  route hop — so a peer on a different mediator was either unreachable or reached
  with no privacy gain.

  Add `TspTransport::send_metadata_private(recipient, peer_mediator, body)`, which
  mirrors the SDK's own `ATM::send_to` gate: when the peer's mediator differs from
  ours, seal the inner message end-to-end to the recipient, wrap it in a Nested
  envelope sealed to the peer's mediator, and route `[our_mediator, peer_mediator]`
  so our mediator (the only intermediary before the peer's) never learns the
  recipient; when they share a mediator — the reference single-mediator topology —
  fall back to the unchanged direct routed send, since there is no intermediary to
  hide the recipient from.

  The peer's mediator DID needs no extra resolution: it is the `#tsp` service
  endpoint the outbound path already read when selecting TSP, so `Outbound::send`
  threads that `endpoint` down through `send_tsp` -> `send_and_await` ->
  `send_metadata_private`. The recovery/re-establish path stays a direct routed send
  (the SDK has no nested re-establishing form, and a §7.2.2 drop recovery values
  getting the reply through over metadata privacy) — the steady-state send is the
  one that nests.

  Covered by two `transport-harness` tests over a two-mediator `TestTopology`: a
  cross-mediator send is received and unpacked by a peer on the other mediator
  (delivery proves nesting — a direct route could not cross), and a same-mediator
  send still delivers over the direct fallback.

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

- **did-webvh**: Mint the keys a template's `keys` block asks for ([#1555](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1555))

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

- **vta-service**: Re-form a dropped TSP relationship on the outbound send path (D6) ([#1549](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1549))

* feat(vta-service): re-form a dropped TSP relationship on the outbound send path (D6)

  Wires the upstream single-flight `RecoveryCoordinator` into the VTA's
  server-initiated TSP sends — the coordinator-grade counterpart to the client-side
  per-call self-repair ([#1544](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1544)), and design note `tsp-relationship-recovery.md`'s D6.

  Every VTA-initiated TSP send funnels through `operations::outbound::send_tsp`. On
  a reply-timeout — the §7.2.2 silent-drop signature — it now asks one shared
  `RecoveryCoordinator` (on `AppState`, keyed by `(our_vid, their_vid)`) whether to
  act: `Start` gives the call the single-flight token, so concurrent sends to one
  lost peer coalesce onto a single re-invite rather than storming it; `Backoff` /
  `GiveUp` cap a genuinely-down peer. On `Start` it resets our stale local half
  (safe against a false positive via D2's reconcile) and, for a task classified
  blind-retry-safe in `vta_sdk::retry_safety`, re-invites and resends once via
  `send_reestablishing`; a task that could double-execute is only healed
  (re-invited, no resend), matching the #1544 gate.

  New on `TspTransport`: `reset_relationship`, `send_reestablishing`, `relate`
  (re-invite only), `our_vid`. The reply timeout becomes a `TspSender` field
  (default the 30s const) only so a test can shorten it.

  Tests (`test_support::transport_harness_tests`): `d6_drives_recovery_on_a_reply_timeout`
  asserts the coordinator is consulted and one recovery runs against a
  routable-but-silent orphan peer; `d6_coalesces_concurrent_recoveries` asserts two
  concurrent recoveries for one peer record a single attempt (single-flight). Both
  are non-vacuous by construction — no coordinator call means zero attempts, no
  coalescing means two.

  Scope note: this is the coordinator wiring for the VTA outbound seam. The VTC
  registry seam is handled separately (reset-only) by feat/vtc-tsp-d4-reset. A full
  end-to-end success-path test (a responding peer that recovers a reply) needs a
  responding-peer harness and is a noted follow-up; the reply-success arm here is
  the trivial passthrough over the SDK-tested `send_reestablishing`.



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

- **webvh**: Select a transport by the sender's live capability, not the build feature ([#1560](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1560))

VTC setup began failing after Dogwood with an opaque `internalError`
  ("the consumer could not complete this task; the request itself was
  accepted"). The real cause, in the VTA log:

      trust task failed with an internal error
      cause=TSP was selected but this node has no TSP transport;
            it should not have been offered

  During provisioning the VTA publishes the new DID to its did-hosting
  server. That server advertises TSP, so the transport seam selected TSP —
  but the request arrived over the DIDComm handler, whose `WebvhDeps::
  from_vta_state` constructs the seam with `tsp: None` (it holds no TSP
  socket). `send_tsp` then hit its "no TSP sender" guard and turned the
  whole provision into an internal error instead of falling to the DIDComm
  the two parties genuinely share.

  The defect: `pick_transport` decided selectability from the compile-time
  `OUTBOUND_SUPPORTED` const, which names TSP in any `tsp`-feature build,
  and never consulted the runtime `Outbound.tsp`. `TspSender::
  from_app_state`'s own doc comment promised "absence here removes TSP from
  selection rather than failing at send time" — but nothing implemented it.

  This is the tail of #1483, which unified onto the seam so a TSP did-host
  is reached over TSP, but left `from_vta_state` passing `tsp: None` while
  the seam kept reading the static const. Before #1483 the webvh selector
  ignored TSP, so `tsp: None` was harmless; after it, it is a live fault.



## [0.33.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-service-v0.32.0...vta-service-v0.33.0) — 2026-09-17


### Added

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

- **tsp**: The VTC persists + answers TSP relationships and relates before sending to the registry (Rev 3 §7.2.2) ([#1543](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1543))

The VTC is a server like the VTA, but its TSP was half-wired: it drove the
  delivery layer yet built the ATM with a bare `ATMConfig::builder().build()`
  (in-memory relationship store, wiped on restart), its `handle_tsp` had no
  relationship-control answering arm, and `MessagingRegistryClient` sent Trust
  Tasks to the trust-registry with a plain `send_routed` and no relationship. So
  the registry §7.2.2-dropped every frame ("no relationship with ...trust-registry"),
  and a VTC restart would have dropped the registry's replies too.

  Bring the VTC to VTA parity:

    - Lift the durable relationship-store adapter (`KeyspaceRelationshipKv` +
      `maintenance_loop`) out of `vta-service` into a shared, feature-gated
      `vti_common::relationship_store`, alongside `VtiOutboxStore`. `vta-service`
      now re-exports it and keeps only its VTA-specific §7.2.2 drop telemetry.
    - Inject the store into the VTC ATM (`with_relationship_store`) over a new
      `tsp_relationships` keyspace — distinct from the VTC's social-graph
      `relationships`, and excluded from backup (transport state). Spawn the
      boot-enumerate + idle-eviction maintenance loop once at startup.
    - `handle_tsp` now answers `InboundKind::RelationshipControl` via a
      `decide_control` policy (accept an invite, record an accept, answer a
      cancel) — the ACL gate stays at the Trust Task layer.
    - `MessagingRegistryClient` sends over `send_reestablishing`: it forms the
      relationship (sends an invite) when readiness demands, then sends the
      payload (§3.6). A `TODO(D4)` marks the reply-timeout reset that belongs at
      the correlated-reply wait site.

  This is the sender-and-responder half of the same recovery work already landed
  in `vta-service` and the trust-registry. The `VtaClient`/`SessionStore` Auto
  path is a different client and was handled separately ([#1540](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1540)).

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



## [0.32.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-service-v0.31.0...vta-service-v0.32.0) — 2026-09-17


### Added

- **tsp**: Surface §7.2.2 relationship-gate drops as telemetry (D8) ([#1536](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1536))

The event that was invisible when the recovery workstream's incident happened — an inbound TSP application message dropped because the VTA holds no relationship with the sender — is now a queryable telemetry event, so a spike is an operational alarm rather than a scatter of error logs (design note tsp-relationship-recovery.md, D8).

  - vti-common: new TelemetryKind::TspRelationshipDropped (BREAKING — the enum is not non_exhaustive; carries a count field). No internal exhaustive match breaks — all sites construct.

  - vta-service build_messaging injects an Arc<AtomicU64> into the ATM via with_relationship_drop_counter (affinidi-messaging-sdk 0.26.7); the SDK gate increments it on every drop.

  - A drop_telemetry_loop spawned ONCE at server startup samples the counter each minute and records a TspRelationshipDropped event with the delta. Spawned beside the eviction sweep, not in build_messaging (which re-runs per reconnect).

  tsp-gated; non-tsp build unaffected. release-plz owns the version bump (the semver-report red is expected for the breaking variant).

- **tsp**: Durable-store maintenance — boot enumerate + idle eviction sweep (D6/D9) ([#1534](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1534))

Wires the D6/D9 SDK cores (affinidi-messaging-sdk 0.26.6) into the VTA:

  - KeyspaceRelationshipKv gains scan_prefix over the keyspace's prefix_iter_raw (keys are plaintext, values decrypted — the invariant the sweep relies on).

  - maintenance_loop logs how many TSP relationships survived a restart (D9 observability) then periodically evicts idle ones (D6/D5, 7-day default).

  - Spawned ONCE at server startup over its own store handle on the relationships keyspace — deliberately NOT in build_messaging, which re-runs per mediator reconnect and would leak a sweep task per reconnect.

  Bumps the sdk lock to 0.26.6 (affinidi/affinidi-tdk-rs#815). tsp-gated; non-tsp build unaffected. Design: docs/05-design-notes/tsp-relationship-recovery.md (D6/D9).

- **keys**: A derived key carries the algorithm it was minted with ([#1532](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1532))

* feat(keys)!: a derived key carries the algorithm it was minted with

  `DerivedEntityKeys` gains `signing_key_type` / `ka_key_type`, and
  `derive_entity_keys_with_preference` mints the first algorithm a template's
  `keys` block asks for that this build can produce.

  ## The defect this closes

  Every `save_key_record` call for a signing key passed the algorithm as a
  literal:

      save_key_record(ks, &vm_ids.signing, &derived.signing_path,
                      SdkKeyType::Ed25519,        // asserted, not carried
                      &derived.signing_pub, ...)

  Correct only while nothing else could be minted. The moment a template can ask
  for ML-DSA, that record names an algorithm the key is not — and a later signing
  operation reaches for a suite the key cannot work in, failing somewhere far from
  the place that decided wrongly. Same shape as the verificationMethod
  mislabelling fixed in #1528, one layer down: a type asserted where it should
  have been carried.

  The imported-key path reads the type from the stored `KeyRecord` rather than
  assuming, because for an imported key the record is where the truth about its
  algorithm lives — assuming Ed25519 there would mislabel an imported ML-DSA key
  at the one moment the system is being told what it is.

  ## Deviation from the plan, deliberately

  The plan said `DerivedEntityKeys` grows "from two fixed fields to a slot map".
  Counting the call sites changed the answer: the two slots are used in 53 places,
  and a map turns every one into a lookup that can fail while *removing* a
  property that is true and worth holding in the type — a DID document has exactly
  one signing key and at most one key-agreement key. `slots["signing"]` returning
  `Option` is a worse description of reality than a field that cannot be absent.

  What the plan was really asking is that a slot's **algorithm** stop being
  implied, which is what the two new fields do. A third slot — two signing keys at
  once, for hybrid credentials — has no consumer until Phase 3, and an empty map
  now would be a mechanism with no users, the thing this plan criticises elsewhere
  about `sign_multi`. The reasoning is recorded on the struct.

  ## Preference semantics

  An algorithm this build cannot mint is **skipped**, not refused — that is what a
  fallback is for, and refusing would make `["mldsa44", "ed25519"]` useless on a
  VTA without post-quantum support. Running out is an error naming what was asked
  for, never a quiet downgrade to Ed25519: the quiet downgrade is the whole
  hazard, because a deployment meant to be post-quantum would ship classical keys
  and nothing would say so.

  The key-agreement slot takes no preference. X25519 is the only algorithm that
  can serve it in a DID document; ML-KEM key agreement is TSP's hybrid KEM, not a
  verification method.

  ## Breaking

  `DerivedEntityKeys` gains two fields, so struct literals no longer compile —
  two in `vta-service`, fixed here.

  Three tests. The one that matters asserts the recorded type and the actual key
  **agree**, and was checked for non-vacuity by making them diverge: it fails with
  "signing_key_type says ML-DSA-44 but the key is 34 bytes".

- **tsp**: Persist TSP relationship state across restarts ([#1531](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1531))

* feat(tsp): persist TSP relationship state across restarts

  Rev 3 §7.2.2 has an endpoint silently drop application traffic from a VID it holds no relationship with. Every VTA ATM::new builds ATMConfig::builder().build() with no relationship store, so it gets the SDK's in-memory default — wiped on restart. A restarted VTA therefore forgets every TSP peer and drops their traffic until each re-handshakes, with no visible error (the failure that started this workstream).

  This injects a durable RelationshipStore backed by an encrypted fjall keyspace:

  - vta-keyspaces: a 'relationships' keyspace, added to ALL, EXCLUDED_FROM_BACKUP (re-establishable and DID-scoped, like sessions) and classified Cascade for DID deletion (protocol state keyed by the VID, like cache/outbox). Both census tests pass.

  - KeyspaceRelationshipKv (messaging/tsp_relationship_store.rs): a RelationshipKv over one KeyspaceHandle. Encryption-at-rest is uniform — the handle is opened via the same apply_encryption(store.keyspace(..)) as every other keyspace.

  - build_messaging (the long-lived TSP listener) injects PersistentRelationshipStore over that adapter via with_relationship_store, #[cfg(feature = tsp)]. The keyspace is opened beside outbox_ks in server.rs and threaded through MessagingConnect; both build_messaging callers pass it.

  Blocked on an affinidi-messaging-sdk release carrying the durable-store types (RelationshipKv, PersistentRelationshipStore) — affinidi/affinidi-tdk-rs#814. cargo check -p vta-service --features tsp fails on exactly those two symbols; everything else type-checks. Draft until that release lands. Design: docs/05-design-notes/tsp-relationship-recovery.md.

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



## [0.31.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-service-v0.30.0...vta-service-v0.31.0) — 2026-09-16


### Added

- **tsp**: Answer an inbound relationship request, instead of recording it and going quiet ([#1525](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1525))

The last functional piece of Rev 3. `affinidi-messaging-sdk` 0.26.4 surfaces a
  TSP relationship control message as `InboundKind::RelationshipControl` instead
  of dropping it after recording; `handle_tsp` now answers one.

  A relationship request is not traffic and must not reach the Trust Task spine:
  it carries no envelope, so dispatching it would answer a perfectly valid
  control message with "this is not a Trust Task envelope".

  ## The ACL gate is NOT here, and that was decided by building it here first

  The plan recorded this as the open question, and the first implementation put
  the gate on the invite: a sender with no ACL entry got an explicit
  `cancel_relationship` (XRFD) rather than §7.2.2's prescribed silent drop. The
  justification was diagnosability — a silent endpoint is indistinguishable from
  a broken transport, so an explicit refusal turns silence into an answer.

  Building it showed the argument runs the other way. A peer sends its invite and
  its first Trust Task together, which §3.6 expressly permits. Refusing the invite
  means §7.2.2 then drops the Trust Task, so the peer's actual request goes
  unanswered — and the XRFD it does get is a *control* message its application
  layer never sees. The gate produced exactly the silence it was meant to prevent.

- **backup**: Back up a DIDComm/TSP-only VTA with the chunkedTrustTask algorithm ([#1522](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1522))

* build(deps): trust-tasks-rs 0.21.1, the release carrying the chunked backup specs

  0.21.1 is the first release with `vta/backup/get-chunk/1.0`,
  `put-chunk/1.0`, `initiate-{export,import}/1.1` and
  `finalize-import/1.1` (trustoverip/dtgwg-trust-tasks-tf#474). A
  dispatched URI the registry has no schema for fails
  `every_served_uri_has_a_published_spec_or_is_tracked_debt`, so the floor
  moves with the tasks that need it.

- **vta-service**: Tune the VTA's rate limits at runtime ([#1519](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1519))

* feat(vta-service)!: tune the VTA's rate limits at runtime

  The per-IP limiters were tower_governor layers built once with the router, so
  changing a quota needed a config edit and a restart — exactly when an operator
  facing 429s can least afford one.

  The limiters are now our own axum middleware over governor's keyed limiter
  (already in the graph via tower_governor, whose spoof-safe client-IP key
  extractors are reused unchanged). The running service reads the four [server]
  quotas from the shared config on every request and swaps in fresh buckets when
  a quota changes; a change resets that limiter's buckets, and a patch that
  leaves a quota alone keeps them. trust_xff stays restart-only. The 429 contract
  is unchanged.

  rate_limit_interval_secs, rate_limit_burst, did_log_rate_limit_interval_secs
  and did_log_rate_limit_burst are registered in the config registry as mutable
  integer keys, applied live and persisted to config.toml: intervals 1-3600,
  bursts 1-10000, super-admin only, through config/patch like every other key.
  Their names come from vta_sdk::rate_limit, which the 429 hints also use.
  pnm and cnm `config update` gain --rate-limit-interval-secs,
  --rate-limit-burst, --did-log-rate-limit-interval-secs and
  --did-log-rate-limit-burst; `config get` shows the keys.

  Adds docs/02-vta/rate-limiting.md and links it from the docs index,
  non-interactive setup and the setup example.



### Fixed

- **vta-service**: Box handlers at the dispatch seam so debug builds don't overflow ([#1526](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1526))

The macro-generated `dispatch_typed` awaited every Trust-Task handler inline in
  its match arms, so the single dispatch future — and the enclosing
  `dispatch_trust_task_core` that the DIDComm and TSP inbound paths both call —
  was sized to the heaviest handler's future and grew with every heavy arm added.
  Debug builds don't elide that layout, so the first inbound Trust Task overflowed
  the worker-thread stack, which reads as (but is not) infinite recursion.

  Box each handler at the dispatch seam (`Box::pin($handler(..)).await`), so every
  arm is a pointer's worth of future and the match frame stays flat regardless of
  handler size. The boxed future is a concrete `Pin<Box<_>>`, so it stays `Send`.

  This makes three prior workarounds redundant, all removed:
  - the four per-handler `Box::pin`s #1522 added inside the backup 1.1 handlers,
  - the `op!` macro's per-operation boxing in services.rs (simplified to a plain
    `match $call.await`),
  - the hand-spawned 32 MiB threads on the two heaviest mock_vta tests, which now
    run as ordinary `#[tokio::test]`s on the default libtest stack and serve as
    the regression guards.

  A new mock_vta test, `heavy_trust_task_dispatches_on_default_stack`, drives a
  chunked `initiate-export/1.1` (a full state export inline — the largest handler
  #1522 hand-boxed) through the full inbound dispatch spine on the default stack.
  Unbox the seam and it overflows again.

  `room_owner.rs`'s handler-internal box is kept as defense-in-depth (its comment
  corrected) because no default-stack test exercises the `anchor` handler.

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



## [0.30.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-service-v0.29.0...vta-service-v0.30.0) — 2026-09-16


### Added

- **cli**: Name removal commands `delete`, and say what a delete leaves behind ([#1513](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1513))

* feat(cli): name removal commands `delete`, and say what a delete leaves behind

  Removal commands across pnm, cnm and the offline vta CLI are named
  `delete`. Each old name stays accepted as a hidden alias, so no script
  breaks:

  - `did-mgmt servers remove` -> `did-mgmt servers delete` (pnm + vta)
  - `pnm vta remove` -> `pnm vta delete`
  - `cnm community remove` -> `cnm community delete` (gains --yes/-y)
  - `pnm memory forget` -> `pnm memory delete`
  - `vta approvals disable` -> `vta approvals delete-all` (`disable` still
    works and prints a note naming the new command)

  Where a delete is not complete, the command now says what remains and
  how to remove it: `vta delete` / `community delete` keep the VTA's ACL
  entry (the notice prints the `acl delete <did>` that revokes it);
  `servers delete` lists DIDs still registered against the server, whose
  logs stay hosted there; `vault delete` / `cred-vault delete` without
  --force name `purge` / `--force`.

- **vta-service**: Give did.jsonl its own rate limiter and make VTA 429s attributable ([#1510](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1510))

* feat(vta-service)!: give did.jsonl its own rate limiter and make VTA 429s attributable

  One per-IP tower_governor bucket (burst 10, one token every 5 s) guarded the
  whole unauthenticated branch, including the public did.jsonl routes. A pnm
  command against a self-hosted VTA DID resolves the log and then runs challenge
  + authenticate from the same address, so a few commands in a row were refused;
  the mediator and the VTA's readiness gate fetch the log too. Serving the log is
  a store read with no crypto.

  - The DID-log routes (/.well-known/did.jsonl, the canonical catch-all,
    /did/{did}/log, TEE /attestation/did-log) move to their own per-IP limiter,
    keyed by trust_xff exactly as before, with new [server] keys
    did_log_rate_limit_interval_secs (default 1) and did_log_rate_limit_burst
    (default 60). The auth limiter keeps rate_limit_interval_secs /
    rate_limit_burst. The catch-all stays the only root wildcard, an opaque bare
    404, rate-limited and body-capped.
  - Every 429 from a VTA limiter carries x-rate-limit-source: vta,
    x-rate-limit-scope (auth | did-log | backup-blob), a rounded-up Retry-After
    and a plain body naming the limiter, with no configuration values.
  - Public log responses send Cache-Control: public, max-age=60 and a strong
    sha256 ETag, and answer If-None-Match with 304. 404s carry neither.

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

- **keys**: Derive ML-DSA keys from the BIP-32 chain ([#1505](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1505))

`Bip32Extension` gains `derive_ml_dsa_44` and `derive_ml_dsa_65`, and the five
  sites that refused post-quantum derivation now do it: key creation, both export
  paths, and the offline `vta keys secrets` CLI. This is what stands between "a
  `KeyRecord` can carry a post-quantum key" and "a VTA can mint one".

  ## Domain separation is the whole of it

  `derive_ed25519` hands the SLIP-0010 output straight to the key constructor, and
  FIPS 204 KeyGen takes a 32-byte seed — so the obvious implementation lines up,
  compiles, and is wrong: **the ML-DSA seed would equal the Ed25519 private key at
  the same path**, and compromising either would yield the other. Both values are
  32 bytes, which is exactly why it reads as correct.

  `derive_p256` already solved this, and these follow its construction exactly —
  HMAC-SHA512 over the derived signing key and chain code, keyed by a label, first
  32 bytes taken. The label differs *per parameter set*, because ML-DSA-44 and
  ML-DSA-65 are different algorithms and a holder of one must not be able to
  reconstruct the other.

  `ml_dsa_seed_is_independent_of_the_ed25519_key_at_the_same_path` is the test for
  it, and it is not theoretical: built against the naive version it fails with
  exactly that message. `the_two_ml_dsa_parameter_sets_get_independent_seeds`
  covers the second half.

  Simpler than P-256 in one respect — xi is 32 arbitrary bytes with no
  group-order constraint, so there is no reduction and no retry.

  The shared helper exists because the two derivations differ only in the label,
  and a second copy is how they would eventually disagree about how a seed is
  produced. That is unrecoverable rather than merely wrong: the key cannot be
  re-derived afterwards.

  ## Internal keys still refuse, and the comment now says why

  Not blocked on cryptography any more — `affinidi_crypto::ml_dsa` signs and this
  change derives. What is missing is a decision. An internal key is deliberately
  the opposite of a derived one: CSPRNG-generated, no derivation path, absent from
  the mnemonic, so losing the keyspace loses it and everything it authorises.
  Whether a VTA should hold an *unrecoverable* post-quantum signing key is a
  question about that trade, and it should not be inherited from a change whose
  subject was derivation.

  Enables `affinidi-secrets-resolver`'s `ml-dsa` feature, which nothing in this
  workspace had turned on — so `Secret::generate_ml_dsa_44` was not compiled here
  at all.

  121 test suites green under `--no-fail-fast`, clippy clean under `-D warnings`,
  rustfmt clean.



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

- **vta-service**: Trust a recent self-resolution instead of re-fetching per connect attempt ([#1509](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1509))

The mediator supervisor re-confirmed that the VTA's own DID resolves over the
  network before every connect attempt, and each confirmation built a throwaway
  DIDCacheClient and fetched did.jsonl uncached. For a VTA that hosts its own log,
  those fetches land on its own unauthenticated routes from its own address and
  share the per-IP rate limiter (10 burst, one token per 5 s by default) with
  everything else from that address. A run of connects failing for reasons that
  have nothing to do with resolvability (the mediator's negative cache, a
  mediator restart) spent that budget at one fetch per attempt, and the check
  straight after a passed gate fetched the document a second time.

  SelfResolutionProbe, owned by MessagingConnect and shared by the gate and every
  reconnect, remembers when a real network resolution last succeeded and answers
  from that for SELF_RESOLUTION_FRESH_FOR (300 s). Each real check is still a
  fresh resolver built and stopped per check, so the preloaded self-DID entry
  cannot mask anything and no long-lived socket needs stopping on shutdown. Only
  successes are remembered: a failure clears the confirmation and the next
  attempt resolves again on the existing backoff.

  300 s is the default mutable-method TTL of affinidi-did-resolver-cache-sdk, the
  resolver the mediator authenticates us through, so the mediator already acts on
  a copy of our document that old. If the document has become unresolvable
  inside the window, the connect's authcrypt check fails and the backoff governs
  the retry as before.

  run_gate and self_did_network_resolvable keep their signatures and behaviour;
  run_gate_with_probe and SelfResolutionProbe are additive.

- **tsp**: One transport for TSP, and it must carry a mediator ([#1507](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1507))

`pnm did-mgmt dids create` against a did-host advertising `#tsp` failed
  instantly with `trust task failed [internalError]`, and in the VTA's log:

      bad gateway: `did:webvh:...:dids.ic3.dev` could not be reached over TSP:
      Config error: No Mediator is configured for this Profile

  The VTA held two `ATMProfile`s for its own DID. `server::init_auth` built one
  with **no mediator** and parked it in `AppState.tsp_profile`, reasoning that
  unsealing a TSP envelope reads the decryption key from the ATM's secrets
  resolver and so needs no route. `messaging::service::build_messaging` built the
  mediator-bearing one and kept it inside `VtaMessaging`, where only the inbound
  loop could see it.

  That reasoning is false. Every TSP entry point in the messaging SDK resolves the
  mediator off the profile handed to it: `TspOps::pack` and `unpack_bytes` call
  `ATMProfile::dids()`, and `send_raw` calls it alongside
  `get_mediator_rest_endpoint()`. All three answer `ConfigError("No Mediator is
  configured for this Profile")` without one, before any I/O — so that profile
  could neither send *nor* unseal, and the vault `tsp-message` path it was built
  for had never worked either.

  It stayed invisible because a mediator-less profile is selectable: right type,
  registers on an ATM without complaint, fails only when asked to do work. The VTA
  answered TSP correctly throughout, because `handle_tsp` seals replies on the
  other profile. When #1482/#1483 taught the outbound seam to *initiate* over TSP,
  it sealed on the profile `AppState` held, and every TSP send died inside the SDK.

  Consolidated onto one type, `messaging::tsp_transport::TspTransport`: the ATM,
  the profile registered on it, and the mediator read off that profile. Its
  constructor calls `dids()`, so a mediator-less profile cannot become a transport
  and the defect is no longer expressible.

  - `handle_tsp` uses the session transport `build_messaging` now builds, so
    `mediator_did` leaves `run_inbound_loop`, `handle_inbound` and `handle_tsp` —
    it was threaded past a DIDComm arm that discarded it. A session whose profile
    cannot route fails the connect instead of coming up able to receive and not to
    answer.
  - `outbound::TspSender` holds a `TspTransport` instead of a mediator copied out
    of `AppConfig`: one fact, one source, nothing to disagree.
  - `step_up::try_push_over_tsp` drops its `mediator_did` argument; the caller's
    `approver_mediator` still gates whether a push happens and still picks the
    DIDComm fallback's route.
  - `operations::vault::upsert::unseal_tsp_secret` takes the transport rather than
    an ATM and a profile that came from different places.
  - `AppState.tsp_profile` is removed. `AppState::tsp_transport()` is the only way
    in, and `None` means no live mediator session — which drops TSP from transport
    selection rather than choosing it and then failing to send.

  The two ATMs stay, and that is deliberate. `AppState.atm` has no socket and no
  mediator by design: vault release, proxy-login and the DIDComm-envelope auth path
  pack and unpack through it with no profile at all, and must keep working on a
  REST-only VTA and while a session is down. Two ATMs with different lifetimes was
  never the defect; two profiles, one of which could not work, was.

  Nothing caught this because `MockVta::start_with_transports` reproduced the same
  split — it ran the inbound loop but left the bridge a placeholder and built its
  own mediator-less profile, so it could only ever answer. It now publishes the
  wiring the way `MessagingConnect::connect_once` does, and three tests hold the
  line:

  - `the_vta_can_initiate_a_tsp_send_not_only_answer_one` drives a real routed send
    through the embedded mediator, and reproduces the reported error verbatim when
    the old profile is put back;
  - `tsp_is_not_offered_before_a_mediator_session_exists` pins selection to the
    live session rather than to config;
  - `atm_profile_mediator_census` fails the build on any `ATMProfile::new(...,
    None)` under `vta-service/src`, with an empty allowlist.



## [0.29.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-service-v0.28.0...vta-service-v0.29.0) — 2026-09-16


### Added

- **keys**: ML-DSA key types, and one codec table instead of two ([#1502](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1502))


## [0.28.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-service-v0.27.1...vta-service-v0.28.0) — 2026-09-15


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



## [0.27.1](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-service-v0.27.0...vta-service-v0.27.1) — 2026-09-14


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

- **webvh**: Clamp versionTime against the previous log entry ([#1456](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1456))

* fix(tee): backdate WebVH genesis versionTime

  The TEE genesis path used the library's current-time default while
  runtime updates used PR #600's backdated timestamps. This caused the
  first update to have a lower versionTime than genesis, making the DID
  unresolvable.

  Apply the shared PR #600 backdating policy to TEE genesis and move the
  helper into vta-support so both TEE and service paths use one implementation.



## [0.27.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-service-v0.26.0...vta-service-v0.27.0) — 2026-09-12


### Security

- **resolver**: Refuse did:webvh resolution to non-public hosts by default ([#1448](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1448))


## [0.26.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-service-v0.25.1...vta-service-v0.26.0) — 2026-09-10


### Added

- **audit**: Write the VTA's audit log as a hash chain ([#1420](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1420))

* feat(audit): write the VTA's audit log as a hash chain

  The sink writes envelopes through the shared writer rather than flat
  rows: each entry commits to its predecessor, and the actor and any
  DID-shaped target are committed under a keyed hash with the plaintext
  beside them, so an erasure can null the plaintext while the row stays
  correlatable and the chain still verifies.

  The chain opens with the creation of the key that chains it. The key is
  established on the first write — there is nothing to audit before a
  node can act, and a node cannot act before it has somewhere to record
  what it did — so the first entry is the record of that key coming into
  existence, committing to its id. A verifier reading from the start
  learns which key the entries after it are hashed under, from an entry
  hashed under that same key.

  The keyspace and the storage-key format are unchanged except for one
  addition. The seconds stay the leading field, because the retention
  sweep compares keys against a cutoff in that shape and a different
  leading field would make every chained row sort past every cutoff and
  never expire. The nanoseconds are new and are not optional: whole
  seconds put two entries written in the same second in uuid order, so a
  verifier reading in key order sees them out of chain order and reports
  a break in a chain that is intact — a false alarm indistinguishable
  from the thing it exists to detect. The tests found this rather than
  review.

  The read path now accepts both shapes. A reader that knows only one
  does not fail loudly; it skips what it cannot parse, so a reader that
  knew only the older shape would have reported a log that stops at the
  moment chaining began.



### Changed

- **audit**: One construction point for the audit sink, and the prerequisites for chaining it ([#1412](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1412))

* refactor(audit): build the keyspace audit sink in one place

  The workspace built the same sink over the same keyspace in
  thirty-one places, including three times inside one function
  (run_create_did_webvh, which already had one in scope two hundred
  lines above the other two). Each was somewhere a later change to what
  a VTA's audit writes would have to be found and repeated.

  There is now one constructor, vta_audit::shared_keyspace_sink, and
  every caller goes through it. A server still takes its sink from
  AppState — that path was already correct, and its comment already said
  why. The factory is for the callers with no AppState to take one from:
  offline CLI commands, setup, sweepers and tests.

  No behaviour change. The next change to this subsystem — writing
  chained envelopes rather than flat rows — is now one edit instead of a
  search.



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



## [0.25.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-service-v0.24.1...vta-service-v0.25.0) — 2026-09-09


### Added

- **persona**: Say whether a link crosses a part of the holder's life ([#1342](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1342))

Serves the members added in dtgwg-trust-tasks-tf#408, published in
  trust-tasks-rs 0.18.10: `crossesFacets` and `facetIds` on a finding,
  `facetId` on each `sharedWith` location. This needs a floor of 0.18.10 —
  the spine validates OUTGOING responses, so under an older schema an analysis
  that fully succeeded would come back 500 `responseSchemaViolation` — and no
  longer moves one: main reached 0.18.11 while this sat open, which satisfies
  it. The bump this branch carried is dropped rather than resolved downward.

  **Severity is how linkable. Facets are whether the holder minds.** Nothing
  here touches `severity`, and that is the design rather than an omission. A
  value shared between two profiles in one facet still links them for anyone
  who sees both — the holder's filing changes nothing a counterparty can do —
  so softening severity on intent would report a false all-clear. What the
  facets add is a second axis: which of these findings the holder would
  actually want to act on.

  **Absent is unknown, not false.** `crosses_facets` is `Option<bool>` and is
  `None` when the holder keeps no facets, because `false` asserts these
  identities sit in one part of a life and an agent with no facets has made no
  such finding. `FacetIndex::any` is what carries that distinction, which is
  why the index is a struct rather than a map.

  **An unarranged profile is not a second facet.** Only distinct, named facets
  count toward a crossing. Counting "no facet" as one would make every holder
  who has arranged one part of their life and not the rest see a crossing on
  everything they own — the dismissal problem arriving from the other
  direction.

  `facet_index` is built once per analysis for the reason `disclosure_index`
  is: `analyze_correlation` with no `attributeId` walks the whole pool, and
  the per-finding shape re-lists every facet for every finding.

  The conformance witness now exercises the three new members rather than
  merely permitting them — they are the ones added last, and an outgoing
  member the embedded schema has not caught up with is a 500 on a call that
  succeeded.

  vta-persona 118/118 (6 new, one per rule above), vta-service lib 1063/1063,
  clippy --all-targets clean.

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

- **rooms**: A browser can be a room member ([#1347](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1347))

* feat(rooms): a `host` feature, so a room's member half reaches wasm

  `vti-rooms` already had two halves and no name for them: `vta-service`
  imports `mls`/`sealed`/`wire` and nothing else, while `vtc-service`,
  `room-host` and `vti-rooms-dtg` import `storage`/`authz`/`audit`. This
  names the second half `host`, on by default, and makes `vti-common`
  optional behind it.

  `vti-common` describes itself as server-side infrastructure and pulls
  axum, fjall and tokio, so it was the whole of what kept a room's member
  code off `wasm32-unknown-unknown`. With it optional,
  `--no-default-features --features mls` builds there — which is what lets
  a browser hold a room's keys itself rather than ask an agent to. See
  `docs/05-design-notes/data-rooms-demo-site.md`.

  The member half needed **no source changes** to get there. That is a
  property of `error.rs`, which deliberately does not use
  `vti_common::error::AppError` because key material is not a service's
  concern; a decision made for its own reasons that paid for itself here.

  `lifecycle` is deliberately left ungated: only hosts consume it today,
  but it needs nothing from `vti-common`, and a member computing a room's
  lifecycle state to explain it on screen should not need a host's
  dependencies.

  Three things about the wasm plumbing, each of which reports as a
  `compile_error!` that reads like an unsupported target:

  - OpenMLS 0.9 has a first-class `js` feature (`web-time` for the
    `SystemTime` wasm lacks, plus getrandom's JS backend). Declared
    per-target rather than as a feature of this crate, so building for
    wasm just works — verified wasm-only: `web-time` appears in the wasm
    tree and not the native one.
  - There are two getrandom majors in the graph. The 0.4 is ours; the 0.2
    arrives transitively under `openmls_rust_crypto` via RustCrypto's
    elliptic-curve stack, so no feature declared here could reach it.
    `getrandom_02` is a feature shim, not a dependency this crate calls.
  - With both declared per-target, **no `RUSTFLAGS` are needed** — the
    `wasm_js` feature alone selects the backend.

  CI gains two steps in the `features` job: clippy on the member half with
  no host, and a wasm32 `--lib` check, so neither property rots silently.

  `vta-service` now takes `default-features = false`: a VTA holds room keys
  and is never a room's host, so it no longer compiles one.

  * feat(rooms): vti-rooms-wasm — a data room's member half, in a browser

  The MLS group, record sealing and the epoch key chain, compiled to
  WebAssembly, so a tab can *be* a member rather than drive an agent that
  is one. `vti-rooms` supplies all of it; this crate is only the boundary,
  and its job is deciding what crosses.

  **Secrets do not cross.** Everything returned is public — a KeyPackage,
  ciphertext, an epoch number — with one deliberate exception: the
  snapshot, which is key material because OpenMLS persists a group through
  its provider rather than as a value. It goes in IndexedDB and nowhere
  else; the docs say so at the method, since it is the one thing here a
  caller could reasonably mishandle.

  ## Two layers, and why

  Every method appears twice: a plain Rust one with the logic, and a
  one-line `#[wasm_bindgen]` wrapper that converts the error. Not
  ceremony — `JsError` and `JsValue` are imported JS functions, so
  constructing one on a native target panics. A crate whose only entry
  points were wrapped would have no reachable native tests at all, and the
  tests worth having are exactly the ones asserting a *failure*.

  Both tests are of that kind, and both are round-trips rather than unit
  assertions, because everything worth catching happens between the steps:

  - a record must not open at a version or under a key it was not sealed
    for — the binding is in the AEAD's associated data, not merely
    alongside it;
  - a snapshot taken before a commit must *refuse* rather than return
    garbage, which is the failure mode a browser member will actually hit
    (a tab closed for a week, reopened after somebody else joined).

  ## Two API decisions

  - **JSON strings in and out**, not `serde-wasm-bindgen`. The structures
    crossing are the published `rooms/*` wire types and JSON is the form
    they already travel in, so the boundary speaks the transport's
    language and there is one fewer representation to get wrong.
  - **`applyCommit` returns `{ epoch, link }`**, not just the epoch. The
    rung is minted in the one moment any party knows both the outgoing and
    incoming keys; it is added to the member's own chain here, and
    returned because it is also what a host stores on their behalf. A
    member who never uploads one keeps their history only as long as this
    browser does.

  ## Size

  A `wasm-release` profile (`opt-level = "z"`, fat LTO, `panic = "abort"`)
  takes the artifact from 693 KB gzipped to **540 KB**. Separate from
  `release` because it trades compile time and native performance for
  bytes — right for one downloaded module, wrong for the services.
  `wasm-opt -Oz` is worth another slice and is not a cargo concern.

  CI reports both sizes rather than gating on a threshold: one picked today
  would be either slack enough to mean nothing or tight enough to fail on a
  dependency's patch release, and what a reviewer needs is the number in
  the log beside the diff that moved it.

  * feat(rooms): gate the browser member on a room invitation

  A VIC is the consent artefact: joining a room is a two-party act and the
  invitation is the other party's half. Ported from vta-service's
  operations::room_invitation, including its check order.

  The gate is on the MEMBER's side, which looks wrong until you ask what it
  defends. Not the room — this key holder. Minting retains a private key
  against a Welcome that may never come, so a key holder that minted for
  anyone is one anyone can fill; and a Welcome carries a group's secrets,
  so accepting an uninvited one holds keys for a room nobody agreed to
  join. The room's own protection is the owner refusing an uninvited key
  package. Two parties, two threats, neither substituting for the other.

  Verification is lexical: the proof is checked against raw public-key
  bytes and a did:key room carries its key in its own name, so a browser
  needs no resolver and cannot be offline. A did:webvh room would need real
  resolution, and that is the one thing this would grow.

  ## A check the original is missing

  Writing a test per clause — rather than one 'a bad invitation is refused'
  case, which passes with any four of five — showed the forgery clause did
  not bite. Nothing binds the proof's verification method to the ISSUER.
  verify_proof_with_public_key checks a signature against whatever bytes it
  is handed, so resolving the method the proof names and verifying against
  that proves somebody signed it, which is also true of a forgery: mint an
  invitation naming the room as issuer, sign it with your own key, point
  the proof at your own verification method, and every other check passes.

  Added here as its own clause. vta-service's copy has the same shape and
  needs the same fix — reported separately; this is a second copy of a gate
  that should live in vti-rooms where both can share it.

  * feat(rooms): the member's key and its authority presentation, in wasm

  Two halves of one thing: everything a member signs is signed in wasm, so
  the private key never crosses into JavaScript.

  The first cut minted the key with WebCrypto and kept the JWK in
  `localStorage` — a raw private key in a page's heap and in a string store
  any script on the origin can read, contradicting this crate's own rule
  that secrets do not cross. Minting it here costs nothing (`ed25519-dalek`
  already arrives through OpenMLS) and leaves JS holding two opaque
  snapshots and no key. `Debug` is hand-written to redact: the places a
  `Debug` reaches — a log line, a panic, a test failure — are exactly the
  places key material must not turn up.

  `present` mints the authority presentation every host task takes:
  attenuate the room's VAC to one action, sign as the member, and return
  `{membership, authority: [leaf, root], nonce}`. Attenuation refuses to
  widen, so asking for more than the room granted fails here — where the
  member can be told why — rather than as a refusal from a host worded as
  though they were at fault.

  ## It takes no `audience` parameter, and that is the point

  `audience` is not who the presentation is addressed to. `verify_chain`
  compares it to the PRESENTER — "the leaf must be presentable by whoever
  is presenting it" — so it is holder binding, and its job is to make a
  captured presentation worthless to anyone else. A browser member always
  presents its own, so the only correct value is its own DID, and offering
  the choice is offering a way to get it wrong.

  Not hypothetical: `vta-cli-common`'s `RoomTarget` passes the HOST's DID
  as the audience, so `pnm-cli rooms --host-did …` mints a leaf bound to an
  audience no presenter can match — refused as `WrongAudience` every time —
  while omitting the flag leaves the presentation bearer-shaped for four
  hours. Its doc states the intent exactly ("with it, a captured
  presentation is worthless to anyone else") and names the wrong party.
  Reported separately.

  Tests assert against `dtg_credentials::authority::verify_chain` itself,
  not a restatement of it: the presentation verifies, a narrowing to `read`
  does not authorise `curate`, over-asking is refused locally, and a
  captured presentation fails for the thief as `WrongAudience` rather than
  as a bad signature. Also pins the shape the server path never produces —
  a browser member is its own agent, so the leaf's subject and the chain
  root's are the same DID.

  * fix(rooms): a presentation travels as strings, not objects

  AuthorityPresentation types membership as a String and authority as a
  Vec<String>: the credential TEXT is the wire form, and vti-rooms-dtg
  decodes base64url or bare JSON on the way in. present() was emitting
  parsed objects, so room-host refused the whole request as "invalid type:
  map, expected a string" — which reads as a malformed payload rather than
  as the shape mismatch it is, and points at the wrong field.

  Found by sending one to a real host rather than by reading the type.

  The root is now passed through exactly as received instead of being
  re-serialised, so nothing on this side can touch the bytes its proof was
  made over. Both tests assert the wire form — that each authority link is
  a string and membership is one too — because a chain that verifies in a
  test and is refused on the wire is the failure this cost an hour to.

  * fix(rooms): the wasm member links a chain the way its hosts verify one

  dtg-credentials 0.7 changed how an authority chain links — a link's
  `parent` went from naming the parent's `id` to naming a *digest* of its
  claims — so a 0.7 `attenuate` and a 0.6 `verify_chain` cannot
  interoperate. The refusal reads as a broken chain rather than a version
  skew:

      chain link 0 names parent `zQmPvoS…`,
      but was presented after `urn:uuid:0647…`

  Found by pointing a browser member at `room-host` and watching a
  perfectly good presentation be refused. Pinned to what the workspace
  verifies with. Reported upstream as OpenVTC/dtg-credentials#22, which
  asks for ordering guidance and a hint in that error message.

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

- **rooms**: Bind an invitation's proof to its issuer ([#1353](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1353))

An invitation naming a room as issuer, signed by anybody at all, was
  accepted. Every other clause passed: it is an invitation, the issuer
  field is the room, the subject is the member, the window is open, and
  the proof verifies — against the attacker's own key, which is the one
  the proof named and the one this module went and resolved.

  Nothing looked at *whose* key it was. So anyone could mint themselves an
  invitation to any room, hand it to their own agent, mint a KeyPackage
  against it, accept the Welcome, and hold that room's group keys. The
  invitation is the consent artefact for joining; without this check it
  consented to nothing.

  The fix is four lines, before the resolver call rather than after: a
  credential that cannot be the room's own is refused without a network
  round trip.

  ## How it was found, which is the part worth keeping

  By porting this module to a browser and writing a test per clause instead
  of one "a bad invitation is refused" case. That shape passes with any
  five of six, and did. The module had no unit tests at all — verify() is
  async and takes a `&dyn VerificationKeys`, which reads as needing a
  resolver and a network, when a fifteen-line did:key resolver is enough to
  exercise the whole of it. Four tests added on that.

  The check list in the module docs is renumbered five to six. A doc
  comment that counts its own checks is load-bearing: it is how the next
  reader knows whether one went missing.

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

- The last two #1341 fallout failures ([#1359](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1359))

* fix(vta): the hosted-DID services test drives REST directly

  `services_write_paths_against_a_hosted_vta_did` repoints `cfg.vta_did` at a
  `did:webvh` the mock mints at runtime. The agent's response-signing identity
  does not follow — `signing_vm_id` is computed once at boot — so the mock
  answers signed as its `did:key` while claiming to be the hosted DID, and
  `VtaClient` refuses every reply since #1341. The refusal is correct; the
  fixture is what is inconsistent.

  Booting the mock with the hosted identity, which is the obvious repair, fixes
  the signer and not the verification. The DID is minted against `StubWebvhHost`,
  which publishes nothing and answers on loopback under a domain that resolves
  nowhere, so a reply signed as it is unverifiable by any client in any process.
  There is no arrangement of this fixture in which a verifying client accepts an
  answer from a stub-hosted DID.

  The subject of the test is the agent's `services/*` write paths, so the four
  dispatches go over the REST binding directly: the same signed document
  `VtaClient` builds, to the same `/trust-tasks` route, with the same bearer
  token. Everything server-side is unchanged — §7.2 admission, the dispatch
  spine, the handlers, the response proof. Only the client's verification of the
  reply is out of the picture, and it is not what this test covers.

  Making `signing_vm_id` runtime-mutable was the other candidate and is worse: it
  would reshape `AppState` to permit something production forbids, which
  `config_registry_round_trips_and_identity_stays_read_only` exists to record.

- **sdk**: The mock VTA signs its answers, as every real one does ([#1355](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1355))

* fix(sdk): the mock VTA signs its answers, as every real one does

  Third wave of the #1341 regression, and the first to be fixed at the cause
  rather than per-test. Main is red on `vta-service`'s round-trip suite; this
  takes it from 0/10 to 10/10 without touching a single test.

  **The harness never did what production does.** `server.rs` sets
  `signing_vm_id` to `{vta_did}#key-0` for every DID method that is not
  `did:peer`, so a REST-only VTA signs its answers with its own key and needs
  no transport identity to do it. `build_test_app` populated that slot *only*
  from `build_transport_state`, which requires a `did:peer:2` — so a `MockVta`
  answered unsigned where the real thing signs, and every round-trip test
  failed with the client blaming the reply for something the harness had never
  provided.

  **The sentinel had to go, for the reason `TEST_ADMIN_SEED` records.** The
  mock's `did:key:z6MkTestVTA` was not a `did:key` at all — the same mistake
  that note describes fixing for the admin identity, and for the same reason:
  nothing resolves it, so nothing it signs can carry a verifiable proof. It is
  now derived from `TEST_VTA_SEED`, and the 28 references that named the
  literal name the real one.

  Deliberately *not* a full provisioning. The default mock gets a real identity
  and the key behind it, and still no seed records or keystore, so a test that
  asserts an unprovisioned VTA still gets one. Only enough to sign.

  `secret_from_ed25519` carries the sharp edge: `Secret::from_multibase` needs
  the multicodec prefix (`0x80 0x26`, ed25519-priv) and refuses raw bytes with
  `Unsupported key type`, while `decode_private_key_multibase` accepts either.
  The two encodings look interchangeable and are not.

  Also, in the spine: a VTA **configured to sign and unable to** now answers
  with a 500 naming the verification method, instead of silently answering
  unsigned into a client that will refuse it and report the reply as the
  problem. A VTA with no signing identity at all still answers unsigned —
  unchanged, and correct for a pre-setup agent.

  `client_round_trip` 10/10, `mock_vta` 12/13. Two known failures remain and
  are the same regression in two more stand-ins; see the PR.

- **rooms**: Verify a host's reply before believing it ([#1337](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1337))

#1334 and #1335 made both services sign their responses. Nothing verified
  one, so the property was not yet bought: producers signing and consumers not
  checking leaves the signature decorative.

  This is the first consumer to check, and it is the one the rooms work
  introduced — the VTA calling a room's host on its principal's behalf.

  **A reply is bytes off a socket.** Without a proof it attests to nothing: an
  intermediary can rewrite a record listing, change the epoch a chain claims
  to reach, or answer for a host that never spoke, and every check downstream
  would pass — because the checks downstream are about shape.

  Two things are required, and the second is the one easy to omit. The proof
  must verify, and its proven signer must be **the host this agent addressed**.
  `verify_trust_task_proof_with` says so in its own documentation: a proof by
  `did:webvh:…:someone-else#key-0` verifies perfectly well, and that it is not
  the party you expected is a separate check. Without the binding, "signed by
  somebody" gets mistaken for "signed by the host", which is the entire
  property.

  Error documents are exempt, from the specification rather than for
  convenience: a refusal's `type` resolves to `trust-task-error`, whose own
  proof requirement is RECOMMENDED (SPEC §8.1). Demanding one would make every
  conforming refusal unreadable — including the `hostRefused` this family
  declares, whose whole purpose is carrying the host's reason to an operator.
  A refusal confers nothing, which is why the framework asks less of it.

  This rejects unsigned success replies outright rather than warning, so a
  room host that predates #1334 will be refused. That is the intended
  behaviour and it is a deployment-order constraint: hosts upgrade before
  agents that talk to them.

  `cargo test -p vta-service --lib`: 1063 passed, 0 failed.

- **vta**: Sign success responses, completing the producer half ([#1335](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1335))

The agent side of #1334. Same gap, same reasoning: SPEC §7.3 item 7 makes a
  single `proofRequirement: REQUIRED` bind the response as well as the
  request, 265 published specifications declare one, and this service attached
  a proof to none of their responses. No consumer verifies one either, which
  is why nothing ever went red.

  Two things made the agent harder than the community, and both are decisions
  rather than mechanics.

  **It does not sign through `load_vta_issuer_secret`.** That helper reads the
  keystore, derives, and writes an audit entry per access. Signing every
  response through it would turn "the agent's issuer key was used" into one
  line per request — drowning a security control in its own noise, which is a
  worse outcome than the gap being closed. It signs from the resident secret
  `secrets_resolver` already holds for the messaging layer: no keystore read,
  no audit entry. The agent signing its own words is not a key access worth
  recording, it is the agent speaking.

  **`signing_vm_id` is no longer feature-gated.** It was
  `#[cfg(any(feature = "didcomm", feature = "tsp"))]`, which would have made a
  `--no-default-features --features rest` build answer the same specifications
  without the proof they require. Conformance must not depend on which
  transports were compiled in.

  The guard is in three parts because the first two are not enough, and
  finding that out is the useful part. `attach_proof` is tested directly — it
  produces a verifiable proof, replaces a stale one rather than nesting, and
  degrades on an unsignable body. Those tests **passed with the call deleted
  from the spine**, which is exactly the shape of the bug they exist to
  prevent, so a source assertion covers the wiring and a state-level test
  covers the plumbing. A comfort is not a guard.

  Worth recording: `build_signing_test_app_state` already ships a resident
  signing secret. The degradation case clears it explicitly rather than
  assuming its absence — the first draft assumed, and was wrong.

  `cargo test -p vta-service --lib`: 1061 passed, 0 failed.



## [0.24.1](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-service-v0.24.0...vta-service-v0.24.1) — 2026-09-08


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

- **persona**: Let a deployment declare its own claim types ([#1327](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1327))

Teaching an agent one word cost five steps across two repositories: a pull
  request against the specification, a publish, a hand-transcription into
  `vta-persona`'s table, a release, a deploy. So nobody did it, every local token
  — `profile.github`, `employer`, whatever an ecosystem actually keeps about its
  people — resolved to the unregistered floor, and holders were shown their own
  values masked as though each were a passport number.

  `CLAIM-TYPES.md` §6 anticipated exactly this: the served-table task was "worth
  doing when the first extension type ships, not before". It ships now.

  `VTA_CLAIM_TYPE_EXTENSIONS` names a JSON file of rows in the shape the agent
  already serves, so an operator can copy a row out of
  `persona/claim-types/list`, change it, and put it back.

  **Extensions feed the same lookup the resolution uses.** `declared()` is one
  iterator over core plus extensions, and `defaults_for`, the family walk and
  `registry_listing` all read it. That is the task's central MUST — what is served
  and what is enforced cannot disagree — and two tables walked separately are two
  tables that resolve differently. The family step is where it would have shown:
  an extension family the exact lookup knew about and the walk did not.

  **What an operator may declare, and why the line falls there:**

  - Anything core does not cover. A token core has never heard of resolves to the
    floor *because nobody has reasoned about it* — §4 rule 3 says so — and an
    operator declaring it is that reasoning arriving.
  - Tightenings of anything core does cover. That direction takes nothing from
    anyone.
  - Not loosenings, compared against what core resolves — exactly (`email.work`)
    or through a family (`payment.giftCard` under `payment`). Otherwise a
    deployment could declare a passport unremarkable, or escape a gated family by
    inventing a member of it, which is the hole rule 3 exists to close.
  - Never an `x:` token. §4's last rule makes that namespace unregistered by
    construction; a row declaring one is a row no conforming client would honour.

  **A bad file stops the agent starting**, rather than dropping the offending row.
  Serving a table the operator did not write means a tightening they believe is in
  force is not, and the values it was meant to protect are the ones they would
  hear about last. An unknown axis value is refused rather than defaulted for the
  same reason — `"hgih"` reading as `normal` looks exactly like a rule that works.
  Loaded rows are logged with the path and the count, because "why is this masked"
  is the question an operator will actually have.

  Configured rather than administered, and the reason is upstream: serving an
  admin task to edit the registry live needs a published task specification first,
  since the dispatcher refuses a URI the registry does not declare. A file is
  diffable, reviewable, and belongs to whoever owns the deployment.

  Nine new tests over the rules, plus `docs/02-vta/claim-type-registry.md` for the
  operator. 99 vta-persona and 1047 vta-service unit tests pass; `cargo fmt
  --check` and `cargo clippy --all-features` clean.

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

- **persona**: Honour a holder's release override at disclosure ([#1310](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1310))

#1304 enforced `release: stepUp` from the claim-type registry only; a holder's
  per-attribute override was ignored. `Attribute` carried a comment explaining
  why the field had been withheld — "a stored override for a gate that does not
  exist is a promise the holder would be entitled to rely on". The gate now
  exists, so the field can be stored honestly.

  The override is set above the boundary and enforced below it, so it travels
  with the projection: Attribute.release → ResolvedClaim → MaterialisedClaim →
  the gate. Nothing reads up. Re-materialisation on an attribute edit already
  propagates, so changing the override changes what every bound context enforces.

  Resolved once at preview creation onto `Preview.step_up_required` rather than
  derived at read like `sensitivity`, because `PreviewClaim` is serialised
  straight into the preview response and that schema declares
  `additionalProperties: false` — this is an at-rest decision, not something a
  verifier is owed. A preview is a single-use snapshot expiring in minutes, so
  freezing it for that window is also the honest reading.

  An override wins in both directions, per CLAIM-TYPES §4 rule 1. Loosening is
  not a hole because `attribute/put` is holder-scoped: no verifier and no
  context-scoped caller can reach it. The audit row records the decision either
  way, since relaxing a card from stepUp to consent is the most consequential
  thing this task can do.



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

- **persona**: A bad claim-type row is refused, not fatal ([#1331](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1331))

The first version exited on a bad extension file, on the reasoning that serving
  a table the operator did not write is worse than not serving at all. That is
  right for a laptop and wrong for a hosted agent: refusing to boot takes out
  sessions, credentials and mediation over a mis-typed claim type, and in a hosted
  deployment nobody is reading stderr.

  Rejection is per row now. The good rows apply, the agent starts, and every
  refusal is reported — an ERROR log line each, and carried on
  `persona/claim-types/list` under `ext["org.openvtc.claim-types"]` as
  `rejected: [{type, reason}]`, with `fileError` beside it when the file itself
  could not be read. `ext` is the specification's vendor-namespaced member, so
  this needs no spec change and a client that does not know the key ignores it.

  **The direction it fails in is stated rather than assumed.** A refused row is
  not applied, so its token resolves as if the file had never mentioned it. For a
  word core has never heard of that is the most protective answer. For a row that
  meant to *tighten* a core type it is not — the looser answer stays in force,
  which is the case the old behaviour existed to prevent. Nothing makes that safe
  except somebody seeing it, which is why the reasons travel to a screen instead
  of stopping at a log line, and why a test pins the resolution rather than only
  the refusal.

  A duplicated token disqualifies **every** row naming it rather than letting the
  first win: applying one of two conflicting declarations is a guess at what the
  operator meant, and an invisible one.

  102 vta-persona tests pass (3 new), `cargo fmt --check` and `cargo clippy
  --all-features` clean.

- **persona**: Give the disclosure step-up context a type an approver can render ([#1306](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1306))

`initiate_disclosure_step_up` emitted a flat bag of members with no `type`.
  `vta-mobile-core` passes the authorization context to the native layer to
  "decode and render as the approval card", and that card discriminates on a
  `type` URI — so the context that exists to show the approver what would leave
  was one no card could be chosen for.

  Now the shape every authorization context uses: `{type, summary, risk,
  action}`, with the specifics under `action` keyed by `kind`.

  `summary` is the same string as `reason` on purpose — `reason_and_context`
  reads `summary` back out as the reason, so two sentences would put two accounts
  of one act in a single signed document. `risk: "high"` restates the claim-type
  registry's judgement rather than making a fresh one: everything reaching this
  gate is a type the registry marked `release: stepUp`.

  Cuts over with OpenVTC/vta-browser-plugin#189, which reads the new shape and
  refuses a context whose `type` is not this one — a share ask travels under the
  same `ext` key and must never be shown in a disclosure's words.



## [0.24.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-service-v0.23.5...vta-service-v0.24.0) — 2026-09-07


### Added

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


### Fixed

- **persona**: The audit trail says what changed, and correlation/analyze conforms ([#1283](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1283))

* fix(persona): the audit trail says what changed

  Every persona write recorded action, actor, resource and outcome and
  nothing else. `audit_persona` called `audit::record(...)`, which has no
  `detail` parameter, so a console audit pane showed twenty rows of
  `persona.attribute.put` against opaque ULIDs with no way to tell a
  create from an update, a cascade delete from a no-op against a typo'd
  id, or a binding that materialised forty claims from one that cleared
  them.

  The console side was never the problem: `AuditEnvelope` already renders
  `detail` in full as `detail.reason`. There was simply nothing to render.

  So the write handlers now go through `audit::record_with_detail` and
  supply one: attribute put/delete, profile put/delete, binding/set, and
  the three context-local writes each say what changed — created or
  updated, the claim type, the value type, the provenance kind, entry and
  claim counts, whether the record existed, how many profiles or personas
  were affected, and the resulting version. Reads still pass `None`; a
  read changes nothing, and a sentence restating the request would be
  noise in an append-only store.

  The attribute VALUE stays out, and `audit_persona` now explains why at
  length, because the reason is not the one people assume. It is NOT an
  access-control reason. Persona rows are recorded with `context_id:
  None`, and `operations::audit::authorize` already refuses every entry
  not confined to a named context to anyone but an unrestricted admin —
  exactly the caller `Reach::Holder` admits to `attribute/list`, which
  returns the plaintext outright. Nobody gains a read by us writing one.

  The reason is lifetime. The audit keyspace is append-only and pruned on
  its own retention schedule; the pool is deleted when the holder deletes
  an attribute. Copy a value across and `attribute/delete` quietly stops
  being a delete — the value outlives the record it came from, in a store
  the holder's delete does not reach. Stating that distinction matters,
  because "don't log values" as a bare prohibition is the rule somebody
  relaxes the first time an operator asks for a better trail, and the
  access-control argument does not survive that conversation.

  The new test asserts both halves together. A test that only checks the
  value is absent passes against a handler that records no detail at all,
  which is precisely the state being fixed.

- **persona**: "edit once, everywhere" reached nothing ([#1281](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1281))

A holder edited their name and the verifier was still shown the old
  one. `rematerialise` — the function whose docstring explains that a
  context holds a materialised copy and can only be updated by a write
  from above the boundary — was **called from no handler in the
  codebase**. The only reference outside its own file was a comment in a
  test.

  A context may never read the pool, so its copy changes only if
  something pushes. Nothing did. `attribute/put`, `attribute/delete
  --cascade` and `profile/put` all changed what a profile projects and
  left every bound context presenting the state from before the edit,
  which `disclosure/preview` and `disclosure/present` then handed to a
  verifier.

  **The push now belongs to the write, not to the call site.** `put`,
  `delete` and `put_profile` push before returning, from inside the lock
  they already hold. Leaving it to handlers is the same decision taken
  once per call site and forgetting it is silent — the pool shows the new
  value, the console shows the pool, and only the verifier sees the old
  one.



## [0.23.5](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-service-v0.23.4...vta-service-v0.23.5) — 2026-09-06


### Added

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

- **vta**: Discharge the backup family's spec debt, and audit what it was hiding ([#1239](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1239))

* feat(vta): discharge the backup family's spec debt, and audit what it was hiding

  trust-tasks-rs 0.17.7 carries the six specs from
  trustoverip/dtgwg-trust-tasks-tf#347, so `vta/backup/*` and
  `vta/management/reload-services` come off `UNSPECCED_DISPATCHED_URIS` and
  gain conformance witnesses. The reduction plan's §D suggestion of a
  top-level `backup/*` was not taken: the family is agent lifecycle, and
  `vta/` is where the rest of it lives.

  That was meant to be bookkeeping. It was not.

  ## Making them visible showed three of them succeeding silently

  The audit census could not see these tasks before, because an unspecced
  task has no witness and an undriven task reports nothing. The moment it
  could, it found three consequential successes leaving no trace at all:

  - **`initiate-export`** — mints a *fetchable copy of the entire agent* at
    a known address.
  - **`initiate-import`** — opens a *writable endpoint into* the agent.
  - **`reload-services`** — restarts the agent, dropping every open session.

  None of the three alters stored state, which is why nothing state-shaped
  ever caught them: the only evidence these operations happened is the row
  that was not being written.

  `reload-services` is the sharper case. It *had* an audit call — the
  `audit!` macro, which emits a `tracing` event and never touches the
  `AuditSink`, so nothing it recorded reached `audit/list` or an operator's
  sink. That is precisely the defect the census module header describes,
  sitting undetected in a task the census could not drive. Its sink write is
  placed **before** `trigger_restart`, because the restart tears down the
  runtime the write runs in.

  ## Three more the census structurally cannot reach

  `complete-export`, `finalize-import` and `abort` were silent on success
  too, and the sweep would never have said so: all three need a real bundle,
  the census drives an empty store, and it therefore only ever sees their
  not-found refusals. It would have reported this family green.

  Found by reading rather than by the sweep, and the blind spot is written
  into the helper's doc comment — a test that cannot reach a path cannot
  vouch for it, and the next person should not mistake a green census for
  coverage of these three.

  `finalize-import` is the one that matters most. On commit it replaces the
  agent's keys, ACLs, contexts **and its audit trail**, so a row written
  into imported state would document its own erasure. It is recorded to the
  sink after the op returns, which is outside the state the import replaced.

  ## Witnesses

  Both `password` fixtures carry an obvious non-secret, and so does
  `transportToken`. The specification's schema directory deliberately holds
  no specimen password — a fixture value is the one thing implementers copy
  — and a witness is read far more often than a spec. `finalize-import`'s
  request pins `confirm: false`: a committing witness would be the one shape
  in that table whose meaning is "replace the agent".

  `cargo test -p vta-service` green — 1014 lib tests and all 25 integration
  binaries; `cargo fmt --check`, `cargo clippy --all-features`, `cargo check
  --workspace` clean.

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

- **acl**: Add MemoryRead/MemoryWrite and gate the memory tasks on them ([#1234](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1234))

There was no read-only grant on agent memory. The gate in
  trust_tasks/memory.rs was auth.require_context and nothing else, and a
  context is binary: any DID that could reach one could also write and
  delete every memory in it. So an operator could not give an agent
  read-only access to their own memory, and the --read-only flag in
  vta-mcp's guard is a client-side glob filter that a caller talking to the
  VTA directly never encounters.

  The published specification already assumes the split exists.
  specs/vta/memory/delete/0.1/spec.md reasons about "a VTA whose write
  capability is granted more freely than its read capability", and about
  callers holding write without read. There was no read capability and no
  write capability; there was a context. The ACL supplied nothing finer
  either - the act axis is (role, allowed_contexts) decoded to a
  three-valued ActScope, a where with no what.

  Adds Capability::{MemoryRead, MemoryWrite}, wires them through
  derived_capabilities_for_role, and gates the three handlers. Legacy rows
  carry no explicit capability set and fall back to the derived mapping, so
  the roles that write memory today keep writing it.

  Deliberate behaviour changes, both tightenings:

  - reader loses memory write. A read-only consumer of a context should not
    be able to rewrite the memories in it.
  - monitor loses memory access entirely. It is the least-privileged role
    and the Default for AuthClaims, precisely so a fixture that leaks past
    its expected reach lands somewhere harmless - which it did not, while
    memory was context-gated alone.

  application keeps both, deliberately and with a test saying why:
  vta-agent-memory grants exactly that role so the memory service is not
  the user, and every existing install would otherwise stop saving.

  The capability is checked before the context, so a caller missing it
  cannot use the reason text to probe which contexts exist.

  Note the canonical Capability enum in the trust-tasks registry
  (device/_shared/0.1) is already behind this crate - it carries neither
  sign-trust-task nor credential-write. A spec PR reconciling all four
  follows separately; this change does not widen that gap unilaterally so
  much as make it worth closing.

  Implements the orthogonal fix called out in
  docs/05-design-notes/data-rooms.md 11.1.



### Fixed

- **persona**: Drive the slice end to end, and fix the four things that found ([#1258](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1258))

Every layer of the persona slice was tested and none of the seams between
  them were. The unit tests assert that `authorize` refuses a context-scoped
  caller; they cannot say whether the dispatcher ever calls `authorize`. The
  store tests assert that a materialised claim carries no pool identifier;
  they cannot say what a context receives on the wire. Those are different
  claims and only one of them is about the system.

  `vta-service/tests/persona_trust_task.rs` posts real Trust Task documents
  through the real dispatch spine into the real store. It failed on four
  counts the first time it ran.

  **`renderers/list` refused the most privileged caller.** The handler
  supplied a context from `auth.allowed_contexts.first()`, reasoning that a
  caller should name one so the request is attributable. That was wrong
  twice: the context did not come from the request, so it attributed
  nothing; and reading the caller's own list inverted the gate — an `Admin`
  with an unrestricted (empty) list is the most privileged caller there is,
  and was the only one refused, while every scoped caller was admitted.
  This is the `allowed_contexts.is_empty()` family CLAUDE.md warns about,
  reached by a route the warning does not name.

  The fix is a third reach rather than a different one of the two, because
  both are wrong for this task in opposite directions. `Context` refuses the
  unscoped holder — the payload schema has no `contextId`, so there is no
  context to name. `Holder` would refuse the callers who most need it:
  `disclosure/preview` is context-scoped and takes a renderer name, so an
  application that cannot list renderers cannot choose one, and choosing
  blind is how a holder discloses through a format that silently drops
  provenance. `Reach::Any` says what is true — the response is a
  compile-time constant naming nothing about anybody.

  **Two responses emitted `null` where the schema types a string.**
  `disclosure/present` for an unminted `credentialId`, and `binding/get` for
  `profileId` / `profileName` / `boundAt` when nothing is bound. `json!`
  renders a `None` as `null`; an unset optional must be *absent*. This is
  the response-side twin of the rule `payload_null_census` pins on requests
  in `vta-sdk`, and it has no census — the response-conformance layer caught
  it at run time, which is the only reason either was noticed. Both now go
  through `put_opt`.

  Note which case failed: `binding/get` conformed while bound and did not
  while unbound. That is the wrong way round — "nobody is bound here" is
  exactly the reading a caller needs to be able to trust.

  **`profile/get --resolve` omitted three required members**, because
  `ResolvedClaim` never carried them. It now carries `valueType`, `version`
  and `updatedAt`, which are also the members that make a resolved read
  useful: a holder can see that an entry is pinned to v3 while the pool is
  at v5.

  **And a spec defect the same test surfaced.** That response types each
  resolved entry as the pool `Attribute` shape, requiring `attributeId`,
  `updatedAt` and `version`. An inline entry has none of them — it has no
  pool record behind it, which is the reason inline exists. So `resolved` is
  a projection that may contain non-pool values and the pool record's shape
  cannot describe them.

  Until that is fixed upstream the handler refuses, naming the reason. The
  two alternatives are both dishonest: a synthesised `attributeId` lies
  about where a value lives, and omitting the entry returns a profile that
  appears to present less than it does — the failure this store exists to
  prevent. `an_inline_entry_is_refused_until_the_schema_allows_one` pins the
  interim behaviour so it expires rather than settles; when the schema takes
  the three members as optional, that test fails and the refusal goes with
  it.

- **vta**: Audit every refusal, and make the census that missed them measure ([#1238](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1238))

#1236 shipped a census reporting 72 consequential tasks that "audit on
  success only", with a budget and a note that fixing them would be ~60
  handlers in one diff. The number was right and everything else was wrong.

  **The census was measuring one gate, 72 times.** It built each document
  with `TrustTask::new(id, type_uri, payload)`. That envelope carries no
  `issuer`, `recipient`, `issuedAt` or `proof`, and the spine enforces all
  four before dispatch — so all 72 documents were refused `422 expired` at
  the freshness check and **not one handler ever ran**. One unaudited code
  path, exercised once per task, reported as a per-handler finding.

  The `silent_on_success` invariant beside it passed *vacuously* for the
  same reason: nothing succeeded, so nothing could succeed silently.

  ## What the gate was hiding

  The path those 72 documents took records nothing, for any task in any
  family. `dispatch_trust_task_validated` has a dozen early returns —
  expiry, wrong recipient, replay, schema validation, proof failure, the
  policy gate — and the blanket vault audit sat a few lines above that
  function's final `return`, so it saw the outcomes that reached the bottom
  and none that did not. Its own doc-comment claimed "read or write, success
  or denied — exactly one persisted audit row"; that was true only of
  denials the *handler* raised.

  So a document refused at the envelope gate left no trace at all. That is
  the refusal an incident review most wants: not "the handler said no", but
  "something arrived claiming to be this, signed like this, and never got
  that far".

  ## The fix is one frame, not sixty handlers

  `DispatchAudit` is captured in `dispatch_trust_task_inner` and recorded
  around the call to `dispatch_trust_task_validated`. No early return inside
  can bypass it, and a fourteenth added tomorrow inherits it.

  Two dispositions, to avoid doubling the trail:

  - **vault family** — every outcome, as before; behaviour unchanged.
  - **everything else consequential** — refusals only. A non-vault success
    is audited by its handler; recording it here too would duplicate every
    row.

  Non-vault refusals record as `task.refused` with the URI as the resource,
  rather than under the operation's name. The handler vocabulary does not
  follow the URI (`acl/grant/0.1` audits as `acl.create`, `keys/create/0.1`
  as `key.create`), so matching it would need an 84-entry table that goes
  stale invisibly — and it would be filing a lie: these refusals happen
  before dispatch, so no ACL was consulted and no key was touched. Exactly
  one task (`task-consent/decision/0.1`) audits its own refusal and now gets
  a second row; the other ten already-audited refusals are vault-family and
  take the unchanged branch.

  ## The census now measures what it claims

  Conforming envelopes: issued now, addressed to this agent, issued by the
  DID the claims authenticate, signed. Documents reach handlers.

  With that, `silent_on_failure` is **0** — down from 50, which is what the
  number actually was once the gate stopped swallowing the run. The budget
  is replaced by a hard invariant, because a gap closed structurally does
  not need a ratchet. Verified non-vacuous: disabling the refusal branch
  fails the census with exactly those 50.

  `silent_on_success` is 2, and neither is a defect. `auth/revoke-session`
  and `consent/revoke` take documented no-op arms against the census's empty
  store — "a revoke that deleted nothing is not a state change worth a
  line". They go in a new `NO_AUDIT_WHEN_NO_OP` list rather than
  `NO_AUDIT_BY_DESIGN`, because that list claims no trail is *ever* correct
  and these audit fine when they change something. Conflating the two would
  license "fixing" a handler into recording work it did not do.

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



## [0.23.4](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-service-v0.23.3...vta-service-v0.23.4) — 2026-09-01


### Fixed

- **vta**: Resolve approver sets from one row-first source, not three ([#1221](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1221))

A consent decision from an approver added with `pnm approvals approvers
  add` was refused:

      audit: action="consent.decision" outcome="denied:not_a_member"

  Three places ask "who is in this approver set?", and they disagreed:

  | Site | Read |
  |---|---|
  | `policy_gate` — raise the pending | row first, config fallback |
  | `ceremony::may_attempt_ceremony` — transport gate | config only |
  | `task_consent` — accept the decision | config only |

  `pnm approvals approvers add` writes the declarative policy row. The gate
  read that row, found the set, raised the pending and pushed the signed
  request to the approver. The approver signed a valid decision — and the
  two config-only sites looked in a table that never had the set, so the
  transport gate turned it away pre-auth and the handler denied it
  `not_a_member`.

  The effect is that DTTE could not be operated through its own CLI. The
  documented way to manage an approver set produced a set that could raise
  requests but never accept an answer, and the only workaround was to *also*
  carry the set in `config.toml` and restart — the very thing row-first
  exists to avoid, since `[policy.approver_sets]` is a seed applied once.

  All three now resolve through `policy_gate::effective_approver_sets`:
  config, overridden by the row **per set name**. Per-set rather than
  whole-model, so an operator with three sets in config who edits one with
  the CLI does not strand the other two — and, more importantly, cannot
  strand them inconsistently, since a whole-model rule would have let an
  approver pass the named membership check while the transport gate, which
  scans every set, still turned it away.

  The transport gate fails closed: a store error is not a membership answer,
  so it refuses the decision and warns rather than admitting the sender.

  `ceremony.rs` was the site that failed most quietly — it runs before
  authentication, so a decision it rejects never reaches a handler and never
  appears in the audit trail at all.

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

- **vta**: Scope device list, disable and wipe to the caller's contexts ([#1217](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1217))

`device/list`, `device/disable` and `device/wipe` gated on
  `auth.require_manage()` and nothing else. That check is role-only —
  `Role::Admin || Role::Initiator`, with no reference to `allowed_contexts` —
  and all three then reached for `list_acl_entries()`, an unfiltered scan of
  the `acl` keyspace. At no point was the caller's context scope applied.

  So a context-scoped admin read every `DeviceBinding` on the VTA: the
  `displayName`, `platform` and `lastSeenAt` of machines belonging to
  principals in contexts they hold no rights in. For the OpenVTC producer
  `displayName` is `OpenVTC on {hostname} ({profile})`, so that is a hostname
  — frequently a person's name — plus an activity window, disclosed to an
  admin whose grant was deliberately scoped elsewhere.

  The two mutations were worse than the listing. Neither checked anything
  after finding a binding by `deviceId`, so any context admin could disable or
  wipe *any* device on the VTA, a super-admin's included. That is authority
  over another context's principals, not merely visibility into them.

  All three now go through `is_acl_entry_visible`, the existing management
  predicate the ACL mutation paths already use, so device management and ACL
  management answer the same question the same way. The two mutations share a
  new `find_manageable_device` helper for the same reason — they had already
  drifted apart from the listing, and one lookup means they cannot drift
  again.

  `is_acl_entry_visible` and not the wider `is_acl_entry_auditable` used by
  `acl list`: both mutations plainly need management authority, and the
  listing reads the same way on purpose. A binding carries operational
  metadata about a *machine*, which is a different and more revealing
  disclosure than the entry's authority that the auditable predicate exists to
  surface. Read and mutations now agree — you see the devices you may manage.

  An out-of-scope binding conflates to the same `NotFound` an absent id
  returns, rather than a distinct `Forbidden` that would confirm the id exists
  and make the error an oracle for enumerating device ids.

  Behaviour change worth noting for operators: an `Initiator` with an empty
  `allowed_contexts` is authorized *nowhere*, not everywhere, so it now lists
  no devices where it previously listed all of them. That is the documented
  `ActScope` reading — an empty context list means unrestricted only for
  `Role::Admin` — and it is the specific misreading this defect class keeps
  producing (#746, #769, #770). Super-admins are unaffected.

  Tests cover the context admin, subtree ancestry, the super-admin
  no-regression control, the acts-nowhere case, the `ActScope::All` edge (a
  super-admin's own device names no context, so it is not inside any context
  admin's subtree), and both refused mutations asserting no write occurred.
  Six of the seven behavioural tests fail against the pre-fix code; the two
  controls pass either way.

  Found while assessing sankarshanmukhopadhyay/rahp-toolkit#285, which
  reported a different and unfounded cross-context correlation claim about the
  same `displayName` value. This is the real cross-context exposure of that
  field, and it was not what that finding tested.



## [0.23.3](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-service-v0.23.2...vta-service-v0.23.3) — 2026-08-30


## [0.23.2](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-service-v0.23.1...vta-service-v0.23.2) — 2026-08-29


### Fixed

- **vta**: Refuse an ambiguous provisioning context with the code its spec declares ([#1204](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1204))

`provision/integration` declares one error code of its own —
  `provision/integration:contextRequired`, whose `details.candidates` lists the
  contexts the caller must choose between. `ProvisionIntegrationRequest::context`
  documents exactly that contract. No transport was honouring it:

  | transport | what it actually sent |
  |---|---|
  | DIDComm | a problem-report, code right, candidates under `args` |
  | REST | a bare 400, message inline, no code at all |
  | Trust-Task spine | `malformedRequest`, candidates joined into the sentence |

  Three renderings of one refusal, none of them the documented one, on the only
  provisioning error a wallet has a recovery UX for: it shows the candidates as
  a picker so the operator chooses and retries inside the ephemeral grant's TTL.
  Off the spine that recovery has to come from a rendered sentence — which is
  the string-matching a machine-readable code exists to prevent (guide rule
  R3.7).

  The spine is the path all three transports converge on, so it is the one worth
  fixing: a wallet that provisions over the dispatcher gets the documented shape
  whichever channel carried it.

  `RejectReason` could not express it. Every variant maps to a `StandardCode`,
  so a task whose own specification declares a code had no way to put it on the
  wire — the nearest fit, `TaskFailed`, says "attempted and could not complete",
  which is the wrong thing to tell a producer whose request was refused before
  anything was attempted. The framework was never the limitation:
  `ErrorPayload::new` takes any `TrustTaskCode` including
  `Extended { slug, local }`, and `TrustTask::reject_with` takes a payload. The
  seam between the two was missing, and `reject_with_code` is it.

  `bound_details` still runs on this path. `reject_with`'s comment calls itself
  "the one funnel every rejection passes through, so a new site cannot be added
  that skips the check" — a second funnel that skipped it would falsify that
  sentence quietly, which is how the unbounded-`details` bug arrived the first
  time.

  The code string is parsed from vta-sdk's existing constant rather than rebuilt
  from a slug/local pair, so the spine and the DIDComm problem-report cannot
  drift into two spellings of one refusal — the drift SPEC §4.10 rule 4 exists
  to prevent. `context_required` falls back to `taskFailed` if that constant ever
  stops parsing, because panicking a request thread over a malformed constant
  serves nobody; a test asserts the constant parses and round-trips, which is
  what keeps the fallback unreachable rather than merely unlikely.

- **vta**: Let an update turn pre-rotation on for a DID that never had it ([#1203](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1203))

* fix(vta): let an update turn pre-rotation on for a DID that never had it

  Editing a DID and answering "yes" to `pnm did-mgmt dids edit`'s "Override
  pre-rotation count?" prompt on a DID reporting "Pre-rotation: disabled (never
  enabled on this DID)" failed, and failed opaquely:

      ✗ Protocol error: trust task failed [internalError]
      webvh library error: update_did: ValidationError: nextKeyHashes must be
      defined when pre-rotation is active

  A document change mints a fresh update key, so the entry carried both
  `updateKeys` and the DID's first-ever `nextKeyHashes`. didwebvh-rs then demanded
  those new keys hash into a commitment the previous entry had never made —
  unsatisfiable, so no such entry could ever be written. That is a library defect,
  fixed separately in didwebvh-rs 0.6.1, but the entry this service was asking for
  was the wrong shape regardless.

  The entry that *activates* pre-rotation no longer rotates `updateKeys`, and the
  reason is structural rather than a way around the library. From that entry
  forward the next update is authorized by the key committed in `nextKeyHashes`,
  not by anything minted alongside the document (didwebvh 1.0 §Authorized Keys,
  Pre-rotation: "the active list is the updateKeys from the current log entry").
  A key minted here would be published, installed, and never able to sign
  anything, while burning a derivation index to do it.

  It also removes a live ambiguity. §Authorized Keys selects the rule by whether
  pre-rotation is active, and on the activating entry the two readings of "active"
  disagree: keyed on the previous entry (what the verification algorithm's step 7
  parenthetical says, and what didwebvh-rs implements) the proof comes from the
  previous entry's updateKeys; keyed on the entry itself, from its own. An entry
  that restates `updateKeys` resolves differently under the two. An entry that
  inherits them resolves the same either way — so this shape is the one that
  interoperates.

  Inheriting is legal precisely because pre-rotation was not yet in force on the
  *previous* entry; the "must restate updateKeys" rule binds from the next entry
  on, which is exactly when this service starts restating them.

  `set_update_keys` now keys off `derived_auth` being non-empty rather than
  restating the predicate that sized the derivation, so the two cannot disagree
  about whether an entry rotates. `sends_next_key_hashes` is likewise computed once
  and consumed by both the derivation sizing and the builder call.

  Regression test drives the real flow end-to-end on the persisted did.jsonl:
  genesis without pre-rotation, then a document edit that activates it (asserting
  the entry publishes the commitment and omits `updateKeys`), then a further update
  that reveals the committed key and restates `updateKeys`, with full chain
  validation after each. It fails on the old code with the operator's exact error,
  and passes against the *published* didwebvh-rs 0.6.0 — this fix does not wait on
  the library release.

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



## [0.23.1](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-service-v0.23.0...vta-service-v0.23.1) — 2026-08-29


### Added

- **vta**: Show what a DID deletion would destroy, and ask first ([#1199](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1199))

Deleting a DID is irreversible and, since #1198, also *revokes* — credentials
  in other people's wallets stop being good and no undo puts them back. It did
  that with no warning and no confirmation.

  `plan_did_deletion` computes what a deletion would do without doing any of it,
  and the deletion consults the same plan. One function, both callers: a preview
  computed separately agrees with the deletion only for as long as somebody keeps
  the two agreeing, and a preview that under-reports is worse than no preview,
  because it is a promise the operator acted on. The read halves of the credential
  and session scans are now shared with the write halves for the same reason.

  The offline `vta did-mgmt dids delete` renders the plan and prompts, following
  the `contexts delete` precedent beside it.

  Credentials are listed **by id**, not counted. An operator deciding whether to
  proceed is deciding about *those* credentials, and "3 will be revoked" cannot be
  checked against what they expected — which is the only question a confirmation
  prompt actually asks.

  `--force` skips the prompt. It does not skip the blockers: a DID something
  still depends on is refused inside the operation regardless, and that refusal
  still has no override. Those are different things and the flag name is the
  obvious place to confuse them, so both the help text and the code say which one
  it is.

  A plan that touches nothing beyond the DID's own records does not prompt. The
  ceremony is for consequences, not for deletions.

  The **online** path still has no preview, and this does not invent one. A
  server-side preview needs a published `webvh/dids/preview-delete` URI, and a
  new Trust Task family cannot be dispatched until its schema lands in
  trustoverip/dtgwg-trust-tasks-tf and trust-tasks-rs bumps.
  `vta/contexts/preview-delete/1.0` is the precedent to copy; the spec PR is the
  prerequisite, not something to route around.

- **vta**: Cascade, refuse and revoke when a DID is deleted ([#1198](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1198))

`dids delete` removed the daemon-side DID, the local webvh record and log, and
  the DID's keys. Nothing else. ACL entries, issued credentials, sessions and
  per-DID state were left behind.

  That is the VTC's ACL-revoke orphan (#1194, #1196) one level up: a surface
  owning part of a multi-part identity and knowing nothing about the rest. There
  it produced a live member row with no authorization and credentials that still
  verified for anyone holding them, found in production. The VTA had the same
  shape and had not been asked the question yet.

  Deleting a DID is four relationships, not one, and treating them alike gets one
  wrong in a way nobody notices until it matters:

  - what the DID **owns** goes with it;
  - what **names it as a subject of authorization** must go with it, or it
    becomes authority for an identity that can no longer be resolved or rotated;
  - what **depends on it to function** must stop the deletion, because cascading
    would silently break it;
  - what the VTA **issued** cannot be deleted at all, because third parties hold
    copies — so the only honest action is revocation.

  The fourth is the one most likely to be got wrong, because it looks most like a
  cascade. Deleting our record of an issued credential does not invalidate the
  copies; it destroys the only means of revoking them.

  This implements the three decisions taken on that model. A deletion revokes the
  credentials it cannot destroy. A dependency refuses the deletion and names the
  command that unpicks it, rather than cascading through something still in use.
  There is no `--force` — the same call as `would_violate_last_service`, for the
  same reason.

  Revocation runs first, before any deletion, remote or local. If a later step
  fails the credentials are already dead and the DID still exists, which is
  recoverable by re-running; the other order leaves live credentials for a DID
  nobody can revoke through any more. When a partial failure is possible, the
  state that survives should be the over-restrictive one. The preflight is
  read-only, so a refusal leaves the VTA exactly as it found it.



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



## [0.23.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-service-v0.22.0...vta-service-v0.23.0) — 2026-08-29


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



## [0.22.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-service-v0.21.0...vta-service-v0.22.0) — 2026-08-28


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

- **compliance**: Enforce SPEC §7.2's flag-driven checks, and sign what we send ([#1146](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1146))

The VTA enforced none of the four checks a *Trust Task specification* declares
  for itself. It now enforces all of them, and the SDK produces documents that
  satisfy them.

    * item 5b — `recipient` REQUIRED: all 109 dispatched specs
    * item 7a — `proof` REQUIRED: 72 of them
    * item 8  — audience binding
    * §7.3 17 — `issuedAt` REQUIRED: 70 of them

  `spec_policy_for` (trust-tasks-rs 0.17.1, trustoverip/dtgwg-trust-tasks-tf#321,
  authored for this) keys those constants by Type URI. That is what makes the
  check reachable at all: `enforce_spec_policy` reads them off `P`, and the
  dispatch spine holds a `TrustTask<Value>`. The alternative was a 109-entry
  URI→type table in this repo, duplicating what the codegen already emits.

  The spine's own comment claimed "each slice's typed handler runs it after
  `parse_payload`". No handler did — that comment was the only occurrence of
  `enforce_audience_binding` in the repository.

  **This is an auth-model change, not a wire-format one.** A bearer token
  authenticates the connection; §7.2 item 7 admits no transport substitute, so
  every producer must now sign every document. `vta-sdk` gains `ClientIdentity`
  (client DID, its key, the VTA's DID) and signs in `dispatch_trust_task`.
  `SessionStore::connect` supplies it from the stored session — re-read *after*
  `ensure_authenticated`, because a session that needed rotation now holds a
  different DID and key, and signing with the pre-rotation pair produces a
  document whose issuer no longer matches the identity its token authenticates.

  `issuer` and `recipient` are set in `build_task_document` rather than at each
  call site, for the reason `issuedAt` already was: a member the framework
  requires of every document belongs to the one function that builds every
  document. Signing is unconditional rather than keyed on the flag — a proof on a
  task that merely RECOMMENDs one is legal and strictly more attributable — but
  it must never happen without an in-band recipient, and both come from the same
  `ClientIdentity` so they cannot come apart.

  Test identities are now derived from one-byte seeds. `did:key:zTestAdmin` was
  not a `did:key`: nothing resolves it and no document issued by it can carry a
  verifiable proof. That was fine while proofless documents were accepted. The
  seed gives a DID and the key behind it from one place, which is what item 6
  needs — it rejects a document whose in-band issuer disagrees with the
  transport-authenticated identity, so a test minting a token for one DID and
  signing with another is refused for that rather than for what it meant to check.

  One real bug surfaced in the fixtures: `delegated_consent_e2e`'s `sign_as` did
  not clear an existing proof before signing. `prepare_sign_input` hashes the
  document as given, so signing over one that already carries a proof yields a
  signature covering bytes no verifier reconstructs — it fails as `proofInvalid`,
  which reads like a key problem and is not one.

  Coverage holds at 88/109 with zero response-conformance violations.

- **tasks**: Catch up to the registry on vault 0.3, device/wipe 0.2 and credentials/issue 0.2 ([#1145](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1145))

Five of the six families vta-sdk lagged the registry on. The sixth,
  `provision/integration/0.3`, is not here: its response schema could never
  validate — `required` named a `digest` the 0.2→0.3 rename had already removed
  from `properties`, against `additionalProperties: false`. Fixed upstream in
  trustoverip/dtgwg-trust-tasks-tf#324; VTI adopts it once that publishes.

  **vault/{list,get,upsert} 0.3.** `AttachmentRef.sha256` — hex, with SHA-256
  pinned by an `^[0-9a-f]{64}$` pattern — becomes `digestMultibase`, a multibase
  multihash that names its own algorithm. Worth stating plainly: nothing in this
  service has ever constructed an `AttachmentRef`. Every site is `vec![]` and
  `vault/upsert` only carries forward whatever an entry already had, so the
  member has never reached the wire and this is a type-level rename today. The
  wire contract is what changes, and it changes so that moving off SHA-256 later
  is a value change rather than another schema revision.

  **device/wipe 0.2.** `cache-and-keys` → `cacheAndKeys`, the same recasing the
  rest of the device slice took. Its constant carried "No 0.2 spec exists
  upstream; this stays on 0.1" while `specs/device/wipe/0.2` had been published
  for some time. The replacement comment says so: a comment asserting an absence
  is a claim about the registry that nothing re-checks, and it is why nobody
  looked again.

  **vta/credentials/issue 0.2.** The request payload is unchanged. The response
  stops restating the shared `IssuedCredential` inline and composes it through
  `allOf` + `unevaluatedProperties` — same members, same required set, identical
  wire form. So the two versions share a dispatch arm rather than a transform.

  The edge-transform table goes from one wire URI per spec to a list.
  `vault/*` 0.3 differs from 0.2 only in `AttachmentRef`, which is not an enum
  value and not at any path the transform touches — so it down-converts to the
  same canonical handler by the same casing rules. Giving it its own row would
  have duplicated every path and left the two to be kept in step by hand.

  `upconvert_response` now answers as the version the caller *sent*. With several
  wire URIs per spec, retyping a response to a fixed one would be refused by a
  client validating against the version it asked for.

  Two guards needed widening, and both were right to fail first:

  * `superseded_tasks_are_dispatched` did not count an edge-transformed URI as
    served. Its premise is that a row whose counter can never move reads the same
    as "safe to retire" — but the counter *does* move for these, because
    `dispatch_trust_task_core` reads the superseded row from the URI as it
    arrived, before the down-convert. The successor half of the pair already
    accepted them.
  * the wire/deprecation parity test checked only the 0.1 hop. A spec accepting
    0.1, 0.2 and 0.3 needs a row per superseded version, or the middle one is
    retired on no evidence at all.

  `ALL_URIS` and `retry_safety` carry the four new URIs; the census caught their
  absence, which is what it is for.

- **vta**: Close the CI cache class, map the 0.5.0 lifecycle, cover more tasks ([#1134](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1134))

Three things belonging to the same release.

- **vta**: Mint the consent ceremony's correlator instead of deriving it ([#1133](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1133))

* feat(vta): mint the consent ceremony's correlator instead of deriving it

  Framework 0.5.0, *Identifier correlation and linkability*: `id`, `threadId` and
  `ceremony.enactment` MUST be freshly minted and unguessable, and MUST NOT be
  derived from subject data.

  The `task-consent/granted` notice threaded on `wire_digest` — a function of the
  task payload, and the same string the document carries as `payloadDigest`.

  The challenge is 256 bits of randomness, so the digest is not guessable from
  the payload; this is not the "UUIDv5 over a subject identifier" case. The
  mediator is the exposure. `threadId` is routing metadata, and the mediator also
  forwards documents carrying `payloadDigest`; with the same value in both it can
  tie the routing it performs to the digest it carries and link the refusal, the
  approval pushes and the notice into one ceremony with named counterparties.

  `PendingTaskConsent` gains a minted `correlator`, created alongside the
  challenge. The notice threads on it and the body still carries `payloadDigest`
  unchanged, so a requester matching on the digest is unaffected. The requester
  is told the correlator in the `auth:consent_required` refusal beside the digest
  it already receives.

  Smaller than it first looked: the request push to approvers already threaded on
  the request document's own id, so only the requester-facing notice was derived.
  The notice is produced but never consumed in this workspace and is explicitly
  non-load-bearing — the grant check at re-submit is the real gate.

- **vta**: Bound the error `details` member ([#1131](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1131))

Framework 0.5.0, *Bounding `details`*. `details` was the one error-payload
  member with no size bound, travelling in the direction no producer-side bound
  reaches: a producer caps what it sends, nothing caps what comes back.

  This service had a live instance. A policy denial puts the Rego module's
  `explanation` on the wire, and that string is authored by whoever wrote the
  policy with no length anybody checked.

  The bound is 4096 bytes of JCS or 16 immediate members — 0.5.0's default where
  a specification declares none — applied in `reject_with`, the single funnel
  every rejection passes through, rather than at the thirty `details: Some(...)`
  construction sites. A new site cannot be added that skips it.

  An oversized `details` is ignored and never grounds to discard the `code`: the
  code is what the receiving party needs, and dropping the rejection because its
  annex was too long would turn a verbose policy into an unexplained failure. An
  uncanonicalisable `details` is dropped too — it cannot be measured, so it does
  not go out.

- **vta**: Stop error messages from being a probing oracle ([#1130](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1130))

Framework 0.5.0 makes the message-sanitization rule normative for every code,
  not just `identityMismatch`: a `message` MUST NOT reveal consumer-internal
  state, the contested value of a mismatched party, or resolver, verifier, or
  key-status internals. Every rejection is emitted on the same path, to the same
  possibly-unauthenticated party, generally before any authorization decision has
  been reached.

  This service violated two of the three.

  `app_error_to_reject` passed `AppError::Internal`'s cause into the `message`
  verbatim, so a caller learned "ATM not configured — server cannot pack DIDComm
  envelopes" or "log entry has no update_keys" — the deployment's shape, its
  configuration, and which invariant just broke. The catch-all arm was the
  quieter half: it rendered whatever `Display` an error happened to have, so a
  variant added later would publish itself with nobody choosing to. Both now land
  on one fixed string and log the cause for the operator.

  `DiProofError`'s `Display` rendered the underlying verifier error, and that
  reaches the wire through `PermissionDenied`. A caller could read which
  cryptosuite ran and how verification failed. The detail moves to a `cause()`
  that is deliberately not reachable through `Display`, since the defect was that
  the wire rendering and the operator rendering were one function.

  `notFound`, `malformedRequest` and `permissionDenied` pass through unchanged:
  they describe the caller's own request back to it, which is not
  consumer-internal state.

  `an_internal_error_does_not_say_internal_error_twice` asserted the cause was on
  the wire. Its subject was a doubled prefix, which the fixed string also
  settles; it is now `an_internal_error_reveals_no_internal_state`, joined by
  `the_catch_all_arm_is_opaque_too`.

- **vta**: Bound the replay record by the acceptance window, not by capacity ([#1127](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1127))

The follow-up #1126 named. VTI now honours SPEC §7.2's same-bound rule: the
  acceptance window and the duplicate-execution record's retention are one
  instant, derived from one policy.

  #1126 shipped the ReplayGuard without a window, leaving the record bounded by
  InMemoryReplayGuard's capacity. That is not "no expiry so entries live
  forever" — it is LRU, which makes the window load-dependent: on a quiet service
  the protection is effectively unbounded, but under burst the eviction horizon
  can fall below any sensible acceptance window and a replay executes a second
  time. The defence was weakest exactly when the service was busiest.

  Ten minutes rather than the library's five: this service routes over a mediator
  that can hold a message while a recipient reconnects. It is the same 600s the
  retired replay::check_and_record used as its dedup TTL, now bounding acceptance
  as well as retention.

  Most of the diff is the fixture migration the window forced, and none of it was
  the policy being wrong. 65 envelopes carried no issuedAt at all — with a window
  set, a document with neither issuedAt nor expiresAt cannot be placed in time
  and is refused, which is what §7.2 requires. 12 more carried fixed literals
  already days stale.

  One subtlety: the first pass used to_rfc3339(), which renders the offset as
  +00:00 where TrustTask's typed DateTime<Utc> round-trip renders Z. That broke a
  signed fixture's proof — a document signed in one spelling and verified after
  the other is a different document, which is the §8.4 distinction #1126 added
  idConflict for, arriving as a signature failure instead. Every stamp now uses
  to_rfc3339_opts(SecondsFormat::Secs, true).

- **vta**: Adopt ReplayGuard and FreshnessPolicy, deleting the hand-rolled pair ([#1126](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1126))

The last of the three stopgaps #1121 unblocked. Deletes trust_tasks/replay.rs
  and the hand-rolled freshness bounds from #1117.

  They land together because ConsumeChecks bundles them in one argument: SPEC
  §7.2 makes the acceptance window and the replay record's retention the same
  bound, and splitting them is how a deployment ends up with a ten-minute record
  against an unbounded window believing it has a replay defence. This service had
  exactly that.

  The retired module keyed on (actor, id) and kept no digest, which cost two
  things. It never produced idConflict — item 11 requires a different document
  under an accepted id to be rejected, and with no digest that case was silently
  absorbed as a retry, the one outcome §7.2 and §8.4 both rule out. And the key
  was wrong: §7.2 fixes it as the document id alone, so actor-scoping let two
  callers each spend the same id. A duplicate is also no longer answered with
  taskFailed, which §7.2 forbids outright.

  A failed outcome releases the claim, mirroring the idempotency layer beside it;
  a successful one records its response so a retry is answered with the result.
  The Err arm fails closed with a retryable unavailable, and the non_exhaustive
  ReplayVerdict gets an arm that refuses rather than executes.

  No acceptance window yet, and that was measured rather than assumed:
  with_max_age(10 minutes) scoped to consequential tasks failed 41 assertions
  across 10 suites with expired, because the suite is full of documents stamped
  hours or days in the past. Fixing those alters what the service accepts and
  belongs in a change whose subject is the window.



### Fixed

- **consent**: Sign the approve-request prompt sent to an approver's device ([#1180](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1180))

`consent/approve-request/0.1` was constructed as a bare `id` / `type` /
  `issuedAt` / `payload` document and buffered to an approver's mediator for
  delivery to their phone, where a human is asked to approve something. It
  carried no proof, so nothing the device could check authenticated it.

  This is the odd one out rather than a deliberate exception. The sibling
  task-consent request in `consent_request.rs` already signs with this key and
  cryptosuite, and the step-up prompt's mobile parser refuses to render
  without a verified proof from an enrolled issuer
  (`vta-mobile-core::task::parse_step_up_request` — "no valid proof from an
  enrolled executor, no prompt"). Both end up in front of a person.

  `issuer` and `recipient` come with the proof, not as decoration: SPEC §7.2
  item 5b makes `recipient` REQUIRED and item 6 requires the in-band issuer to
  match the transport identity. A proof over a document naming neither party
  is replayable at a different approver, which is most of what the signature
  was supposed to buy.

  Fails closed. The wake path is best-effort and already warns on a failed
  buffer, leaving the approver to mediator pickup; an unsignable prompt takes
  the same route. "No prompt" is recoverable in a way "unverifiable prompt"
  is not.

  ## Sequencing

  This changes nothing about security on its own, because nothing verifies it
  yet, and that is the reason to land it now rather than later: the fleet has
  to be signing before devices can require a signature. Device-side
  enforcement in `vta-mobile-core` follows, and must not ship first or it
  breaks every VTA that has not deployed this.

  Publishing the spec with `proof` REQUIRED is the third step, so the
  requirement is normative rather than local convention. Tracked in #1177.

  The test runs the real verifier over the document as sent rather than
  asserting a `proof` member exists — a signature copied from another document
  would satisfy the weaker check — and pins `issuer` and `recipient`.
  Confirmed it has teeth by swapping the recipient DID and watching it fail.

- **services**: Let enable reconcile a config the document does not match ([#1150](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1150))

Coverage 93 to 97 of 109 — the `services/{enable,update,disable,rollback}`
  write paths — and a state they could not get out of.

  `enable` refused when the service was on in the live config **or** advertised
  in the published document. `update` requires it on in **both**. So config-on
  with a silent document was unmanageable: neither operation would touch it, and
  the operator's only route out was to edit the config by hand.

  That state is reachable, and not exotically. Re-point `vta_did` at a freshly
  minted DID and you have it — the new document advertises nothing while the
  config still says REST is on. Restoring a config without its log does the same.

  "Already enabled" now means enabled in both places, which is the only reading
  under which there is nothing to do. Where the two disagree there is work, and
  this is the operation that does it. Both disagreement directions become
  recoverable; the no-op case is still refused.

  The coverage is what found it. These four were the last block with a shared
  cause: they publish a new WebVH LogEntry for the VTA's *own* DID, so
  `load_vta_doc_state` needs a record and a log for it — and the ordinary fixture's
  `vta_did` is a self-resolving `did:key`, which has neither. No amount of
  test-writing reaches them from there. Minting one against the stub host and
  pointing `vta_did` at it is the unlock, which is why this is one test rather
  than four.

  The client is rebuilt after the flip. A document's `recipient` must name the
  consumer it is sent to, and the VTA's identity just changed — reusing the old
  client fails on `wrongRecipient` before reaching anything under test.

  The two unit tests that encoded the old rule now assert the new one, and assert
  it precisely: the fixture seeds no webvh record, so reaching
  `VtaDidRecordMissing` is what proves the config check no longer short-circuits
  ahead of the document. Asserting success would need a fixture modelling a fully
  published VTA, which is what the stub-host round-trip is for.

- **trust-tasks**: Verify the proofs we require, and cover the canonical device lifecycle ([#1149](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1149))

**SPEC §7.2 item 7 has two clauses. Only the second was implemented.**

    "If the document carries a `proof` member, verify it per §4.7 against the
     in-band `issuer` and reject the document with `proofInvalid` on verification
     failure. Independently, if the specification declares `proof` REQUIRED and
     no `proof` is present, reject with `proofRequired`."

  #1146 added the second. The first was never there, and that is the worse way
  round to have it: a caller attaches a proof *because* the task demands one, and
  until now any bytes in the member satisfied the demand. A document signed by a
  key its issuer does not control reached the handler — proven by the test added
  here, which sent one signed by an unrelated seed and watched it fail on
  `session not found` rather than on the proof.

  The verifier already existed. `vti_common::auth::di_proof::verify_trust_task_proof`
  returns the cryptographically-proven signer, and `step_up` and `task_consent`
  have called it for their own gates all along. The spine did not, so every other
  task took the issuer's word for who signed.

  Two checks, because a valid proof is not the same as a valid proof *by the
  issuer*: the proof must verify, and the DID it verifies as must be the
  document's `issuer`. Without the second, a signature would establish only that
  somebody signed something.

  `step_up` and `task_consent` keep their own calls. They bind the signer to a
  *specific* party — the approver — which is a stronger claim than "the issuer
  signed this" and not one this can make for them.

  **Coverage 88 → 93 of 109.** The device family's canonical 0.1 URIs, plus
  `disable` and `wipe`, which have no 0.2 form.

  Not a duplicate of the existing 0.2 walk. A 0.2 request is down-converted to
  the 0.1 handler and its response up-converted back, so driving 0.2 never
  produces a `…/0.1#response` and never exercises the branch that answers a
  caller who asked canonically. Two paths through the spine; one was tested.

  One fixture needed a real second identity. `idempotency_trust_task`'s
  "other caller" was a hand-written DID with no key: the document claimed that
  issuer and was signed by the *first* caller, and the VTA took its word for it.
  It cannot now, which is the point.

- **deps**: Declare the spec families this VTA validates against ([#1148](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1148))

The workspace asks `trust-tasks-rs` for `default-features = false, features =
  ["validate"]` and receives every spec family regardless, because
  `affinidi-messaging-sdk` -> `affinidi-tdk` enables the default feature and cargo
  unions them. The entire schema index — the thing `validate_payload` checks
  payloads against and `spec_policy_for` reads SPEC §7.2's constants from —
  arrives by luck rather than by request.

  Both of those fail **open**. `validate_payload` dispatches unvalidated when it
  knows no schema (unless `policy.require_payload_schema` is set), and
  `spec_policy_for` returning `None` skips the recipient/proof/issuedAt checks
  entirely. So the day any crate in that chain set `default-features = false`,
  this VTA would have stopped validating payloads and stopped enforcing §7.2,
  with a single `debug!` line between that and nobody noticing.

  `all-specs` is now declared. No behaviour change today — the features were
  already resolving on — which is the point: the resolved set is unchanged and
  the reason it resolves is no longer somebody else's business.

  The test asserts the index is populated, for three URIs across three families.
  Worth being exact about what it proves: it fails when the index is empty, which
  is the outcome that matters, and it *cannot* fail when the declaration is
  removed while the transitive path still supplies the families — cargo unions
  features, so from inside the build the two are indistinguishable. That is the
  right coverage anyway. An index populated by either route is a working VTA;
  this fires on the day neither route supplies it.

- **sdk**: Give every authenticated client its identity, and adopt provision/integration 0.3 ([#1147](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1147))

#1146 made every producer sign, and left seven production paths building
  clients that cannot. Each authenticates, takes the token, and drops the DID and
  key on the floor — so every task they dispatch is refused for a missing
  `recipient` and `proof`. `SessionStore::connect` was fixed; nothing else was,
  because no test drives those paths against an enforcing VTA.

- **auth**: Stop revoke-session telling a stranger the session exists ([#1141](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1141))

Coverage 87 to 88 of 109, and a disclosure the spec forbids in as many words.

  `auth/revoke-session/0.1` had three answers where it should have one. A session
  that is not there rejected with `TaskFailed "session not found: {id}"`; a
  session belonging to someone else rejected with `PermissionDenied`; only the
  caller's own succeeded. So anyone holding a bearer token could enumerate session
  ids and read existence straight off which refusal came back.

  The `notOwner` error code says, in its own definition: "The auth service MUST
  NOT reveal whether the session exists at all when the producer is not its
  owner."

  Meanwhile the response schema says "Zero is a valid outcome (e.g. the named
  sessionId was already revoked)", the prose adds that producers "SHOULD treat
  zero as 'the post-state is what you asked for', not as an error", and
  `vta-sdk`'s own `retry_safety` table has this task down as `RetrySafe` — which
  it was not, because retrying a completed revoke rejected.

  Both rules hold together only if "not yours" and "not there" answer
  identically, so both now return `revokedCount: 0`. The count is literally true
  either way: zero sessions were invalidated by this call. This handler therefore
  never emits `notOwner` — emitting it only when the session exists is precisely
  the disclosure the code's own definition forbids, and an error code is a
  registry entry, not an obligation.

  Non-disclosure is not a licence to act: a session the caller cannot touch is
  left alone, and the test asserts it is still there afterwards. The refusal is
  recorded in the audit trail (`outcome = "no-op"`) and a `warn!` line, neither of
  which is the caller's to read. The authorisation rule itself is unchanged —
  owner or admin — and an admin still reaches another subject's session.

- **consent**: Stop dropping the approver's label, and make revoke idempotent ([#1139](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1139))

Coverage 81 to 87 of 109 — the whole `consent/*` family — and three
  divergences from the published schemas that covering it turned up.

  **The approval prompt lost its label.** `consent/request` declares
  `displayHint`: the operator-facing name for the conversation, sent precisely
  because `conversationRef` is an opaque handle by design. The SDK sent it. The
  VTA's `RequestPayload` had no field for it, so serde dropped it, and the wake
  prompt built for the approver carried `{subject, scope, challenge}`. An
  approver was being asked to allow or deny `sig-1a2b3c4d`. Nothing failed —
  that is why it lasted.

  **`firstMessageDigest` existed only in the schema.** Declared on the same
  payload, absent from the SDK body and from the VTA's, so no part of the stack
  could send, store, or name it. It binds the prompt the approver answered to
  concrete content. The VTA never sees the message, so carrying it *is* the
  implementation: the bridge checks the digest, the VTA records what was shown.

  **`consent/revoke` could never emit a status its own schema promises.** The
  published response declares `"revoked" | "notFound"` — "`notFound` = no grant
  existed for the subject" — and the VTA rejected instead, so a conforming
  producer written to receive that value never could. It is also the answer the
  caller wants: revoke's post-condition is "no grant for this subject", and with
  none stored that already holds. An operator revoking twice, or racing another
  operator to the same grant, got an error for the outcome they asked for. The
  `consent/revoke:notFound` error code stays declared upstream for a consumer
  that cannot answer at all; it is not this case.

  `consent_request` now takes its body. The schema declares three optional
  members and two are hints, so the positional form was four `Option<&str>` in a
  row with `displayHint` and `contextHint` adjacent and interchangeable to the
  compiler — and it broke every time the schema grew a member, as it just did.

  Both conformance witnesses for the request now set every optional member. They
  left the hints `None`, which serializes them away, so the fixtures proved the
  required trio and nothing about the optional members' encoding —
  `firstMessageDigest` is a `DigestMultibase`, and an omitted member cannot fail
  its pattern.

  The coverage test drives the six as the ceremony they are rather than six
  shapes in isolation: `approver-set` is not setup for it, it is the step that
  makes `request` resolve an approver at all. The caller is minted with exactly
  one context, because the no-`contextHint` fallback goes through
  `default_context()`, which answers `Some` only then — an admin minted with
  `vec![]` has unrestricted access and no default, and would leave that path
  dead.

- **vta**: Say which fact refused a retire-orphan, and cover the slot paths ([#1138](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1138))

Coverage 79 to 81 of 109, and a misleading refusal message found by trying to
  make the task succeed.

  `servers/retire-orphan` routes two very different facts to the same
  `NotOrphaned` variant, and the message asserted one of them for both: "slot X
  has a record in this VTA, so it is not an orphan … use webvh/dids/delete for
  one it still controls."

  The variant already carries `did: Option<String>`, which distinguishes them.
  `Some` means the VTA still controls the slot, and the message was right.
  `None` means the slot is not in the host's listing at all — so the message told
  an operator the VTA held a record it had never heard of, and pointed them at
  `dids/delete` for a DID that does not exist. Both now say what happened and
  name different next actions. The `Option` was there the whole time; only the
  message ignored it.

  The stub host now answers `GET /api/dids` with one slot the VTA has no record
  of, rather than an empty list. That makes both reconcile arms non-empty in one
  call — host_only is the stub's slot, agent_only is the minted DID — where an
  empty list proved one arm and a list echoing the VTA's own records would prove
  neither. It is also what makes retire-orphan reachable: a slot is retireable
  precisely when it is host-only.

  Covers `vta/webvh/servers/{retire-orphan,remove}`. `remove` runs last, after
  `dids/delete`, because removing the server registration invalidates every path
  above it — the order an operator actually uses.

- **vta**: Refuse a swap-key without linkProof by name, not as malformed ([#1137](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1137))

Coverage 77 to 79 of 109, and a fifth request-side divergence.

- **vta**: Carry ecosystem-local capabilities under ext, not in the closed enum ([#1136](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1136))

Coverage 76 to 77 of 109, and a real conformance defect found by covering the
  device family.

  `device/register/0.2` put `credentialWrite` in the response's `capabilities`
  array. The published `Capability` enum does not define it, so the response
  failed its own schema. This was already known and half-fixed: a filter dropped
  `sign-trust-task` with a comment saying it is "absent from the wire schema's
  closed `Capability` enum". `CredentialWrite` was added later, the filter was not
  extended, and it went straight out.

  Fixed by carrying both under `ext["org.openvtc"].capabilities` rather than
  dropping them. Dropping is what the old filter did, and it is lossy in the
  direction that matters: omitting a capability from a listing is a safety claim,
  and it was not a true one — the device held `sign-trust-task` and the response
  said it did not. SPEC §4.5.1 provides the extension slot and `DeviceBinding`
  declares one, so no upstream change is needed; widening the framework's closed
  vocabulary with two ecosystem-specific concepts would be the wrong fix anyway.

  The filter is now positive: `PUBLISHED_CAPABILITIES` lists what the published
  enum defines and everything else is local, so a capability added tomorrow lands
  in `ext` by default rather than leaking one variant at a time.

  The local values are camel-cased at the source, because `wire_v0_2` re-cases
  kebab to camel only at declared enum field paths and an `ext` member is
  invisible to it — otherwise the response would answer `deviceAdmin` beside
  `sign-trust-task`, in two dialects at once.

  Two blockers recorded in earlier PRs turned out to be one line each.
  `passkey-vms/enroll-challenge` needs `public_url`, not a WebAuthn relying
  party — the RP is derived from the public origin. `device/*` needs one ACL
  row, not a provisioned integration — the entry is the enrolment the device is
  completing. Both notes were mine; a refusal that names a procedure reads as
  needing the whole procedure when it needs that procedure's residue.

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

- **vta**: Take keyId from the wire instead of minting one ([#1123](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1123))

First of the three stopgaps #1121 unblocked. `keys/create/0.1` publishes
  `keyId` as of trust-tasks-rs 0.12.1 (dtgwg-trust-tasks-tf#275), so the caller
  names the key and the binding no longer has to invent one.

  #1118 minted `internal-<uuid>` at the binding for an internal key. That was a
  deliberate deviation from a SHOULD I wrote in #275 — a maintainer offering
  internal keys and receiving no `keyId` SHOULD reject — taken because the
  alternative was a security feature nobody could use: an internal key has no
  derivation path to be named after, the operation layer refuses one without an
  id, and the wire had no member to carry it. The comment at that site said to
  delete it when the bump landed.

- **vta**: --internal creates an internal key ([#1118](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1118))

`pnm keys create --internal` printed a non-recoverable-key warning, required
  the operator to type "i understand this key cannot be recovered", and then
  created an ordinary seed-derived key — recoverable from the mnemonic, included
  in backups, exportable. The operator was told the opposite of what happened.

  `CreateKeyRequest` carries `internal`, `key_id` and `derivation_path`; the CLI
  set them and `VtaClient::create_key` built its wire body with `internal: None`
  hardcoded, `key_id` never read, and `derivation_path` as `unwrap_or_default()`
  — `""` for absent, which worked only because the operation layer reads `""` as
  absent. The operation layer was always right: `derivation_path` is an `Option`
  there that auto-derives, and `internal` short-circuits to a CSPRNG key.

  It could not have worked even with the flag forwarded. The spine rejected the
  document, because `keys/create/0.1` was `additionalProperties: false` with no
  `internal` member (fixed upstream in dtgwg-trust-tasks-tf#269, which also added
  `internal` to `KeyOrigin` — the value that makes the outcome checkable); and an
  internal key needs an explicit `key_id`, which neither the wire type nor the
  specification had (dtgwg-trust-tasks-tf#275).

  Forwards `internal` and `derivation_path`, makes `CreateKeyBody`'s
  `derivation_path` optional to match the specification and the operation layer,
  and mints a `key_id` for an internal key at the trust-task binding, which has
  no `keyId` member to carry one yet.

  That minting is a deliberate, temporary deviation from a SHOULD in the
  specification, taken because `keyId` needs trust-tasks-rs 0.12.1 and this
  workspace cannot move to 0.12: `affinidi-messaging-sdk` 0.19.12 pins
  `trust-tasks-rs ^0.11` and `vta_sdk::acl_setup` hands it a generated
  `MediatorAcl`, so two nodes in one graph fail to compile. The id is returned on
  the record and `keys/rename/0.1` can change it; the site says to delete the
  branch when the bump lands.

  `an_internal_key_is_actually_internal` asserts `origin == "internal"` — the
  check the CLI already made and that always silently failed.



### Chore

- **deps**: Aes-gcm 0.11, and stop the nonce conversions panicking ([#1173](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1173))
- **sdk**: Release vta-sdk 0.30.0 for the added CreateKeyBody field ([#1156](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1156))

`CreateKeyBody` gained a `key_id` field while the crate stayed at 0.29.0.
  The struct is exhaustively constructible through the public API, so an
  existing literal no longer compiles — a breaking change under 0.x rules,
  which the semver report has been flagging as its one real finding
  (195 pass, 1 fail) since the field landed.

  Bumps the crate and the nineteen intra-workspace requirements that pin it,
  so `cargo check --workspace` still resolves the path copy and a consumer
  resolving from the registry gets a version that admits the break.

- **deps**: Move VTI to trust-tasks-rs 0.17 ([#1144](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1144))

Every `trust-tasks-*` pin to 0.17, plus the TDK crates that had to publish
  first: `affinidi-tdk` 0.10, `affinidi-messaging-sdk` 0.21,
  `affinidi-messaging-test-mediator` 0.4 (affinidi/affinidi-tdk-rs#744). Two
  `trust-tasks-rs` versions in one graph fail to compile, so the messaging stack
  had to move before this could.

  Breaking for `vta-sdk` consumers, which is why the `!`. 0.17 marks the
  generated payload, response, component structs **and enums**
  `#[non_exhaustive]`, and those types sit in this crate's public API — a
  consumer that builds one with a struct literal, with or without
  `..Default::default()`, must move to the generated builder and to 0.17 in the
  same change.

  Struct literals become builders; matches gain a wildcard. That is what lets the
  registry add an optional member or an enum variant without breaking every
  consumer that spelled out the old list, and the cost is that "is every required
  member set?" moves from compile time to the builder's conversion. Every call
  site here sets its required members explicitly.

  The wildcard arms are decisions, and they went different ways:

  * `step_up`'s `evidence` match **refuses**. It chooses which cryptographic gate
    to verify, so falling through to the did-signed arm would check a gate the
    approver never presented and report the step-up satisfied on evidence this
    VTA did not understand.
  * `services/{enable,update,disable,rollback,get}` **refuse** an unknown service
    kind. Every arm mutates the DID document; picking one would write the wrong
    service. `get` additionally exists to tell "never configured" from
    "configured and disabled", which answering about another transport destroys.
  * `device/register`'s consumer kind, form factor and service kind **refuse**,
    and `wire_kind_to_internal` became fallible to say so. It writes an ACL entry
    and the kind is what policy keys off.
  * `push/wake`'s reply status **logs and continues** — the only one that does.
    Wake is best-effort with a mediator-queue fallback, and an unknown status is
    worth an operator's attention but not a failure. Named separately from `None`
    because the two say different things: "no status we could read" against "a
    status we read but do not know".

  `reason`, `deniedReason` and their siblings became bounded newtypes rather than
  `String`. Parsing them at the producer means an over-long value fails on the
  device that would otherwise sign a document the consumer must reject.

  **The response gate caught a live violation.** `passkey-vms/enroll-challenge`
  put the raw DID into WebAuthn's `userName`/`userDisplayName`, which 0.17 bounds
  at 64 characters — a `did:webvh` is ~85, so the response was unconformant.
  Worth stating that the schema is self-contradictory here: `userName`'s own
  description says "e.g. the DID" while its constraint makes any `did:webvh`
  unrepresentable. The constraint is the defensible half — WebAuthn L2 §5.4.3
  lets an authenticator truncate at 64 bytes, so the raw DID was already
  producing a picker entry cut mid-SCID, unreadable and identical between two
  DIDs on the same host. `userHandle` carries the DID-derived binding and is
  unbounded, so nothing is lost: `userName` now takes the operator's label, or
  the DID with its `did:<method>:<scid>:` prefix dropped, clamped on a char
  boundary.

  Coverage holds at 88/109 with zero response-conformance violations.

- **deps**: Trust-tasks-rs 0.12 and the TDK crates that carry it ([#1121](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1121))

Verified locally against a path-patched affinidi-tdk-rs before those crates
  published (affinidi/affinidi-tdk-rs#743); VTI's graph collapses to a single
  trust-tasks-rs 0.12.1 node and the workspace compiles.

  Bumps trust-tasks-rs 0.11.17 -> 0.12 with the four sibling crates that moved
  with it — capability-client 0.10 -> 0.11, https 0.10 -> 0.12, didcomm 0.10 ->
  0.12, proof 0.10 -> 0.11 — and the TDK crates whose public API carries
  trust-tasks-rs types: affinidi-tdk 0.8.5 -> 0.9, affinidi-messaging-sdk 0.19 ->
  0.20, affinidi-messaging-test-mediator 0.2 -> 0.3. They move together because
  two trust-tasks-rs nodes in one graph do not warn, they fail to compile:
  `expected MediatorAcl, found a different MediatorAcl`.

  One source change. `classify_git_trust_reply` gained a required
  `expected_thread_id` in capability-client 0.11, because acting on an
  uncorrelated reply lets whichever document arrives next decide the fate of a
  write it has nothing to do with. The `replies` registry already keys its waiter
  on `doc.id`, so this is defence in depth — and `correlation_thread` is the
  library's own SPEC §4.9 rule (`threadId` falling back to `id`) rather than this
  call site's guess at it.

  Three marked stopgaps become deletable once this lands, each of which names
  this bump at its site: the freshness stand-in from #1117 in favour of
  `FreshnessPolicy`/`validate_freshness`, the minted `key_id` branch from #1118
  in favour of the wire `keyId`, and `replay::check_and_record` in favour of
  `ReplayGuard`. They are left alone here so this change is a dependency move and
  nothing else.



### Test

- **vta**: Cover the did-templates and policy families ([#1128](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1128))

Coverage 48 -> 58 of 109 (44% -> 53%). Two families, one real defect.



## [0.21.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-service-v0.20.0...vta-service-v0.21.0) — 2026-08-26


### Added

- **vta**: Framework 0.5.0 freshness bounds at the dispatch spine ([#1117](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1117))

Framework 0.5.0 Consumer Requirements item 13. A consumer MUST reject a
  document whose `issuedAt` is ahead of its own clock beyond its skew tolerance,
  and one whose `expiresAt` is at or before its `issuedAt`.

  Both are `malformedRequest`, never `expired`, and that distinction is the
  substance of the rule: `expired` names a document that was once acceptable and
  no longer is, so it tells the producer to wait when what it must do is reissue.
  Neither of these was acceptable at any instant.

  The rule makes the duplicate-execution record of item 11 implementable. That
  record is bounded only if every accepted document can be placed in a window,
  and both shapes escape every window while still looking acceptable: a future
  `issuedAt` sits in a window that has not opened and re-enters it as the clock
  advances, and an `expiresAt` at or before issuance describes an interval that
  never contained an instant.

  This is a stand-in and says so. `trust-tasks-rs` 0.12.0
  (dtgwg-trust-tasks-tf#274) ships `FreshnessPolicy` and
  `TrustTask::validate_freshness`, which implement these two rules identically —
  same 60s skew — and add the `max_age` window and the `ReplayGuard` item 11
  needs. The 0.12 bump is blocked on an external crate: `affinidi-messaging-sdk`
  0.19.12 pins `trust-tasks-rs ^0.11` and `vta_sdk::acl_setup` hands it a
  generated `MediatorAcl`, so two nodes in one graph fail to compile with
  `expected MediatorAcl, found a different MediatorAcl`. The four sibling
  trust-tasks crates have published 0.12-compatible releases; the messaging SDK
  has not.

  The module doc names the blocker and the replacement call, and the tests are
  written against behaviour rather than this implementation, so they survive the
  swap unchanged and are the check that it was faithful.

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

- **audit**: Make the audit destination a deployment choice, not a protocol one ([#1049](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1049))

`AuditLogEntry` is `{id, timestamp, action, actor, resource, outcome, channel,
  contextId, detail}` — no signature, no hash chain. The log corroborates what
  happened; it cannot prove it, and a compromised VTA can rewrite its own history.
  The canonical `AuditEnvelope` already names the members that would change that
  (`prevHash`, `entryHash`, `schemaVersion`) and records why this maintainer omits
  them: its log is flat and unchained.

  This does not add tamper-evidence, deliberately. It adds the seam, so an
  operator who needs a stronger guarantee implements one — an append-only file, a
  transparency log, a blockchain anchor, a hash chain filling in those three
  members — without the VTA committing to any scheme. Closes #1031.

  ## The shape

- **service**: Retire routes and Trust Tasks on evidence, not on a hand audit ([#1047](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1047))

Two gaps in how this workspace retires things, both surfaced while retiring
  `vta/discovery/capabilities/1.0` (#1043, #1044). Closes #1045.

  ## The superseded-route table had no guard

  `deprecation.rs` maps legacy REST routes to the Trust Task that supersedes them
  so that removal can be gated on observed usage dropping to zero. #1042 deleted
  `GET /capabilities` and left its row behind — a row matching a path that can
  never be hit again reads zero forever, which is exactly the signal the table
  exists to produce, emitted about something already deleted. It was noticed by
  accident and removed by hand in #1044, because nothing tied the table to the
  live router.

  `every_superseded_row_names_a_live_route` now walks the assembled router and
  asserts every row matches a live route. It asserts on `MatchedPath` rather than
  on a status code, because `MatchedPath` is what `mark_superseded` matches on: a
  row spelling a parameter differently — `/acl/{id}` where the router registered
  `/acl/{did}` — attaches no header and counts nothing while the route goes on
  answering, and a status-only probe reads green over that. The failure text says
  which way to fix it. The reverse direction is deliberately not asserted; a live
  route absent from the table is legitimate, and `deprecation.rs` already records
  which routes are excluded and why.

  ## Trust Task URIs had no deprecation path at all

  A task could be retired only by deleting it, and the only evidence available was
  a source audit — grep the repos we can see and reason about the rest. That was
  defensible for one task with zero consumers anywhere and does not generalise;
  the next retirement may be one somebody is calling.

  `SUPERSEDED_TASKS` gives them the route mechanism:
  `deprecated_trust_task_requests_total` labelled by URI, the successor named in
  the response so a client can act rather than guess, and removal on an observed
  zero. Seeded with the eleven dispatched URIs already carrying `#[deprecated]` in
  `vta_sdk::trust_tasks` — attributes that told a Rust caller to migrate, told a
  wire caller nothing, and left no instrument saying whether anyone was still
  sending them.

  Checked against the framework first. The *registry* has the concept
  (`status: retired` + `supersededBy`, how twelve `messaging/*` tasks were retired
  upstream), but `trust-tasks-rs` 0.11 exposes none of it: `schema_index` is
  URI → payload schema and nothing else, `Payload` carries no lifecycle constant,
  and `trust-task-discovery/0.1`'s expanded `supportedTypes` entry is closed over
  `{type, requiredExt}`. So this is invention rather than adoption; the vocabulary
  matches the registry's so that adopting a published signal later is a rename.

  The notice rides the response document's **top level**, not `payload.ext`. The
  framework envelope keeps unrecognized top-level members in `TrustTask::extra`
  and SPEC §7.1/§7.2 tells consumers to preserve rather than reject them, so a
  member there cannot break a client that has never heard of it. `payload` can
  make no such promise: every published payload schema is
  `additionalProperties: false`, the generated `Response` types are
  `deny_unknown_fields`, and the conformance sweep validates against both. This is
  the Trust-Task analogue of putting the REST signal in a header — beside the
  answer rather than inside it. A document carrying a `proof` is left untouched.

  ## Both tables are now pinned to what they describe

  `superseded_tasks_are_dispatched` refuses a row nothing routes (that reads zero
  forever, same defect as the dangling route row), `superseded_task_successors_are
  _served` refuses a successor this VTA does not serve (a notice that sends a
  migrating client onto an unsupported type), and
  `every_dual_accepted_spec_marks_its_0_1_form_superseded` pins
  `wire_v0_2::WIRE_SPECS_V0_2` against `SUPERSEDED_TASKS`, so a new dual-accept
  cannot land without an instrument on the form it replaces.

  Not covered, and said so in the source rather than papered over:
  `auth/passkey/login/{start,finish}/0.1` are deprecated but reach neither
  instrument. They are REST-routed on paths the route table excludes on purpose,
  and one path serves both versions with the delta inside the body, so separating
  them needs a counter in those two handlers.

  Two things the tests found rather than confirmed. The signal is attached in
  `dispatch_trust_task_inner` wrapping every exit out of the checks, not after
  them — the spine has a dozen early returns, and a URI going quiet because its
  callers are all being rejected before the hook would read as "nobody sends this
  any more"; the first version had exactly that hole and the rejection test caught
  it. And that split is `Box::pin`ed: the callee's state machine inlines every
  handler's future through `dispatch_typed`, and awaiting it by value overflowed
  the test-thread stack in `tests/mock_vta.rs` under `cargo test --workspace`,
  where feature unification builds more of vta-service than `-p vta-service` does.



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

- **vtc**: Follow the spec on every auth response, and close the conformance gate ([#1112](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1112))

* test(vtc)!: make response conformance fail the build

  Until now the layer reported and a green suite was not evidence of
  conformance — #1107's own memory note said to grep the run rather than trust
  the exit code, which is a signal nobody has to obey.

  A violation outside the allowlist now returns 500 with the schema error, so the
  test that provoked it fails on its own status assertion and prints the reason.
  Chosen over panicking in middleware, which surfaces at the call site as a
  transport error and says nothing about which task or why.

  The allowlist is eight `auth/*` tasks with ALLOWED_COUNT asserted beside them —
  the same discipline as KNOWN_DRIFT_COUNT, because the cheapest way to make a
  failing check pass is to add a line to a list nobody watches. An allowlisted
  violation is still reported, pinned by a test: a list that suppressed the
  evidence would mean rediscovering each entry before it could be closed.

  Two existing guards caught mistakes of mine on the first run. The allowlist
  named login/{start,finish}/0.1 where the service binds 0.2 — built from the
  violation output rather than the route mounts — and the manifest guard flagged a
  fake `trusttasks.org/spec/` URI in a new unit test, correctly, since binding
  such a URI asserts the registry serves it.

  Also retargets relationships/{list,graph} to the 0.2s from
  trustoverip/dtgwg-trust-tasks-tf#266, and fixes a seeder that wrote
  `seed-{uuid}` into `vrcDigestMultibase` — unique per row, and so a suite
  structurally blind to digest format.

  The VTC family is now clean; every remaining violation is `auth/*`.

- **service**: Make AppStateParts non-exhaustive so adding a field stops being a break ([#1057](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1057))

`AppState` was marked `#[non_exhaustive]` in #1024 for a defect this struct
  has too, and the two are constructed side by side. `AppStateParts` is all
  public fields with no private field and no constructor guard, so any crate
  could write an `AppStateParts { .. }` literal — including the
  functional-update form — which made *adding a field* a source break under
  `constructible_struct_adds_field`.

  Not hypothetical, and recent: #1049 added `audit_sink`, and #1051 nearly added
  `app_state_locks` before the break was spotted and routed around by taking the
  value off the built `AppState` instead. That workaround was the right call for
  a feature PR, but it treated the symptom.

  Construction inside this crate is unaffected. Outside it, `Default` plus field
  assignment replaces the literal:

      let mut parts = AppStateParts::default();
      parts.audit_sink = Some(sink);

  `tests/audit_sink.rs` now does exactly that. It is worth noting *why* that file
  had to change: an integration test is a separate crate, so it was the first
  thing the attribute broke — which makes it a fair proxy for what a consumer
  has to do, and a standing check that the supported shape keeps working.



### Chore

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



## [0.20.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-service-v0.19.0...vta-service-v0.20.0) — 2026-08-22


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



## [0.19.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-service-v0.18.0...vta-service-v0.19.0) — 2026-08-21


### Fixed

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

- **service**: Make AppState non-exhaustive so adding a field stops being a break ([#1024](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1024))

`AppState` is 46 public fields, no private field, no constructor guard. Any
  crate could write an `AppState { .. }` literal, which made *adding a field* a
  source-breaking change under `constructible_struct_adds_field`. Twenty-nine
  commits have added at least one field; c93c7b57 added five.

  That break has never once been reported. `cargo semver-checks` cannot build
  this crate's baseline — the published ranges resolve two `trust-tasks-rs`
  versions into one graph — and a crate whose baseline fails to build is
  silently not compared rather than reported as unchecked.

  The version numbers came out right anyway, and it is worth recording why,
  because the reason is two coincidences rather than a working process:

    - at 0.x a break needs a MINOR bump, and conventional commits already force
      one for `feat:`;
    - every field addition since release-plz adoption happened to be a `feat:`.

  Neither holds in general. `refactor:`, `fix:`, `perf:` and `chore:` all yield
  a patch and can add fields just as easily — c93c7b57 is a `refactor:` and
  added five, which is the largest single addition in the file's history.
  Moving state between structs is what a refactor does, so the commit type most
  likely to add public fields is one of the types that yields a patch. And the
  alignment fails completely at 1.0, where a break needs a MAJOR and `feat:`
  gives only a MINOR: the cover expires exactly when the consequences become
  external.

  `#[non_exhaustive]` closes the class permanently instead of relying on any of
  that continuing to hold.

  Nothing outside the crate is affected. Both construction sites are in-crate
  (`build_app_state` and `test_support`), `MockVta` is the supported entry
  point for consumers, and `tests/app_state_single_construction.rs` already
  goes through `build_app_state` rather than a literal — that test is from the
  P1.1 work in c93c7b57, so a single canonical constructor was already the
  crate's intent. This makes it enforceable from outside rather than
  conventional.

  Marked `!` because it is one: outside this crate, `AppState { .. }` and
  exhaustive destructuring stop compiling. That is the point — it is the last
  such break this struct can have.

  cargo test --workspace: 145 suites, 0 failed. cargo check --all-features
  clean, zero warnings.



## [0.18.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-service-v0.17.1...vta-service-v0.18.0) — 2026-08-20


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

- **vta**: Dedup keyed Trust Tasks on an idempotency key ([#1011](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1011))

A client that retries a timed-out request is doing the right thing. The
  dangerous case is the one where the VTA processed it and only the reply
  was lost, because the retry then produces a second durable effect —
  `webvh/dids/create` being the sharp example, where auto-assigned paths
  mean the retry mints a *different* DID and the first stays published
  with nobody holding a reference to it.

  The existing `trust_tasks::replay` layer cannot catch that. It keys on
  `(actor, envelope-id)` and every SDK path mints a fresh `urn:uuid:` per
  attempt, so a genuine retry sails past it. Its own module docs name this
  work as the deliberate follow-up.

  ## Built on the store that was already here

- **service**: Signal every superseded REST route, from one layer ([#1007](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1007))


### Documentation

- **service**: Record why a witness is typed or raw, and when that flips ([#1021](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1021))

The conformance sweep's witnesses are typed for some families and raw JSON
  for others, and nothing in the module said why. The reasoning lived only in
  #1015's PR body, where it does not reach anyone reading the table.

  The rule: typed when the spec preceded the type, raw JSON when it did not,
  and the second case is a debt.

  Typed is the stronger form — it proves our types conform rather than that
  someone can hand-write an acceptable body — but only when the type did not
  derive its shape from the same misreading that produced the witness. When
  the contexts/webvh schemas arrived, create_did_webvh was sending context_id
  against a schema naming contextId, and update_context was dropping
  contextPolicy entirely. Witnesses built from those types would have encoded
  both defects and passed green.

  Same principle scripts/check-bindings-conformance.mjs applies a layer down
  by re-implementing the binding rules instead of importing them.

  This also makes the retro-fit legible as a real step rather than tidying:
  converting the 22 to typed bodies is only sound now that #1015 corrected
  the types, and would have laundered the bugs before that.

  Docs only; no behaviour change.



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



## [0.17.1](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-service-v0.17.0...vta-service-v0.17.1) — 2026-08-18


## [0.17.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-service-v0.16.1...vta-service-v0.17.0) — 2026-08-17


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



### Chore

- **deps**: Track trust-tasks 0.9 across the workspace ([#996](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/996))

Moves all five `trust-tasks-*` requirements and `trust-tasks-capability-client`
  (0.5 -> 0.8) together, as the family requires: `trust-tasks-rs`'s core types
  cross the public API of `-https` / `-didcomm` / `-proof`, so a graph mixing
  majors does not type-check. Takes the `affinidi-messaging-*` releases built on
  0.9 (sdk 0.19.8, mediator 0.18.18, didcomm-service 0.3.26, test-mediator 0.2.51)
  in the same move, so the lockfile carries exactly one copy of everything.

  There are no `consume_inbound` call sites in this workspace, so 0.9.0's new
  `PayloadPolicy` argument costs nothing here, and nothing matches on
  `StandardCode`, so 0.7.0's `#[non_exhaustive]` costs nothing either. The
  `validate` feature stays enabled and unused, as before.

  What did change is the wire version of the error documents this stack emits.

  `trust-task-error` moved 0.3 -> 0.4 -> 0.5 upstream, each step for the same
  reason the 0.3 step happened: a new standard code that the older payload
  schema's `code` enum does not list and whose extended-code pattern does not
  match, so a document carrying it would not validate as the older version. 0.4
  carries `idConflict`, 0.5 carries `cancelled` (SPEC §8.3).

  Both services hand-write that version on their one unrouted path — where there
  is no request document to reject from, and so no framework call to ask —
  and both were left naming 0.3 while `reject_with` stamped 0.5 on every routed
  rejection. One service emitting two versions is a trap for exactly the consumer
  that pins one of them. `unrouted_and_routed_errors_agree_on_the_type_uri` exists
  in both services to catch precisely this, and it did: the bump failed those two
  tests rather than shipping two dialects. Constants updated, rationale extended.

  Two in-`src` VTC test fixtures that also named 0.3 now take the version from
  `framework_error_type_uri()` instead of repeating it, so they follow the emitter
  on the next bump rather than stranding a version behind. That also keeps
  `trust_task_manifest`'s unpublished-URI census at one URI for the family; the
  census is deliberately exact so the debt can shrink but never grow unnoticed,
  and raising the expected count would have been the wrong fix.

  Backward acceptance of an *older* error document keeps its coverage:
  `vtc-service/tests/registry_didcomm.rs` pins 0.1 on purpose, and is left alone.

  Per SPEC §5.2 forward-minor compatibility, a consumer still pinned to
  `trust-task-error/0.3` SHOULD accept 0.5. Marked `!` because this changes the
  version on the wire, not because any Rust signature moved.



## [0.16.1](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-service-v0.16.0...vta-service-v0.16.1) — 2026-08-16


## [0.16.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-service-v0.15.4...vta-service-v0.16.0) — 2026-08-16


### Added

- **vta-vault**: Bind an mdoc to the VTA key that can present it ([#990](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/990))

An mdoc's holder binding is a key, not a DID: the MSO carries a deviceKey, and
  only its private half can sign DeviceAuth. Nothing in the stored envelope said
  which VTA key that was, so a received mdoc could be stored and then turn out to
  be unpresentable — with the failure surfacing much later, at presentation, and
  nothing pointing at the cause.

  Receive now resolves that binding and refuses the credential if this VTA does
  not hold the key. Storing a credential you can never present is a trap, and the
  right moment to find out is the moment it arrives.

  mdoc_device_key_sec1 extracts the MSO deviceKey as a compressed SEC1 point —
  the same encoding the VTA stores its own P-256 public keys in — so the caller
  can compare without re-deriving either side. Extraction lives in vta-vault
  because it reads mdoc internals; the matching lives in vta-service because that
  is the layer that can see the keyspace. vta-vault does not depend on vta-keys,
  and this keeps it that way.

  find_key_by_public_multibase is a linear scan: the keyspace is indexed by key
  id, not by public key, and a reverse index for one receive-path caller is not
  worth the write amplification on every mint. It takes no AuthClaims because it
  answers a factual question, not an authorization one — the caller gates on the
  returned record's context_id, because binding a credential to a key in a
  context the caller cannot act in would be a cross-tenant escape.

- **vta-service**: Accept ISO mdoc over the credential-receive Trust Task ([#989](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/989))

Everything shipped for mdoc so far — the format identity ([#984](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/984)), receive-side
  verification ([#986](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/986)) and the IACA trust anchors ([#987](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/987)) — was reachable only
  through the library. handle_receive was hardcoded to the Data-Integrity path:
  a JSON credential, an issuer DID resolved through the DID cache, no format
  parameter. An mdoc could not arrive at the VTA at all. This connects it.

  ReceiveBody gains an optional format tag and a credentialBase64 carrier, since
  an mdoc is CBOR and cannot travel as JSON. Absent format still means
  Data-Integrity, which is the shape every existing client sends, so a deployed
  wallet is unaffected — pinned by a test that parses a pre-existing body and
  asserts it still routes to the DI path. Exactly one of credential or
  credentialBase64 must be present; both, or neither, is a malformedRequest.

  The mdoc arm is where the two credential families genuinely diverge. A DI
  credential names its issuer as a DID and the key is resolved through the cache;
  an mdoc names its issuer as an X.509 Document Signer, so the credential is
  decoded first to read its x5chain and the key comes from the configured IACA
  anchors instead. That asymmetry is the whole reason the anchors exist.

  AppState carries the parsed anchors, built once in build_app_state from
  [vault] mdoc_iaca_trust_anchors. A malformed certificate fails the boot rather
  than surfacing as a puzzling rejection on the first mdoc that arrives. Empty is
  legal and means this VTA accepts no mdoc issuers; the resolver fails closed on
  it, so wiring the wire surface does not by itself make any VTA start trusting
  mdocs — an operator still has to configure anchors deliberately.

  No schema change: vault/credentials/receive/0.1 is in UNSPECCED_DISPATCHED_URIS,
  so there is no published payload schema to update and dispatch validation is a
  no-op for it either way.

  Note for a follow-up, not changed here: test_support.rs constructs an AppState
  literal directly, so build_app_state is not in practice the single constructor
  its doc comment claims. Adding a field has to be done in both places.



## [0.15.4](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-service-v0.15.3...vta-service-v0.15.4) — 2026-08-16


### Added

- **vta-vault**: Verify and store ISO mdoc credentials on receive ([#986](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/986))

#984 gave mdoc a CredentialFormat identity but receive still refused it, because
  affinidi-mdoc had no way to turn a stored body back into an IssuerSigned. 0.2.6
  added that codec, so receive can now do the real work.

  Verifies three things per ISO 18013-5 S9.3.1, rejecting-without-storing on any
  failure: the issuerAuth COSE_Sign1 over the MSO, every item digest against the
  MSO valueDigests (a good signature over an MSO whose digests do not match means
  the items were swapped after signing), and the validityInfo window.

  issuer_pub is the caller-resolved Document Signer key — deliberately the same
  shape as the DI path's issuer key, and for the same reason: deciding *which*
  key to trust is policy that belongs to the wire layer. That seam matters more
  here, because mdoc anchors issuer trust in an X.509 chain (x5chain, COSE label
  33, rooted in an IACA) while this stack is DID-rooted end to end. Taking a
  resolved key keeps that unresolved question out of the storage layer instead of
  quietly settling it.

  ES256 only, checked explicitly before the signature so a mismatched algorithm
  is refused by name rather than failing as an opaque bad signature. ISO 18013-5
  and the EUDI profiles mandate ES256, which the VTA already has via
  KeyType::P256, so no new curve enters the graph.

  subject_did and issuer_did are left None: an mdoc binds to its holder through
  the MSO deviceKey, not a subject DID, and carries no issuer DID. Inventing
  either would put an unverifiable identifier into a secondary index.

  coset and time are declared as direct dependencies rather than used
  transitively through affinidi-mdoc — the receive path names their types, and
  depending on a transitive is how an unrelated version bump breaks a crate.

  DCQL matching and presentation are deliberately NOT in this change. dcql_format
  still returns None for mdoc: admitting it without a present_single arm trips
  formats_admitted_for_dcql_are_all_presentable, and that guard is right — a
  matched-but-unpresentable credential bails the entire vp_token, not just itself.
  Presenting an mdoc needs DeviceResponse::to_cbor_bytes (affinidi-mdoc 0.2.7,
  under review as affinidi/affinidi-tdk-rs#712), so matching and presentation land
  together in a follow-up.

- **vta-vault**: Give ISO mdoc a first-class CredentialFormat identity ([#984](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/984))

An mdoc arriving at the credential vault previously deserialised into the
  `Other(String)` escape hatch, so every downstream `match` treated one of
  the two eIDAS-mandated credential formats as an unknown vendor tag.

  Adds `CredentialFormat::MsoMdoc`, tagged `mso_mdoc` — the OpenID4VP
  `CredentialQuery.format` spelling, explicitly renamed rather than taking
  the enum's kebab-case `mso-mdoc`, so storage and protocol agree on one
  token. A test pins the exact bytes, not just the round-trip.

  Receive refuses an mdoc rather than storing a body it cannot re-read, and
  `dcql_format` returns `None` for it, keeping the existing matchable-implies-
  presentable invariant true. Both carry the reason: affinidi-mdoc 0.2.5 has
  no CBOR codec for `IssuerSigned` (it derives only Debug + Clone, with no
  Serialize/Deserialize and no to/from_cbor_bytes), so the body cannot be
  decoded, verified, or re-encoded for presentation. Wiring receive, DCQL
  matching and presentation is blocked on that codec landing upstream.

  The invariant guard in credential_exchange enumerates formats by hand, so
  MsoMdoc is added there too — otherwise a new variant is silently uncovered.



## [0.15.3](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-service-v0.15.2...vta-service-v0.15.3) — 2026-08-14


### Added

- **nitro**: Un-bake tenant config, deliver to the enclave over vsock ([#939](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/939))

* feat(nitro): un-bake tenant config, deliver to the enclave over vsock

  The Nitro enclave image no longer bakes tenant config.toml into the EIF, so one image (one PCR0) serves every tenant. The entrypoint fetches a versioned config envelope from the parent over vsock:5800 (bounded connect/read timeouts, 1 MB size cap, version check), fails closed unless VTA_ALLOW_DEFAULT_CONFIG=true, and writes /etc/vta/config.toml before start. Adds jq to the runtime; documents the KMS-policy isolation requirement and the tee-mode enforcement floor.



## [0.15.2](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-service-v0.15.1...vta-service-v0.15.2) — 2026-08-14


## [0.15.1](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-service-v0.15.0...vta-service-v0.15.1) — 2026-08-14


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



### Fixed

- **trust-tasks**: Stop emitting two versions of the framework error document ([#973](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/973))

* fix(trust-tasks): stop emitting two versions of the framework error document

  Both services routed their rejections through `TrustTask::reject_with`, which
  stamps whatever version `trust-tasks-rs` emits — `trust-task-error/0.3` since
  the framework's own 0.3 release. But each service also has one *unrouted* path,
  for a body that never parsed into a Trust Task at all, and with no request
  document to reject from it had to write the Type URI out by hand. Both wrote
  `0.1`.

  So a single service spoke two dialects, distinguished only by whether the
  request happened to parse. That is a trap for exactly the consumer that pins a
  version, and it is not hypothetical: a client enumerating `0.1`/`0.2` read every
  `0.3` rejection as a **success**, because an unrecognised error document falls
  through to the success branch and its payload is returned as the operation's
  result (OpenVTC/vta-browser-plugin#115, affinidi/affinidi-webvh-service#160).
  The version a service emits is wire contract; emitting two is worse than
  emitting the wrong one, because whichever a consumer pins is right half the time.

  `trust-tasks-rs` keeps `trust_task_error_type_uri()` `pub(crate)`, so the value
  cannot be read from the framework. Each service now names it once, in
  `framework_error_type_uri()` beside the unrouted builder, and a test compares
  that against the Type URI a real `reject_with` produces. A framework bump now
  fails a test instead of silently re-splitting the service in two. A second test
  asserts the bytes on the wire carry it, not just the value we compute.

  Test fixtures that stood in for a peer's rejection were built at `0.1` — a
  version no peer on trust-tasks-rs 0.4 sends. They now use what a peer actually
  emits. Those assertions pass either way (the matchers key on the slug, which is
  the right way to match), but a suite that exercises a wire nobody speaks is how
  the client-side version pin survived this long unnoticed.

  Left alone deliberately: `vtc-service::messaging`'s `.unwrap_or(…/0.1)` default,
  which labels an inbound document that carries no `type` at all. It is not an
  emitted document, and every consumer of that label matches on the slug.

- **webvh**: Sign with the update keys in force, not the ones the head restated ([#972](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/972))

A DID whose most recent log entry did not restate `updateKeys` could not be
  updated again. Every attempt died with

      webvh library error: log entry has no update_keys — DID is deactivated or malformed

  about a DID that was neither deactivated nor malformed, and the operator reads
  that as lost keys. Nothing was lost. The keys were never consulted.

  webvh parameters are a delta: an entry that omits `updateKeys` leaves the
  previous entry's in force. `didwebvh-rs` models that as two fields —
  `update_keys` is what the entry *declared* (`None` when it declared nothing) and
  `active_update_keys` is the effective set validation carried forward
  (`parameters/mod.rs`, the `None =>` arm: "If absent, keep current updateKeys").
  Only the second answers "which key signs the next entry". The orchestrator read
  the first, got an empty list, and handed it to `load_active_update_key`, whose
  first line rejects an empty list — so the DID's real update key was never looked
  up in the handle cache, never re-derived from the seed, never tried.

  The head entry that triggers it is one this code writes itself: for a
  metadata-only update with no pre-rotation, `set_update_keys` is `None` (nothing
  forces a key reveal, and rotating on a no-op change would be wrong), so the
  entry lands as `"parameters": {}`. One such update and the DID is permanently
  un-updatable by this VTA. Found on a live hosting-server DID whose v3 was
  exactly that; v1 declared the keys, v2 rotated them, v3 declared nothing.

  `next_key_hashes` needs no equivalent change: the library inherits that one into
  the field itself, so the pre-rotation path was always reading the effective set.
  That is also why the failure looked so selective — a DID whose head happens to
  restate its keys, which every document-changing update does, works fine.

  Regression test drives the real sequence: create, metadata-only update, then
  update again. It asserts the intermediate entry really does omit the parameter,
  so it cannot pass for the wrong reason if the write path ever changes. Reverting
  the one-line read reproduces the production error verbatim.

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


