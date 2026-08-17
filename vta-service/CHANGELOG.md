# Changelog

Notable changes to the published crates. Generated from conventional commits by
[git-cliff](https://git-cliff.org) when a release is cut — do not edit by hand.
## [0.17.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-service-v0.16.1...vta-service-v0.17.0) — 2026-08-16


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


