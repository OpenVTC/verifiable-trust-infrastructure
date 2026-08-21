# Changelog

Notable changes to the published crates. Generated from conventional commits by
[git-cliff](https://git-cliff.org) when a release is cut — do not edit by hand.
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


