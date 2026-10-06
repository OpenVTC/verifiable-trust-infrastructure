# Changelog

Notable changes to the published crates. Generated from conventional commits by
[git-cliff](https://git-cliff.org) when a release is cut — do not edit by hand.
## [0.16.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-config-v0.15.0...vta-config-v0.16.0) — 2026-10-06


## [0.15.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-config-v0.14.0...vta-config-v0.15.0) — 2026-10-05


## [0.14.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-config-v0.13.0...vta-config-v0.14.0) — 2026-10-04


## [0.13.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-config-v0.12.0...vta-config-v0.13.0) — 2026-10-02


## [0.12.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-config-v0.11.0...vta-config-v0.12.0) — 2026-10-02


## [0.11.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-config-v0.10.0...vta-config-v0.11.0) — 2026-10-01


## [0.10.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-config-v0.9.0...vta-config-v0.10.0) — 2026-10-01


## [0.9.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-config-v0.8.3...vta-config-v0.9.0) — 2026-09-30


## [0.8.3](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-config-v0.8.2...vta-config-v0.8.3) — 2026-09-30


## [0.8.2](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-config-v0.8.1...vta-config-v0.8.2) — 2026-09-28


### Added

- **storage**: Optional Fjall memory settings for the VTA and VTC ([#1803](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1803))

Add STORAGE_FJALL_BLOCK_CACHE, STORAGE_FJALL_WRITE_BUFFER and
  STORAGE_FJALL_MAX_JOURNAL, plus a matching [fjall] config-file table, so
  an operator can keep fjall's block cache, buffered writes and startup
  journal replay inside a pod's Kubernetes memory limit.

  All three are optional and shared, unprefixed names for every consumer
  (vti_common::config::FjallTuning, apply_fjall_env_overrides). Unset
  leaves fjall's own defaults byte for byte; an env var overrides the
  config file; an invalid, zero, or absurdly small value is refused at
  startup naming the setting. Values accept a plain byte count or a
  suffixed size ("64MiB", "512MB", "1GiB").



## [0.8.1](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-config-v0.8.0...vta-config-v0.8.1) — 2026-09-27


## [0.8.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-config-v0.7.1...vta-config-v0.8.0) — 2026-09-27


### Added

- **attestation**: The TEE attestation reads are public Trust Tasks, over any transport ([#1776](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1776))

* feat(attestation)!: the TEE attestation reads are public Trust Tasks, over any transport

  A TEE VTA answered three attestation reads only as unauthenticated REST routes
  (`GET /attestation/status`, `GET`/`POST /attestation/report`,
  `POST /attestation/config-report`), plus a bare DIDComm protocol arm that
  nothing sent to. Under the rule that every remote API is a spec-first,
  spine-dispatched Trust Task reachable over TSP, DIDComm and HTTPS, they are now
  `vta/attestation/{status,report,config-report}/0.1` (trustoverip/
  dtgwg-trust-tasks-tf#654, trust-tasks-rs 0.23.2), dispatched on the spine.

  Public tasks
  - `vta_sdk::trust_tasks::PUBLIC_URIS` names the tasks a caller may send with no
    identity: no session, no ACL entry, no request proof. A verifier asks before
    it trusts the VTA; the nonce bound into the evidence is what makes a report
    its own, and every response is the VTA's signed operational document.
  - HTTPS: `/trust-tasks` takes an optional credential. An anonymous caller may
    send only a public task (anything else is 401), capped at 64 KB, and those
    requests are charged to the unauthenticated limiter — which charges only
    requests presenting no credential, decided by the extractor's own rule
    (`vti_common::auth::extractor::presents_credential`), so a junk header cannot
    move a request between the two classes.
  - DIDComm/TSP: a sender the ACL does not know gets a zero-authority claim for a
    public task, and `bind_document_to_sender` accepts it unsigned — the spec
    makes the request proof OPTIONAL and HTTPS accepts it unsigned, so refusing it
    here would make the requirement depend on the transport (VTI-OPS-021). An
    attached proof is still verified and bound.
  - A census (`every_public_task_is_proof_optional_and_read_only`) fails if a task
    whose spec requires a proof, or whose dispatch class changes state, discloses
    a secret or acts as its subject, is ever added to `PUBLIC_URIS`.

  Behaviour
  - `report` and `config-report` require a 32-byte verifier nonce; the cached,
    nonce-less report is not carried over — evidence nobody asked for is evidence
    anybody can replay.
  - Failures carry the specs' declared codes: `notAttested` (no provider),
    `noConfigSnapshot` (only the enclave front-end captures one),
    `evidenceUnavailable` (the platform refused a quote).
  - The VTA still requires `issuedAt` on every document (bounding its replay
    record), stricter than the spec; the deploy README examples send it.

  Removed (breaking)
  - The REST routes above and the DIDComm `firstperson.network/vta/1.0/
    attestation/*` arms, with their SDK constants; `TASK_ATTESTATION_{STATUS,
    REPORT}_1_0` become `TASK_ATTESTATION_{STATUS,REPORT,CONFIG_REPORT}_0_1` and
    leave `REST_ROUTED_URIS`.
  - The `TeeAttestation` DID-document service, which pointed at the REST route
    (user decision: removed, not re-pointed). `tee.embed_in_did` and
    `VTA_TEE_EMBED_IN_DID` are **refused** at config load as retired, naming the
    replacement, rather than silently ignored. The shipped Nitro configs drop the
    key; the deploy scripts' health hints point at `/health`.



## [0.7.1](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-config-v0.7.0...vta-config-v0.7.1) — 2026-09-26


## [0.7.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-config-v0.6.8...vta-config-v0.7.0) — 2026-09-26


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



## [0.6.8](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-config-v0.6.7...vta-config-v0.6.8) — 2026-09-24


## [0.6.7](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-config-v0.6.6...vta-config-v0.6.7) — 2026-09-23


## [0.6.6](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-config-v0.6.5...vta-config-v0.6.6) — 2026-09-23


## [0.6.5](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-config-v0.6.4...vta-config-v0.6.5) — 2026-09-22


## [0.6.4](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-config-v0.6.3...vta-config-v0.6.4) — 2026-09-22


## [0.6.3](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-config-v0.6.2...vta-config-v0.6.3) — 2026-09-21


## [0.6.2](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-config-v0.6.1...vta-config-v0.6.2) — 2026-09-21


## [0.6.1](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-config-v0.6.0...vta-config-v0.6.1) — 2026-09-21


## [0.6.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-config-v0.5.3...vta-config-v0.6.0) — 2026-09-20


### Fixed

- **rate-limit**: Key the per-IP limiter on trusted-proxy CIDRs, not a global XFF flag ([#1562](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1562))

* fix(rate-limit)!: key the per-IP limiter on trusted-proxy CIDRs, not a global XFF flag

  Replaces the boolean `trust_xff` flag with `trust_xff_cidrs: Vec<CIDR>` (VTA + VTC). The per-IP rate limiter now reads `X-Forwarded-For` only when the request's peer address falls inside an explicit trusted-proxy CIDR allowlist, keying on the rightmost entry.

  Fixes two issues with the old flag: an untrusted peer could forge a leading XFF entry to evade its own limit, and every request behind a trusted proxy shared one bucket — one client's burst could 429 unrelated clients.

  Breaking config change: replace `trust_xff = true/false` with `trust_xff_cidrs = ["<cidr>", ...]`.



## [0.5.3](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-config-v0.5.2...vta-config-v0.5.3) — 2026-09-18


## [0.5.2](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-config-v0.5.1...vta-config-v0.5.2) — 2026-09-17


## [0.5.1](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-config-v0.5.0...vta-config-v0.5.1) — 2026-09-16


## [0.5.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-config-v0.4.9...vta-config-v0.5.0) — 2026-09-16


### Added

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



### Fixed

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



## [0.4.9](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-config-v0.4.8...vta-config-v0.4.9) — 2026-09-16


## [0.4.8](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-config-v0.4.7...vta-config-v0.4.8) — 2026-09-12


## [0.4.7](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-config-v0.4.6...vta-config-v0.4.7) — 2026-09-10


## [0.4.5](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-config-v0.4.4...vta-config-v0.4.5) — 2026-09-09


## [0.4.4](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-config-v0.4.3...vta-config-v0.4.4) — 2026-09-07


## [0.4.3](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-config-v0.4.2...vta-config-v0.4.3) — 2026-09-07


## [0.4.2](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-config-v0.4.1...vta-config-v0.4.2) — 2026-09-06


### Fixed

- **tee**: Make allow_kms_reinit explicit authorization for reinit regardless of KMS failure type ([#1249](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1249))

* fix(tee): make allow_kms_reinit explicit authorization for reinit regardless of KMS failure type



## [0.4.1](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-config-v0.4.0...vta-config-v0.4.1) — 2026-08-29


## [0.4.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-config-v0.3.13...vta-config-v0.4.0) — 2026-08-28


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



## [0.3.13](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-config-v0.3.12...vta-config-v0.3.13) — 2026-08-26


### Added

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



## [0.3.12](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-config-v0.3.11...vta-config-v0.3.12) — 2026-08-22


## [0.3.11](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-config-v0.3.10...vta-config-v0.3.11) — 2026-08-21


## [0.3.10](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-config-v0.3.9...vta-config-v0.3.10) — 2026-08-20


## [0.3.9](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-config-v0.3.8...vta-config-v0.3.9) — 2026-08-18


## [0.3.8](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-config-v0.3.7...vta-config-v0.3.8) — 2026-08-17


## [0.3.7](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-config-v0.3.6...vta-config-v0.3.7) — 2026-08-16


## [0.3.6](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-config-v0.3.5...vta-config-v0.3.6) — 2026-08-16


## [0.3.5](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-config-v0.3.4...vta-config-v0.3.5) — 2026-08-14


### Added

- **nitro**: Un-bake tenant config, deliver to the enclave over vsock ([#939](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/939))

* feat(nitro): un-bake tenant config, deliver to the enclave over vsock

  The Nitro enclave image no longer bakes tenant config.toml into the EIF, so one image (one PCR0) serves every tenant. The entrypoint fetches a versioned config envelope from the parent over vsock:5800 (bounded connect/read timeouts, 1 MB size cap, version check), fails closed unless VTA_ALLOW_DEFAULT_CONFIG=true, and writes /etc/vta/config.toml before start. Adds jq to the runtime; documents the KMS-policy isolation requirement and the tee-mode enforcement floor.



## [0.3.4](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-config-v0.3.3...vta-config-v0.3.4) — 2026-08-13


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


