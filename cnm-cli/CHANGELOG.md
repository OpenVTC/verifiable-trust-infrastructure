# Changelog

Notable changes to the published crates. Generated from conventional commits by
[git-cliff](https://git-cliff.org) when a release is cut — do not edit by hand.
## [0.17.2](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/cnm-cli-v0.17.1...cnm-cli-v0.17.2) — 2026-09-22


## [0.17.1](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/cnm-cli-v0.17.0...cnm-cli-v0.17.1) — 2026-09-22


### Added

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



## [0.17.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/cnm-cli-v0.16.8...cnm-cli-v0.17.0) — 2026-09-21


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



## [0.16.8](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/cnm-cli-v0.16.7...cnm-cli-v0.16.8) — 2026-09-21


## [0.16.7](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/cnm-cli-v0.16.6...cnm-cli-v0.16.7) — 2026-09-21


## [0.16.6](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/cnm-cli-v0.16.5...cnm-cli-v0.16.6) — 2026-09-20


### Fixed

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



## [0.16.5](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/cnm-cli-v0.16.4...cnm-cli-v0.16.5) — 2026-09-18


## [0.16.4](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/cnm-cli-v0.16.3...cnm-cli-v0.16.4) — 2026-09-18


## [0.16.3](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/cnm-cli-v0.16.2...cnm-cli-v0.16.3) — 2026-09-17


## [0.16.2](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/cnm-cli-v0.16.1...cnm-cli-v0.16.2) — 2026-09-17


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



## [0.16.1](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/cnm-cli-v0.16.0...cnm-cli-v0.16.1) — 2026-09-16


## [0.16.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/cnm-cli-v0.15.4...cnm-cli-v0.16.0) — 2026-09-16


### Added

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

- **cli**: Type rate-limit refusals on the hand-rolled bootstrap and VTC paths ([#1521](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1521))

pnm bootstrap connect, cnm backup, and cnm audit verify build their own error strings from the HTTP status instead of going through the SDK client, so a 429 read as a bare "request failed" — the same class #1511 fixed for the SDK paths. Map 429 to VtaError::RateLimited via rate_limited_from_http (headers captured before the body), so print_cli_error names which service limited, the wait, and how to tune it. On pnm bootstrap connect the limiter runs before the carve-out is touched, so a note says the one-shot first boot is not spent and retry after the wait is safe. The header/attribution parsing is covered by vta-sdk's rate_limit tests; this is the call-site wiring.



## [0.15.4](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/cnm-cli-v0.15.3...cnm-cli-v0.15.4) — 2026-09-16


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



## [0.15.3](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/cnm-cli-v0.15.2...cnm-cli-v0.15.3) — 2026-09-16


## [0.15.2](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/cnm-cli-v0.15.1...cnm-cli-v0.15.2) — 2026-09-15


## [0.15.1](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/cnm-cli-v0.15.0...cnm-cli-v0.15.1) — 2026-09-14


## [0.15.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/cnm-cli-v0.14.4...cnm-cli-v0.15.0) — 2026-09-12


### Security

- **resolver**: Refuse did:webvh resolution to non-public hosts by default ([#1448](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1448))


## [0.14.4](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/cnm-cli-v0.14.3...cnm-cli-v0.14.4) — 2026-09-10


## [0.14.2](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/cnm-cli-v0.14.1...cnm-cli-v0.14.2) — 2026-09-09


## [0.14.1](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/cnm-cli-v0.14.0...cnm-cli-v0.14.1) — 2026-09-08


## [0.14.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/cnm-cli-v0.13.6...cnm-cli-v0.14.0) — 2026-09-07


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


## [0.13.6](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/cnm-cli-v0.13.5...cnm-cli-v0.13.6) — 2026-09-07


## [0.13.5](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/cnm-cli-v0.13.4...cnm-cli-v0.13.5) — 2026-09-06


## [0.13.4](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/cnm-cli-v0.13.3...cnm-cli-v0.13.4) — 2026-09-06


## [0.13.3](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/cnm-cli-v0.13.2...cnm-cli-v0.13.3) — 2026-09-01


## [0.13.2](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/cnm-cli-v0.13.1...cnm-cli-v0.13.2) — 2026-08-29


## [0.13.1](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/cnm-cli-v0.13.0...cnm-cli-v0.13.1) — 2026-08-29


## [0.13.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/cnm-cli-v0.12.2...cnm-cli-v0.13.0) — 2026-08-28


### Fixed

- **sdk**: Give every authenticated client its identity, and adopt provision/integration 0.3 ([#1147](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1147))

#1146 made every producer sign, and left seven production paths building
  clients that cannot. Each authenticates, takes the token, and drops the DID and
  key on the floor — so every task they dispatch is refused for a missing
  `recipient` and `proof`. `SessionStore::connect` was fixed; nothing else was,
  because no test drives those paths against an enforcing VTA.



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



## [0.12.2](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/cnm-cli-v0.12.1...cnm-cli-v0.12.2) — 2026-08-26


## [0.12.1](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/cnm-cli-v0.12.0...cnm-cli-v0.12.1) — 2026-08-22


## [0.12.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/cnm-cli-v0.11.24...cnm-cli-v0.12.0) — 2026-08-21


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



## [0.11.24](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/cnm-cli-v0.11.23...cnm-cli-v0.11.24) — 2026-08-20


## [0.11.23](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/cnm-cli-v0.11.22...cnm-cli-v0.11.23) — 2026-08-18


## [0.11.22](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/cnm-cli-v0.11.21...cnm-cli-v0.11.22) — 2026-08-17


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



## [0.11.21](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/cnm-cli-v0.11.20...cnm-cli-v0.11.21) — 2026-08-16


## [0.11.20](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/cnm-cli-v0.11.19...cnm-cli-v0.11.20) — 2026-08-16


## [0.11.19](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/cnm-cli-v0.11.18...cnm-cli-v0.11.19) — 2026-08-14


## [0.11.18](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/cnm-cli-v0.11.17...cnm-cli-v0.11.18) — 2026-08-14


## [0.11.17](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/cnm-cli-v0.11.16...cnm-cli-v0.11.17) — 2026-08-12


## [0.11.16](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/cnm-cli-v0.11.15...cnm-cli-v0.11.16) — 2026-08-12


## [0.11.15](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/cnm-cli-v0.11.14...cnm-cli-v0.11.15) — 2026-08-12

