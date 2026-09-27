# WebVH daemon REST integration — robustness audit

> **Superseded.** The REST client this audit covers (`webvh_client.rs`,
> `webvh_auth.rs`, the `server-auth:` token cache and its per-server locks)
> has been removed. The VTA reaches a DID hosting service only with Trust
> Tasks (`vta-service/src/webvh_host.rs`), over TSP, DIDComm or HTTPS, with
> every request signed by the VTA and every reply required to carry the
> host's proof. Kept as a record of the findings.

Status: 2026-05-15. Captures the audit performed during the
`feat/webvh-rest-auth-hardened` branch (successor to PR #111).

## Scope

The audit covered the full webvh integration on `vta-service` —
not just what PR #111 touched. We surveyed:

- `webvh_client.rs` (HTTP transport + auth flow)
- `webvh_auth.rs` (JWS-signed message builders)
- `webvh_store.rs` (keyspace + auth-cache)
- `webvh_didcomm.rs` (DIDComm transport)
- `operations/did_webvh/{mod,update/*,register_server,servers,
   lifecycle,document,concurrency,transport,webvh_keys}.rs`
- `operations/backup.rs` (export + restore symmetry)
- `vta-sdk::webvh` (public types)

## What's already shipped on this branch (fixed)

The commits between `main` and `feat/webvh-rest-auth-hardened` HEAD
address these items from the earlier PR #111 review:

- **HTTPS enforcement** on daemon REST URLs (`WebvhClient::new`
  refuses non-https except documented loopback hosts).
- **JWS-signed daemon authenticate / refresh** built via pure
  `webvh_auth::build_*_message` and consumed by `WebvhClient::
  {authenticate, refresh}`. DIDComm `to: [server_did]` field
  populated for forward-looking audience binding.
- **Typed errors with operator hints** on daemon failures: 401
  surfaces the ACL hint; 4xx becomes `Validation`; 5xx becomes
  `Internal`. Refresh-401 surfaces `Authentication` so callers can
  re-auth.
- **Auth-cache storage isolation**: `WebvhServerAuthRecord` lives
  under `server-auth:{id}` keyspace, never embedded on the
  operator-visible `WebvhServerRecord`. Token fields removed from
  `WebvhServerRecord` entirely. Legacy on-disk records still
  deserialise (unknown fields are dropped).
- **Cascade-delete**: `webvh_store::delete_server` also removes
  the auth record. Same-id re-add can't inherit stale tokens.
- **Backup hygiene**: `apply_import` adds `server-auth:` to the
  wipe prefix list so cross-installation token replay is closed.
  Export already excludes the prefix (the `prefix_iter_raw
  ("server:")` byte-prefix doesn't match `server-auth:`).
- **Secret hygiene**: `ZeroizeOnDrop` + redacting `Debug` on
  `WebvhServerAuthRecord` and `TokenData` so neither
  `tracing::info!(?record)` nor post-drop memory exposes the token
  bytes.
- **Transport-resolution module**: `operations::did_webvh::
  transport::resolve_server_transport` is a pure function over a
  `ServiceEntry` trait. Accepts `DIDCommMessaging`, `WebVHHosting`
  (canonical), and `WebVHHostingService` (legacy alias). DIDComm
  precedence regardless of service[] array ordering.

## Findings: not addressed on this branch

The findings below are flagged for follow-up commits / PRs. They
do not block landing this branch; they are tracked so the
operation-layer plumbing that lands next can pick them up.

### Critical

**C1. Production REST endpoints will 401 against any ACL-enforcing
daemon.** `WebvhTransport::from_server` constructs an
unauthenticated `WebvhClient` and no call site invokes
`authenticate`/`set_access_token`. Every `publish_did` /
`delete_did` / `request_uri` / `check_path` will fail.

- *Why deferred*: requires plumbing the VTA's signing identity
  (`VtaSigningIdentity { vta_did, signing_kid, private_key }`)
  through every operation that builds a transport. Substantial,
  benefits from its own focused commit.
- *Implementation hint surfaced by the audit*: reuse
  `operations::keys::get_key_secret_internal` +
  `InternalAuthority` rather than building a new helper. The
  pattern lives in `operations/provision_integration/vta_keys.rs`
  and handles both `KeyOrigin::Derived` and `KeyOrigin::Imported`
  symmetrically — so the "imported keys can't sign daemon REST"
  caveat from the earlier audit is moot once we use this helper.

### High

**H1. Daemon 401 vs 403 hint mismatch.**
`WebvhClient::map_auth_failure` (`webvh_client.rs:310-329`)
attaches the "VTA DID not in daemon ACL" hint to 401 responses.
The daemon actually returns **403** for ACL failures and **401**
for signature/session/challenge invalidation. The hint is on the
wrong branch.

- *Fix*: split a 403 arm out of the generic 4xx case. Move the
  ACL hint there. The 401 case becomes "signature/session/
  challenge invalid — check clock skew, re-fetch challenge, verify
  the VTA's signing-key fragment matches its DID document."

**Status on this branch: fixed in a follow-up commit on this branch.**

**H2. `update_did_webvh` doesn't use `RecordSnapshot` for CAS.**
`operations/did_webvh/update/orchestrator.rs:249-261` checks only
`log_entry_count`. A concurrent `register_did_with_server` that
flips `server_id` from `serverless` to `webvh-prod` (and updates
`mnemonic`) slips past unchallenged because it leaves
`log_entry_count` untouched. Step 13 then publishes to the wrong
server.

- *Fix*: capture `RecordSnapshot` at step 1, assert unchanged at
  step 11. Mirror what `rotate.rs:102,158-160` and
  `register_server.rs:141,202-204` already do.

**Status on this branch: fixed in a follow-up commit on this branch.**

**H3. Backup restore replays `WebvhDidRecord` with server-managed
state.** On `apply_import`, every imported DID with `server_id !=
"serverless"` lands in the new VTA's local store. A subsequent
`update` or `rotate` on that DID publishes the new log entry to
the original VTA's daemon — clobbering it if the daemon's ACL
still trusts the shared VTA DID (which the backup also carried).

- *Fix*: when `running_did != backup_did` (disaster-recovery to a
  different VTA), strip `server_id`/`mnemonic` off imported
  `WebvhDidRecord` entries — operator must re-`register_did_
  with_server` per imported DID. When `running_did == backup_did`
  (full-system restore), keep them.

- *Why deferred from this branch*: needs a follow-up commit that
  also adds new test infrastructure for the "different-VTA
  restore" path. Captured here for tracking.

**H4. `delete_did_webvh` swallows daemon-side failure silently.**
`mod.rs:1019-1052` `warn!`s on `transport.delete_did()` failure
and continues with local cleanup, returning `deleted: true`. The
local record is gone; the daemon still hosts the log; the
operator has no surface to discover the orphan.

- *Fix*: extend `DeleteDidWebvhResultBody` with
  `daemon_cleanup: Result<(), String>` (or a typed
  `AppError::DaemonOrphan`), and surface the orphan in CLI output
  with a corrective command suggestion. Don't fail the whole
  operation — local cleanup matters most — just stop hiding the
  orphan.

- *Why deferred*: API surface change on the SDK result type; touches
  CLI rendering. Worth its own commit.

### Medium

**M1. Document `WebvhDIDCommClient` parity.** The DIDComm
transport has no signing identity, no audience binding,
no typed errors. **This is correct** — DIDComm authcrypt
already binds sender DID at the envelope layer (verified by
`unpack_signed` the same way the JWS path is). The JWS-over-REST
machinery we added is the *equivalent* of what authcrypt gives us
for free over DIDComm. Action: add a module-level comment in
`webvh_didcomm.rs` documenting this so the next reviewer doesn't
try to "add parity" and break the abstraction.

**Status on this branch: fixed in a follow-up commit on this branch.**

**M2. Decorative `to:` audience binding.** The current daemon
doesn't verify `to:`, so today the binding is decorative —
practical defence comes from session_id+challenge uniqueness
(UUIDv4 + 32 random bytes, both daemon-supplied). But the moment
a future daemon starts verifying `to:` (a five-line change in
the daemon's `unpack_signed` caller), the JWS will need it. We
already populate it, so no client redeploy is required when that
day comes. **No change needed.**

**M3. Log lines hardcode `status = 200`.** `webvh_client.rs:369,
403, 418, 429` all `debug!(method = "PUT", status = 200, …)`
regardless of actual response code (daemon PUT/DELETE returns
204). Cosmetic but operator-facing tracing should match reality.

- *Fix*: pass `resp.status().as_u16()` into the debug line, or drop
  the `status` field — the success branch already implies 2xx.

**Status on this branch: fixed in a follow-up commit on this branch.**

**M4. `delete_did_webvh` pre-rotation cleanup loop bound is
fragile.** `mod.rs:1043-1050` `for i in 0..100u32` is a hard cap.
`pre_rotation_count: u32` has no upper validator at create time,
so a DID created with `pre_rotation_count=200` leaks 100 key
records on delete.

- *Fix*: bound the loop to `record.pre_rotation_count` (the value
  is in scope from the loaded `WebvhDidRecord`), and/or add a
  hard validation in `create_did_webvh` capping at 32.

**M5. Fresh `reqwest::Client` per call site.** Each
`WebvhTransport::from_server` builds a new `WebvhClient` which
builds a new `reqwest::Client`. Connection pool and DNS cache
are per-client. For high-traffic operators (rotate-and-publish
cycles, drain-driven service updates) this is a small but real
tax.

- *Fix*: shared `reqwest::Client` on `AppState`, passed into
  `WebvhClient::new`. Not urgent.

### Low

**L1. No clock-skew defence on authenticate.** Daemon's
freshness window is 5 minutes past / 60 seconds future. VTAs with
clocks more than 6 minutes off get a flat auth failure with no
actionable hint.

**L2. `WebvhClient::send` body-text-buffering is unbounded.** A
hostile/misbehaved daemon can OOM the VTA. Daemons are
operator-controlled, so blast radius is small.

**L3. `WebvhTransport::from_server` re-resolves the server DID on
every operation.** Cheap, but redundant when one op does it twice
(e.g. `rotate_did_webvh_keys` → `update_did_webvh`).

## What's good and shouldn't be undone

1. `RecordSnapshot` is the right CAS abstraction. The conscious
   split of "version-vector fields vs. owned-mutated fields"
   (`concurrency.rs:55-66`) is correct. **Lift it everywhere**
   record-mutating ops live — H2 above is exactly this.
2. `WebvhServerAuthRecord` storage isolation, redacted `Debug`,
   `ZeroizeOnDrop`, and the `delete_server` cascade are all the
   right paranoia. The `prefix_iter_raw("server:")` does *not*
   match `server-auth:`; the dedicated test pins this invariant.
3. Transport-security policy (`webvh_client.rs:39-74`) is the
   right shape: https always, http only to documented loopback
   subnets, explicit reject for `0.0.0.0` and
   `localhost.evil.example`.
4. Typed errors (`UpdateDidWebvhError`, `RegisterDidWith
   ServerError`) with `From<…> for AppError` wire mappings and
   explicit `Conflict(RaceDetected)` carry-through is the
   discipline the workspace CLAUDE.md asks for. Keep it.
5. `get_key_secret_internal` + `InternalAuthority`
   (`operations/keys.rs:630-727`) is the right plumbing for
   daemon-REST signing. **Reuse it; don't add a new helper.**
6. `register_did_with_server` uses `register_did_atomic` — single-
   batch claim-and-publish — instead of `request_uri` +
   `publish_did`. Avoids the resolvability gap. Good.

## Deferred follow-ups (tracked)

The operation-level integration commit that follows this branch
should:

1. **C1** — Plumb `VtaSigningIdentity` through `WebvhTransport`
   construction using `get_key_secret_internal`. Make `from_server`
   load the auth cache, refresh-or-reauth, set the token on the
   client. Implement one-shot 401-retry-with-reauth on
   `publish_did` / `delete_did` / `request_uri` / `check_path`.
2. **H3** — Strip `server_id`/`mnemonic` from imported
   `WebvhDidRecord` entries on cross-VTA restore.
3. **H4** — Surface daemon orphan via the `DeleteDidWebvhResultBody`
   shape; add CLI rendering for the corrective command.
4. **Concurrent-refresh mutex** — `DashMap<String, Arc<Mutex<()>>>`
   on `AppState` keyed by `server.id`, lock around the auth-cache
   RMW cycle. The lock serialises refresh, not the I/O — only one
   waiter per server at a time.
5. **M4** — Bound the pre-rotation cleanup loop to
   `record.pre_rotation_count`.
6. **M5, L1, L2, L3** — Performance / clock-skew / safety
   refinements. Low priority.

## Test coverage status

| Area | Coverage on this branch | Gap |
|------|-------------------------|-----|
| Transport resolution | 13 unit tests in `transport::tests` | None known |
| HTTPS enforcement | 14 unit tests | None known |
| JWS builder | 7 unit tests, round-trip via daemon's `unpack` | None known |
| Daemon REST auth flow | 6 wiremock integration tests | 403 hint coverage (H1 fix adds it) |
| Auth-cache lifecycle | 5 unit tests | None known |
| Backup restore wipe | 1 unit test | Cross-VTA replay (H3 will add) |
| Token Debug redaction | 2 unit tests | None known |
| `update_did_webvh` CAS | Pre-existing log_entry_count check | RecordSnapshot test (H2 fix adds it) |

## How to use this document

If you're picking up the follow-up work: start with C1 (it's the
biggest user-visible gap), then H3, then H4. The Medium and Low
items can land opportunistically.

If you're reviewing a PR that touches webvh paths: cross-check
the section "What's good and shouldn't be undone" — those
patterns are deliberate and removing them would re-open the
findings.
