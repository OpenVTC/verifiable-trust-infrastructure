# Todo: VTC MVP — Phase 0

Status legend: `[ ]` not started · `[~]` in progress · `[x]` done · `[!]` blocked

Each task lists: **acceptance** (what must be true), **verify** (how
to prove it), **files** (what's touched), **deps** (which task IDs
must land first). Tasks within a milestone that share `deps` can run
in parallel.

Spec: `docs/05-design-notes/vtc-mvp.md`
Plan: `tasks/vtc-mvp/plan.md`

Every code task also drafts the matching Trust Task spec
(`trust-tasks/.../spec.md` + `schema.json`) in the same PR — soft
gate per spec §9.4. Stable IDs are non-negotiable; spec body can be
skeletal.

Every PR must be DCO-signed (`git commit -s`) and pass
`cargo fmt --check`, `cargo clippy -- -D warnings`, `cargo test`.

---

## M0.1 — Hygiene primitives (`vti-common`)

### `[ ]` M0.1.0 — Add `webauthn-rs` to workspace deps + scaffold `vtc-service` import

- **Acceptance**
  - `webauthn-rs = "0.5"` (or current stable) added to workspace deps
  - Re-exported into `vtc-service`'s `Cargo.toml`
  - Empty `vtc-service/src/webauthn.rs` module compiles
- **Verify** `cargo build --package vtc-service` succeeds
- **Files**
  - `Cargo.toml` (workspace)
  - `vtc-service/Cargo.toml`
  - `vtc-service/src/webauthn.rs` (new, empty)
  - `vtc-service/src/lib.rs` (add module)
- **Deps**: none

### `[x]` M0.1.1 — Trust-Task extractor + `TrustTaskRouter` builder

- **Acceptance**
  - `vti-common::trust_task::TrustTask` newtype around a validated
    `https://trusttasks.org/.../{maj}.{min}` URL
  - Axum extractor `TrustTaskHeader` reads the `Trust-Task` header
    and parses it into `TrustTask`; missing → 400 `TrustTaskMissing`;
    malformed → 400 `TrustTaskMalformed`
  - `TrustTaskRouter` builder wraps Axum `Router` with an explicit
    `.route_with_task(path, method, handler, task)` method that
    enforces **exact-match** on the header at request time
  - `.route_exempt(path, method, handler)` for `/health` (and only
    `/health` — codified in docs)
  - Errors are typed (`AppError::TrustTaskMissing`,
    `AppError::TrustTaskMismatch`) with structured JSON responses
    naming the expected task
- **Verify**
  - Unit tests: missing header, malformed URL, mismatched URL,
    exact match
  - Doctest example wiring a handler to a task
- **Files**
  - `vti-common/src/trust_task/mod.rs` (new)
  - `vti-common/src/trust_task/extractor.rs` (new)
  - `vti-common/src/trust_task/router.rs` (new)
  - `vti-common/src/error.rs` (new variants)
  - `vti-common/src/lib.rs` (re-export)
- **Deps**: M0.1.0
- **Pre-impl decision**: D1 (schema format), D8 (header name), D9
  (builder vs macros)

### `[x]` M0.1.2 — Audit envelope + HMAC actor hashing + `audit_key` keyspace

- **Acceptance**
  - `AuditEnvelope` struct per spec §11.1, including `event_version`,
    `schema_version`, `event_id`, `timestamp`, hash + plaintext pairs
  - `AuditEvent` tagged enum (`#[serde(tag = "type", content = "data")]`)
    with a single variant `Generic { kind: String, payload: Value }`
    as a placeholder — full Phase-0 variants land in M0.1.5
  - `AuditWriter` that takes events, hashes actor/target with HMAC,
    persists into an `audit` keyspace
  - `AuditKeyStore` manages the per-community `audit_key` lifecycle:
    generate-on-first-use, persist under `HKDF(seed, "vtc-audit-key/v1")`,
    rotate-on-RTBF, retain history for verifying pre-rotation hashes
- **Verify**
  - Round-trip a `Generic` event through `AuditWriter` and read back
  - Two events with the same actor DID yield the same hash within one
    `audit_key` epoch
  - `rotate_audit_key()` causes new events to use the new key;
    pre-rotation events still verify under the retained prior key
  - Snapshot test of the wire JSON shape of `AuditEnvelope` (catches
    accidental schema drift)
- **Files**
  - `vti-common/src/audit/mod.rs` (new)
  - `vti-common/src/audit/envelope.rs` (new)
  - `vti-common/src/audit/writer.rs` (new)
  - `vti-common/src/audit/key_store.rs` (new)
  - `vti-common/src/lib.rs`
- **Deps**: M0.1.0
- **Pre-impl decision**: D3 (audit_key storage)

### `[x]` M0.1.3 — Idempotency keyspace + middleware

- **Acceptance**
  - `IdempotencyClass` enum: `NonDestructive` (24 h TTL) and
    `Destructive` (60 s TTL with target-state revalidation hook)
  - `IdempotencyStore` keyed by `(session_id, idempotency_key)` →
    `(request_hash, response_bytes, expires_at)`
  - Axum middleware that:
    - reads `Idempotency-Key` header
    - hashes the request body (sha256)
    - on cache hit with matching hash, returns the cached response
    - on cache hit with mismatched hash, returns 422 `IdempotencyKeyConflict`
    - for `Destructive` class, calls a per-route revalidation closure
      before serving the cached response
  - Per-route registration via `.with_idempotency(class)` on
    `TrustTaskRouter`
- **Verify**
  - Unit tests for the three branches (miss → store; hit + match →
    cached; hit + mismatch → 422)
  - Test that two principals with the same key get separate cache
    entries (session_id scoping)
  - Test that the destructive class fires the revalidation closure
- **Files**
  - `vti-common/src/idempotency/mod.rs` (new)
  - `vti-common/src/idempotency/store.rs` (new)
  - `vti-common/src/idempotency/middleware.rs` (new)
  - `vti-common/src/trust_task/router.rs` (extend builder)
- **Deps**: M0.1.1
- **Pre-impl decision**: D6 (destructive op identification)

### `[x]` M0.1.4 — Cursor pagination contract

- **Acceptance**
  - `Cursor` newtype: opaque base64url-encoded
    `(last_key: String, snapshot_id: u64)` tuple, signed under the
    audit_key so cursors can't be forged across communities
  - `Paginated<T>` response wrapper with `items`, `next_cursor`,
    optional `total_estimate`
  - Helper `paginate<K, V, T>` that takes a fjall iterator + a
    cursor + a limit + a mapper and returns the wrapper
- **Verify**
  - Unit test: walk a populated keyspace via repeated calls,
    confirm all items returned exactly once with monotonic cursor
  - Limit clamping (`1..200`)
  - Forged cursor (different audit_key) returns 400
- **Files**
  - `vti-common/src/pagination/mod.rs` (new)
  - `vti-common/src/lib.rs`
- **Deps**: M0.1.2 (uses audit_key for cursor signing)

### `[x]` M0.1.5 — Phase-0 audit event variants

- **Acceptance**
  - `AuditEvent` variants added (replacing the `Generic` placeholder):
    `CommunityInstalled`, `EmergencyBootstrapInvoked`,
    `AdminPasskeyRegistered`, `AdminPasskeyRevoked`,
    `ConfigChanged`, `ConfigReloaded`, `RestartRequested`,
    `CommunityProfileUpdated`, `AuditKeyRotated`
  - `ConfigChanged.data` carries the sensitivity-flag-aware redaction
    logic (per spec §11.4)
- **Verify**
  - Snapshot test per variant
  - Round-trip every variant through `AuditWriter`
- **Files**
  - `vti-common/src/audit/envelope.rs`
- **Deps**: M0.1.2

### M0.1.6 — Reusable passkey infrastructure in `vti-common`

Per **D11** + the `webvh-common::server::passkey` reference (see
`plan.md` Reference implementations). Split into two PRs during
implementation: scaffold + storage lands first, route handlers
follow once consumers (M0.5) need them.

#### `[x]` M0.1.6a — Scaffold + types + storage

- **Acceptance**
  - `webauthn-rs` added to workspace dependencies.
  - New feature `passkey` on `vti-common` gating the module.
  - New module `vti-common::auth::passkey` containing:
    - `PasskeyState` trait extending `AuthState`.
    - `build_webauthn(public_url: &str) -> Result<Webauthn, AppError>`
      with single-source RP-ID derivation per **D7**.
    - `ENROLLMENT_CLAIM_WINDOW_SECS = 300` constant per **D12**.
  - Sub-module `store` containing:
    - Types: `Enrollment` (with manual redacted `Debug` per **D13**),
      `PasskeyUser`, `CredentialMapping`.
    - Module-local `take` / `take_raw` helpers (sequenced
      `get` + `remove`; the atomicity gap is documented and
      acceptable for in-process use).
    - Storage helpers covering enrolments, registration state,
      authentication state, registration → user mapping,
      registration → enrolment mapping, passkey users, credential
      mappings.
  - 10 unit tests cover `build_webauthn` (happy + invalid URL +
    no-domain), `Enrollment` `Debug` redaction, every storage
    round-trip plus the `take` consumption semantics.
- **Verify**
  - `cargo test --package vti-common --features passkey passkey::`
    runs all 10 new tests green.
  - `cargo clippy --package vti-common --features passkey -- -D warnings`
    clean.
  - `cargo build --workspace` clean (default features unaffected).
- **Files**
  - `Cargo.toml` (workspace `webauthn-rs` dep)
  - `vti-common/Cargo.toml` (passkey feature + per-feature deps)
  - `vti-common/src/auth/mod.rs` (gate the new module)
  - `vti-common/src/auth/passkey/mod.rs` (new)
  - `vti-common/src/auth/passkey/store.rs` (new)
- **Deps**: none (replaces M0.1.0's "add webauthn-rs to workspace +
  scaffold vtc-service import" — the dep is added here and `vtc-service`
  will consume `vti-common::auth::passkey` rather than depending on
  `webauthn-rs` directly).

#### `[ ]` M0.1.6b — Route handlers

- **Acceptance**
  - `enroll_start`, `enroll_finish`, `login_start`, `login_finish`
    route handlers generic over `S: PasskeyState`, in a new
    `vti-common::auth::passkey::routes` module.
  - Helper `require_webauthn`, `require_jwt_keys`, `token_prefix`.
  - Uses the existing `vti-common::auth::session::create_authenticated_session`
    + `vti-common::acl::check_acl` for post-ceremony session minting
    (so the handler returns a `TokenResponse` ready for the service
    to forward).
  - Round-trip integration test using `webauthn-rs`'s deterministic
    test authenticator harness — exercises `enroll_start` →
    ceremony → `enroll_finish` end-to-end through a stub
    `PasskeyState` impl.
- **Files**
  - `vti-common/src/auth/passkey/routes.rs` (new)
  - `vti-common/src/auth/passkey/mod.rs` (re-export)
- **Deps**: M0.1.6a + access to the existing session/ACL helpers
  (already in vti-common).

### Checkpoint A — Hygiene foundation green
After M0.1.0–M0.1.5: `cargo test --package vti-common` clean. No
consumer yet; primitives ready for the rest of Phase 0 to depend on.

---

## M0.2 — `vtc-host` DID template (`vta-sdk`)

### `[x]` M0.2.1 — Author `vtc-host.json` template

- **Acceptance**
  - `vta-sdk/templates/vtc-host.json` exists, structurally validated
    by the existing `DidTemplate::from_json` parser
  - `kind: "vtc-host"`, `methods: ["webvh", "web"]`
  - `requiredVars`: `URL`, `COMMUNITY_NAME`
  - `optionalVars`: `STATUS_LIST_PATH` (default `/v1/status-lists`),
    `ACCEPT` (default `["didcomm/v2"]`, used only if a mediator is
    added in a later phase)
  - Document mints three keys: assertionMethod Ed25519, authentication
    Ed25519, keyAgreement X25519
  - Service entries: `#vtc-rest` (`type: "VTCRest"`, endpoint = `{URL}`)
    and `#vtc-status-list` (`type: "VTCStatusList"`, endpoint =
    `{URL}{STATUS_LIST_PATH}`) — the latter is a placeholder URL
    until Phase 2 wires the actual status list, gracefully present
- **Verify**
  - `every_builtin_parses_and_validates` test (existing in
    `builtin.rs`) covers the new template automatically
  - Snapshot test of the rendered document for a known input
- **Files**
  - `vta-sdk/templates/vtc-host.json` (new)
  - `vta-sdk/src/did_templates/builtin.rs` (add to `BUILTIN_NAMES`
    + `load_embedded` switch)
- **Deps**: none — fully parallel with M0.1

### `[x]` M0.2.2 — Documentation entry for `vtc-host`

- **Acceptance**
  - `docs/03-integrating/did-templates.md` updated with `vtc-host`
    template description, vars, usage example
- **Verify** doc renders; no broken links
- **Files**
  - `docs/03-integrating/did-templates.md`
- **Deps**: M0.2.1

### Checkpoint B — DID template provisionable
After M0.2.1–M0.2.2: a developer can run
`vta bootstrap provision-integration --template vtc-host --var URL=…
--var COMMUNITY_NAME=…` against any local VTA and receive a sealed
bundle containing a valid VTC `did:webvh`. No VTC binary needed yet.

---

## M0.3 — `/v1/` URL migration + Trust-Task wiring

### `[x]` M0.3.1 — Move existing routes under `/v1/` prefix

- **Acceptance**
  - `vtc-service/src/routes/mod.rs` mounts auth + acl + config
    routes under `/v1/`
  - `/health` stays at root and is Trust-Task-exempt
  - Existing integration tests in `vtc-service/tests/` updated to use
    `/v1/` paths
- **Verify**
  - `cargo test --package vtc-service` green
- **Files**
  - `vtc-service/src/routes/mod.rs`
  - `vtc-service/tests/auth_audience.rs` (path updates)
- **Deps**: M0.1.1 (for `TrustTaskRouter`)

### `[x]` M0.3.2 — Wire Trust-Task header on existing routes (placeholder IDs)

- **Acceptance**
  - Each existing route registered with a placeholder Trust Task ID
    matching its eventual stable ID (e.g., the legacy auth routes
    get IDs we'll revisit in Phase 1; for now they pass through with
    `auth/legacy/challenge/1.0` etc.)
  - `TrustTask` header missing → 400 with structured error
  - `TrustTask` header mismatched → 415 with structured error
- **Verify**
  - Integration test: each route returns 400 / 415 appropriately
  - `/health` does not require the header
- **Files**
  - `vtc-service/src/routes/auth.rs`
  - `vtc-service/src/routes/acl.rs`
  - `vtc-service/src/routes/config.rs`
  - `trust-tasks/auth/legacy/...` (Draft `spec.md` + `schema.json`
    stubs; will be revisited)
  - `trust-tasks/index.json`
- **Deps**: M0.3.1

---

## M0.4 — Install token + carve-out primitive

### `[x]` M0.4.1 — `InstallToken` struct + JWT signer

- **Acceptance**
  - `InstallToken` claims: `iss` (VTC DID), `sub` ("install"),
    `aud` ("vtc-install"), `exp` (15 min), `iat`, `jti`, `cnonce`
    (32-byte WebAuthn challenge), `epubkey` (ephemeral Ed25519
    pubkey for the ceremony)
  - `mint_install_token()` produces a signed JWT using a fresh
    ephemeral keypair (private key retained server-side in a new
    `install` keyspace keyed by `jti`)
  - `parse_install_token()` validates signature, audience, expiry,
    and the `cnonce` length
- **Verify**
  - Round-trip a minted token
  - Expired token rejected
  - Wrong audience rejected
  - Tampered signature rejected
- **Files**
  - `vtc-service/src/install/token.rs` (new)
  - `vtc-service/src/install/mod.rs` (new)
  - `vtc-service/src/lib.rs`
- **Deps**: M0.1.0
- **Pre-impl decision**: D2 (nonce binding mechanism)

### `[x]` M0.4.2 — Install carve-out keyspace with claim-window state machine

Per **D12**: webvh-common's claim-window pattern, not immediate
single-use.

- **Acceptance**
  - New `install` keyspace stores `(jti → InstallTokenState)`:
    - `Issued { exp, cnonce, ephemeral_privkey, claimed_at: Option<DateTime> }`
    - `Consumed { at }`
    - `Closed`
  - Single global `INSTALL_CARVEOUT_LOCK: tokio::sync::Mutex<()>`
    in `vtc-service`
  - `start_claim(jti, now)` (called from `/v1/install/claim/start`):
    takes the lock, reads state, refuses if `Consumed` or `Closed`,
    refuses if `claimed_at` is set within
    `ENROLLMENT_CLAIM_WINDOW_SECS = 300`, otherwise sets `claimed_at`
    and returns the ephemeral private key + cnonce for the WebAuthn
    ceremony. **Does not consume.**
  - `finish_claim(jti)` (called from `/v1/install/claim/finish`
    after WebAuthn success): transitions `Issued → Consumed`
  - `close_carveout()` (called after admin bootstrap) sets the
    keyspace's `Closed` marker; subsequent `mint_install_token()`
    calls return `AppError::InstallCarveoutClosed`
- **Verify**
  - Concurrent `start_claim` calls on the same JTI within the
    300s window: exactly one succeeds; second waits or fails
  - `start_claim` → 5min timeout (no `finish_claim`) → retry
    `start_claim` succeeds
  - Re-minting after `close_carveout` is rejected
  - State machine transitions audited in tests
- **Files**
  - `vtc-service/src/install/state_machine.rs` (new)
  - `vtc-service/src/install/mod.rs`
- **Deps**: M0.4.1
- **Pre-impl decision**: D12

### Checkpoint C — Install-token primitive works
After M0.4.1–M0.4.2: install tokens mint/claim/close atomically;
concurrent claims race correctly through the mutex. No WebAuthn yet.

---

## M0.5 — WebAuthn claim flow

### `[x]` M0.5.0 — WebAuthn test harness validation

- **Acceptance**
  - `tests/common/webauthn_harness.rs` ships a
    `SoftEd25519Authenticator` producing deterministic CTAP-format
    registration + authentication responses (none-attestation, COSE
    OKP Ed25519 public keys via `ciborium` CBOR encoding, signatures
    from `ed25519-dalek`).
  - The harness refuses non-EdDSA registration challenges with a
    panic — protects callers that bypass
    `vtc_service::webauthn::start_eddsa_passkey_registration`.
- **Verify**
  - `tests/webauthn_harness.rs` × 3 tests:
    - `register_then_authenticate_completes_end_to_end` — full
      ceremony succeeds, harness pubkey matches the passkey's stored
      COSE `x` coordinate (proves the byte that becomes the
      `did:key` is the one the authenticator generated).
    - `second_authenticate_increments_sign_count` — counter
      monotonicity holds across multiple assertions.
    - `register_panics_when_challenge_lacks_eddsa` — guard against
      misuse by tests that drive the upstream challenge directly.
- **Files**
  - `vtc-service/tests/common/mod.rs` (new)
  - `vtc-service/tests/common/webauthn_harness.rs` (new — ~260 lines)
  - `vtc-service/tests/webauthn_harness.rs` (new — 3 validation tests)
  - `vtc-service/Cargo.toml` (`ciborium` dev-dep)
- **Deps**: M0.5.1 (uses the EdDSA-restricting wrappers as the
  challenge producer)
- **Note**: Upstream `webauthn-authenticator-rs::SoftPasskey` is
  hard-coded to ES256 (`openssl::ec`) and was unsuitable; the
  in-tree harness sidesteps that.

### `[x]` M0.5.1 — VTC `AppState` implements `PasskeyState`

- **Acceptance**
  - `vtc-service::server::AppState` implements
    `vti_common::auth::passkey::PasskeyState`
  - `build_webauthn` called once at startup using `public_url` from
    the existing `AppConfig.public_url` field; resulting
    `Arc<Webauthn>` lives in `AppState`
  - **Ed25519-only enforcement**: new `vtc_service::webauthn` module
    wraps the upstream `start_passkey_registration` so the wire
    `pubKeyCredParams` and the persisted `RegistrationState.credential_algorithms`
    both contain **only** EdDSA (`alg = -8`). `webauthn-rs` 0.5 has
    no public `algorithms(…)` setter, so the rewrite uses serde
    round-trip via `danger-allow-state-serialisation`.
    `finish_eddsa_passkey_registration` additionally asserts the
    returned `Passkey::cred_algorithm() == EDDSA` as defence in depth.
- **Verify**
  - Startup test: missing `public_url` → `AppState.webauthn()`
    returns `None` (`tests/passkey_state.rs::webauthn_returns_none_when_public_url_unset`).
    Install routes returning 503 is deferred to **M0.5.2** when the
    routes themselves land.
  - The CCR + registration state rewrite is asserted via four unit
    tests in `vtc-service::webauthn::tests::*` — start-time rewrite
    + the two primitive mutators in isolation. The integration test
    asserting "ES256 registration attempt is rejected" needs the
    deterministic EdDSA authenticator harness from M0.5.0 and ships
    in PR B alongside M0.5.2.
- **Files**
  - `vtc-service/src/webauthn.rs` (new — Ed25519 restricting wrappers)
  - `vtc-service/src/server.rs` (AppState +
    `webauthn`/`passkey_ks`/`public_url`; `impl PasskeyState`)
  - `vtc-service/src/lib.rs` (`pub mod webauthn`)
  - `vtc-service/Cargo.toml` (enable `vti-common/passkey`, add
    `webauthn-rs` + `webauthn-rs-proto` direct deps)
  - `vtc-service/tests/passkey_state.rs` (new — 5 trait-impl tests)
  - `vtc-service/tests/{admin_config,auth_audience,community_profile}.rs`
    (new AppState fields)
- **Deps**: M0.5.0 (test harness — deferred to PR B), M0.1.6
- **Pre-impl decision**: D7, D11

### `[ ]` M0.5.2 — Install claim endpoints (start + finish)

Per **D12**: two-phase ceremony, not a single endpoint. Adopts the
webvh-common `enroll_start` / `enroll_finish` shape but specialised
for the install carve-out (one-shot, not an ongoing invite system).

- **Acceptance**
  - `POST /v1/install/claim/start`: accepts `{ install_token }`,
    validates via `parse_install_token`, calls
    `install::state_machine::start_claim`, then calls
    `vti_common::auth::passkey::enroll_start` to begin the
    WebAuthn registration ceremony. Returns
    `{ registration_id, options: CreationChallengeResponse }`.
    Challenge bound to the token's `cnonce`.
  - `POST /v1/install/claim/finish`: accepts
    `{ registration_id, webauthn_response, candidate_did_signature }`,
    completes the ceremony via `enroll_finish`, calls
    `install::state_machine::finish_claim`, verifies
    `candidate_did_signature` over a server-issued nonce using the
    candidate `did:key`. Returns a setup-session token
    (audience `"vtc-install-session"`) + the candidate admin DID.
  - Trust Task IDs: `install/claim/start/1.0`,
    `install/claim/finish/1.0`
- **Verify**
  - End-to-end test using `Router::oneshot` + the harness from M0.5.0
  - Failure cases: bad token, expired token, replayed token after
    consume, mismatched cnonce, wrong DID signature, non-Ed25519
    algorithm, second concurrent `claim/start` within the 5min
    claim window, abandoned ceremony followed by retry after
    timeout (succeeds)
- **Files**
  - `vtc-service/src/routes/install.rs` (new)
  - `vtc-service/src/routes/mod.rs`
  - `trust-tasks/install/claim/start/1.0/{spec.md,schema.json}`
  - `trust-tasks/install/claim/finish/1.0/{spec.md,schema.json}`
  - `trust-tasks/index.json`
- **Deps**: M0.4.2, M0.5.1, M0.3.1, M0.1.6
- **Pre-impl decision**: D2, D12

---

## M0.6 — Admin bootstrap + multi-passkey schema

### `[ ]` M0.6.1 — Extend ACL `Role` enum + `AdminEntry` shape

- **Acceptance**
  - `VtcRole` per spec §5.3 (`Admin`, `Moderator`, `Issuer`,
    `Member`, `Custom(String)`)
  - `AclEntry` extended: admin-role entries carry
    `passkeys: Vec<RegisteredPasskey>` and `extensions: JsonValue`
  - Migration path from existing ACL entries documented (existing
    `Admin` rows get an empty `passkeys` vec)
- **Verify**
  - Unit tests for serialization round-trip
  - Backwards-compat test: existing ACL records deserialize cleanly
- **Files**
  - `vti-common/src/acl/mod.rs`
  - `vtc-service/src/acl/mod.rs`
- **Deps**: M0.1.0

### `[ ]` M0.6.2 — `POST /v1/admin/bootstrap`

- **Acceptance**
  - Endpoint accepts the setup-session token from M0.5.2 and the
    candidate admin DID + first passkey
  - Atomically: writes ACL entry with `role: Admin`, single passkey,
    emits `CommunityInstalled` audit event, calls
    `install::carveout::close_carveout()`
  - Returns 409 if any admin already exists (defence-in-depth even
    though the install carve-out should prevent this)
  - Trust Task ID: `admin/bootstrap/1.0`
- **Verify**
  - End-to-end happy path test
  - Bootstrap-after-bootstrap returns 409
  - `CommunityInstalled` event present in audit log
- **Files**
  - `vtc-service/src/routes/admin/bootstrap.rs` (new)
  - `vtc-service/src/routes/admin/mod.rs` (new)
  - `vtc-service/src/routes/mod.rs`
  - `trust-tasks/admin/bootstrap/1.0/{spec.md,schema.json}`
- **Deps**: M0.5.2, M0.6.1, M0.1.2

### `[ ]` M0.6.3 — Multi-passkey endpoints with step-up UV reauth

- **Acceptance**
  - `POST /v1/admin/passkeys/register`: requires authenticated
    session AND fresh WebAuthn UV in the same request
  - `DELETE /v1/admin/passkeys/{credential_id}`: same UV requirement;
    CAS-protected last-passkey check (refuses if it would leave
    zero passkeys)
  - `GET /v1/admin/passkeys`: lists with `credential_id`, `label`,
    `transports`, `registered_at`, `last_used_at`
  - Trust Task IDs: `admin/passkeys/{register,revoke,list}/1.0`
- **Verify**
  - Register-with-stale-session (no UV) → 401
  - Revoke last passkey → 409 `LastPasskeyProtected`
  - Concurrent revoke calls do not race past the CAS check
  - Each operation emits the correct audit event
- **Files**
  - `vtc-service/src/routes/admin/passkeys.rs` (new)
  - `vtc-service/src/auth/extractor.rs` (extend with
    `StepUpUvAuth` extractor)
  - `trust-tasks/admin/passkeys/register/1.0/{spec.md,schema.json}`
  - `trust-tasks/admin/passkeys/revoke/1.0/{spec.md,schema.json}`
  - `trust-tasks/admin/passkeys/list/1.0/{spec.md,schema.json}`
- **Deps**: M0.6.2, M0.5.0

### Checkpoint D — End-to-end first-admin install
After M0.6.1–M0.6.3: a fresh VTC binary can be set up, install URL
claimed via WebAuthn (test harness), admin DID bootstrapped, and a
second passkey registered. Install carve-out permanently closed.

---

## M0.7 — Community profile (parallel track)

### `[x]` M0.7.1 — `CommunityProfile` schema + `community` keyspace

- **Acceptance**
  - `CommunityProfile` per spec §5.1 (community_did immutable, all
    other fields editable; `extensions: JsonValue`)
  - `extensions` enforced at ≤ 16 KiB (per D4); larger → 413
  - Stored under stable key `community/profile` in a new keyspace
- **Verify**
  - Round-trip serialization
  - `extensions` size-limit test
- **Files**
  - `vtc-service/src/community/mod.rs` (new)
  - `vtc-service/src/community/profile.rs` (new)
  - `vtc-service/src/store/mod.rs` (register keyspace)
- **Deps**: M0.1.0
- **Pre-impl decision**: D4

### `[x]` M0.7.2 — `GET / PUT /v1/community/profile`

- **Acceptance**
  - `GET` returns the singleton profile; 404 if not yet initialised
  - `PUT` requires `Admin` role; rejects changes to `community_did`
  - Successful `PUT` emits `CommunityProfileUpdated` audit event
  - Trust Task IDs: `community/profile/{show,update}/1.0`
- **Verify**
  - Integration tests cover happy + immutable-field rejection +
    non-admin auth failure
- **Files**
  - `vtc-service/src/routes/community/mod.rs` (new)
  - `vtc-service/src/routes/community/profile.rs` (new)
  - `vtc-service/src/routes/mod.rs`
  - `trust-tasks/community/profile/show/1.0/{spec.md,schema.json}`
  - `trust-tasks/community/profile/update/1.0/{spec.md,schema.json}`
- **Deps**: M0.7.1, M0.6.1

---

## M0.8 — Config plumbing (parallel track)

### `[x]` M0.8.1 — Three-layer config overlay

- **Acceptance**
  - `EffectiveConfig` struct exposes the merged view with per-field
    `source: ConfigSource` annotation (`env` / `db` / `toml` /
    `default`) and `requires_restart: bool`
  - `config` keyspace stores DB-layer overrides as `key → ConfigValue`
  - Existing `config.rs` shapes adapted (additive) so existing tests
    keep passing
- **Verify**
  - Layer-precedence tests: env beats db beats toml beats default
  - Unknown key in TOML logs a warning, doesn't fail
- **Files**
  - `vtc-service/src/config.rs`
  - `vtc-service/src/config_store.rs` (new)
- **Deps**: M0.1.0

### `[x]` M0.8.2 — `GET / PATCH /v1/admin/config`

- **Acceptance**
  - `GET` returns `EffectiveConfig`
  - `PATCH` writes to DB layer; refuses sensitive-path values outside
    the directory allowlist (per spec §14.2)
  - Returns `{ applied, pending_restart, rejected }` per spec
  - Emits `ConfigChanged` audit event with sensitivity-flag-aware
    redaction
  - Trust Task IDs: `admin/config/{show,patch}/1.0`
- **Verify**
  - Integration tests cover allowlist enforcement, sensitive-key
    redaction in the audit log
- **Files**
  - `vtc-service/src/routes/admin/config.rs` (new)
  - `trust-tasks/admin/config/show/1.0/{spec.md,schema.json}`
  - `trust-tasks/admin/config/patch/1.0/{spec.md,schema.json}`
- **Deps**: M0.8.1, M0.6.2

### `[ ]` M0.8.3 — Reload + restart endpoints with supervisor handshake

- **Acceptance**
  - `POST /v1/admin/config/reload` reapplies hot-reloadable settings
  - `POST /v1/admin/config/restart` initiates graceful shutdown
    only if **one of**: `VTC_SUPERVISED=1` env var OR `NOTIFY_SOCKET`
    present OR a k8s downward-API marker is detected; otherwise
    returns 412 `SupervisorRequired`
  - Both endpoints emit audit events (`ConfigReloaded` /
    `RestartRequested`)
  - Trust Task IDs: `admin/config/{reload,restart}/1.0`
- **Verify**
  - Test without supervisor env: restart returns 412
  - Test with `VTC_SUPERVISED=1`: graceful shutdown completes within
    `restart.drain_timeout` (default 30 s); audit event recorded
    before exit
- **Files**
  - `vtc-service/src/routes/admin/config.rs`
  - `vtc-service/src/supervisor.rs` (new)
  - `trust-tasks/admin/config/reload/1.0/{spec.md,schema.json}`
  - `trust-tasks/admin/config/restart/1.0/{spec.md,schema.json}`
- **Deps**: M0.8.2

### `[ ]` M0.8.4 — Config export / import (diff-and-confirm)

- **Acceptance**
  - `POST /v1/admin/config/export` returns plain JSON of community
    profile + DB-layer config (no TOML / env values)
  - `POST /v1/admin/config/import` runs diff-and-confirm:
    `?confirm=false` (default) returns the diff; `?confirm=true`
    applies; per-field audit events emitted on apply
  - Refuses if `community_did` mismatch
  - Trust Task IDs: `admin/config/{export,import}/1.0`
- **Verify**
  - Round-trip test: export → fresh VTC → import → equivalence
  - Mismatched community_did → 409
  - Diff response shape stable
- **Files**
  - `vtc-service/src/routes/admin/config.rs`
  - `trust-tasks/admin/config/export/1.0/{spec.md,schema.json}`
  - `trust-tasks/admin/config/import/1.0/{spec.md,schema.json}`
- **Deps**: M0.8.3

---

## M0.9 — CLI setup wizard rewrite

### `[ ]` M0.9.1 — Map `vta-service` setup shape onto VTC needs

Per **D5**: `vta-service` is the latest working reference;
`vtc-service`'s existing code is throw-away. This task is **research,
not code** — produces a markdown findings doc that drives M0.9.2.

- **Acceptance**
  - Read `vta-service/src/main.rs`, `vta-service/src/setup/*`, the
    seed-store wiring, the `provision-integration` client path
  - Identify helpers genuinely shared between VTA setup and VTC
    setup (likely candidates: seed generation, secret-backend
    selection, keyspace bootstrap, `vta-sdk` client construction)
  - Decide for each: keep in `vta-service` and call cross-crate
    (no), promote to `vti-common` (yes for genuinely shared), or
    reimplement thin in `vtc-service` (yes for VTC-specific).
  - Output: `tasks/vtc-mvp/setup-mapping.md` with a 3-column table
    `(vta-service helper, decision, target location)` and a sketch
    of the new `vtc setup` wizard's call graph
- **Verify** the doc exists and the call graph is unambiguous
  enough that M0.9.2 can be implemented from it
- **Files**
  - `tasks/vtc-mvp/setup-mapping.md` (new, ~1 page)
- **Deps**: none — research task; can start at day one in parallel
  with M0.1
- **Pre-impl decision**: D5

### `[ ]` M0.9.2 — New minimal `vtc setup` wizard

- **Acceptance**
  - Three questions: VTC URL, admin UX URL, VTA URL
  - Mints seed via `affinidi-secrets-resolver` (default keyring)
  - Calls VTA's `POST /provision-integration` with `vtc-host` template
    using the existing `vta-sdk` client; opens sealed bundle locally
  - Initialises all Phase-0 keyspaces (sessions, acl, install,
    audit, audit_key, idempotency, community, config)
  - Mints install token via `install::token::mint_install_token()`
  - Prints install URL and starts the daemon
- **Verify**
  - End-to-end test against a running VTA fixture (likely a Docker
    Compose service in CI, or skipped with `#[ignore]` locally)
  - Idempotent: re-running `vtc setup` on an already-set-up daemon
    is refused with a clear error
- **Files**
  - `vtc-service/src/setup/wizard.rs` (new)
  - `vtc-service/src/main.rs` (wire the new wizard)
- **Deps**: M0.2.1, M0.4.2, M0.9.1, M0.6.1, M0.7.1, M0.8.1

### `[ ]` M0.9.3 — Retire entire legacy `vtc-service` install/setup surface

Per **D5**: the existing `vtc-service` predates the spec and is
throw-away. The new install path arrives in M0.9.2; M0.9.3 deletes
everything the new path replaces.

- **Acceptance**
  - Delete `vtc-service/src/setup.rs` (legacy)
  - Delete `vtc-service/src/did_webvh.rs` if replaced by
    `vta-sdk::did_templates::builtin::vtc-host` consumption
  - Delete `vtc-service/src/import_did.rs` (legacy cold-start path
    not in the new spec)
  - Delete `vtc-service/src/acl_cli.rs` (CLI-side ACL CRUD that
    predates the install flow; replaced by web UX in Phase 0+)
  - Delete any other module M0.9.1's mapping doc identifies as
    superseded
  - All references in `main.rs` / `lib.rs` updated
  - `cargo build` + `cargo clippy --workspace -- -D warnings` clean
- **Verify** workspace builds; no dead-code warnings
- **Files**
  - `vtc-service/src/setup.rs` (delete)
  - `vtc-service/src/did_webvh.rs` (delete if superseded)
  - `vtc-service/src/import_did.rs` (delete)
  - `vtc-service/src/acl_cli.rs` (delete)
  - `vtc-service/src/lib.rs`
  - `vtc-service/src/main.rs`
- **Deps**: M0.9.2

---

## M0.10 — Emergency bootstrap

### `[ ]` M0.10.1 — `vtc admin emergency-bootstrap` subcommand

- **Acceptance**
  - CLI subcommand runs only when the daemon is stopped (file-lock
    check on the fjall directory)
  - Prompts for the 24-word BIP-39 mnemonic; verifies it derives
    the same VTC master seed as the stored seed
  - On success: opens a fresh install token via the same
    `mint_install_token()` path, reopens the install carve-out
    keyspace marker, prints the install URL
  - Persists a `pending_emergency_bootstrap_at: DateTime<Utc>`
    marker that the daemon reads on next boot and emits the
    `EmergencyBootstrapInvoked` audit event
  - Trust Task ID: none (CLI-only, not a wire op)
- **Verify**
  - Wrong mnemonic → command refuses without changing state
  - Correct mnemonic → install URL printed; daemon on next boot
    emits the loud audit event
- **Files**
  - `vtc-service/src/setup/emergency.rs` (new)
  - `vtc-service/src/main.rs` (subcommand wiring)
- **Deps**: M0.4.2, M0.9.2

---

## M0.11 — Routing + CORS + cookie-scope

### `[ ]` M0.11.1 — Routing config + mount logic

- **Acceptance**
  - `RoutingConfig` per spec §9.2 supports `mount` + optional `host`
    per surface (api, admin_ui, website — website mount accepted in
    config but routes 404 until Phase 5)
  - Path-prefix default: `/v1`, `/admin`, `/` (catch-all)
  - Subdomain mode supported by `Host`-header middleware (codified
    but not exercised by Phase-0 tests)
  - Mount conflicts at config-load time produce a clear startup
    error
- **Verify**
  - Path-prefix routing test: `/v1/community/profile` resolves;
    `/admin/some/path` returns 404 (since admin UX not bundled yet)
  - Subdomain config parses but does not break path-prefix tests
- **Files**
  - `vtc-service/src/config.rs` (add `RoutingConfig`)
  - `vtc-service/src/routes/mod.rs`
- **Deps**: M0.3.2

### `[ ]` M0.11.2 — CORS + cookie-scope invariants

- **Acceptance**
  - `cors.allowed_origins` allowlist; wildcards refused at config-load
  - Admin session cookie set with `Path=/admin; SameSite=Strict;
    Secure; HttpOnly` in path mode
  - Public-website origin auto-allow disabled (no public website yet)
  - Config-load-time invariant: refuses to start if cookie scopes
    would overlap (e.g., admin mounted at `/` is rejected)
- **Verify**
  - Bad-config startup tests fail loud
  - CORS preflight test includes `Idempotency-Key`,
    `Trust-Task` in `Access-Control-Allow-Headers`
- **Files**
  - `vtc-service/src/config.rs`
  - `vtc-service/src/server.rs`
- **Deps**: M0.11.1

---

## M0.12 — Install-flow integration tests + Phase 0 gate

### `[ ]` M0.12.1 — End-to-end install integration test

- **Acceptance**
  - Single integration test exercises:
    1. `vtc setup` mints seed + install token (test harness shortcut
       — provisioning against a fake VTA is acceptable)
    2. `POST /v1/install/claim` succeeds with mocked WebAuthn
    3. `POST /v1/admin/bootstrap` succeeds
    4. `POST /v1/admin/passkeys/register` adds a second passkey
    5. `GET /v1/admin/passkeys` returns both
    6. `GET /v1/community/profile` returns the configured profile
    7. `PATCH /v1/admin/config` updates a setting
    8. `POST /v1/admin/config/restart` refuses without supervisor
    9. Second `POST /v1/install/claim` fails (carve-out closed)
- **Verify** test green
- **Files**
  - `vtc-service/tests/install_flow.rs` (new)
- **Deps**: M0.6.3, M0.7.2, M0.8.3, M0.11.2

### `[ ]` M0.12.2 — Emergency bootstrap integration test

- **Acceptance**
  - Test exercises the full recovery path:
    1. Set up a VTC + bootstrap admin
    2. Simulate "all passkeys lost" by removing them
    3. Stop daemon, run `vtc admin emergency-bootstrap` with the
       correct mnemonic
    4. Restart daemon; confirm `EmergencyBootstrapInvoked` in audit
    5. Re-claim install + bootstrap with a new admin
- **Verify** test green
- **Files**
  - `vtc-service/tests/emergency_bootstrap.rs` (new)
- **Deps**: M0.10.1, M0.12.1

### `[ ]` M0.12.3 — Workspace gate green

- **Acceptance**
  - `cargo build --workspace` green
  - `cargo test --workspace` green
  - `cargo clippy --workspace -- -D warnings` clean
  - `cargo fmt --check` clean
  - `trust-tasks/index.json` lists every Phase-0 Trust Task in
    `Draft` status with corresponding `spec.md` + `schema.json` on
    disk
  - Memory entry `project_vtc_mvp.md` updated with any tweaks
    discovered during implementation
- **Verify** CI green on the merge commit
- **Files**
  - `trust-tasks/index.json`
  - `/Users/glenngore/.claude/projects/-Users-glenngore-devel-fpp-verifiable-trust-infrastructure/memory/project_vtc_mvp.md`
- **Deps**: M0.12.1, M0.12.2

### Checkpoint E — Phase 0 gate met
After M0.12.1–M0.12.3: full install flow runs through
`Router::oneshot`, including emergency-bootstrap recovery; community
profile and config endpoints work; routing + cookie-scope + CORS
invariants enforced; all Phase-0 endpoints have Draft Trust Task
spec files on disk. Phase 1 can start.

---

## Open questions surfaced during planning

These are not blockers — they have proposed defaults in `plan.md`
under "Pre-implementation design decisions". Listed here so they're
findable from the todo:

- D1 (Trust Task schema format), D2 (nonce binding), D3 (audit_key
  storage), D4 (extensions size limit), D5 (setup.rs strategy),
  D6 (destructive op identification), D7 (RP ID derivation), D8
  (Trust-Task header name), D9 (builder vs macros).

Any decision that drifts from the default during implementation
should be recorded in `plan.md` under a "Phase 0 outcome" header
(mirroring the prior DIDComm plan's pattern).
