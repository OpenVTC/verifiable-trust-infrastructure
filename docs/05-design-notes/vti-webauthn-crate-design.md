# `vti-webauthn` — crate design

**Status:** **implemented** — the `vti-webauthn` crate (published). This was the
Phase 1 design-lock for the trust-task envelope migration initiative.
**Date:** 2026-05-20.
**Crate location:** new workspace member `vti-webauthn/` at the root of
`verifiable-trust-infrastructure`. Leaf crate (no internal VTI deps),
publishable to crates.io.

## Purpose

Verify WebAuthn (FIDO2) assertions where the credential's public key is
resolved from a **DID Document `verificationMethod`**, not from a
server-side credential store. Produced as the implementation of "Path B"
in the trust-task migration initiative (hand-rolled WebAuthn verification
using `p256` rather than coercing webauthn-rs).

Primary consumers:

- `vta-service` for `vta/auth/passkey-login-{start,finish}/1.0` handlers.
- `affinidi-webvh-service` (cross-workspace via crates.io) when it adopts
  the DID-VM-resolved login model alongside its existing service-store
  passkey flow.

## Scope boundaries

**In scope:**

- Parse and validate `clientDataJSON` and `authenticatorData`.
- ECDSA P-256 signature verification (v0.1).
- Mapping a DID-Document `Multikey` VM to a public key the verifier can
  use.
- Document-binding helper: compute the canonical-doc-hash that callers
  pass into `navigator.credentials.get()` and check on receipt.
- A typed result that exposes the security-relevant flags
  (`user_present`, `user_verified`, `sign_count`) so callers can apply
  their own policy.

**Out of scope:**

- DID resolution itself. The caller supplies a resolver (trait seam).
- Replay defence at the server-issued-nonce level. The caller manages its
  own nonce store / session state.
- Counter persistence. The crate reports `sign_count`; callers decide
  what to do with it.
- Trust-task envelope semantics. The crate operates on plain
  `AssertionPayload` bytes; callers wrap/unwrap their envelope.
- Browser-side prover code. (TypeScript/WASM concern — the prover is
  `navigator.credentials.get()` directly.)
- Enrolment / registration ceremony. Enrolment runs through
  `vta/passkey-vms/enroll-{challenge,submit}/1.0` (already shipped) and
  persists VMs to the DID document; this crate only deals with
  *assertion* (login) verification.

## Public API sketch

```rust
//! vti-webauthn — DID-VM-resolved WebAuthn assertion verification.

use async_trait::async_trait;

// ─── Configuration ──────────────────────────────────────────────────────

pub struct VerifierConfig {
    /// Relying-Party ID expected in authenticatorData.rpIdHash. Bare
    /// hostname only — no scheme, no port, no path.
    /// Example: "control.example.com".
    pub rp_id: String,

    /// Origin expected in clientData.origin. Includes scheme; default
    /// port stripped (443 for https). Case-normalised to lowercase host.
    /// Example: "https://control.example.com".
    pub expected_origin: String,

    /// If true, the UV (user-verified) flag MUST be set on the assertion.
    /// If false, UV is informational only.
    pub require_user_verification: bool,
}

impl VerifierConfig {
    /// Construct from a public URL. Strips scheme, port (if default),
    /// trailing slash; lowercases host. Errors on malformed input.
    pub fn from_public_url(public_url: &str, require_uv: bool) -> Result<Self, ConfigError>;
}

// ─── Resolver seam ──────────────────────────────────────────────────────

#[async_trait]
pub trait VmResolver: Send + Sync {
    /// Resolve a verificationMethod URL (e.g.
    /// "did:webvh:vta.example.com:alice#passkey-abc") to the
    /// resolved key material plus the controller DID. The crate
    /// performs no caching; the resolver implementation owns that.
    async fn resolve_vm(&self, vm_url: &str) -> Result<ResolvedVm, ResolverError>;
}

pub struct ResolvedVm {
    /// Detected from the multikey multicodec prefix.
    pub algorithm: VerificationAlgorithm,
    /// Raw public-key bytes (multicodec prefix stripped).
    /// - P-256: 33 bytes compressed form.
    pub public_key_bytes: Vec<u8>,
    /// The VM's controller DID, used to verify it matches the claimed
    /// holder of the trust-task envelope.
    pub controller: String,
}

pub enum VerificationAlgorithm {
    /// multicodec 0x1200
    P256,
    // Ed25519 (multicodec 0xed01) — v0.2
}

#[non_exhaustive]
pub enum ResolverError {
    NotFound,
    /// DID document did not resolve, or VM not present in it.
    UnresolvableDid(String),
    /// VM was present but encoded incorrectly.
    MalformedVm(String),
    /// Anything else the resolver wants to surface (transport, etc.).
    Other(String),
}

// ─── Input + result ─────────────────────────────────────────────────────

/// The WebAuthn assertion as it arrives — caller has already pulled
/// these bytes from the trust-task payload.
pub struct AssertionPayload {
    pub credential_id: Vec<u8>,
    pub authenticator_data: Vec<u8>,
    pub client_data_json: Vec<u8>,
    pub signature: Vec<u8>,
    /// The VM URL the caller claims this assertion was produced against.
    pub verification_method: String,
}

/// What `verify_assertion` returns on success. The caller decides what
/// to do with it (issue a JWT, run an op, etc.).
#[derive(Debug, Clone)]
pub struct VerifiedAssertion {
    /// The DID portion of `verification_method`.
    pub did: String,
    pub verification_method: String,
    pub user_present: bool,
    pub user_verified: bool,
    /// Reported by the authenticator. 0 from synced passkeys; strictly
    /// monotonic from hardware authenticators. Caller persists if it
    /// wants counter regression detection.
    pub sign_count: u32,
    pub algorithm: VerificationAlgorithm,
}

// ─── Verification ───────────────────────────────────────────────────────

/// Verify a WebAuthn assertion against a DID-resolved VM.
///
/// `expected_challenge` is the bytes the caller expects `clientData.
/// challenge` to equal (base64url-decoded). For trust-task-bound
/// assertions, derive it via [`document_binding_challenge`]. For
/// server-issued-nonce flows, pass the nonce bytes directly.
pub async fn verify_assertion(
    payload: &AssertionPayload,
    expected_challenge: &[u8],
    resolver: &dyn VmResolver,
    config: &VerifierConfig,
) -> Result<VerifiedAssertion, VerifyError>;

// ─── Document binding helper ────────────────────────────────────────────

/// Compute the canonical-doc challenge for a trust-task that carries an
/// AssertionPayload at a known JSON pointer in its payload. The helper:
///
/// 1. Clones the trust-task body.
/// 2. Sets the assertion's `signature`, `authenticatorData`, and
///    `clientDataJSON` fields to `null` (so the challenge isn't a
///    chicken-and-egg over itself).
/// 3. Canonicalises the result via JCS (RFC 8785).
/// 4. Returns SHA-256 of the canonical bytes.
///
/// Same routine on both prover and verifier — prover passes the result
/// as the `challenge` argument to `navigator.credentials.get()`;
/// verifier passes it as `expected_challenge`.
pub fn document_binding_challenge(
    trust_task_body: &serde_json::Value,
    assertion_pointer: &str,
) -> Result<[u8; 32], BindingError>;

// ─── Errors ─────────────────────────────────────────────────────────────

#[non_exhaustive]
pub enum VerifyError {
    MalformedAssertion(&'static str),
    VmResolution(ResolverError),
    UnsupportedAlgorithm,
    WrongClientDataType,
    WrongOrigin,
    ChallengeMismatch,
    WrongRpId,
    UserPresenceMissing,
    UserVerificationMissing,
    SignatureInvalid,
    /// `verification_method`'s DID and the resolved VM's controller
    /// disagree. Should be impossible if the resolver is correct;
    /// surfaced for defence in depth.
    ControllerMismatch { expected: String, found: String },
}

pub enum BindingError {
    AssertionPointerMissing(String),
    Canonicalisation(String),
}

pub enum ConfigError {
    InvalidUrl(String),
    NoHostInUrl,
}
```

## Verification algorithm

Implements the rules from the superseded
`webauthn-vti-v1-cryptosuite.md` §Verification, minus the
Data-Integrity-proof framing. Concretely, inside `verify_assertion`:

1. Resolve `payload.verification_method` via the resolver. Extract algorithm + public key.
2. Confirm `payload.verification_method`'s DID portion matches the resolver's reported controller.
3. Parse `client_data_json` as UTF-8 JSON.
   - `type` == `"webauthn.get"` → else `WrongClientDataType`.
   - `origin` == config's `expected_origin` (lowercased, default port stripped) → else `WrongOrigin`.
   - `challenge` (base64url-decoded) == `expected_challenge` → else `ChallengeMismatch`.
4. Parse `authenticator_data` (≥ 37 bytes).
   - `rpIdHash` (bytes 0-31) == `SHA-256(config.rp_id)` → else `WrongRpId`.
   - Flags byte (byte 32): UP bit set → else `UserPresenceMissing`; UV bit (if `require_user_verification`) → else `UserVerificationMissing`.
   - `signCount` (bytes 33-36, big-endian u32) → into the result.
5. Build the message: `authenticator_data ‖ SHA-256(client_data_json)`.
6. Verify signature against the resolved public key using `p256::ecdsa::VerifyingKey` (DER-encoded signature, fixed-form supported as fallback).
7. Return `VerifiedAssertion`.

## Crate skeleton

```
vti-webauthn/
├── Cargo.toml
├── README.md
└── src/
    ├── lib.rs                — re-exports, module docs
    ├── config.rs             — VerifierConfig, ConfigError
    ├── resolver.rs           — VmResolver, ResolvedVm, ResolverError, VerificationAlgorithm
    ├── payload.rs            — AssertionPayload, VerifiedAssertion
    ├── verify.rs             — verify_assertion + helpers
    ├── client_data.rs        — clientDataJSON parsing + validation
    ├── auth_data.rs          — authenticatorData parsing + validation
    ├── multikey.rs           — multicodec → algorithm decode, multibase strip
    ├── document_binding.rs   — document_binding_challenge + BindingError
    └── error.rs              — VerifyError
└── tests/
    ├── fixtures/             — JSON test vectors (real assertions captured offline)
    │   ├── valid_p256.json
    │   ├── wrong_origin.json
    │   ├── wrong_rp_id.json
    │   ├── challenge_mismatch.json
    │   ├── mutated_signature.json
    │   ├── up_missing.json
    │   ├── uv_missing.json
    │   └── ...
    └── verify_assertion.rs   — fixture-driven integration tests
```

## Dependencies (`Cargo.toml` sketch)

```toml
[package]
name = "vti-webauthn"
version = "0.1.0"
edition = "2024"
rust-version = "1.94.0"
license = "Apache-2.0"
description = "DID-VM-resolved WebAuthn assertion verifier for Verifiable Trust Infrastructure"
repository = "https://github.com/openvtc/verifiable-trust-infrastructure"
publish = true

[dependencies]
async-trait = "0.1"
aws-lc-rs = "1.13"             # ECDSA verification (FIPS-validated, workspace policy)
base64 = "0.22"                # base64url for clientData
multibase = "0.9"              # base58btc decode for Multikey
serde = { version = "1", features = ["derive"] }
serde_json = "1"
serde_json_canonicalizer = "0.3"  # RFC 8785 (active maintainer; RFC author)
sha2 = "0.10"
thiserror = "1"
unsigned-varint = "0.8"        # multicodec varint prefix decode

[dev-dependencies]
tokio = { version = "1", features = ["macros", "rt"] }
```

Crypto deps follow the workspace convention (CLAUDE.md): pin minimum
patch to avoid silent regression when a CVE lands. `aws-lc-rs` and
`sha2` are the crypto-pinned deps in this crate.

## v0.1 ↔ v0.2 scope cut

**v0.1 (this initiative):**

- P-256 / ES256 verification.
- `VerifierConfig`, `VmResolver`, `AssertionPayload`, `VerifiedAssertion`, `VerifyError`.
- `verify_assertion` async function.
- `document_binding_challenge` helper.
- Test vectors for valid + every negative path.
- No replay-cache integration.
- No counter-persistence built-in (caller exposed to `sign_count` via the result).

**v0.2 (later, not in this initiative):**

- Ed25519 support (multicodec 0xed01) behind `ed25519` feature flag.
- Optional `CounterStore` trait + automatic counter-regression check
  built into `verify_assertion`.
- A higher-level `verify_trust_task_assertion` that takes a serialised
  trust-task body and the JSON pointer to the assertion, internalising
  the canonicalisation + binding-challenge derivation.
- Telemetry hooks (a `Telemetry` trait the caller can plug in to count
  refusals by reason).

The v0.2 path stays open by keeping `VerifyError` `#[non_exhaustive]`
and exposing `VerificationAlgorithm` as a non-exhaustive enum.

## Test strategy

- **Fixtures captured offline.** A one-time recording script in the
  workspace uses Chrome DevTools / Playwright to enrol a passkey and
  produce a real assertion against a known DID + challenge, then writes
  the canned `AssertionPayload` + expected resolver output to a JSON
  file. Fixtures live in the crate's `tests/fixtures/`.
- **Negative-mutation tests** generate variants of `valid_p256.json` by
  programmatically flipping bytes / changing fields, asserting each
  produces the right `VerifyError` variant.
- **Test resolver** (`tests/common/mod.rs`) is a hardcoded `HashMap<String, ResolvedVm>` — no DID resolution machinery needed for unit tests.
- **No browser in CI.** Fixtures are static; the recording script runs
  once when adding/refreshing fixtures.
- **Cross-crate parity.** When the plugin's TypeScript prover ships
  (Phase 2), an integration test in the plugin's CI exercises the
  prover→fixture pipeline against the Rust verifier via a shared JSON
  fixture set.

## How callers wire it up

**VTA-service shape (`vta/auth/passkey-login-finish/1.0` handler):**

```rust
// In vta-service/src/operations/auth/passkey_login.rs:

async fn handle_passkey_login_finish(
    state: &AppState,
    payload: PasskeyLoginFinishPayload,
) -> Result<AuthenticateResponse, AppError> {
    // 1. Look up the pending challenge for this session.
    let session = sessions::get_pending(&state.sessions_ks, &payload.session_id).await?;

    // 2. Build the AssertionPayload from the trust-task fields.
    let assertion = vti_webauthn::AssertionPayload {
        credential_id: payload.credential_id,
        authenticator_data: payload.authenticator_data,
        client_data_json: payload.client_data_json,
        signature: payload.signature,
        verification_method: format!("{}#{}", session.did, payload.credential_fragment),
    };

    // 3. Verify against the DID-resolved VM.
    let verified = vti_webauthn::verify_assertion(
        &assertion,
        &session.challenge_bytes,        // server-issued nonce (replay defence)
        state.vm_resolver.as_ref(),       // implements VmResolver
        &state.webauthn_config,
    )
    .await
    .map_err(map_webauthn_error)?;

    // 4. Issue JWT, finalise session, etc. Steady-state webvh-service code.
    session::finalize_challenge_session(...).await
}
```

The VTA's `VmResolver` impl wraps its existing DID resolver. Same shape
on webvh-service when it adopts this model.

## Resolved decisions (2026-05-20)

1. **Default-port stripping in `expected_origin`** — strip `:443` for https and `:80` for http **only**. Any other port stays in the comparison string. Security-clarity rule: the origin a real browser produces is normalised this way too, so anything else is a misconfiguration.
2. **ECDSA backend** — `aws-lc-rs`. Matches workspace crypto policy (CLAUDE.md), FIPS-validated, no second ECDSA implementation in the dependency tree. Drops `p256` from the Cargo.toml sketch.
3. **JCS library** — `serde_json_canonicalizer` (v0.3.2+). Author is Anders Rundgren (RFC 8785 chair); actively maintained; already in the workspace's transitive dep graph via `affinidi-data-integrity`, so no new transitive bloat. `serde_jcs` (v0.1.0, last touched 2022) explicitly rejected.
4. **Error type** — `thiserror` derive, consistent with the rest of the workspace.

## Next steps after design lock

1. **Resolve open questions 1–3** (15-min decisions each).
2. **Create the crate skeleton** — Cargo.toml + empty modules + lib.rs.
3. **Implement v0.1** — verify.rs is the hard one; everything else is data shuffling.
4. **Capture fixtures** — one-time recording session, ~10 negative variants.
5. **Wire it into vta-service** as `vta/auth/passkey-login-finish/1.0` handler.

Estimated calendar: skeleton + impl + fixtures = ~5 working days for one
engineer. Wiring into vta-service is its own task (~3 days, depends on
the trust-task dispatcher landing).
