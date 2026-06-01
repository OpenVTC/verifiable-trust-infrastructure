//! `POST /bootstrap/request` — TEE first-boot sealed-bootstrap endpoint.
//!
//! This endpoint only handles **Mode B**: a fresh TEE VTA that has no admin
//! yet. The server generates an attestation quote committing to the client
//! pubkey, nonce, and its own ephemeral producer pubkey, mints an Admin
//! credential, and closes the first-boot carve-out permanently. The bundle's
//! assertion is `Attested(quote)` so the consumer can verify end-to-end
//! without any prior shared secret.
//!
//! The former Mode A (token-gated online bootstrap for non-TEE VTAs) was
//! removed: non-TEE clients now use `pnm setup`'s unified temp-did:key
//! flow (client mints locally, admin grants via `vta acl create`, PNM
//! rotates on first authenticated connect).

use axum::Json;
use axum::extract::State;
use axum::response::IntoResponse;
#[cfg(feature = "tee")]
use base64::Engine;
#[cfg(feature = "tee")]
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use serde::{Deserialize, Serialize};

#[cfg(feature = "tee")]
use sha2::{Digest, Sha256};
#[cfg(feature = "tee")]
use tracing::info;
#[cfg(feature = "tee")]
use vta_sdk::credentials::CredentialBundle;
#[cfg(feature = "tee")]
use vta_sdk::sealed_transfer::{
    AssertionProof, AttestationQuoteAssertion, ProducerAssertion, SealedPayloadV1, armor,
    bundle_digest, generate_ed25519_keypair, seal_payload,
};

#[cfg(feature = "tee")]
use crate::acl::store_acl_entry;
#[cfg(feature = "tee")]
use crate::acl::{AclEntry, Role};
#[cfg(feature = "tee")]
use crate::audit::audit;
use crate::auth::session::now_epoch;
use crate::error::AppError;
#[cfg(feature = "tee")]
use crate::sealed_nonce_store::PersistentNonceStore;
use crate::server::AppState;

/// Maximum length (in bytes) of the operator-supplied bootstrap label.
/// The wire body is already capped globally, but the label is the only
/// free-form attacker-controlled string in this DTO and ends up in audit
/// logs — keep it short so an aggressive logger can't spill MBs.
const MAX_LABEL_LEN: usize = 256;

/// Request body. `#[serde(deny_unknown_fields)]` so a client cannot smuggle
/// in `requested_role` / `allowed_contexts` — minting parameters are
/// determined entirely by attestation policy.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootstrapRequestBody {
    /// Wire-format version. Currently 1.
    pub version: u8,
    /// Consumer's ephemeral `did:key` (Ed25519). The server derives the
    /// X25519 pubkey from this for the HPKE seal.
    pub client_did: String,
    /// Random 16-byte nonce, base64url-no-pad. Becomes the bundle_id.
    pub nonce: String,
    /// Optional human-readable label (operator-visible only). Echoed into
    /// server-side audit logs. Wire field stays present on non-TEE builds so
    /// older clients keep deserializing; the value is only consumed by the
    /// TEE first-boot path. Bounded length protects audit log size from a
    /// hostile caller submitting an MB-scale string.
    #[serde(default, deserialize_with = "deserialize_bounded_label")]
    #[cfg_attr(not(feature = "tee"), allow(dead_code))]
    pub label: Option<String>,
}

fn deserialize_bounded_label<'de, D>(de: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s: Option<String> = Option::deserialize(de)?;
    if let Some(label) = &s
        && label.len() > MAX_LABEL_LEN
    {
        return Err(serde::de::Error::custom(format!(
            "label exceeds {MAX_LABEL_LEN} bytes"
        )));
    }
    Ok(s)
}

/// Response body — a single armored sealed bundle as UTF-8 text, plus the
/// canonical SHA-256 digest so clients can optionally anchor on it.
#[derive(Debug, Serialize)]
pub struct BootstrapResponseBody {
    pub bundle: String,
    pub digest: String,
}

/// `POST /bootstrap/request`
pub async fn request(
    State(state): State<AppState>,
    Json(req): Json<BootstrapRequestBody>,
) -> Result<Json<BootstrapResponseBody>, AppError> {
    if req.version != 1 {
        return Err(AppError::Validation(format!(
            "unsupported bootstrap request version: {}",
            req.version
        )));
    }

    let client_ed25519_pub = decode_client_did(&req.client_did)?;
    let bundle_id = decode_nonce(&req.nonce)?;
    let now = now_epoch();

    #[cfg(feature = "tee")]
    let bundle = mint_mode_b(&state, &client_ed25519_pub, bundle_id, now).await?;

    #[cfg(not(feature = "tee"))]
    {
        let _ = (state, client_ed25519_pub, bundle_id, now);
        Err(AppError::Forbidden(
            "bootstrap request requires TEE first-boot attestation, which is not available on \
             this VTA build. Non-TEE VTAs use the `pnm setup` temp-did:key + ACL flow instead."
                .into(),
        ))
    }

    #[cfg(feature = "tee")]
    {
        let digest = bundle_digest(&bundle);
        let armored = armor::encode(&bundle);

        // Log a SHA-256 prefix of the operator-supplied label rather than
        // the raw string. Labels are free-form and often carry PII
        // ("glenn's iphone", "alice@example.com") — a hash preserves
        // "same label → same identifier" for operational correlation
        // without leaking the plaintext into log aggregators.
        info!(
            client_label_hash = %label_hash_prefix(req.label.as_deref()),
            "TEE first-boot bootstrap completed"
        );
        audit!(
            "bootstrap.swap",
            actor = "bootstrap-endpoint",
            resource = "bootstrap",
            outcome = "success"
        );
        let _ = crate::audit::record(
            &state.audit_ks,
            "bootstrap.swap",
            "bootstrap-endpoint",
            None,
            "success",
            Some("rest"),
            None,
        )
        .await;

        Ok(Json(BootstrapResponseBody {
            bundle: armored,
            digest,
        }))
    }
}

/// Process-wide lock that serializes the carve-out check-and-set. The
/// keyspace exposes no compare-and-swap, so two concurrent requests can
/// each pass the `is_some()` check, mint admins, and write distinct ACL
/// rows before either writes the closed-sentinel. A `tokio::sync::Mutex`
/// held across the whole sequence collapses that window — the second
/// request waits, then sees the sentinel and is refused. The mint flow
/// is single-use and rare, so contention is irrelevant.
#[cfg(feature = "tee")]
static MODE_B_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Mode B: TEE first-boot sealed bootstrap. No token; the attestation quote
/// is the sole authorization anchor.
///
/// On success, closes the first-boot carve-out permanently by writing the
/// `BOOTSTRAP_CARVEOUT_CLOSED_KEY` sentinel. Any subsequent request is
/// rejected.
#[cfg(feature = "tee")]
async fn mint_mode_b(
    state: &AppState,
    client_ed25519_pub: &[u8; 32],
    bundle_id: [u8; 16],
    now: u64,
) -> Result<vta_sdk::sealed_transfer::SealedBundle, AppError> {
    use crate::tee::admin_bootstrap::{BOOTSTRAP_CARVEOUT_CLOSED_KEY, LEGACY_ADMIN_CREDENTIAL_KEY};

    let tee_state =
        state.tee.as_ref().map(|tc| &tc.state).ok_or_else(|| {
            AppError::Forbidden("TEE first-boot is not available on this VTA".into())
        })?;

    // Serialize the carve-out check-and-set across all concurrent requests.
    // The lock is released when this function returns, by which point the
    // sentinel has been written (success path) or nothing has been written
    // (early-error path), so subsequent requests see a consistent view.
    let _carve_out_guard = MODE_B_LOCK.lock().await;

    // Carve-out active ⇔ neither the closed-sentinel nor the legacy
    // admin-credential row is present. (The latter is a transitional case —
    // startup migration rewrites it into the closed-sentinel before this
    // handler ever runs, but we check here too to keep the handler correct
    // even without startup migration.)
    if state
        .keys_ks
        .get_raw(BOOTSTRAP_CARVEOUT_CLOSED_KEY)
        .await?
        .is_some()
        || state
            .keys_ks
            .get_raw(LEGACY_ADMIN_CREDENTIAL_KEY)
            .await?
            .is_some()
    {
        return Err(AppError::Forbidden(
            "TEE first-boot carve-out has already been used".into(),
        ));
    }

    let cfg = state.config.read().await;
    let vta_did = cfg
        .vta_did
        .as_ref()
        .ok_or_else(|| AppError::Internal("VTA DID not configured".into()))?
        .clone();
    let vta_url = cfg.public_url.clone();
    drop(cfg);

    // Per-request ephemeral producer Ed25519 keypair. The did:key bytes are
    // bound into the attestation `user_data` alongside the client's did:key
    // bytes + nonce so the consumer can recompute against DID-visible data.
    let (_producer_seed, producer_ed_pub) = generate_ed25519_keypair();
    let producer_did = affinidi_crypto::did_key::ed25519_pub_to_did_key(&producer_ed_pub);

    // Attestation user_data binds DID-layer bytes end-to-end:
    //   SHA256(client_ed25519 || bundle_id || producer_ed25519)
    // Both halves match what the consumer sees via the `client_did` it sent
    // and the `producer_did` in the returned `ProducerAssertion`.
    let mut hasher = Sha256::new();
    hasher.update(client_ed25519_pub);
    hasher.update(bundle_id);
    hasher.update(producer_ed_pub);
    let user_data = hasher.finalize();

    // Attestation nonce: reuse the client nonce for freshness.
    let report = tee_state
        .provider
        .attest(user_data.as_slice(), &bundle_id)
        .map_err(|e| AppError::Internal(format!("tee attest failed: {e}")))?;

    // Mint admin credential and insert ACL entry. Sentinel write goes
    // FIRST so that even if a future refactor breaks the `MODE_B_LOCK`
    // guard above, a concurrent request fails closed (the sentinel is
    // visible before any second admin row could be written). The
    // current `MODE_B_LOCK` ensures the check-and-set is already
    // serialized; this ordering is defence-in-depth.
    let (did, private_key_multibase) = crate::auth::credentials::generate_did_key();

    state
        .keys_ks
        .insert_raw(BOOTSTRAP_CARVEOUT_CLOSED_KEY, did.as_bytes().to_vec())
        .await?;

    let entry = AclEntry::new(did.clone(), Role::Admin, "tee:mode-b")
        .with_label(Some("TEE first-boot admin".to_string()))
        .with_created_at(now);
    store_acl_entry(&state.acl_ks, &entry).await?;

    let credential = CredentialBundle {
        did,
        private_key_multibase,
        vta_did,
        vta_url,
    };

    let assertion = ProducerAssertion {
        producer_did,
        proof: AssertionProof::Attested(AttestationQuoteAssertion {
            format: format!("{}", report.tee_type),
            quote_b64: report.evidence,
        }),
    };

    // HPKE targets the consumer's derived X25519 pubkey; the DID layer is
    // invisible to the cipher. Any decoding error here should be impossible
    // (the handler already validated `client_did`), so surface as 500.
    let client_x25519_pub =
        affinidi_crypto::did_key::ed25519_pub_to_x25519_bytes(client_ed25519_pub)
            .map_err(|e| AppError::Internal(format!("client_did X25519 derivation: {e}")))?;

    let nonce_store = PersistentNonceStore::new(state.sealed_nonces_ks.clone());
    let payload = SealedPayloadV1::AdminCredential(Box::new(credential));
    let bundle = seal_payload(
        &client_x25519_pub,
        bundle_id,
        assertion,
        &payload,
        &nonce_store,
    )
    .await
    .map_err(|e| AppError::Internal(format!("sealed-transfer seal failed: {e}")))?;
    info!("TEE first-boot carve-out consumed — closed for good");
    Ok(bundle)
}

/// Decode the consumer's `did:key` (Ed25519) to its raw 32-byte pubkey.
/// X25519 derivation happens inside `mint_mode_b` where HPKE is actually
/// invoked; the Ed25519 pubkey is separately bound into the attestation
/// `user_data` so the consumer can verify against did:key-visible bytes.
fn decode_client_did(did: &str) -> Result<[u8; 32], AppError> {
    affinidi_crypto::did_key::did_key_to_ed25519_pub(did)
        .map_err(|e| AppError::Validation(format!("invalid client_did: {e}")))
}

/// SHA-256 the operator-supplied label, return the first 16 hex chars
/// (64 bits — enough to tell distinct labels apart in practice). When
/// no label is supplied, return `"none"` so the log field is always
/// populated.
///
/// The point is to keep free-form strings (potentially carrying PII
/// like "alice@example.com" or a device name) out of the log
/// aggregator while preserving "same label → same hash" for operator
/// correlation across requests.
#[cfg(feature = "tee")]
fn label_hash_prefix(label: Option<&str>) -> String {
    match label {
        Some(s) => {
            let digest = Sha256::digest(s.as_bytes());
            let mut hex = String::with_capacity(16);
            for b in &digest[..8] {
                hex.push_str(&format!("{b:02x}"));
            }
            hex
        }
        None => "none".to_string(),
    }
}

#[cfg(feature = "tee")]
fn decode_nonce(s: &str) -> Result<[u8; 16], AppError> {
    let raw = B64URL
        .decode(s)
        .map_err(|e| AppError::Validation(format!("invalid nonce base64: {e}")))?;
    raw.try_into()
        .map_err(|_| AppError::Validation("nonce must be 16 bytes".into()))
}

#[cfg(not(feature = "tee"))]
fn decode_nonce(_s: &str) -> Result<[u8; 16], AppError> {
    // Non-TEE builds never reach the seal path; the handler returns Forbidden
    // before calling this. Keep a stub with the right signature so the
    // top-level handler compiles without ballooning the conditional code.
    Err(AppError::Forbidden(
        "bootstrap request requires TEE first-boot attestation".into(),
    ))
}

impl IntoResponse for BootstrapResponseBody {
    fn into_response(self) -> axum::response::Response {
        Json(self).into_response()
    }
}

#[cfg(all(test, feature = "tee"))]
mod tests {
    use super::*;

    #[test]
    fn label_hash_prefix_is_stable_and_truncated() {
        // Same label → same hash. Different labels → different hashes
        // (collision at 16 hex chars is 1-in-2^64, not worth guarding).
        // None → "none" so the log field is never empty.
        let a1 = label_hash_prefix(Some("alice@example.com"));
        let a2 = label_hash_prefix(Some("alice@example.com"));
        let b = label_hash_prefix(Some("bob@example.com"));
        assert_eq!(a1, a2, "same label produces same hash");
        assert_ne!(a1, b, "different labels produce different hashes");
        assert_eq!(a1.len(), 16, "prefix is 16 hex chars (64 bits)");
        assert!(
            a1.chars().all(|c| c.is_ascii_hexdigit()),
            "hash prefix is hex"
        );
        assert_eq!(label_hash_prefix(None), "none");
    }

    #[test]
    fn label_hash_prefix_does_not_leak_raw_label() {
        // Defence-in-depth: the returned string should not contain any
        // substring of the original label. A regression here would mean
        // the hash helper got replaced with an echo / truncation by
        // someone not thinking about PII.
        let raw = "glenn's iphone";
        let hashed = label_hash_prefix(Some(raw));
        for substr_len in 3..=raw.len() {
            for start in 0..=(raw.len() - substr_len) {
                let needle = &raw[start..start + substr_len];
                assert!(
                    !hashed.contains(needle),
                    "hashed output '{hashed}' must not contain raw substring '{needle}'"
                );
            }
        }
    }

    /// Concurrency contract for [`MODE_B_LOCK`].
    ///
    /// Property under test: when N concurrent `mint_mode_b`-style
    /// "lock-then-check-then-set" sequences race against the same
    /// keyspace, exactly one writes the carve-out sentinel; the others
    /// see the sentinel after acquiring the lock and refuse.
    ///
    /// This is the safety invariant CLAUDE.md highlights as load-bearing
    /// — two concurrent `/bootstrap/request` calls without the lock
    /// would both pass the `is_some()` check and both mint admin
    /// credentials. The test deliberately mirrors the exact ordering
    /// (`lock → get_raw → ... await ... → insert_raw`) including a
    /// yield point between the check and the set, where an unprotected
    /// implementation would interleave.
    ///
    /// Uses the actual `MODE_B_LOCK` static and the actual sentinel key
    /// constant so a refactor that relocates either is caught here.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn mode_b_lock_serializes_carveout_check_and_set() {
        use crate::tee::admin_bootstrap::BOOTSTRAP_CARVEOUT_CLOSED_KEY;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::time::Duration;
        use vti_common::config::StoreConfig;
        use vti_common::store::Store;

        let dir = tempfile::tempdir().expect("tempdir");
        let store_config = StoreConfig {
            data_dir: dir.path().to_path_buf(),
        };
        let store = Store::open(&store_config).expect("open store");
        let keys_ks = store.keyspace("keys").expect("keyspace");

        let n_tasks: usize = 16;
        let successes = std::sync::Arc::new(AtomicUsize::new(0));

        let mut handles = Vec::with_capacity(n_tasks);
        for i in 0..n_tasks {
            let ks = keys_ks.clone();
            let successes = std::sync::Arc::clone(&successes);
            handles.push(tokio::spawn(async move {
                // Same shape as `mint_mode_b`: take MODE_B_LOCK, check
                // the sentinel, do "work", write the sentinel. The yield
                // between check and set models the TEE attestation +
                // mint window an unprotected impl would race in.
                let _guard = MODE_B_LOCK.lock().await;
                if ks
                    .get_raw(BOOTSTRAP_CARVEOUT_CLOSED_KEY)
                    .await
                    .expect("get_raw sentinel")
                    .is_some()
                {
                    return; // carve-out already used
                }
                tokio::time::sleep(Duration::from_millis(2)).await;
                ks.insert_raw(
                    BOOTSTRAP_CARVEOUT_CLOSED_KEY,
                    format!("admin-{i}").into_bytes(),
                )
                .await
                .expect("insert sentinel");
                successes.fetch_add(1, Ordering::SeqCst);
            }));
        }

        for h in handles {
            h.await.expect("task joined");
        }

        assert_eq!(
            successes.load(Ordering::SeqCst),
            1,
            "MODE_B_LOCK must serialize the carve-out check-and-set so \
             exactly one task writes the sentinel; got {} successes",
            successes.load(Ordering::SeqCst),
        );
        assert!(
            keys_ks
                .get_raw(BOOTSTRAP_CARVEOUT_CLOSED_KEY)
                .await
                .unwrap()
                .is_some(),
            "sentinel must be set after the run"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────
// POST /bootstrap/provision-integration
// ─────────────────────────────────────────────────────────────────────
//
// Authenticated counterpart to the offline `vta bootstrap
// provision-integration` CLI. The same shared library fn under
// `operations::provision_integration` backs both; only the I/O differs.

#[cfg(feature = "webvh")]
pub use provision::provision_integration;

#[cfg(feature = "webvh")]
mod provision {
    use axum::Json;
    use axum::extract::State;
    use serde::{Deserialize, Serialize};

    use crate::auth::AdminAuth;
    use crate::error::AppError;
    use crate::operations::provision_integration::{
        AssertionMode, ProvisionIntegrationParams,
        provision_integration as provision_integration_lib,
    };
    use crate::server::AppState;
    use vta_sdk::provision_integration::BootstrapRequest;

    /// Request body for `POST /bootstrap/provision-integration`.
    #[derive(Debug, Deserialize)]
    pub struct ProvisionIntegrationRequestBody {
        /// The integration's VP-framed bootstrap request (signed by its
        /// ephemeral `client_did`).
        pub request: BootstrapRequest,
        /// VTA context to provision into. **Optional** per the canonical
        /// Trust Task spec; omit to let the VTA infer from the caller's
        /// ACL grant or its own contexts state. See
        /// `vta_sdk::provision_integration::http::ProvisionIntegrationRequest`
        /// for the full inference rules + error semantics when ambiguous.
        #[serde(default)]
        pub context: Option<String>,
        /// Optional — default `DidSigned`. Rejected unless the assertion
        /// mode is one the server is happy to sign (pinned-only is
        /// accepted on the HTTP surface because dev/test HTTP use is
        /// legitimate).
        #[serde(default)]
        pub assertion: Option<AssertionModeWire>,
        /// Optional override for the VC's validity window, in seconds.
        /// Omit for the 1-hour default.
        #[serde(default)]
        pub vc_validity_seconds: Option<i64>,
        /// Create the target context as part of provisioning if it
        /// doesn't already exist. **Requires super-admin** — the
        /// op-layer `create_context` enforces this. Idempotent when
        /// the context already exists. Defaults to `false`.
        #[serde(default)]
        pub create_context: bool,
    }

    /// Wire-form enum for `assertion` (camelCase-serialised via
    /// `#[serde(rename_all = ...)]`).
    #[derive(Debug, Clone, Copy, Deserialize)]
    #[serde(rename_all = "kebab-case")]
    pub enum AssertionModeWire {
        DidSigned,
        PinnedOnly,
    }

    impl From<AssertionModeWire> for AssertionMode {
        fn from(m: AssertionModeWire) -> Self {
            match m {
                AssertionModeWire::DidSigned => AssertionMode::DidSigned,
                AssertionModeWire::PinnedOnly => AssertionMode::PinnedOnly,
            }
        }
    }

    /// Response body.
    #[derive(Debug, Serialize)]
    pub struct ProvisionIntegrationResponseBody {
        /// Armored sealed bundle (PGP-style BEGIN/END blocks).
        pub bundle: String,
        /// SHA-256 digest of the sealed ciphertext (lowercase hex).
        pub digest: String,
        /// Operator-readable summary.
        pub summary: ProvisionSummaryWire,
    }

    #[derive(Debug, Serialize)]
    pub struct ProvisionSummaryWire {
        pub client_did: String,
        pub admin_did: String,
        pub admin_rolled_over: bool,
        /// `None` for the `AdminRotation` ask.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub integration_did: Option<String>,
        /// `None` for the `AdminRotation` ask.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub template_name: Option<String>,
        /// `None` for the `AdminRotation` ask.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub template_kind: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub admin_template_name: Option<String>,
        pub bundle_id_hex: String,
        pub secret_count: usize,
        pub output_count: usize,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub webvh_server_id: Option<String>,
        /// `true` when the target context didn't exist before this
        /// call and was created inline because the caller passed
        /// `create_context: true`. Lets operators see whether
        /// `--create-context` actually did something.
        #[serde(default)]
        pub context_created: bool,
    }

    /// Handler. Gated by `AdminAuth` — the caller must have admin role
    /// and the target context in `allowed_contexts` (enforced inside
    /// the library fn's preconditions). Super-admin passes through.
    pub async fn provision_integration(
        auth: AdminAuth,
        State(state): State<AppState>,
        Json(req): Json<ProvisionIntegrationRequestBody>,
    ) -> Result<Json<ProvisionIntegrationResponseBody>, AppError> {
        let verified = req
            .request
            .verify()
            .map_err(|e| AppError::Validation(format!("verify BootstrapRequest: {e}")))?;

        let assertion_mode = req.assertion.map(AssertionMode::from).unwrap_or_default();

        let vc_validity = req.vc_validity_seconds.map(chrono::Duration::seconds);

        let deps = crate::operations::provision_integration::ProvisionIntegrationDeps::from(&state);

        // Resolve the target context. When the caller sent one, use it
        // verbatim; otherwise run the spec's inference rules. On
        // ambiguity we collapse into Validation here — REST clients
        // (pnm-cli, scripts) get the message + candidates inline. The
        // DIDComm path emits the canonical
        // `provision/integration:context_required` code so structured
        // clients can branch on it; REST's typed-error vocabulary
        // wasn't designed for arbitrary new codes, so we stay with the
        // existing 400 shape.
        let context = match req.context {
            Some(c) => c,
            None => match crate::operations::provision_integration::infer_target_context(
                &auth.0,
                &deps.contexts_ks,
            )
            .await?
            {
                Ok(ctx) => ctx,
                Err(crate::operations::provision_integration::AmbiguousContext {
                    candidates,
                    message,
                }) => {
                    return Err(AppError::Validation(format!(
                        "{message} (candidates: {})",
                        candidates.join(", "),
                    )));
                }
            },
        };

        // `--create-context`: create the target context inline if
        // it doesn't exist. Hits the super-admin gate inside
        // `operations::contexts::create_context` — context-admin
        // callers surface as Forbidden here. Idempotent when the
        // context already exists.
        let context_created =
            crate::operations::provision_integration::ensure_target_context_or_create(
                &deps.contexts_ks,
                &auth.0,
                &context,
                req.create_context,
            )
            .await?;
        let output = provision_integration_lib(
            &deps,
            &auth.0,
            ProvisionIntegrationParams {
                request: verified,
                context,
                assertion_mode,
                vc_validity,
            },
        )
        .await?;

        Ok(Json(ProvisionIntegrationResponseBody {
            bundle: output.armored,
            digest: output.digest,
            summary: ProvisionSummaryWire {
                client_did: output.summary.client_did,
                admin_did: output.summary.admin_did,
                admin_rolled_over: output.summary.admin_rolled_over,
                integration_did: output.summary.integration_did,
                template_name: output.summary.template_name,
                template_kind: output.summary.template_kind,
                admin_template_name: output.summary.admin_template_name,
                bundle_id_hex: output.summary.bundle_id_hex,
                secret_count: output.summary.secret_count,
                output_count: output.summary.output_count,
                webvh_server_id: output.summary.webvh_server_id,
                context_created,
            },
        }))
    }
}
