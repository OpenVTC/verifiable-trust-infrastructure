//! `/bootstrap/request` — the TEE first-boot claim (wire version 2, #2066).
//!
//! This endpoint handles only **Mode B**: a fresh TEE VTA that has no
//! administrator yet. Only the holder of the VTA's configured
//! `tee.bootstrap_claim_did` may claim: the claim names it as `clientDid`, is
//! signed by its key, and names this VTA's own DID. Anyone else is refused
//! before anything is written, even if the carve-out sentinel has gone missing
//! (a host forging its absence, or a lost write).
//!
//! On a verified claim the enclave **enrols the claim DID itself** as an
//! expiring, hand-off-marked bootstrap administrator and closes the carve-out.
//! It mints no key and returns none: the answer is an attested acknowledgement
//! with no key material in it (VTI-CLT-001, VTI-CLT-002 — a node never holds a
//! client's private key, so a compromised node cannot impersonate its
//! clients). The client then authenticates as the claim DID, rolls the entry
//! over onto a long-term key it minted itself, and destroys the claim key
//! (VTI-CLT-017, VTI-CLT-034). Before #2066 the enclave minted the admin key
//! and sealed it back (`SealedPayloadV1::AdminCredential`); version-1 claims
//! are now refused.
//!
//! `GET /bootstrap/request` answers the DID a claim must name, for a client
//! that reached the VTA by URL rather than by DID (see
//! [`vta_sdk::tee_bootstrap::FirstBootClaimInfo`] for why that is safe to sign).
//!
//! The former Mode A (token-gated online bootstrap for non-TEE VTAs) was
//! removed: non-TEE clients use `pnm setup`'s temp-did:key flow.

use axum::Json;
use axum::extract::State;
#[cfg(feature = "tee")]
use sha2::{Digest, Sha256};
#[cfg(feature = "tee")]
use tracing::info;
#[cfg(feature = "tee")]
use vta_sdk::sealed_transfer::generate_ed25519_keypair;
use vta_sdk::tee_bootstrap::{CLAIM_VERSION, FirstBootAck, FirstBootClaim, FirstBootClaimInfo};
#[cfg(feature = "tee")]
use vta_sdk::tee_bootstrap::{FirstBootAttestation, VerifiedFirstBootClaim};

#[cfg(feature = "tee")]
use crate::acl::delete_acl_entry;
#[cfg(feature = "tee")]
use crate::acl::store_acl_entry;
#[cfg(feature = "tee")]
use crate::acl::{AclEntry, HandOff, HandOffBound, Role};
#[cfg(feature = "tee")]
use crate::audit::audit;
use crate::auth::session::now_epoch;
use crate::error::AppError;
use crate::server::AppState;

/// Maximum length (in bytes) of the operator-supplied bootstrap label.
/// The wire body is already capped globally, but the label is the only
/// free-form attacker-controlled string in this DTO and ends up (hashed) in
/// logs — keep it short so an aggressive logger can't spill MBs.
const MAX_LABEL_LEN: usize = 256;

/// How long the claim DID's bootstrap entry lives unless rolled over first.
///
/// VTI-CLT-014: the entry an enrolment writes SHOULD carry a short expiry —
/// it is named by a key that existed before the VTA did. `pnm bootstrap
/// connect` rolls it over within seconds of the claim. The window is not
/// shorter because on a TEE VTA nobody else can re-enrol an administrator once
/// the single-use carve-out is spent: an operator whose connect was
/// interrupted after the claim has this long to re-run it (which resumes the
/// rollover) before the VTA is left with no administrator at all.
#[cfg(feature = "tee")]
pub(crate) const BOOTSTRAP_ENTRY_TTL_SECS: u64 = 24 * 60 * 60;

/// `GET /bootstrap/request` — the DID a first-boot claim on this VTA names.
#[utoipa::path(
    get, path = "/bootstrap/request", tag = "bootstrap",
    responses(
        (status = 200, description = "This VTA's DID, for the claim signature", body = FirstBootClaimInfo),
        (status = 403, description = "TEE first-boot is not available on this VTA"),
    ),
)]
pub async fn claim_info(
    State(state): State<AppState>,
) -> Result<Json<FirstBootClaimInfo>, AppError> {
    if state.tee.is_none() || cfg!(not(feature = "tee")) {
        return Err(AppError::Forbidden(
            "TEE first-boot is not available on this VTA".into(),
        ));
    }
    let vta_did = state
        .config
        .read()
        .await
        .vta_did
        .clone()
        .ok_or_else(|| AppError::Internal("VTA DID not configured".into()))?;
    Ok(Json(FirstBootClaimInfo {
        version: CLAIM_VERSION,
        vta_did,
    }))
}

/// `POST /bootstrap/request`
#[utoipa::path(
    post, path = "/bootstrap/request", tag = "bootstrap",
    request_body = FirstBootClaim,
    responses(
        (status = 200, description = "The claim DID is enrolled as the bootstrap administrator; attested acknowledgement, no key material", body = FirstBootAck),
        (status = 400, description = "Unsupported version (a pre-#2066 client) or a malformed claim"),
        (status = 403, description = "TEE first-boot unavailable; the claim is not signed by the configured bootstrap claim DID; or it names another VTA"),
        (status = 410, description = "Carve-out already used — this VTA already has an admin"),
    ),
)]
pub async fn request(
    State(state): State<AppState>,
    Json(raw): Json<serde_json::Value>,
) -> Result<Json<FirstBootAck>, AppError> {
    // Read the version before the shape, so a version-1 client (whose body has
    // different members) is told to upgrade rather than that its JSON is bad.
    let version = raw.get("version").and_then(serde_json::Value::as_u64);
    if version != Some(u64::from(CLAIM_VERSION)) {
        return Err(AppError::Validation(format!(
            "bootstrap request version {} is not accepted: this VTA speaks version \
             {CLAIM_VERSION}, in which it enrols your claim DID instead of minting an admin key \
             for you (#2066). Upgrade pnm and re-run `pnm bootstrap connect`.",
            version.map_or_else(|| "(missing)".to_string(), |v| v.to_string())
        )));
    }
    let claim: FirstBootClaim = serde_json::from_value(raw)
        .map_err(|e| AppError::Validation(format!("malformed bootstrap claim: {e}")))?;
    if claim
        .label
        .as_ref()
        .is_some_and(|l| l.len() > MAX_LABEL_LEN)
    {
        return Err(AppError::Validation(format!(
            "label exceeds {MAX_LABEL_LEN} bytes"
        )));
    }

    #[cfg(not(feature = "tee"))]
    {
        let _ = (state, claim, now_epoch());
        Err(AppError::Forbidden(
            "bootstrap request requires TEE first-boot attestation, which is not available on \
             this VTA build. Non-TEE VTAs use the `pnm setup` temp-did:key + ACL flow instead."
                .into(),
        ))
    }

    #[cfg(feature = "tee")]
    {
        let verified = claim.verify().map_err(|e| {
            AppError::Forbidden(format!(
                "bootstrap claim must be signed by the clientDid's key: {e}"
            ))
        })?;
        let ack = enrol_mode_b(&state, &verified, now_epoch()).await?;

        // Log a SHA-256 prefix of the operator-supplied label rather than
        // the raw string. Labels are free-form and often carry PII.
        info!(
            client_label_hash = %label_hash_prefix(verified.label()),
            "TEE first-boot claim enrolled"
        );
        audit!(
            "bootstrap.claim",
            actor = verified.client_did(),
            resource = "bootstrap",
            outcome = "success"
        );
        let _ = crate::audit::record(
            &state.audit_sink,
            "bootstrap.claim",
            verified.client_did(),
            None,
            "success",
            Some("rest"),
            None,
        )
        .await;
        Ok(Json(ack))
    }
}

/// Process-wide lock that serializes the carve-out check-and-set. The
/// keyspace exposes no compare-and-swap, so two concurrent requests could
/// each pass the `is_some()` check and write their entries before either
/// writes the closed-sentinel. A `tokio::sync::Mutex` held across the whole
/// sequence collapses that window — the second request waits, then sees the
/// sentinel and is refused. The claim is single-use and rare, so contention is
/// irrelevant.
#[cfg(feature = "tee")]
static MODE_B_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Mode B: enrol the verified claim DID as the bootstrap administrator.
///
/// On success, closes the first-boot carve-out permanently by writing the
/// `BOOTSTRAP_CARVEOUT_CLOSED_KEY` sentinel. Any subsequent request is
/// rejected with [`carve_out_closed_error`] (410 Gone) — the carve-out is
/// consumed, not merely disallowed for this caller, which is what
/// distinguishes it from a 403.
#[cfg(feature = "tee")]
async fn enrol_mode_b(
    state: &AppState,
    claim: &VerifiedFirstBootClaim,
    now: u64,
) -> Result<FirstBootAck, AppError> {
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

    let cfg = state.config.read().await;
    let configured_claim_did = cfg.tee.bootstrap_claim_did.clone();
    let vta_did = cfg
        .vta_did
        .clone()
        .ok_or_else(|| AppError::Internal("VTA DID not configured".into()))?;
    drop(cfg);

    // Both before the carve-out check, so a stranger — or a claim meant for
    // another VTA — learns nothing about its state.
    authorize_claimant(configured_claim_did.as_deref(), claim.client_ed25519_pub())?;
    // The claim signature covers the VTA DID. Refusing any DID but our own is
    // what lets the attestation quote (which binds only key, nonce and
    // producer) stand for "this VTA accepted your claim": a claim captured on
    // its way to one VTA cannot be spent on another, and a host cannot relabel
    // the acknowledgement.
    if claim.vta_did() != vta_did {
        return Err(AppError::Forbidden(format!(
            "the claim is for VTA {}, but this VTA is {vta_did}",
            claim.vta_did()
        )));
    }

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
        return Err(carve_out_closed_error());
    }

    // Per-request ephemeral producer Ed25519 keypair. The did:key bytes are
    // bound into the attestation `user_data` alongside the client's did:key
    // bytes + nonce so the consumer can recompute against DID-visible data.
    let (_producer_seed, producer_ed_pub) = generate_ed25519_keypair();
    let producer_did = affinidi_crypto::did_key::ed25519_pub_to_did_key(&producer_ed_pub);

    // Attestation user_data binds DID-layer bytes end-to-end, unchanged from
    // wire version 1 so PCR pinning and the verifier are untouched:
    //   SHA256(client_ed25519 || nonce || producer_ed25519)
    let mut hasher = Sha256::new();
    hasher.update(claim.client_ed25519_pub());
    hasher.update(claim.nonce());
    hasher.update(producer_ed_pub);
    let user_data = hasher.finalize();

    // Attest FIRST, before touching any carve-out state: a failure here must
    // leave the carve-out open and retryable — no ACL, no sentinel written.
    let report = tee_state
        .provider
        .attest(user_data.as_slice(), claim.nonce())
        .map_err(|e| AppError::Internal(format!("tee attest failed: {e}")))?;

    // The bootstrap entry: the claim DID itself (VTI-CLT-010), with the
    // authority the VTA-minted admin had before #2066 — unrestricted act scope,
    // no narrowing — but expiring (VTI-CLT-014) and marked as a hand-off
    // (VTI-ACL-054, VTI-CLT-017).
    //
    // The marker is why the long-term administrator can outlive this entry. A
    // rotation (`acl/swap-key`) preserves expiry exactly (VTI-CLT-029), so
    // rotating off an expiring entry would leave the VTA's only administrator
    // expiring with it, and nobody could lift it. The rollover the marker
    // allows writes the client's own long-term DID bounded by the granter's
    // recorded authority instead. The granter is this VTA acting on the
    // operator's configured claim DID — the first-boot authority, which holds
    // everything — so the bound is an unrestricted, permanent administrator.
    let expires_at = now + BOOTSTRAP_ENTRY_TTL_SECS;
    let entry = AclEntry::new(claim.client_did(), Role::Admin, "tee:mode-b")
        .with_label(Some("TEE first-boot claim DID (bootstrap)".to_string()))
        .with_created_at(now)
        .with_expires_at(Some(expires_at));
    let entry = entry.clone().with_handoff(Some(HandOff {
        granted_by: vta_did.clone(),
        granted_at: now,
        bound: HandOffBound {
            role: Role::Admin,
            allowed_contexts: Vec::new(),
            capabilities: Vec::new(),
            approve_scope: entry.approve_scope.clone(),
            allowed_keys: None,
            expires_at: None,
        },
    }));

    // Now commit the carve-out. Ordering and durability are load-bearing
    // (P0.8):
    //
    //   1. The ACL entry is written BEFORE the sentinel, so a torn fsync
    //      recovers to {ACL, no sentinel} — a safe reopen (the next claim
    //      overwrites the same entry for the same claim DID) — rather than
    //      {sentinel, no ACL}, which would brick the VTA (carve-out closed, no
    //      admin).
    //   2. The sentinel is claimed with `insert_raw_if_absent`: even if a
    //      future refactor breaks the `MODE_B_LOCK` guard above, a concurrent
    //      request's claim returns `false` and fails closed.
    //   3. `persist()` fsyncs the ACL + sentinel together BEFORE the
    //      acknowledgement is returned. The client destroys nothing and acts
    //      on nothing until it holds the acknowledgement, and a power loss
    //      after it cannot reopen the carve-out.
    store_acl_entry(&state.acl_ks, &entry).await?;

    if !state
        .keys_ks
        .insert_raw_if_absent(
            BOOTSTRAP_CARVEOUT_CLOSED_KEY,
            claim.client_did().as_bytes().to_vec(),
        )
        .await?
    {
        // Lost the carve-out race (only reachable if MODE_B_LOCK were
        // bypassed). Roll back the entry we just wrote and refuse.
        let _ = delete_acl_entry(&state.acl_ks, claim.client_did()).await;
        return Err(carve_out_closed_error());
    }

    // Durability barrier: do not acknowledge until the carve-out close is on
    // disk.
    state.keys_ks.persist().await?;

    // Re-seal the TEE integrity manifest now that the carve-out is closed, so a
    // subsequent boot detects any parent attempt to reopen it (P0.2a). The
    // carve-out sentinel write above is a direct `insert_raw_if_absent`, not an
    // ACL/counter chokepoint, so it needs its own reseal. No-op outside a TEE.
    vti_common::integrity::reseal_if_active().await?;

    info!(
        claim_did = %claim.client_did(),
        expires_at,
        "TEE first-boot carve-out consumed — claim DID enrolled as bootstrap admin"
    );
    Ok(FirstBootAck {
        version: CLAIM_VERSION,
        vta_did,
        admin_did: claim.client_did().to_string(),
        expires_at,
        producer_did,
        attestation: FirstBootAttestation {
            format: format!("{}", report.tee_type),
            quote_b64: report.evidence,
        },
    })
}

/// The consumed-carve-out refusal, shared by both places `enrol_mode_b` can
/// discover the sentinel is already set (the up-front check, and the
/// defensive `insert_raw_if_absent` loss on the commit path).
///
/// Rendered as **410 Gone**, not 403: the carve-out is not a permission this
/// caller lacks (a 403 would suggest a *different* caller or a *later*
/// retry might succeed) — it is a single-use resource that has been
/// permanently, irreversibly consumed for this VTA. `vta_sdk::error::VtaError`
/// keys its `Gone` variant (and CLI hint) off this exact status.
#[cfg(feature = "tee")]
fn carve_out_closed_error() -> AppError {
    AppError::Gone("TEE first-boot carve-out has already been used".into())
}

/// Admit only the configured claim DID. Unset admits nobody (fail closed).
#[cfg(feature = "tee")]
fn authorize_claimant(
    configured: Option<&str>,
    client_ed25519_pub: &[u8; 32],
) -> Result<(), AppError> {
    let configured = configured.ok_or_else(|| {
        AppError::Forbidden(
            "this VTA has no tee.bootstrap_claim_did configured, so no first-boot admin claim \
             is accepted"
                .into(),
        )
    })?;
    let authorized = affinidi_crypto::did_key::did_key_to_ed25519_pub(configured).map_err(|e| {
        AppError::Internal(format!(
            "configured tee.bootstrap_claim_did is not an Ed25519 did:key: {e}"
        ))
    })?;
    if &authorized != client_ed25519_pub {
        return Err(AppError::Forbidden(
            "client_did is not this VTA's bootstrap claim DID".into(),
        ));
    }
    Ok(())
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

#[cfg(all(test, feature = "tee"))]
mod tests {
    use super::*;
    use axum::response::IntoResponse;

    const VTA: &str = "did:webvh:QmTestScid:vta.example.com";

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

    /// Concurrency contract for the carve-out close (P0.8).
    ///
    /// Property under test: when N concurrent `enrol_mode_b`-style
    /// sequences race against the same keyspace, exactly one claims the
    /// carve-out sentinel; the others see the atomic claim fail and
    /// refuse. Each task takes `MODE_B_LOCK` (the primary serializer)
    /// and then claims the sentinel via `insert_raw_if_absent` (the
    /// mechanism `enrol_mode_b` uses) — so the claim is correct *even if a
    /// future refactor drops the lock*.
    ///
    /// Uses the actual `MODE_B_LOCK` static and the actual sentinel key
    /// constant so a refactor that relocates either is caught here.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn carveout_claim_admits_exactly_one_concurrent_minter() {
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
        let keys_ks = store.keyspace(crate::keyspaces::KEYS).expect("keyspace");

        let n_tasks: usize = 16;
        let successes = std::sync::Arc::new(AtomicUsize::new(0));

        let mut handles = Vec::with_capacity(n_tasks);
        for i in 0..n_tasks {
            let ks = keys_ks.clone();
            let successes = std::sync::Arc::clone(&successes);
            handles.push(tokio::spawn(async move {
                let _guard = MODE_B_LOCK.lock().await;
                tokio::time::sleep(Duration::from_millis(2)).await;
                let claimed = ks
                    .insert_raw_if_absent(
                        BOOTSTRAP_CARVEOUT_CLOSED_KEY,
                        format!("admin-{i}").into_bytes(),
                    )
                    .await
                    .expect("claim sentinel");
                if claimed {
                    ks.persist().await.expect("persist carve-out");
                    successes.fetch_add(1, Ordering::SeqCst);
                }
            }));
        }

        for h in handles {
            h.await.expect("task joined");
        }

        assert_eq!(
            successes.load(Ordering::SeqCst),
            1,
            "exactly one task may claim the carve-out sentinel; got {} successes",
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

    /// Simulated-TEE app state named `VTA`, whose configured claim DID is
    /// `claim_pub`'s.
    async fn claim_state(claim_pub: Option<&[u8; 32]>) -> AppState {
        use crate::config::{TeeConfig, TeeMode};
        use crate::server::TeeContext;

        let (_app, ctx) = crate::test_support::build_test_app().await;
        let tee_state = crate::tee::init_tee(&TeeConfig {
            mode: TeeMode::Simulated,
            ..Default::default()
        })
        .expect("init simulated tee")
        .expect("simulated tee state present");

        let mut state = ctx.state.clone();
        state.tee = Some(TeeContext {
            state: tee_state,
            mnemonic_guard: None,
        });
        {
            let mut cfg = state.config.write().await;
            cfg.tee.bootstrap_claim_did =
                claim_pub.map(affinidi_crypto::did_key::ed25519_pub_to_did_key);
            cfg.vta_did = Some(VTA.to_string());
        }
        state
    }

    /// A verified claim by `seed` on `vta_did`.
    fn claim(seed: &[u8; 32], vta_did: &str, nonce: u8) -> VerifiedFirstBootClaim {
        FirstBootClaim::new_signed(seed, vta_did, [nonce; 16], None)
            .verify()
            .expect("signed claim verifies")
    }

    /// The body `request` receives, as JSON.
    fn body(claim: &FirstBootClaim) -> Json<serde_json::Value> {
        Json(serde_json::to_value(claim).unwrap())
    }

    /// Nothing written: no carve-out sentinel and no ACL entry for `did`.
    async fn assert_nothing_written(state: &AppState, did: &str) {
        use crate::tee::admin_bootstrap::BOOTSTRAP_CARVEOUT_CLOSED_KEY;
        assert!(
            state
                .keys_ks
                .get_raw(BOOTSTRAP_CARVEOUT_CLOSED_KEY)
                .await
                .unwrap()
                .is_none(),
            "the carve-out sentinel must not be written for a refused claim"
        );
        assert!(
            crate::acl::get_acl_entry(&state.acl_ks, did)
                .await
                .unwrap()
                .is_none(),
            "no ACL entry may be written for a refused claim"
        );
    }

    /// #2066: the claim DID itself is enrolled, as an expiring hand-off-marked
    /// super-admin, and the answer carries no private key material
    /// (VTI-CLT-002, VTI-CLT-014).
    #[tokio::test]
    async fn claim_enrols_the_claim_did_with_an_expiry_and_returns_no_key() {
        use crate::tee::admin_bootstrap::BOOTSTRAP_CARVEOUT_CLOSED_KEY;

        let (seed, claim_pub) = generate_ed25519_keypair();
        let state = claim_state(Some(&claim_pub)).await;
        let signed = FirstBootClaim::new_signed(&seed, VTA, [1; 16], None);
        let claim_did = signed.client_did.clone();
        let now = now_epoch();

        let Json(ack) = request(State(state.clone()), body(&signed))
            .await
            .expect("claim accepted");

        assert_eq!(ack.version, CLAIM_VERSION);
        assert_eq!(ack.admin_did, claim_did);
        assert_eq!(ack.vta_did, VTA);
        assert!(ack.expires_at >= now + BOOTSTRAP_ENTRY_TTL_SECS);
        assert!(!ack.attestation.quote_b64.is_empty());
        // No key material anywhere in the answer: its members are fixed by
        // `deny_unknown_fields`, and none of them is a key.
        let json = serde_json::to_value(&ack).unwrap();
        let text = json.to_string();
        for forbidden in ["privateKey", "private_key", "secret", "seed", "bundle"] {
            assert!(
                !text.contains(forbidden),
                "ack carries `{forbidden}`: {text}"
            );
        }

        let entry = crate::acl::get_acl_entry(&state.acl_ks, &claim_did)
            .await
            .unwrap()
            .expect("claim DID is enrolled");
        assert_eq!(entry.role, Role::Admin);
        assert!(
            entry.allowed_contexts.is_empty(),
            "the bootstrap admin is unrestricted, as the minted admin was"
        );
        assert_eq!(entry.expires_at, Some(ack.expires_at));
        let marker = entry.handoff.expect("bootstrap entry is a hand-off");
        assert_eq!(marker.granted_by, VTA);
        assert_eq!(marker.bound.role, Role::Admin);
        assert_eq!(marker.bound.expires_at, None);

        assert_eq!(
            state
                .keys_ks
                .get_raw(BOOTSTRAP_CARVEOUT_CLOSED_KEY)
                .await
                .unwrap()
                .as_deref(),
            Some(claim_did.as_bytes()),
            "the carve-out is closed, naming the claim DID"
        );
    }

    /// The API-contract regression this module exists to close: a consumed
    /// Mode B carve-out must render **410 Gone**, not 403. The second request
    /// comes from the authorized claim key with a fresh nonce, so it is
    /// neither a replay nor an unauthorized caller.
    #[tokio::test]
    async fn consumed_carveout_returns_410_gone_not_403() {
        let (seed, claim_pub) = generate_ed25519_keypair();
        let state = claim_state(Some(&claim_pub)).await;
        let now = now_epoch();

        enrol_mode_b(&state, &claim(&seed, VTA, 1), now)
            .await
            .expect("first claim enrols");

        let err = enrol_mode_b(&state, &claim(&seed, VTA, 2), now)
            .await
            .expect_err("second claim must be refused");

        assert!(
            matches!(err, AppError::Gone(_)),
            "consumed carve-out must map to AppError::Gone, got {err:?}"
        );
        assert_eq!(
            err.into_response().status(),
            axum::http::StatusCode::GONE,
            "consumed carve-out must render as HTTP 410, not 403/409"
        );
    }

    #[tokio::test]
    async fn caller_without_the_claim_did_is_refused_without_writing() {
        let (_, claim_pub) = generate_ed25519_keypair();
        let (stranger_seed, _) = generate_ed25519_keypair();
        let state = claim_state(Some(&claim_pub)).await;
        let stranger = claim(&stranger_seed, VTA, 1);

        let err = enrol_mode_b(&state, &stranger, now_epoch())
            .await
            .expect_err("a stranger must not claim admin");
        assert!(matches!(err, AppError::Forbidden(_)), "got {err:?}");
        assert_nothing_written(&state, stranger.client_did()).await;
    }

    #[tokio::test]
    async fn no_configured_claim_did_admits_nobody() {
        let (seed, _) = generate_ed25519_keypair();
        let state = claim_state(None).await;
        let caller = claim(&seed, VTA, 1);

        let err = enrol_mode_b(&state, &caller, now_epoch())
            .await
            .expect_err("without a claim DID no one may claim");
        assert!(matches!(err, AppError::Forbidden(_)), "got {err:?}");
        assert_nothing_written(&state, caller.client_did()).await;
    }

    /// The carve-out sentinel vanishes after a successful claim (a lost write,
    /// or a host deleting it — which the TEE integrity manifest catches at the
    /// next boot, not here). A stranger is still refused: the claim DID, not the
    /// sentinel, is what keeps an anonymous caller out.
    #[tokio::test]
    async fn missing_sentinel_does_not_admit_a_stranger() {
        use crate::tee::admin_bootstrap::BOOTSTRAP_CARVEOUT_CLOSED_KEY;

        let (seed, claim_pub) = generate_ed25519_keypair();
        let (stranger_seed, _) = generate_ed25519_keypair();
        let state = claim_state(Some(&claim_pub)).await;

        enrol_mode_b(&state, &claim(&seed, VTA, 1), now_epoch())
            .await
            .expect("first claim enrols");
        state
            .keys_ks
            .remove(BOOTSTRAP_CARVEOUT_CLOSED_KEY)
            .await
            .unwrap();

        let err = enrol_mode_b(&state, &claim(&stranger_seed, VTA, 2), now_epoch())
            .await
            .expect_err("a stranger must not walk through a reopened window");
        assert!(matches!(err, AppError::Forbidden(_)), "got {err:?}");
    }

    /// The right claim key, a valid signature — but over another VTA's DID.
    /// Refused before the carve-out is touched (#2066).
    #[tokio::test]
    async fn claim_signed_for_another_vta_is_refused() {
        let (seed, claim_pub) = generate_ed25519_keypair();
        let state = claim_state(Some(&claim_pub)).await;
        let elsewhere = claim(&seed, "did:webvh:QmOther:other.example.com", 1);

        let err = enrol_mode_b(&state, &elsewhere, now_epoch())
            .await
            .expect_err("a claim on another VTA must not be spent here");
        assert!(matches!(err, AppError::Forbidden(_)), "got {err:?}");
        assert_nothing_written(&state, elsewhere.client_did()).await;
    }

    /// A version-1 body (pre-#2066 pnm) is refused with an upgrade hint, and a
    /// version-1 signature relabelled as version 2 does not verify.
    #[tokio::test]
    async fn version_one_claims_are_refused() {
        use base64::Engine;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
        use ed25519_dalek::Signer;

        let (seed, claim_pub) = generate_ed25519_keypair();
        let state = claim_state(Some(&claim_pub)).await;
        let did = affinidi_crypto::did_key::ed25519_pub_to_did_key(&claim_pub);
        let nonce = [5u8; 16];
        let mut v1_input = b"vti/bootstrap-claim/v1\0".to_vec();
        v1_input.extend_from_slice(&claim_pub);
        v1_input.extend_from_slice(&nonce);
        let v1_sig = B64.encode(
            ed25519_dalek::SigningKey::from_bytes(&seed)
                .sign(&v1_input)
                .to_bytes(),
        );

        let v1_body = serde_json::json!({
            "version": 1,
            "client_did": did,
            "nonce": B64.encode(nonce),
            "claim_signature": v1_sig,
        });
        let err = request(State(state.clone()), Json(v1_body))
            .await
            .expect_err("a version-1 claim is refused");
        match &err {
            AppError::Validation(msg) => assert!(msg.contains("Upgrade pnm"), "{msg}"),
            other => panic!("expected a validation refusal, got {other:?}"),
        }

        let mut relabelled = FirstBootClaim::new_signed(&seed, VTA, nonce, None);
        relabelled.claim_signature = v1_sig;
        let err = request(State(state.clone()), body(&relabelled))
            .await
            .expect_err("a v1 signature does not verify as v2");
        assert!(matches!(err, AppError::Forbidden(_)), "got {err:?}");
        assert_nothing_written(&state, &did).await;
    }

    #[tokio::test]
    async fn tampered_or_unsigned_claims_are_refused() {
        let (seed, claim_pub) = generate_ed25519_keypair();
        let state = claim_state(Some(&claim_pub)).await;

        // The VTA DID swapped in after signing.
        let mut retargeted =
            FirstBootClaim::new_signed(&seed, "did:webvh:QmOther:x", [1; 16], None);
        retargeted.vta_did = VTA.into();
        let err = request(State(state.clone()), body(&retargeted))
            .await
            .expect_err("the VTA DID is signed");
        assert!(matches!(err, AppError::Forbidden(_)), "got {err:?}");

        // Someone who knows the public claim DID but not its key.
        let (other_seed, _) = generate_ed25519_keypair();
        let mut forged = FirstBootClaim::new_signed(&other_seed, VTA, [1; 16], None);
        forged.client_did = affinidi_crypto::did_key::ed25519_pub_to_did_key(&claim_pub);
        let err = request(State(state.clone()), body(&forged))
            .await
            .expect_err("a forged claim is refused");
        assert!(matches!(err, AppError::Forbidden(_)), "got {err:?}");

        // Unknown members (a smuggled role) are not ignored.
        let mut smuggled =
            serde_json::to_value(FirstBootClaim::new_signed(&seed, VTA, [1; 16], None)).unwrap();
        smuggled["requestedRole"] = "admin".into();
        let err = request(State(state.clone()), Json(smuggled))
            .await
            .expect_err("unknown members are refused");
        assert!(matches!(err, AppError::Validation(_)), "got {err:?}");

        assert_nothing_written(
            &state,
            &affinidi_crypto::did_key::ed25519_pub_to_did_key(&claim_pub),
        )
        .await;
    }

    #[tokio::test]
    async fn claim_info_names_this_vta() {
        let state = claim_state(None).await;
        let Json(info) = claim_info(State(state)).await.expect("served on a TEE VTA");
        assert_eq!(info.version, CLAIM_VERSION);
        assert_eq!(info.vta_did, VTA);
    }

    /// The whole hand-off: the claim DID, authenticated, rolls its bootstrap
    /// entry over onto a long-term DID the client minted. The successor is a
    /// permanent unrestricted admin, and the claim DID has no standing left
    /// (VTI-ACL-056, VTI-CLT-017).
    #[tokio::test]
    async fn claim_did_rolls_over_onto_a_permanent_client_minted_admin() {
        use vta_sdk::protocols::acl_management::entry::AclEntry as WireAclEntry;

        let (seed, claim_pub) = generate_ed25519_keypair();
        let state = claim_state(Some(&claim_pub)).await;
        let claim = claim(&seed, VTA, 1);
        enrol_mode_b(&state, &claim, now_epoch())
            .await
            .expect("claim enrols");

        let auth = crate::auth::AuthClaims {
            did: claim.client_did().to_string(),
            role: Role::Admin,
            allowed_contexts: Vec::new(),
            ..crate::test_support::super_admin_claims()
        };
        let (_, long_term_pub) = generate_ed25519_keypair();
        let long_term = affinidi_crypto::did_key::ed25519_pub_to_did_key(&long_term_pub);

        // An expiry on the successor is refused, not silently replaced.
        let mut with_expiry = WireAclEntry::new(long_term.clone(), "admin".into(), Vec::new());
        with_expiry.expires_at = Some(chrono::Utc::now() + chrono::Duration::hours(1));
        assert!(matches!(
            crate::operations::acl::rollover_from_entry(
                &state.acl_ks,
                &state.audit_sink,
                &state.contexts_ks,
                &auth,
                with_expiry,
                "test",
            )
            .await,
            Err(AppError::Validation(_))
        ));

        crate::operations::acl::rollover_from_entry(
            &state.acl_ks,
            &state.audit_sink,
            &state.contexts_ks,
            &auth,
            WireAclEntry::new(long_term.clone(), "admin".into(), Vec::new()),
            "test",
        )
        .await
        .expect("the claim DID rolls over");

        let successor = crate::acl::get_acl_entry(&state.acl_ks, &long_term)
            .await
            .unwrap()
            .expect("successor written");
        assert_eq!(successor.role, Role::Admin);
        assert!(successor.allowed_contexts.is_empty());
        assert_eq!(
            successor.expires_at, None,
            "the long-term admin is permanent"
        );
        assert!(successor.handoff.is_none());
        assert!(
            crate::acl::get_acl_entry(&state.acl_ks, claim.client_did())
                .await
                .unwrap()
                .is_none(),
            "the claim DID has no standing after the rollover"
        );
    }
}
