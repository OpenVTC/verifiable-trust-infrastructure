//! Attestation slice trust-task handlers.
//!
//! - `spec/vta/attestation/{status,report,config-report}/0.1` — the three
//!   **public** reads ([`vta_sdk::trust_tasks::PUBLIC_URIS`]). A verifier asks
//!   before it trusts this agent, so they need no session, ACL entry or request
//!   proof; the nonce bound into the evidence is what makes a report the
//!   verifier's own, and the spine signs every response with this agent's
//!   `authentication` key. They were REST-only routes and a DIDComm arm nothing
//!   sent to; on the spine they are reachable over TSP, DIDComm and HTTPS alike.
//! - `spec/vta/attestation/mnemonic-export/1.0` — authenticated, end-to-end
//!   only (or a signed first-boot request); see [`handle_mnemonic_export`].
//! - `spec/vta/attestation/mnemonic-status/0.1` — the export window's current
//!   state. Super-admin only; see [`handle_mnemonic_status`]. Was
//!   `GET /attestation/mnemonic`, a documented `REST_EXCEPTIONS` keep until
//!   this spec landed.

use serde_json::Value;
use trust_tasks_rs::specs::vta::attestation::mnemonic_export::v1_0 as mnemonic_export_spec;
use trust_tasks_rs::{RejectReason, TrustTask};
use vta_sdk::sealed_transfer::BootstrapRequest;
use vti_common::error::AppError;

use super::helpers::{
    TrustTaskOutcome, app_error_to_reject, parse_payload, reject_declared, reject_with,
    success_response,
};
use super::transport::{self, TransportConfidentiality};
use crate::auth::AuthClaims;
use crate::operations;
use crate::server::AppState;
use trust_tasks_rs::specs::vta::attestation::{
    config_report::v0_1 as config_report_spec, mnemonic_status::v0_1 as mnemonic_status_spec,
    report::v0_1 as report_spec, status::v0_1 as status_spec,
};

/// The platform name as the specifications spell it. The internal enum
/// displays `sev_snp`; the registry says `sev-snp`.
fn tee_type_wire(tee_type: &str) -> &'static str {
    match tee_type {
        "nitro" => "nitro",
        "sev_snp" | "sev-snp" => "sev-snp",
        _ => "simulated",
    }
}

/// Unix seconds as the RFC 3339 `generatedAt` the specifications carry.
fn rfc3339(secs: u64) -> Option<String> {
    chrono::DateTime::from_timestamp(i64::try_from(secs).ok()?, 0)
        .map(|t| t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
}

/// Build the response through the generated type, so what goes out is checked
/// against the published schema on the way (the patterns on `nonce`,
/// `evidence`, the digest) rather than trusted to a hand-built map.
fn typed_response<R: serde::de::DeserializeOwned + serde::Serialize>(
    doc: &TrustTask<Value>,
    body: Value,
) -> TrustTaskOutcome {
    match serde_json::from_value::<R>(body) {
        Ok(r) => success_response(doc, r),
        Err(e) => reject_with(
            doc,
            RejectReason::InternalError {
                reason: format!("attestation response does not match its schema: {e}"),
            },
        ),
    }
}

/// `spec/vta/attestation/status/0.1` — which TEE this agent detected at boot.
/// Public: answered to anyone, the same for everyone.
pub(super) async fn handle_status(
    state: &AppState,
    _auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    if let Err(resp) = parse_payload::<status_spec::Payload>(&doc) {
        return resp;
    }
    let Some(tee) = state.tee.as_ref() else {
        return reject_declared(
            &doc,
            status_spec::error_codes::NOT_ATTESTED,
            "this agent has no attestation provider",
        );
    };
    let status = operations::attestation::get_tee_status(&tee.state);
    let mut body = serde_json::json!({
        "teeType": tee_type_wire(&status.tee_type.to_string()),
        "detected": status.detected,
    });
    if let Some(v) = status.platform_version {
        body["platformVersion"] = Value::String(v);
    }
    typed_response::<status_spec::Response>(&doc, body)
}

/// `spec/vta/attestation/report/0.1` — fresh evidence binding the verifier's
/// nonce and this agent's DID. Public; there is no nonce-less form, because a
/// report nobody asked for is one anybody can replay.
pub(super) async fn handle_report(
    state: &AppState,
    _auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let payload: report_spec::Payload = match parse_payload(&doc) {
        Ok(p) => p,
        Err(resp) => return resp,
    };
    let Some(tee) = state.tee.as_ref() else {
        return reject_declared(
            &doc,
            report_spec::error_codes::NOT_ATTESTED,
            "this agent has no attestation provider",
        );
    };
    let nonce = payload.nonce.to_string();
    let report = match operations::attestation::generate_attestation_report(
        &tee.state,
        &state.config,
        &nonce,
    )
    .await
    {
        Ok(r) => r,
        Err(e @ AppError::Validation(_)) => return app_error_to_reject(&doc, e),
        Err(e) => {
            tracing::warn!(error = %e, "attestation report: the platform produced no quote");
            return reject_declared(
                &doc,
                report_spec::error_codes::EVIDENCE_UNAVAILABLE,
                "the platform did not produce a quote",
            );
        }
    };
    let mut body = serde_json::json!({
        "teeType": tee_type_wire(&report.tee_type.to_string()),
        "evidence": report.evidence,
        "nonce": nonce,
        "generatedAt": rfc3339(report.generated_at),
    });
    if let Some(did) = report.vta_did {
        body["vtaDid"] = Value::String(did);
    }
    typed_response::<report_spec::Response>(&doc, body)
}

/// `spec/vta/attestation/config-report/0.1` — fresh evidence binding the
/// verifier's nonce and the SHA-384 of the secret-free view of the
/// configuration this enclave booted. Public. Only the enclave front-end
/// captures that view at boot; any other build answers `noConfigSnapshot`.
pub(super) async fn handle_config_report(
    state: &AppState,
    _auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let payload: config_report_spec::Payload = match parse_payload(&doc) {
        Ok(p) => p,
        Err(resp) => return resp,
    };
    let Some(tee) = state.tee.as_ref() else {
        return reject_declared(
            &doc,
            config_report_spec::error_codes::NOT_ATTESTED,
            "this agent has no attestation provider",
        );
    };
    {
        let cfg = state.config.read().await;
        if cfg.effective_config_digest.is_none() || cfg.effective_config_view.is_none() {
            return reject_declared(
                &doc,
                config_report_spec::error_codes::NO_CONFIG_SNAPSHOT,
                "this agent captured no configuration snapshot at boot",
            );
        }
    }
    let nonce = payload.nonce.to_string();
    let report = match operations::attestation::generate_config_attestation(
        &tee.state,
        &state.config,
        &nonce,
    )
    .await
    {
        Ok(r) => r,
        Err(e @ AppError::Validation(_)) => return app_error_to_reject(&doc, e),
        Err(e) => {
            tracing::warn!(error = %e, "config attestation: the platform produced no quote");
            return reject_declared(
                &doc,
                config_report_spec::error_codes::EVIDENCE_UNAVAILABLE,
                "the platform did not produce a quote",
            );
        }
    };
    let body = serde_json::json!({
        "configDigestSha384": report.config_digest_sha384,
        "configView": report.config_view,
        "nonce": report.nonce,
        "teeType": tee_type_wire(&report.tee_type),
        "evidence": report.evidence,
        "generatedAt": rfc3339(report.generated_at),
    });
    typed_response::<config_report_spec::Response>(&doc, body)
}

/// `spec/vta/attestation/mnemonic-status/0.1` — the export window's current
/// state (active?, already exported?, entropy still held?, seconds
/// remaining). Super-admin only, same as the export itself; unlike the
/// export it carries no secret, but who is watching the window is still not
/// public.
pub(super) async fn handle_mnemonic_status(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    if let Err(e) = auth.require_super_admin() {
        return app_error_to_reject(&doc, e);
    }
    if let Err(resp) = parse_payload::<mnemonic_status_spec::Payload>(&doc) {
        return resp;
    }
    let Some(guard) = state.tee.as_ref().and_then(|tc| tc.mnemonic_guard.as_ref()) else {
        return reject_declared(
            &doc,
            mnemonic_status_spec::error_codes::NOT_AVAILABLE,
            "mnemonic export not available (TEE mode not active or no KMS bootstrap)",
        );
    };
    let status = guard.status();
    let body = serde_json::json!({
        "windowActive": status.window_active,
        "alreadyExported": status.already_exported,
        "entropyAvailable": status.entropy_available,
        "windowRemainingSecs": status.window_remaining_secs,
    });
    typed_response::<mnemonic_status_spec::Response>(&doc, body)
}

/// `spec/vta/attestation/mnemonic-export/1.0` — release the TEE VTA's seed
/// mnemonic, sealed to the requester, over one of the two paths the
/// specification's *Channel* section defines.
///
/// Entitlement first (super admin holding `key-export`), then the path. Both
/// paths need the request signed by the caller ([`signed_by_the_caller`]):
///
/// - **End-to-end** (DIDComm authcrypt, TSP): `clientDid` is the requester's
///   ephemeral key.
/// - **Signed first boot** (Trust Tasks on HTTPS): a fresh TEE VTA may have
///   no DIDComm or TSP endpoint yet, and the export window is short.
///   Allowed only when `clientDid` is exactly the signing caller's DID, so the
///   words are sealed to a key only the caller holds. A TLS terminator that
///   holds the bearer token cannot sign as the caller, so it can neither make
///   its own request nor swap the recipient in the caller's. The replay guard
///   in the dispatch spine refuses a second use of the document's `id`, and
///   never answers a duplicate with the bundle.
///
/// Every refusal happens before the guard is touched, so the words stay
/// available for a request that qualifies.
pub(super) async fn handle_mnemonic_export(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let payload: mnemonic_export_spec::Payload = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let client_did = payload.client_did.to_string();
    if let Err(e) = entitled(state, auth).await {
        return app_error_to_reject(&doc, e);
    }
    if let Err(outcome) = signed_by_the_caller(state, auth, &doc).await {
        return *outcome;
    }
    if transport::current() != TransportConfidentiality::EndToEnd && client_did != auth.did {
        return app_error_to_reject(
            &doc,
            AppError::Forbidden(
                "the mnemonic export over a hop-by-hop transport is allowed only as a request whose clientDid is the signing caller's own DID, so the words are sealed to a key only the caller holds. Set clientDid to your DID, or send the request over DIDComm or TSP"
                    .into(),
            ),
        );
    }
    let req = BootstrapRequest {
        version: 1,
        client_did,
        nonce: payload.nonce.to_string(),
        label: payload.label.map(|l| l.to_string()),
    };
    match operations::attestation::export_mnemonic_sealed(
        state,
        auth,
        req,
        transport::audit_channel(),
    )
    .await
    {
        Ok(body) => success_response(&doc, body),
        Err(e) => app_error_to_reject(&doc, e),
    }
}

async fn entitled(state: &AppState, auth: &AuthClaims) -> Result<(), AppError> {
    auth.require_super_admin()?;
    operations::keys::ensure_may_export(&state.acl_ks, auth, "attestation/mnemonic-export").await
}

/// The request is the caller's own signed document, addressed to this VTA and
/// fresh: the rules both paths of the specification's *Channel* section share.
///
/// - `proof` present, made for `authentication`, verifying as `issuer`;
/// - `issuer` is the authenticated caller;
/// - `recipient` is this VTA's DID (a VTA without one is refused);
/// - `issuedAt` present and inside the dispatch freshness bound.
///
/// The spine checks the proof, the recipient and freshness too. They are
/// checked again here because the mnemonic export relies on them where no
/// other task does, and a change to the spine must not quietly drop them.
async fn signed_by_the_caller(
    state: &AppState,
    auth: &AuthClaims,
    doc: &TrustTask<Value>,
) -> Result<(), Box<TrustTaskOutcome>> {
    let refuse = |why: &str| {
        Box::new(app_error_to_reject(
            doc,
            AppError::Forbidden(format!("the mnemonic export is refused: {why}")),
        ))
    };
    let Some(proof) = doc.proof.as_ref() else {
        return Err(refuse(
            "the request must carry the caller's own proof; a bearer token alone never              releases the mnemonic",
        ));
    };
    if proof.proof_purpose != "authentication" {
        return Err(refuse(
            "the request's proof must be made for authentication",
        ));
    }
    match vti_common::auth::verify_trust_task_proof_with(doc, &state.trust_task_vm_resolver()).await
    {
        Ok(signer) if doc.issuer.as_deref() == Some(signer.as_str()) && signer == auth.did => {}
        Ok(signer) => {
            tracing::warn!(
                signer = %signer,
                issuer = ?doc.issuer,
                caller = %auth.did,
                "mnemonic export refused: the proof is not the caller's"
            );
            return Err(refuse(
                "the request must be issued and signed by the authenticated caller",
            ));
        }
        Err(e) => {
            tracing::info!(error = %e, cause = ?e.cause(), "mnemonic export proof failed");
            return Err(Box::new(reject_with(
                doc,
                RejectReason::ProofInvalid {
                    reason: e.to_string(),
                },
            )));
        }
    }
    let vta_did = state.config.read().await.vta_did.clone();
    match (vta_did.as_deref(), doc.recipient.as_deref()) {
        (Some(mine), Some(named)) if mine == named => {}
        (None, _) => {
            return Err(refuse(
                "this VTA has no DID to bind the request to. Run `vta setup` first",
            ));
        }
        _ => return Err(refuse("the request's recipient must be this VTA's DID")),
    }
    if let Err(reason) = doc.validate_freshness(chrono::Utc::now(), &super::freshness_policy()) {
        return Err(Box::new(reject_with(doc, reason)));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use serde_json::{Value, json};
    use trust_tasks_rs::{TrustTask, TypeUri};
    use vta_sdk::sealed_transfer::{
        SealedPayloadV1, armor, ed25519_seed_to_x25519_secret, generate_ed25519_keypair,
        open_bundle,
    };

    use super::super::transport::{TransportConfidentiality, with_confidentiality};
    use super::handle_mnemonic_export;
    use crate::auth::AuthClaims;
    use crate::server::TeeContext;
    use crate::tee::mnemonic_guard::MnemonicExportGuard;
    use crate::test_support::{TEST_ADMIN_SEED, did_for_seed, sign_as_for, super_admin_claims};

    /// A test VTA inside a simulated TEE, holding first-boot entropy.
    async fn state_with_guard() -> (
        crate::server::AppState,
        Arc<MnemonicExportGuard>,
        tempfile::TempDir,
    ) {
        let (mut state, dir) = crate::test_support::build_signing_test_app_state().await;
        let guard = Arc::new(MnemonicExportGuard::new([0x42; 32], 60));
        let tee = crate::tee::init_tee(&crate::config::TeeConfig {
            mode: crate::config::TeeMode::Simulated,
            ..Default::default()
        })
        .expect("simulated TEE")
        .expect("simulated TEE state");
        state.tee = Some(TeeContext {
            state: tee,
            mnemonic_guard: Some(guard.clone()),
        });
        (state, guard, dir)
    }

    /// How the request is built: who signs it, whom it seals to.
    struct Request {
        /// The seed of the test identity that issues and signs it; `None`
        /// leaves it unsigned (issued by the test admin).
        signer: Option<u8>,
        client_did: String,
        purpose: &'static str,
    }

    impl Request {
        /// Signed by the test admin, sealed to `client_did`.
        fn signed_to(client_did: String) -> Self {
            Self {
                signer: Some(TEST_ADMIN_SEED[0]),
                client_did,
                purpose: "authentication",
            }
        }
    }

    fn the_admins_did() -> String {
        did_for_seed(TEST_ADMIN_SEED[0]).0
    }

    async fn request_doc(state: &crate::server::AppState, req: &Request) -> TrustTask<Value> {
        let uri: TypeUri = vta_sdk::trust_tasks::TASK_ATTESTATION_MNEMONIC_EXPORT_1_0
            .parse()
            .unwrap();
        let nonce =
            base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, [7u8; 16]);
        let mut doc = TrustTask::new(
            format!("urn:uuid:{}", uuid::Uuid::new_v4()),
            uri,
            json!({ "clientDid": req.client_did, "nonce": nonce }),
        );
        let issuer = did_for_seed(req.signer.unwrap_or(TEST_ADMIN_SEED[0])).0;
        doc.issuer = Some(issuer);
        doc.recipient = state.config.read().await.vta_did.clone();
        doc.issued_at = Some(chrono::Utc::now());
        if let Some(seed) = req.signer {
            sign_as_for(seed, req.purpose, &mut doc);
        }
        doc
    }

    async fn export_over(
        state: &crate::server::AppState,
        confidentiality: TransportConfidentiality,
        auth: &AuthClaims,
        req: &Request,
    ) -> Value {
        let doc = request_doc(state, req).await;
        let outcome = with_confidentiality(
            confidentiality,
            Box::pin(handle_mnemonic_export(state, auth, doc)),
        )
        .await;
        serde_json::from_slice(&outcome.body).expect("a response document")
    }

    /// Open `doc`'s bundle with the Ed25519 `seed`'s X25519 key; assert that no
    /// other key opens it, and return the words.
    fn open_only_with(doc: &Value, seed: &[u8; 32]) -> String {
        let armored = doc["payload"]["bundle"].as_str().expect("a bundle");
        let digest = doc["payload"]["digest"].as_str().expect("a digest");
        let bundles = armor::decode(armored).expect("armor");
        let opened = open_bundle(
            &ed25519_seed_to_x25519_secret(seed),
            &bundles[0],
            Some(digest),
        )
        .expect("the requester opens it");
        let (other_seed, _) = generate_ed25519_keypair();
        assert!(
            open_bundle(
                &ed25519_seed_to_x25519_secret(&other_seed),
                &bundles[0],
                Some(digest)
            )
            .is_err(),
            "no other key opens it"
        );
        match opened.payload {
            SealedPayloadV1::SeedMnemonic(m) => {
                assert_eq!(m.mnemonic.split_whitespace().count(), 24);
                assert!(
                    !doc.to_string().contains(&m.mnemonic),
                    "the words never travel in the clear"
                );
                m.mnemonic.clone()
            }
            other => panic!("expected SeedMnemonic, got {other:?}"),
        }
    }

    fn assert_refused_untouched(doc: &Value, guard: &MnemonicExportGuard, code: &str) {
        assert_eq!(doc["payload"]["code"], code, "{doc}");
        assert!(doc["payload"]["bundle"].is_null(), "{doc}");
        let status = guard.status();
        assert!(
            status.window_active && !status.already_exported,
            "a refused request must not spend the release"
        );
    }

    /// Over an end-to-end channel the mnemonic is released once, sealed to the
    /// requester's ephemeral key: only that key opens it, and the guard is
    /// spent.
    #[tokio::test]
    async fn a_mnemonic_export_over_an_end_to_end_channel_is_sealed_to_the_requester() {
        let (state, guard, _dir) = state_with_guard().await;
        let (seed, client_pub) = generate_ed25519_keypair();
        let req = Request::signed_to(affinidi_crypto::did_key::ed25519_pub_to_did_key(
            &client_pub,
        ));
        let auth = super_admin_claims();
        let doc = export_over(&state, TransportConfidentiality::EndToEnd, &auth, &req).await;
        open_only_with(&doc, &seed);
        assert!(guard.status().already_exported, "one time");

        let again = export_over(&state, TransportConfidentiality::EndToEnd, &auth, &req).await;
        assert!(again["payload"]["bundle"].is_null(), "{again}");
    }

    /// First boot over HTTPS: signed by the caller and sealed to the caller's
    /// own DID, the mnemonic is released, and only the caller's key opens it.
    #[tokio::test]
    async fn a_signed_first_boot_export_over_https_is_sealed_to_the_signer() {
        let (state, guard, _dir) = state_with_guard().await;
        let req = Request::signed_to(the_admins_did());
        let auth = super_admin_claims();
        let doc = export_over(&state, TransportConfidentiality::HopByHop, &auth, &req).await;
        open_only_with(&doc, &TEST_ADMIN_SEED);
        assert!(guard.status().already_exported, "one time");

        let again = export_over(&state, TransportConfidentiality::HopByHop, &auth, &req).await;
        assert!(again["payload"]["bundle"].is_null(), "{again}");
    }

    /// Over HTTPS the seal key must be the signer's: a terminator that could
    /// choose `clientDid` would choose its own.
    #[tokio::test]
    async fn over_https_a_client_did_other_than_the_signer_is_refused() {
        let (state, guard, _dir) = state_with_guard().await;
        let (_seed, client_pub) = generate_ed25519_keypair();
        let req = Request::signed_to(affinidi_crypto::did_key::ed25519_pub_to_did_key(
            &client_pub,
        ));
        let doc = export_over(
            &state,
            TransportConfidentiality::HopByHop,
            &super_admin_claims(),
            &req,
        )
        .await;
        assert_refused_untouched(&doc, &guard, "permissionDenied");
        assert!(doc.to_string().contains("clientDid"), "{doc}");
    }

    /// A bearer token alone never releases the mnemonic, on either path.
    #[tokio::test]
    async fn an_unsigned_request_is_refused() {
        let (state, guard, _dir) = state_with_guard().await;
        for channel in [
            TransportConfidentiality::HopByHop,
            TransportConfidentiality::EndToEnd,
        ] {
            let req = Request {
                signer: None,
                ..Request::signed_to(the_admins_did())
            };
            let doc = export_over(&state, channel, &super_admin_claims(), &req).await;
            assert_refused_untouched(&doc, &guard, "permissionDenied");
            assert!(doc.to_string().contains("proof"), "{doc}");
        }
    }

    /// Signed by someone other than the session's caller: a terminator holding
    /// the caller's token and signing with its own key.
    #[tokio::test]
    async fn a_request_signed_by_another_did_is_refused() {
        let (state, guard, _dir) = state_with_guard().await;
        let intruder = 0x11;
        let req = Request {
            signer: Some(intruder),
            client_did: did_for_seed(intruder).0,
            purpose: "authentication",
        };
        let doc = export_over(
            &state,
            TransportConfidentiality::HopByHop,
            &super_admin_claims(),
            &req,
        )
        .await;
        assert_refused_untouched(&doc, &guard, "permissionDenied");
    }

    /// The request is an operational message, so its proof is made for
    /// `authentication`.
    #[tokio::test]
    async fn a_proof_made_for_another_purpose_is_refused() {
        let (state, guard, _dir) = state_with_guard().await;
        let req = Request {
            purpose: "assertionMethod",
            ..Request::signed_to(the_admins_did())
        };
        let doc = export_over(
            &state,
            TransportConfidentiality::HopByHop,
            &super_admin_claims(),
            &req,
        )
        .await;
        assert_refused_untouched(&doc, &guard, "permissionDenied");
    }

    /// Only a super admin holding `key-export` may take the root. Refused
    /// before the proof or the channel are looked at.
    #[tokio::test]
    async fn a_non_super_admin_is_refused() {
        let (state, guard, _dir) = state_with_guard().await;
        let req = Request::signed_to(the_admins_did());
        let auth = crate::test_support::admin_claims_for_context("ctx-a");
        for channel in [
            TransportConfidentiality::HopByHop,
            TransportConfidentiality::EndToEnd,
        ] {
            let doc = export_over(&state, channel, &auth, &req).await;
            assert_refused_untouched(&doc, &guard, "permissionDenied");
        }
    }

    /// Through the whole dispatch spine over HTTPS: the document is executed
    /// once, and a replay of it is absorbed without the bundle — the replay
    /// record never keeps a secret-bearing response.
    #[tokio::test]
    async fn a_replayed_first_boot_request_is_refused_the_bundle() {
        let (state, guard, _dir) = state_with_guard().await;
        let doc = request_doc(&state, &Request::signed_to(the_admins_did())).await;
        let body = serde_json::to_vec(&doc).expect("envelope");
        let auth = super_admin_claims();
        let dispatch = || {
            super::super::dispatch_trust_task_core(
                &state,
                &auth,
                &body,
                TransportConfidentiality::HopByHop,
            )
        };

        let first = dispatch().await;
        let first_doc: Value = serde_json::from_slice(&first.body).expect("a response");
        assert!(first.status.is_success(), "{first_doc}");
        open_only_with(&first_doc, &TEST_ADMIN_SEED);
        assert!(guard.status().already_exported);

        let replay = dispatch().await;
        assert!(
            !String::from_utf8_lossy(&replay.body).contains("BEGIN VTA SEALED BUNDLE"),
            "a replay must not be answered with the bundle: {}",
            String::from_utf8_lossy(&replay.body)
        );
        assert_ne!(replay.status, axum::http::StatusCode::OK);
    }

    // ── the public reads ────────────────────────────────────────────────

    const NONCE: &str = "8f14e45fceea167a5a36dedd4bea2543a1f0b1c2d3e4f5a6b7c8d9e0f1a2b3c4";

    /// A request as an unidentified verifier sends it: no issuer, no proof,
    /// addressed to this agent.
    async fn anonymous_request(
        state: &crate::server::AppState,
        type_uri: &str,
        payload: Value,
    ) -> Vec<u8> {
        let mut doc = json!({
            "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
            "type": type_uri,
            // The spec leaves it optional; this agent requires it on every
            // document, to bound its duplicate-execution record (SPEC §7.2).
            "issuedAt": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            "payload": payload,
        });
        if let Some(vta_did) = state.config.read().await.vta_did.clone() {
            doc["recipient"] = json!(vta_did);
        }
        serde_json::to_vec(&doc).unwrap()
    }

    /// Dispatch as an anonymous HTTPS caller would reach it.
    async fn dispatch_anonymously(
        state: &crate::server::AppState,
        type_uri: &str,
        payload: Value,
    ) -> Value {
        let body = anonymous_request(state, type_uri, payload).await;
        let out = super::super::dispatch_trust_task_core(
            state,
            &super::super::anonymous_claims(),
            &body,
            TransportConfidentiality::HopByHop,
        )
        .await;
        serde_json::from_slice(&out.body).expect("a JSON document")
    }

    fn error_code(doc: &Value) -> Option<&str> {
        doc.pointer("/payload/code").and_then(Value::as_str)
    }

    /// A verifier with no identity gets the agent's platform, in the agent's
    /// own signed answer, with the registry's spelling of the platform.
    #[tokio::test]
    async fn status_is_answered_to_an_anonymous_caller_and_signed() {
        let (state, _guard, _dir) = state_with_guard().await;
        let resp = dispatch_anonymously(
            &state,
            vta_sdk::trust_tasks::TASK_ATTESTATION_STATUS_0_1,
            json!({}),
        )
        .await;
        assert_eq!(
            resp["type"],
            format!(
                "{}#response",
                vta_sdk::trust_tasks::TASK_ATTESTATION_STATUS_0_1
            ),
            "{resp}"
        );
        assert_eq!(resp["payload"]["teeType"], "simulated", "{resp}");
        assert_eq!(resp["payload"]["detected"], true, "{resp}");
        assert!(
            resp["proof"].is_object(),
            "the answer is the agent's signed document: {resp}"
        );
    }

    /// The evidence binds the verifier's nonce, which comes back with it.
    #[tokio::test]
    async fn a_report_binds_the_verifiers_nonce() {
        let (state, _guard, _dir) = state_with_guard().await;
        let resp = dispatch_anonymously(
            &state,
            vta_sdk::trust_tasks::TASK_ATTESTATION_REPORT_0_1,
            json!({ "nonce": NONCE }),
        )
        .await;
        assert_eq!(resp["payload"]["nonce"], NONCE, "{resp}");
        assert!(
            resp["payload"]["evidence"]
                .as_str()
                .is_some_and(|e| !e.is_empty()),
            "{resp}"
        );
        assert!(resp["payload"]["generatedAt"].is_string(), "{resp}");
        assert!(resp["proof"].is_object(), "{resp}");
    }

    /// There is no nonce-less report: it would be evidence anybody can replay.
    #[tokio::test]
    async fn a_report_without_a_nonce_is_refused() {
        let (state, _guard, _dir) = state_with_guard().await;
        let resp = dispatch_anonymously(
            &state,
            vta_sdk::trust_tasks::TASK_ATTESTATION_REPORT_0_1,
            json!({}),
        )
        .await;
        assert!(
            resp["type"]
                .as_str()
                .is_some_and(|t| t.contains("trust-task-error")),
            "{resp}"
        );
    }

    /// An agent with no attestation provider says so in the specification's
    /// own code, for each of the three reads.
    #[tokio::test]
    async fn no_attestation_provider_is_not_attested() {
        let (state, _dir) = crate::test_support::build_signing_test_app_state().await;
        for (uri, payload) in [
            (vta_sdk::trust_tasks::TASK_ATTESTATION_STATUS_0_1, json!({})),
            (
                vta_sdk::trust_tasks::TASK_ATTESTATION_REPORT_0_1,
                json!({ "nonce": NONCE }),
            ),
            (
                vta_sdk::trust_tasks::TASK_ATTESTATION_CONFIG_REPORT_0_1,
                json!({ "nonce": NONCE }),
            ),
        ] {
            let resp = dispatch_anonymously(&state, uri, payload).await;
            let slug = uri
                .trim_start_matches("https://trusttasks.org/spec/")
                .trim_end_matches("/0.1");
            assert_eq!(
                error_code(&resp),
                Some(format!("{slug}:notAttested").as_str()),
                "{uri}: {resp}"
            );
        }
    }

    /// Only the enclave front-end captures a configuration snapshot at boot;
    /// any other build answers the declared `noConfigSnapshot`.
    #[tokio::test]
    async fn a_config_report_without_a_snapshot_says_so() {
        let (state, _guard, _dir) = state_with_guard().await;
        let resp = dispatch_anonymously(
            &state,
            vta_sdk::trust_tasks::TASK_ATTESTATION_CONFIG_REPORT_0_1,
            json!({ "nonce": NONCE }),
        )
        .await;
        assert_eq!(
            error_code(&resp),
            Some("vta/attestation/config-report:noConfigSnapshot"),
            "{resp}"
        );
    }
}
