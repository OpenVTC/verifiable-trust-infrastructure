//! Attestation slice trust-task handlers — the one dispatched task of the
//! family, `spec/vta/attestation/mnemonic-export/1.0`. (`status` and `report`
//! are REST-routed and unauthenticated; see `vta_sdk::trust_tasks`.)

use serde_json::Value;
use trust_tasks_rs::specs::vta::attestation::mnemonic_export::v1_0 as mnemonic_export_spec;
use trust_tasks_rs::{RejectReason, TrustTask};
use vta_sdk::sealed_transfer::BootstrapRequest;
use vti_common::error::AppError;

use super::helpers::{
    TrustTaskOutcome, app_error_to_reject, parse_payload, reject_with, success_response,
};
use super::transport::{self, TransportConfidentiality};
use crate::auth::AuthClaims;
use crate::operations;
use crate::server::AppState;

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
                "the mnemonic export over a hop-by-hop transport is allowed only as a request                  whose clientDid is the signing caller's own DID, so the words are sealed to a                  key only the caller holds. Set clientDid to your DID, or send the request over                  DIDComm or TSP"
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
}
