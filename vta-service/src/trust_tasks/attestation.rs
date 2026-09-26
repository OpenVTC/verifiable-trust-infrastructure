//! Attestation slice trust-task handlers — the one dispatched task of the
//! family, `spec/vta/attestation/mnemonic-export/1.0`. (`status` and `report`
//! are REST-routed and unauthenticated; see `vta_sdk::trust_tasks`.)

use serde_json::Value;
use trust_tasks_rs::TrustTask;
use vta_sdk::protocols::attestation_management::MnemonicExportBody;
use vta_sdk::sealed_transfer::BootstrapRequest;
use vti_common::error::AppError;

use super::helpers::{TrustTaskOutcome, app_error_to_reject, parse_payload, success_response};
use super::transport::{self, TransportConfidentiality};
use crate::auth::AuthClaims;
use crate::operations;
use crate::server::AppState;

/// `spec/vta/attestation/mnemonic-export/1.0` — release the TEE VTA's seed
/// mnemonic, sealed to the requester, over an end-to-end channel only.
///
/// Entitlement first (super admin holding `key-export`), then the channel:
/// over Trust Tasks on HTTPS the request is refused with `permissionDenied`
/// before the guard is touched, the same rule as the backup export. The
/// bundle is sealed to the requester, but the root mnemonic must not rely on
/// the seal alone: over a hop-by-hop channel the request binding it and the
/// sealed answer both exist wherever TLS terminates.
pub(super) async fn handle_mnemonic_export(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let body: MnemonicExportBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let req = BootstrapRequest {
        version: 1,
        client_did: body.client_did,
        nonce: body.nonce,
        label: body.label,
    };
    if let Err(e) = entitled(state, auth).await {
        return app_error_to_reject(&doc, e);
    }
    if transport::current() != TransportConfidentiality::EndToEnd {
        return app_error_to_reject(
            &doc,
            AppError::Forbidden(
                "the mnemonic export is refused over a hop-by-hop transport: the request and \
                 its sealed answer would exist wherever TLS terminates. Send it over DIDComm \
                 or TSP"
                    .into(),
            ),
        );
    }
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
    use crate::server::TeeContext;
    use crate::tee::mnemonic_guard::MnemonicExportGuard;

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

    async fn export_over(
        state: &crate::server::AppState,
        confidentiality: TransportConfidentiality,
        client_pub: [u8; 32],
    ) -> Value {
        let uri: TypeUri = vta_sdk::trust_tasks::TASK_ATTESTATION_MNEMONIC_EXPORT_1_0
            .parse()
            .unwrap();
        let nonce =
            base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, [7u8; 16]);
        let doc = TrustTask::new(
            "urn:uuid:test",
            uri,
            json!({
                "clientDid": affinidi_crypto::did_key::ed25519_pub_to_did_key(&client_pub),
                "nonce": nonce,
            }),
        );
        let auth = crate::test_support::super_admin_claims();
        let outcome = with_confidentiality(
            confidentiality,
            Box::pin(handle_mnemonic_export(state, &auth, doc)),
        )
        .await;
        serde_json::from_slice(&outcome.body).expect("a response document")
    }

    /// Over Trust Tasks on HTTPS the export is refused with `permissionDenied`
    /// before the guard is touched: the words stay available for an
    /// end-to-end request.
    #[tokio::test]
    async fn a_mnemonic_export_over_https_is_refused() {
        let (state, guard, _dir) = state_with_guard().await;
        let (_seed, client_pub) = generate_ed25519_keypair();
        let doc = export_over(&state, TransportConfidentiality::HopByHop, client_pub).await;
        assert_eq!(doc["payload"]["code"], "permissionDenied", "{doc}");
        assert!(doc.to_string().contains("hop-by-hop"), "{doc}");
        assert!(doc["payload"]["bundle"].is_null(), "{doc}");
        let status = guard.status();
        assert!(status.window_active && !status.already_exported);
    }

    /// Over an end-to-end channel the mnemonic is released once, sealed to the
    /// requester: only the requester's key opens it, and the guard is spent.
    #[tokio::test]
    async fn a_mnemonic_export_over_an_end_to_end_channel_is_sealed_to_the_requester() {
        let (state, guard, _dir) = state_with_guard().await;
        let (seed, client_pub) = generate_ed25519_keypair();
        let doc = export_over(&state, TransportConfidentiality::EndToEnd, client_pub).await;
        let armored = doc["payload"]["bundle"]
            .as_str()
            .expect("a bundle")
            .to_string();
        let digest = doc["payload"]["digest"].as_str().expect("a digest");

        let bundles = armor::decode(&armored).expect("armor");
        let opened = open_bundle(
            &ed25519_seed_to_x25519_secret(&seed),
            &bundles[0],
            Some(digest),
        )
        .expect("the requester opens it");
        match opened.payload {
            SealedPayloadV1::SeedMnemonic(m) => {
                assert_eq!(m.mnemonic.split_whitespace().count(), 24);
                assert!(
                    !doc.to_string().contains(&m.mnemonic),
                    "the words never travel in the clear"
                );
            }
            other => panic!("expected SeedMnemonic, got {other:?}"),
        }
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
        assert!(guard.status().already_exported, "one time");

        let again = export_over(&state, TransportConfidentiality::EndToEnd, client_pub).await;
        assert!(again["payload"]["bundle"].is_null(), "{again}");
    }
}
