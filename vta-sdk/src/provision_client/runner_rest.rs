//! REST transport for the online provisioning attempt fns.
//!
//! Sibling to [`super::runner_didcomm`] which handles the DIDComm path.
//! Both modules return the shared [`super::event::AttemptOutcome`] so the
//! orchestrator's outcome → event translation is uniform regardless of
//! which wire delivered the credential.

use tokio::sync::mpsc::UnboundedSender;

use crate::client::VtaClient;
use crate::did_key::decode_private_key_multibase;
use crate::provision_integration::http::ProvisionIntegrationRequest;

use super::ask::ProvisionAsk;
use super::diagnostics::{DiagCheck, DiagStatus};
use super::event::{AttemptOutcome, VtaEvent};
use super::intent::{AdminCredentialReply, VtaReply};
use super::result::{admin_rotation_response_to_reply, decode_nonce_b64url, response_to_result};

/// Run the REST leg of the AdminOnly auth check.
///
/// AdminOnly's proof-of-ACL today is "the auth handshake completes" —
/// for REST that's a successful round-trip through the DI-signed
/// [`super::auth_rest::challenge_response_di`]. The returned access token is
/// discarded; the integration's downstream code re-authenticates at
/// runtime via the same flow.
///
/// Mirrors the diagnostic-row emissions of the DIDComm AdminOnly path:
/// `AuthenticateREST` runs, `ListWebvhServers` and `ProvisionIntegration`
/// are `Skipped` with the same operator rationale. AdminOnly has no
/// post-auth phase.
pub(crate) async fn run_rest_attempt_admin_only(
    rest_url: &str,
    vta_did: &str,
    setup_did: String,
    setup_privkey_mb: String,
    tx: &UnboundedSender<VtaEvent>,
) -> AttemptOutcome {
    let _ = tx.send(VtaEvent::CheckStart(DiagCheck::AuthenticateREST));

    match super::auth_rest::challenge_response_di(rest_url, &setup_did, &setup_privkey_mb, vta_did)
        .await
    {
        Ok(_auth) => {
            let _ = tx.send(VtaEvent::CheckDone(
                DiagCheck::AuthenticateREST,
                DiagStatus::Ok(format!("REST auth as {setup_did}")),
            ));
            let _ = tx.send(VtaEvent::CheckDone(
                DiagCheck::ListWebvhServers,
                DiagStatus::Skipped("AdminOnly — no VTA-minted DID so no webvh host needed".into()),
            ));
            let _ = tx.send(VtaEvent::CheckDone(
                DiagCheck::ProvisionIntegration,
                DiagStatus::Skipped(
                    "AdminOnly — setup did:key is the long-term admin credential; \
                     no template render, no rollover"
                        .into(),
                ),
            ));
            AttemptOutcome::Connected(VtaReply::AdminOnly(AdminCredentialReply {
                admin_did: setup_did,
                admin_private_key_mb: setup_privkey_mb,
            }))
        }
        Err(e) => {
            let msg = e.to_string();
            let _ = tx.send(VtaEvent::CheckDone(
                DiagCheck::AuthenticateREST,
                DiagStatus::Failed(msg.clone()),
            ));
            let _ = tx.send(VtaEvent::CheckDone(
                DiagCheck::ListWebvhServers,
                DiagStatus::Skipped("REST auth did not complete".into()),
            ));
            let _ = tx.send(VtaEvent::CheckDone(
                DiagCheck::ProvisionIntegration,
                DiagStatus::Skipped("REST auth did not complete".into()),
            ));
            AttemptOutcome::PreAuthFailure(format!(
                "Could not complete REST authentication against the VTA. \
                 Confirm the `pnm acl create` command ran successfully for \
                 this setup DID and that the VTA's REST endpoint is reachable. \
                 ({msg})"
            ))
        }
    }
}

/// Run the REST FullSetup flow: authenticate, then POST a VP-framed
/// provision-integration request and open the returned sealed bundle.
///
/// Pre-auth boundary: failures inside [`super::auth_rest::challenge_response_di`] or
/// [`VtaClient`] construction → [`AttemptOutcome::PreAuthFailure`]. Once
/// auth completes, any error from the provision RPC, VP signing, nonce
/// decode, or sealed-bundle opening is [`AttemptOutcome::PostAuthFailure`]
/// — the VTA accepted us, so a different transport will reproduce the
/// same outcome.
pub(crate) async fn run_rest_attempt_full_setup(
    rest_url: &str,
    vta_did: &str,
    setup_did: String,
    setup_privkey_mb: String,
    ask: ProvisionAsk,
    tx: &UnboundedSender<VtaEvent>,
) -> AttemptOutcome {
    let _ = tx.send(VtaEvent::CheckStart(DiagCheck::AuthenticateREST));

    let token_result = match super::auth_rest::challenge_response_di(
        rest_url,
        &setup_did,
        &setup_privkey_mb,
        vta_did,
    )
    .await
    {
        Ok(r) => {
            let _ = tx.send(VtaEvent::CheckDone(
                DiagCheck::AuthenticateREST,
                DiagStatus::Ok(format!("REST auth as {setup_did}")),
            ));
            r
        }
        Err(e) => {
            let msg = e.to_string();
            let _ = tx.send(VtaEvent::CheckDone(
                DiagCheck::AuthenticateREST,
                DiagStatus::Failed(msg.clone()),
            ));
            let _ = tx.send(VtaEvent::CheckDone(
                DiagCheck::ListWebvhServers,
                DiagStatus::Skipped("REST auth did not complete".into()),
            ));
            let _ = tx.send(VtaEvent::CheckDone(
                DiagCheck::ProvisionIntegration,
                DiagStatus::Skipped("REST auth did not complete".into()),
            ));
            return AttemptOutcome::PreAuthFailure(format!(
                "Could not complete REST authentication against the VTA. \
                     Confirm the `pnm acl create` command ran successfully for \
                     this setup DID and that the VTA's REST endpoint is reachable. \
                     ({msg})"
            ));
        }
    };

    let client = VtaClient::new(rest_url);
    client.set_token_async(token_result.access_token).await;

    let _ = tx.send(VtaEvent::CheckDone(
        DiagCheck::ListWebvhServers,
        DiagStatus::Skipped(
            "REST FullSetup — picker not run; using operator-supplied template vars".into(),
        ),
    ));

    let _ = tx.send(VtaEvent::CheckStart(DiagCheck::ProvisionIntegration));

    // Past the auth boundary: every failure below is post-auth.
    let seed = match decode_private_key_multibase(&setup_privkey_mb) {
        Ok(s) => s,
        Err(e) => {
            let msg = e.to_string();
            let _ = tx.send(VtaEvent::CheckDone(
                DiagCheck::ProvisionIntegration,
                DiagStatus::Failed(msg.clone()),
            ));
            return AttemptOutcome::PostAuthFailure(format!("setup key decode failed: {msg}"));
        }
    };
    let vp = match ask.to_builder().sign_with(&seed, &setup_did).await {
        Ok(v) => v,
        Err(e) => {
            let msg = e.to_string();
            let _ = tx.send(VtaEvent::CheckDone(
                DiagCheck::ProvisionIntegration,
                DiagStatus::Failed(msg.clone()),
            ));
            return AttemptOutcome::PostAuthFailure(format!("VP signing failed: {msg}"));
        }
    };
    let nonce = match decode_nonce_b64url(&vp.nonce) {
        Ok(n) => n,
        Err(e) => {
            let _ = tx.send(VtaEvent::CheckDone(
                DiagCheck::ProvisionIntegration,
                DiagStatus::Failed(e.clone()),
            ));
            return AttemptOutcome::PostAuthFailure(format!("nonce decode failed: {e}"));
        }
    };

    let req = ProvisionIntegrationRequest {
        request: vp,
        context: Some(ask.context.clone()),
        assertion: None,
        vc_validity_seconds: None,
        create_context: false,
    };
    let response = match client.provision_integration(req).await {
        Ok(r) => r,
        Err(e) => {
            let msg = e.to_string();
            let _ = tx.send(VtaEvent::CheckDone(
                DiagCheck::ProvisionIntegration,
                DiagStatus::Failed(msg.clone()),
            ));
            return AttemptOutcome::PostAuthFailure(format!(
                "VTA rejected the REST provision request. ({msg})"
            ));
        }
    };

    let result = match response_to_result(&seed, nonce, response) {
        Ok(r) => r,
        Err(e) => {
            let msg = e.to_string();
            let _ = tx.send(VtaEvent::CheckDone(
                DiagCheck::ProvisionIntegration,
                DiagStatus::Failed(msg.clone()),
            ));
            return AttemptOutcome::PostAuthFailure(format!(
                "could not open returned bundle: {msg}"
            ));
        }
    };

    let _ = tx.send(VtaEvent::CheckDone(
        DiagCheck::ProvisionIntegration,
        DiagStatus::Ok(format!(
            "admin DID: {} (rolled: {}), integration DID: {}",
            result.admin_did(),
            result.summary.admin_rolled_over,
            result.integration_did().unwrap_or("(none)"),
        )),
    ));

    AttemptOutcome::Connected(VtaReply::Full(Box::new(result)))
}

/// Run the REST AdminRotated flow: authenticate, then POST a VP-framed
/// `BootstrapAsk::AdminRotation` request and open the returned sealed
/// `SealedPayloadV1::AdminRotation` bundle.
///
/// Mirrors [`run_rest_attempt_full_setup`] for the admin-only-rotation
/// intent. Same pre-auth / post-auth boundary semantics. Emits the same
/// diagnostic rows so consumer UIs don't need to fork their event
/// handling between the two flows; `ListWebvhServers` is `Skipped` here
/// because no integration DID is minted.
pub(crate) async fn run_rest_attempt_admin_rotated(
    rest_url: &str,
    vta_did: &str,
    setup_did: String,
    setup_privkey_mb: String,
    ask: ProvisionAsk,
    tx: &UnboundedSender<VtaEvent>,
) -> AttemptOutcome {
    let _ = tx.send(VtaEvent::CheckStart(DiagCheck::AuthenticateREST));

    let token_result = match super::auth_rest::challenge_response_di(
        rest_url,
        &setup_did,
        &setup_privkey_mb,
        vta_did,
    )
    .await
    {
        Ok(r) => {
            let _ = tx.send(VtaEvent::CheckDone(
                DiagCheck::AuthenticateREST,
                DiagStatus::Ok(format!("REST auth as {setup_did}")),
            ));
            r
        }
        Err(e) => {
            let msg = e.to_string();
            let _ = tx.send(VtaEvent::CheckDone(
                DiagCheck::AuthenticateREST,
                DiagStatus::Failed(msg.clone()),
            ));
            let _ = tx.send(VtaEvent::CheckDone(
                DiagCheck::ListWebvhServers,
                DiagStatus::Skipped("REST auth did not complete".into()),
            ));
            let _ = tx.send(VtaEvent::CheckDone(
                DiagCheck::ProvisionIntegration,
                DiagStatus::Skipped("REST auth did not complete".into()),
            ));
            return AttemptOutcome::PreAuthFailure(format!(
                "Could not complete REST authentication against the VTA. \
                     Confirm the `pnm acl create` command ran successfully for \
                     this setup DID and that the VTA's REST endpoint is reachable. \
                     ({msg})"
            ));
        }
    };

    let client = VtaClient::new(rest_url);
    client.set_token_async(token_result.access_token).await;

    let _ = tx.send(VtaEvent::CheckDone(
        DiagCheck::ListWebvhServers,
        DiagStatus::Skipped(
            "AdminRotated — no integration DID minted so no webvh host needed".into(),
        ),
    ));

    let _ = tx.send(VtaEvent::CheckStart(DiagCheck::ProvisionIntegration));

    // Past the auth boundary: every failure below is post-auth.
    let seed = match decode_private_key_multibase(&setup_privkey_mb) {
        Ok(s) => s,
        Err(e) => {
            let msg = e.to_string();
            let _ = tx.send(VtaEvent::CheckDone(
                DiagCheck::ProvisionIntegration,
                DiagStatus::Failed(msg.clone()),
            ));
            return AttemptOutcome::PostAuthFailure(format!("setup key decode failed: {msg}"));
        }
    };
    let vp = match ask.to_builder().sign_with(&seed, &setup_did).await {
        Ok(v) => v,
        Err(e) => {
            let msg = e.to_string();
            let _ = tx.send(VtaEvent::CheckDone(
                DiagCheck::ProvisionIntegration,
                DiagStatus::Failed(msg.clone()),
            ));
            return AttemptOutcome::PostAuthFailure(format!("VP signing failed: {msg}"));
        }
    };
    let nonce = match decode_nonce_b64url(&vp.nonce) {
        Ok(n) => n,
        Err(e) => {
            let _ = tx.send(VtaEvent::CheckDone(
                DiagCheck::ProvisionIntegration,
                DiagStatus::Failed(e.clone()),
            ));
            return AttemptOutcome::PostAuthFailure(format!("nonce decode failed: {e}"));
        }
    };

    let req = ProvisionIntegrationRequest {
        request: vp,
        context: Some(ask.context.clone()),
        assertion: None,
        vc_validity_seconds: None,
        create_context: false,
    };
    let response = match client.provision_integration(req).await {
        Ok(r) => r,
        Err(e) => {
            let msg = e.to_string();
            let _ = tx.send(VtaEvent::CheckDone(
                DiagCheck::ProvisionIntegration,
                DiagStatus::Failed(msg.clone()),
            ));
            return AttemptOutcome::PostAuthFailure(format!(
                "VTA rejected the REST AdminRotation request. ({msg})"
            ));
        }
    };

    let reply = match admin_rotation_response_to_reply(&seed, nonce, response) {
        Ok(r) => r,
        Err(e) => {
            let msg = e.to_string();
            let _ = tx.send(VtaEvent::CheckDone(
                DiagCheck::ProvisionIntegration,
                DiagStatus::Failed(msg.clone()),
            ));
            return AttemptOutcome::PostAuthFailure(format!(
                "could not open returned AdminRotation bundle: {msg}"
            ));
        }
    };

    let _ = tx.send(VtaEvent::CheckDone(
        DiagCheck::ProvisionIntegration,
        DiagStatus::Ok(format!("admin DID rotated: {}", reply.admin_did)),
    ));

    AttemptOutcome::Connected(VtaReply::AdminOnly(reply))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provision_client::setup_key::EphemeralSetupKey;
    use serde_json::json;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// `did:key` is self-resolving (the verification key is encoded in
    /// the identifier itself), so the unit test stays network-free.
    fn test_vta_did_key() -> String {
        EphemeralSetupKey::generate().unwrap().did
    }

    fn drain(rx: &mut tokio::sync::mpsc::UnboundedReceiver<VtaEvent>) -> Vec<VtaEvent> {
        let mut out = Vec::new();
        while let Ok(ev) = rx.try_recv() {
            out.push(ev);
        }
        out
    }

    #[tokio::test]
    async fn admin_only_returns_connected_on_successful_auth() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/auth/challenge"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "challenge": "test-challenge",
                "sessionId": "test-session",
                "expiresAt": "2026-12-31T23:59:59Z"
            })))
            .mount(&server)
            .await;
        // Canonical authenticate response shape: { session, tokens }.
        Mock::given(method("POST"))
            .and(path("/auth/"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "session": {
                    "id": "test-session",
                    "subject": "did:example:caller",
                    "issuedAt": "2026-05-23T10:00:00Z",
                    "expiresAt": "2026-05-23T10:15:00Z",
                    "amr": ["did"],
                    "acr": "aal1"
                },
                "tokens": {
                    "accessToken": "test-access-token",
                    "tokenType": "Bearer",
                    "expiresIn": 900
                }
            })))
            .mount(&server)
            .await;

        let key = EphemeralSetupKey::generate().unwrap();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();

        let outcome = run_rest_attempt_admin_only(
            &server.uri(),
            &test_vta_did_key(),
            key.did.clone(),
            key.private_key_multibase().to_string(),
            &tx,
        )
        .await;

        match outcome {
            AttemptOutcome::Connected(VtaReply::AdminOnly(reply)) => {
                assert_eq!(reply.admin_did, key.did);
                assert_eq!(reply.admin_private_key_mb, key.private_key_multibase());
            }
            other => panic!("expected Connected/AdminOnly, got {other:?}"),
        }

        drop(tx);
        let events = drain(&mut rx);
        assert!(matches!(
            events.first(),
            Some(VtaEvent::CheckStart(DiagCheck::AuthenticateREST))
        ));
        let mut saw_auth_ok = false;
        let mut saw_provision_skip = false;
        for ev in &events {
            if let VtaEvent::CheckDone(DiagCheck::AuthenticateREST, DiagStatus::Ok(_)) = ev {
                saw_auth_ok = true;
            }
            if let VtaEvent::CheckDone(DiagCheck::ProvisionIntegration, DiagStatus::Skipped(_)) = ev
            {
                saw_provision_skip = true;
            }
        }
        assert!(saw_auth_ok, "AuthenticateREST did not transition to Ok");
        assert!(
            saw_provision_skip,
            "ProvisionIntegration did not get a Skipped row"
        );
    }

    #[tokio::test]
    async fn admin_only_returns_pre_auth_failure_on_401() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/auth/challenge"))
            .respond_with(ResponseTemplate::new(401).set_body_string("ACL not found"))
            .mount(&server)
            .await;

        let key = EphemeralSetupKey::generate().unwrap();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();

        let outcome = run_rest_attempt_admin_only(
            &server.uri(),
            &test_vta_did_key(),
            key.did.clone(),
            key.private_key_multibase().to_string(),
            &tx,
        )
        .await;

        match outcome {
            AttemptOutcome::PreAuthFailure(reason) => {
                assert!(
                    reason.contains("REST authentication"),
                    "operator-facing message missing REST mention: {reason}"
                );
                assert!(
                    reason.contains("401") || reason.contains("ACL not found"),
                    "operator-facing message did not include upstream detail: {reason}"
                );
            }
            other => panic!("expected PreAuthFailure, got {other:?}"),
        }

        drop(tx);
        let events = drain(&mut rx);
        let mut saw_auth_failed = false;
        for ev in &events {
            if let VtaEvent::CheckDone(DiagCheck::AuthenticateREST, DiagStatus::Failed(_)) = ev {
                saw_auth_failed = true;
            }
        }
        assert!(
            saw_auth_failed,
            "AuthenticateREST did not transition to Failed"
        );
    }

    #[tokio::test]
    async fn full_setup_returns_pre_auth_failure_on_auth_401() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/auth/challenge"))
            .respond_with(ResponseTemplate::new(401).set_body_string("ACL not found"))
            .mount(&server)
            .await;

        let key = EphemeralSetupKey::generate().unwrap();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let ask = ProvisionAsk::didcomm_mediator("mediator", "https://mediator.example.com");

        let outcome = run_rest_attempt_full_setup(
            &server.uri(),
            &test_vta_did_key(),
            key.did.clone(),
            key.private_key_multibase().to_string(),
            ask,
            &tx,
        )
        .await;

        match outcome {
            AttemptOutcome::PreAuthFailure(reason) => {
                assert!(
                    reason.contains("REST authentication"),
                    "operator-facing message missing REST mention: {reason}"
                );
            }
            other => panic!("expected PreAuthFailure, got {other:?}"),
        }

        drop(tx);
        let events = drain(&mut rx);
        let mut saw_provision_skipped = false;
        for ev in &events {
            if let VtaEvent::CheckDone(DiagCheck::ProvisionIntegration, DiagStatus::Skipped(_)) = ev
            {
                saw_provision_skipped = true;
            }
        }
        assert!(
            saw_provision_skipped,
            "ProvisionIntegration row should be Skipped after pre-auth failure"
        );
    }

    #[tokio::test]
    async fn full_setup_returns_post_auth_failure_on_provision_400() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/auth/challenge"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "challenge": "test-challenge",
                "sessionId": "test-session",
                "expiresAt": "2026-12-31T23:59:59Z"
            })))
            .mount(&server)
            .await;
        // Canonical authenticate response shape: { session, tokens }.
        Mock::given(method("POST"))
            .and(path("/auth/"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "session": {
                    "id": "test-session",
                    "subject": "did:example:caller",
                    "issuedAt": "2026-05-23T10:00:00Z",
                    "expiresAt": "2026-05-23T10:15:00Z",
                    "amr": ["did"],
                    "acr": "aal1"
                },
                "tokens": {
                    "accessToken": "test-access-token",
                    "tokenType": "Bearer",
                    "expiresIn": 900
                }
            })))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/bootstrap/provision-integration"))
            .respond_with(ResponseTemplate::new(400).set_body_string("template render rejected"))
            .mount(&server)
            .await;

        let key = EphemeralSetupKey::generate().unwrap();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let ask = ProvisionAsk::didcomm_mediator("mediator", "https://mediator.example.com");

        let outcome = run_rest_attempt_full_setup(
            &server.uri(),
            &test_vta_did_key(),
            key.did.clone(),
            key.private_key_multibase().to_string(),
            ask,
            &tx,
        )
        .await;

        match outcome {
            AttemptOutcome::PostAuthFailure(reason) => {
                assert!(
                    reason.contains("REST provision request"),
                    "operator-facing message missing provision mention: {reason}"
                );
            }
            other => panic!("expected PostAuthFailure, got {other:?}"),
        }

        drop(tx);
        let events = drain(&mut rx);
        let mut saw_auth_ok = false;
        let mut saw_provision_failed = false;
        for ev in &events {
            if let VtaEvent::CheckDone(DiagCheck::AuthenticateREST, DiagStatus::Ok(_)) = ev {
                saw_auth_ok = true;
            }
            if let VtaEvent::CheckDone(DiagCheck::ProvisionIntegration, DiagStatus::Failed(_)) = ev
            {
                saw_provision_failed = true;
            }
        }
        assert!(
            saw_auth_ok,
            "AuthenticateREST should be Ok before the provision call fails"
        );
        assert!(
            saw_provision_failed,
            "ProvisionIntegration row should be Failed after the 400"
        );
    }
}
