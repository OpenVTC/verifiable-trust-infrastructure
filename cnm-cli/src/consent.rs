//! `cnm consent {show,approve,deny}` — answer the community's consent requests.
//!
//! Making or widening an unrestricted administrator needs another unrestricted
//! administrator's consent (VTI-APV-014). The VTC raises a signed
//! `task-consent/request/0.1` for each approver, pushes it to them, and hands
//! the same documents back to the requester in its refusal
//! (`details.consentRequests`). An approver with a `cnm` profile takes the
//! relayed request and signs the decision here. What is shown and the code
//! comparison approval requires are shared with `pnm consent`
//! ([`vta_cli_common::consent_approve`]).

use std::path::{Path, PathBuf};

use clap::Subcommand;
use vta_cli_common::consent_approve;
use vta_cli_common::render::bin_name;
use vta_sdk::session::TransportChoice;
use vta_sdk::task_consent::VerifiedConsentRequest;
use vtc_client::VtcError;

use crate::vtc::{self, VtcTarget};

type CliResult<T> = Result<T, Box<dyn std::error::Error>>;

#[derive(Subcommand)]
pub enum ConsentCommands {
    /// Verify a consent request and show what it asks. Sends nothing.
    Show {
        /// The request: a request document, the requester's refusal body, or
        /// its `details` (`-` reads stdin).
        request: PathBuf,
    },
    /// Approve a consent request, after comparing its match code.
    Approve {
        /// The request: a request document, the requester's refusal body, or
        /// its `details` (`-` reads stdin).
        request: PathBuf,
        /// The code the requester's screen shows. Without it you are asked to
        /// type it; approval never proceeds on a code nobody compared.
        #[arg(long)]
        match_code: Option<String>,
        /// A note recorded with the decision (at most 500 characters).
        #[arg(long)]
        reason: Option<String>,
    },
    /// Deny a consent request. The requester has to ask again.
    Deny {
        /// The request: a request document, the requester's refusal body, or
        /// its `details` (`-` reads stdin).
        request: PathBuf,
        /// Why, recorded with the decision (at most 500 characters).
        #[arg(long)]
        reason: Option<String>,
    },
}

pub async fn run(
    command: ConsentCommands,
    keyring_key: &str,
    target: &VtcTarget,
    transport: TransportChoice,
) -> CliResult<()> {
    match command {
        ConsentCommands::Show { request } => {
            let verified = load(&request, keyring_key, target).await?;
            consent_approve::render(&verified);
            Ok(())
        }
        ConsentCommands::Approve {
            request,
            match_code,
            reason,
        } => {
            let verified = load(&request, keyring_key, target).await?;
            consent_approve::render(&verified);
            consent_approve::confirm_match_code(&verified, match_code.as_deref(), bin_name())?;
            decide(
                &verified,
                true,
                reason.as_deref(),
                keyring_key,
                target,
                transport,
            )
            .await
        }
        ConsentCommands::Deny { request, reason } => {
            let verified = load(&request, keyring_key, target).await?;
            consent_approve::render(&verified);
            decide(
                &verified,
                false,
                reason.as_deref(),
                keyring_key,
                target,
                transport,
            )
            .await
        }
    }
}

async fn load(
    path: &Path,
    keyring_key: &str,
    target: &VtcTarget,
) -> CliResult<VerifiedConsentRequest> {
    let approver = crate::auth::loaded_session(keyring_key)
        .ok_or_else(|| {
            format!(
                "no stored identity for this community profile. Run `{} setup` first.",
                bin_name()
            )
        })?
        .client_did;
    consent_approve::load(path, &approver, &target.did, bin_name()).await
}

/// Send the decision to the VTC as a signed `task-consent/decision/0.1` Trust
/// Task — over TSP when the VTC advertises it, else DIDComm, else a signed
/// document over HTTPS ([`vtc::connect_for_tasks`]); `transport`
/// (`--transport`) pins one. The session is closed on every path out.
async fn decide(
    req: &VerifiedConsentRequest,
    approve: bool,
    reason: Option<&str>,
    keyring_key: &str,
    target: &VtcTarget,
    transport: TransportChoice,
) -> CliResult<()> {
    let decision = req
        .decision(approve, reason)
        .map_err(|e| format!("could not build the decision: {e}"))?;
    let vtc = vtc::connect_for_tasks(keyring_key, target, transport).await?;
    let response = vtc
        .client
        .decide_task_consent(&decision)
        .await
        .map_err(|e| decision_error(e, &vtc.client_did));
    vtc.client.shutdown().await;
    let response = response?;
    consent_approve::report(&response);
    Ok(())
}

/// Turn the VTC's refusal into what the approver should do next.
fn decision_error(err: VtcError, approver: &str) -> Box<dyn std::error::Error> {
    let text = err.to_string();
    // The VTC answers a member's decision `permissionDenied` before it reaches
    // the approver-set check, so it means the same as `notAnApprover` here.
    let hint = if text.contains("permissionDenied") || text.contains("notAnApprover") {
        Some(format!(
            "{approver} is not an unrestricted administrator of this community, so its \
             decision does not count. Only an administrator with community-wide scope can \
             consent."
        ))
    } else {
        consent_approve::refusal_hint(&text, approver)
    };
    match hint {
        Some(hint) => format!("{text}\n  {hint}").into(),
        None => text.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vta_sdk::task_consent::decision;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn did_key_from_seed(seed_byte: u8) -> (String, String) {
        let seed = [seed_byte; 32];
        let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
        let did = format!(
            "did:key:{}",
            vta_sdk::did_key::ed25519_multibase_pubkey(&sk.verifying_key().to_bytes())
        );
        let mut buf = vec![0x80, 0x26];
        buf.extend_from_slice(&seed);
        (did, multibase::encode(multibase::Base::Base58Btc, &buf))
    }

    /// A valid `task-consent/decision/0.1` payload and the digest it echoes.
    fn approve_decision() -> (decision::Payload, String) {
        let mut mh = vec![0x12, 0x20];
        mh.extend_from_slice(&[7u8; 32]);
        let digest = multibase::encode(multibase::Base::Base58Btc, mh);
        let payload: decision::Payload = serde_json::from_value(serde_json::json!({
            "challenge": "a".repeat(32),
            "decision": "approve",
            "payloadDigest": digest,
        }))
        .unwrap();
        (payload, digest)
    }

    /// `cnm consent approve`/`deny` used to authenticate to the VTC with a
    /// bearer-token session ([`vtc::connect`]) — REST only, hard-coded, never
    /// TSP or DIDComm. It now reaches the VTC the same way every other Trust
    /// Task does, over [`vtc::connect_for_tasks`]'s resolved transport: a
    /// pinned `--transport rest` sends the decision as a signed document to
    /// the VTC's Trust Task endpoint, with no bearer challenge/response at
    /// all.
    #[tokio::test]
    async fn the_decision_reaches_the_vtc_as_a_signed_document_not_a_bearer_session() {
        let (vtc_did, _) = did_key_from_seed(0x10);
        let (approver_did, approver_key) = did_key_from_seed(0x11);
        let (decision, digest) = approve_decision();

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/trust-tasks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "urn:uuid:11111111-1111-1111-1111-111111111111",
                "type": "https://trusttasks.org/spec/task-consent/decision/0.1#response",
                "payload": { "status": "granted", "payloadDigest": digest },
            })))
            .mount(&server)
            .await;

        let target = VtcTarget {
            did: vtc_did,
            base: format!("{}/v1", server.uri()),
        };
        let vtc =
            vtc::connect_for_tasks_as(&target, &approver_did, &approver_key, TransportChoice::Rest)
                .await
                .unwrap();
        let response = vtc.client.decide_task_consent(&decision).await.unwrap();
        vtc.client.shutdown().await;
        assert_eq!(response.status, decision::ResponseStatus::Granted);

        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 1, "{requests:?}");
        assert_eq!(requests[0].url.path(), "/v1/trust-tasks");
        assert!(
            requests
                .iter()
                .all(|r| !r.url.path().starts_with("/v1/auth")),
            "the decision must not open a bearer session: {requests:?}"
        );
    }

    /// Every `cnm` command, `consent` included, resolves the VTC's target from
    /// what its own DID document advertises before it ever picks a transport
    /// ([`vtc::resolve_target`]); a plaintext endpoint is refused there, so the
    /// fix does not need — and must not add — a second, weaker check just for
    /// consent.
    #[test]
    fn an_advertised_plaintext_rest_endpoint_is_refused() {
        let doc = serde_json::json!({
            "id": "did:web:vtc.example.com",
            "service": [{
                "id": "did:web:vtc.example.com#vtc-rest",
                "type": vtc_client::REST_SERVICE_TYPE,
                "serviceEndpoint": "http://vtc.example.com/v1",
            }],
        });
        let base = vtc_client::api_base_from_did_document(&doc).expect("advertises a REST base");
        let err = vta_sdk::http::guard_vta_endpoint(
            &base,
            vta_sdk::http::EndpointPolicy::process_default(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("plaintext"), "{err}");
    }
}
