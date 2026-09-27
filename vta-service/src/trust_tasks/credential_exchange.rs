// Handlers share the `Result<_, Response>` shape via `parse_payload`; the
// Response is owned and emitted on the same stack frame (see `vault.rs`).
#![allow(clippy::result_large_err)]

//! Credential-exchange slice — the holder's side of the exchange, and the
//! holder operator's deferred-presentation approval surface.
//!
//! # The exchange
//!
//! Issuance runs `offer → request → issue`, presentation `query → present`.
//! Each step is its own Trust Task, and none of the five defines a response
//! document: the answer is the **next task in the thread**, which this VTA
//! pushes to the counterparty over whichever transport both speak
//! ([`push_step`], over `crate::messaging::push`). The three steps a
//! counterparty sends here are dispatched on the spine like any other task:
//!
//! - [`handle_offer`] — answer an issuer's offer with a `request` carrying a
//!   key-binding proof by the configured `credential_holder_did`.
//! - [`handle_issue`] — deposit a delivered credential into the vault.
//! - [`handle_query`] — answer a verifier's DCQL query with a `present`, or defer
//!   it for the operator when the verifier is not trusted.
//!
//! They used to be bare DIDComm messages typed as their task URI, served beside
//! the envelope. `bindings/didcomm/0.2` §2 requires a consumer to refuse that
//! carriage, no other transport could carry it, and none of the spine's proof,
//! freshness, recipient or replay checks applied; the `query` arm had already
//! been deleted for exactly that (#1739), leaving a holder that could not
//! answer a verifier at all.
//!
//! **A counterparty is not an operator.** An issuer or verifier holds no ACL
//! entry here, so the envelope's ACL check would turn it away before any of
//! this ran. [`is_counterparty_task`] is the carve-out, beside the ceremony
//! one: these three dispatch on a zero-authority claim when the ACL does not
//! know the sender, and every handler acts with **this VTA's own authority**,
//! gated exactly as before — an offer only when `credential_holder_did` is
//! configured, a presentation only to a trusted verifier or after the
//! operator approves.
//!
//! # The approval surface
//!
//! When a verifier the holder hasn't pre-trusted sends a
//! `credential-exchange/query`, the VTA **defers** it: it persists a
//! `pending-present:` record ([`handle_query`]). These three tasks are the
//! holder operator's out-of-band surface over that backlog:
//!
//! - `pending-list/1.0` — list the actionable deferrals.
//! - `pending-approve/1.0` — approve one and **re-present**: returns the
//!   `vp_token`, and pushes it to the verifier on the query's thread.
//! - `pending-deny/1.0` — deny one (no presentation is made).
//!
//! All three are **super-admin only**: the credentials presented are the VTA's
//! own, so authorization mirrors the autonomous flow's "own authority"
//! ([`handle_query`]). The approve op's re-present resolves the holder key
//! through the same `auth`-gated path as a trusted-verifier present, so the
//! caller's super-admin claims authorize key access and give correct audit
//! attribution.

use super::helpers::TrustTaskOutcome;
use serde_json::Value;
use trust_tasks_rs::TrustTask;
use vta_sdk::protocols::credential_exchange::{
    self as cx, IssueBody, OfferBody, PendingApproveBody, PendingDenyBody, PendingDenyResponse,
    PendingListResponse, PendingPresentationSummary, QueryBody, RequestedCredentialSummary,
};

use crate::acl::Role;
use crate::audit::audit;
use crate::auth::AuthClaims;
use crate::error::AppError;
use crate::operations::credential_exchange::{
    ConsentPolicy, PresentOutcome, RequestedCredential, approve_pending_presentation,
    build_credential_request_for_offer, defer_presentation, deny_pending_presentation, pending,
    present_query, receive_issued_credential,
};
use crate::server::AppState;

use super::helpers::{acknowledge, app_error_to_reject, parse_payload, silence, success_response};
#[cfg(any(feature = "didcomm", feature = "tsp"))]
use super::idempotency::IDEMPOTENCY_KEY_MEMBER;

/// How long a pushed exchange step may take to be delivered. A counterparty
/// that misses one can ask again: an issuer re-offers, a verifier re-queries.
const EXCHANGE_DELIVER_BY: std::time::Duration = std::time::Duration::from_secs(24 * 3600);

/// The steps a **counterparty** — an issuer, a verifier — sends this holder.
/// They carry no request for this VTA's operator authority: each handler acts
/// with the VTA's own, under its own gate, so the envelope lets a sender the
/// ACL does not know dispatch them on a zero-authority claim
/// (`messaging::auth::auth_for_trust_task_envelope`).
pub(crate) fn is_counterparty_task(type_uri: &str) -> bool {
    type_uri == cx::OFFER || type_uri == cx::ISSUE || type_uri == cx::QUERY
}

/// The thread a step belongs to: its `threadId`, or — for a step that opens a
/// thread — its own `id`.
fn thread_of(doc: &TrustTask<Value>) -> String {
    doc.thread_id.clone().unwrap_or_else(|| doc.id.clone())
}

/// The claims this VTA acts under when it answers a counterparty: its **own**
/// authority over its own contexts, never the counterparty's. Holder-key
/// resolution is still ACL-gated to the subject's context.
async fn own_authority(state: &AppState) -> AuthClaims {
    AuthClaims {
        did: state
            .config
            .read()
            .await
            .vta_did
            .clone()
            .unwrap_or_else(|| "vta:self".into()),
        role: Role::Admin,
        allowed_contexts: Vec::new(),
        ..Default::default()
    }
}

/// Sign `payload` as a `type_uri` step from this VTA to `recipient`, on
/// `thread`, and push it over whichever transport both speak. Returns the
/// pushed document's `id`.
///
/// Signed with the operational key under `authentication` (VTI-KEY-106): this
/// VTA composed it, and the counterparty binds that proof to the sender.
#[cfg_attr(
    not(any(feature = "didcomm", feature = "tsp")),
    allow(unused_variables)
)]
async fn push_step(
    state: &AppState,
    recipient: &str,
    type_uri: &str,
    payload: Value,
    thread: &str,
) -> Result<String, AppError> {
    #[cfg(any(feature = "didcomm", feature = "tsp"))]
    {
        let vta_did = state
            .config
            .read()
            .await
            .vta_did
            .clone()
            .ok_or_else(|| AppError::Internal("VTA DID not configured".into()))?;
        let mut doc =
            vti_common::capability_client::build_document(&vta_did, recipient, type_uri, payload);
        doc.thread_id = Some(thread.to_string());
        let id = doc.id.clone();
        // One key for every attempt at this step (VTI-OPS-064). The push
        // engine issues a new attempt — a fresh `id` — when the step outlives
        // its acceptance window, and a step whose repeat leaves a second
        // artefact (`issue` deposits a credential, `request` asks for one) must
        // then run once at the counterparty however many attempts reach it.
        doc.extra.insert(
            IDEMPOTENCY_KEY_MEMBER.to_string(),
            Value::String(id.clone()),
        );
        let mut doc_value = serde_json::to_value(&doc)
            .map_err(|e| AppError::Internal(format!("serialise {type_uri} document: {e}")))?;
        if !super::sign_outbound_request(state, &mut doc_value).await {
            return Err(AppError::Internal(format!(
                "{type_uri} could not be signed, so it was not sent"
            )));
        }
        crate::messaging::push::push_trust_task(state, recipient, doc_value, EXCHANGE_DELIVER_BY)
            .await?;
        Ok(id)
    }
    #[cfg(not(any(feature = "didcomm", feature = "tsp")))]
    Err(AppError::Internal(format!(
        "{type_uri} cannot be sent: this build has no messaging transport"
    )))
}

/// `credential-exchange/offer/0.1` — an issuer offered a credential; answer
/// with a `request` on the offer's thread.
///
/// **Opt-in**: the VTA accepts an offer only when `credential_holder_did` is
/// configured — the registered VTA-managed holder identity the new credential
/// binds to. With it unset (the default) an unsolicited offer is declined; the
/// VTA does not request credentials from arbitrary issuers. When set, it signs
/// an `openid4vci-proof+jwt` bound to that holder key and the offer's issuer and
/// pre-authorized code, and pushes `request` back to the issuer, whose `issue`
/// reaches [`handle_issue`].
pub(super) async fn handle_offer(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let body: OfferBody = match parse_payload(&doc) {
        Ok(b) => b,
        Err(resp) => return resp,
    };
    let issuer = auth.did.clone();

    let Some(subject_did) = state.config.read().await.credential_holder_did.clone() else {
        tracing::info!(
            from = %issuer,
            "credential offer received but no credential_holder_did configured — declining"
        );
        return app_error_to_reject(
            &doc,
            AppError::Forbidden(
                "this VTA does not accept unsolicited credential offers \
                 (no credential_holder_did configured)"
                    .into(),
            ),
        );
    };

    let request = match build_credential_request_for_offer(
        &state.keys_ks,
        &state.contexts_ks,
        &state.seed_store,
        &state.audit_sink,
        &own_authority(state).await,
        &body.credential_offer,
        &subject_did,
        chrono::Utc::now(),
    )
    .await
    {
        Ok(r) => r,
        Err(e) => return app_error_to_reject(&doc, e),
    };
    let payload = match serde_json::to_value(&request) {
        Ok(v) => v,
        Err(e) => {
            return app_error_to_reject(
                &doc,
                AppError::Internal(format!("request serialise: {e}")),
            );
        }
    };
    if let Err(e) = push_step(state, &issuer, cx::REQUEST, payload, &thread_of(&doc)).await {
        return app_error_to_reject(&doc, e);
    }
    tracing::info!(from = %issuer, subject = %subject_did, "answered credential offer with a request");
    acknowledge(&doc)
}

/// `credential-exchange/issue/0.1` — a credential delivered to this holder, as
/// the answer to its `request` or unprompted (a community admitting it).
///
/// The document's proven signer is the issuer that delivered it, and is
/// recorded as the stored credential's provenance. There is no ACL gate — the
/// issuer is a counterparty, not an operator — and the credential's own issuer
/// signature, not the delivery, is what the vault trusts it by.
pub(super) async fn handle_issue(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let body: IssueBody = match parse_payload(&doc) {
        Ok(b) => b,
        Err(resp) => return resp,
    };
    let stored = match receive_issued_credential(
        &state.vault_ks,
        &body,
        state.did_resolver.as_ref(),
        Some(auth.did.clone()),
        chrono::Utc::now(),
    )
    .await
    {
        Ok(s) => s,
        Err(e) => return app_error_to_reject(&doc, e),
    };
    tracing::info!(
        credential_id = %stored.id,
        format = ?stored.format,
        from = %auth.did,
        "received issued credential into vault"
    );
    acknowledge(&doc)
}

/// `credential-exchange/query/0.1` — a verifier asks this holder for a
/// presentation.
///
/// The VTA presents its **own** held credentials with its own authority; the
/// **consent policy** (trusted verifiers from config) is the gate.
/// `present_query` does match → ACL-gated holder-key resolution →
/// consent-policy → present. A trusted verifier gets a `present` pushed back on
/// the query's thread. Any other **defers**: the query is persisted as a
/// pending presentation keyed by its thread, for the operator to approve
/// (`pending-approve`, which then pushes the `present`) or deny. Nothing goes
/// back on the transport for a deferral — it is accepted but not performed, so
/// an acknowledgement would claim too much, and silence says nothing
/// (SPEC §4.4.2 item 3).
pub(super) async fn handle_query(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let body: QueryBody = match parse_payload(&doc) {
        Ok(b) => b,
        Err(resp) => return resp,
    };
    let verifier_did = auth.did.clone();
    let thread = thread_of(&doc);
    let policy = ConsentPolicy::trusting(
        state
            .config
            .read()
            .await
            .trusted_presentation_verifiers
            .clone(),
    );

    let outcome = match present_query(
        &state.vault_ks,
        &state.keys_ks,
        &state.contexts_ks,
        &state.seed_store,
        &state.audit_sink,
        &own_authority(state).await,
        &body,
        &verifier_did,
        &policy,
        state.status_list_resolver.as_deref(),
        chrono::Utc::now(),
    )
    .await
    {
        Ok(o) => o,
        Err(e) => return app_error_to_reject(&doc, e),
    };

    match outcome {
        PresentOutcome::Presented(present) => {
            let payload = match serde_json::to_value(&present) {
                Ok(v) => v,
                Err(e) => {
                    return app_error_to_reject(
                        &doc,
                        AppError::Internal(format!("present serialise: {e}")),
                    );
                }
            };
            if let Err(e) = push_step(state, &verifier_did, cx::PRESENT, payload, &thread).await {
                return app_error_to_reject(&doc, e);
            }
            tracing::info!(verifier = %verifier_did, "presented a vp_token");
            acknowledge(&doc)
        }
        PresentOutcome::ConsentRequired {
            requested, purpose, ..
        } => {
            let requested_count = requested.len();
            if let Err(e) = defer_presentation(
                &state.vault_ks,
                &thread,
                &verifier_did,
                requested,
                &body,
                chrono::Utc::now(),
            )
            .await
            {
                return app_error_to_reject(&doc, e);
            }
            tracing::info!(
                verifier = %verifier_did,
                approval_id = %thread,
                requested = requested_count,
                %purpose,
                "credential query deferred — holder consent required (pending approval persisted)"
            );
            silence()
        }
    }
}

/// Project an internal pending record into the approver-facing wire summary.
/// Drops the full DCQL `query` (an internal re-present detail).
fn summarize(record: pending::PendingPresentation) -> PendingPresentationSummary {
    PendingPresentationSummary {
        id: record.id,
        verifier_did: record.verifier_did,
        requested: record
            .requested
            .into_iter()
            .map(summarize_requested)
            .collect(),
        purpose: record.purpose,
        created_at: record.created_at,
        expires_at: record.expires_at,
    }
}

fn summarize_requested(r: RequestedCredential) -> RequestedCredentialSummary {
    RequestedCredentialSummary {
        credential_query_id: r.credential_query_id,
        credential_id: r.credential_id,
        claims: r.claims,
    }
}

/// `credential-exchange/pending-list/1.0` — list the actionable deferred
/// presentations (status `Pending`, not yet expired). Super-admin only.
pub(super) async fn handle_pending_list(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    if let Err(e) = auth.require_super_admin() {
        return app_error_to_reject(&doc, e);
    }

    let records = match pending::list(&state.vault_ks).await {
        Ok(r) => r,
        Err(e) => return app_error_to_reject(&doc, e),
    };

    // Only surface what the holder can still act on — terminal records are
    // deleted (delete-on-terminal), and approval refuses an expired deferral.
    let now = chrono::Utc::now();
    let pending_out: Vec<PendingPresentationSummary> = records
        .into_iter()
        .filter(|r| r.status == pending::PendingStatus::Pending && r.expires_at > now)
        .map(summarize)
        .collect();

    audit!(
        "credential-exchange.pending-list",
        actor = &auth.did,
        resource = "pending-present",
        outcome = "success"
    );
    success_response(
        &doc,
        PendingListResponse {
            pending: pending_out,
        },
    )
}

/// `credential-exchange/pending-approve/1.0` — approve a deferral and
/// re-present, returning the freshly-minted `vp_token`. Super-admin only.
/// Deletes the record on success (delete-on-terminal).
pub(super) async fn handle_pending_approve(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    if let Err(e) = auth.require_super_admin() {
        return app_error_to_reject(&doc, e);
    }
    let body: PendingApproveBody = match parse_payload(&doc) {
        Ok(b) => b,
        Err(resp) => return resp,
    };

    // Read before approving: approval deletes the record, and the verifier it
    // names is who the presentation goes to.
    let verifier_did = match pending::get(&state.vault_ks, &body.id).await {
        Ok(Some(record)) => record.verifier_did,
        Ok(None) => {
            return app_error_to_reject(
                &doc,
                AppError::NotFound(format!("no pending presentation `{}`", body.id)),
            );
        }
        Err(e) => return app_error_to_reject(&doc, e),
    };

    let present = match approve_pending_presentation(
        &state.vault_ks,
        &state.keys_ks,
        &state.contexts_ks,
        &state.seed_store,
        &state.audit_sink,
        auth,
        &body.id,
        state.status_list_resolver.as_deref(),
        chrono::Utc::now(),
    )
    .await
    {
        Ok(p) => p,
        Err(e) => return app_error_to_reject(&doc, e),
    };

    audit!(
        "credential-exchange.pending-approve",
        actor = &auth.did,
        resource = &body.id,
        outcome = "success"
    );
    // The verifier asked on a thread whose id is this record's; the present
    // answers on it. The operator's response still carries the `vp_token`, so a
    // failed push leaves a relay path rather than a lost presentation.
    match serde_json::to_value(&present) {
        Ok(payload) => {
            if let Err(e) = push_step(state, &verifier_did, cx::PRESENT, payload, &body.id).await {
                tracing::warn!(verifier = %verifier_did, pending = %body.id, error = %e, "approved presentation could not be pushed to the verifier; the vp_token is in the response for relay");
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, "approved presentation did not serialise for the push")
        }
    }
    success_response(&doc, present)
}

/// `credential-exchange/pending-deny/1.0` — deny a deferral (no presentation).
/// Super-admin only. Deletes the record (delete-on-terminal).
pub(super) async fn handle_pending_deny(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    if let Err(e) = auth.require_super_admin() {
        return app_error_to_reject(&doc, e);
    }
    let body: PendingDenyBody = match parse_payload(&doc) {
        Ok(b) => b,
        Err(resp) => return resp,
    };

    if let Err(e) = deny_pending_presentation(&state.vault_ks, &body.id).await {
        return app_error_to_reject(&doc, e);
    }

    audit!(
        "credential-exchange.pending-deny",
        actor = &auth.did,
        resource = &body.id,
        outcome = "success"
    );
    success_response(
        &doc,
        PendingDenyResponse {
            id: body.id,
            status: "denied".to_string(),
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const ISSUER: &str = "did:key:zIssuerCounterparty";

    fn doc(type_uri: &str, payload: Value) -> TrustTask<Value> {
        serde_json::from_value(json!({
            "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
            "type": type_uri,
            "issuer": ISSUER,
            "recipient": "did:example:vta",
            "issuedAt": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            "payload": payload,
        }))
        .expect("a Trust Task document")
    }

    fn body(outcome: &TrustTaskOutcome) -> Value {
        serde_json::from_slice(&outcome.body).expect("a JSON document")
    }

    /// An SD-JWT-VC issued by a `did:key` — the credential format the vault
    /// verifies with no DID resolver.
    fn minted_credential() -> String {
        use affinidi_sd_jwt::error::SdJwtError;
        use affinidi_sd_jwt::signer::JwtSigner;
        use base64::Engine;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use ed25519_dalek::Signer;

        struct Issuer {
            key: ed25519_dalek::SigningKey,
            kid: String,
        }
        impl JwtSigner for Issuer {
            fn algorithm(&self) -> &str {
                "EdDSA"
            }
            fn key_id(&self) -> Option<&str> {
                Some(&self.kid)
            }
            fn sign_jwt(&self, header: &Value, payload: &Value) -> Result<String, SdJwtError> {
                let h = URL_SAFE_NO_PAD.encode(serde_json::to_string(header)?.as_bytes());
                let p = URL_SAFE_NO_PAD.encode(serde_json::to_string(payload)?.as_bytes());
                let input = format!("{h}.{p}");
                Ok(format!(
                    "{input}.{}",
                    URL_SAFE_NO_PAD.encode(self.key.sign(input.as_bytes()).to_bytes())
                ))
            }
        }

        let key = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        let issuer_did =
            affinidi_crypto::did_key::ed25519_pub_to_did_key(key.verifying_key().as_bytes());
        let signer = Issuer {
            key,
            kid: format!("{issuer_did}#key-0"),
        };
        let subject_did = affinidi_crypto::did_key::ed25519_pub_to_did_key(
            ed25519_dalek::SigningKey::from_bytes(&[7u8; 32])
                .verifying_key()
                .as_bytes(),
        );
        crate::vault::mint::mint_sd_jwt_vc(
            &crate::vault::mint::MintRequest {
                vct: "https://openvtc.org/credentials/MembershipCredential",
                issuer_did: &issuer_did,
                subject_did: &subject_did,
                claims: &json!({ "givenName": "Alice" }),
                disclosable: &["givenName"],
                iat: 1_700_000_000,
                exp: Some(1_900_000_000),
            },
            &signer,
        )
        .expect("mint an SD-JWT-VC")
    }

    /// A delivered credential lands in the vault, and the transport carries
    /// back only the empty `#response` acknowledgement (SPEC §4.4.2).
    #[tokio::test]
    async fn an_issued_credential_is_stored_and_acknowledged() {
        let (state, _dir) = crate::test_support::build_signing_test_app_state().await;
        let issue = doc(
            cx::ISSUE,
            json!({ "credential_response": { "credential": minted_credential() } }),
        );
        let outcome = handle_issue(
            &state,
            &super::super::ceremony::ceremony_claims(ISSUER),
            issue,
        )
        .await;

        let ack = body(&outcome);
        assert_eq!(ack["type"], format!("{}#response", cx::ISSUE), "{ack}");
        assert_eq!(
            ack["payload"],
            json!({}),
            "an acknowledgement carries nothing"
        );
        let stored = state
            .vault_ks
            .prefix_keys("cred:")
            .await
            .expect("scan the credential store");
        assert_eq!(stored.len(), 1, "the credential is in the vault");
    }

    /// An `issue` with no credential in it is refused on the spine as a typed
    /// rejection, not dropped.
    #[tokio::test]
    async fn an_issue_carrying_no_credential_is_refused() {
        let (state, _dir) = crate::test_support::build_signing_test_app_state().await;
        let outcome = handle_issue(
            &state,
            &super::super::ceremony::ceremony_claims(ISSUER),
            doc(cx::ISSUE, json!({})),
        )
        .await;
        let error = body(&outcome);
        assert!(
            error["type"]
                .as_str()
                .is_some_and(|t| t.contains("trust-task-error")),
            "{error}"
        );
    }

    /// With no `credential_holder_did`, this VTA requests nothing from an
    /// issuer, and nothing is pushed.
    #[tokio::test]
    async fn an_offer_is_declined_without_a_configured_holder() {
        let (state, _dir) = crate::test_support::build_signing_test_app_state().await;
        state.config.write().await.credential_holder_did = None;
        let offer = doc(
            cx::OFFER,
            json!({ "credential_offer": {
                "credential_issuer": ISSUER,
                "credential_configuration_ids": ["VIC"],
                "grants": { "urn:ietf:params:oauth:grant-type:pre-authorized_code":
                            { "pre-authorized_code": "code" } },
            }}),
        );
        let outcome = handle_offer(
            &state,
            &super::super::ceremony::ceremony_claims(ISSUER),
            offer,
        )
        .await;
        let error = body(&outcome);
        assert_eq!(error["payload"]["code"], "permissionDenied", "{error}");
        #[cfg(any(feature = "didcomm", feature = "tsp"))]
        assert!(
            crate::messaging::push::take_pushes(&state).is_empty(),
            "a declined offer sends no request"
        );
    }
}
