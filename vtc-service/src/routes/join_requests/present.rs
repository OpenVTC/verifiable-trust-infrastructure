//! Credential-exchange `present` → join decision (close-the-join-loop, part 2).
//!
//! The VTA holder answers a verifier's DCQL query with an OID4VP `vp_token`
//! (the map keyed by `credential_query_id` that
//! `vta-service`'s `present_query` produces). This module is the VTC verifier's
//! decision path: it **cryptographically verifies** the `vp_token`
//! ([`crate::credentials::verify_vp_token`]), projects the verified set into the
//! ceremony [`Presentation`] evidence shape, runs the active **join** policy, and
//! realizes the verdict — auto-admitting (issuing the MembershipCredential) on
//! `allow`, else queuing / rejecting like the VP submit path.
//!
//! Unlike the VP submit path (whose `presentation.verified` rests on a
//! route-layer hex signature), here `verified` rests on the holder `kb-jwt` /
//! DI holder proof binding the verifier's `nonce` + audience — real VP
//! cryptography. [`present_and_decide_join`] takes the expected audience + nonce
//! as parameters so it is transport-agnostic; the DIDComm
//! `credential-exchange/present` handler (`messaging.rs`) sources them from the
//! single-use presentation challenge it consumes.
//!
//! This module also hosts the **query send side** ([`prepare_join_query`] +
//! [`send_query`]): the VTC issues the challenge and builds the DCQL query (from
//! a registered Accepts criterion) the holder answers.

use std::sync::Arc;

use affinidi_openid4vp::DcqlQuery;
use axum::Json;
use axum::extract::State;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value as JsonValue, json};
use tracing::{info, warn};
use uuid::Uuid;
use vta_sdk::protocols::credential_exchange::{QUERY as CREDENTIAL_QUERY_TYPE, QueryBody};

use vti_common::auth::AdminAuth;
use vti_common::error::AppError;

use crate::ceremony::{Credential, CredentialStatus, Presentation};
use crate::credentials::present_challenge::{self, DEFAULT_CHALLENGE_TTL};
use crate::credentials::{VerifiedPresentation, VerifiedPresentationSet, verify_vp_token};
use affinidi_data_integrity::VerificationMethodResolver;

use crate::credentials::vm_resolver::DidVmResolver;
use crate::join::JoinTransport;
use crate::recognition::{HttpStatusListFetcher, StatusListFetcher};
use crate::registry::TrustRegistryClient;
use crate::schemas::accepts::get_accepts;
use crate::server::AppState;

use crate::join::{JoinSubmitOutcome, decide_join, realize_join_verdict};

/// Verify a presented OID4VP `vp_token`, run the join decision, and realize it.
///
/// `expected_aud` is this VTC's identity (the `domain`/`aud` the holder bound
/// into the kb-jwt); `expected_nonce` is the single-use freshness value the VTC
/// issued with its query. On success the applicant is the **proven holder** of
/// the presentation. On `allow` the MembershipCredential is issued inline (the
/// returned [`JoinSubmitOutcome::admit`]).
pub async fn present_and_decide_join(
    state: &AppState,
    vp_token: &JsonValue,
    expected_aud: &str,
    expected_nonce: &str,
    transport: JoinTransport,
    now: DateTime<Utc>,
) -> Result<JoinSubmitOutcome, AppError> {
    // 1. Cryptographically verify every presentation in the vp_token. The holder
    //    is proven (kb-jwt / DI holder proof) and consistent across the set.
    //    did:webvh / did:web issuers + holders resolve through the DID cache.
    let set = verify_vp_token(
        vp_token,
        expected_aud,
        expected_nonce,
        state.did_resolver.as_ref(),
        now,
    )
    .await?;
    let applicant_did = set.holder.clone();

    // 2. Project the verified set into the ceremony evidence shape, resolving
    //    each issuer's trust via TRQP against the community's recognition graph.
    let presentation = presentation_from_verified_set(state, &set).await;

    // 3 + 4. Decide under the active join policy, then realize the verdict.
    let verdict = decide_join(state, &applicant_did, presentation).await?;
    let vp_claims = vp_claims_from_set(&set);
    realize_join_verdict(
        state,
        &applicant_did,
        vp_token.clone(),
        vp_claims,
        false,
        JsonValue::Null,
        verdict,
        transport,
    )
    .await
}

// ---------------------------------------------------------------------------
// Query send side (close-the-join-loop, part B): the VTC issues the challenge
// and builds the DCQL query the holder answers.
// ---------------------------------------------------------------------------

/// Prepare a `credential-exchange/query` for a join: load the registered Accepts
/// DCQL criterion `criterion_id` (Phase 2 — the community's acceptance rule),
/// issue a **single-use presentation challenge** keyed by `thread_id` and bound
/// to the VTC's own DID, and assemble the [`QueryBody`] (the DCQL query + the
/// freshness nonce + a purpose shown to the holder).
///
/// The holder presents on this `thread_id`; the
/// `credential-exchange/present` handler consumes the challenge to recover the
/// nonce + audience and verify the presentation.
pub async fn prepare_join_query(
    state: &AppState,
    thread_id: &str,
    criterion_id: &str,
    now: DateTime<Utc>,
) -> Result<QueryBody, AppError> {
    let vtc_did = state.config.read().await.vtc_did.clone().ok_or_else(|| {
        AppError::Internal("VTC DID not configured — cannot bind a presentation challenge".into())
    })?;

    let criterion = get_accepts(&state.schemas_ks, criterion_id)
        .await?
        .ok_or_else(|| {
            AppError::NotFound(format!("no Accepts criterion `{criterion_id}` registered"))
        })?;
    let dcql_query = DcqlQuery::from_json(&criterion.query).map_err(|e| {
        AppError::Internal(format!(
            "registered Accepts criterion `{criterion_id}` is not a valid DCQL query: {e}"
        ))
    })?;

    let nonce = present_challenge::issue(
        &state.join_requests_ks,
        thread_id,
        &vtc_did,
        DEFAULT_CHALLENGE_TTL,
        now,
    )
    .await?;

    let purpose = criterion
        .description
        .unwrap_or_else(|| format!("join: present credentials satisfying `{criterion_id}`"));
    Ok(QueryBody {
        dcql_query,
        nonce,
        purpose,
    })
}

/// `POST /v1/join-requests/query` request — ask the VTC to prepare a join query
/// for `holderDid` from the named Accepts criterion.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[derive(utoipa::ToSchema)]
pub struct SendQueryRequest {
    /// The holder the query is for (delivered to it over DIDComm by the VTC or a
    /// relayer — relayer ≠ holder is supported; the holder still proves binding).
    pub holder_did: String,
    /// The registered Accepts criterion whose DCQL query to send.
    pub criterion_id: String,
}

/// `POST /v1/join-requests/query` response — the prepared query to deliver, and
/// the thread the holder presents on.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
#[derive(utoipa::ToSchema)]
pub struct SendQueryResponse {
    /// The DIDComm thread id the holder must reply on (the challenge is keyed by
    /// it; the `present` handler consumes it).
    pub thread_id: String,
    /// Echoed for the caller's correlation.
    pub holder_did: String,
    /// The `credential-exchange/query` body to deliver to the holder.
    #[schema(value_type = Object)]
    pub query: QueryBody,
    /// Whether the VTC pushed the query to the holder over DIDComm. `false` when
    /// no mediator is configured or the push failed — the caller can still relay
    /// the returned [`query`](Self::query) out-of-band (relayer ≠ holder).
    pub delivered: bool,
}

/// `POST /v1/join-requests/query` (admin) — prepare a `credential-exchange/query`
/// for `holderDid` from the Accepts criterion `criterionId`: issue the single-use
/// challenge, **push the query to the holder over DIDComm** when a mediator is
/// configured, and return the [`QueryBody`] (so a relayer can deliver it when the
/// push is unavailable — relayer ≠ holder is supported). The holder presents on
/// the returned `threadId`, and the `credential-exchange/present` handler
/// consumes the challenge.
/// POST /join-requests/query — prepare + push a credential-exchange query to
/// a holder for a registered Accepts criterion. Auth: Admin.
#[utoipa::path(
    post, path = "/join-requests/query", tag = "join-requests",
    security(("bearer_jwt" = [])),
    request_body = SendQueryRequest,
    responses(
        (status = 200, description = "Prepared query + thread to present on", body = SendQueryResponse),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not an admin"),
        (status = 404, description = "No such Accepts criterion registered"),
    ),
)]
pub async fn send_query(
    _auth: AdminAuth,
    State(state): State<AppState>,
    Json(body): Json<SendQueryRequest>,
) -> Result<Json<SendQueryResponse>, AppError> {
    let thread_id = Uuid::new_v4().to_string();
    let query = prepare_join_query(&state, &thread_id, &body.criterion_id, Utc::now()).await?;

    // Best-effort DIDComm push. A failure (no mediator, unreachable holder) is not
    // fatal — the query is still returned for relay delivery.
    let delivered = match push_credential_query(&state, &body.holder_did, &thread_id, &query).await
    {
        Ok(()) => {
            info!(holder = %body.holder_did, thread = %thread_id, "pushed credential query over DIDComm");
            true
        }
        Err(e) => {
            warn!(holder = %body.holder_did, thread = %thread_id, error = %e, "credential-query push failed — returning query for relay");
            false
        }
    };

    Ok(Json(SendQueryResponse {
        thread_id,
        holder_did: body.holder_did,
        query,
        delivered,
    }))
}

/// Push a `credential-exchange/query` to `holder_did` over DIDComm: pack it
/// authcrypt to the holder, wrap it in a mediator forward, and send. The query
/// message id **is** `thread_id` (the thread root), so the holder's `present`
/// reply threads back to the single-use challenge the VTC just issued.
///
/// The forward is addressed to the **holder's own mediator** (resolved from the
/// holder's DID document) and sent through the **VTC's own mediator** — the
/// mediator the VTC has a connection to. The VTC's mediator routes the forward
/// onward to the holder's mediator, which delivers it. When the holder
/// advertises no mediator, the VTC's own mediator is used as the forward target
/// (the shared-mediator deployment).
async fn push_credential_query(
    state: &AppState,
    holder_did: &str,
    thread_id: &str,
    query: &QueryBody,
) -> Result<(), AppError> {
    let body = serde_json::to_value(query)
        .map_err(|e| AppError::Internal(format!("query serialise: {e}")))?;
    // The message id is the thread root; the holder replies with `thid = thread_id`.
    crate::credentials::delivery::push_to_holder(
        state,
        holder_did,
        thread_id,
        CREDENTIAL_QUERY_TYPE,
        body,
    )
    .await
}

/// Project a [`VerifiedPresentationSet`] into the verified ceremony
/// [`Presentation`]. Crypto is already resolved, so `verified: true`. Each
/// credential's `issuer_trusted` is resolved per-issuer via TRQP
/// ([`issuer_trusted`]) and its lifecycle `status` is resolved live against the
/// issuer's status list ([`resolve_presented_status`]). The credential `type` is
/// the SD-JWT-VC `vct`.
async fn presentation_from_verified_set(
    state: &AppState,
    set: &VerifiedPresentationSet,
) -> Presentation {
    let own_did = state.config.read().await.vtc_did.clone();
    let registry = state.registry_client.as_deref();
    // A presented credential's revocation is checked against the *issuer's*
    // status list (a foreign URL): same fetcher + SSRF guard the recognition
    // path uses. When a DID resolver is configured, the fetcher also verifies
    // the list credential's own issuer signature (bound to the presented
    // credential's issuer) — so a MITM on the status-list host can't forge or
    // hide a revocation. Built once for the whole set.
    let status_fetcher = match state.did_resolver.clone() {
        Some(resolver) => {
            let key_resolver: Arc<dyn VerificationMethodResolver> =
                Arc::new(DidVmResolver::new(Some(resolver)));
            HttpStatusListFetcher::with_issuer_verification(key_resolver)
        }
        None => HttpStatusListFetcher::new(),
    };

    let mut credentials = Vec::with_capacity(set.presentations.len());
    for p in &set.presentations {
        let trusted = issuer_trusted(registry, own_did.as_deref(), &p.issuer_did).await;
        let status = resolve_presented_status(
            p.credential_status.as_ref(),
            Some(&p.issuer_did),
            &status_fetcher,
        )
        .await;
        credentials.push(credential_from_verified(p, trusted, status));
    }

    Presentation {
        verified: true,
        holder: set.holder.clone(),
        credentials,
    }
}

/// Pure projection of a single [`VerifiedPresentation`] into a ceremony
/// [`Credential`], with the caller-resolved `issuer_trusted` verdict and
/// lifecycle `status`. Kept separate from the TRQP + status-list lookups so it
/// stays unit-testable without a registry or network.
fn credential_from_verified(
    p: &VerifiedPresentation,
    issuer_trusted: bool,
    status: CredentialStatus,
) -> Credential {
    Credential {
        credential_type: p
            .vct
            .clone()
            .unwrap_or_else(|| "VerifiableCredential".to_string()),
        issuer: p.issuer_did.clone(),
        issuer_trusted,
        status,
        holder_bound: p.holder_bound,
        claims: p.claims.clone(),
        // SD-JWT-VC carries expiry in `exp` (epoch seconds).
        valid_until: p
            .claims
            .get("exp")
            .and_then(JsonValue::as_i64)
            .and_then(|s| DateTime::from_timestamp(s, 0)),
    }
}

/// Resolve a presented credential's lifecycle [`CredentialStatus`] against the
/// issuer's status list.
///
/// The verifier must not accept a **revoked** credential at join. Resolution is
/// surfaced into the ceremony evidence rather than enforced here, so the join
/// policy decides (the ceremony [`CredentialStatus`] model carries `Unknown`
/// exactly for this):
///
/// - no `credentialStatus` entry → [`CredentialStatus::Valid`] (the issuer opted
///   into no status list — an implicit "not revocable" claim, matching the
///   recognition path).
/// - status bit clear → [`CredentialStatus::Valid`].
/// - status bit set → [`CredentialStatus::Revoked`], or
///   [`CredentialStatus::Suspended`] when the entry's `statusPurpose` is
///   `suspension`.
/// - entry present but unresolvable (malformed, or the list unreachable) →
///   [`CredentialStatus::Unknown`]: **surfaced, not guessed**, so the policy can
///   refuse rather than the verifier silently trusting an uncheckable credential.
async fn resolve_presented_status(
    status_entry: Option<&JsonValue>,
    expected_issuer: Option<&str>,
    fetcher: &dyn StatusListFetcher,
) -> CredentialStatus {
    // No status block → the credential never opted into revocation.
    let Some(entry) = status_entry else {
        return CredentialStatus::Valid;
    };

    // Accept both the W3C `BitstringStatusListEntry`
    // (`{ statusListCredential, statusListIndex, statusPurpose }`) and the
    // SD-JWT-VC IETF `status` object (`{ status_list: { uri, idx } }`).
    let (url, index, suspension) = match parse_status_entry(entry) {
        Some(parts) => parts,
        // A malformed entry is suspicious — surface Unknown, don't trust it.
        None => return CredentialStatus::Unknown,
    };

    match fetcher.check_status_bit(&url, index, expected_issuer).await {
        Ok(false) => CredentialStatus::Valid,
        Ok(true) if suspension => CredentialStatus::Suspended,
        Ok(true) => CredentialStatus::Revoked,
        Err(e) => {
            warn!(
                url = %url,
                error = %e,
                "presented credential's status list did not resolve — surfacing Unknown for the join policy"
            );
            CredentialStatus::Unknown
        }
    }
}

/// Parse a status entry into `(status_list_url, index, is_suspension)`. Handles
/// the W3C `BitstringStatusListEntry` and the SD-JWT-VC IETF `status.status_list`
/// shapes. Returns `None` if neither yields a usable URL + index.
fn parse_status_entry(entry: &JsonValue) -> Option<(String, usize, bool)> {
    // W3C: { statusListCredential, statusListIndex, statusPurpose }.
    if let Some(url) = entry
        .get("statusListCredential")
        .and_then(JsonValue::as_str)
    {
        let index = parse_status_index(entry.get("statusListIndex"))?;
        let suspension =
            entry.get("statusPurpose").and_then(JsonValue::as_str) == Some("suspension");
        return Some((url.to_string(), index, suspension));
    }
    // SD-JWT-VC IETF: { status_list: { uri, idx } } — no per-entry purpose.
    if let Some(sl) = entry.get("status_list") {
        let url = sl.get("uri").and_then(JsonValue::as_str)?;
        let index = parse_status_index(sl.get("idx"))?;
        return Some((url.to_string(), index, false));
    }
    None
}

/// Parse a `statusListIndex` / `idx` that may be a JSON string or number.
fn parse_status_index(v: Option<&JsonValue>) -> Option<usize> {
    match v {
        Some(JsonValue::String(s)) => s.parse::<usize>().ok(),
        Some(JsonValue::Number(n)) => n.as_u64().map(|u| u as usize),
        _ => None,
    }
}

/// Resolve whether the community trusts `issuer_did` to issue credentials, for
/// the ceremony evidence shape. The community's **own** DID is always trusted
/// (it issued the credential itself). Any other issuer is resolved via TRQP
/// `recognise` against the trust registry:
///
/// - `Ok(true)` → the issuer is in the recognition graph → trusted.
/// - `Ok(false)` (clean not-found) → not trusted.
/// - transport / parse `Err` → not trusted (**fail-soft** + warn): the join
///   policy still gets to decide over a `false` rather than the whole request
///   erroring on a flaky registry.
/// - no-registry mode (`registry` is `None`) → not trusted.
///
/// Trust is **never cached** here (spec §8.4): a peer removed from the
/// recognition graph loses trust on the next presentation, not when a TTL
/// elapses. The verdict feeds the Rego `cred_trusted` policy helper — it is an
/// input to the decision, not the decision itself.
async fn issuer_trusted(
    registry: Option<&dyn TrustRegistryClient>,
    own_did: Option<&str>,
    issuer_did: &str,
) -> bool {
    if own_did == Some(issuer_did) {
        return true;
    }
    let Some(registry) = registry else {
        return false;
    };
    match registry.recognise(issuer_did).await {
        Ok(trusted) => trusted,
        Err(e) => {
            warn!(
                issuer = %issuer_did,
                error = %e,
                "trust-registry recognise failed — treating issuer as untrusted; join policy decides"
            );
            false
        }
    }
}

/// The lossy `vp_claims` admin-display projection (mirrors the VP path's
/// `extract_vp_claims`): the holder + a credential summary, persisted on the
/// join-request row for the admin show.
fn vp_claims_from_set(set: &VerifiedPresentationSet) -> JsonValue {
    let credentials: Vec<JsonValue> = set
        .presentations
        .iter()
        .map(|p| {
            json!({
                "issuer": p.issuer_did,
                "type": p.vct,
                "credentialSubject": p.claims,
            })
        })
        .collect();
    json!({ "holder": set.holder, "credentials": credentials })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recognition::RecognitionError;
    use crate::registry::MockRegistryClient;

    fn sample_presentation() -> VerifiedPresentation {
        VerifiedPresentation {
            issuer_did: "did:key:zIssuer".into(),
            holder_did: "did:key:zHolder".into(),
            vct: Some("https://openvtc.org/credentials/MembershipCredential".into()),
            holder_bound: true,
            claims: json!({ "givenName": "Alice", "exp": 1_900_000_000 }),
            credential_status: None,
        }
    }

    /// A `StatusListFetcher` stub: returns a fixed bit, or an error, without
    /// touching the network.
    struct StubFetcher(Result<bool, ()>);

    #[async_trait::async_trait]
    impl StatusListFetcher for StubFetcher {
        async fn check_status_bit(
            &self,
            _url: &str,
            _index: usize,
            _expected_issuer: Option<&str>,
        ) -> Result<bool, RecognitionError> {
            self.0
                .map_err(|()| RecognitionError::StatusListFailed("stub".into()))
        }
    }

    fn w3c_status(purpose: &str) -> JsonValue {
        json!({
            "type": "BitstringStatusListEntry",
            "statusPurpose": purpose,
            "statusListIndex": "42",
            "statusListCredential": "https://issuer.example/status/1",
        })
    }

    #[test]
    fn projects_a_verified_presentation_into_a_ceremony_credential() {
        let c = credential_from_verified(&sample_presentation(), true, CredentialStatus::Valid);
        assert_eq!(
            c.credential_type,
            "https://openvtc.org/credentials/MembershipCredential"
        );
        assert_eq!(c.issuer, "did:key:zIssuer");
        assert!(c.issuer_trusted);
        assert_eq!(c.status, CredentialStatus::Valid);
        assert!(c.valid_until.is_some());
        assert_eq!(c.claims["givenName"], "Alice");
    }

    #[test]
    fn resolved_status_carries_through_to_the_credential() {
        let c = credential_from_verified(&sample_presentation(), true, CredentialStatus::Revoked);
        assert_eq!(c.status, CredentialStatus::Revoked);
    }

    #[tokio::test]
    async fn no_status_block_is_valid_without_a_fetch() {
        let status = resolve_presented_status(None, None, &StubFetcher(Ok(true))).await;
        assert_eq!(status, CredentialStatus::Valid);
    }

    #[tokio::test]
    async fn clear_bit_is_valid() {
        let entry = w3c_status("revocation");
        let status = resolve_presented_status(Some(&entry), None, &StubFetcher(Ok(false))).await;
        assert_eq!(status, CredentialStatus::Valid);
    }

    #[tokio::test]
    async fn set_revocation_bit_is_revoked() {
        let entry = w3c_status("revocation");
        let status = resolve_presented_status(Some(&entry), None, &StubFetcher(Ok(true))).await;
        assert_eq!(status, CredentialStatus::Revoked);
    }

    #[tokio::test]
    async fn set_suspension_bit_is_suspended() {
        let entry = w3c_status("suspension");
        let status = resolve_presented_status(Some(&entry), None, &StubFetcher(Ok(true))).await;
        assert_eq!(status, CredentialStatus::Suspended);
    }

    #[tokio::test]
    async fn sd_jwt_status_list_shape_resolves() {
        let entry = json!({ "status_list": { "idx": 7, "uri": "https://issuer.example/sl" } });
        let status = resolve_presented_status(Some(&entry), None, &StubFetcher(Ok(true))).await;
        assert_eq!(status, CredentialStatus::Revoked);
    }

    #[tokio::test]
    async fn unreachable_status_list_is_unknown_not_valid() {
        // The verifier must not silently trust an uncheckable credential —
        // surface Unknown so the join policy can refuse.
        let entry = w3c_status("revocation");
        let status = resolve_presented_status(Some(&entry), None, &StubFetcher(Err(()))).await;
        assert_eq!(status, CredentialStatus::Unknown);
    }

    #[tokio::test]
    async fn malformed_status_entry_is_unknown() {
        let entry = json!({ "type": "BitstringStatusListEntry" }); // no url/index
        let status = resolve_presented_status(Some(&entry), None, &StubFetcher(Ok(false))).await;
        assert_eq!(status, CredentialStatus::Unknown);
    }

    #[test]
    fn untrusted_issuer_carries_through_to_the_credential() {
        let c = credential_from_verified(&sample_presentation(), false, CredentialStatus::Valid);
        assert!(!c.issuer_trusted);
    }

    #[tokio::test]
    async fn own_did_is_trusted_without_consulting_the_registry() {
        let registry = MockRegistryClient::new();
        // Own DID short-circuits — recognise is never called.
        assert!(issuer_trusted(Some(&registry), Some("did:vtc:home"), "did:vtc:home").await);
        assert_eq!(registry.call_counts().await.recognise, 0);
    }

    #[tokio::test]
    async fn recognised_foreign_issuer_is_trusted() {
        let registry = MockRegistryClient::new();
        registry.set_recognised("did:webvh:peer.example:abc").await;
        assert!(
            issuer_trusted(
                Some(&registry),
                Some("did:vtc:home"),
                "did:webvh:peer.example:abc"
            )
            .await
        );
        assert_eq!(registry.call_counts().await.recognise, 1);
    }

    #[tokio::test]
    async fn unrecognised_foreign_issuer_is_not_trusted() {
        let registry = MockRegistryClient::new();
        assert!(
            !issuer_trusted(
                Some(&registry),
                Some("did:vtc:home"),
                "did:webvh:stranger.example"
            )
            .await
        );
    }

    #[tokio::test]
    async fn registry_error_fails_soft_to_untrusted() {
        let registry = MockRegistryClient::new();
        registry
            .fail_next_recognise(crate::registry::RegistryError::Unreachable("dns".into()))
            .await;
        // A flaky registry must not error the request — it degrades to untrusted
        // and lets the join policy decide.
        assert!(
            !issuer_trusted(
                Some(&registry),
                Some("did:vtc:home"),
                "did:webvh:peer.example"
            )
            .await
        );
    }

    #[tokio::test]
    async fn no_registry_mode_is_not_trusted() {
        // No-registry deployment: no recognition graph, so no foreign issuer is
        // trusted (the own-DID short-circuit still applies elsewhere).
        assert!(!issuer_trusted(None, Some("did:vtc:home"), "did:webvh:peer.example").await);
    }
}
