//! Opening a wallet session and receiving a wallet's answer — the VTC side of
//! OpenID4VP 1.0 for `vtc/join-requests/wallet-session/start/0.1`.
//!
//! [`start`] resolves what the applicant asked for, signs the request object
//! with the community's verifier identity and stores the session. [`receive`]
//! takes what the wallet posted to `response_uri` and verifies it, in the order
//! the design note gives (`oid4vp-wallet-verifier.md` §Verifying a response),
//! stopping at the first failure:
//!
//! 1. the session is open and unanswered — claiming it takes its response key,
//!    so a second answer finds none;
//! 2. the response decrypts under that key with an allowed `enc`, and echoes
//!    the session's `state`;
//! 3. each presentation verifies: the issuer's signature, the validity window,
//!    and the key-binding JWT over the session nonce with the prefixed
//!    `client_id` as its audience, under the credential's `cnf` key
//!    (VTI-CRD-020…022); all of them bind one holder;
//! 4. each credential's status is valid — never assumed (VTI-CRD-014);
//! 5. each issuer is one the criterion's `credentialIssuers` admits;
//! 6. the presentations satisfy the criterion's DCQL query;
//!
//! and then records the evidence on the session.

use std::collections::BTreeMap;

use affinidi_oid4vc_core::jwe::{ContentEncryption, EcdhEsDecryptionKey};
use affinidi_openid4vp::dcql::CandidateCredential;
use affinidi_openid4vp::request_object::{
    REQUEST_OBJECT_TYP, RequestObject, VerifierClientMetadata,
};
use affinidi_openid4vp::response::{DirectPostJwt, receive_direct_post_jwt};
use affinidi_openid4vp::{ClientId, DcqlQuery};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Duration, Utc};
use serde_json::{Map, Value, json};
use tracing::{info, warn};
use uuid::Uuid;
use vti_common::error::AppError;

use super::session::{
    self, EvidenceCredential, RefusalReason, SessionPhase, WalletEvidence, WalletSession,
};
use super::{VerifierIdentityRecord, VerifierKind, list_identities};
use crate::ceremony::CredentialStatus;
use crate::join::JoinStatus;
use crate::join::criteria::{LDP_VC_FORMAT, SD_JWT_VC_FORMAT};
use crate::server::AppState;

/// The swiyu Verification Profile a request object declares in its header.
pub const SWIYU_PROFILE_VERSION: &str = "swiss-profile-verification:1.0.0";

/// One wallet answer at a time is handed to the join: two sessions bound to the
/// same deferred request must not decide it twice from the same starting
/// state.
static JOIN_HANDOFF: std::sync::LazyLock<tokio::sync::Mutex<()>> =
    std::sync::LazyLock::new(|| tokio::sync::Mutex::new(()));

/// The `kid` of a session's response-encryption key in `client_metadata.jwks`.
const RESPONSE_KEY_ID: &str = "response-encryption";

/// Why a session could not be opened — each one of
/// `wallet-session/start/0.1`'s declared codes.
#[derive(Debug)]
pub enum StartRefusal {
    CriterionNotFound,
    NoWalletPresentation,
    /// Carries what is missing, for the operator reading the message.
    VerifierNotConfigured(String),
    RequestNotFound,
    RequestClosed,
    TooManySessions,
    Other(AppError),
}

impl From<AppError> for StartRefusal {
    fn from(e: AppError) -> Self {
        Self::Other(e)
    }
}

/// An opened session and the URI the applicant shows the wallet.
#[derive(Debug)]
pub struct Started {
    pub session: WalletSession,
    pub wallet_uri: String,
}

/// The client identifier prefix an identity presents itself with.
fn prefix_of(kind: VerifierKind) -> &'static str {
    match kind {
        VerifierKind::Swiyu => "decentralized_identifier",
        VerifierKind::Eudi => "x509_hash",
    }
}

/// The wallet invocation scheme of an identity's ecosystem.
fn scheme_of(kind: VerifierKind) -> &'static str {
    match kind {
        VerifierKind::Swiyu => "swiyu-verify",
        // HAIP's own scheme, which EUDI wallets register.
        VerifierKind::Eudi => "haip-vp",
    }
}

/// The JWE `enc` values a response to an identity may use. swiyu requires
/// `A256GCM`; HAIP has wallets support both `A128GCM` and `A256GCM`.
fn enc_values_of(kind: VerifierKind) -> Vec<ContentEncryption> {
    match kind {
        VerifierKind::Swiyu => vec![ContentEncryption::A256Gcm],
        VerifierKind::Eudi => vec![ContentEncryption::A128Gcm, ContentEncryption::A256Gcm],
    }
}

/// Header members an identity's ecosystem requires beyond `alg` and `typ`:
/// how the key is named (a swiyu DID URL as `kid`, an EUDI access
/// certificate chain as `x5c`) and any profile marker.
fn identity_header_of(
    identity: &VerifierIdentityRecord,
    signer: &dyn super::VerifierSigner,
) -> Map<String, Value> {
    let mut header = Map::new();
    match identity.kind {
        VerifierKind::Swiyu => {
            header.insert("kid".into(), json!(signer.kid()));
            header.insert("profile_version".into(), json!(SWIYU_PROFILE_VERSION));
        }
        VerifierKind::Eudi => {
            header.insert("x5c".into(), json!(identity.x5c));
        }
    }
    header
}

/// Choose the verifier identity a session presents itself as: the first
/// installed one with the requested prefix, or — when none was requested — the
/// configured default, else the first installed.
async fn choose_identity(
    state: &AppState,
    prefix: Option<&str>,
    default_identity: Option<&str>,
) -> Result<VerifierIdentityRecord, StartRefusal> {
    let installed: Vec<VerifierIdentityRecord> = list_identities(&state.oid4vp_keys_ks)
        .await?
        .into_iter()
        .filter(|r| state.oid4vp_signers.contains_key(&r.id))
        // An EUDI identity is not usable until its certificate is installed.
        .filter(|r| r.client_id().is_some())
        .collect();
    let chosen = match prefix {
        Some(p) => installed.into_iter().find(|r| prefix_of(r.kind) == p),
        None => match default_identity {
            Some(id) => installed.into_iter().find(|r| r.id == id),
            None => installed.into_iter().next(),
        },
    };
    chosen.ok_or_else(|| {
        StartRefusal::VerifierNotConfigured(match prefix {
            Some(p) => {
                format!(
                    "this community holds no verifier identity for client identifier prefix {p}"
                )
            }
            None => "this community holds no OpenID4VP verifier identity".into(),
        })
    })
}

/// Open a wallet session for `applicant_did` (the start document's proof
/// signer) — `wallet-session/start/0.1` consumer rules 1–8.
pub async fn start(
    state: &AppState,
    applicant_did: &str,
    criterion_digest: &str,
    request_id: Option<&str>,
    prefix: Option<&str>,
    now: DateTime<Utc>,
) -> Result<Started, StartRefusal> {
    let (cfg, public_url, community_name) = {
        let config = state.config.read().await;
        (
            config.oid4vp.clone(),
            config.public_url.clone(),
            config.vtc_name.clone(),
        )
    };

    // Rule 1: a criterion the community publishes, or still honours.
    let served = crate::join::criteria::served_by_digest(state, criterion_digest, now)
        .await?
        .ok_or(StartRefusal::CriterionNotFound)?;
    let query = served.stored.dcql()?;
    let published_query = served
        .json
        .get("presentationDefinition")
        .cloned()
        .unwrap_or(Value::Null);
    let Some(query) =
        query.filter(|q| q.credentials.iter().any(|cq| cq.format == SD_JWT_VC_FORMAT))
    else {
        return Err(StartRefusal::NoWalletPresentation);
    };

    // Rule 2: the applicant's own request, still able to take evidence.
    let request_id = match request_id {
        None => None,
        Some(raw) => {
            let id = Uuid::parse_str(raw).map_err(|_| StartRefusal::RequestNotFound)?;
            let request = crate::join::storage::get_join_request(&state.join_requests_ks, id)
                .await?
                .filter(|r| r.applicant_did == applicant_did)
                .ok_or(StartRefusal::RequestNotFound)?;
            if !matches!(request.status, JoinStatus::Pending | JoinStatus::Deferred) {
                return Err(StartRefusal::RequestClosed);
            }
            Some(id)
        }
    };

    // Rule 3: the identity the prefix names.
    let identity = choose_identity(state, prefix, cfg.default_identity.as_deref()).await?;
    let signer = state
        .oid4vp_signers
        .get(&identity.id)
        .cloned()
        .ok_or_else(|| StartRefusal::VerifierNotConfigured(identity.id.clone()))?;
    let public_url = public_url
        .filter(|u| u.starts_with("https://"))
        .ok_or_else(|| {
            StartRefusal::VerifierNotConfigured(
                "this community has no https public_url for a wallet to reach".into(),
            )
        })?;
    let public_url = public_url.trim_end_matches('/');

    // Rule 12: a bound on what one applicant holds open.
    if session::open_count(&state.oid4vp_sessions_ks, applicant_did, now).await?
        >= cfg.max_open_sessions
    {
        return Err(StartRefusal::TooManySessions);
    }

    // Rule 5: nonce, state and response key, all fresh.
    let id = session::random_token(24);
    let nonce = session::random_token(16);
    let wallet_state = session::random_token(16);
    let response_key = EcdhEsDecryptionKey::generate(RESPONSE_KEY_ID);
    let response_jwk = response_key
        .public_jwk()
        .map_err(|e| AppError::Internal(format!("response key: {e}")))?;
    let encs = enc_values_of(identity.kind);
    let expires_at = now + Duration::seconds(cfg.session_ttl_secs as i64);

    let client_id = identity
        .client_id()
        .ok_or_else(|| StartRefusal::VerifierNotConfigured(identity.id.clone()))?;
    let client_id = ClientId::parse(&client_id)
        .map_err(|e| AppError::Internal(format!("verifier identity client_id: {e}")))?;
    let request_uri = format!("{public_url}/v1/oid4vp/request/{id}");
    let response_uri = format!("{public_url}/v1/oid4vp/response/{id}");

    let mut additional = Map::new();
    if let Some(name) = community_name {
        // Shown on the wallet's consent screen: whom the holder is presenting
        // to (the cross-device relay mitigation the specification names).
        additional.insert("client_name".into(), json!(name));
    }
    // Rule 6: the criterion's published query and nothing else.
    let mut request = RequestObject::direct_post_jwt(
        &client_id,
        response_uri,
        nonce.clone(),
        query,
        VerifierClientMetadata {
            jwks: json!({ "keys": [response_jwk] }),
            encrypted_response_enc_values_supported: encs
                .iter()
                .map(|e| e.as_str().to_string())
                .collect(),
            vp_formats_supported: None,
            additional,
        },
    );
    request.state = Some(wallet_state.clone());
    // What the identity's ecosystem has said about it — an EUDI registration
    // certificate, which the wallet checks the requested claims against, or
    // swiyu trust statements. One that has expired is left out: the wallet
    // would refuse it, and it says nothing a missing one does not.
    request.verifier_info = identity.verifier_info.as_deref().and_then(|entries| {
        let (kept, expired) = super::trust_statement::current(entries, now.timestamp());
        for s in &expired {
            warn!(identity = %identity.id, expired_at = %super::trust_statement::timestamp(s.exp),
                "verifier identity's {} has expired and is left out of the request; install a \
                 new one with `vtc oid4vp trust-statement`", s.kind.label());
        }
        (!kept.is_empty()).then_some(kept)
    });
    request.iat = Some(now.timestamp());
    request.exp = Some(expires_at.timestamp());
    let jar = sign_request_object(&request, &identity, signer.as_ref()).await?;

    let wallet_uri = RequestObject::wallet_invocation_uri(
        cfg.wallet_uri_scheme
            .as_deref()
            .unwrap_or(scheme_of(identity.kind)),
        &client_id,
        &request_uri,
    )
    .map_err(|e| StartRefusal::VerifierNotConfigured(e.to_string()))?;

    let session = WalletSession {
        id,
        applicant_did: applicant_did.to_string(),
        criterion_id: served.stored.id.clone(),
        requirements_digest: served.digest.clone(),
        credential_issuers: served
            .stored
            .credential_issuers
            // Registration refuses a query without one; a row that has one
            // anyway is read the restrictive way, as the join decision does.
            .unwrap_or(crate::schemas::accepts::CredentialIssuers::Community),
        request_id,
        identity_id: identity.id.clone(),
        client_id: client_id.to_string(),
        dcql_query: published_query,
        nonce,
        state: wallet_state,
        enc_values: encs.iter().map(|e| e.as_str().to_string()).collect(),
        response_key_id: RESPONSE_KEY_ID.into(),
        response_key: Some(URL_SAFE_NO_PAD.encode(response_key.scalar_bytes())),
        request_object: Some(jar),
        phase: SessionPhase::AwaitingWallet,
        reason: None,
        evidence: None,
        created_at: now,
        expires_at,
        closed_at: None,
        held_until: None,
    };
    session::insert(&state.oid4vp_sessions_ks, &session).await?;
    info!(
        session = %session.id,
        applicant = %applicant_did,
        criterion = %session.criterion_id,
        identity = %session.identity_id,
        "OpenID4VP wallet session opened"
    );
    Ok(Started {
        session,
        wallet_uri,
    })
}

/// Sign a request object as a JAR through the identity's [`super::VerifierSigner`]
/// — `typ: oauth-authz-req+jwt`, plus the header members its ecosystem
/// requires ([`identity_header_of`]).
async fn sign_request_object(
    request: &RequestObject,
    identity: &VerifierIdentityRecord,
    signer: &dyn super::VerifierSigner,
) -> Result<String, AppError> {
    request
        .validate()
        .map_err(|e| AppError::Internal(format!("request object: {e}")))?;
    let mut header = identity_header_of(identity, signer);
    header.insert("typ".into(), json!(REQUEST_OBJECT_TYP));
    let Value::Object(claims) = serde_json::to_value(request)
        .map_err(|e| AppError::Internal(format!("request object: {e}")))?
    else {
        return Err(AppError::Internal(
            "request object: not a JSON object".into(),
        ));
    };
    signer.sign_jws(header, claims).await
}

/// What became of a wallet's post to `response_uri`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalletAnswer {
    /// The presentation verified and its evidence is recorded.
    Presented,
    /// The wallet answered with an OpenID4VP error; recorded as
    /// `walletDeclined`.
    Declined,
    /// The answer was refused for the reason given; recorded on the session.
    Refused(RefusalReason),
    /// No open session by that id, or it was already answered.
    NoSession,
}

/// Receive a wallet's `direct_post.jwt` body for session `id`.
pub async fn receive(
    state: &AppState,
    id: &str,
    form_body: &[u8],
    now: DateTime<Utc>,
) -> Result<WalletAnswer, AppError> {
    let Some(claimed) = session::claim_for_response(&state.oid4vp_sessions_ks, id, now).await?
    else {
        return Ok(WalletAnswer::NoSession);
    };
    let hold = Duration::seconds(state.config.read().await.oid4vp.evidence_hold_secs as i64);
    let outcome = verify_answer(state, &claimed, form_body, now).await;
    let answer = match &outcome {
        Ok(_) => WalletAnswer::Presented,
        Err(RefusalReason::WalletDeclined) => WalletAnswer::Declined,
        Err(reason) => WalletAnswer::Refused(*reason),
    };
    let finished = session::finish(&state.oid4vp_sessions_ks, id, outcome, hold, now).await?;
    if finished.phase == SessionPhase::Presented && finished.request_id.is_some() {
        // The wallet's answer is accepted whatever the join does next; a
        // failure here is the community's to see, not the wallet's.
        let _serial = JOIN_HANDOFF.lock().await;
        match crate::join::orchestrate::wallet_evidence_arrived(state, &finished).await {
            Ok(Some(outcome)) => info!(
                session = %finished.id,
                request = %outcome.request.id,
                status = %outcome.request.status,
                "join request decided again on wallet evidence"
            ),
            Ok(None) => {}
            Err(e) => warn!(
                session = %finished.id,
                error = %e,
                "wallet evidence could not be applied to its join request"
            ),
        }
    }
    match &finished.evidence {
        Some(evidence) => info!(
            session = %finished.id,
            applicant = %finished.applicant_did,
            holder = %evidence.holder,
            credentials = evidence.credentials.len(),
            "OpenID4VP wallet presentation verified"
        ),
        None => info!(
            session = %finished.id,
            applicant = %finished.applicant_did,
            reason = ?finished.reason,
            "OpenID4VP wallet answer refused"
        ),
    }
    Ok(answer)
}

/// Steps 2–6. Every failure is a [`RefusalReason`]; the detail goes to the
/// log, never to the wallet.
async fn verify_answer(
    state: &AppState,
    session: &WalletSession,
    form_body: &[u8],
    now: DateTime<Utc>,
) -> Result<WalletEvidence, RefusalReason> {
    let invalid = |what: &str, detail: &dyn std::fmt::Display| {
        warn!(session = %session.id, %detail, "wallet response refused: {what}");
        RefusalReason::PresentationInvalid
    };

    // 2. Decrypt under the session's key, allowing only its `enc` values.
    let scalar = session
        .response_key
        .as_deref()
        .and_then(|k| URL_SAFE_NO_PAD.decode(k).ok())
        .ok_or_else(|| invalid("response key", &"missing"))?;
    let key = EcdhEsDecryptionKey::from_scalar(&session.response_key_id, &scalar)
        .map_err(|e| invalid("response key", &e))?;
    let allowed: Vec<ContentEncryption> = session
        .enc_values
        .iter()
        .filter_map(|e| ContentEncryption::parse(e))
        .collect();
    let response = match receive_direct_post_jwt(form_body, &key, &allowed)
        .map_err(|e| invalid("not a readable direct_post.jwt", &e))?
    {
        DirectPostJwt::Response(r) => r,
        DirectPostJwt::Error(e) => {
            info!(
                session = %session.id,
                error = %e.error,
                "the wallet answered with an error"
            );
            return Err(RefusalReason::WalletDeclined);
        }
        _ => {
            return Err(invalid(
                "response",
                &"an unrecognised direct_post.jwt shape",
            ));
        }
    };
    if response.state.as_deref() != Some(session.state.as_str()) {
        return Err(invalid("state", &"does not echo the session's"));
    }

    // 3. Each presentation, bound to this session's nonce and client_id.
    let mut verified = Vec::new();
    for (query_id, presentations) in &response.vp_token {
        for presentation in presentations {
            let set = crate::credentials::verify_vp_token_with_anchors(
                presentation,
                &session.client_id,
                &session.nonce,
                state.did_resolver.as_ref(),
                &state.x509_trust_anchors,
                now,
            )
            .await
            .map_err(|e| invalid("presentation", &e))?;
            let format = if presentation.is_string() {
                SD_JWT_VC_FORMAT
            } else {
                LDP_VC_FORMAT
            };
            for p in set.presentations {
                verified.push((query_id.clone(), format, p));
            }
        }
    }
    let holder = match verified.first() {
        Some((_, _, p)) => p.holder_did.clone(),
        None => return Err(invalid("vp_token", &"carries no presentation")),
    };
    if verified.iter().any(|(_, _, p)| p.holder_did != holder) {
        return Err(invalid(
            "vp_token",
            &"its presentations bind different holders",
        ));
    }

    // 4. Status, never assumed.
    let fetcher = crate::routes::join_requests::present::credential_status_fetcher(state);
    for (_, _, p) in &verified {
        let status = crate::routes::join_requests::present::resolve_presented_status(
            p.credential_status.as_ref(),
            Some(&p.issuer_did),
            &fetcher,
        )
        .await;
        if status != CredentialStatus::Valid {
            warn!(session = %session.id, issuer = %p.issuer_did, ?status,
                "wallet response refused: a credential's status is not valid");
            return Err(RefusalReason::StatusNotValid);
        }
    }

    // 5. Issuers the criterion admits.
    let own_did = state.config.read().await.vtc_did.clone();
    for (_, _, p) in &verified {
        if !crate::join::criteria::issuer_admitted(
            state,
            own_did.as_deref(),
            session.credential_issuers,
            &p.issuer_did,
        )
        .await
        {
            warn!(session = %session.id, issuer = %p.issuer_did,
                "wallet response refused: an issuer the criterion does not admit");
            return Err(RefusalReason::IssuerNotTrusted);
        }
    }

    // 6. The criterion's query, satisfied by what verified — each credential
    //    certified by an authority its query's `trusted_authorities` names,
    //    which the matcher does not read.
    let query =
        DcqlQuery::from_json(&session.dcql_query).map_err(|e| invalid("stored query", &e))?;
    for (query_id, _, p) in &verified {
        let authorities = query
            .credentials
            .iter()
            .find(|cq| cq.id == *query_id)
            .and_then(|cq| cq.trusted_authorities.as_deref());
        if let Some(authorities) = authorities
            && !crate::join::criteria::meets_trusted_authorities(
                authorities,
                &p.issuer_authority_key_ids,
            )
        {
            warn!(session = %session.id, issuer = %p.issuer_did,
                "wallet response refused: no authority the query trusts certifies its issuer");
            return Err(RefusalReason::IssuerNotTrusted);
        }
    }
    let mut answered: BTreeMap<String, Vec<CandidateCredential>> = BTreeMap::new();
    for (n, (query_id, format, p)) in verified.iter().enumerate() {
        answered
            .entry(query_id.clone())
            .or_default()
            .push(CandidateCredential {
                id: n.to_string(),
                format: (*format).to_string(),
                claims: p.claims.clone(),
                vct: p.vct.clone(),
                doctype: None,
                supports_holder_binding: p.holder_bound,
            });
    }
    if let Err(e) = query.evaluate_presentation(&answered) {
        warn!(session = %session.id, error = %e,
            "wallet response refused: it does not satisfy the query");
        return Err(RefusalReason::QueryNotSatisfied);
    }

    Ok(WalletEvidence {
        satisfied: true,
        holder,
        credentials: verified
            .into_iter()
            .map(|(credential_query_id, format, p)| EvidenceCredential {
                credential_query_id,
                format: format.to_string(),
                issuer: p.issuer_did,
                vct: p.vct,
                claims: p.claims,
                issuer_authority_key_ids: p.issuer_authority_key_ids,
            })
            .collect(),
    })
}
