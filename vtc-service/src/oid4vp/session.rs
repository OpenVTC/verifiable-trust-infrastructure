//! OpenID4VP wallet sessions — `vtc/join-requests/wallet-session/{start,status}/0.1`.
//!
//! A session is opened by an applicant, in a signed Trust Task, for one join
//! criterion, and answered by a wallet over OpenID4VP 1.0: it fetches the
//! signed request object from `request_uri` and posts an encrypted response to
//! `response_uri`. What the session holds, and why each piece is kept the way
//! it is:
//!
//! - **The binding** — applicant DID (the start document's proof signer),
//!   criterion version, join request. Fixed at start; nothing a wallet sends
//!   changes it (start consumer rule 4).
//! - **The nonce, `state` and the response key** — fresh per session, never
//!   reused (rule 5). The response key's private half is held only until a
//!   wallet answers or the session expires, then dropped (start §Retention),
//!   so a response captured in transit can no longer be decrypted.
//! - **The request object** — signed at start and answered once (rule 7).
//! - **The outcome** — `presented` with the evidence, or `refused` with the
//!   reason. The evidence keeps the presented claims, for the join decision
//!   to read; the status task never returns them (status consumer rule 4).
//!
//! Every state change runs under one process lock, so two wallets racing on one
//! session cannot both be accepted: the first to claim the response key wins,
//! and the second finds none.
//!
//! The keyspace is encrypted at rest and excluded from backup; the sweeper
//! closes sessions at `expiresAt` and drops records once nothing can read them.

use std::sync::LazyLock;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Duration, Utc};
use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;
use vti_common::error::AppError;

use crate::schemas::accepts::CredentialIssuers;
use crate::store::KeyspaceHandle;

/// How long a closed session's record is kept for the applicant's
/// `wallet-session/status` poll when it holds no evidence still waiting for a
/// submission (status consumer rule 8).
pub const CLOSED_RECORD_RETENTION: Duration = Duration::hours(1);

const KEY_PREFIX: &str = "session:";

/// Serialises every session state change in this process.
static SESSION_LOCK: LazyLock<tokio::sync::Mutex<()>> =
    LazyLock::new(|| tokio::sync::Mutex::new(()));

/// Where a session stands. The specification's five states, plus `verifying`:
/// a response has been claimed and is being checked, which the status task
/// reports as `requestRetrieved` — the wallet has the request and the outcome
/// is not yet known.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SessionPhase {
    AwaitingWallet,
    RequestRetrieved,
    Verifying,
    Presented,
    Refused,
    Expired,
}

impl SessionPhase {
    /// Whether a wallet may still fetch the request or answer.
    pub fn is_open(self) -> bool {
        matches!(self, Self::AwaitingWallet | Self::RequestRetrieved)
    }
}

/// Why a session ended `refused` — the status task's `reason` values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RefusalReason {
    PresentationInvalid,
    QueryNotSatisfied,
    IssuerNotTrusted,
    StatusNotValid,
    WalletDeclined,
}

/// One credential a verified presentation carried.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceCredential {
    /// The DCQL credential query it answered.
    pub credential_query_id: String,
    /// OpenID4VP's format identifier, e.g. `dc+sd-jwt`.
    pub format: String,
    /// The issuer, as verified.
    pub issuer: String,
    /// The SD-JWT VC type, when there is one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vct: Option<String>,
    /// The disclosed claims. Kept for the join decision; never returned by the
    /// status task.
    pub claims: Value,
}

impl std::fmt::Debug for EvidenceCredential {
    /// Written by hand so presented claims never reach a log.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EvidenceCredential")
            .field("credential_query_id", &self.credential_query_id)
            .field("format", &self.format)
            .field("issuer", &self.issuer)
            .field("vct", &self.vct)
            .field("claims", &"<redacted>")
            .finish()
    }
}

/// What a verified wallet response established.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WalletEvidence {
    /// The presentation satisfies the session's DCQL query.
    pub satisfied: bool,
    /// The key that held the credentials: the `did:key` of their `cnf` key.
    /// Recorded beside the applicant, never as them (start consumer rule 10).
    pub holder: String,
    pub credentials: Vec<EvidenceCredential>,
}

/// One wallet session, as stored.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WalletSession {
    /// The session id: 192 random bits, base64url. Also the last path segment
    /// of `request_uri` and `response_uri`.
    pub id: String,
    /// The start document's proof signer.
    pub applicant_did: String,
    /// The criterion the session collects evidence for.
    pub criterion_id: String,
    /// The `requirementsDigest` of the version the applicant named.
    pub requirements_digest: String,
    /// Which issuers that criterion version admits.
    pub credential_issuers: CredentialIssuers,
    /// The join request the evidence is for, when the applicant named one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<Uuid>,
    /// The verifier identity that signed the request object.
    pub identity_id: String,
    /// Its client identifier, prefix included: the audience a key-binding
    /// proof must name.
    pub client_id: String,
    /// The criterion's published query, unchanged.
    pub dcql_query: Value,
    /// The single-use challenge the key-binding proof commits to.
    pub nonce: String,
    /// The OpenID4VP `state` the wallet echoes.
    pub state: String,
    /// The JWE `enc` values the response may use.
    pub enc_values: Vec<String>,
    /// The response key's `kid`, as published in `client_metadata.jwks`.
    pub response_key_id: String,
    /// The response key's private scalar, base64url. `None` once a wallet has
    /// answered or the session has closed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_key: Option<String>,
    /// The signed request object. `None` once fetched or the session closed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_object: Option<String>,
    pub phase: SessionPhase,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<RefusalReason>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence: Option<WalletEvidence>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub closed_at: Option<DateTime<Utc>>,
    /// When evidence not bound to a join request is discarded unclaimed
    /// (start consumer rule 11).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub held_until: Option<DateTime<Utc>>,
}

impl std::fmt::Debug for WalletSession {
    /// Written by hand so the response key never reaches a log.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WalletSession")
            .field("id", &self.id)
            .field("applicant_did", &self.applicant_did)
            .field("criterion_id", &self.criterion_id)
            .field("request_id", &self.request_id)
            .field("identity_id", &self.identity_id)
            .field("phase", &self.phase)
            .field("reason", &self.reason)
            .field(
                "response_key",
                &self.response_key.as_ref().map(|_| "<redacted>"),
            )
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

impl WalletSession {
    /// Whether the session is still open at `now`.
    pub fn open_at(&self, now: DateTime<Utc>) -> bool {
        self.phase.is_open() && now < self.expires_at
    }

    /// Close the session as `phase`, dropping the response key and the
    /// request object.
    fn close(&mut self, phase: SessionPhase, now: DateTime<Utc>) {
        self.phase = phase;
        self.response_key = None;
        self.request_object = None;
        self.closed_at = Some(now);
    }

    /// When the record may be dropped: a while after it closed, or when its
    /// held evidence lapses, whichever is later.
    fn drop_after(&self) -> Option<DateTime<Utc>> {
        let closed = self.closed_at? + CLOSED_RECORD_RETENTION;
        Some(match self.held_until {
            Some(held) if held > closed => held,
            _ => closed,
        })
    }
}

/// `n` random bytes, base64url.
pub fn random_token(n: usize) -> String {
    let mut bytes = vec![0u8; n];
    rand::rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn storage_key(id: &str) -> String {
    format!("{KEY_PREFIX}{id}")
}

/// Store a new session.
pub async fn insert(ks: &KeyspaceHandle, session: &WalletSession) -> Result<(), AppError> {
    let _guard = SESSION_LOCK.lock().await;
    ks.insert(storage_key(&session.id), session).await
}

/// Read a session.
pub async fn get(ks: &KeyspaceHandle, id: &str) -> Result<Option<WalletSession>, AppError> {
    ks.get(storage_key(id)).await
}

/// Every stored session.
pub async fn list(ks: &KeyspaceHandle) -> Result<Vec<WalletSession>, AppError> {
    let rows = ks.prefix_iter_raw(KEY_PREFIX).await?;
    let mut out = Vec::with_capacity(rows.len());
    for (_, value) in rows {
        out.push(serde_json::from_slice(&value).map_err(|e| {
            AppError::Internal(format!("an oid4vp_sessions record does not parse: {e}"))
        })?);
    }
    Ok(out)
}

/// How many sessions `applicant_did` holds open at `now`.
pub async fn open_count(
    ks: &KeyspaceHandle,
    applicant_did: &str,
    now: DateTime<Utc>,
) -> Result<usize, AppError> {
    Ok(list(ks)
        .await?
        .iter()
        .filter(|s| s.applicant_did == applicant_did && s.open_at(now))
        .count())
}

/// Hand out the request object, once. Moves an `awaitingWallet` session to
/// `requestRetrieved`. `None` for an unknown, closed or expired session, or
/// one whose request object was already fetched.
pub async fn take_request_object(
    ks: &KeyspaceHandle,
    id: &str,
    now: DateTime<Utc>,
) -> Result<Option<String>, AppError> {
    let _guard = SESSION_LOCK.lock().await;
    let Some(mut session) = get(ks, id).await? else {
        return Ok(None);
    };
    if !session.open_at(now) {
        return Ok(None);
    }
    let Some(jar) = session.request_object.take() else {
        return Ok(None);
    };
    session.phase = SessionPhase::RequestRetrieved;
    ks.insert(storage_key(id), &session).await?;
    Ok(Some(jar))
}

/// Claim a session for a wallet's response: take its response key and mark it
/// `verifying`. Exactly one caller succeeds; any later response finds no key.
/// Returns the session as it was claimed, response key included.
pub async fn claim_for_response(
    ks: &KeyspaceHandle,
    id: &str,
    now: DateTime<Utc>,
) -> Result<Option<WalletSession>, AppError> {
    let _guard = SESSION_LOCK.lock().await;
    let Some(mut session) = get(ks, id).await? else {
        return Ok(None);
    };
    if !session.open_at(now) || session.response_key.is_none() {
        return Ok(None);
    }
    let claimed = session.clone();
    session.phase = SessionPhase::Verifying;
    session.response_key = None;
    session.request_object = None;
    ks.insert(storage_key(id), &session).await?;
    Ok(Some(claimed))
}

/// Record the outcome of a claimed session. `evidence` for `presented`,
/// `reason` for `refused`; `hold` is how long unbound evidence is held.
pub async fn finish(
    ks: &KeyspaceHandle,
    id: &str,
    outcome: Result<WalletEvidence, RefusalReason>,
    hold: Duration,
    now: DateTime<Utc>,
) -> Result<WalletSession, AppError> {
    let _guard = SESSION_LOCK.lock().await;
    let mut session = get(ks, id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("wallet session {id} vanished")))?;
    match outcome {
        Ok(evidence) => {
            session.close(SessionPhase::Presented, now);
            if session.request_id.is_none() {
                session.held_until = Some(now + hold);
            }
            session.evidence = Some(evidence);
        }
        Err(reason) => {
            session.close(SessionPhase::Refused, now);
            session.reason = Some(reason);
        }
    }
    ks.insert(storage_key(id), &session).await?;
    Ok(session)
}

/// Close sessions past `expiresAt` that no wallet answered, and drop records
/// nothing can read any more. Returns `(expired, dropped)`.
///
/// A session left `verifying` by a process that died mid-check is closed as
/// `refused` once it is past `expiresAt`: its response key is already gone,
/// so it cannot be finished, and `presentationInvalid` is the honest account.
pub async fn sweep(ks: &KeyspaceHandle, now: DateTime<Utc>) -> Result<(usize, usize), AppError> {
    let _guard = SESSION_LOCK.lock().await;
    let (mut expired, mut dropped) = (0, 0);
    for mut session in list(ks).await? {
        if session.phase.is_open() && now >= session.expires_at {
            session.close(SessionPhase::Expired, now);
            ks.insert(storage_key(&session.id), &session).await?;
            expired += 1;
        } else if session.phase == SessionPhase::Verifying && now >= session.expires_at {
            session.close(SessionPhase::Refused, now);
            session.reason = Some(RefusalReason::PresentationInvalid);
            ks.insert(storage_key(&session.id), &session).await?;
            expired += 1;
        } else if session.drop_after().is_some_and(|t| now >= t) {
            ks.remove(storage_key(&session.id)).await?;
            dropped += 1;
        }
    }
    Ok((expired, dropped))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn session(id: &str, applicant: &str, now: DateTime<Utc>) -> WalletSession {
        WalletSession {
            id: id.into(),
            applicant_did: applicant.into(),
            criterion_id: "residence".into(),
            requirements_digest: "zQmDigest".into(),
            credential_issuers: CredentialIssuers::Any,
            request_id: None,
            identity_id: "swiyu".into(),
            client_id: "decentralized_identifier:did:webvh:Qm:verifier.example".into(),
            dcql_query: json!({ "credentials": [] }),
            nonce: random_token(16),
            state: random_token(16),
            enc_values: vec!["A256GCM".into()],
            response_key_id: "response-key".into(),
            response_key: Some("scalar".into()),
            request_object: Some("jar".into()),
            phase: SessionPhase::AwaitingWallet,
            reason: None,
            evidence: None,
            created_at: now,
            expires_at: now + Duration::minutes(10),
            closed_at: None,
            held_until: None,
        }
    }

    fn evidence() -> WalletEvidence {
        WalletEvidence {
            satisfied: true,
            holder: "did:key:zDnHolder".into(),
            credentials: vec![],
        }
    }

    async fn ks() -> (tempfile::TempDir, KeyspaceHandle) {
        let dir = tempfile::tempdir().unwrap();
        let store = vti_common::store::Store::open(&vti_common::config::StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .unwrap();
        let ks = store
            .keyspace(crate::store::keyspaces::OID4VP_SESSIONS)
            .unwrap();
        (dir, ks)
    }

    /// The request object is answered once (start consumer rule 7), and the
    /// fetch is what moves the session to `requestRetrieved`.
    #[tokio::test]
    async fn the_request_object_is_handed_out_once() {
        let (_dir, ks) = ks().await;
        let now = Utc::now();
        insert(&ks, &session("s1", "did:key:a", now)).await.unwrap();
        assert_eq!(
            take_request_object(&ks, "s1", now)
                .await
                .unwrap()
                .as_deref(),
            Some("jar")
        );
        assert_eq!(take_request_object(&ks, "s1", now).await.unwrap(), None);
        let s = get(&ks, "s1").await.unwrap().unwrap();
        assert_eq!(s.phase, SessionPhase::RequestRetrieved);
    }

    /// One response per session: the first claim takes the key, a second
    /// finds none.
    #[tokio::test]
    async fn only_one_response_can_claim_a_session() {
        let (_dir, ks) = ks().await;
        let now = Utc::now();
        insert(&ks, &session("s1", "did:key:a", now)).await.unwrap();
        let claimed = claim_for_response(&ks, "s1", now).await.unwrap().unwrap();
        assert_eq!(claimed.response_key.as_deref(), Some("scalar"));
        assert!(claim_for_response(&ks, "s1", now).await.unwrap().is_none());
        let stored = get(&ks, "s1").await.unwrap().unwrap();
        assert_eq!(stored.phase, SessionPhase::Verifying);
        assert!(
            stored.response_key.is_none(),
            "the key leaves with the claim"
        );
    }

    /// An expired session takes no request fetch and no response.
    #[tokio::test]
    async fn an_expired_session_answers_nothing() {
        let (_dir, ks) = ks().await;
        let now = Utc::now();
        insert(&ks, &session("s1", "did:key:a", now)).await.unwrap();
        let later = now + Duration::minutes(11);
        assert_eq!(take_request_object(&ks, "s1", later).await.unwrap(), None);
        assert!(
            claim_for_response(&ks, "s1", later)
                .await
                .unwrap()
                .is_none()
        );
    }

    /// Unbound evidence is held for a bounded time; evidence bound to a
    /// request is not "held" at all.
    #[tokio::test]
    async fn only_unbound_evidence_is_held() {
        let (_dir, ks) = ks().await;
        let now = Utc::now();
        insert(&ks, &session("s1", "did:key:a", now)).await.unwrap();
        let mut bound = session("s2", "did:key:a", now);
        bound.request_id = Some(Uuid::new_v4());
        insert(&ks, &bound).await.unwrap();
        for id in ["s1", "s2"] {
            claim_for_response(&ks, id, now).await.unwrap().unwrap();
        }
        let hold = Duration::hours(6);
        let s1 = finish(&ks, "s1", Ok(evidence()), hold, now).await.unwrap();
        assert_eq!(s1.held_until, Some(now + hold));
        assert_eq!(s1.phase, SessionPhase::Presented);
        let s2 = finish(&ks, "s2", Ok(evidence()), hold, now).await.unwrap();
        assert_eq!(s2.held_until, None);
    }

    /// The sweeper expires an unanswered session (dropping its key), refuses one
    /// a dead process left mid-check, and drops records once nothing reads
    /// them.
    #[tokio::test]
    async fn the_sweeper_closes_and_then_drops() {
        let (_dir, ks) = ks().await;
        let now = Utc::now();
        insert(&ks, &session("open", "did:key:a", now))
            .await
            .unwrap();
        insert(&ks, &session("stuck", "did:key:a", now))
            .await
            .unwrap();
        claim_for_response(&ks, "stuck", now)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(sweep(&ks, now).await.unwrap(), (0, 0));
        let past = now + Duration::minutes(11);
        assert_eq!(sweep(&ks, past).await.unwrap(), (2, 0));
        let open = get(&ks, "open").await.unwrap().unwrap();
        assert_eq!(open.phase, SessionPhase::Expired);
        assert!(open.response_key.is_none() && open.request_object.is_none());
        let stuck = get(&ks, "stuck").await.unwrap().unwrap();
        assert_eq!(stuck.phase, SessionPhase::Refused);
        assert_eq!(stuck.reason, Some(RefusalReason::PresentationInvalid));

        let much_later = past + CLOSED_RECORD_RETENTION;
        assert_eq!(sweep(&ks, much_later).await.unwrap(), (0, 2));
        assert!(list(&ks).await.unwrap().is_empty());
    }

    /// A record holding evidence for a submission outlives the usual retention
    /// until its hold lapses.
    #[tokio::test]
    async fn held_evidence_outlives_the_closed_record_retention() {
        let (_dir, ks) = ks().await;
        let now = Utc::now();
        insert(&ks, &session("s1", "did:key:a", now)).await.unwrap();
        claim_for_response(&ks, "s1", now).await.unwrap().unwrap();
        finish(&ks, "s1", Ok(evidence()), Duration::hours(6), now)
            .await
            .unwrap();
        assert_eq!(sweep(&ks, now + Duration::hours(2)).await.unwrap(), (0, 0));
        assert_eq!(sweep(&ks, now + Duration::hours(6)).await.unwrap(), (0, 1));
    }

    #[test]
    fn open_counts_only_this_applicants_open_sessions() {
        let now = Utc::now();
        let mut closed = session("c", "did:key:a", now);
        closed.close(SessionPhase::Expired, now);
        assert!(!closed.open_at(now));
        assert!(session("o", "did:key:a", now).open_at(now));
    }
}
