//! Persisted single-use pending-offer store backing the OID4VCI
//! offer -> request -> issue loop (split out of `exchange.rs`, P2.3).

use super::issue::{credential_offer, issue_on_request};
use super::jwt::decode_segment;
use affinidi_openid4vci::{CredentialOffer, CredentialRequest, CredentialResponse};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;
use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;

// ── Pending-issuance store + the offer→request→issue wire flow ──
//
// When the community decides to issue a credential (e.g. ceremony admit mints a
// VMC), the VTC emits a pre-authorized-code offer and persists a *pending
// issuance* keyed by that code. The holder later redeems it with a
// `credential-exchange/request` carrying a key-binding proof; the issuer looks
// the pending record up, verifies the proof binds the intended subject, and
// returns the credential. The **pre-authorized code doubles as the proof
// `nonce`** (the issuer-generated freshness value the holder commits to) — no
// separate token-endpoint round-trip in the DIDComm collapse.

/// Key prefix for pending issuances. Stored in the `join_requests` keyspace
/// (credential issuance is the terminal step of the join/admit lifecycle that
/// keyspace already tracks); the join retention sweeper walks `join_requests:`,
/// a disjoint prefix, so the two never collide. A dedicated keyspace is a clean
/// future migration — the prefix is the single source of truth for the shape.
const PENDING_PREFIX: &str = "credx-pending:";

/// Default lifetime of a pending offer before it expires unredeemed.
pub const DEFAULT_OFFER_TTL: Duration = Duration::minutes(30);

fn pending_key(code: &str) -> String {
    format!("{PENDING_PREFIX}{code}")
}

/// A credential the VTC has decided to issue, awaiting redemption by the holder.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PendingIssuance {
    /// The credential to deliver (already minted; opaque here).
    credential: Value,
    /// The subject the credential is bound to — only this DID, proving key
    /// possession, may redeem.
    expected_holder_did: String,
    /// The Credential Issuer Identifier the holder's proof `aud` must name.
    issuer_id: String,
    /// Expiry, seconds since the Unix epoch.
    expires_at: i64,
}

/// Emit a pre-authorized-code credential offer and persist the pending issuance.
///
/// Returns the [`CredentialOffer`] to send to the holder and the single-use
/// `pre_authorized_code` (which the holder echoes as the proof `nonce`). The
/// credential is bound to `expected_holder_did`; only that subject can redeem.
#[allow(clippy::too_many_arguments)]
pub async fn make_offer(
    ks: &KeyspaceHandle,
    issuer_id: &str,
    config_ids: Vec<String>,
    credential: Value,
    expected_holder_did: &str,
    ttl: Duration,
    now: DateTime<Utc>,
) -> Result<(CredentialOffer, String), AppError> {
    let code = format!("pac_{}", Uuid::new_v4().simple());
    let pending = PendingIssuance {
        credential,
        expected_holder_did: expected_holder_did.to_string(),
        issuer_id: issuer_id.to_string(),
        expires_at: (now + ttl).timestamp(),
    };
    ks.insert(pending_key(&code), &pending).await?;
    Ok((credential_offer(issuer_id, config_ids, code.clone()), code))
}

/// GC every pending-issuance row whose `expires_at` has passed. [`redeem`]
/// rejects an expired offer, but an offer the holder never redeems would
/// otherwise sit in the keyspace forever (each carrying a minted credential).
/// Returns the count purged. Called by the daemon's retention sweeper.
pub async fn sweep_expired_pending(
    ks: &KeyspaceHandle,
    now: DateTime<Utc>,
) -> Result<usize, AppError> {
    let now_ts = now.timestamp();
    let mut purged = 0usize;
    for (k, raw) in ks
        .prefix_iter_raw(PENDING_PREFIX.as_bytes().to_vec())
        .await?
    {
        // Unparseable rows are left alone — best-effort GC, not validation.
        if let Ok(rec) = serde_json::from_slice::<PendingIssuance>(&raw)
            && now_ts >= rec.expires_at
        {
            ks.remove(k).await?;
            purged += 1;
        }
    }
    Ok(purged)
}

/// Redeem a credential request against a persisted pending offer.
///
/// Looks the pending issuance up by the request's proof `nonce` (the
/// pre-authorized code), checks it hasn't expired, then [`issue_on_request`]
/// verifies the key-binding proof and binds the holder. The pending record is
/// consumed (single-use) **only on success** — a forged or wrong-party request
/// returns an error without burning the legitimate holder's offer.
pub async fn redeem(
    ks: &KeyspaceHandle,
    request: &CredentialRequest,
    now: DateTime<Utc>,
) -> Result<CredentialResponse, AppError> {
    let code = proof_nonce(request)?.ok_or_else(|| {
        AppError::Validation(
            "credential request proof carries no nonce (the pre-authorized code)".into(),
        )
    })?;

    let pending = get_pending(ks, &code).await?.ok_or_else(|| {
        AppError::NotFound(
            "no pending issuance for this code (unknown, already redeemed, or expired)".into(),
        )
    })?;

    if now.timestamp() > pending.expires_at {
        // Best-effort cleanup of the expired record; ignore the result.
        let _ = ks.remove(pending_key(&code)).await;
        return Err(AppError::Validation("pending issuance has expired".into()));
    }

    // Verifies the proof signature, audience, freshness, and that the proven
    // holder DID equals the credential's bound subject (else `Forbidden`).
    let response = issue_on_request(
        request,
        pending.credential.clone(),
        &pending.expected_holder_did,
        &pending.issuer_id,
        now,
    )?;

    // Single-use: consume the offer now that issuance succeeded.
    ks.remove(pending_key(&code)).await?;
    Ok(response)
}

async fn get_pending(ks: &KeyspaceHandle, code: &str) -> Result<Option<PendingIssuance>, AppError> {
    match ks.get_raw(pending_key(code)).await? {
        Some(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|e| AppError::Internal(format!("PendingIssuance decode: {e}"))),
        None => Ok(None),
    }
}

/// Structurally read the `nonce` claim from a credential request's proof JWT —
/// the lookup key for the pending offer. This is an **unverified** peek; the
/// real cryptographic verification happens in [`issue_on_request`], and the
/// credential is only released after the holder-binding check there.
fn proof_nonce(request: &CredentialRequest) -> Result<Option<String>, AppError> {
    let Some(proof) = request.proof.as_ref() else {
        return Ok(None);
    };
    let payload_b64 = proof.jwt.split('.').nth(1).ok_or_else(|| {
        AppError::Validation("credential request proof is not a compact JWT".into())
    })?;
    let payload = decode_segment(payload_b64, "proof payload")?;
    Ok(payload
        .get("nonce")
        .and_then(Value::as_str)
        .map(str::to_string))
}
