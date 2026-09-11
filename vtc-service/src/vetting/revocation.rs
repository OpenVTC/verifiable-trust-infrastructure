//! Withdrawal of vetting statements (`vtc/vetting/revoke-statement/0.1`).
//!
//! OpenVTC vetting design §9.6. A vetter who made a mistake, learned something
//! new, or lost control of their key tells the community — the one party that
//! relies on the statement — directly. The VTA's own `credentials/revoke` only
//! marks its local record, so without this nothing a verifier reads would
//! change.
//!
//! ## What a notice can do
//!
//! A notice is keyed by **issuer + statement id + statement digest** and counts
//! only against a presented statement with all three. The issuer half is the
//! authenticated sender, never a member of the body, so a notice can withdraw
//! only a statement its sender signed: a notice about someone else's statement
//! is recorded under the wrong issuer and matches nothing. The digest half
//! binds it to one credential rather than to an id another credential could
//! reuse, and is compared on its decoded bytes, as DTG Credentials requires.
//!
//! Only members may send one. Vetters are members, and it keeps the store from
//! being a sink anyone who can reach the service can write to.
//!
//! Recording converges: a repeated notice returns the time the first was
//! recorded and writes nothing.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::info;

use vta_sdk::protocols::vetting::{RevocationReason, RevokeStatementBody};
use vti_common::audit::{AuditEvent, VettingStatementRevokedData};
use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;

use crate::members::storage::get_member;
use crate::server::AppState;

/// Domain separation for notice keys.
const KEY_DOMAIN: &[u8] = b"vtc-vetting-revocation/v1\0";

/// A recorded withdrawal.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RevocationNotice {
    /// The vetter who withdrew it — the authenticated sender.
    pub issuer: String,
    /// The statement's `id`.
    pub statement_id: String,
    /// The statement's `digestMultibase`, as sent.
    pub statement_digest_multibase: String,
    /// The vetter's reason, when given.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<RevocationReason>,
    /// When the first notice was recorded.
    pub recorded_at: DateTime<Utc>,
}

/// The storage key: a domain-separated hash over the issuer, the statement id,
/// and the digest's algorithm and decoded bytes — two encodings of one digest
/// are one key.
fn notice_key(
    issuer: &str,
    statement_id: &str,
    digest_multibase: &str,
) -> Result<String, AppError> {
    let (algorithm, digest) = dtg_credentials::decode_digest_multibase(digest_multibase)
        .map_err(|e| AppError::Validation(format!("statementDigestMultibase: {e}")))?;
    let mut hasher = Sha256::new();
    hasher.update(KEY_DOMAIN);
    hasher.update(issuer.as_bytes());
    hasher.update([0u8]);
    hasher.update(statement_id.as_bytes());
    hasher.update([0u8]);
    hasher.update(algorithm.to_be_bytes());
    hasher.update(&digest);
    Ok(hex::encode(hasher.finalize()))
}

/// Has `issuer` withdrawn the statement with this id and digest?
///
/// A digest that does not decode cannot name a notice, so it reads as not
/// withdrawn; statements reaching this have been verified, and their digest is
/// computed here rather than taken from the wire.
pub async fn is_revoked(
    ks: &KeyspaceHandle,
    issuer: &str,
    statement_id: &str,
    digest_multibase: &str,
) -> Result<bool, AppError> {
    let Ok(key) = notice_key(issuer, statement_id, digest_multibase) else {
        return Ok(false);
    };
    Ok(ks.get_raw(key.as_bytes()).await?.is_some())
}

/// Record a notice from `issuer`, or return the one already recorded. The
/// boolean is `true` when this call wrote it.
pub async fn record(
    ks: &KeyspaceHandle,
    issuer: &str,
    body: &RevokeStatementBody,
    now: DateTime<Utc>,
) -> Result<(RevocationNotice, bool), AppError> {
    body.check_shape()
        .map_err(|e| AppError::Validation(e.to_string()))?;
    let key = notice_key(issuer, &body.statement_id, &body.statement_digest_multibase)?;
    if let Some(bytes) = ks.get_raw(key.as_bytes()).await? {
        let existing = serde_json::from_slice(&bytes)
            .map_err(|e| AppError::Internal(format!("revocation notice decode: {e}")))?;
        return Ok((existing, false));
    }
    let notice = RevocationNotice {
        issuer: issuer.to_string(),
        statement_id: body.statement_id.clone(),
        statement_digest_multibase: body.statement_digest_multibase.clone(),
        reason: body.reason,
        recorded_at: now,
    };
    ks.insert(key, &notice).await?;
    Ok((notice, true))
}

/// Every recorded notice, newest first. A row that does not decode is skipped
/// and logged.
pub async fn list_notices(ks: &KeyspaceHandle) -> Result<Vec<RevocationNotice>, AppError> {
    let rows = ks.prefix_iter_raw(Vec::new()).await?;
    let mut notices: Vec<RevocationNotice> = rows
        .into_iter()
        .filter_map(|(_k, v)| match serde_json::from_slice(&v) {
            Ok(n) => Some(n),
            Err(e) => {
                tracing::warn!(error = %e, "skipping an undecodable withdrawal notice");
                None
            }
        })
        .collect();
    notices.sort_by_key(|n| std::cmp::Reverse(n.recorded_at));
    Ok(notices)
}

/// Handle a withdrawal from `vetter_did`, the authenticated sender: refuse a
/// non-member, record the notice, and audit it the first time.
pub async fn withdraw(
    state: &AppState,
    vetter_did: &str,
    body: &RevokeStatementBody,
) -> Result<RevocationNotice, AppError> {
    if get_member(&state.members_ks, vetter_did).await?.is_none() {
        return Err(AppError::Forbidden(
            "only a member of this community can withdraw a vetting statement".into(),
        ));
    }
    let (notice, created) =
        record(&state.vetting_revocations_ks, vetter_did, body, Utc::now()).await?;
    if created {
        if let Some(writer) = state.audit_writer.as_ref() {
            writer
                .write(
                    vetter_did,
                    None,
                    AuditEvent::VettingStatementRevoked(VettingStatementRevokedData {
                        statement_id: notice.statement_id.clone(),
                        statement_digest_multibase: notice.statement_digest_multibase.clone(),
                        reason: notice
                            .reason
                            .and_then(|r| serde_json::to_value(r).ok())
                            .and_then(|v| v.as_str().map(str::to_string)),
                    }),
                )
                .await?;
        }
        info!(statement = %notice.statement_id, "vetting statement withdrawn");
    }
    Ok(notice)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use vti_common::config::StoreConfig;
    use vti_common::store::Store;

    async fn ks() -> (tempfile::TempDir, Store, KeyspaceHandle) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .unwrap();
        let ks = store.keyspace("vetting_revocations").unwrap();
        (dir, store, ks)
    }

    fn body(id: &str, digest: &str) -> RevokeStatementBody {
        RevokeStatementBody {
            statement_id: id.into(),
            statement_digest_multibase: digest.into(),
            reason: Some(RevocationReason::Mistake),
            ext: None,
        }
    }

    fn digest_of(v: serde_json::Value) -> String {
        dtg_credentials::digest_multibase_json(&v).unwrap()
    }

    #[tokio::test]
    async fn a_notice_withdraws_only_its_own_issuers_statement() {
        let (_d, _s, ks) = ks().await;
        let digest = digest_of(json!({ "statement": 1 }));
        record(
            &ks,
            "did:key:zCarol",
            &body("urn:uuid:s1", &digest),
            Utc::now(),
        )
        .await
        .unwrap();

        assert!(
            is_revoked(&ks, "did:key:zCarol", "urn:uuid:s1", &digest)
                .await
                .unwrap()
        );
        assert!(
            !is_revoked(&ks, "did:key:zMallory", "urn:uuid:s1", &digest)
                .await
                .unwrap(),
            "a notice is keyed by its sender — it cannot reach another issuer's statement"
        );
        let other = digest_of(json!({ "statement": 2 }));
        assert!(
            !is_revoked(&ks, "did:key:zCarol", "urn:uuid:s1", &other)
                .await
                .unwrap(),
            "a different credential reusing the id is not withdrawn"
        );
    }

    #[tokio::test]
    async fn repeating_a_notice_converges_on_the_first() {
        let (_d, _s, ks) = ks().await;
        let digest = digest_of(json!({ "statement": 1 }));
        let first_time = Utc::now() - chrono::Duration::hours(1);
        let (first, created) = record(
            &ks,
            "did:key:zCarol",
            &body("urn:uuid:s1", &digest),
            first_time,
        )
        .await
        .unwrap();
        assert!(created);
        let (again, created) = record(
            &ks,
            "did:key:zCarol",
            &body("urn:uuid:s1", &digest),
            Utc::now(),
        )
        .await
        .unwrap();
        assert!(!created);
        assert_eq!(again.recorded_at, first.recorded_at);
    }

    #[tokio::test]
    async fn a_malformed_digest_is_refused_and_names_nothing() {
        let (_d, _s, ks) = ks().await;
        let err = record(
            &ks,
            "did:key:zCarol",
            &body("urn:uuid:s1", "not-multibase"),
            Utc::now(),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, AppError::Validation(_)), "{err:?}");
        assert!(
            !is_revoked(&ks, "did:key:zCarol", "urn:uuid:s1", "not-multibase")
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn an_empty_statement_id_is_refused() {
        let (_d, _s, ks) = ks().await;
        let digest = digest_of(json!({ "statement": 1 }));
        assert!(matches!(
            record(&ks, "did:key:zCarol", &body("  ", &digest), Utc::now()).await,
            Err(AppError::Validation(_))
        ));
    }
}
