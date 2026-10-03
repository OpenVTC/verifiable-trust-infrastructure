//! CRUD helpers for [`super::JoinRequest`].
//!
//! `join_requests:<uuid>` key shape. The UUID-keyed shape (rather
//! than DID-keyed) is plan §D8: a join request has an ID before
//! the applicant DID is admitted to the community.

use uuid::Uuid;
use vti_common::audit::AuditKey;
use vti_common::error::AppError;
use vti_common::pagination::{Cursor, Paginated, paginate};
use vti_common::store::KeyspaceHandle;

use super::JoinRequest;

/// Hard cap on the bytes-on-disk size of `JoinRequest.vp`. The
/// route layer enforces this at submit time so an adversary
/// can't fill the keyspace with multi-megabyte VPs.
pub const JOIN_REQUEST_VP_MAX_BYTES: usize = 256 * 1024;

/// Hard cap on `JoinRequest.extensions`.
pub const JOIN_REQUEST_EXTENSIONS_MAX_BYTES: usize = 16 * 1024;

const PREFIX: &[u8] = b"join_requests:";

fn key(id: Uuid) -> Vec<u8> {
    let mut k = PREFIX.to_vec();
    k.extend_from_slice(id.as_hyphenated().to_string().as_bytes());
    k
}

fn decode(bytes: &[u8]) -> Result<JoinRequest, AppError> {
    serde_json::from_slice(bytes)
        .map_err(|e| AppError::Internal(format!("JoinRequest decode: {e}")))
}

pub async fn get_join_request(
    ks: &KeyspaceHandle,
    id: Uuid,
) -> Result<Option<JoinRequest>, AppError> {
    let raw = ks.get_raw(key(id)).await?;
    match raw {
        Some(bytes) => Ok(Some(decode(&bytes)?)),
        None => Ok(None),
    }
}

pub async fn store_join_request(
    ks: &KeyspaceHandle,
    request: &JoinRequest,
) -> Result<(), AppError> {
    let vp_bytes = serde_json::to_vec(&request.vp)
        .map_err(|e| AppError::Internal(format!("JoinRequest vp serialize: {e}")))?;
    if vp_bytes.len() > JOIN_REQUEST_VP_MAX_BYTES {
        return Err(AppError::Validation(format!(
            "join request VP exceeds {} bytes (got {})",
            JOIN_REQUEST_VP_MAX_BYTES,
            vp_bytes.len(),
        )));
    }
    let extensions_bytes = serde_json::to_vec(&request.extensions)
        .map_err(|e| AppError::Internal(format!("JoinRequest extensions serialize: {e}")))?;
    if extensions_bytes.len() > JOIN_REQUEST_EXTENSIONS_MAX_BYTES {
        return Err(AppError::Validation(format!(
            "join request extensions exceeds {} bytes (got {})",
            JOIN_REQUEST_EXTENSIONS_MAX_BYTES,
            extensions_bytes.len(),
        )));
    }
    ks.insert(
        String::from_utf8(key(request.id)).expect("key is ASCII"),
        request,
    )
    .await?;
    // Created, decided, withdrawn, supplemented: every change to a request is
    // a store here (`crate::admin_events`).
    crate::admin_events::notify(crate::admin_events::Topic::JoinRequests);
    Ok(())
}

/// Delete a join request and the vetting facts recorded for it.
pub async fn delete_join_request(ks: &KeyspaceHandle, id: Uuid) -> Result<(), AppError> {
    ks.remove(vetting_facts_key(id)).await?;
    ks.remove(credential_resends_key(id)).await?;
    ks.remove(criterion_key(id)).await?;
    ks.remove(key(id)).await?;
    crate::admin_events::notify(crate::admin_events::Topic::JoinRequests);
    Ok(())
}

/// Key prefix of the criterion record kept for a join request. Distinct from
/// [`PREFIX`], so a request listing never reads one.
const CRITERION_PREFIX: &[u8] = b"join_criterion:";

fn criterion_key(id: Uuid) -> Vec<u8> {
    let mut k = CRITERION_PREFIX.to_vec();
    k.extend_from_slice(id.as_hyphenated().to_string().as_bytes());
    k
}

/// Which criterion, and which version of it, a join was decided under, and so
/// what a supplement re-decides it under.
///
/// The record decision rule 4 of `vtc/join-requests/submit/0.3` requires.
///
/// Kept beside the request rather than on it, for the reason
/// [`StoredVettingFacts`] is: the request row is a published wire shape.
/// Deleted with the request.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StoredCriterion {
    /// The join request.
    pub request_id: Uuid,
    /// The criterion as the decision read it.
    pub criterion: crate::join::criteria::CriterionFact,
    /// When the decision was taken.
    pub decided_at: chrono::DateTime<chrono::Utc>,
}

/// Record the criterion a join request was decided under.
pub async fn store_criterion(
    ks: &KeyspaceHandle,
    request_id: Uuid,
    criterion: &crate::join::criteria::CriterionFact,
    decided_at: chrono::DateTime<chrono::Utc>,
) -> Result<(), AppError> {
    let row = StoredCriterion {
        request_id,
        criterion: criterion.clone(),
        decided_at,
    };
    ks.insert(
        String::from_utf8(criterion_key(request_id)).expect("key is ASCII"),
        &row,
    )
    .await
}

/// The criterion a join request was decided under, if recorded.
pub async fn get_criterion(
    ks: &KeyspaceHandle,
    request_id: Uuid,
) -> Result<Option<StoredCriterion>, AppError> {
    match ks.get_raw(criterion_key(request_id)).await? {
        Some(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|e| AppError::Internal(format!("join criterion record decode: {e}"))),
        None => Ok(None),
    }
}

/// Key prefix of the credential re-delivery record for a join request
/// ([`CredentialResends`]). Distinct from [`PREFIX`], so a request listing
/// never reads one.
const CREDENTIAL_RESENDS_PREFIX: &[u8] = b"join_resend:";

fn credential_resends_key(id: Uuid) -> Vec<u8> {
    let mut k = CREDENTIAL_RESENDS_PREFIX.to_vec();
    k.extend_from_slice(id.as_hyphenated().to_string().as_bytes());
    k
}

/// The community's own count of credential re-deliveries it has honoured for
/// one join request, kept for their rate limit. Never on the wire.
///
/// An applicant asks for a re-delivery with the status poll's
/// `resendCredentials` flag; this records how often that was honoured and when
/// last. A row of its own rather than a member of [`JoinRequest`], which is the
/// canonical `JoinRequest` component on the admin surface: this is the
/// community's bookkeeping, not part of the request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialResends {
    /// Re-deliveries honoured so far.
    pub count: u32,
    /// When the last one was honoured.
    pub last_at: chrono::DateTime<chrono::Utc>,
}

/// The re-delivery record for `request_id`, if any re-delivery was honoured.
pub async fn get_credential_resends(
    ks: &KeyspaceHandle,
    request_id: Uuid,
) -> Result<Option<CredentialResends>, AppError> {
    ks.get(credential_resends_key(request_id)).await
}

/// Record a re-delivery honoured for `request_id`.
pub async fn store_credential_resends(
    ks: &KeyspaceHandle,
    request_id: Uuid,
    resends: &CredentialResends,
) -> Result<(), AppError> {
    ks.insert(
        String::from_utf8(credential_resends_key(request_id)).expect("key is ASCII"),
        resends,
    )
    .await
}

/// Key prefix of the vetting facts recorded for a join request. Distinct from
/// [`PREFIX`], so a request listing never reads one.
const VETTING_FACTS_PREFIX: &[u8] = b"join_vetting:";

fn vetting_facts_key(id: Uuid) -> Vec<u8> {
    let mut k = VETTING_FACTS_PREFIX.to_vec();
    k.extend_from_slice(id.as_hyphenated().to_string().as_bytes());
    k
}

/// What the community established about a join request's vetting evidence
/// when it decided the request — the facts the policy read.
///
/// Kept beside the request rather than on it: the request row is a published
/// wire shape (`vtc/join-requests/show/0.1`), and these are the host's working
/// record. They answer `GET /v1/join-requests/{id}/vetting`, tell the vetter
/// sweep how a member was admitted, and let a withdrawn statement be traced to
/// the admissions it counted toward. Deleted with the request.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StoredVettingFacts {
    /// The join request.
    pub request_id: Uuid,
    /// The facts, as the policy read them.
    pub facts: crate::vetting::VettingFacts,
    /// When they were recorded.
    pub recorded_at: chrono::DateTime<chrono::Utc>,
}

/// Record the vetting facts a join request was decided on.
pub async fn store_vetting_facts(
    ks: &KeyspaceHandle,
    request_id: Uuid,
    facts: &crate::vetting::VettingFacts,
    recorded_at: chrono::DateTime<chrono::Utc>,
) -> Result<(), AppError> {
    let row = StoredVettingFacts {
        request_id,
        facts: facts.clone(),
        recorded_at,
    };
    ks.insert(
        String::from_utf8(vetting_facts_key(request_id)).expect("key is ASCII"),
        &row,
    )
    .await
}

/// The vetting facts recorded for a join request, if any.
pub async fn get_vetting_facts(
    ks: &KeyspaceHandle,
    request_id: Uuid,
) -> Result<Option<StoredVettingFacts>, AppError> {
    match ks.get_raw(vetting_facts_key(request_id)).await? {
        Some(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|e| AppError::Internal(format!("join vetting facts decode: {e}"))),
        None => Ok(None),
    }
}

/// Whole-keyspace walk — used by the retention sweeper. Routes use
/// [`list_join_requests_paginated`] instead.
pub async fn list_join_requests(ks: &KeyspaceHandle) -> Result<Vec<JoinRequest>, AppError> {
    let raw = ks.prefix_iter_raw(PREFIX.to_vec()).await?;
    let mut out = Vec::with_capacity(raw.len());
    for (_k, v) in raw {
        match decode(&v) {
            Ok(r) => out.push(r),
            Err(err) => tracing::warn!(error = %err, "skipping unparseable join_request row"),
        }
    }
    Ok(out)
}

pub async fn list_join_requests_paginated(
    ks: &KeyspaceHandle,
    audit_key: &AuditKey,
    cursor: Option<&Cursor>,
    limit: usize,
) -> Result<Paginated<JoinRequest>, AppError> {
    list_join_requests_filtered(ks, audit_key, cursor, limit, |_| true).await
}

/// One page of the join requests `keep` admits, the filter applied **before**
/// paging: the cursor walks the filtered set, so a page of pending requests
/// is never empty while a pending request lies further on, and
/// `totalEstimate` is the exact number the filter admits
/// (`vtc/join-requests/list/0.1`). Exact because it is free here — the page
/// is cut from the keyspace already held in memory. A row that does not
/// decode is skipped and logged, never fatal.
pub async fn list_join_requests_filtered(
    ks: &KeyspaceHandle,
    audit_key: &AuditKey,
    cursor: Option<&Cursor>,
    limit: usize,
    keep: impl Fn(&JoinRequest) -> bool,
) -> Result<Paginated<JoinRequest>, AppError> {
    let mut pairs = ks.prefix_iter_raw(PREFIX.to_vec()).await?;
    pairs.sort_by(|(a, _), (b, _)| a.cmp(b));
    let snapshot_id: u64 = pairs.len() as u64;
    pairs.retain(|(_, v)| match decode(v) {
        Ok(r) => keep(&r),
        Err(err) => {
            tracing::warn!(error = %err, "skipping unparseable join_request row");
            false
        }
    });
    let total = pairs.len() as u64;
    let mut page = paginate(pairs, cursor, limit, &audit_key.key, snapshot_id, decode)?;
    page.total_estimate = Some(total);
    Ok(page)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::join::JoinStatus;
    use vti_common::config::StoreConfig;
    use vti_common::store::Store;

    async fn temp_ks() -> (KeyspaceHandle, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .unwrap();
        let ks = store.keyspace("join_requests").unwrap();
        (ks, dir)
    }

    fn fresh(applicant: &str) -> JoinRequest {
        JoinRequest::new(applicant, serde_json::json!({"vp":"placeholder"}))
    }

    #[tokio::test]
    async fn round_trip() {
        let (ks, _dir) = temp_ks().await;
        let r = fresh("did:key:zApplicant");
        store_join_request(&ks, &r).await.unwrap();
        let got = get_join_request(&ks, r.id).await.unwrap().unwrap();
        assert_eq!(got, r);
    }

    #[tokio::test]
    async fn list_returns_every_request() {
        let (ks, _dir) = temp_ks().await;
        for did in ["did:key:zA", "did:key:zB", "did:key:zC"] {
            store_join_request(&ks, &fresh(did)).await.unwrap();
        }
        let list = list_join_requests(&ks).await.unwrap();
        assert_eq!(list.len(), 3);
    }

    #[tokio::test]
    async fn delete_is_idempotent() {
        let (ks, _dir) = temp_ks().await;
        let r = fresh("did:key:z");
        store_join_request(&ks, &r).await.unwrap();
        delete_join_request(&ks, r.id).await.unwrap();
        delete_join_request(&ks, r.id).await.unwrap();
        assert!(get_join_request(&ks, r.id).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn vp_size_limit_enforced() {
        let (ks, _dir) = temp_ks().await;
        let big = "a".repeat(JOIN_REQUEST_VP_MAX_BYTES + 1);
        let mut r = fresh("did:key:zBig");
        r.vp = serde_json::json!(big);
        let err = store_join_request(&ks, &r).await.expect_err("size hit");
        assert!(matches!(err, AppError::Validation(_)));
    }

    #[test]
    fn join_status_lowercase_wire() {
        let r = JoinRequest {
            status: JoinStatus::Pending,
            ..fresh("did:key:z")
        };
        let json = serde_json::to_value(&r).unwrap();
        assert_eq!(json["status"], "pending");
    }
}
