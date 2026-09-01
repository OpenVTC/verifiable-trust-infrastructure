//! Issued-credential lifecycle (operations layer) — mint a VTA-signed W3C
//! Verifiable Credential to a holder DID and revoke it by id.
//!
//! Backs the `vta/credentials/{issue,revoke}/0.1` Trust Tasks
//! (`crate::trust_tasks::credentials`). The transport/auth ceremony (step-up
//! gate, capability check, audit) stays in the trust-task handler; this module
//! owns the privileged minting + the issued-credentials store.
//!
//! ## Issuer key
//!
//! The VTA issues as its own DID. The issuer signing key is `{vta_did}#key-0`
//! — the same VC-issuance key the provision-integration flow uses
//! (`operations::provision_integration::vta_keys::load_vta_vc_issuance_secret`).
//! It's loaded via [`crate::operations::keys::get_key_secret_internal`] under an
//! [`InternalAuthority`] (route handlers can't construct one, so the elevation
//! is reachable only from the operations layer), then the VC is signed with a
//! `eddsa-jcs-2022` Data-Integrity proof (`proofPurpose = "assertionMethod"`),
//! mirroring `vault::consent::sign_with` and
//! `provision_integration::credential::issue_vta_authorization_credential`.

use affinidi_data_integrity::{DataIntegrityProof, SignOptions, crypto_suites::CryptoSuite};
use affinidi_secrets_resolver::secrets::Secret;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::error::AppError;
use crate::operations::internal_authority::InternalAuthority;
use crate::server::AppState;
use crate::store::KeyspaceHandle;
use vta_sdk::did_key::decode_private_key_multibase;
use vta_sdk::protocols::credentials_issuance::{
    IssuedCredentialStatus, IssuedCredentialSummary, ListCredentialsBody, ListCredentialsResponse,
};

/// VC Data Model 2.0 base context — every issued VC carries this.
const VC_V2_CONTEXT: &str = "https://www.w3.org/ns/credentials/v2";

/// Storage-key prefix for issued-credential records.
///
/// Named rather than inlined because two things depend on it agreeing: the
/// writer below, and `list_issued`'s prefix scan. A literal in each is a pair
/// that can drift into a list that silently returns nothing.
pub(crate) const CRED_KEY_PREFIX: &str = "cred:";

/// Storage key for an issued-credential record (`cred:<id>`).
fn store_key(id: &str) -> String {
    format!("{CRED_KEY_PREFIX}{id}")
}

/// A persisted issued-credential record. The signed VC itself is stored
/// verbatim under `credential`; revocation sets `revoked_at` (+ optional
/// `reason`) in place rather than deleting (tombstone — the audit/verifier
/// trail must survive revocation).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssuedCredentialRecord {
    pub id: String,
    pub holder: String,
    /// The full signed W3C VC (with its Data-Integrity proof).
    pub credential: Value,
    pub issued_at: String,
    pub expires_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revocation_reason: Option<String>,
}

impl IssuedCredentialRecord {
    fn is_revoked(&self) -> bool {
        self.revoked_at.is_some()
    }
}

/// Parameters for [`issue_credential`].
pub struct IssueParams<'a> {
    pub holder: &'a str,
    /// The claims merged into `credentialSubject` (must be a non-empty object).
    pub claims: &'a Value,
    /// Optional extra type appended after `VerifiableCredential`.
    pub credential_type: Option<&'a str>,
    pub validity_seconds: u64,
}

/// Mint, sign, and store a scoped, time-boxed VC for `params.holder`.
///
/// Returns the stored record (its `id`, the signed `credential`, and
/// `expires_at`). The caller (the trust-task handler) is responsible for the
/// step-up gate, the capability check, and the audit record.
pub async fn issue_credential(
    state: &AppState,
    params: IssueParams<'_>,
) -> Result<IssuedCredentialRecord, AppError> {
    // Validate claims up front: a VC with no subject claims is almost certainly
    // an operator error, and `deny_unknown_fields` already rejected typos.
    let claims_obj = params
        .claims
        .as_object()
        .ok_or_else(|| AppError::Validation("claims must be a JSON object".to_string()))?;
    if claims_obj.is_empty() {
        return Err(AppError::Validation(
            "claims must be a non-empty object".to_string(),
        ));
    }
    if params.validity_seconds == 0 {
        return Err(AppError::Validation(
            "validitySeconds must be greater than zero".to_string(),
        ));
    }

    let vta_did =
        state.config.read().await.vta_did.clone().ok_or_else(|| {
            AppError::Internal("VTA DID not configured; cannot issue".to_string())
        })?;

    let issuer_secret = load_vta_issuer_secret(state, &vta_did, "credentials-issue").await?;

    let now = Utc::now();
    let expires = now + Duration::seconds(params.validity_seconds as i64);
    let id = format!("urn:uuid:{}", uuid::Uuid::new_v4());

    // Build the unsigned VC. `credentialSubject` = the caller's claims with
    // `id` set to the holder DID (an explicit `id` in claims is overridden — the
    // subject is whoever the credential is issued to).
    let mut subject = claims_obj.clone();
    subject.insert("id".to_string(), Value::String(params.holder.to_string()));

    let mut types = vec![Value::String("VerifiableCredential".to_string())];
    if let Some(ct) = params.credential_type {
        types.push(Value::String(ct.to_string()));
    }

    let mut vc = json!({
        "@context": [VC_V2_CONTEXT],
        "id": id,
        "type": types,
        "issuer": vta_did,
        "validFrom": rfc3339(now),
        "validUntil": rfc3339(expires),
        "credentialSubject": Value::Object(subject),
    });

    // Sign with the VTA issuer key (eddsa-jcs-2022, assertionMethod) — same
    // suite/purpose as `vault::consent` and the provision-integration issuer.
    let proof = DataIntegrityProof::sign(
        &vc,
        &issuer_secret,
        SignOptions::new()
            .with_proof_purpose("assertionMethod")
            .with_cryptosuite(CryptoSuite::EddsaJcs2022),
    )
    .await
    .map_err(|e| AppError::Internal(format!("sign issued credential: {e}")))?;
    vc.as_object_mut().expect("vc is an object").insert(
        "proof".to_string(),
        serde_json::to_value(&proof)
            .map_err(|e| AppError::Internal(format!("serialize issued-credential proof: {e}")))?,
    );

    let record = IssuedCredentialRecord {
        id: id.clone(),
        holder: params.holder.to_string(),
        credential: vc,
        issued_at: rfc3339(now),
        expires_at: rfc3339(expires),
        revoked_at: None,
        revocation_reason: None,
    };

    store_put(&state.issued_credentials_ks, &record).await?;
    Ok(record)
}

/// Revoke a previously-issued credential by id.
///
/// - `not_found` if no record exists for `id`.
/// - `already_revoked` (a [`AppError::Conflict`]) if it already carries a
///   `revoked_at`.
///
/// On success the record's `revoked_at` (+ optional `reason`) is set in place
/// and the revocation timestamp is returned.
pub async fn revoke_credential(
    state: &AppState,
    credential_id: &str,
    reason: Option<&str>,
) -> Result<String, AppError> {
    let mut record = store_get(&state.issued_credentials_ks, credential_id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("credential {credential_id} not found")))?;

    if record.is_revoked() {
        return Err(AppError::Conflict(format!(
            "credential {credential_id} is already revoked"
        )));
    }

    let revoked_at = rfc3339(Utc::now());
    record.revoked_at = Some(revoked_at.clone());
    record.revocation_reason = reason.map(str::to_string);
    store_put(&state.issued_credentials_ks, &record).await?;
    Ok(revoked_at)
}

/// Load the VTA's `{vta_did}#key-0` VC-issuance key as a signing `Secret`.
///
/// Mirrors `provision_integration::vta_keys::load_vta_vc_issuance_secret`: an
/// [`InternalAuthority`]-gated `get_key_secret_internal`, then reconstruct the
/// `Secret` from the multibase private key with `id = {vta_did}#key-0` so the
/// Data-Integrity proof's `verificationMethod` resolves under the VTA DID.
pub(crate) async fn load_vta_issuer_secret(
    state: &AppState,
    vta_did: &str,
    purpose: &'static str,
) -> Result<Secret, AppError> {
    let key_id = format!("{vta_did}#key-0");
    let authority = InternalAuthority::new(purpose);
    let resp = crate::operations::keys::get_key_secret_internal(
        &state.keys_ks,
        &state.imported_ks,
        &*state.seed_store,
        &state.audit_sink,
        authority,
        &key_id,
        purpose,
    )
    .await?;
    // Validate the multibase decodes to a 32-byte Ed25519 seed before
    // constructing the Secret (a malformed record would otherwise fail opaquely
    // at sign time).
    let _seed: [u8; 32] = decode_private_key_multibase(&resp.private_key_multibase)
        .map_err(|e| AppError::Internal(format!("decode VTA issuer key {key_id}: {e}")))?;
    let mut secret = Secret::from_multibase(&resp.private_key_multibase, None)
        .map_err(|e| AppError::Internal(format!("construct issuer Secret for {key_id}: {e}")))?;
    secret.id = key_id;
    Ok(secret)
}

async fn store_put(ks: &KeyspaceHandle, record: &IssuedCredentialRecord) -> Result<(), AppError> {
    ks.insert(store_key(&record.id), record).await
}

async fn store_get(
    ks: &KeyspaceHandle,
    id: &str,
) -> Result<Option<IssuedCredentialRecord>, AppError> {
    ks.get(store_key(id)).await
}

/// RFC 3339 with a `Z` suffix (UTC), matching the workspace's VC timestamps.
fn rfc3339(dt: DateTime<Utc>) -> String {
    dt.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

// ─── Listing what this agent has issued ──────────────────────────────────────
//
// `revoke` is keyed on a `credentialId` that `issue` returns exactly once, so
// before this an issuer that did not record it at that moment could not recover
// it from the agent at all. This reads records that already exist: the scan is
// over the same `cred:` prefix `store_put` writes under, and revocation is a
// tombstone rather than a delete, so a revoked credential is still there to
// list.

/// One row of a list answer — the record with its body removed.
///
/// The projection happens in one place so "a summary never carries the
/// credential" is enforced here rather than remembered at each call site. The
/// `credential` field of [`IssuedCredentialRecord`] is not read.
fn summarise(record: &IssuedCredentialRecord, now: DateTime<Utc>) -> IssuedCredentialSummary {
    IssuedCredentialSummary {
        credential_id: record.id.clone(),
        holder: record.holder.clone(),
        credential_type: credential_type_of(&record.credential),
        issued_at: record.issued_at.clone(),
        expires_at: record.expires_at.clone(),
        status: status_of(record, now),
        revoked_at: record.revoked_at.clone(),
        revocation_reason: record.revocation_reason.clone(),
    }
}

/// The credential's own type tag beyond `VerifiableCredential`.
///
/// Read out of the stored VC rather than kept alongside it: the VC is what was
/// signed, so a separately-stored copy could disagree with the document a
/// verifier sees. Absent when the credential carries only the base type.
fn credential_type_of(credential: &Value) -> Option<String> {
    credential
        .get("type")?
        .as_array()?
        .iter()
        .filter_map(Value::as_str)
        .find(|t| *t != "VerifiableCredential")
        .map(str::to_string)
}

/// Derive the state at read time.
///
/// **Revoked takes precedence over expired.** A credential revoked before its
/// window closed is revoked; reporting it as merely expired would hide that
/// somebody acted, which is the one thing a caller reading this list is most
/// likely to be asking about.
///
/// An `expires_at` that will not parse is treated as **not** expired rather
/// than as expired: guessing "expired" from an unreadable timestamp would
/// report a live credential as dead, and the failure should be visible as a
/// credential that never expires rather than one that silently did.
fn status_of(record: &IssuedCredentialRecord, now: DateTime<Utc>) -> IssuedCredentialStatus {
    if record.is_revoked() {
        return IssuedCredentialStatus::Revoked;
    }
    match DateTime::parse_from_rfc3339(&record.expires_at) {
        Ok(expires) if expires.with_timezone(&Utc) <= now => IssuedCredentialStatus::Expired,
        _ => IssuedCredentialStatus::Active,
    }
}

/// The agent's ceiling on a page, whatever the caller asked for.
const LIST_PAGE_MAX: usize = 200;
/// What a caller gets when it expresses no preference.
const LIST_PAGE_DEFAULT: usize = 50;

/// Enumerate issued credentials, filtered and paged.
///
/// Filters are AND-combined and every one is optional; an unfiltered request is
/// answered. Unlike `vault/credentials/query`, which refuses a filter that
/// constrains nothing, the caller here is the issuer reading a record of its
/// own past actions rather than a delegate reading a holder's private store.
///
/// Ordering is by storage key, which is `cred:<id>` — stable, so the cursor
/// below means the same thing across calls. It is deliberately not "newest
/// first": that would need a sort of the whole set before paging, and the
/// answer a caller wants ordered is one they can order themselves.
pub async fn list_issued(
    state: &AppState,
    filter: &ListCredentialsBody,
) -> Result<ListCredentialsResponse, AppError> {
    let now = Utc::now();
    let limit = filter
        .page_size
        .map_or(LIST_PAGE_DEFAULT, |n| (n as usize).min(LIST_PAGE_MAX))
        .max(1);

    let mut rows: Vec<(String, IssuedCredentialSummary)> = Vec::new();
    for (raw_key, bytes) in state
        .issued_credentials_ks
        .prefix_iter_raw(CRED_KEY_PREFIX.as_bytes().to_vec())
        .await?
    {
        let record: IssuedCredentialRecord = serde_json::from_slice(&bytes)
            .map_err(|e| AppError::Internal(format!("decode issued-credential record: {e}")))?;
        let summary = summarise(&record, now);

        if let Some(h) = &filter.holder
            && summary.holder != *h
        {
            continue;
        }
        if let Some(t) = &filter.credential_type
            && summary.credential_type.as_deref() != Some(t.as_str())
        {
            continue;
        }
        if let Some(s) = filter.status
            && summary.status != s
        {
            continue;
        }
        rows.push((String::from_utf8_lossy(&raw_key).into_owned(), summary));
    }

    Ok(page_rows(rows, filter.cursor.as_deref(), limit))
}

/// Order, resume and cut one page out of the matched rows.
///
/// Split out of [`list_issued`] because this is the part with the sharp edges,
/// and the rest of that function needs an `AppState` to exercise at all. Kept
/// pure so the cursor's exact semantics are pinned by unit tests rather than
/// inferred from an integration run.
///
/// **The cursor is the last storage key of the page before**, and resumption is
/// strictly *after* it rather than at an offset. That matters because issuance
/// is concurrent with paging: an offset shifts when a credential is issued
/// mid-walk, which silently skips a row the caller has not seen. A key does not
/// move.
fn page_rows(
    mut rows: Vec<(String, IssuedCredentialSummary)>,
    cursor: Option<&str>,
    limit: usize,
) -> ListCredentialsResponse {
    rows.sort_by(|a, b| a.0.cmp(&b.0));

    if let Some(cursor) = cursor {
        rows.retain(|(k, _)| k.as_str() > cursor);
    }

    let truncated = rows.len() > limit;
    rows.truncate(limit);
    // Emitted only when there is more, so a caller stops on its absence rather
    // than needing one empty page to learn it is done.
    let cursor = truncated
        .then(|| rows.last().map(|(k, _)| k.clone()))
        .flatten();

    ListCredentialsResponse {
        credentials: rows.into_iter().map(|(_, s)| s).collect(),
        truncated,
        cursor,
        ext: None,
    }
}

#[cfg(test)]
mod list_tests {
    use super::*;

    fn record(id: &str, expires: &str, revoked: Option<&str>) -> IssuedCredentialRecord {
        IssuedCredentialRecord {
            id: id.into(),
            holder: "did:key:zHolder".into(),
            credential: serde_json::json!({
                "type": ["VerifiableCredential", "MembershipCredential"],
            }),
            issued_at: "2026-01-01T00:00:00Z".into(),
            expires_at: expires.into(),
            revoked_at: revoked.map(str::to_string),
            revocation_reason: revoked.map(|_| "role ended".to_string()),
        }
    }

    fn now() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-06-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc)
    }

    #[test]
    fn revoked_takes_precedence_over_expired() {
        // Both true at once. Reporting `expired` would hide that somebody
        // acted, which is the thing a caller reading this list most wants.
        let r = record("a", "2026-02-01T00:00:00Z", Some("2026-01-15T00:00:00Z"));
        assert_eq!(status_of(&r, now()), IssuedCredentialStatus::Revoked);
    }

    #[test]
    fn expiry_is_measured_against_the_clock() {
        assert_eq!(
            status_of(&record("a", "2026-02-01T00:00:00Z", None), now()),
            IssuedCredentialStatus::Expired
        );
        assert_eq!(
            status_of(&record("a", "2027-01-01T00:00:00Z", None), now()),
            IssuedCredentialStatus::Active
        );
    }

    #[test]
    fn an_unreadable_expiry_reads_as_active_not_expired() {
        // Guessing `expired` from a timestamp we could not parse would report a
        // live credential as dead, and a caller would go and reissue something
        // that was working.
        let r = record("a", "not-a-timestamp", None);
        assert_eq!(status_of(&r, now()), IssuedCredentialStatus::Active);
    }

    #[test]
    fn the_type_tag_skips_the_base_type() {
        let r = record("a", "2027-01-01T00:00:00Z", None);
        assert_eq!(
            credential_type_of(&r.credential).as_deref(),
            Some("MembershipCredential")
        );
    }

    #[test]
    fn a_credential_with_only_the_base_type_has_none() {
        let mut r = record("a", "2027-01-01T00:00:00Z", None);
        r.credential = serde_json::json!({ "type": ["VerifiableCredential"] });
        assert_eq!(credential_type_of(&r.credential), None);
    }

    #[test]
    fn a_summary_never_carries_the_credential() {
        // The invariant this whole task rests on. Serialising the summary is
        // the check that matters: a field added to the projection later would
        // show up here, not in a review.
        let r = record("a", "2027-01-01T00:00:00Z", None);
        let wire = serde_json::to_value(summarise(&r, now())).unwrap();
        assert!(wire.get("credential").is_none());
        assert!(!wire.to_string().contains("VerifiableCredential"));
    }

    fn rows(ids: &[&str]) -> Vec<(String, IssuedCredentialSummary)> {
        ids.iter()
            .map(|id| {
                (
                    format!("cred:{id}"),
                    summarise(&record(id, "2027-01-01T00:00:00Z", None), now()),
                )
            })
            .collect()
    }

    #[test]
    fn a_short_page_is_not_truncated_and_offers_no_cursor() {
        let page = page_rows(rows(&["a", "b"]), None, 10);
        assert_eq!(page.credentials.len(), 2);
        assert!(!page.truncated);
        // A caller must be able to stop on the cursor's absence rather than
        // needing to fetch an empty page to find out.
        assert_eq!(page.cursor, None);
    }

    #[test]
    fn a_full_page_reports_truncation_and_the_key_to_resume_after() {
        let page = page_rows(rows(&["a", "b", "c"]), None, 2);
        assert_eq!(page.credentials.len(), 2);
        assert!(page.truncated);
        assert_eq!(page.cursor.as_deref(), Some("cred:b"));
    }

    #[test]
    fn a_cursor_resumes_strictly_after_it() {
        let page = page_rows(rows(&["a", "b", "c"]), Some("cred:b"), 10);
        let ids: Vec<_> = page
            .credentials
            .iter()
            .map(|c| c.credential_id.as_str())
            .collect();
        assert_eq!(ids, ["c"], "the cursor row itself must not repeat");
    }

    #[test]
    fn a_row_issued_mid_walk_does_not_displace_an_unseen_one() {
        // The reason the cursor is a key rather than an offset. Page one is
        // a,b; `a0` then appears before both. With an offset of 2 the next page
        // would start at `c` and `b` would never be seen.
        let page_one = page_rows(rows(&["a", "b", "c"]), None, 2);
        assert_eq!(page_one.cursor.as_deref(), Some("cred:b"));

        let page_two = page_rows(rows(&["a0", "a", "b", "c"]), page_one.cursor.as_deref(), 2);
        let ids: Vec<_> = page_two
            .credentials
            .iter()
            .map(|c| c.credential_id.as_str())
            .collect();
        assert_eq!(ids, ["c"]);
    }

    #[test]
    fn ordering_is_stable_regardless_of_scan_order() {
        let forward = page_rows(rows(&["a", "b", "c"]), None, 10);
        let reversed = page_rows(rows(&["c", "b", "a"]), None, 10);
        let ids = |p: &ListCredentialsResponse| {
            p.credentials
                .iter()
                .map(|c| c.credential_id.clone())
                .collect::<Vec<_>>()
        };
        assert_eq!(ids(&forward), ids(&reversed));
    }
}
