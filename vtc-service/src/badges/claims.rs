//! Claim codes for a community badge (`vtc/badges/claims/*`, VTI-BDG-025 – 027).
//!
//! A badge's owner issues a code — for handing out at an event — with a label, a time
//! after which it admits no one, and a number of claims it admits. The code is 256 bits
//! from the CSPRNG, answered to its issuer once; the community keeps only its SHA-256
//! digest (`bcdig:<hex>` → the record's id) beside the record (`bclaim:<claimId>`, indexed
//! by badge `bcbadge:<badgeId>:<claimId>`), and a marker per member who redeemed it
//! (`bcwho:<claimId>:<entryId>`), so nobody claims one code twice.
//!
//! A redemption **reserves** its claim — counts it, under [`super::WRITE_LOCK`] — before the
//! credential is issued, and [`release`]s it where the issue fails: two members racing for
//! a code's last claim admit one (`claims/redeem` item 5), and a crash between the two
//! steps can only under-admit, never over-admit.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;

/// The furthest ahead a code's time may be.
pub const MAX_DAYS: i64 = 90;

/// A claim code's record — never the code.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClaimRecord {
    pub claim_id: String,
    pub badge_id: String,
    pub label: String,
    pub valid_until: DateTime<Utc>,
    pub limit: u32,
    pub claims: u32,
    pub withdrawn: bool,
    pub created_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_by: Option<String>,
}

impl ClaimRecord {
    /// `ClaimCode` on the wire.
    pub fn wire(&self) -> Value {
        let mut out = json!({
            "claimId": self.claim_id,
            "badgeId": self.badge_id,
            "label": self.label,
            "validUntil": self.valid_until,
            "limit": self.limit,
            "claims": self.claims,
            "state": if self.withdrawn { "withdrawn" } else { "active" },
            "createdAt": self.created_at,
        });
        if let Some(by) = &self.created_by {
            out["createdBy"] = json!(by);
        }
        out
    }

    /// Whether the code admits anyone now.
    pub fn admits(&self, now: DateTime<Utc>) -> bool {
        !self.withdrawn && now < self.valid_until && self.claims < self.limit
    }
}

fn record_key(claim_id: &str) -> Vec<u8> {
    format!("bclaim:{claim_id}").into_bytes()
}
fn badge_index(badge_id: &str, claim_id: &str) -> Vec<u8> {
    format!("bcbadge:{badge_id}:{claim_id}").into_bytes()
}
fn digest_key(code: &str) -> Vec<u8> {
    format!("bcdig:{}", hex::encode(Sha256::digest(code.as_bytes()))).into_bytes()
}
fn redeemed_key(claim_id: &str, entry_id: &str) -> Vec<u8> {
    format!("bcwho:{claim_id}:{entry_id}").into_bytes()
}

fn random_b64(n: usize) -> String {
    let mut bytes = vec![0u8; n];
    rand::fill(bytes.as_mut_slice());
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Issue a code for `badge_id`: the record and the code, which is answered this once.
pub async fn create(
    ks: &KeyspaceHandle,
    badge_id: &str,
    label: &str,
    valid_until: DateTime<Utc>,
    limit: u32,
    created_by: Option<&str>,
) -> Result<(ClaimRecord, String), AppError> {
    let code = random_b64(32);
    let rec = ClaimRecord {
        claim_id: format!("bcl_{}", random_b64(16)),
        badge_id: badge_id.to_string(),
        label: label.to_string(),
        valid_until,
        limit,
        claims: 0,
        withdrawn: false,
        created_at: Utc::now(),
        created_by: created_by.map(str::to_string),
    };
    let _guard = super::WRITE_LOCK.lock().await;
    ks.insert(digest_key(&code), &rec.claim_id).await?;
    ks.insert(badge_index(badge_id, &rec.claim_id), &rec.claim_id)
        .await?;
    ks.insert(record_key(&rec.claim_id), &rec).await?;
    Ok((rec, code))
}

pub async fn get(ks: &KeyspaceHandle, claim_id: &str) -> Result<Option<ClaimRecord>, AppError> {
    ks.get(record_key(claim_id)).await
}

/// The record a code names, where it names one.
pub async fn by_code(ks: &KeyspaceHandle, code: &str) -> Result<Option<ClaimRecord>, AppError> {
    let Some(id) = ks.get::<String>(digest_key(code)).await? else {
        return Ok(None);
    };
    get(ks, &id).await
}

/// Every code of `badge_id`, newest first.
pub async fn of_badge(ks: &KeyspaceHandle, badge_id: &str) -> Result<Vec<ClaimRecord>, AppError> {
    let mut out = Vec::new();
    for (_, raw) in ks
        .prefix_iter_raw(format!("bcbadge:{badge_id}:").into_bytes())
        .await?
    {
        if let Ok(id) = serde_json::from_slice::<String>(&raw)
            && let Some(r) = get(ks, &id).await?
        {
            out.push(r);
        }
    }
    out.sort_by_key(|r| std::cmp::Reverse(r.created_at));
    Ok(out)
}

/// Withdraw a code: it admits no one from now on. Idempotent.
pub async fn withdraw(
    ks: &KeyspaceHandle,
    claim_id: &str,
) -> Result<Option<ClaimRecord>, AppError> {
    let _guard = super::WRITE_LOCK.lock().await;
    let Some(mut r) = get(ks, claim_id).await? else {
        return Ok(None);
    };
    if !r.withdrawn {
        r.withdrawn = true;
        ks.insert(record_key(claim_id), &r).await?;
    }
    Ok(Some(r))
}

/// Withdraw every code of `badge_id`: the badge is retired (VTI-BDG-027).
pub async fn withdraw_all_of_badge(ks: &KeyspaceHandle, badge_id: &str) -> Result<usize, AppError> {
    let mut n = 0;
    for r in of_badge(ks, badge_id).await? {
        if !r.withdrawn {
            withdraw(ks, &r.claim_id).await?;
            n += 1;
        }
    }
    Ok(n)
}

/// Why a redemption is refused before anything is issued.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// Unknown, past its time, out of claims or withdrawn — alike (item 2).
    CodeInvalid,
    /// This member already redeemed this code (item 3).
    AlreadyClaimed,
}

/// Reserve one claim of `code` for `entry_id`: counted and marked now, under the lock.
/// The caller issues the credential, then keeps the reservation or [`release`]s it.
pub async fn reserve(
    ks: &KeyspaceHandle,
    code: &str,
    entry_id: &str,
    now: DateTime<Utc>,
) -> Result<Result<ClaimRecord, Refusal>, AppError> {
    let _guard = super::WRITE_LOCK.lock().await;
    let Some(mut r) = by_code(ks, code).await? else {
        return Ok(Err(Refusal::CodeInvalid));
    };
    if ks
        .get::<bool>(redeemed_key(&r.claim_id, entry_id))
        .await?
        .is_some()
    {
        return Ok(Err(Refusal::AlreadyClaimed));
    }
    if !r.admits(now) {
        return Ok(Err(Refusal::CodeInvalid));
    }
    r.claims += 1;
    ks.insert(redeemed_key(&r.claim_id, entry_id), &true)
        .await?;
    ks.insert(record_key(&r.claim_id), &r).await?;
    Ok(Ok(r))
}

/// Give a reserved claim back: the issue failed, so nothing was claimed.
pub async fn release(ks: &KeyspaceHandle, claim_id: &str, entry_id: &str) -> Result<(), AppError> {
    let _guard = super::WRITE_LOCK.lock().await;
    ks.remove(redeemed_key(claim_id, entry_id)).await?;
    if let Some(mut r) = get(ks, claim_id).await? {
        r.claims = r.claims.saturating_sub(1);
        ks.insert(record_key(claim_id), &r).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_code_admits_until_its_time_its_limit_or_its_withdrawal() {
        let now = Utc::now();
        let mut r = ClaimRecord {
            claim_id: "bcl_x".into(),
            badge_id: "bdg_x".into(),
            label: "x".into(),
            valid_until: now + chrono::Duration::hours(1),
            limit: 2,
            claims: 1,
            withdrawn: false,
            created_at: now,
            created_by: None,
        };
        assert!(r.admits(now));
        r.claims = 2;
        assert!(!r.admits(now));
        r.claims = 0;
        assert!(!r.admits(now + chrono::Duration::hours(2)));
        r.withdrawn = true;
        assert!(!r.admits(now));
        assert_eq!(r.wire()["state"], "withdrawn");
        assert!(r.wire().get("code").is_none());
    }

    #[test]
    fn a_code_carries_256_random_bits_and_is_stored_by_digest() {
        let a = random_b64(32);
        assert_eq!(a.len(), 43);
        assert_ne!(a, random_b64(32));
        assert!(
            String::from_utf8(digest_key(&a))
                .unwrap()
                .starts_with("bcdig:")
        );
        assert!(!String::from_utf8(digest_key(&a)).unwrap().contains(&a));
    }
}
