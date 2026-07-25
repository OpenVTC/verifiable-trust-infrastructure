//! DynamoDB-backed external anti-rollback counter (P0.2b).
//!
//! Implements [`vti_common::integrity::AnchorCounter`] over a single-item
//! DynamoDB table — one item per VTA DID holding a monotonic `version`. The
//! atomic compare-and-set is a conditional `UpdateItem`
//! (`ConditionExpression: version = :expected`), which is the §5.4
//! linearization point: a concurrent replica or a torn write fails the
//! condition rather than silently clobbering the counter.
//!
//! The parent EC2 host proxies the (TLS-protected) bytes but can neither read
//! nor forge the responses. **P0.2b scope:** the counter is written with the
//! enclave's *instance-role* credentials, which a root-on-parent attacker
//! shares — so this resists storage/backup rollback but not a compromised
//! parent OS. The KMS-attestation-gated writer that closes that gap is P0.2c.

use std::future::Future;
use std::pin::Pin;

use aws_sdk_dynamodb::Client;
use aws_sdk_dynamodb::config::Credentials;
use aws_sdk_dynamodb::types::AttributeValue;
use serde::Deserialize;
use zeroize::ZeroizeOnDrop;

use vti_common::error::AppError;
use vti_common::integrity::AnchorCounter;

const PARTITION_KEY: &str = "vta_did";
const VERSION_ATTR: &str = "version";
const DIGEST_ATTR: &str = "digest";
const UPDATED_AT_ATTR: &str = "updated_at";

type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// The `vta-anchor-writer` IAM credentials, unsealed at boot from the
/// attestation-gated KMS ciphertext (P0.2c). Zeroized on drop; once the client
/// is built the AWS SDK holds its own copy.
#[derive(Deserialize, ZeroizeOnDrop)]
pub struct WriterCredentials {
    pub access_key_id: String,
    pub secret_access_key: String,
}

/// External anchor counter backed by a single DynamoDB item keyed by VTA DID.
pub struct DynamoAnchorCounter {
    client: Client,
    table: String,
    vta_did: String,
}

impl DynamoAnchorCounter {
    /// Build a client for `region` bound to `table` + `vta_did` (the partition
    /// key).
    ///
    /// With `writer` (P0.2c) the client uses the attestation-gated
    /// `vta-anchor-writer` static credentials — the only principal allowed to
    /// write the counter (the instance role is IAM-denied), so a root-on-parent
    /// attacker can't move it. Without `writer` (P0.2b) it uses the default
    /// credential chain (the instance role via the parent's IMDS proxy), which
    /// resists storage rollback but not root-on-parent.
    pub async fn new(
        region: &str,
        table: String,
        vta_did: String,
        writer: Option<WriterCredentials>,
    ) -> Self {
        let mut builder = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(aws_config::Region::new(region.to_string()));
        if let Some(w) = writer {
            builder = builder.credentials_provider(Credentials::new(
                w.access_key_id.clone(),
                w.secret_access_key.clone(),
                None,
                None,
                "vta-anchor-writer",
            ));
        }
        let sdk_config = builder.load().await;
        Self {
            client: Client::new(&sdk_config),
            table,
            vta_did,
        }
    }

    fn pk(&self) -> AttributeValue {
        AttributeValue::S(self.vta_did.clone())
    }
}

/// Parse a DynamoDB numeric attribute into a `u64`.
fn parse_version(av: &AttributeValue) -> Result<u64, AppError> {
    match av {
        AttributeValue::N(n) => n
            .parse::<u64>()
            .map_err(|e| AppError::Internal(format!("anchor: non-numeric version '{n}': {e}"))),
        _ => Err(AppError::Internal(
            "anchor: version attribute is not a number".into(),
        )),
    }
}

impl AnchorCounter for DynamoAnchorCounter {
    fn read(&self) -> BoxFuture<'_, Result<Option<u64>, AppError>> {
        Box::pin(async move {
            let resp = self
                .client
                .get_item()
                .table_name(&self.table)
                .key(PARTITION_KEY, self.pk())
                .consistent_read(true) // must observe the latest committed bump
                .send()
                .await
                .map_err(|e| {
                    AppError::Internal(format!(
                        "anchor get_item failed: {}",
                        e.into_service_error()
                    ))
                })?;
            match resp.item().and_then(|i| i.get(VERSION_ATTR)) {
                Some(av) => Ok(Some(parse_version(av)?)),
                None => Ok(None),
            }
        })
    }

    fn init(&self, version: u64, digest: [u8; 32]) -> BoxFuture<'_, Result<(), AppError>> {
        Box::pin(async move {
            self.client
                .put_item()
                .table_name(&self.table)
                .item(PARTITION_KEY, self.pk())
                .item(VERSION_ATTR, AttributeValue::N(version.to_string()))
                .item(DIGEST_ATTR, AttributeValue::S(hex::encode(digest)))
                .item(UPDATED_AT_ATTR, AttributeValue::S(now_rfc3339()))
                // Create-if-absent: never overwrite an existing counter.
                .condition_expression(format!("attribute_not_exists({PARTITION_KEY})"))
                .send()
                .await
                .map_err(|e| {
                    let svc = e.into_service_error();
                    if svc.is_conditional_check_failed_exception() {
                        AppError::Conflict("anchor counter already initialized".into())
                    } else {
                        AppError::Internal(format!("anchor put_item failed: {svc}"))
                    }
                })?;
            Ok(())
        })
    }

    fn set(
        &self,
        expected: u64,
        new: u64,
        digest: [u8; 32],
    ) -> BoxFuture<'_, Result<(), AppError>> {
        Box::pin(async move {
            self.client
                .update_item()
                .table_name(&self.table)
                .key(PARTITION_KEY, self.pk())
                .update_expression(format!(
                    "SET {VERSION_ATTR} = :new, {DIGEST_ATTR} = :d, {UPDATED_AT_ATTR} = :t"
                ))
                // The compare-and-set: only bump if the stored version is what
                // the caller observed (§5.4 linearization point).
                .condition_expression(format!("{VERSION_ATTR} = :expected"))
                .expression_attribute_values(":new", AttributeValue::N(new.to_string()))
                .expression_attribute_values(":expected", AttributeValue::N(expected.to_string()))
                .expression_attribute_values(":d", AttributeValue::S(hex::encode(digest)))
                .expression_attribute_values(":t", AttributeValue::S(now_rfc3339()))
                .send()
                .await
                .map_err(|e| {
                    let svc = e.into_service_error();
                    if svc.is_conditional_check_failed_exception() {
                        AppError::Conflict(format!(
                            "anchor CAS failed: counter is not at expected v{expected} \
                             (concurrent writer or rollback)"
                        ))
                    } else {
                        AppError::Internal(format!("anchor update_item failed: {svc}"))
                    }
                })?;
            Ok(())
        })
    }
}

/// RFC-3339 UTC timestamp for the `updated_at` bookkeeping attribute.
fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The sealed writer credential is the JSON the operator encrypts under the
    /// PCR-gated KMS key; it must deserialize to the two AWS fields (P0.2c).
    #[test]
    fn writer_credentials_parse_from_sealed_json() {
        let json = br#"{"access_key_id":"AKIAEXAMPLE","secret_access_key":"s3cr3t"}"#;
        let w: WriterCredentials = serde_json::from_slice(json).expect("parse writer creds");
        assert_eq!(w.access_key_id, "AKIAEXAMPLE");
        assert_eq!(w.secret_access_key, "s3cr3t");
    }

    /// Extra fields (e.g. a future `session_token`) are tolerated; a missing
    /// required field is a hard parse error surfaced as a config problem.
    #[test]
    fn writer_credentials_tolerate_extra_but_require_both() {
        let extra = br#"{"access_key_id":"A","secret_access_key":"B","note":"x"}"#;
        assert!(serde_json::from_slice::<WriterCredentials>(extra).is_ok());
        let missing = br#"{"access_key_id":"A"}"#;
        assert!(serde_json::from_slice::<WriterCredentials>(missing).is_err());
    }
}
