//! A presign batch (`external/credentials/issue/0.2` and `0.3`, `PresignBatch`):
//! up to 128 operations (64 at 0.3) on one object and at most one multipart upload of it, each
//! presigned with exactly the method, query and headers the specification's
//! table names.
//!
//! The batch is read as the specification's own generated type. What its schema
//! cannot state — the batch rules of Conformance item 4, the ceiling of item 5 —
//! is checked here, in that order, and every value that will reach a canonical
//! request is validated again against a closed character class (item 8), as
//! [`crate::scope`] does for a scope.

use std::collections::BTreeSet;

pub use trust_tasks_rs::specs::external::credentials::issue::v0_2::{PresignBatch, PresignRequest};

use crate::model::{Binding, ScopeCeiling};
use crate::scope::{validate_object_key, validate_prefix};

/// The most operations one batch holds at `issue/0.2`.
pub const MAX_OPERATIONS: usize = 128;

/// The most operations one batch holds at `issue/0.3`, whose schema narrows the
/// batch to 64. A 0.3 batch is checked as the 0.2 type it is a subset of, with
/// this bound applied as well.
pub const MAX_OPERATIONS_0_3: usize = 64;

/// The `PresignOperation` name of `op`.
pub fn operation_name(op: &PresignRequest) -> &'static str {
    match op {
        PresignRequest::Put { .. } => "put",
        PresignRequest::Get => "get",
        PresignRequest::Head => "head",
        PresignRequest::Delete => "delete",
        PresignRequest::CreateMultipart => "create-multipart",
        PresignRequest::UploadPart { .. } => "upload-part",
        PresignRequest::ListParts { .. } => "list-parts",
        PresignRequest::CompleteMultipart { .. } => "complete-multipart",
        PresignRequest::AbortMultipart => "abort-multipart",
        // The generated enum is non-exhaustive; an operation this build does not
        // know is refused by `check_batch` before anything is signed.
        _ => "unknown",
    }
}

/// The ceiling action that authorizes `op` (`PresignOperation`): writing in
/// parts is writing, reading an object's length and checksum is less than
/// reading it, aborting an upload destroys bytes as deleting does.
pub fn ceiling_action(op: &PresignRequest) -> Option<&'static str> {
    match operation_name(op) {
        "put" | "create-multipart" | "upload-part" | "list-parts" | "complete-multipart" => {
            Some("put")
        }
        "get" | "head" => Some("get"),
        "delete" | "abort-multipart" => Some("delete"),
        _ => None,
    }
}

/// Whether `op` acts on an existing multipart upload, and so needs `uploadId`.
pub fn needs_upload_id(op: &PresignRequest) -> bool {
    matches!(
        operation_name(op),
        "upload-part" | "list-parts" | "complete-multipart" | "abort-multipart"
    )
}

/// Why a batch was refused, in the order the specification checks.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum BatchRefusal {
    /// `external/credentials/issue:invalidBatch` (item 4), or a value that is
    /// not what the schema allows.
    Invalid(String),
    /// `external/credentials/issue:scopeOutsideCeiling` (item 5).
    OutsideCeiling(String),
    /// `external/credentials/issue:ttlTooLong` (item 6).
    TtlTooLong { requested: u32, max: u32 },
}

impl std::fmt::Display for BatchRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(m) | Self::OutsideCeiling(m) => f.write_str(m),
            Self::TtlTooLong { requested, max } => write!(
                f,
                "ttlSeconds {requested} exceeds the binding's maxTtlSeconds {max}"
            ),
        }
    }
}

/// `ChecksumSha256`: standard, padded base64 of 32 bytes — 43 characters of the
/// alphabet and one `=`.
pub fn validate_checksum(c: &str) -> bool {
    c.len() == 44
        && c.ends_with('=')
        && c[..43]
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '+' || ch == '/')
}

/// `PresignBatch.uploadId`: `[A-Za-z0-9._~+/=-]`, 1 to 1024 bytes.
pub fn validate_upload_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 1024
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "._~+/=-".contains(c))
}

/// Check `batch` against `binding` (items 4, 5 and 6, in that order).
pub fn check_batch(
    binding: &Binding,
    batch: &PresignBatch,
    ttl_seconds: u32,
) -> Result<(), BatchRefusal> {
    let invalid = |why: String| Err(BatchRefusal::Invalid(why));
    let prefix = batch.prefix.as_str();
    let object = batch.object_key.as_str();
    validate_prefix(prefix).map_err(|e| BatchRefusal::Invalid(e.to_string()))?;
    validate_object_key(object).map_err(|e| BatchRefusal::Invalid(e.to_string()))?;
    if batch.requests.is_empty() || batch.requests.len() > MAX_OPERATIONS {
        return invalid(format!(
            "a batch holds 1 to {MAX_OPERATIONS} operations, not {}",
            batch.requests.len()
        ));
    }

    // Item 4: the batch rules.
    let upload_id = batch.upload_id.as_ref().map(|u| u.as_str());
    if let Some(id) = upload_id
        && !validate_upload_id(id)
    {
        return invalid("uploadId is not one storage could have returned".into());
    }
    let any_needs = batch.requests.iter().any(needs_upload_id);
    let creates = batch
        .requests
        .iter()
        .any(|op| matches!(op, PresignRequest::CreateMultipart));
    if any_needs && upload_id.is_none() {
        return invalid("a multipart operation needs the batch's uploadId".into());
    }
    if upload_id.is_some() && creates {
        return invalid("a batch that creates a multipart upload names no uploadId".into());
    }
    if upload_id.is_some() && !any_needs {
        return invalid("uploadId is given, but no operation in the batch uses it".into());
    }
    let mut seen = BTreeSet::new();
    let mut parts = BTreeSet::new();
    for op in &batch.requests {
        if ceiling_action(op).is_none() {
            return invalid(format!("unknown operation {}", operation_name(op)));
        }
        let canonical = serde_json::to_string(op).unwrap_or_default();
        if !seen.insert(canonical) {
            return invalid(format!(
                "the batch names the same {} operation twice",
                operation_name(op)
            ));
        }
        match op {
            PresignRequest::Put {
                checksum_sha256,
                content_length,
            } => {
                if !validate_checksum(checksum_sha256.as_str()) {
                    return invalid("a put's checksumSha256 is not a SHA-256".into());
                }
                if !(0..=5 * 1024 * 1024 * 1024).contains(content_length) {
                    return invalid("a put's contentLength is outside 0 to 5 GiB".into());
                }
            }
            PresignRequest::UploadPart {
                checksum_sha256,
                content_length,
                part_number,
            } => {
                if !validate_checksum(checksum_sha256.as_str()) {
                    return invalid("an upload-part's checksumSha256 is not a SHA-256".into());
                }
                if part_number.get() > 10_000 || content_length.get() > 5 * 1024 * 1024 * 1024 {
                    return invalid("an upload-part is outside S3's part bounds".into());
                }
                if !parts.insert(part_number.get()) {
                    return invalid(format!(
                        "two upload-part operations name part {part_number}"
                    ));
                }
            }
            PresignRequest::ListParts { part_number_marker }
                if part_number_marker.is_some_and(|m| !(0..=10_000).contains(&m)) =>
            {
                return invalid("partNumberMarker is outside 0 to 10000".into());
            }
            PresignRequest::CompleteMultipart { content_length }
                if !(0..=5 * 1024 * 1024 * 1024 * 1024).contains(content_length) =>
            {
                return invalid("complete-multipart's contentLength is outside 0 to 5 TiB".into());
            }
            _ => {}
        }
    }

    // Item 5: inside the ceiling.
    let empty = ScopeCeiling::default();
    let ceiling = binding.scope_ceiling.as_ref().unwrap_or(&empty);
    if !ceiling
        .prefixes
        .iter()
        .any(|p| prefix.starts_with(p.as_str()))
    {
        return Err(BatchRefusal::OutsideCeiling(format!(
            "prefix {prefix:?} is under none of the binding's prefixes"
        )));
    }
    for op in &batch.requests {
        let action = ceiling_action(op).expect("checked above");
        if !ceiling.actions.iter().any(|a| a == action) {
            return Err(BatchRefusal::OutsideCeiling(format!(
                "{} needs the ceiling action {action:?}, which the binding does not grant",
                operation_name(op)
            )));
        }
    }

    // Item 6.
    if ttl_seconds > binding.max_ttl_seconds {
        return Err(BatchRefusal::TtlTooLong {
            requested: ttl_seconds,
            max: binding.max_ttl_seconds,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn binding(actions: &[&str]) -> Binding {
        Binding {
            consumer: "did:key:z6Mkc".into(),
            scope_ceiling: Some(ScopeCeiling {
                prefixes: vec!["rooms/".into()],
                actions: actions.iter().map(|a| a.to_string()).collect(),
                scopes: vec![],
            }),
            max_ttl_seconds: 300,
            rate_per_minute: 10,
            source_cidrs: vec![],
            granted_at: None,
        }
    }

    fn batch(v: serde_json::Value) -> PresignBatch {
        serde_json::from_value(v).unwrap()
    }

    const SUM: &str = "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=";

    #[test]
    fn upload_id_is_present_exactly_when_an_operation_needs_it() {
        let b = binding(&["put", "get", "delete"]);
        let part = json!({"operation": "upload-part", "partNumber": 1, "contentLength": 5, "checksumSha256": SUM});
        let no_id = batch(json!({"prefix": "rooms/x/", "objectKey": "o", "requests": [part]}));
        assert!(matches!(
            check_batch(&b, &no_id, 300),
            Err(BatchRefusal::Invalid(_))
        ));
        let create_with_id = batch(
            json!({"prefix": "rooms/x/", "objectKey": "o", "uploadId": "u1",
            "requests": [{"operation": "create-multipart"}]}),
        );
        assert!(matches!(
            check_batch(&b, &create_with_id, 300),
            Err(BatchRefusal::Invalid(_))
        ));
        let unused_id = batch(
            json!({"prefix": "rooms/x/", "objectKey": "o", "uploadId": "u1",
            "requests": [{"operation": "head"}]}),
        );
        assert!(check_batch(&b, &unused_id, 300).is_err());
        let ok = batch(
            json!({"prefix": "rooms/x/", "objectKey": "o", "uploadId": "u1",
            "requests": [part, {"operation": "list-parts"}, {"operation": "abort-multipart"}]}),
        );
        check_batch(&b, &ok, 300).unwrap();
    }

    #[test]
    fn duplicates_and_repeated_parts_are_invalid() {
        let b = binding(&["put", "get", "delete"]);
        let twice = batch(json!({"prefix": "rooms/x/", "objectKey": "o",
            "requests": [{"operation": "head"}, {"operation": "head"}]}));
        assert!(matches!(
            check_batch(&b, &twice, 300),
            Err(BatchRefusal::Invalid(_))
        ));
        let same_part = batch(
            json!({"prefix": "rooms/x/", "objectKey": "o", "uploadId": "u",
            "requests": [
                {"operation": "upload-part", "partNumber": 2, "contentLength": 5, "checksumSha256": SUM},
                {"operation": "upload-part", "partNumber": 2, "contentLength": 6, "checksumSha256": SUM},
            ]}),
        );
        assert!(matches!(
            check_batch(&b, &same_part, 300),
            Err(BatchRefusal::Invalid(_))
        ));
    }

    /// Each operation is authorized by its ceiling action: `abort-multipart` needs
    /// `delete`, `head` needs `get`, multipart writes need `put`.
    #[test]
    fn each_operation_needs_its_ceiling_action() {
        let put_only = binding(&["put"]);
        let abort = batch(
            json!({"prefix": "rooms/x/", "objectKey": "o", "uploadId": "u",
            "requests": [{"operation": "abort-multipart"}]}),
        );
        assert!(matches!(
            check_batch(&put_only, &abort, 300),
            Err(BatchRefusal::OutsideCeiling(_))
        ));
        let head = batch(
            json!({"prefix": "rooms/x/", "objectKey": "o", "requests": [{"operation": "head"}]}),
        );
        assert!(matches!(
            check_batch(&put_only, &head, 300),
            Err(BatchRefusal::OutsideCeiling(_))
        ));
        let create = batch(
            json!({"prefix": "rooms/x/", "objectKey": "o", "requests": [{"operation": "create-multipart"}]}),
        );
        check_batch(&put_only, &create, 300).unwrap();
        let elsewhere = batch(
            json!({"prefix": "other/", "objectKey": "o", "requests": [{"operation": "create-multipart"}]}),
        );
        assert!(matches!(
            check_batch(&put_only, &elsewhere, 300),
            Err(BatchRefusal::OutsideCeiling(_))
        ));
        assert!(matches!(
            check_batch(&put_only, &create, 301),
            Err(BatchRefusal::TtlTooLong { .. })
        ));
    }
}
