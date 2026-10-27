//! The sealed cleartext of a community's storage credential
//! (`vtc/_shared/0.2/room-storage`, `SealedStorageCredential`).
//!
//! Its shape is the specification's, and the generated type
//! (`trust_tasks_rs::specs::vtc::storage::credentials::set::v0_2::SealedStorageCredential`)
//! is what a producer builds and a community checks it against. It travels as the
//! JSON value it was sealed as, not as that type: the community must read the
//! cleartext as received and never normalise it into validity, which a round trip
//! through a typed form would do silently.

use serde::{Deserialize, Serialize};

/// A `SealedStorageCredential`, as the JSON it was sealed as: what
/// [`SealedPayloadV1::StorageCredential`](super::SealedPayloadV1::StorageCredential)
/// carries.
#[derive(Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct StorageCredentialPayload(pub serde_json::Value);

/// Written by hand so the credential never reaches a log: only its `kind` and
/// `configId` are shown.
impl std::fmt::Debug for StorageCredentialPayload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StorageCredentialPayload")
            .field("kind", &self.0.get("kind"))
            .field("configId", &self.0.get("configId"))
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_never_shows_the_secret() {
        let p = StorageCredentialPayload(serde_json::json!({
            "kind": "s3", "configId": "r2", "accessKeyId": "AKID", "secretAccessKey": "hunter2"
        }));
        let d = format!("{p:?}");
        assert!(!d.contains("hunter2") && !d.contains("AKID"), "{d}");
        assert!(d.contains("r2"));
    }
}
