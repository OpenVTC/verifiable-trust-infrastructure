//! `BitstringStatusListCredential` builder.
//!
//! Wraps a [`super::storage::StatusListState`] in the W3C VC
//! shape and signs it with the workspace's M2.9 [`LocalSigner`].
//! The published VC is what verifiers fetch from `GET
//! /v1/status-lists/{purpose}` (the route lands in M2.11; this
//! milestone just lands the builder).
//!
//! Wire shape (per W3C bitstring status list v1.0):
//!
//! ```json
//! {
//!   "@context": [
//!     "https://www.w3.org/ns/credentials/v2"
//!   ],
//!   "id": "<list_credential_id>",
//!   "type": ["VerifiableCredential", "BitstringStatusListCredential"],
//!   "issuer": "<vtc_did>",
//!   "validFrom": "<rfc3339>",
//!   "credentialSubject": {
//!     "id": "<list_credential_id>#list",
//!     "type": "BitstringStatusList",
//!     "statusPurpose": "revocation" | "suspension",
//!     "encodedList": "<gzip + base64url>"
//!   },
//!   "proof": { … }
//! }
//! ```

use affinidi_status_list::BitstringStatusList;
use affinidi_vc::{CredentialBuilder, VerifiableCredential};
use chrono::Utc;
use serde_json::{Map, Value as JsonValue};
use vti_common::error::AppError;

use crate::credentials::LocalSigner;

use super::storage::StatusListState;

/// Type the VC's `type` array carries alongside
/// `VerifiableCredential`. Stable W3C name.
pub const BITSTRING_STATUS_LIST_VC_TYPE: &str = "BitstringStatusListCredential";

/// Build + sign a `BitstringStatusListCredential` for the given
/// state. `issuer = signer.issuer_did()`; the VC's `id` is the
/// state's `list_credential_id` (the canonical public URL).
///
/// The encoded bitstring uses the same GZIP+base64url format
/// `affinidi-status-list::BitstringStatusList::encode` produces;
/// we reuse that crate to avoid a second compressor in the
/// workspace.
pub async fn build_status_list_credential(
    signer: &LocalSigner,
    state: &StatusListState,
) -> Result<VerifiableCredential, AppError> {
    // Materialise into the upstream BitstringStatusList shape
    // long enough to call `encode`. The state we persist owns
    // the truth (`assigned` mask, etc.); the upstream type's
    // internal `assigned` is unused after the encode call.
    let encoded = encode_bits(state).map_err(|e| {
        AppError::Internal(format!("status list encode for {}: {e}", state.purpose))
    })?;

    let mut subject = Map::new();
    subject.insert(
        "id".into(),
        JsonValue::String(format!("{}#list", state.list_credential_id)),
    );
    subject.insert(
        "type".into(),
        JsonValue::String("BitstringStatusList".into()),
    );
    subject.insert(
        "statusPurpose".into(),
        JsonValue::String(state.purpose.to_string()),
    );
    subject.insert("encodedList".into(), JsonValue::String(encoded));

    let now = Utc::now();
    let mut vc = CredentialBuilder::v2()
        .issuer_uri(signer.issuer_did().to_string())
        .add_type(BITSTRING_STATUS_LIST_VC_TYPE)
        .valid_from(rfc3339(now))
        .subject(subject)
        .build()
        .map_err(|e| AppError::Internal(format!("status-list VC build: {e}")))?;

    // The `id` field on the typed VC isn't builder-settable;
    // splice it via JSON like the VMC's credentialStatus.
    attach_top_level_id(&mut vc, &state.list_credential_id)?;

    signer.sign(&mut vc).await?;
    Ok(vc)
}

/// Encode the raw bits via `affinidi-status-list`'s GZIP+base64url
/// path. We construct a fresh `BitstringStatusList` and copy our
/// bits into it via `set` calls so the encode output matches
/// what verifiers expect from the upstream crate.
fn encode_bits(state: &StatusListState) -> Result<String, affinidi_status_list::StatusListError> {
    let mut bsl = BitstringStatusList::new(state.capacity, state.purpose.clone());
    // Apply each `1` bit in the source. Iterating once over the
    // raw bytes is cheap; this is the steady-state path for the
    // M2.11 publish handler and the M2.14 flip-on-removal path.
    for i in 0..state.capacity {
        if state.is_set(i) {
            bsl.set(i, true)?;
        }
    }
    bsl.encode()
}

fn rfc3339(t: chrono::DateTime<Utc>) -> String {
    t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

fn attach_top_level_id(vc: &mut VerifiableCredential, id: &str) -> Result<(), AppError> {
    let mut as_value = serde_json::to_value(&*vc)
        .map_err(|e| AppError::Internal(format!("status-list VC -> value: {e}")))?;
    as_value
        .as_object_mut()
        .ok_or_else(|| AppError::Internal("status-list VC not an object".into()))?
        .insert("id".into(), JsonValue::String(id.into()));
    *vc = serde_json::from_value(as_value)
        .map_err(|e| AppError::Internal(format!("value -> status-list VC: {e}")))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credentials::LocalSigner;
    use crate::status_list::allocator::{allocate, flip};
    use affinidi_status_list::StatusPurpose;
    use affinidi_vc::SubjectValue;

    const TEST_VTC_DID: &str = "did:webvh:vtc.example.com:abc";

    fn signer() -> LocalSigner {
        LocalSigner::from_ed25519_seed(TEST_VTC_DID.into(), &[0xCC; 32])
    }

    fn smallish_state() -> StatusListState {
        let mut s = StatusListState::new(
            StatusPurpose::Revocation,
            "https://vtc.example.com/v1/status-lists/revocation".into(),
        );
        // Shrink for fast tests.
        s.capacity = 128;
        s.bits = vec![0u8; 128 / 8];
        s.assigned = vec![false; 128];
        s
    }

    #[tokio::test]
    async fn round_trip_status_list_vc_verifies() {
        let signer = signer();
        let mut state = smallish_state();
        // Flip a couple of real slots.
        let a = allocate(&mut state).unwrap();
        let b = allocate(&mut state).unwrap();
        flip(&mut state, a, true).unwrap();
        flip(&mut state, b, true).unwrap();

        let vc = build_status_list_credential(&signer, &state)
            .await
            .expect("build status-list VC");

        // Type array carries BitstringStatusListCredential.
        assert!(
            vc.types.iter().any(|t| t == BITSTRING_STATUS_LIST_VC_TYPE),
            "expected {BITSTRING_STATUS_LIST_VC_TYPE} in types: {:?}",
            vc.types
        );

        // Subject shape: id, type, statusPurpose, encodedList.
        let subject = match &vc.credential_subject {
            SubjectValue::Single(m) => m.clone(),
            SubjectValue::Multiple(v) => v[0].clone(),
        };
        assert_eq!(
            subject.get("type"),
            Some(&JsonValue::String("BitstringStatusList".into()))
        );
        assert_eq!(
            subject.get("statusPurpose"),
            Some(&JsonValue::String("revocation".into()))
        );
        let encoded = subject
            .get("encodedList")
            .and_then(|v| v.as_str())
            .expect("encodedList must be a string");
        assert!(!encoded.is_empty());

        // Top-level `id` carries the canonical URL.
        let as_value = serde_json::to_value(&vc).unwrap();
        assert_eq!(as_value["id"], state.list_credential_id);

        // Proof verifies.
        signer.verify(&vc).expect("status-list VC must verify");
    }

    /// Decoding the encoded bitstring yields the same bits we
    /// fed in. Confirms the wire round-trip works end-to-end.
    #[tokio::test]
    async fn encoded_list_round_trips_through_decode() {
        let signer = signer();
        let mut state = smallish_state();
        let a = allocate(&mut state).unwrap();
        flip(&mut state, a, true).unwrap();
        let b = allocate(&mut state).unwrap();
        flip(&mut state, b, true).unwrap();

        let vc = build_status_list_credential(&signer, &state).await.unwrap();
        let subject = match &vc.credential_subject {
            SubjectValue::Single(m) => m.clone(),
            SubjectValue::Multiple(v) => v[0].clone(),
        };
        let encoded = subject["encodedList"].as_str().unwrap();
        let decoded =
            BitstringStatusList::decode(encoded, state.capacity, state.purpose.clone()).unwrap();
        assert!(
            decoded.get(a as usize).unwrap(),
            "slot {a} should round-trip as set"
        );
        assert!(decoded.get(b as usize).unwrap());
        // A slot we never touched is `0`.
        let untouched = state.capacity - 1;
        if !state.assigned[untouched] && !state.is_set(untouched) {
            assert!(!decoded.get(untouched).unwrap());
        }
    }
}
