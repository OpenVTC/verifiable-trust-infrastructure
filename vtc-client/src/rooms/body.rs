//! The sealed record body: what a member writes inside a sealed record, signed by them.
//!
//! `SealedRecordBody` in `rooms/_shared/0.1/room.schema.json`. It is the plaintext inside
//! `SealedRecord.ciphertext` on an `attributed` or `private` room, as JSON, and it is
//! client to client: no host task carries it, because a host receives only ciphertext. So
//! there is no generated type for it, and this is the one definition every member's client
//! in this workspace reads and writes.
//!
//! # Why the author signs, and why the signature names the location
//!
//! The AEAD binds a record to `roomId`, `key`, `version` and epoch, which stops the **host**
//! moving it. It does nothing about a **member**: every member can open a record and seal it
//! again. So the author signs the body, which is what attributes it (and on a `private`
//! room is the only attribution there is), and the signature covers the same location. A
//! member who copied someone else's signed body to another key or a later version produces
//! a body whose signed location is not where it was read, and a reader refuses it.
//!
//! # Signing and verifying
//!
//! [`SealedRecordBody::sign`] produces the bytes to seal. [`verify_record_body`] is the only
//! way to a [`VerifiedRecordBody`], so code that shows a record or trusts its `file` cannot
//! forget a check: it does not have the type otherwise.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use vta_sdk::trust_task_proof::{ProofPurpose, PurposeVmResolver, verify_proof_set};
use vta_sdk::trust_task_sign::{HolderKey, sign_object_for_assertion};

pub use vti_rooms::files::FileManifest;

/// The suites a body may be signed with: `eddsa-jcs-2022`, which every writer supports,
/// and `ecdsa-jcs-2019`, for a hardware-backed signer.
const ACCEPTED_SUITES: [&str; 2] = ["eddsa-jcs-2022", "ecdsa-jcs-2019"];

// The schema's bounds, the same as the open tier's `cleartext`.
const MAX_KEY: usize = 512;
const MAX_TITLE: usize = 512;
const MAX_DESCRIPTION: usize = 2048;
const MAX_BODY: usize = 1_048_576;
const MAX_TAGS: usize = 32;
const MAX_TAG: usize = 64;

/// Why a body could not be signed, or was refused on reading.
#[derive(Debug, thiserror::Error)]
pub enum BodyError {
    /// The body breaks the schema: an unknown member, a bound exceeded, a missing one.
    #[error("the record body is malformed: {0}")]
    Malformed(String),
    /// The proof is missing, does not verify, or verifies for someone other than `author`.
    #[error("the record body's signature does not hold: {0}")]
    Signature(String),
    /// The body was signed for another room, key or version than the one it was read from.
    #[error("the record body was signed for {signed}, but was read from {read}")]
    Relocated { signed: String, read: String },
    /// On an `attributed` room, the signer is not the author the host recorded.
    #[error(
        "the record body is signed by {signed}, but the host recorded {recorded} as its author"
    )]
    AuthorMismatch { signed: String, recorded: String },
    /// Signing failed: the key could not be used, or it is not `author`'s.
    #[error("could not sign the record body: {0}")]
    Signing(String),
}

/// Where a record was written or read: what the body's signature has to name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordLocation<'a> {
    pub room_id: &'a str,
    pub key: &'a str,
    pub version: u64,
}

impl std::fmt::Display for RecordLocation<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} / {} @ v{}", self.room_id, self.key, self.version)
    }
}

/// A record body, before signing or after verification. Never the signed form: that is
/// the bytes [`SealedRecordBody::sign`] returns.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SealedRecordBody {
    pub room_id: String,
    pub key: String,
    pub version: u64,
    /// The DID that signs: the member, or the agent acting under an attenuated credential.
    pub author: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Markdown. Untrusted text from another member: render it inert.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    /// Present when the record carries a file. Its `blobRef` must be the one the record
    /// names in `blobs`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file: Option<FileManifest>,
}

impl SealedRecordBody {
    /// A body for `author` at `at`, with nothing in it yet.
    pub fn new(at: RecordLocation<'_>, author: impl Into<String>) -> Self {
        Self {
            room_id: at.room_id.to_string(),
            key: at.key.to_string(),
            version: at.version,
            author: author.into(),
            title: None,
            description: None,
            body: None,
            tags: Vec::new(),
            file: None,
        }
    }

    /// The location the body names.
    pub fn location(&self) -> RecordLocation<'_> {
        RecordLocation {
            room_id: &self.room_id,
            key: &self.key,
            version: self.version,
        }
    }

    /// The same body for another version: what a writer re-signs when the host assigned a
    /// version other than the one it predicted.
    #[must_use]
    pub fn at_version(mut self, version: u64) -> Self {
        self.version = version;
        self
    }

    /// The schema's rules, checked on both sides.
    fn check(&self) -> Result<(), BodyError> {
        let bad = |m: String| Err(BodyError::Malformed(m));
        if self.room_id.is_empty() {
            return bad("roomId is empty".into());
        }
        if self.key.is_empty() || self.key.len() > MAX_KEY {
            return bad(format!("key must be 1 to {MAX_KEY} characters"));
        }
        if self.version == 0 {
            return bad("version starts at 1".into());
        }
        if !self.author.starts_with("did:") {
            return bad("author is not a DID".into());
        }
        let too_long =
            |v: &Option<String>, max: usize| v.as_ref().is_some_and(|s| s.chars().count() > max);
        if too_long(&self.title, MAX_TITLE) {
            return bad(format!("title is longer than {MAX_TITLE} characters"));
        }
        if too_long(&self.description, MAX_DESCRIPTION) {
            return bad(format!(
                "description is longer than {MAX_DESCRIPTION} characters"
            ));
        }
        if too_long(&self.body, MAX_BODY) {
            return bad(format!("body is longer than {MAX_BODY} characters"));
        }
        if self.tags.len() > MAX_TAGS || self.tags.iter().any(|t| t.chars().count() > MAX_TAG) {
            return bad(format!(
                "at most {MAX_TAGS} tags of {MAX_TAG} characters each"
            ));
        }
        Ok(())
    }

    /// Sign the body with `key` and return the bytes to seal.
    ///
    /// `key` must be `author`'s: a body signed by anyone else would be refused by every
    /// reader, so it is refused here, where the mistake is still the writer's to fix.
    pub async fn sign(&self, key: &HolderKey) -> Result<Vec<u8>, BodyError> {
        self.check()?;
        if key.holder_did() != self.author {
            return Err(BodyError::Signing(format!(
                "the key belongs to {}, not to the author {}",
                key.holder_did(),
                self.author
            )));
        }
        let mut value =
            serde_json::to_value(self).map_err(|e| BodyError::Signing(e.to_string()))?;
        sign_object_for_assertion(&mut value, key)
            .await
            .map_err(|e| BodyError::Signing(e.to_string()))?;
        serde_json::to_vec(&value).map_err(|e| BodyError::Signing(e.to_string()))
    }
}

/// A body whose signature, location and author have all been checked.
///
/// Only [`verify_record_body`] makes one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedRecordBody {
    inner: SealedRecordBody,
}

impl VerifiedRecordBody {
    /// The verified body.
    pub fn body(&self) -> &SealedRecordBody {
        &self.inner
    }

    /// The verified body, owned.
    pub fn into_inner(self) -> SealedRecordBody {
        self.inner
    }
}

/// Check an opened record's body before anything in it is shown or trusted.
///
/// `plaintext` is what `rooms/keys/open` (or `read`) returned, decoded. `read_at` is where
/// the record was read from. `host_author` is the `author` the host recorded for it: always
/// present on an `attributed` room, and absent on a `private` one, where the host records
/// none.
///
/// Refuses, rather than returning a body with a warning, when the body:
/// - is not a `SealedRecordBody`, or names an unknown member;
/// - carries no proof, or one that does not verify for `author`, for `assertionMethod`, in an
///   accepted suite;
/// - names a different location than `read_at`;
/// - is signed by someone other than `host_author`, when there is one.
pub async fn verify_record_body(
    plaintext: &[u8],
    read_at: RecordLocation<'_>,
    host_author: Option<&str>,
    resolver: &(dyn PurposeVmResolver + '_),
) -> Result<VerifiedRecordBody, BodyError> {
    let signed: Value = serde_json::from_slice(plaintext)
        .map_err(|e| BodyError::Malformed(format!("not JSON: {e}")))?;

    let verified = verify_proof_set(&signed, ProofPurpose::AssertionMethod, resolver)
        .await
        .map_err(|e| BodyError::Signature(e.to_string()))?;
    for proof in verified.proofs() {
        let suite = serde_json::to_value(proof.cryptosuite)
            .ok()
            .and_then(|v| v.as_str().map(str::to_string))
            .unwrap_or_default();
        if !ACCEPTED_SUITES.contains(&suite.as_str()) {
            return Err(BodyError::Signature(format!(
                "signed with {suite}; a record body takes {}",
                ACCEPTED_SUITES.join(" or ")
            )));
        }
    }

    let mut unsigned = signed;
    if let Some(obj) = unsigned.as_object_mut() {
        obj.remove("proof");
    }
    let body: SealedRecordBody =
        serde_json::from_value(unsigned).map_err(|e| BodyError::Malformed(e.to_string()))?;
    body.check()?;

    if verified.signer() != body.author {
        return Err(BodyError::Signature(format!(
            "it verifies for {}, but the body names {} as its author",
            verified.signer(),
            body.author
        )));
    }
    if body.location() != read_at {
        return Err(BodyError::Relocated {
            signed: body.location().to_string(),
            read: read_at.to_string(),
        });
    }
    if let Some(recorded) = host_author
        && recorded != body.author
    {
        return Err(BodyError::AuthorMismatch {
            signed: body.author,
            recorded: recorded.to_string(),
        });
    }
    Ok(VerifiedRecordBody { inner: body })
}

#[cfg(test)]
mod tests {
    use super::*;
    use vta_sdk::trust_task_proof::TrustTaskVmResolver;

    fn did_key(seed_byte: u8) -> (String, HolderKey) {
        let seed = [seed_byte; 32];
        let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
        let did = format!(
            "did:key:{}",
            vta_sdk::did_key::ed25519_multibase_pubkey(&sk.verifying_key().to_bytes())
        );
        let mut buf = vec![0x80, 0x26];
        buf.extend_from_slice(&seed);
        let key =
            HolderKey::from_did_key(&did, multibase::encode(multibase::Base::Base58Btc, &buf))
                .expect("a did:key holder");
        (did, key)
    }

    const ROOM: &str = "did:webvh:QmRoom:rooms.example:deal";

    fn at(key: &str, version: u64) -> RecordLocation<'_> {
        RecordLocation {
            room_id: ROOM,
            key,
            version,
        }
    }

    async fn signed_by(seed: u8, location: RecordLocation<'_>) -> (String, Vec<u8>) {
        let (did, key) = did_key(seed);
        let mut body = SealedRecordBody::new(location, &did);
        body.title = Some("Pricing holds".into());
        body.body = Some("Northwind accepted the term sheet.".into());
        (did, body.sign(&key).await.expect("signs"))
    }

    fn resolver() -> TrustTaskVmResolver {
        TrustTaskVmResolver::did_key_only()
    }

    #[tokio::test]
    async fn a_body_verifies_where_it_was_signed() {
        let (did, bytes) = signed_by(1, at("k1", 3)).await;
        let v = verify_record_body(&bytes, at("k1", 3), Some(&did), &resolver())
            .await
            .expect("verifies");
        assert_eq!(v.body().title.as_deref(), Some("Pricing holds"));
        assert_eq!(v.body().author, did);
    }

    /// A member who re-seals someone else's body under another key, or at a later version,
    /// cannot re-sign it, so the location it names is not where it is read.
    #[tokio::test]
    async fn a_body_moved_to_another_key_or_version_is_refused() {
        let (_, bytes) = signed_by(1, at("k1", 3)).await;
        for elsewhere in [at("k2", 3), at("k1", 4)] {
            let err = verify_record_body(&bytes, elsewhere, None, &resolver())
                .await
                .expect_err("relocated");
            assert!(matches!(err, BodyError::Relocated { .. }), "{err}");
        }
    }

    #[tokio::test]
    async fn an_altered_body_does_not_verify() {
        let (_, bytes) = signed_by(1, at("k1", 3)).await;
        let mut v: Value = serde_json::from_slice(&bytes).unwrap();
        v["title"] = "Pricing collapses".into();
        let err = verify_record_body(
            &serde_json::to_vec(&v).unwrap(),
            at("k1", 3),
            None,
            &resolver(),
        )
        .await
        .expect_err("altered");
        assert!(matches!(err, BodyError::Signature(_)), "{err}");
    }

    /// The author is what the body claims and the signer is who proved it; a body claiming
    /// someone else verifies for its signer and is refused for the mismatch.
    #[tokio::test]
    async fn a_body_claiming_another_author_is_refused() {
        let (other, _) = did_key(2);
        let (_, key) = did_key(1);
        let mut body = SealedRecordBody::new(at("k1", 3), &other);
        body.body = Some("x".into());
        // `sign` refuses this outright…
        assert!(matches!(body.sign(&key).await, Err(BodyError::Signing(_))));
        // …and a hand-built one is refused on reading.
        let mut value = serde_json::to_value(&body).unwrap();
        sign_object_for_assertion(&mut value, &key).await.unwrap();
        let err = verify_record_body(
            &serde_json::to_vec(&value).unwrap(),
            at("k1", 3),
            None,
            &resolver(),
        )
        .await
        .expect_err("wrong author");
        assert!(matches!(err, BodyError::Signature(_)), "{err}");
    }

    #[tokio::test]
    async fn on_an_attributed_room_the_host_recorded_author_must_match() {
        let (_, bytes) = signed_by(1, at("k1", 3)).await;
        let (someone_else, _) = did_key(2);
        let err = verify_record_body(&bytes, at("k1", 3), Some(&someone_else), &resolver())
            .await
            .expect_err("author mismatch");
        assert!(matches!(err, BodyError::AuthorMismatch { .. }), "{err}");
    }

    #[tokio::test]
    async fn an_unsigned_or_unknown_member_body_is_refused() {
        let (did, _) = did_key(1);
        let unsigned = serde_json::to_vec(&SealedRecordBody::new(at("k1", 3), &did)).unwrap();
        assert!(matches!(
            verify_record_body(&unsigned, at("k1", 3), None, &resolver()).await,
            Err(BodyError::Signature(_))
        ));

        let (_, key) = did_key(1);
        let mut value = serde_json::to_value(SealedRecordBody::new(at("k1", 3), &did)).unwrap();
        value["comment"] = "smuggled".into();
        sign_object_for_assertion(&mut value, &key).await.unwrap();
        assert!(matches!(
            verify_record_body(
                &serde_json::to_vec(&value).unwrap(),
                at("k1", 3),
                None,
                &resolver()
            )
            .await,
            Err(BodyError::Malformed(_))
        ));
    }

    #[tokio::test]
    async fn the_schema_bounds_hold_on_signing() {
        let (did, key) = did_key(1);
        let mut body = SealedRecordBody::new(at("k1", 3), &did);
        body.title = Some("t".repeat(MAX_TITLE + 1));
        assert!(matches!(
            body.sign(&key).await,
            Err(BodyError::Malformed(_))
        ));
        let body = SealedRecordBody::new(at("k1", 0), &did);
        assert!(matches!(
            body.sign(&key).await,
            Err(BodyError::Malformed(_))
        ));
    }
}
