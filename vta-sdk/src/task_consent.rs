//! Answer a `task-consent/request/0.1` from a tool rather than a device.
//!
//! The ceremony has three documents (`docs/02-vta/task-consent.md`): a node
//! pushes a signed **request** to each approver, an approver returns a
//! DI-signed **decision**, and the requester is told once the grant exists.
//! Until this module existed only `vta-mobile-core` could produce a decision,
//! so an approver without an enrolled device could not answer at all — and at
//! the VTC, where every unrestricted-admin grant needs another admin's consent
//! (VTI-APV-014), that left a community with no CLI path to its own
//! administration.
//!
//! What lives here is what every approver surface has to get the same way:
//!
//! - [`match_code`] — the six characters the approver compares against the
//!   requester's screen. Derived from the **decoded** digest bytes, never from
//!   the multibase string, whose first characters are the same for every
//!   digest. Both ends of the comparison must call this.
//! - [`ConsentRequest::verify`] — the request's proof must verify, its signer
//!   must be its issuer, the issuer must be the node the approver expects, and
//!   it must be addressed to the approver. It returns a
//!   [`VerifiedConsentRequest`], the only type a decision can be built from,
//!   so an approval of an unverified request does not compile.
//! - [`VerifiedConsentRequest::decision`] — the decision payload, echoing the
//!   challenge and digest the node bound the request to.
//!
//! Signing and sending the decision stay with the caller's client, which
//! already holds the approver's key and a route to the node.

use serde_json::Value;

/// The generated `task-consent/decision/0.1` types.
pub use trust_tasks_rs::specs::task_consent::decision::v0_1 as decision;
/// The generated `task-consent/request/0.1` types.
pub use trust_tasks_rs::specs::task_consent::request::v0_1 as request;

/// Type URI of the request document an approver answers.
pub const REQUEST_TYPE: &str = <request::Payload as trust_tasks_rs::Payload>::TYPE_URI;

/// Type URI of the decision document an approver returns.
pub const DECISION_TYPE: &str = <decision::Payload as trust_tasks_rs::Payload>::TYPE_URI;

/// Length of the match code, in hex characters. UI-only: there is no wire
/// field, so every surface showing one must agree on this.
pub const MATCH_CODE_LEN: usize = 6;

/// Multihash prefix for SHA-256 with a 32-byte digest.
const MULTIHASH_SHA2_256_32: [u8; 2] = [0x12, 0x20];

/// Why a request could not be read, or would not be answered.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TaskConsentError {
    /// `payloadDigest` is not a multibase-encoded SHA-256 multihash.
    #[error("payloadDigest is not a multibase sha2-256 multihash: {0}")]
    Digest(String),
    /// The input holds no request document.
    #[error("no task-consent request found in the input")]
    NoRequest,
    /// The document or its payload does not match the published schema.
    #[error("not a valid task-consent/request/0.1 document: {0}")]
    Malformed(String),
    /// The proof is missing or does not verify.
    #[error("the request's proof does not verify")]
    ProofInvalid,
    /// The proof verifies, but under a key the document's issuer does not
    /// control.
    #[error("the request is signed by {signer}, not by its issuer {issuer}")]
    SignerNotIssuer {
        /// The DID whose key made the proof.
        signer: String,
        /// The DID the document names as its issuer.
        issuer: String,
    },
    /// The request was issued by a node other than the one the approver named.
    #[error("the request was issued by {actual}, not by {expected}")]
    WrongIssuer {
        /// The node the approver expected.
        expected: String,
        /// The node that issued the request.
        actual: String,
    },
    /// The request is addressed to somebody else.
    #[error("the request is addressed to {actual}, not to this approver ({expected})")]
    WrongRecipient {
        /// The approver's own DID.
        expected: String,
        /// The DID the request is addressed to.
        actual: String,
    },
    /// The request's window has closed; the node has discarded it.
    #[error("the request expired at {0}")]
    Expired(chrono::DateTime<chrono::Utc>),
}

/// The operator's comparison code for a `payloadDigest`: the first
/// [`MATCH_CODE_LEN`] hex characters of the **digest bytes**.
///
/// A `digestMultibase` always begins `zQm` — the base58btc marker and the
/// sha2-256 multihash prefix — so slicing the encoded string would spend half
/// the code on a constant while still looking random: about 17.6 bits where
/// the operator believes they compare about 35. Decoding first restores the
/// entropy, and yields exactly `hex(digest)[..6]`, the code approver devices
/// have always shown.
pub fn match_code(payload_digest: &str) -> Result<String, TaskConsentError> {
    let (_base, bytes) =
        multibase::decode(payload_digest).map_err(|e| TaskConsentError::Digest(e.to_string()))?;
    let digest = bytes
        .strip_prefix(&MULTIHASH_SHA2_256_32)
        .filter(|d| d.len() == 32)
        .ok_or_else(|| TaskConsentError::Digest("not a 32-byte sha2-256 multihash".into()))?;
    Ok(crate::hex::lower(&digest[..MATCH_CODE_LEN.div_ceil(2)])[..MATCH_CODE_LEN].to_string())
}

/// Pick out the request documents in what an approver was handed.
///
/// Requests reach an approver pushed by the node, or relayed by the requester
/// from the refusal it received. So this accepts a request document, an array
/// of them, a refusal's `details` (`{"consentRequests": [...]}`), or an error
/// body carrying those details (`{"details": {"consentRequests": [...]}}`).
pub fn extract_requests(input: &Value) -> Vec<Value> {
    fn is_request(v: &Value) -> bool {
        v.get("type").and_then(Value::as_str) == Some(REQUEST_TYPE)
    }
    match input {
        Value::Array(items) => items.iter().filter(|v| is_request(v)).cloned().collect(),
        v if is_request(v) => vec![v.clone()],
        Value::Object(map) => map
            .get("consentRequests")
            .or_else(|| map.get("details").and_then(|d| d.get("consentRequests")))
            .map(extract_requests)
            .unwrap_or_default(),
        _ => Vec::new(),
    }
}

/// A `task-consent/request/0.1` document as received: unverified.
#[derive(Debug, Clone)]
pub struct ConsentRequest {
    raw: Value,
}

impl ConsentRequest {
    /// Wrap a request document exactly as it was received.
    pub fn new(raw: Value) -> Self {
        Self { raw }
    }

    /// The DID the document names as its recipient, if any — for choosing
    /// which of several relayed requests is addressed to this approver before
    /// verifying it.
    pub fn recipient(&self) -> Option<&str> {
        self.raw.get("recipient").and_then(Value::as_str)
    }
}

#[cfg(feature = "client")]
impl ConsentRequest {
    /// Verify the request and read it.
    ///
    /// Refuses unless the document is a request that matches its schema, its
    /// proof verifies, the proof's signer is the document's issuer, that
    /// issuer is `expected_issuer`, the document is addressed to `approver`,
    /// and it has not expired at `now`.
    ///
    /// The issuer check is what makes the rest meaningful: anyone can sign a
    /// well-formed request, so a request is only worth answering when it comes
    /// from the node the approver means to answer.
    pub async fn verify(
        self,
        expected_issuer: &str,
        approver: &str,
        resolver: &crate::trust_task_proof::TrustTaskVmResolver,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<VerifiedConsentRequest, TaskConsentError> {
        use trust_tasks_rs::validate::ValidatedPayload;

        let doc: trust_tasks_rs::TrustTask<Value> = serde_json::from_value(self.raw.clone())
            .map_err(|e| TaskConsentError::Malformed(e.to_string()))?;
        if doc.type_uri.to_string() != REQUEST_TYPE {
            return Err(TaskConsentError::Malformed(format!(
                "document type is {}",
                doc.type_uri
            )));
        }

        let signer = crate::trust_task_proof::verify_trust_task_proof_with(&doc, resolver)
            .await
            .map_err(|_| TaskConsentError::ProofInvalid)?;
        let issuer = doc.issuer.clone().unwrap_or_default();
        if signer != issuer {
            return Err(TaskConsentError::SignerNotIssuer { signer, issuer });
        }
        if issuer != expected_issuer {
            return Err(TaskConsentError::WrongIssuer {
                expected: expected_issuer.to_string(),
                actual: issuer,
            });
        }
        let recipient = doc.recipient.clone().unwrap_or_default();
        if recipient != approver {
            return Err(TaskConsentError::WrongRecipient {
                expected: approver.to_string(),
                actual: recipient,
            });
        }

        // Read the payload as received, against the schema, before parsing it.
        request::Payload::validate_value(&doc.payload)
            .map_err(|e| TaskConsentError::Malformed(e.to_string()))?;
        let payload: request::Payload = serde_json::from_value(doc.payload.clone())
            .map_err(|e| TaskConsentError::Malformed(e.to_string()))?;
        if payload.expires_at <= now {
            return Err(TaskConsentError::Expired(payload.expires_at));
        }
        let match_code = match_code(&payload.payload_digest)?;

        Ok(VerifiedConsentRequest {
            issuer,
            payload,
            match_code,
        })
    }
}

/// A request whose proof, issuer, recipient and expiry have been checked. Only
/// [`ConsentRequest::verify`] makes one.
#[derive(Debug, Clone)]
pub struct VerifiedConsentRequest {
    issuer: String,
    payload: request::Payload,
    match_code: String,
}

impl VerifiedConsentRequest {
    /// The node that issued the request, and that the decision goes back to.
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// The request payload: what is being asked, by whom, and its effects.
    pub fn payload(&self) -> &request::Payload {
        &self.payload
    }

    /// The code to compare against the requester's screen.
    pub fn match_code(&self) -> &str {
        &self.match_code
    }

    /// The decision payload answering this request.
    ///
    /// Echoes the request's challenge and digest; the node matches the decision
    /// to its pending request by those two and nothing else. `reason` is at
    /// most 500 characters.
    pub fn decision(
        &self,
        approve: bool,
        reason: Option<&str>,
    ) -> Result<decision::Payload, TaskConsentError> {
        let malformed = |e: &dyn std::fmt::Display| TaskConsentError::Malformed(e.to_string());
        decision::Payload::builder()
            .challenge(
                decision::PayloadChallenge::try_from(self.payload.challenge.to_string())
                    .map_err(|e| malformed(&e))?,
            )
            .decision(if approve {
                decision::Decision::Approve
            } else {
                decision::Decision::Deny
            })
            .payload_digest(
                decision::DigestMultibase::try_from(self.payload.payload_digest.to_string())
                    .map_err(|e| malformed(&e))?,
            )
            .reason(
                reason
                    .map(|r| decision::PayloadReason::try_from(r.to_string()))
                    .transpose()
                    .map_err(|e| malformed(&e))?,
            )
            .try_into()
            .map_err(|e: decision::error::ConversionError| malformed(&e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest_of(bytes: [u8; 32]) -> String {
        let mut mh = MULTIHASH_SHA2_256_32.to_vec();
        mh.extend_from_slice(&bytes);
        multibase::encode(multibase::Base::Base58Btc, mh)
    }

    #[test]
    fn match_code_reads_the_digest_bytes_not_the_encoding() {
        let mut bytes = [0u8; 32];
        bytes[..3].copy_from_slice(&[0xab, 0xcd, 0xef]);
        let digest = digest_of(bytes);
        assert!(digest.starts_with("zQm"), "{digest}");
        assert_eq!(match_code(&digest).unwrap(), "abcdef");
    }

    #[test]
    fn match_code_refuses_a_digest_that_is_not_sha2_256() {
        assert!(match_code("not-multibase!").is_err());
        let short = multibase::encode(multibase::Base::Base58Btc, [0x12, 0x20, 1, 2, 3]);
        assert!(matches!(
            match_code(&short),
            Err(TaskConsentError::Digest(_))
        ));
    }

    #[test]
    fn extract_requests_accepts_every_relayed_shape() {
        let req = serde_json::json!({ "type": REQUEST_TYPE, "payload": {} });
        let other = serde_json::json!({ "type": DECISION_TYPE });
        assert_eq!(extract_requests(&req).len(), 1);
        assert_eq!(extract_requests(&serde_json::json!([req, other])).len(), 1);
        assert_eq!(
            extract_requests(&serde_json::json!({ "consentRequests": [req] })).len(),
            1
        );
        assert_eq!(
            extract_requests(&serde_json::json!({ "details": { "consentRequests": [req] } })).len(),
            1
        );
        assert!(extract_requests(&other).is_empty());
    }
}
