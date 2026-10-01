//! Building, signing and verifying the peer-vetting artifacts (feature
//! `vetting`).
//!
//! The wire shapes are the types generated from the published specifications,
//! re-exported in [`crate::protocols::vetting`]; this module is the behaviour
//! that operates on them:
//!
//! - [`card`] — the Vetting Card an applicant signs for one vetter, and the
//!   verification a vetter's client runs before showing it.
//! - [`statement`] — the Vetting Statement (a DTG `StatementCredential` under
//!   the `vetted/1` predicate) a vetter signs, and its verification.
//! - [`requirements`] — the `requirementsDigest`, and the evaluation of a set
//!   of statements against a community's [`VettingRequirements`]. The applicant's
//!   client uses it to show progress; the community uses the same counting to
//!   build the facts its policy decides on.
//! - [`match_code`] — the code two people read to each other to confirm they
//!   are in the same session.
//! - [`eligibility`] — a vetter presenting the vetter role credential the
//!   community issued them, and the applicant's check of it.
//! - [`status`] — the applicant's check that such a credential has not been
//!   revoked, against the issuer's signed status list.
//! - [`ticket_uri`] — the Vetting Ticket as the URI a vetter's QR code carries.
//!
//! Every verification returns a distinct `Verified*` type (workspace typestate
//! rule): code that needs a verified card or statement cannot be handed an
//! unverified one.
//!
//! [`VettingRequirements`]: crate::protocols::vetting::VettingRequirements

pub mod card;
pub mod eligibility;
pub mod match_code;
pub mod requirements;
pub mod statement;
pub mod status;
pub mod ticket_uri;

use serde_json::Value;

use crate::trust_task_proof::TrustTaskVmResolver;

/// Why building or verifying a vetting artifact failed.
///
/// [`Display`](std::fmt::Display) is safe to show a counterparty; verifier
/// internals are only reachable through [`VettingError::cause`], in the same
/// way as [`crate::trust_task_proof::DiProofError`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum VettingError {
    /// The artifact does not parse as its type.
    #[error("malformed {what}")]
    Malformed {
        /// Which artifact.
        what: &'static str,
        /// Parser detail, for the log.
        detail: String,
    },
    /// A binding member does not match what the verifier expects.
    #[error("{0} does not match this session")]
    Binding(&'static str),
    /// Outside the validity window.
    #[error("{0} is outside its validity window")]
    Expired(&'static str),
    /// Signed by (or to be signed by) someone other than the named party.
    #[error("{what} is not signed by its {role}")]
    WrongSigner {
        /// Which artifact.
        what: &'static str,
        /// `publisher` or `issuer`.
        role: &'static str,
    },
    /// No proof, or the proof does not verify.
    #[error("{what} proof verification failed")]
    Proof {
        /// Which artifact.
        what: &'static str,
        /// Verifier detail, for the log.
        detail: String,
    },
    /// The identity commitment does not recompute from the card.
    #[error("identity commitment does not recompute from the card")]
    Commitment,
    /// A required claim is absent.
    #[error("required claim `{0}` is missing")]
    MissingClaim(String),
    /// An eligibility presentation carries no role credential naming its
    /// holder, in the required role, for the expected community.
    #[error("no role credential names this vetter in that role for this community")]
    NoRoleCredential,
    /// The artifact names a version this reader does not understand — a newer
    /// client made it.
    #[error("{what} version `{version}` is not supported")]
    UnsupportedVersion {
        /// Which artifact.
        what: &'static str,
        /// The version it named, truncated.
        version: String,
    },
    /// Signing failed.
    #[error("signing failed")]
    Sign(String),
    /// Digest computation failed.
    #[error("digest computation failed")]
    Digest(String),
    /// Randomness was unavailable.
    #[error("no randomness available")]
    Random(String),
}

impl VettingError {
    /// Underlying detail for the operator's log. Never put this on the wire.
    #[must_use]
    pub fn cause(&self) -> Option<&str> {
        match self {
            Self::Malformed { detail, .. }
            | Self::Proof { detail, .. }
            | Self::Sign(detail)
            | Self::Digest(detail)
            | Self::Random(detail) => Some(detail),
            _ => None,
        }
    }
}

/// The DID before `#` in a verification method or secret id.
pub(crate) fn did_of(vm: &str) -> &str {
    vm.split('#').next().unwrap_or_default()
}

/// Verify the Data Integrity proof block on `signed` — one proof or a proof
/// set (VTI-44: a multi-key community signs once per key) — and return the
/// one signer DID, which the caller binds to the party the artifact names.
///
/// Every proof must declare `expected_purpose` and verify with a key its DID
/// authorises for it; see [`crate::trust_task_proof::proof_set`] for the rule.
pub(crate) async fn verify_attached_proof(
    what: &'static str,
    signed: &Value,
    expected_purpose: &str,
    resolver: &TrustTaskVmResolver,
) -> Result<String, VettingError> {
    use crate::trust_task_proof::{ProofPurpose, verify_proof_set};

    let expected = ProofPurpose::parse(expected_purpose).map_err(|e| VettingError::Proof {
        what,
        detail: e.to_string(),
    })?;
    verify_proof_set(signed, expected, resolver)
        .await
        .map(|verified| verified.into_signer())
        .map_err(|e| VettingError::Proof {
            what,
            detail: e.to_string(),
        })
}

/// `digestMultibase` per DTG Credentials §Digest Encoding (JCS without the
/// top-level `proof`, SHA-256 multihash, base58btc).
pub(crate) fn digest(value: &Value) -> Result<String, VettingError> {
    dtg_credentials::digest_multibase_json(value).map_err(|e| VettingError::Digest(e.to_string()))
}

/// A catalog credential's wire form, for tests.
#[cfg(test)]
pub(crate) fn tests_support_json(dtg: &dtg_credentials::DTGCredential) -> Value {
    serde_json::to_value(dtg).expect("catalog credential serialises")
}

#[cfg(test)]
pub(crate) mod test_support {
    use affinidi_secrets_resolver::secrets::Secret;

    /// A `did:key` Ed25519 secret from a fixed seed, `id` = `<did>#<multibase>`.
    pub fn secret(seed_byte: u8) -> Secret {
        let seed = [seed_byte; 32];
        let mut secret = Secret::generate_ed25519(None, Some(&seed));
        let public = secret.get_public_keymultibase().unwrap();
        secret.id = format!("did:key:{public}#{public}");
        secret
    }

    pub fn did(secret: &Secret) -> String {
        super::did_of(&secret.id).to_string()
    }
}

#[cfg(test)]
mod proof_set_tests {
    use super::test_support::{did, secret};
    use super::*;
    use affinidi_data_integrity::{DataIntegrityProof, SignOptions};
    use affinidi_secrets_resolver::secrets::Secret;
    use serde_json::json;

    fn statement() -> Value {
        json!({
            "type": ["VerifiableCredential", "StatementCredential"],
            "credentialSubject": { "id": "did:example:applicant" }
        })
    }

    async fn proof_over(doc: &Value, key: &Secret, created: &str) -> Value {
        let proof = DataIntegrityProof::sign(
            doc,
            key,
            SignOptions::new()
                .with_proof_purpose("assertionMethod")
                .with_created(created.parse().unwrap()),
        )
        .await
        .unwrap();
        serde_json::to_value(proof).unwrap()
    }

    /// VTI-44: a vetting artifact whose `proof` is an array — one proof per
    /// signing key, as a multi-key issuer emits — verifies and names its one
    /// signer. The single-object reader refused it outright.
    #[tokio::test]
    async fn vti_44_a_proof_set_verifies_and_names_one_signer() {
        let key = secret(0x51);
        let doc = statement();
        let mut signed = doc.clone();
        signed["proof"] = json!([
            proof_over(&doc, &key, "2026-09-17T15:00:00Z").await,
            proof_over(&doc, &key, "2026-09-17T15:00:01Z").await,
        ]);
        let signer = verify_attached_proof(
            "statement",
            &signed,
            "assertionMethod",
            &TrustTaskVmResolver::did_key_only(),
        )
        .await
        .expect("a proof set verifies");
        assert_eq!(signer, did(&key));
    }

    /// VTI-44: one proof in the set that does not verify refuses the set.
    #[tokio::test]
    async fn vti_44_one_tampered_proof_in_the_set_is_refused() {
        let key = secret(0x52);
        let doc = statement();
        let mut signed = doc.clone();
        let good = proof_over(&doc, &key, "2026-09-17T15:00:00Z").await;
        let other = proof_over(&json!({"other": 1}), &key, "2026-09-17T15:00:00Z").await;
        let mut bad = good.clone();
        bad["proofValue"] = other["proofValue"].clone();
        signed["proof"] = json!([good, bad]);
        let err = verify_attached_proof(
            "statement",
            &signed,
            "assertionMethod",
            &TrustTaskVmResolver::did_key_only(),
        )
        .await
        .expect_err("one bad proof refuses the set");
        assert!(
            err.cause().is_some_and(|c| c.contains("1 of 2 proofs")),
            "{err:?}"
        );
    }

    /// VTI-44: a genuine proof by a second party appended to the set is
    /// refused rather than reported as one signer.
    #[tokio::test]
    async fn vti_44_a_proof_by_another_key_is_refused() {
        let (key, other) = (secret(0x53), secret(0x54));
        let doc = statement();
        let mut signed = doc.clone();
        signed["proof"] = json!([
            proof_over(&doc, &key, "2026-09-17T15:00:00Z").await,
            proof_over(&doc, &other, "2026-09-17T15:00:00Z").await,
        ]);
        let err = verify_attached_proof(
            "statement",
            &signed,
            "assertionMethod",
            &TrustTaskVmResolver::did_key_only(),
        )
        .await
        .expect_err("two signers");
        assert!(
            err.cause()
                .is_some_and(|c| c.contains("two different issuers")),
            "{err:?}"
        );
    }

    /// A single proof object — the shape every vetting artifact had before —
    /// still verifies, and a wrong expected purpose is still refused.
    #[tokio::test]
    async fn vti_44_a_single_proof_object_still_verifies() {
        let key = secret(0x55);
        let doc = statement();
        let mut signed = doc.clone();
        signed["proof"] = proof_over(&doc, &key, "2026-09-17T15:00:00Z").await;
        let resolver = TrustTaskVmResolver::did_key_only();
        let signer = verify_attached_proof("statement", &signed, "assertionMethod", &resolver)
            .await
            .expect("verifies");
        assert_eq!(signer, did(&key));
        assert!(
            verify_attached_proof("statement", &signed, "authentication", &resolver)
                .await
                .is_err()
        );
    }
}
