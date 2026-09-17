//! Reading the proof block of a document that may carry more than one proof.
//!
//! # Why this exists
//!
//! W3C Data Integrity allows a document to carry several proofs, and the
//! multi-year post-quantum transition is the reason to use it: a credential
//! signed with **both** Ed25519 and ML-DSA-44 can be verified by a classical
//! verifier and a post-quantum one, neither needing to know about the other.
//! `affinidi-data-integrity` has had `sign_multi` / `verify_multi` for this
//! since it was written, and until now nothing in this workspace called them.
//!
//! Every verification path here read the proof as a single object:
//!
//! ```ignore
//! let proof: DataIntegrityProof = serde_json::from_value(proof_value.clone())?;
//! ```
//!
//! A two-proof credential arrives as a JSON **array**, so that deserialize
//! fails and the credential is rejected as malformed. Which means the stack
//! could not have accepted a hybrid credential from anyone — including one it
//! issued itself, had issuance been wired first. That ordering is why
//! verification moves before issuance.
//!
//! # Acceptance rule
//!
//! `RequireAny`: at least one proof must verify. During the transition that is
//! the only rule that works — a verifier is expected not to understand every
//! suite on the document, and demanding all of them would make a post-quantum
//! proof a liability to the classical verifier that cannot check it. Once the
//! fleet holds PQC keys this tightens to `RequireAll`, which is a policy change
//! rather than a code one.
//!
//! # The rule that is not about cryptography
//!
//! **Every proof that verifies must name the same issuer.** A document carrying
//! a valid proof from Alice and a valid proof from Bob is not "verified" in any
//! sense a single answer can express, and a caller handed one `Ok` would
//! reasonably assume one signer. Refusing is the only honest answer, and it also
//! closes the obvious trick: appending a proof from a party the reader trusts
//! more.

use serde_json::Value as JsonValue;

use affinidi_data_integrity::DataIntegrityProof;

/// The proofs on `value`, whether it carries one or several.
///
/// A bare object is one proof — the shape everything in this workspace emits
/// today, and the reason this is not simply `Vec::deserialize`.
pub(crate) fn proof_set(proof_value: &JsonValue) -> Result<Vec<DataIntegrityProof>, String> {
    let raw: Vec<&JsonValue> = match proof_value {
        JsonValue::Array(items) => items.iter().collect(),
        single => vec![single],
    };
    if raw.is_empty() {
        return Err(
            "proof block is an empty array; a document with no proof is unsigned, \
                    which is a different thing from one whose proofs did not verify"
                .to_string(),
        );
    }

    raw.iter()
        .enumerate()
        .map(|(i, v)| {
            serde_json::from_value::<DataIntegrityProof>((*v).clone()).map_err(|e| {
                // The index matters: with several proofs, "did not parse" alone
                // leaves a caller unable to tell which one is malformed.
                format!("proof {i} did not parse as a Data Integrity proof: {e}")
            })
        })
        .collect()
}

/// The issuer DID a proof's `verificationMethod` names, before the fragment.
pub(crate) fn proof_signer_did(proof: &DataIntegrityProof) -> &str {
    proof
        .verification_method
        .split('#')
        .next()
        .unwrap_or_default()
}

/// Apply the acceptance rule to the outcome of verifying each proof.
///
/// `outcomes` pairs each proof's signer DID with whether it verified.
pub(crate) fn accept_any(outcomes: &[(String, Result<(), String>)]) -> Result<String, String> {
    let verified: Vec<&String> = outcomes
        .iter()
        .filter(|(_, r)| r.is_ok())
        .map(|(did, _)| did)
        .collect();

    let Some(first) = verified.first() else {
        // Report every failure, not just the first. With a hybrid credential the
        // interesting information is usually *which* suite failed — a classical
        // proof that verifies beside a post-quantum one that does not says
        // something quite different from the reverse.
        let reasons: Vec<String> = outcomes
            .iter()
            .enumerate()
            .filter_map(|(i, (did, r))| r.as_ref().err().map(|e| format!("proof {i} ({did}): {e}")))
            .collect();
        return Err(format!("no proof verified — {}", reasons.join("; ")));
    };

    if let Some(other) = verified.iter().find(|d| **d != *first) {
        return Err(format!(
            "proofs verify for two different issuers ({first} and {other}); a document signed \
             by more than one party cannot be reported as verified for one of them"
        ));
    }
    Ok((*first).clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn a_proof(vm: &str) -> JsonValue {
        json!({
            "type": "DataIntegrityProof",
            "cryptosuite": "eddsa-jcs-2022",
            "created": "2026-01-01T00:00:00Z",
            "verificationMethod": vm,
            "proofPurpose": "assertionMethod",
            "proofValue": "z2V1p3vLnQ8kZ9YbW3xJ5tR7mN4qS6dF8gH1jK2lM3nP",
        })
    }

    /// A single proof object still reads as one proof — everything this
    /// workspace emits today is this shape, and the change must not require a
    /// document to become an array to stay valid.
    #[test]
    fn a_bare_object_is_one_proof() {
        let set = proof_set(&a_proof("did:example:alice#key-0")).expect("parses");
        assert_eq!(set.len(), 1);
    }

    /// The case the old code could not read at all.
    #[test]
    fn an_array_is_a_proof_set() {
        let set = proof_set(&json!([
            a_proof("did:example:alice#key-0"),
            a_proof("did:example:alice#key-pq"),
        ]))
        .expect("parses");
        assert_eq!(set.len(), 2);
    }

    /// A malformed proof names its position, because "did not parse" alone
    /// leaves a caller with several proofs unable to tell which.
    #[test]
    fn a_malformed_proof_is_identified_by_index() {
        let err = proof_set(&json!([
            a_proof("did:example:alice#key-0"),
            json!({"type": "nope"})
        ]))
        .expect_err("the second proof is not a Data Integrity proof");
        assert!(err.contains("proof 1"), "unexpected: {err}");
    }

    /// An empty array is distinguished from an unsigned document.
    #[test]
    fn an_empty_array_says_what_it_is() {
        let err = proof_set(&json!([])).expect_err("empty");
        assert!(err.contains("unsigned"), "unexpected: {err}");
    }

    /// One good proof beside one bad one is accepted — that is the whole point
    /// during the transition, when a verifier is expected not to understand
    /// every suite on the document.
    #[test]
    fn one_verifying_proof_is_enough() {
        let did = "did:example:alice".to_string();
        let out = accept_any(&[
            (did.clone(), Err("unsupported suite".into())),
            (did.clone(), Ok(())),
        ])
        .expect("one proof verified");
        assert_eq!(out, did);
    }

    /// When nothing verifies, every reason is reported.
    ///
    /// With a hybrid credential the interesting fact is usually *which* suite
    /// failed, and a first-error-only message hides exactly that.
    #[test]
    fn no_verifying_proof_reports_every_reason() {
        let err = accept_any(&[
            ("did:example:alice".into(), Err("bad signature".into())),
            ("did:example:alice".into(), Err("unsupported suite".into())),
        ])
        .expect_err("nothing verified");
        assert!(err.contains("bad signature"), "unexpected: {err}");
        assert!(err.contains("unsupported suite"), "unexpected: {err}");
    }

    /// **The rule that is not about cryptography.** Two valid proofs from two
    /// different issuers is not a verified document.
    ///
    /// Both signatures are real here; that is what makes it worth refusing. A
    /// caller handed one `Ok` and one DID would reasonably believe one party
    /// signed — and the obvious trick is appending a proof from someone the
    /// reader trusts more.
    #[test]
    fn proofs_from_two_issuers_are_refused_even_when_both_verify() {
        let err = accept_any(&[
            ("did:example:alice".into(), Ok(())),
            ("did:example:mallory".into(), Ok(())),
        ])
        .expect_err("two issuers cannot be reported as one");
        assert!(err.contains("two different issuers"), "unexpected: {err}");
    }
}
