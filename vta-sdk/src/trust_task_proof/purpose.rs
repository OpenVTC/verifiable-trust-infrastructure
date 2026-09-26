//! A proof's key must be authorised for the purpose the proof declares.
//!
//! **VTI-KEY-022**: a verifier MUST check that the key used is authorised for
//! the purpose the material is relied on for, and MUST refuse where it is not.
//! For a W3C Data Integrity proof that purpose is its `proofPurpose`, and the
//! authorisation is the DID document's verification relationship of the same
//! name (Controlled Identifiers v1.0 §3.3, *Retrieve Verification Method*,
//! steps 10 and 11; restated for Trust Task documents by the framework's
//! "Proof Purpose and Verification Relationship").
//!
//! # Why this is not left to the upstream resolver trait
//!
//! `affinidi_data_integrity::VerificationMethodResolver::resolve_vm` receives
//! only the method URI. A resolver behind it cannot know what the proof claims
//! to be for, so every resolver here used to accept any key the DID document
//! listed — including one published for key agreement, or authorised only to
//! authenticate — as a key that could make any assertion. [`PurposeVmResolver`]
//! carries the purpose, and [`PurposeBound`] hands the upstream `verify` a
//! resolver fixed to one proof's purpose.
//!
//! # What is checked
//!
//! [`authorised_method`] requires, of the resolved document:
//!
//! 1. its `id` is the DID the method URI names;
//! 2. the relationship `proofPurpose` names lists the method — by absolute DID
//!    URL, by `#fragment` relative to the document id, or embedded;
//! 3. the method's `controller` is that DID.
//!
//! `keyAgreement` is never a signing purpose; [`ProofPurpose::parse`] refuses
//! it along with any unknown value. `did:key` has implicit relationships: its
//! key `did:key:<id>#<id>` is authorised for all four signing purposes.
//!
//! Refusals name the rule that failed, never the document, a DID or key
//! material — they reach logs.

use affinidi_data_integrity::{
    DataIntegrityError, DataIntegrityProof, ResolvedKey, VerificationMethodResolver,
};
use affinidi_did_common::Document;
use affinidi_did_common::verification_method::{VerificationMethod, VerificationRelationship};

/// A verification relationship a signature can be made under — the values a
/// proof's `proofPurpose` may take. `keyAgreement` is deliberately absent.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ProofPurpose {
    /// `assertionMethod` — an attestation a third party may rely on.
    AssertionMethod,
    /// `authentication` — the signer proves control of the identifier.
    Authentication,
    /// `capabilityInvocation`.
    CapabilityInvocation,
    /// `capabilityDelegation`.
    CapabilityDelegation,
}

impl ProofPurpose {
    /// Every purpose a signature can carry.
    pub const ALL: [ProofPurpose; 4] = [
        ProofPurpose::AssertionMethod,
        ProofPurpose::Authentication,
        ProofPurpose::CapabilityInvocation,
        ProofPurpose::CapabilityDelegation,
    ];

    /// The `proofPurpose` value, which is also the DID-document property
    /// naming the relationship.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            ProofPurpose::AssertionMethod => "assertionMethod",
            ProofPurpose::Authentication => "authentication",
            ProofPurpose::CapabilityInvocation => "capabilityInvocation",
            ProofPurpose::CapabilityDelegation => "capabilityDelegation",
        }
    }

    /// Parse a proof's `proofPurpose`, refusing `keyAgreement`, an empty
    /// value and anything naming no signing relationship.
    pub fn parse(value: &str) -> Result<Self, DataIntegrityError> {
        match value {
            "assertionMethod" => Ok(ProofPurpose::AssertionMethod),
            "authentication" => Ok(ProofPurpose::Authentication),
            "capabilityInvocation" => Ok(ProofPurpose::CapabilityInvocation),
            "capabilityDelegation" => Ok(ProofPurpose::CapabilityDelegation),
            "keyAgreement" => Err(DataIntegrityError::MalformedProof(
                "proofPurpose keyAgreement never authorises a signature".to_string(),
            )),
            _ => Err(DataIntegrityError::MalformedProof(
                "proofPurpose names no signing verification relationship".to_string(),
            )),
        }
    }
}

impl std::fmt::Display for ProofPurpose {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Resolves a verification method to its key **only if** the DID that names
/// it authorised it for `purpose` (see the module docs for the rules).
#[async_trait::async_trait]
pub trait PurposeVmResolver: Send + Sync {
    /// Resolve `vm` — an absolute DID URL — for a proof declaring `purpose`.
    async fn resolve_vm_for_purpose(
        &self,
        vm: &str,
        purpose: ProofPurpose,
    ) -> Result<ResolvedKey, DataIntegrityError>;
}

#[async_trait::async_trait]
impl<R: PurposeVmResolver + ?Sized> PurposeVmResolver for &R {
    async fn resolve_vm_for_purpose(
        &self,
        vm: &str,
        purpose: ProofPurpose,
    ) -> Result<ResolvedKey, DataIntegrityError> {
        (**self).resolve_vm_for_purpose(vm, purpose).await
    }
}

#[async_trait::async_trait]
impl<R: PurposeVmResolver + ?Sized> PurposeVmResolver for std::sync::Arc<R> {
    async fn resolve_vm_for_purpose(
        &self,
        vm: &str,
        purpose: ProofPurpose,
    ) -> Result<ResolvedKey, DataIntegrityError> {
        (**self).resolve_vm_for_purpose(vm, purpose).await
    }
}

/// A [`PurposeVmResolver`] fixed to one proof's purpose, as the upstream
/// [`VerificationMethodResolver`] `DataIntegrityProof::verify` takes:
///
/// ```ignore
/// proof.verify(&doc, &PurposeBound::for_proof(&resolver, &proof)?, options).await?;
/// ```
pub struct PurposeBound<R> {
    resolver: R,
    purpose: ProofPurpose,
}

impl<R> PurposeBound<R> {
    /// Bind `resolver` to `purpose`.
    pub fn new(resolver: R, purpose: ProofPurpose) -> Self {
        Self { resolver, purpose }
    }

    /// Bind `resolver` to the purpose `proof` declares, refusing a purpose no
    /// signature can carry.
    pub fn for_proof(resolver: R, proof: &DataIntegrityProof) -> Result<Self, DataIntegrityError> {
        Ok(Self::new(
            resolver,
            ProofPurpose::parse(&proof.proof_purpose)?,
        ))
    }

    /// The purpose every resolution is checked against.
    pub fn purpose(&self) -> ProofPurpose {
        self.purpose
    }
}

#[async_trait::async_trait]
impl<R: PurposeVmResolver> VerificationMethodResolver for PurposeBound<R> {
    async fn resolve_vm(&self, vm: &str) -> Result<ResolvedKey, DataIntegrityError> {
        self.resolver.resolve_vm_for_purpose(vm, self.purpose).await
    }
}

/// Split an absolute verification-method DID URL into its DID and fragment.
/// A relative reference, or a DID URL with no fragment, names no method.
pub fn split_vm(vm: &str) -> Result<(&str, &str), DataIntegrityError> {
    match vm.split_once('#') {
        Some((did, fragment)) if did.starts_with("did:") && !fragment.is_empty() => {
            Ok((did, fragment))
        }
        _ => Err(DataIntegrityError::Resolver(
            "verificationMethod must be an absolute DID URL with a fragment".to_string(),
        )),
    }
}

/// `did:key`'s implicit relationships: the only method is
/// `did:key:<id>#<id>`, authorised for every signing purpose. Refuses any
/// other method URI.
pub fn check_did_key_method(vm: &str) -> Result<(), DataIntegrityError> {
    let (did, fragment) = split_vm(vm)?;
    let id = did.strip_prefix("did:key:").ok_or_else(|| {
        DataIntegrityError::Resolver("verificationMethod is not a did:key".to_string())
    })?;
    if fragment != id {
        return Err(DataIntegrityError::Resolver(
            "verificationMethod is not the did:key's own key (fragment must repeat the key id)"
                .to_string(),
        ));
    }
    Ok(())
}

fn relationship(doc: &Document, purpose: ProofPurpose) -> &[VerificationRelationship] {
    match purpose {
        ProofPurpose::AssertionMethod => &doc.assertion_method,
        ProofPurpose::Authentication => &doc.authentication,
        ProofPurpose::CapabilityInvocation => &doc.capability_invocation,
        ProofPurpose::CapabilityDelegation => &doc.capability_delegation,
    }
}

/// The verification method `vm` names in `doc`, provided `doc` is `did`'s
/// document, the relationship `purpose` names lists the method, and the
/// method's controller is `did`.
pub fn authorised_method(
    doc: &Document,
    did: &str,
    vm: &str,
    purpose: ProofPurpose,
) -> Result<VerificationMethod, DataIntegrityError> {
    if doc.id.as_str() != did {
        return Err(DataIntegrityError::Resolver(
            "the resolved DID document's id is not the verificationMethod's DID".to_string(),
        ));
    }
    // A reference is an absolute DID URL or a fragment relative to `did`.
    let names_vm = |id: &str| match id.strip_prefix('#') {
        Some(fragment) => {
            vm.strip_prefix(did).and_then(|rest| rest.strip_prefix('#')) == Some(fragment)
        }
        None => id == vm,
    };
    let embedded = |r: &VerificationRelationship| match r {
        VerificationRelationship::VerificationMethod(m) if names_vm(m.id.as_str()) => {
            Some((**m).clone())
        }
        _ => None,
    };

    // `Some(None)`: listed by reference; `Some(Some(m))`: embedded.
    let listed = relationship(doc, purpose).iter().find_map(|r| match r {
        VerificationRelationship::Reference(id) if names_vm(id) => Some(None),
        other => embedded(other).map(Some),
    });
    let method = match listed {
        None => {
            return Err(DataIntegrityError::Resolver(format!(
                "verificationMethod is not listed under {purpose} in its DID document"
            )));
        }
        Some(Some(method)) => method,
        // A reference names a method defined in the document's
        // `verificationMethod` set. It is never resolved to a method embedded
        // under another relationship: that method is authorised for that
        // relationship only, and borrowing it here would let the purpose's
        // list vouch for a key defined for a different purpose.
        Some(None) => doc
            .verification_method
            .iter()
            .find(|m| names_vm(m.id.as_str()))
            .cloned()
            .ok_or_else(|| {
                DataIntegrityError::Resolver(
                    "verificationMethod is referenced but not defined under verificationMethod \
                     in its DID document"
                        .to_string(),
                )
            })?,
    };
    if method.controller.as_str() != did {
        return Err(DataIntegrityError::Resolver(
            "verificationMethod's controller is not the DID that names it".to_string(),
        ));
    }
    Ok(method)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const DID: &str = "did:web:issuer.example";

    fn doc(v: serde_json::Value) -> Document {
        serde_json::from_value(v).expect("DID document")
    }

    fn method(id: &str, controller: &str) -> serde_json::Value {
        json!({ "id": id, "type": "Multikey", "controller": controller,
                "publicKeyMultibase": "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK" })
    }

    fn vm() -> String {
        format!("{DID}#key-1")
    }

    #[test]
    fn a_method_in_the_wrong_relationship_is_refused() {
        let d = doc(
            json!({ "id": DID, "verificationMethod": [method(&vm(), DID)],
                             "authentication": [vm()] }),
        );
        let err = authorised_method(&d, DID, &vm(), ProofPurpose::AssertionMethod).unwrap_err();
        assert!(
            err.to_string().contains("not listed under assertionMethod"),
            "{err}"
        );
        authorised_method(&d, DID, &vm(), ProofPurpose::Authentication).expect("listed");
    }

    #[test]
    fn a_key_agreement_key_is_never_a_signing_key() {
        let d = doc(
            json!({ "id": DID, "verificationMethod": [method(&vm(), DID)],
                             "keyAgreement": [vm()] }),
        );
        for p in ProofPurpose::ALL {
            assert!(authorised_method(&d, DID, &vm(), p).is_err(), "{p}");
        }
        assert!(ProofPurpose::parse("keyAgreement").is_err());
        assert!(ProofPurpose::parse("").is_err());
        assert!(ProofPurpose::parse("assertion").is_err());
    }

    #[test]
    fn a_method_of_another_did_is_refused() {
        // Embedded under the issuer's DID but controlled by someone else.
        let d =
            doc(json!({ "id": DID, "assertionMethod": [method(&vm(), "did:web:other.example")] }));
        let err = authorised_method(&d, DID, &vm(), ProofPurpose::AssertionMethod).unwrap_err();
        assert!(err.to_string().contains("controller"), "{err}");

        // A document that is not the DID's own.
        let d = doc(json!({ "id": "did:web:other.example",
                             "verificationMethod": [method(&vm(), DID)],
                             "assertionMethod": [vm()] }));
        let err = authorised_method(&d, DID, &vm(), ProofPurpose::AssertionMethod).unwrap_err();
        assert!(err.to_string().contains("document's id"), "{err}");

        // Another DID's key listed by the issuer.
        let other = "did:web:other.example#key-1";
        let d = doc(
            json!({ "id": DID, "verificationMethod": [method(other, "did:web:other.example")],
                             "assertionMethod": [other] }),
        );
        assert!(authorised_method(&d, DID, other, ProofPurpose::AssertionMethod).is_err());
    }

    #[test]
    fn a_relative_reference_resolves_against_the_document_id() {
        let d = doc(
            json!({ "id": DID, "verificationMethod": [method(&vm(), DID)],
                             "assertionMethod": ["#key-1"] }),
        );
        authorised_method(&d, DID, &vm(), ProofPurpose::AssertionMethod).expect("#key-1");
        let d = doc(
            json!({ "id": DID, "verificationMethod": [method(&vm(), DID)],
                             "assertionMethod": ["#key-2"] }),
        );
        assert!(authorised_method(&d, DID, &vm(), ProofPurpose::AssertionMethod).is_err());
    }

    #[test]
    fn an_embedded_method_counts_for_its_own_relationship() {
        let d = doc(json!({ "id": DID, "authentication": [method(&vm(), DID)] }));
        authorised_method(&d, DID, &vm(), ProofPurpose::Authentication).expect("embedded");
        assert!(authorised_method(&d, DID, &vm(), ProofPurpose::AssertionMethod).is_err());
    }

    #[test]
    fn a_did_key_names_only_its_own_key() {
        let id = "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";
        check_did_key_method(&format!("did:key:{id}#{id}")).expect("its own key");
        assert!(check_did_key_method(&format!("did:key:{id}#key-0")).is_err());
        assert!(check_did_key_method(&format!("did:key:{id}")).is_err());
    }

    #[test]
    fn refusals_carry_no_identifier() {
        let d = doc(json!({ "id": DID, "verificationMethod": [method(&vm(), DID)] }));
        let err = authorised_method(&d, DID, &vm(), ProofPurpose::AssertionMethod).unwrap_err();
        assert!(!err.to_string().contains(DID), "{err}");
    }
}
