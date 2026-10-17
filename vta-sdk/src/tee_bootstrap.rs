//! TEE first-boot claim — the wire of `POST /bootstrap/request` (#2066).
//!
//! A fresh TEE VTA has no administrator. The operator minted a claim `did:key`
//! before the VTA existed (`pnm bootstrap claim-did create`) and delivered only
//! its public DID to the enclave as `tee.bootstrap_claim_did`. The claim is the
//! holder of that key asking the enclave to enrol **that same DID** as its
//! bootstrap administrator.
//!
//! The enclave mints nothing for the client. It writes an expiring, hand-off
//! marked ACL entry for the claim DID (VTI-CLT-010, VTI-CLT-014, VTI-CLT-017)
//! and answers with an attested acknowledgement that carries no key material:
//! the client's private key never leaves the client (VTI-CLT-001,
//! VTI-CLT-002). The client then authenticates as the claim DID, rolls the
//! entry over onto a long-term key it mints itself, and destroys the claim key
//! (VTI-CLT-034).
//!
//! # Wire version 2
//!
//! Version 1 sealed a VTA-minted admin key back to the claimant
//! (`SealedPayloadV1::AdminCredential`). Version 2 is a clean break: a VTA
//! speaking it refuses version 1, and a version-1 client cannot read its
//! answer.
//!
//! # What the claim signature binds
//!
//! `vti/bootstrap-claim/v2\0 ‖ client_ed25519_pub ‖ nonce ‖ utf8(vta_did)`.
//!
//! Version 1 covered only the key and the nonce. Version 2 adds the DID of the
//! VTA the claimant means to claim, and the enclave refuses a claim naming any
//! DID but its own. The attestation quote binds the claimant's key, the nonce
//! and the producer key (`SHA256(client ‖ nonce ‖ producer)`), unchanged from
//! version 1; together with the signature, a quote for this nonce from a
//! pinned enclave image says that enclave accepted a claim on *the DID the
//! claimant signed* — the image only quotes after checking that DID is its
//! own, and the claimant signed exactly one DID for this nonce. So a host that
//! rewrites `vtaDid` in the acknowledgement is caught by the comparison with
//! what was signed, and a claim captured on its way to one VTA cannot be
//! replayed against another.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64;
use serde::{Deserialize, Serialize};

use crate::sealed_transfer::{
    AssertionProof, AttestationQuoteAssertion, ProducerAssertion, SealedTransferError,
};

/// Wire version of the claim, the claim-info answer and the acknowledgement.
pub const CLAIM_VERSION: u8 = 2;

/// Domain tag of the version-2 claim signature. A new protocol takes a new tag
/// rather than a version parameter, so a version-1 signature can never verify
/// here, nor a version-2 one in any other Ed25519 signing context.
const CLAIM_SIGNATURE_DOMAIN: &[u8] = b"vti/bootstrap-claim/v2\0";

/// Bytes signed for [`FirstBootClaim::claim_signature`]:
/// `domain ‖ client_ed25519_pub ‖ nonce ‖ utf8(vta_did)`.
///
/// The key and the nonce have fixed lengths and the DID comes last, so the
/// encoding is unambiguous without a length prefix.
pub fn claim_signing_input(
    client_ed25519_pub: &[u8; 32],
    nonce: &[u8; 16],
    vta_did: &str,
) -> Vec<u8> {
    let mut input = Vec::with_capacity(CLAIM_SIGNATURE_DOMAIN.len() + 32 + 16 + vta_did.len());
    input.extend_from_slice(CLAIM_SIGNATURE_DOMAIN);
    input.extend_from_slice(client_ed25519_pub);
    input.extend_from_slice(nonce);
    input.extend_from_slice(vta_did.as_bytes());
    input
}

/// `POST /bootstrap/request` body: the claim. Carries no secret.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct FirstBootClaim {
    /// Wire version, [`CLAIM_VERSION`].
    pub version: u8,
    /// The claim `did:key` (Ed25519) — the DID the VTA is configured with as
    /// `tee.bootstrap_claim_did`, and the DID it enrols.
    pub client_did: String,
    /// The DID of the VTA being claimed. Signed; the VTA refuses a claim that
    /// names any DID but its own.
    pub vta_did: String,
    /// Random 16-byte nonce, base64url-no-pad. Committed to by the attestation
    /// quote.
    pub nonce: String,
    /// Optional operator label. Not signed; the VTA logs only a hash of it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// Ed25519 signature by `client_did` over [`claim_signing_input`],
    /// base64url-no-pad.
    pub claim_signature: String,
}

impl FirstBootClaim {
    /// Build a claim on `vta_did` by the key behind `client_ed25519_seed`.
    pub fn new_signed(
        client_ed25519_seed: &[u8; 32],
        vta_did: &str,
        nonce: [u8; 16],
        label: Option<String>,
    ) -> Self {
        use ed25519_dalek::Signer;

        let signing = ed25519_dalek::SigningKey::from_bytes(client_ed25519_seed);
        let public = signing.verifying_key().to_bytes();
        let signature = signing.sign(&claim_signing_input(&public, &nonce, vta_did));
        Self {
            version: CLAIM_VERSION,
            client_did: affinidi_crypto::did_key::ed25519_pub_to_did_key(&public),
            vta_did: vta_did.to_string(),
            nonce: BASE64.encode(nonce),
            label,
            claim_signature: BASE64.encode(signature.to_bytes()),
        }
    }

    /// Check the version, the encodings and the signature by `client_did`.
    ///
    /// Only the shape and the proof of possession: whether `client_did` is the
    /// configured claim DID and `vta_did` this VTA's own is the VTA's to check
    /// on the [`VerifiedFirstBootClaim`] this returns.
    pub fn verify(&self) -> Result<VerifiedFirstBootClaim, SealedTransferError> {
        if self.version != CLAIM_VERSION {
            return Err(SealedTransferError::UnsupportedVersion(self.version));
        }
        if !self.vta_did.starts_with("did:") {
            return Err(SealedTransferError::Wire("vtaDid must be a DID".into()));
        }
        let public = affinidi_crypto::did_key::did_key_to_ed25519_pub(&self.client_did)
            .map_err(|e| SealedTransferError::Wire(format!("clientDid: {e}")))?;
        let nonce: [u8; 16] = BASE64
            .decode(&self.nonce)
            .map_err(|e| SealedTransferError::Base64(e.to_string()))?
            .try_into()
            .map_err(|_| SealedTransferError::Wire("nonce must be 16 bytes".into()))?;
        let raw: [u8; 64] = BASE64
            .decode(&self.claim_signature)
            .map_err(|e| SealedTransferError::Base64(e.to_string()))?
            .try_into()
            .map_err(|_| SealedTransferError::Wire("claimSignature must be 64 bytes".into()))?;
        let key = ed25519_dalek::VerifyingKey::from_bytes(&public)
            .map_err(|e| SealedTransferError::Wire(format!("clientDid key: {e}")))?;
        key.verify_strict(
            &claim_signing_input(&public, &nonce, &self.vta_did),
            &ed25519_dalek::Signature::from_bytes(&raw),
        )
        .map_err(|_| SealedTransferError::Wire("claimSignature does not verify".into()))?;
        Ok(VerifiedFirstBootClaim {
            client_did: self.client_did.clone(),
            client_ed25519_pub: public,
            vta_did: self.vta_did.clone(),
            nonce,
            label: self.label.clone(),
        })
    }
}

/// A claim whose signature verified. Constructible only through
/// [`FirstBootClaim::verify`], so code that takes one cannot be handed an
/// unchecked claim.
#[derive(Debug, Clone)]
pub struct VerifiedFirstBootClaim {
    client_did: String,
    client_ed25519_pub: [u8; 32],
    vta_did: String,
    nonce: [u8; 16],
    label: Option<String>,
}

impl VerifiedFirstBootClaim {
    /// The claim DID, proven held by the signer.
    pub fn client_did(&self) -> &str {
        &self.client_did
    }
    /// The claim DID's Ed25519 public key.
    pub fn client_ed25519_pub(&self) -> &[u8; 32] {
        &self.client_ed25519_pub
    }
    /// The VTA DID the claimant signed.
    pub fn vta_did(&self) -> &str {
        &self.vta_did
    }
    /// The claim nonce.
    pub fn nonce(&self) -> &[u8; 16] {
        &self.nonce
    }
    /// The unsigned operator label.
    pub fn label(&self) -> Option<&str> {
        self.label.as_deref()
    }
}

/// `GET /bootstrap/request` answer: the DID a claim on this VTA must name.
///
/// Used by a client that reached the VTA by URL (`pnm bootstrap connect
/// --vta-url`) and so has no DID of its own to sign. It is the server's word,
/// and only that: what makes it safe to sign is that a pinned enclave image
/// refuses a claim naming a DID other than its own, so the acknowledgement of
/// a claim on this DID comes only from an enclave that holds it. It does not
/// pin *which* VTA answered — `--vta-did` does that.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct FirstBootClaimInfo {
    /// Wire version, [`CLAIM_VERSION`].
    pub version: u8,
    /// This VTA's DID.
    pub vta_did: String,
}

/// The attestation quote in a [`FirstBootAck`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct FirstBootAttestation {
    /// Vendor / format tag, e.g. `aws-nitro-v1`.
    pub format: String,
    /// Raw attestation document, base64url-no-pad.
    pub quote_b64: String,
}

/// `POST /bootstrap/request` answer: the enclave enrolled the claim DID.
///
/// Holds no key material (VTI-CLT-002) — there is nothing to seal, so it is
/// plain JSON rather than a sealed bundle, and there is no bundle digest to
/// pin. Its integrity anchor is the attestation quote, checked against a
/// pinned enclave image (`--expect-pcr0`), plus the claim signature's binding
/// of `vtaDid` (module docs).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct FirstBootAck {
    /// Wire version, [`CLAIM_VERSION`].
    pub version: u8,
    /// The VTA's DID — the one the claim named.
    pub vta_did: String,
    /// The DID now holding the bootstrap admin entry: the claim DID itself.
    pub admin_did: String,
    /// Unix-epoch seconds at which the bootstrap entry expires unless rolled
    /// over first. Informational: not covered by the quote.
    pub expires_at: u64,
    /// The enclave's per-request producer `did:key`, committed to by the quote.
    pub producer_did: String,
    /// The attestation quote over `SHA256(client ‖ nonce ‖ producer)`.
    pub attestation: FirstBootAttestation,
}

impl FirstBootAck {
    /// The quote as the [`ProducerAssertion`] the attestation verifier reads.
    pub fn producer_assertion(&self) -> ProducerAssertion {
        ProducerAssertion {
            producer_did: self.producer_did.clone(),
            proof: AssertionProof::Attested(AttestationQuoteAssertion {
                format: self.attestation.format.clone(),
                quote_b64: self.attestation.quote_b64.clone(),
            }),
        }
    }

    /// Check that this acknowledges `claim`: same version, same claim DID,
    /// same VTA DID, and a genuine Nitro quote binding the claim key and nonce.
    ///
    /// PCR pinning is the caller's next step, on the returned attestation
    /// (`check_pcrs`); without it any genuine enclave image could have
    /// answered.
    #[cfg(feature = "attest-verify")]
    pub fn verify(
        self,
        claim: &VerifiedFirstBootClaim,
    ) -> Result<VerifiedFirstBootAck, FirstBootAckError> {
        if self.version != CLAIM_VERSION {
            return Err(FirstBootAckError::Mismatch(format!(
                "acknowledgement version {} (expected {CLAIM_VERSION})",
                self.version
            )));
        }
        if self.admin_did != claim.client_did() {
            return Err(FirstBootAckError::Mismatch(format!(
                "acknowledgement enrols {} but the claim was for {}",
                self.admin_did,
                claim.client_did()
            )));
        }
        if self.vta_did != claim.vta_did() {
            return Err(FirstBootAckError::Mismatch(format!(
                "acknowledgement names VTA {} but the claim was signed for {}",
                self.vta_did,
                claim.vta_did()
            )));
        }
        let attestation = crate::attestation::verify_nitro_assertion(
            &self.producer_assertion(),
            claim.client_ed25519_pub(),
            claim.nonce(),
        )?;
        Ok(VerifiedFirstBootAck {
            ack: self,
            attestation,
        })
    }
}

/// Why a [`FirstBootAck`] does not acknowledge the claim it answers.
#[cfg(feature = "attest-verify")]
#[derive(Debug, thiserror::Error)]
pub enum FirstBootAckError {
    #[error("{0}")]
    Mismatch(String),
    #[error("attestation: {0}")]
    Attestation(#[from] crate::attestation::AttestationVerifyError),
}

/// An acknowledgement checked against its claim and a genuine quote.
#[cfg(feature = "attest-verify")]
#[derive(Debug)]
pub struct VerifiedFirstBootAck {
    ack: FirstBootAck,
    attestation: crate::attestation::VerifiedAttestation,
}

#[cfg(feature = "attest-verify")]
impl VerifiedFirstBootAck {
    /// The acknowledgement.
    pub fn ack(&self) -> &FirstBootAck {
        &self.ack
    }
    /// The verified quote, for PCR pinning and display.
    pub fn attestation(&self) -> &crate::attestation::VerifiedAttestation {
        &self.attestation
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sealed_transfer::generate_ed25519_keypair;

    const VTA: &str = "did:webvh:QmScid:vta.example.com";

    #[test]
    fn signed_claim_verifies_and_round_trips() {
        let (seed, public) = generate_ed25519_keypair();
        let claim = FirstBootClaim::new_signed(&seed, VTA, [7; 16], Some("ops".into()));
        let json = serde_json::to_value(&claim).unwrap();
        assert!(json.get("clientDid").is_some() && json.get("claimSignature").is_some());
        let back: FirstBootClaim = serde_json::from_value(json).unwrap();
        let verified = back.verify().unwrap();
        assert_eq!(verified.client_ed25519_pub(), &public);
        assert_eq!(verified.vta_did(), VTA);
        assert_eq!(verified.nonce(), &[7; 16]);
    }

    #[test]
    fn signature_binds_key_nonce_and_vta_did() {
        let (seed, _) = generate_ed25519_keypair();
        let signed = FirstBootClaim::new_signed(&seed, VTA, [7; 16], None);

        let mut other_vta = signed.clone();
        other_vta.vta_did = "did:webvh:QmOther:evil.example.com".into();
        assert!(other_vta.verify().is_err(), "the VTA DID is signed");

        let mut renonced = signed.clone();
        renonced.nonce = BASE64.encode([8u8; 16]);
        assert!(renonced.verify().is_err(), "the nonce is signed");

        let (_, other_pub) = generate_ed25519_keypair();
        let mut swapped = signed.clone();
        swapped.client_did = affinidi_crypto::did_key::ed25519_pub_to_did_key(&other_pub);
        assert!(swapped.verify().is_err(), "the key is the signer");

        let mut garbled = signed;
        garbled.claim_signature = "AAAA".into();
        assert!(garbled.verify().is_err());
    }

    /// A version-1 signature (`vti/bootstrap-claim/v1\0 ‖ pub ‖ nonce`) is not
    /// a version-2 one, even relabelled as version 2.
    #[test]
    fn version_one_signature_is_refused() {
        use ed25519_dalek::Signer;
        let (seed, public) = generate_ed25519_keypair();
        let nonce = [9u8; 16];
        let mut v1_input = b"vti/bootstrap-claim/v1\0".to_vec();
        v1_input.extend_from_slice(&public);
        v1_input.extend_from_slice(&nonce);
        let sig = ed25519_dalek::SigningKey::from_bytes(&seed).sign(&v1_input);
        let mut claim = FirstBootClaim::new_signed(&seed, VTA, nonce, None);
        claim.claim_signature = BASE64.encode(sig.to_bytes());
        assert!(claim.verify().is_err());

        let mut v1 = FirstBootClaim::new_signed(&seed, VTA, nonce, None);
        v1.version = 1;
        assert!(matches!(
            v1.verify(),
            Err(SealedTransferError::UnsupportedVersion(1))
        ));
    }

    #[test]
    fn unknown_members_are_refused() {
        let (seed, _) = generate_ed25519_keypair();
        let mut json =
            serde_json::to_value(FirstBootClaim::new_signed(&seed, VTA, [1; 16], None)).unwrap();
        json["requestedRole"] = "admin".into();
        assert!(serde_json::from_value::<FirstBootClaim>(json).is_err());
    }
}
