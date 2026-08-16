//! IACA trust anchors for ISO/IEC 18013-5 mdoc issuers.
//!
//! This is the answer to "which key do I trust to have issued this mdoc?" —
//! the one question mdoc answers differently from everything else in this
//! workspace.
//!
//! ## Why this module exists at all
//!
//! Every other credential format here names its issuer as a **DID**. Receiving
//! a Data-Integrity VC resolves `credential.issuer` through the DID resolver
//! and verifies against whatever key comes back; the VTA holds no list, nothing
//! expires, and there is no operator step. Trust is delegated to the DID method.
//!
//! An mdoc has no issuer DID. It carries an **X.509 chain** in the `issuerAuth`
//! COSE unprotected header (`x5chain`, label 33): a Document Signer certificate
//! issued by an Issuing Authority Certificate Authority (IACA). Verifying it
//! means the VTA must *already hold* the set of roots it accepts. That is not a
//! lookup, it is a trust store — an operational object with a lifecycle.
//!
//! So this module exists because mdoc forces a decision the rest of the stack
//! never had to make. The decision taken is: **a configured set of IACA root
//! certificates**, which is how production EUDI verifiers work and what Member
//! State trusted lists (ETSI TS 119 612) distribute. It keeps X.509 at the
//! boundary — nothing below this module learns that certificates exist, and
//! [`crate::receive::receive_mdoc`] still takes a plain resolved key.
//!
//! ## Scope of validation
//!
//! ISO 18013-5 Annex B specifies a **two-level** hierarchy: IACA root →
//! Document Signer. There is no intermediate tier, so this does not need — and
//! deliberately does not implement — general RFC 5280 path building. It checks:
//!
//! 1. the leaf's issuer DN matches a configured anchor's subject DN;
//! 2. the leaf's signature verifies against that anchor's public key;
//! 3. the leaf is inside its validity window *now*;
//! 4. the anchor is a CA (`basicConstraints`), so a leaf certificate configured
//!    by mistake cannot act as a root;
//! 5. the leaf permits signing (`keyUsage.digitalSignature`) where the
//!    extension is present.
//!
//! **Not checked, deliberately:** certificate revocation (CRL/OCSP), which
//! needs network egress and a policy for what to do when it is unavailable —
//! a decision with its own operational weight, and one an mdoc's short validity
//! window partly mitigates. Also not checked: the ISO mDL Extended Key Usage
//! OID `1.0.18013.5.1.2`. The EUDI PID profile does not share it, so enforcing
//! it would reject valid PID credentials — a false rejection that looks exactly
//! like a trust failure and would be miserable to debug.
//!
//! ## Fail closed
//!
//! An empty anchor set is an error, not "accept anything". A deployment that
//! has not configured trust anchors cannot receive mdocs at all, which is the
//! safe direction for a check whose entire purpose is deciding what to trust.

use chrono::{DateTime, Utc};
use vti_common::error::AppError;
use x509_parser::prelude::*;

/// COSE header label carrying an X.509 certificate chain (RFC 9360 §2).
const COSE_HEADER_X5CHAIN: i64 = 33;

/// A configured IACA root certificate.
#[derive(Debug)]
struct Anchor {
    /// Raw DER of the subject DN, compared byte-for-byte against a leaf's
    /// issuer DN. Byte comparison rather than string formatting: DN string
    /// rendering is not canonical, and two DNs that print identically can
    /// differ in encoding (and vice versa).
    subject_der: Vec<u8>,
    /// The certificate's own DER, re-parsed on demand. Held as bytes because
    /// `X509Certificate` borrows from its input and cannot be stored alongside
    /// it without self-reference.
    der: Vec<u8>,
}

/// The set of IACA roots this VTA will accept mdoc issuers under.
///
/// Build once at startup from configuration; cheap to share.
#[derive(Debug)]
pub struct IacaTrustAnchors {
    anchors: Vec<Anchor>,
}

impl IacaTrustAnchors {
    /// Parse a set of PEM-encoded IACA root certificates.
    ///
    /// Each entry may contain one or more `CERTIFICATE` blocks, so an operator
    /// can paste a bundle as a single value.
    ///
    /// Rejects a certificate that is not a CA: a Document Signer certificate
    /// configured here by mistake would otherwise silently become a root,
    /// trusting every credential that DS ever signs.
    pub fn from_pem(pems: &[String]) -> Result<Self, AppError> {
        let mut anchors = Vec::new();

        for (i, pem_text) in pems.iter().enumerate() {
            let mut rest = pem_text.as_bytes();
            let mut found = 0usize;

            while let Ok((remaining, pem)) = x509_parser::pem::parse_x509_pem(rest) {
                if pem.label != "CERTIFICATE" {
                    rest = remaining;
                    continue;
                }
                let cert = pem.parse_x509().map_err(|e| {
                    AppError::Validation(format!("IACA trust anchor {i} is not a valid X.509: {e}"))
                })?;

                let is_ca = cert
                    .basic_constraints()
                    .ok()
                    .flatten()
                    .map(|bc| bc.value.ca)
                    .unwrap_or(false);
                if !is_ca {
                    return Err(AppError::Validation(format!(
                        "IACA trust anchor {i} ({}) is not a CA certificate — a Document \
                         Signer certificate cannot be used as a trust anchor",
                        cert.subject()
                    )));
                }

                anchors.push(Anchor {
                    subject_der: cert.subject().as_raw().to_vec(),
                    der: pem.contents.clone(),
                });
                found += 1;
                rest = remaining;
            }

            if found == 0 {
                return Err(AppError::Validation(format!(
                    "IACA trust anchor {i} contained no PEM CERTIFICATE block"
                )));
            }
        }

        Ok(Self { anchors })
    }

    /// True when no anchors are configured — mdoc receive is unavailable.
    pub fn is_empty(&self) -> bool {
        self.anchors.is_empty()
    }

    /// Resolve the Document Signer public key for an mdoc, if and only if its
    /// `x5chain` leaf chains to a configured IACA root.
    ///
    /// Returns the SEC1-encoded EC point, which is what
    /// [`crate::receive::receive_mdoc`] takes as its `issuer_pub`.
    ///
    /// `now` is injected rather than read from the clock so the validity check
    /// is testable, matching the rest of the receive path.
    pub fn resolve_issuer_key(
        &self,
        issuer_auth: &coset::CoseSign1,
        now: DateTime<Utc>,
    ) -> Result<Vec<u8>, AppError> {
        if self.anchors.is_empty() {
            return Err(AppError::Validation(
                "no IACA trust anchors are configured, so no mdoc issuer can be trusted"
                    .to_string(),
            ));
        }

        let leaf_der = extract_leaf_certificate(issuer_auth)?;
        let (_, leaf) = X509Certificate::from_der(&leaf_der).map_err(|e| {
            AppError::Validation(format!("mdoc x5chain leaf is not a valid X.509: {e}"))
        })?;

        // Validity window, before any signature work — an expired DS is a
        // cheaper and more specific rejection than a failed chain.
        let now_asn1 = ASN1Time::from_timestamp(now.timestamp())
            .map_err(|e| AppError::Internal(format!("clock conversion: {e}")))?;
        if !leaf.validity().is_valid_at(now_asn1) {
            return Err(AppError::Validation(format!(
                "mdoc Document Signer certificate is not valid at {} (validity {} .. {})",
                now.to_rfc3339(),
                leaf.validity().not_before,
                leaf.validity().not_after
            )));
        }

        // The leaf must be permitted to sign, where it says so at all.
        if let Ok(Some(ku)) = leaf.key_usage()
            && !ku.value.digital_signature()
        {
            return Err(AppError::Validation(
                "mdoc Document Signer certificate does not permit digitalSignature".to_string(),
            ));
        }

        // Find the anchor that claims to have issued this leaf, then make it
        // prove it. Matching on DN alone establishes nothing — the signature
        // check below is what actually decides.
        let issuer_dn = leaf.issuer().as_raw();
        let mut candidates = 0usize;
        for anchor in &self.anchors {
            if anchor.subject_der != issuer_dn {
                continue;
            }
            candidates += 1;

            let (_, root) = X509Certificate::from_der(&anchor.der).map_err(|e| {
                AppError::Internal(format!("configured IACA anchor failed to re-parse: {e}"))
            })?;

            if leaf.verify_signature(Some(root.public_key())).is_ok() {
                // SEC1 point, uncompressed — what `Es256CoseVerifier` expects.
                return Ok(leaf.public_key().subject_public_key.data.to_vec());
            }
        }

        Err(AppError::Validation(if candidates == 0 {
            format!(
                "mdoc Document Signer was issued by `{}`, which is not a configured IACA \
                 trust anchor",
                leaf.issuer()
            )
        } else {
            format!(
                "mdoc Document Signer claims issuer `{}` but its signature does not verify \
                 against the configured anchor for that name",
                leaf.issuer()
            )
        }))
    }
}

/// Pull the leaf (Document Signer) certificate out of an `issuerAuth`'s
/// `x5chain` header.
///
/// Per RFC 9360 the value is a single `bstr` when the chain has one
/// certificate, and an array of `bstr` otherwise — with the **leaf first**.
/// Both shapes appear in practice, so both are accepted.
fn extract_leaf_certificate(issuer_auth: &coset::CoseSign1) -> Result<Vec<u8>, AppError> {
    let entry = issuer_auth
        .unprotected
        .rest
        .iter()
        .find(|(label, _)| matches!(label, coset::Label::Int(COSE_HEADER_X5CHAIN)))
        .map(|(_, value)| value)
        .ok_or_else(|| {
            AppError::Validation(
                "mdoc issuerAuth carries no x5chain, so its issuer cannot be established"
                    .to_string(),
            )
        })?;

    match entry {
        coset::cbor::Value::Bytes(der) => Ok(der.clone()),
        coset::cbor::Value::Array(certs) => match certs.first() {
            Some(coset::cbor::Value::Bytes(der)) => Ok(der.clone()),
            Some(other) => Err(AppError::Validation(format!(
                "mdoc x5chain entries must be byte strings, got {other:?}"
            ))),
            None => Err(AppError::Validation(
                "mdoc x5chain is an empty array".to_string(),
            )),
        },
        other => Err(AppError::Validation(format!(
            "mdoc x5chain must be a byte string or an array of them, got {other:?}"
        ))),
    }
}

/// Extract the MSO `deviceKey` as a **compressed SEC1 point** (33 bytes).
///
/// This is the holder-binding key an mdoc is issued to: only its private half
/// can sign `DeviceAuth`, so a VTA that does not hold it can never present the
/// credential with holder binding. Returning the compressed encoding is
/// deliberate — it is the form the VTA stores its own P-256 public keys in
/// (`to_encoded_point(true)` + multicodec `p256-pub`), so the caller can compare
/// without re-deriving either side.
///
/// Lives here rather than in the caller because it reads mdoc internals; the
/// *matching* stays with the caller, which is the layer that can see the VTA's
/// keyspace.
pub fn mdoc_device_key_sec1(
    mso: &affinidi_mdoc::MobileSecurityObject,
) -> Result<Vec<u8>, AppError> {
    let cose =
        affinidi_mdoc::CoseKey::from_cbor_value(&mso.device_key_info.device_key).map_err(|e| {
            AppError::Validation(format!("mdoc deviceKey is not a valid COSE_Key: {e}"))
        })?;

    if !matches!(cose.crv, affinidi_mdoc::Curve::P256) {
        return Err(AppError::Validation(format!(
            "mdoc deviceKey must be P-256 (ISO 18013-5 / EUDI); got {:?}",
            cose.crv
        )));
    }

    let x = &cose.x;
    let y = cose
        .y
        .as_ref()
        .ok_or_else(|| AppError::Validation("mdoc deviceKey has no Y coordinate".to_string()))?;
    if x.len() != 32 || y.len() != 32 {
        return Err(AppError::Validation(format!(
            "mdoc deviceKey coordinates must be 32 bytes each; got x={} y={}",
            x.len(),
            y.len()
        )));
    }

    // SEC1 compressed: 0x02 for an even Y, 0x03 for odd, then X.
    let prefix = if y[31] & 1 == 0 { 0x02u8 } else { 0x03u8 };
    let mut point = Vec::with_capacity(33);
    point.push(prefix);
    point.extend_from_slice(x);
    Ok(point)
}

#[cfg(test)]
mod tests {
    use super::*;
    use affinidi_mdoc::es256_cose::Es256CoseSigner;
    use affinidi_mdoc::mso::ValidityInfo;
    use coset::CoseSign1;
    use rcgen::{
        BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose,
        PKCS_ECDSA_P256_SHA256,
    };

    /// A generated IACA root plus the material to issue Document Signers under it.
    struct Iaca {
        pem: String,
        params: CertificateParams,
        key: KeyPair,
    }

    fn iaca(common_name: &str) -> Iaca {
        let mut params = CertificateParams::new(vec![]).unwrap();
        params
            .distinguished_name
            .push(DnType::CommonName, common_name);
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let cert = params.clone().self_signed(&key).unwrap();
        Iaca {
            pem: cert.pem(),
            params,
            key,
        }
    }

    /// Issue a Document Signer certificate under `root`, returning its DER.
    fn document_signer(root: &Iaca, common_name: &str) -> (Vec<u8>, KeyPair) {
        let mut params = CertificateParams::new(vec![]).unwrap();
        params
            .distinguished_name
            .push(DnType::CommonName, common_name);
        params.is_ca = IsCa::NoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        let ds_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let issuer = root.params.clone().self_signed(&root.key).unwrap();
        let cert = params.signed_by(&ds_key, &issuer, &root.key).unwrap();
        (cert.der().to_vec(), ds_key)
    }

    /// Build an `issuerAuth` COSE_Sign1 carrying `chain` as its x5chain. The
    /// signature itself is irrelevant here — this module decides *which key* to
    /// trust, not whether the MSO signature is good (that is `receive_mdoc`).
    fn issuer_auth_with_chain(chain: Vec<Vec<u8>>) -> CoseSign1 {
        let signer = Es256CoseSigner::generate();
        let mso = affinidi_mdoc::MdocBuilder::new("eu.europa.ec.eudi.pid.1")
            .validity(ValidityInfo {
                signed: "2026-01-01T00:00:00Z".into(),
                valid_from: "2026-01-01T00:00:00Z".into(),
                valid_until: "2036-01-01T00:00:00Z".into(),
            })
            .build(&signer)
            .unwrap();
        let mut sign1 = mso.issuer_auth;
        sign1
            .unprotected
            .rest
            .retain(|(l, _)| !matches!(l, coset::Label::Int(x) if *x == COSE_HEADER_X5CHAIN));
        let value = if chain.len() == 1 {
            coset::cbor::Value::Bytes(chain[0].clone())
        } else {
            coset::cbor::Value::Array(chain.into_iter().map(coset::cbor::Value::Bytes).collect())
        };
        sign1
            .unprotected
            .rest
            .push((coset::Label::Int(COSE_HEADER_X5CHAIN), value));
        sign1
    }

    fn now() -> DateTime<Utc> {
        Utc::now()
    }

    #[test]
    fn a_document_signer_under_a_configured_root_resolves() {
        let root = iaca("Test IACA");
        let (ds_der, _) = document_signer(&root, "Test Document Signer");
        let anchors = IacaTrustAnchors::from_pem(std::slice::from_ref(&root.pem)).unwrap();

        let key = anchors
            .resolve_issuer_key(&issuer_auth_with_chain(vec![ds_der]), now())
            .expect("a DS issued by the configured root must resolve");
        assert!(!key.is_empty(), "an EC point should come back");
    }

    /// The core negative: a well-formed DS from a CA we do not trust. This is
    /// the attack the whole module exists to stop.
    #[test]
    fn a_document_signer_under_an_unconfigured_root_is_refused() {
        let trusted = iaca("Trusted IACA");
        let rogue = iaca("Rogue IACA");
        let (rogue_ds, _) = document_signer(&rogue, "Rogue Document Signer");
        let anchors = IacaTrustAnchors::from_pem(std::slice::from_ref(&trusted.pem)).unwrap();

        let err = anchors
            .resolve_issuer_key(&issuer_auth_with_chain(vec![rogue_ds]), now())
            .unwrap_err();
        assert!(
            matches!(&err, AppError::Validation(m) if m.contains("not a configured IACA")),
            "{err:?}"
        );
    }

    /// Name collision must not be enough. A rogue CA that gives itself the same
    /// subject DN as a trusted root gets past the DN match and must still fail
    /// on the signature — proving the DN lookup is an index, not a decision.
    #[test]
    fn a_matching_issuer_name_without_a_matching_signature_is_refused() {
        let trusted = iaca("Shared Name IACA");
        let impostor = iaca("Shared Name IACA");
        let (impostor_ds, _) = document_signer(&impostor, "Impostor DS");
        let anchors = IacaTrustAnchors::from_pem(std::slice::from_ref(&trusted.pem)).unwrap();

        let err = anchors
            .resolve_issuer_key(&issuer_auth_with_chain(vec![impostor_ds]), now())
            .unwrap_err();
        assert!(
            matches!(&err, AppError::Validation(m) if m.contains("does not verify")),
            "a DN match must not be sufficient; got {err:?}"
        );
    }

    #[test]
    fn an_empty_anchor_set_fails_closed() {
        let root = iaca("Test IACA");
        let (ds_der, _) = document_signer(&root, "DS");
        let anchors = IacaTrustAnchors::from_pem(&[]).unwrap();
        assert!(anchors.is_empty());

        let err = anchors
            .resolve_issuer_key(&issuer_auth_with_chain(vec![ds_der]), now())
            .unwrap_err();
        assert!(
            matches!(&err, AppError::Validation(m) if m.contains("no IACA trust anchors")),
            "an unconfigured deployment must refuse, not accept everything; got {err:?}"
        );
    }

    /// A Document Signer certificate configured as a root would silently trust
    /// everything that DS ever signs.
    #[test]
    fn a_non_ca_certificate_is_refused_as_an_anchor() {
        let root = iaca("Test IACA");
        let (ds_der, _) = document_signer(&root, "Not A CA");
        let ds_pem = pem_wrap(&ds_der);

        let err = IacaTrustAnchors::from_pem(&[ds_pem]).unwrap_err();
        assert!(
            matches!(&err, AppError::Validation(m) if m.contains("not a CA certificate")),
            "{err:?}"
        );
    }

    #[test]
    fn an_issuer_auth_without_an_x5chain_is_refused() {
        let root = iaca("Test IACA");
        let anchors = IacaTrustAnchors::from_pem(std::slice::from_ref(&root.pem)).unwrap();

        let signer = Es256CoseSigner::generate();
        let mso = affinidi_mdoc::MdocBuilder::new("eu.europa.ec.eudi.pid.1")
            .validity(ValidityInfo {
                signed: "2026-01-01T00:00:00Z".into(),
                valid_from: "2026-01-01T00:00:00Z".into(),
                valid_until: "2036-01-01T00:00:00Z".into(),
            })
            .build(&signer)
            .unwrap();

        let err = anchors
            .resolve_issuer_key(&mso.issuer_auth, now())
            .unwrap_err();
        assert!(
            matches!(&err, AppError::Validation(m) if m.contains("no x5chain")),
            "{err:?}"
        );
    }

    /// RFC 9360 allows a bare `bstr` for a single certificate and an array
    /// otherwise, leaf first. Both must work — a peer picks one and we do not
    /// get to choose.
    #[test]
    fn both_x5chain_encodings_are_accepted() {
        let root = iaca("Test IACA");
        let (ds_der, _) = document_signer(&root, "DS");
        let anchors = IacaTrustAnchors::from_pem(std::slice::from_ref(&root.pem)).unwrap();

        let single = anchors
            .resolve_issuer_key(&issuer_auth_with_chain(vec![ds_der.clone()]), now())
            .expect("bare bstr");
        // Leaf first, root appended — the array form.
        let root_der = pem_to_der(&root.pem);
        let array = anchors
            .resolve_issuer_key(&issuer_auth_with_chain(vec![ds_der, root_der]), now())
            .expect("array form");
        assert_eq!(single, array, "both encodings must yield the same DS key");
    }

    #[test]
    fn a_bundle_of_several_roots_in_one_value_parses() {
        let a = iaca("IACA A");
        let b = iaca("IACA B");
        let bundle = format!("{}{}", a.pem, b.pem);
        let anchors = IacaTrustAnchors::from_pem(&[bundle]).unwrap();

        // A DS under either root resolves.
        for root in [&a, &b] {
            let (ds, _) = document_signer(root, "DS");
            anchors
                .resolve_issuer_key(&issuer_auth_with_chain(vec![ds]), now())
                .expect("each root in the bundle must be usable");
        }
    }

    #[test]
    fn a_value_with_no_certificate_block_is_refused() {
        let err = IacaTrustAnchors::from_pem(&["not a pem".to_string()]).unwrap_err();
        assert!(
            matches!(&err, AppError::Validation(m) if m.contains("no PEM CERTIFICATE block")),
            "{err:?}"
        );
    }

    // ── helpers ──────────────────────────────────────────────────────

    fn pem_wrap(der: &[u8]) -> String {
        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD.encode(der);
        let body = b64
            .as_bytes()
            .chunks(64)
            .map(|c| String::from_utf8_lossy(c).to_string())
            .collect::<Vec<_>>()
            .join("\n");
        format!("-----BEGIN CERTIFICATE-----\n{body}\n-----END CERTIFICATE-----\n")
    }

    fn pem_to_der(pem: &str) -> Vec<u8> {
        let (_, parsed) = x509_parser::pem::parse_x509_pem(pem.as_bytes()).unwrap();
        parsed.contents
    }
}
