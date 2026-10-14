//! An EUDI verifier identity's X.509 side (#1988).
//!
//! EUDI wallets accept a request object only from a relying party whose
//! **access certificate** chains to an Access CA on their trusted list; the
//! `client_id` is `x509_hash:<SHA-256 of that certificate>` and the request
//! carries the chain as `x5c`. The certificate's key is the identity's
//! VTA-minted P-256 key, cached here like a swiyu identity's.
//!
//! The VTC holds the key, so it writes the certificate signing request itself
//! ([`build_csr`]), signed by that key — the proof of possession a registrar
//! asks for. The operator takes it to their registrar and brings back the
//! issued chain, which [`check_chain`] accepts only if its leaf certifies this
//! key and each certificate is signed by the next.

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use vti_common::error::AppError;
use x509_parser::prelude::*;

use super::{LocalP256Signer, VerifierIdentityRecord};

/// Who the access certificate names. Only what an operator needs to put in a
/// request; the registrar decides what the certificate finally says.
#[derive(Debug, Clone, Default)]
pub struct CsrSubject {
    pub common_name: String,
    pub organization: Option<String>,
    /// The organisation's registered identifier (OID 2.5.4.97), e.g.
    /// `VATDE-123456789` — the field EUDI access certificates identify a
    /// relying party by.
    pub organization_identifier: Option<String>,
    /// ISO 3166-1 alpha-2.
    pub country: Option<String>,
    pub dns_names: Vec<String>,
}

/// The identity's public key as an uncompressed SEC1 point, from the JWK it
/// was installed with.
fn public_point(record: &VerifierIdentityRecord) -> Result<Vec<u8>, AppError> {
    let coord = |name: &str| -> Result<Vec<u8>, AppError> {
        let value = record
            .public_jwk
            .get(name)
            .and_then(|v| v.as_str())
            .ok_or_else(|| AppError::Internal(format!("verifier key JWK has no {name}")))?;
        URL_SAFE_NO_PAD
            .decode(value)
            .map_err(|e| AppError::Internal(format!("verifier key JWK {name}: {e}")))
    };
    let (x, y) = (coord("x")?, coord("y")?);
    if x.len() != 32 || y.len() != 32 {
        return Err(AppError::Internal("verifier key is not a P-256 key".into()));
    }
    let mut point = Vec::with_capacity(65);
    point.push(0x04);
    point.extend_from_slice(&x);
    point.extend_from_slice(&y);
    Ok(point)
}

/// The identity's key, as `rcgen` signs with it. X.509 carries ECDSA
/// signatures DER-encoded, where JWS carries `r || s`.
struct CsrKey {
    signer: LocalP256Signer,
    point: Vec<u8>,
}

impl rcgen::PublicKeyData for CsrKey {
    fn der_bytes(&self) -> &[u8] {
        &self.point
    }

    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        &rcgen::PKCS_ECDSA_P256_SHA256
    }
}

impl rcgen::SigningKey for CsrKey {
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        let raw = affinidi_crypto::p256::sign(&self.signer.private_key, msg)
            .map_err(|_| rcgen::Error::RemoteKeyError)?;
        ecdsa_signature_der(&raw).ok_or(rcgen::Error::RemoteKeyError)
    }
}

/// `r || s` (32 + 32 bytes) as the DER `ECDSA-Sig-Value` (RFC 3279 §2.2.3).
fn ecdsa_signature_der(raw: &[u8]) -> Option<Vec<u8>> {
    if raw.len() != 64 {
        return None;
    }
    fn integer(bytes: &[u8]) -> Vec<u8> {
        let first = bytes
            .iter()
            .position(|b| *b != 0)
            .unwrap_or(bytes.len() - 1);
        let bytes = &bytes[first..];
        let pad = bytes[0] & 0x80 != 0;
        let mut out = vec![0x02, (bytes.len() + usize::from(pad)) as u8];
        if pad {
            out.push(0);
        }
        out.extend_from_slice(bytes);
        out
    }
    let (r, s) = (integer(&raw[..32]), integer(&raw[32..]));
    let mut out = vec![0x30, (r.len() + s.len()) as u8];
    out.extend(r);
    out.extend(s);
    Some(out)
}

/// A PEM certificate signing request for the identity's key, signed by it.
pub fn build_csr(
    record: &VerifierIdentityRecord,
    subject: &CsrSubject,
) -> Result<String, AppError> {
    if subject.common_name.trim().is_empty() {
        return Err(AppError::Validation(
            "an access certificate request needs a common name".into(),
        ));
    }
    let key = CsrKey {
        signer: LocalP256Signer::from_record(record)?,
        point: public_point(record)?,
    };

    let mut params = rcgen::CertificateParams::default();
    let mut dn = rcgen::DistinguishedName::new();
    dn.push(rcgen::DnType::CommonName, subject.common_name.trim());
    if let Some(o) = &subject.organization {
        dn.push(rcgen::DnType::OrganizationName, o.as_str());
    }
    if let Some(id) = &subject.organization_identifier {
        dn.push(
            rcgen::DnType::CustomDnType(vec![2, 5, 4, 97]),
            rcgen::DnValue::Utf8String(id.clone()),
        );
    }
    if let Some(c) = &subject.country {
        if c.len() != 2 || !c.chars().all(|ch| ch.is_ascii_uppercase()) {
            return Err(AppError::Validation(format!(
                "country '{c}' must be an ISO 3166-1 alpha-2 code, e.g. DE"
            )));
        }
        dn.push(
            rcgen::DnType::CountryName,
            rcgen::DnValue::PrintableString(
                c.as_str()
                    .try_into()
                    .map_err(|e| AppError::Validation(format!("country: {e}")))?,
            ),
        );
    }
    params.distinguished_name = dn;
    for name in &subject.dns_names {
        params.subject_alt_names.push(rcgen::SanType::DnsName(
            name.as_str()
                .try_into()
                .map_err(|e| AppError::Validation(format!("DNS name '{name}': {e}")))?,
        ));
    }
    let csr = params
        .serialize_request(&key)
        .map_err(|e| AppError::Internal(format!("certificate signing request: {e}")))?;
    csr.pem()
        .map_err(|e| AppError::Internal(format!("certificate signing request PEM: {e}")))
}

/// An access certificate chain [`check_chain`] accepted.
#[derive(Debug)]
pub struct CheckedChain {
    /// Leaf first, standard base64 DER — the JAR's `x5c`. Never the trust
    /// anchor: a wallet holds that already, and HAIP keeps it out of `x5c`.
    pub x5c: Vec<String>,
    /// The leaf's subject, for the operator.
    pub subject: String,
    /// The leaf's `notAfter`, seconds since the epoch.
    pub not_after: i64,
    /// Whether a self-signed root at the end of the file was left out.
    pub dropped_root: bool,
}

/// Accept the chain the registrar issued for `record`'s key, from PEM.
///
/// Refused, naming why: no certificate; a leaf that certifies a different key,
/// is outside its validity window or may not sign; a certificate not signed
/// by the one after it; a chain that is only a self-signed certificate, which
/// no wallet's trusted list would admit.
pub fn check_chain(
    record: &VerifierIdentityRecord,
    pem: &[u8],
    now_unix: i64,
) -> Result<CheckedChain, AppError> {
    let invalid = |m: String| AppError::Validation(m);
    let blocks = Pem::iter_from_buffer(pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| invalid(format!("the chain is not PEM: {e}")))?;
    let blocks: Vec<_> = blocks
        .into_iter()
        .filter(|b| b.label == "CERTIFICATE")
        .collect();
    if blocks.is_empty() {
        return Err(invalid("the file holds no CERTIFICATE block".into()));
    }
    let certs = blocks
        .iter()
        .enumerate()
        .map(|(i, b)| {
            b.parse_x509()
                .map_err(|e| invalid(format!("certificate {}: {e}", i + 1)))
        })
        .collect::<Result<Vec<_>, _>>()?;

    let leaf = &certs[0];
    if leaf.public_key().subject_public_key.data.as_ref() != public_point(record)?.as_slice() {
        return Err(invalid(format!(
            "the first certificate ({}) does not certify verifier identity '{}''s key — \
             was it issued for the request `vtc oid4vp csr --identity {}` wrote?",
            leaf.subject(),
            record.id,
            record.id
        )));
    }
    let at = ASN1Time::from_timestamp(now_unix)
        .map_err(|e| AppError::Internal(format!("clock: {e}")))?;
    if !leaf.validity().is_valid_at(at) {
        return Err(invalid(format!(
            "the access certificate is valid from {} to {}, not now",
            leaf.validity().not_before,
            leaf.validity().not_after
        )));
    }
    if let Ok(Some(usage)) = leaf.key_usage()
        && !usage.value.digital_signature()
    {
        return Err(invalid(
            "the access certificate's key usage does not allow digitalSignature".into(),
        ));
    }
    for (i, pair) in certs.windows(2).enumerate() {
        let (child, parent) = (&pair[0], &pair[1]);
        if child.issuer() != parent.subject() {
            return Err(invalid(format!(
                "certificate {} is issued by {}, but certificate {} is {} — list the chain leaf \
                 first, each certificate followed by its issuer",
                i + 1,
                child.issuer(),
                i + 2,
                parent.subject()
            )));
        }
        child
            .verify_signature(Some(parent.public_key()))
            .map_err(|e| {
                invalid(format!(
                    "certificate {} is not signed by certificate {}: {e}",
                    i + 1,
                    i + 2
                ))
            })?;
    }

    let self_signed =
        |c: &X509Certificate| c.issuer() == c.subject() && c.verify_signature(None).is_ok();
    let last = certs.len() - 1;
    if last == 0 && self_signed(leaf) {
        return Err(invalid(
            "the certificate is self-signed; a wallet accepts an access certificate only through \
             the Access CA that issued it"
                .into(),
        ));
    }
    let dropped_root = last > 0 && self_signed(&certs[last]);
    let keep = if dropped_root { last } else { last + 1 };

    Ok(CheckedChain {
        x5c: blocks[..keep]
            .iter()
            .map(|b| STANDARD.encode(&b.contents))
            .collect(),
        subject: leaf.subject().to_string(),
        not_after: leaf.validity().not_after.timestamp(),
        dropped_root,
    })
}

/// A test registrar: a self-signed Access CA (its P-256 key from `ca_seed`)
/// and an access certificate it issues for `record`'s key. Returns
/// `(leaf PEM, CA PEM)`.
#[cfg(any(test, feature = "test-support"))]
pub fn issue_for_test(record: &VerifierIdentityRecord, ca_seed: u8) -> (String, String) {
    let (leaf, ca) = issue_for_test_with(record, ca_seed, &["vtc.example.org"]);
    (leaf.pem(), ca.pem())
}

/// [`issue_for_test`] for a leaf naming `dns_names` in its subject alternative
/// name — e.g. a credential issuer's host. Returns `(leaf, CA)`.
#[cfg(any(test, feature = "test-support"))]
pub fn issue_for_test_with(
    record: &VerifierIdentityRecord,
    ca_seed: u8,
    dns_names: &[&str],
) -> (rcgen::Certificate, rcgen::Certificate) {
    let key = |r: &VerifierIdentityRecord| CsrKey {
        signer: LocalP256Signer::from_record(r).expect("test key"),
        point: public_point(r).expect("test key"),
    };
    let ca_record = crate::test_support::oid4vp_test_identity("test-access-ca", ca_seed);
    let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("CA params");
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "Test Access CA");
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    // Without a crypto backend rcgen draws no serial number of its own.
    ca_params.serial_number = Some(rcgen::SerialNumber::from(u64::from(ca_seed) + 1));
    // Nor does it hash a key identifier: without one, every identifier is empty.
    ca_params.key_identifier_method = rcgen::KeyIdMethod::PreSpecified(vec![ca_seed; 20]);
    let ca_key = key(&ca_record);
    let ca = ca_params.self_signed(&ca_key).expect("CA certificate");
    let issuer = rcgen::Issuer::new(ca_params, ca_key);

    let mut leaf_params =
        rcgen::CertificateParams::new(dns_names.iter().map(|n| n.to_string()).collect::<Vec<_>>())
            .expect("leaf params");
    leaf_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "Example community verifier");
    leaf_params.serial_number = Some(rcgen::SerialNumber::from(0x1000 + u64::from(ca_seed)));
    // As a real one does: names its CA, which DCQL `trusted_authorities` reads.
    leaf_params.use_authority_key_identifier_extension = true;
    let leaf = leaf_params
        .signed_by(&key(record), &issuer)
        .expect("access certificate");
    (leaf, ca)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::oid4vp::VerifierKind;

    /// An EUDI identity with no certificate yet.
    pub(crate) fn eudi_record(seed: u8) -> VerifierIdentityRecord {
        let mut record = crate::oid4vp::tests::p256_record("eudi", seed);
        record.kind = VerifierKind::Eudi;
        record.did = None;
        record.kid = None;
        record
    }

    #[test]
    fn the_request_is_signed_by_the_identitys_key() {
        let record = eudi_record(0x41);
        let pem = build_csr(
            &record,
            &CsrSubject {
                common_name: "Example".into(),
                ..Default::default()
            },
        )
        .unwrap();
        let (_, block) = x509_parser::pem::parse_x509_pem(pem.as_bytes()).unwrap();
        let (_, csr) =
            x509_parser::certification_request::X509CertificationRequest::from_der(&block.contents)
                .unwrap();
        csr.verify_signature()
            .expect("proof of possession verifies");
        assert_eq!(
            csr.certification_request_info
                .subject_pki
                .subject_public_key
                .data
                .as_ref(),
            public_point(&record).unwrap().as_slice()
        );
    }

    #[test]
    fn an_issued_chain_is_accepted_without_its_root() {
        let record = eudi_record(0x41);
        let (leaf, ca) = issue_for_test(&record, 0x51);
        let now = chrono::Utc::now().timestamp();
        let checked = check_chain(&record, format!("{leaf}{ca}").as_bytes(), now).unwrap();
        assert!(checked.dropped_root);
        assert_eq!(checked.x5c.len(), 1, "the trust anchor stays out of x5c");
        assert!(checked.subject.contains("Example community verifier"));

        // The leaf alone is accepted too: the wallet holds the CA.
        let checked = check_chain(&record, leaf.as_bytes(), now).unwrap();
        assert!(!checked.dropped_root);

        let mut installed = record.clone();
        installed.x5c = Some(checked.x5c);
        let client_id = installed.client_id().unwrap();
        assert!(client_id.starts_with("x509_hash:"), "{client_id}");
    }

    #[test]
    fn a_chain_for_another_key_or_out_of_order_is_refused() {
        let record = eudi_record(0x41);
        let (leaf, ca) = issue_for_test(&record, 0x51);
        let now = chrono::Utc::now().timestamp();

        let other = eudi_record(0x42);
        let err = check_chain(&other, leaf.as_bytes(), now).unwrap_err();
        assert!(err.to_string().contains("does not certify"), "{err}");

        let err = check_chain(&record, format!("{ca}{leaf}").as_bytes(), now).unwrap_err();
        assert!(err.to_string().contains("does not certify"), "{err}");

        // A CA that did not issue the leaf, under the same name: the
        // signature, not the name, decides.
        let (_, other_ca) = issue_for_test(&eudi_record(0x43), 0x52);
        let err = check_chain(&record, format!("{leaf}{other_ca}").as_bytes(), now).unwrap_err();
        assert!(err.to_string().contains("not signed by"), "{err}");

        // A leaf followed by itself: a name that does not match.
        let err = check_chain(&record, format!("{leaf}{leaf}").as_bytes(), now).unwrap_err();
        assert!(err.to_string().contains("issued by"), "{err}");

        assert!(check_chain(&record, b"not pem", now).is_err());
    }

    #[test]
    fn an_expired_certificate_is_refused() {
        let record = eudi_record(0x41);
        let (leaf, _) = issue_for_test(&record, 0x51);
        // rcgen's default validity ends in 4096; read it as at year 5000.
        let err = check_chain(&record, leaf.as_bytes(), 95_617_584_000).unwrap_err();
        assert!(err.to_string().contains("not now"), "{err}");
    }

    /// `[oid4vp] x509_trust_anchors` loads every file it names, and a file
    /// that is missing or holds no certificate stops the boot.
    #[test]
    fn trust_anchor_files_load_or_stop_the_boot() {
        let dir = tempfile::tempdir().unwrap();
        let (_, ca) = issue_for_test(&eudi_record(0x41), 0x51);
        let good = dir.path().join("anchors.pem");
        std::fs::write(&good, &ca).unwrap();
        let empty = dir.path().join("empty.pem");
        std::fs::write(&empty, "").unwrap();

        let anchors = crate::server::load_x509_trust_anchors(std::slice::from_ref(&good)).unwrap();
        assert_eq!(anchors.len(), 1);
        assert!(crate::server::load_x509_trust_anchors(&[good.clone(), empty]).is_err());
        assert!(crate::server::load_x509_trust_anchors(&[dir.path().join("missing.pem")]).is_err());
        assert!(
            crate::server::load_x509_trust_anchors(&[])
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn signatures_are_der_encoded() {
        let der = ecdsa_signature_der(&[[0x80u8; 32], [0x01u8; 32]].concat()).unwrap();
        assert_eq!(&der[..4], &[0x30, 0x45, 0x02, 0x21]);
        assert_eq!(der[4], 0x00, "a high bit takes a leading zero");
        let der = ecdsa_signature_der(&[[0u8; 31].as_slice(), &[7], &[0x01; 32]].concat()).unwrap();
        assert_eq!(&der[2..5], &[0x02, 0x01, 0x07], "leading zeros are dropped");
        assert!(ecdsa_signature_der(&[0; 10]).is_none());
    }
}
