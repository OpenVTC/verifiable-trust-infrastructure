//! Credential issuers known by an X.509 certificate chain instead of a DID
//! (#1988).
//!
//! An EUDI credential — the PID, or one a Rulebook governs — is signed by a key
//! certified in an `x5c` chain to a trust anchor, and its `iss` is an `https`
//! URL, not a DID. Such an issuer is trusted only through anchors the verifier
//! configured: [`x5c_issuer_key`] returns the leaf's key only if the chain ends
//! at one of them, every certificate in it is valid now, each is signed by the
//! next, every certificate above the leaf is a CA, the leaf may sign, and the
//! leaf names `iss` in its subject alternative name (an equal `URI`, or a
//! `dNSName` equal to its host) — SD-JWT VC's binding of a certificate to the
//! issuer it speaks for.
//!
//! A verifier with no anchors trusts no certificate-named issuer, as a
//! verifier with no DID resolver trusts no DID it cannot resolve.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde_json::Value;
use x509_parser::prelude::*;

use crate::jws::{JwsError, JwsKey};
use crate::trust_task_proof::{ProofPurpose, PurposeVmResolver};

/// The longest `x5c` accepted, leaf included.
const MAX_CHAIN: usize = 8;

/// Certificates a verifier trusts to certify credential issuers, as DER.
#[derive(Debug, Clone, Default)]
pub struct X509TrustAnchors {
    certs: Vec<Vec<u8>>,
}

impl X509TrustAnchors {
    /// No anchors: no certificate-named issuer is trusted.
    pub fn new() -> Self {
        Self::default()
    }

    /// Every `CERTIFICATE` block of a PEM file. A file with none, or a block
    /// that does not parse as a certificate, is refused — an anchor file that
    /// silently loads nothing would fail every credential it was meant to
    /// admit, or none of them if it were later "fixed" in place.
    pub fn from_pem(pem: &[u8]) -> Result<Self, JwsError> {
        let mut anchors = Self::new();
        anchors.add_pem(pem)?;
        Ok(anchors)
    }

    /// Add every `CERTIFICATE` block of a PEM file (see [`Self::from_pem`]).
    pub fn add_pem(&mut self, pem: &[u8]) -> Result<usize, JwsError> {
        let mut added = 0;
        for block in Pem::iter_from_buffer(pem) {
            let block = block
                .map_err(|e| JwsError::Issuer(format!("trust anchor file is not PEM: {e}")))?;
            if block.label != "CERTIFICATE" {
                continue;
            }
            block
                .parse_x509()
                .map_err(|e| JwsError::Issuer(format!("trust anchor certificate: {e}")))?;
            self.certs.push(block.contents);
            added += 1;
        }
        if added == 0 {
            return Err(JwsError::Issuer(
                "trust anchor file holds no CERTIFICATE block".into(),
            ));
        }
        Ok(added)
    }

    pub fn len(&self) -> usize {
        self.certs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.certs.is_empty()
    }
}

fn refused(m: impl Into<String>) -> JwsError {
    JwsError::Issuer(m.into())
}

/// Whether a JWS header names its key by an `x5c` chain.
pub fn names_key_by_x5c(header: &Value) -> bool {
    header.get("x5c").is_some()
}

/// The key of the certificate that signs for `iss`, from the JWS header's
/// `x5c`, trusted only through `anchors` — see the module docs.
pub fn x5c_issuer_key(
    header: &Value,
    iss: &str,
    anchors: &X509TrustAnchors,
    now_unix: i64,
) -> Result<JwsKey, JwsError> {
    if anchors.is_empty() {
        return Err(refused(format!(
            "issuer `{iss}` is named by a certificate chain, and no X.509 trust anchors are \
             configured"
        )));
    }
    let ders = header
        .get("x5c")
        .and_then(Value::as_array)
        .filter(|c| !c.is_empty() && c.len() <= MAX_CHAIN)
        .ok_or_else(|| refused(format!("`x5c` must hold 1 to {MAX_CHAIN} certificates")))?
        .iter()
        .map(|c| {
            c.as_str()
                .and_then(|s| STANDARD.decode(s).ok())
                .ok_or_else(|| refused("an `x5c` entry is not base64 DER"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let chain = ders
        .iter()
        .map(|der| {
            X509Certificate::from_der(der)
                .map(|(_, c)| c)
                .map_err(|e| refused(format!("an `x5c` certificate does not parse: {e}")))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let anchor_certs = anchors
        .certs
        .iter()
        .filter_map(|der| X509Certificate::from_der(der).ok().map(|(_, c)| c))
        .collect::<Vec<_>>();
    let at = ASN1Time::from_timestamp(now_unix).map_err(|e| refused(format!("clock: {e}")))?;

    for (i, cert) in chain.iter().enumerate() {
        if !cert.validity().is_valid_at(at) {
            return Err(refused(format!(
                "`x5c` certificate {} ({}) is not valid now",
                i + 1,
                cert.subject()
            )));
        }
        if i > 0 && !is_ca(cert) {
            return Err(refused(format!(
                "`x5c` certificate {} ({}) certifies another but is not a CA",
                i + 1,
                cert.subject()
            )));
        }
    }
    for (i, pair) in chain.windows(2).enumerate() {
        let (child, parent) = (&pair[0], &pair[1]);
        if child.issuer() != parent.subject()
            || child.verify_signature(Some(parent.public_key())).is_err()
        {
            return Err(refused(format!(
                "`x5c` certificate {} is not issued by certificate {}",
                i + 1,
                i + 2
            )));
        }
    }

    // The chain ends at an anchor, or at a certificate an anchor signed.
    let last_index = chain.len() - 1;
    let last = &chain[last_index];
    let anchored = anchors.certs.iter().any(|a| *a == ders[last_index])
        || anchor_certs.iter().any(|a| {
            a.validity().is_valid_at(at)
                && last.issuer() == a.subject()
                && last.verify_signature(Some(a.public_key())).is_ok()
        });
    if !anchored {
        return Err(refused(format!(
            "issuer `{iss}`'s certificate chain does not end at a configured trust anchor"
        )));
    }

    let leaf = &chain[0];
    if is_ca(leaf) && chain.len() > 1 {
        return Err(refused("the `x5c` leaf is a CA certificate"));
    }
    if let Ok(Some(usage)) = leaf.key_usage()
        && !usage.value.digital_signature()
    {
        return Err(refused(
            "the `x5c` leaf's key usage does not allow digitalSignature",
        ));
    }
    if !leaf_names_issuer(leaf, iss) {
        return Err(refused(format!(
            "the `x5c` leaf ({}) does not name issuer `{iss}` in its subject alternative name",
            leaf.subject()
        )));
    }
    spki_key(leaf.public_key())
}

fn is_ca(cert: &X509Certificate) -> bool {
    matches!(cert.basic_constraints(), Ok(Some(bc)) if bc.value.ca)
}

/// SD-JWT VC's binding of an `x5c` leaf to `iss`: an `https` issuer named by a
/// SAN `URI` equal to it, or a SAN `dNSName` equal to its host.
fn leaf_names_issuer(leaf: &X509Certificate, iss: &str) -> bool {
    let Ok(url) = url::Url::parse(iss) else {
        return false;
    };
    if url.scheme() != "https" {
        return false;
    }
    let Some(host) = url.host_str() else {
        return false;
    };
    let Ok(Some(san)) = leaf.subject_alternative_name() else {
        return false;
    };
    san.value.general_names.iter().any(|name| match name {
        GeneralName::URI(uri) => *uri == iss,
        GeneralName::DNSName(dns) => dns.eq_ignore_ascii_case(host),
        _ => false,
    })
}

/// A certificate's subject key as a [`JwsKey`]: P-256, secp256k1 or Ed25519.
fn spki_key(spki: &SubjectPublicKeyInfo) -> Result<JwsKey, JwsError> {
    const EC_PUBLIC_KEY: &str = "1.2.840.10045.2.1";
    const P256: &str = "1.2.840.10045.3.1.7";
    const SECP256K1: &str = "1.3.132.0.10";
    const ED25519: &str = "1.3.101.112";
    let point = spki.subject_public_key.data.as_ref();
    let algorithm = spki.algorithm.algorithm.to_id_string();
    if algorithm == ED25519 {
        let key: [u8; 32] = point
            .try_into()
            .map_err(|_| JwsError::Key("Ed25519 certificate key is not 32 bytes".into()))?;
        return Ok(JwsKey::Ed25519(key));
    }
    if algorithm != EC_PUBLIC_KEY {
        return Err(JwsError::Key(format!(
            "the certificate's key ({algorithm}) is not one a JWS verifies with here"
        )));
    }
    let curve = spki
        .algorithm
        .parameters
        .as_ref()
        .and_then(|p| p.as_oid().ok())
        .map(|oid| oid.to_id_string());
    match curve.as_deref() {
        Some(P256) => Ok(JwsKey::P256(crate::jws::compress_sec1(point, "P-256")?)),
        Some(SECP256K1) => Ok(JwsKey::Secp256k1(crate::jws::compress_sec1(
            point,
            "secp256k1",
        )?)),
        other => Err(JwsError::Key(format!(
            "the certificate's curve ({}) is not one a JWS verifies with here",
            other.unwrap_or("unnamed")
        ))),
    }
}

/// The key that verifies an issuer's JWS (a credential, or its status list):
/// a DID issuer's verification method, resolved for `assertionMethod`
/// ([`crate::jws::sd_jwt_issuer_method`]), or — for an issuer that is not a
/// DID — the `x5c` leaf's key, trusted through `anchors` ([`x5c_issuer_key`]).
pub async fn issuer_jws_key(
    header: &Value,
    iss: &str,
    resolver: &(dyn PurposeVmResolver + '_),
    anchors: &X509TrustAnchors,
    now_unix: i64,
) -> Result<JwsKey, JwsError> {
    if !iss.starts_with("did:") && names_key_by_x5c(header) {
        return x5c_issuer_key(header, iss, anchors, now_unix);
    }
    let method = crate::jws::sd_jwt_issuer_method(header, iss)?;
    let resolved = resolver
        .resolve_vm_for_purpose(&method, ProofPurpose::AssertionMethod)
        .await
        .map_err(|e| JwsError::Key(e.to_string()))?;
    JwsKey::from_resolved(&resolved)
}

/// Test fixtures: a CA and leaves it issues, built with `rcgen`.
#[cfg(test)]
pub(crate) mod test_chain {
    use super::*;

    pub struct Ca {
        pub pem: String,
        pub der: Vec<u8>,
        issuer: rcgen::Issuer<'static, rcgen::KeyPair>,
    }

    pub fn ca(name: &str) -> Ca {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, name);
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let cert = params.self_signed(&key).unwrap();
        Ca {
            pem: cert.pem(),
            der: cert.der().to_vec(),
            issuer: rcgen::Issuer::new(params, key),
        }
    }

    /// A leaf for `sans` (DNS names, or `https://` URIs) under `ca`: its DER
    /// and the key that signs with it.
    pub fn leaf(ca: &Ca, sans: &[&str], is_ca: bool) -> (Vec<u8>, rcgen::KeyPair) {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "Test issuer");
        for san in sans {
            params
                .subject_alt_names
                .push(if san.starts_with("https://") {
                    rcgen::SanType::URI((*san).try_into().unwrap())
                } else {
                    rcgen::SanType::DnsName((*san).try_into().unwrap())
                });
        }
        if is_ca {
            params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        }
        let cert = params.signed_by(&key, &ca.issuer).unwrap();
        (cert.der().to_vec(), key)
    }

    /// A compact ES256 JWS signed by an `rcgen` key: its DER `ECDSA-Sig-Value`
    /// re-encoded as JWS's `r || s`.
    pub fn sign_jws(key: &rcgen::KeyPair, header: &Value, payload: &Value) -> String {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use rcgen::SigningKey as _;
        let encode = |v: &Value| URL_SAFE_NO_PAD.encode(serde_json::to_vec(v).unwrap());
        let input = format!("{}.{}", encode(header), encode(payload));
        let der = key.sign(input.as_bytes()).unwrap();
        // SEQUENCE { INTEGER r, INTEGER s }, each short-form length.
        let mut raw = Vec::with_capacity(64);
        let mut at = 2;
        for _ in 0..2 {
            let len = der[at + 1] as usize;
            let int = &der[at + 2..at + 2 + len];
            let int = &int[int.len().saturating_sub(32)..];
            raw.extend(std::iter::repeat_n(0u8, 32 - int.len()));
            raw.extend_from_slice(int);
            at += 2 + len;
        }
        format!("{input}.{}", URL_SAFE_NO_PAD.encode(raw))
    }

    pub fn header(chain: &[&[u8]]) -> Value {
        serde_json::json!({
            "alg": "ES256",
            "x5c": chain.iter().map(|d| STANDARD.encode(d)).collect::<Vec<_>>(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::test_chain::*;
    use super::*;

    const ISS: &str = "https://pid.example.org/issuer";

    fn now() -> i64 {
        chrono::Utc::now().timestamp()
    }

    #[test]
    fn a_chain_to_an_anchor_yields_the_leafs_key() {
        let ca = ca("Test PID CA");
        let (leaf, key) = leaf(&ca, &["pid.example.org"], false);
        let anchors = X509TrustAnchors::from_pem(ca.pem.as_bytes()).unwrap();

        let got = x5c_issuer_key(&header(&[&leaf]), ISS, &anchors, now()).unwrap();
        let JwsKey::P256(point) = got else {
            panic!("a P-256 key")
        };
        let expected = crate::jws::compress_sec1(key.public_key_raw(), "P-256").unwrap();
        assert_eq!(point, expected);

        // The anchor may also travel in the chain.
        x5c_issuer_key(&header(&[&leaf, &ca.der]), ISS, &anchors, now()).unwrap();
        // A SAN URI equal to `iss` binds it too.
        let (by_uri, _) = leaf_for(&ca, ISS);
        x5c_issuer_key(&header(&[&by_uri]), ISS, &anchors, now()).unwrap();
    }

    fn leaf_for(ca: &Ca, san: &str) -> (Vec<u8>, rcgen::KeyPair) {
        leaf(ca, &[san], false)
    }

    #[test]
    fn a_chain_to_no_anchor_or_with_no_anchors_is_refused() {
        let ca1 = ca("Test PID CA");
        let other = ca("Another CA");
        let (leaf, _) = leaf(&ca1, &["pid.example.org"], false);
        let anchors = X509TrustAnchors::from_pem(other.pem.as_bytes()).unwrap();
        let err = x5c_issuer_key(&header(&[&leaf]), ISS, &anchors, now()).unwrap_err();
        assert!(err.to_string().contains("trust anchor"), "{err}");

        let err =
            x5c_issuer_key(&header(&[&leaf]), ISS, &X509TrustAnchors::new(), now()).unwrap_err();
        assert!(err.to_string().contains("no X.509 trust anchors"), "{err}");
    }

    #[test]
    fn the_leaf_must_name_the_issuer() {
        let ca = ca("Test PID CA");
        let anchors = X509TrustAnchors::from_pem(ca.pem.as_bytes()).unwrap();
        let (leaf, _) = leaf(&ca, &["other.example.org"], false);
        let err = x5c_issuer_key(&header(&[&leaf]), ISS, &anchors, now()).unwrap_err();
        assert!(err.to_string().contains("does not name issuer"), "{err}");

        let (leaf, _) = leaf_for(&ca, "pid.example.org");
        let err = x5c_issuer_key(&header(&[&leaf]), "http://pid.example.org", &anchors, now())
            .unwrap_err();
        assert!(err.to_string().contains("does not name issuer"), "{err}");
    }

    #[test]
    fn an_expired_chain_or_a_ca_leaf_is_refused() {
        let ca = ca("Test PID CA");
        let anchors = X509TrustAnchors::from_pem(ca.pem.as_bytes()).unwrap();
        let (leaf_der, _) = leaf(&ca, &["pid.example.org"], false);
        // rcgen's certificates run to 4096; read them in the year 5000.
        let err = x5c_issuer_key(&header(&[&leaf_der]), ISS, &anchors, 95_617_584_000).unwrap_err();
        assert!(err.to_string().contains("not valid now"), "{err}");

        // A CA signing as the leaf of a longer chain.
        let (ca_leaf, _) = leaf(&ca, &["pid.example.org"], true);
        let err = x5c_issuer_key(&header(&[&ca_leaf, &ca.der]), ISS, &anchors, now()).unwrap_err();
        assert!(err.to_string().contains("CA certificate"), "{err}");
    }

    #[test]
    fn a_chain_out_of_order_is_refused() {
        let ca = ca("Test PID CA");
        let anchors = X509TrustAnchors::from_pem(ca.pem.as_bytes()).unwrap();
        let (leaf, _) = leaf(&ca, &["pid.example.org"], false);
        let err = x5c_issuer_key(&header(&[&ca.der, &leaf]), ISS, &anchors, now()).unwrap_err();
        assert!(err.to_string().contains("not a CA"), "{err}");
        assert!(x5c_issuer_key(&serde_json::json!({ "x5c": [] }), ISS, &anchors, now()).is_err());
        assert!(
            x5c_issuer_key(&serde_json::json!({ "x5c": ["***"] }), ISS, &anchors, now()).is_err()
        );
    }

    #[test]
    fn an_anchor_file_with_no_certificate_is_refused() {
        assert!(X509TrustAnchors::from_pem(b"").is_err());
        assert!(X509TrustAnchors::from_pem(b"not pem").is_err());
        let mut anchors = X509TrustAnchors::new();
        assert_eq!(anchors.add_pem(ca("a").pem.as_bytes()).unwrap(), 1);
        assert_eq!(anchors.len(), 1);
    }
}
