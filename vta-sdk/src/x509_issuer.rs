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
//! The path is validated as RFC 5280 §6 requires of the parts it delegates to
//! a CA, every certification authority on it — the anchor it ends at included
//! (#2618):
//!
//! - **`pathLenConstraint`**: no more CA certificates below a CA than it
//!   allows.
//! - **`keyUsage`**: a CA that states its key usage must allow `keyCertSign`.
//! - **`nameConstraints`**: the leaf's `dNSName` and `URI` names (which bind
//!   `iss`) must lie inside every CA's permitted subtrees and outside its
//!   excluded ones. A `dNSName` constraint is applied to a `URI`'s host too, so
//!   a sub-CA constrained by DNS name cannot certify an issuer URL outside it.
//!   A constraint of a form not evaluated here (`directoryName`, `iPAddress`,
//!   `rfc822Name`, …) that could apply to the leaf refuses the chain.
//! - **Critical extensions**: one not processed here refuses the certificate,
//!   and so does any extension that does not parse — a check that cannot be
//!   read is a check that failed.
//! - **Signatures**: SHA-1 signatures are refused.
//!
//! Revocation (CRL, OCSP) is not checked: an anchor's PKI withdraws a
//! certificate here only by expiry, or by the operator removing the anchor.
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
    x5c_issuer(header, iss, anchors, now_unix).map(|issuer| issuer.key)
}

/// An issuer known by an `x5c` chain that [`x5c_issuer`] accepted.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct X5cIssuer {
    /// The leaf's key, which signs for the issuer.
    pub key: JwsKey,
    /// The key identifiers of the certification authorities above the leaf:
    /// each certificate's `authorityKeyIdentifier`, the `subjectKeyIdentifier`
    /// of each certificate above the leaf, and that of the anchor the chain
    /// ends at. What a DCQL `trusted_authorities` entry of type `aki` names
    /// (OpenID4VP 1.0 §6.1.1).
    pub authority_key_ids: Vec<Vec<u8>>,
}

/// [`x5c_issuer_key`], also returning the key identifiers of the authorities
/// that certify the issuer.
pub fn x5c_issuer(
    header: &Value,
    iss: &str,
    anchors: &X509TrustAnchors,
    now_unix: i64,
) -> Result<X5cIssuer, JwsError> {
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
        check_extensions(cert, &format!("`x5c` certificate {}", i + 1))?;
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
        if child.issuer() != parent.subject() || !issued_by(child, parent) {
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
    let signing_anchor = anchor_certs.iter().find(|a| {
        a.validity().is_valid_at(at) && last.issuer() == a.subject() && issued_by(last, a)
    });
    let anchored = anchors.certs.iter().any(|a| *a == ders[last_index]) || signing_anchor.is_some();
    if !anchored {
        return Err(refused(format!(
            "issuer `{iss}`'s certificate chain does not end at a configured trust anchor"
        )));
    }

    let leaf = &chain[0];
    if is_ca(leaf) && chain.len() > 1 {
        return Err(refused("the `x5c` leaf is a CA certificate"));
    }
    match leaf.key_usage() {
        Ok(Some(usage)) if !usage.value.digital_signature() => {
            return Err(refused(
                "the `x5c` leaf's key usage does not allow digitalSignature",
            ));
        }
        Ok(_) => {}
        Err(e) => return Err(refused(format!("the `x5c` leaf's key usage: {e}"))),
    }

    // What each certification authority on the path delegates (RFC 5280 §6):
    // the chain's CAs, where `cas_below` is how many CA certificates sit
    // between it and the leaf, then the anchor the chain ends at when it is
    // not carried in it.
    if let Some(anchor) = signing_anchor {
        check_extensions(anchor, "the trust anchor")?;
    }
    let authorities = chain
        .iter()
        .enumerate()
        .skip(1)
        .map(|(i, c)| (c, i - 1, format!("`x5c` certificate {}", i + 1)))
        .chain(signing_anchor.map(|a| (a, chain.len() - 1, "the trust anchor".to_string())));
    for (ca, cas_below, what) in authorities {
        check_authority(ca, cas_below, leaf, &what)?;
    }
    if !leaf_names_issuer(leaf, iss) {
        return Err(refused(format!(
            "the `x5c` leaf ({}) does not name issuer `{iss}` in its subject alternative name",
            leaf.subject()
        )));
    }
    let mut authority_key_ids: Vec<Vec<u8>> = Vec::new();
    for (i, cert) in chain.iter().chain(signing_anchor).enumerate() {
        for ext in cert.extensions() {
            let id = match ext.parsed_extension() {
                ParsedExtension::AuthorityKeyIdentifier(aki) => aki.key_identifier.as_ref(),
                // The leaf's own key is the issuer's, not an authority's.
                ParsedExtension::SubjectKeyIdentifier(ski) if i > 0 => Some(ski),
                _ => None,
            };
            if let Some(id) = id
                && !authority_key_ids.iter().any(|known| known == id.0)
            {
                authority_key_ids.push(id.0.to_vec());
            }
        }
    }
    Ok(X5cIssuer {
        key: spki_key(leaf.public_key())?,
        authority_key_ids,
    })
}

fn is_ca(cert: &X509Certificate) -> bool {
    matches!(cert.basic_constraints(), Ok(Some(bc)) if bc.value.ca)
}

/// `sha1WithRSAEncryption` and its OIW alias: `x509-parser` verifies these
/// (down to 1024-bit keys) for legacy use; a credential issuer's path does not
/// get to rest on them.
const SHA1_SIGNATURES: &[&str] = &["1.2.840.113549.1.1.5", "1.3.14.3.2.29"];

/// Whether `parent`'s key signed `child`, by an algorithm accepted here.
fn issued_by(child: &X509Certificate, parent: &X509Certificate) -> bool {
    let algorithm = child.signature_algorithm.algorithm.to_id_string();
    !SHA1_SIGNATURES.contains(&algorithm.as_str())
        && child.verify_signature(Some(parent.public_key())).is_ok()
}

/// Extensions this module processes, and so may be critical (RFC 5280
/// §4.2: a certificate with a critical extension the verifier does not
/// recognise or cannot process must be rejected).
const PROCESSED_EXTENSIONS: &[&str] = &[
    "2.5.29.14", // subjectKeyIdentifier
    "2.5.29.15", // keyUsage
    "2.5.29.17", // subjectAltName
    "2.5.29.19", // basicConstraints
    "2.5.29.30", // nameConstraints
    "2.5.29.35", // authorityKeyIdentifier
    "2.5.29.37", // extKeyUsage — no purpose is asked of the leaf here
];

/// Refuse a certificate carrying an extension that does not parse, one this
/// module relies on twice over, or a critical one it does not process.
fn check_extensions(cert: &X509Certificate, what: &str) -> Result<(), JwsError> {
    for ext in cert.extensions() {
        let oid = ext.oid.to_id_string();
        if let ParsedExtension::ParseError { error } = ext.parsed_extension() {
            return Err(refused(format!(
                "{what} ({}): extension {oid} does not parse: {error}",
                cert.subject()
            )));
        }
        if ext.critical && !PROCESSED_EXTENSIONS.contains(&oid.as_str()) {
            return Err(refused(format!(
                "{what} ({}) carries critical extension {oid}, which is not processed here",
                cert.subject()
            )));
        }
    }
    // Each errs on a duplicated extension.
    let unreadable = |e: X509Error| refused(format!("{what} ({}): {e}", cert.subject()));
    cert.basic_constraints().map_err(unreadable)?;
    cert.key_usage().map_err(unreadable)?;
    cert.name_constraints().map_err(unreadable)?;
    cert.subject_alternative_name().map_err(unreadable)?;
    cert.extended_key_usage().map_err(unreadable)?;
    Ok(())
}

/// What a certification authority delegates, held against the path below it:
/// `cas_below` CA certificates between it and `leaf`.
fn check_authority(
    ca: &X509Certificate,
    cas_below: usize,
    leaf: &X509Certificate,
    what: &str,
) -> Result<(), JwsError> {
    let subject = ca.subject();
    if let Ok(Some(bc)) = ca.basic_constraints()
        && let Some(max) = bc.value.path_len_constraint
        && cas_below > max as usize
    {
        return Err(refused(format!(
            "{what} ({subject}) allows {max} CA certificate(s) below it, and the chain has              {cas_below}"
        )));
    }
    if let Ok(Some(usage)) = ca.key_usage()
        && !usage.value.key_cert_sign()
    {
        return Err(refused(format!(
            "{what} ({subject}) certifies another certificate, but its key usage does not              allow keyCertSign"
        )));
    }
    if let Ok(Some(nc)) = ca.name_constraints() {
        check_name_constraints(&nc.value, leaf)
            .map_err(|m| refused(format!("{what} ({subject}): {m}")))?;
    }
    Ok(())
}

/// The leaf against one CA's `nameConstraints` (RFC 5280 §4.2.1.10).
fn check_name_constraints(nc: &NameConstraints, leaf: &X509Certificate) -> Result<(), String> {
    let permitted = nc.permitted_subtrees.as_deref().unwrap_or_default();
    let excluded = nc.excluded_subtrees.as_deref().unwrap_or_default();
    let all = || permitted.iter().chain(excluded);
    // A subject name is always present; a constraint on it is not evaluated.
    if all().any(|t| matches!(t.base, GeneralName::DirectoryName(_))) {
        return Err("directoryName name constraints are not evaluated here".into());
    }
    let sans = leaf
        .subject_alternative_name()
        .map_err(|e| format!("the leaf's subject alternative name: {e}"))?
        .map(|san| san.value.general_names.clone())
        .unwrap_or_default();
    for name in &sans {
        match name {
            GeneralName::DNSName(dns) => {
                // `dNSName` subtrees, against a DNS name.
                check_subtrees(permitted, excluded, dns, |base| match base {
                    GeneralName::DNSName(c) => Some(dns_within(dns, c)),
                    _ => None,
                })?;
            }
            GeneralName::URI(uri) => {
                let host = url::Url::parse(uri)
                    .ok()
                    .and_then(|u| u.host_str().map(str::to_string))
                    .ok_or_else(|| format!("the leaf's URI name {uri} names no host"))?;
                // `uniformResourceIdentifier` subtrees by their rule, and
                // `dNSName` subtrees against the host as well.
                check_subtrees(permitted, excluded, uri, |base| match base {
                    GeneralName::URI(c) => Some(uri_host_within(&host, c)),
                    _ => None,
                })?;
                check_subtrees(permitted, excluded, uri, |base| match base {
                    GeneralName::DNSName(c) => Some(dns_within(&host, c)),
                    _ => None,
                })?;
            }
            other => {
                // A name of another form, under a constraint of that form,
                // is one this cannot evaluate.
                let same_form = |t: &&GeneralSubtree| {
                    std::mem::discriminant(&t.base) == std::mem::discriminant(other)
                };
                if all().any(|t| same_form(&t)) {
                    return Err(format!(
                        "a name constraint applies to the leaf's name {other:?}, of a form                          not evaluated here"
                    ));
                }
            }
        }
    }
    Ok(())
}

/// One name against the subtrees `within` reads (it answers `None` for a
/// subtree of another form): inside a permitted one of its form when there are
/// any, and inside no excluded one.
fn check_subtrees(
    permitted: &[GeneralSubtree],
    excluded: &[GeneralSubtree],
    name: &str,
    within: impl Fn(&GeneralName) -> Option<bool>,
) -> Result<(), String> {
    let mut of_form = permitted.iter().filter_map(|t| within(&t.base)).peekable();
    if of_form.peek().is_some() && !of_form.any(|inside| inside) {
        return Err(format!(
            "the leaf's name {name} is outside the permitted names"
        ));
    }
    if excluded.iter().any(|t| within(&t.base) == Some(true)) {
        return Err(format!("the leaf's name {name} is an excluded name"));
    }
    Ok(())
}

/// RFC 5280 §4.2.1.10 `dNSName`: the constraint itself, or the constraint with
/// labels added on the left. A leading `.` admits subdomains only; an empty
/// constraint admits every name.
fn dns_within(name: &str, constraint: &str) -> bool {
    let name = name.trim_end_matches('.').to_ascii_lowercase();
    let constraint = constraint.trim_end_matches('.').to_ascii_lowercase();
    if constraint.is_empty() {
        return true;
    }
    if constraint.starts_with('.') {
        return name.ends_with(&constraint);
    }
    name == constraint || name.ends_with(&format!(".{constraint}"))
}

/// RFC 5280 §4.2.1.10 `uniformResourceIdentifier`: a constraint without a
/// leading `.` is a host, matched exactly; with one, every host below it.
fn uri_host_within(host: &str, constraint: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    let constraint = constraint.trim_end_matches('.').to_ascii_lowercase();
    if constraint.starts_with('.') {
        host.ends_with(&constraint)
    } else {
        host == constraint
    }
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

/// The subject key of one DER certificate, checking nothing else about it — no
/// validity, no chain, no trust. For a custodian asked to put the certificate
/// into a JWS header beside a key it holds (`keys/sign-jws`'s `x5c` rule),
/// which needs only to know whose key it certifies.
pub fn certificate_key(der: &[u8]) -> Result<JwsKey, JwsError> {
    let (rest, cert) = X509Certificate::from_der(der)
        .map_err(|e| JwsError::Key(format!("not a DER certificate: {e}")))?;
    if !rest.is_empty() {
        return Err(JwsError::Key(
            "trailing bytes after the DER certificate".into(),
        ));
    }
    spki_key(cert.public_key())
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
        pub issuer: rcgen::Issuer<'static, rcgen::KeyPair>,
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

    /// An intermediate CA under `ca`.
    pub fn intermediate(ca: &Ca, name: &str) -> Ca {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, name);
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.use_authority_key_identifier_extension = true;
        let cert = params.signed_by(&key, &ca.issuer).unwrap();
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
        // Either way it carries a subjectKeyIdentifier, as a real one does.
        params.is_ca = if is_ca {
            rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained)
        } else {
            rcgen::IsCa::ExplicitNoCa
        };
        params.use_authority_key_identifier_extension = true;
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

    fn subject_key_id(der: &[u8]) -> Vec<u8> {
        let (_, cert) = X509Certificate::from_der(der).unwrap();
        cert.extensions()
            .iter()
            .find_map(|e| match e.parsed_extension() {
                ParsedExtension::SubjectKeyIdentifier(ski) => Some(ski.0.to_vec()),
                _ => None,
            })
            .expect("a subjectKeyIdentifier")
    }

    #[test]
    fn the_authorities_are_the_cas_above_the_leaf_never_the_leaf() {
        let ca = ca("Test PID CA");
        let (direct, _) = leaf(&ca, &["pid.example.org"], false);
        let anchors = X509TrustAnchors::from_pem(ca.pem.as_bytes()).unwrap();
        let ca_id = subject_key_id(&ca.der);

        // The anchor reached by signature, and the one carried in the chain.
        for chain in [
            vec![direct.as_slice()],
            vec![direct.as_slice(), ca.der.as_slice()],
        ] {
            let got = x5c_issuer(&header(&chain), ISS, &anchors, now()).unwrap();
            assert_eq!(got.authority_key_ids, vec![ca_id.clone()]);
        }

        // An intermediate: its own identifier and the root's, never the leaf's.
        let mid = intermediate(&ca, "Test PID intermediate");
        let (leaf2, _) = leaf(&mid, &["pid.example.org"], false);
        let got = x5c_issuer(&header(&[&leaf2, &mid.der]), ISS, &anchors, now()).unwrap();
        assert_eq!(got.authority_key_ids, vec![subject_key_id(&mid.der), ca_id]);
        assert!(!got.authority_key_ids.contains(&subject_key_id(&leaf2)));
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

    // ── #2618: what a CA delegates ─────────────────────────────────────────

    /// A CA under `parent` (self-signed when `None`) shaped by `shape`.
    fn ca_with(
        parent: Option<&Ca>,
        name: &str,
        shape: impl FnOnce(&mut rcgen::CertificateParams),
    ) -> Ca {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, name);
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.use_authority_key_identifier_extension = parent.is_some();
        shape(&mut params);
        let cert = match parent {
            Some(p) => params.signed_by(&key, &p.issuer).unwrap(),
            None => params.self_signed(&key).unwrap(),
        };
        Ca {
            pem: cert.pem(),
            der: cert.der().to_vec(),
            issuer: rcgen::Issuer::new(params, key),
        }
    }

    fn anchors_of(ca: &Ca) -> X509TrustAnchors {
        X509TrustAnchors::from_pem(ca.pem.as_bytes()).unwrap()
    }

    fn dns_subtrees(names: &[&str]) -> Vec<rcgen::GeneralSubtree> {
        names
            .iter()
            .map(|n| rcgen::GeneralSubtree::DnsName((*n).to_string()))
            .collect()
    }

    #[test]
    fn issue_2618_a_constrained_sub_ca_cannot_certify_a_name_outside_its_subtree() {
        let root = ca("Test root");
        let sub = ca_with(Some(&root), "Constrained sub-CA", |p| {
            p.name_constraints = Some(rcgen::NameConstraints {
                permitted_subtrees: dns_subtrees(&["pid.example.org"]),
                excluded_subtrees: dns_subtrees(&["bad.pid.example.org"]),
            });
        });
        let anchors = anchors_of(&root);

        // Inside: the host itself, and a name below it.
        let (ok, _) = leaf(&sub, &["pid.example.org"], false);
        x5c_issuer_key(&header(&[&ok, &sub.der]), ISS, &anchors, now()).unwrap();
        let (deeper, _) = leaf(&sub, &["a.pid.example.org"], false);
        x5c_issuer_key(
            &header(&[&deeper, &sub.der]),
            "https://a.pid.example.org/i",
            &anchors,
            now(),
        )
        .unwrap();

        // Outside the permitted subtree, by DNS name and by URI host.
        let (evil, _) = leaf(&sub, &["evil.example.com"], false);
        let err = x5c_issuer_key(
            &header(&[&evil, &sub.der]),
            "https://evil.example.com",
            &anchors,
            now(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("outside the permitted"), "{err}");
        let (evil_uri, _) = leaf(&sub, &["https://evil.example.com/issuer"], false);
        let err = x5c_issuer_key(
            &header(&[&evil_uri, &sub.der]),
            "https://evil.example.com/issuer",
            &anchors,
            now(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("outside the permitted"), "{err}");

        // Inside the permitted subtree but excluded.
        let (excluded, _) = leaf(&sub, &["bad.pid.example.org"], false);
        let err = x5c_issuer_key(
            &header(&[&excluded, &sub.der]),
            "https://bad.pid.example.org",
            &anchors,
            now(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("excluded"), "{err}");
    }

    #[test]
    fn issue_2618_an_anchors_own_name_constraints_hold() {
        let root = ca_with(None, "Constrained root", |p| {
            p.name_constraints = Some(rcgen::NameConstraints {
                permitted_subtrees: dns_subtrees(&["example.net"]),
                excluded_subtrees: Vec::new(),
            });
        });
        let (leaf_der, _) = leaf(&root, &["pid.example.org"], false);
        let err =
            x5c_issuer_key(&header(&[&leaf_der]), ISS, &anchors_of(&root), now()).unwrap_err();
        assert!(err.to_string().contains("the trust anchor"), "{err}");
    }

    #[test]
    fn issue_2618_a_path_longer_than_a_cas_path_length_is_refused() {
        let root = ca_with(None, "Root, pathLen 0", |p| {
            p.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Constrained(0));
        });
        let anchors = anchors_of(&root);
        // Directly under the root: no CA below it.
        let (direct, _) = leaf(&root, &["pid.example.org"], false);
        x5c_issuer_key(&header(&[&direct]), ISS, &anchors, now()).unwrap();
        // One intermediate below a pathLen 0 root.
        let mid = intermediate(&root, "Intermediate");
        let (under_mid, _) = leaf(&mid, &["pid.example.org"], false);
        let err =
            x5c_issuer_key(&header(&[&under_mid, &mid.der]), ISS, &anchors, now()).unwrap_err();
        assert!(err.to_string().contains("allows 0 CA"), "{err}");

        // And within the chain itself: a pathLen 0 intermediate over another.
        let root = ca("Root");
        let mid0 = ca_with(Some(&root), "pathLen 0", |p| {
            p.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Constrained(0));
        });
        let below = intermediate(&mid0, "Below a pathLen 0 CA");
        let (l, _) = leaf(&below, &["pid.example.org"], false);
        let err = x5c_issuer_key(
            &header(&[&l, &below.der, &mid0.der]),
            ISS,
            &anchors_of(&root),
            now(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("allows 0 CA"), "{err}");
    }

    #[test]
    fn issue_2618_a_ca_whose_key_usage_lacks_key_cert_sign_is_refused() {
        let root = ca("Root");
        let mid = ca_with(Some(&root), "No keyCertSign", |p| {
            p.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
        });
        let (l, _) = leaf(&mid, &["pid.example.org"], false);
        let err =
            x5c_issuer_key(&header(&[&l, &mid.der]), ISS, &anchors_of(&root), now()).unwrap_err();
        assert!(err.to_string().contains("keyCertSign"), "{err}");

        let mid = ca_with(Some(&root), "With keyCertSign", |p| {
            p.key_usages = vec![
                rcgen::KeyUsagePurpose::KeyCertSign,
                rcgen::KeyUsagePurpose::CrlSign,
            ];
        });
        let (l, _) = leaf(&mid, &["pid.example.org"], false);
        x5c_issuer_key(&header(&[&l, &mid.der]), ISS, &anchors_of(&root), now()).unwrap();
    }

    #[test]
    fn issue_2618_an_unprocessed_critical_extension_is_refused() {
        let root = ca("Root");
        let mid = ca_with(Some(&root), "Critical unknown", |p| {
            let mut ext = rcgen::CustomExtension::from_oid_content(
                &[1, 3, 6, 1, 4, 1, 99999, 1],
                vec![0x05, 0x00],
            );
            ext.set_criticality(true);
            p.custom_extensions.push(ext);
        });
        let (l, _) = leaf(&mid, &["pid.example.org"], false);
        let err =
            x5c_issuer_key(&header(&[&l, &mid.der]), ISS, &anchors_of(&root), now()).unwrap_err();
        assert!(err.to_string().contains("critical extension"), "{err}");

        // The same extension, not critical, is ignorable.
        let mid = ca_with(Some(&root), "Non-critical unknown", |p| {
            p.custom_extensions
                .push(rcgen::CustomExtension::from_oid_content(
                    &[1, 3, 6, 1, 4, 1, 99999, 1],
                    vec![0x05, 0x00],
                ));
        });
        let (l, _) = leaf(&mid, &["pid.example.org"], false);
        x5c_issuer_key(&header(&[&l, &mid.der]), ISS, &anchors_of(&root), now()).unwrap();
    }

    #[test]
    fn issue_2618_an_extension_that_does_not_parse_is_refused() {
        let root = ca("Root");
        // A keyUsage whose content is not a BIT STRING.
        let mid = ca_with(Some(&root), "Broken keyUsage", |p| {
            p.custom_extensions
                .push(rcgen::CustomExtension::from_oid_content(
                    &[2, 5, 29, 15],
                    vec![0x05, 0x00],
                ));
        });
        let (l, _) = leaf(&mid, &["pid.example.org"], false);
        let err =
            x5c_issuer_key(&header(&[&l, &mid.der]), ISS, &anchors_of(&root), now()).unwrap_err();
        assert!(err.to_string().contains("does not parse"), "{err}");
    }

    #[test]
    fn dns_and_uri_constraint_matching() {
        assert!(dns_within("example.org", "example.org"));
        assert!(dns_within("a.b.example.org", "example.org"));
        assert!(!dns_within("badexample.org", "example.org"));
        assert!(dns_within("a.example.org", ".example.org"));
        assert!(!dns_within("example.org", ".example.org"));
        assert!(dns_within("Anything.Test", ""));
        assert!(uri_host_within("pid.example.org", "pid.example.org"));
        assert!(!uri_host_within("a.pid.example.org", "pid.example.org"));
        assert!(uri_host_within("a.pid.example.org", ".pid.example.org"));
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
