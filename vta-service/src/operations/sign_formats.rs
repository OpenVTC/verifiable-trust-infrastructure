//! The byte strings `keys/sign-jws/0.1`, `keys/sign-csr/0.1` and
//! `keys/sign-document/0.1` sign, built here and nowhere else.
//!
//! Both tasks rest on one property: the VTA signs a structure it built itself,
//! never bytes the caller chose. A JWS signing input is ASCII beginning `eyJ`;
//! a `CertificationRequestInfo` is DER beginning `0x30`. Neither is a framed
//! `keys/sign` payload or an SSHSIG statement, so a signature obtained through
//! one task verifies as nothing the others produce. `eddsa-jcs-2022` hash data
//! is two SHA-256 digests, 64 bytes the cryptosuite defines as its own domain
//! separation. This module only builds and checks; the gates, the key and the
//! audit row are the operations' (see [`super::keys::sign_jws`],
//! [`super::keys::sign_csr`] and [`super::keys::sign_document`]).

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use serde_json::{Map, Value};
use vta_sdk::jws::JwsKey;
use vta_sdk::protocols::key_management::sign_csr::{
    SignCsrRdnAttribute, SignCsrRdnType, SignCsrSubjectAltNames,
};
use vta_sdk::protocols::key_management::sign_jws::FORBIDDEN_HEADER_MEMBERS;
use yasna::Tag;
use yasna::models::ObjectIdentifier;

/// Why a request could not be built into bytes to sign — each a code the
/// specification declares.
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum FormatRefusal {
    /// `keys/sign-jws:headerMemberForbidden`, naming the member.
    HeaderMemberForbidden(String),
    /// `keys:invalidArgument`.
    InvalidArgument(String),
    /// `keys/sign-jws:payloadInvalid`.
    PayloadInvalid(String),
    /// `keys/sign-csr:subjectInvalid`: `member` is `subject` or
    /// `subjectAltNames`, `index` the element of its array.
    SubjectInvalid {
        member: &'static str,
        index: Option<usize>,
        reason: String,
    },
    /// `keys/sign-document:proofPresent`.
    ProofPresent,
    /// `keys/sign-document:documentInvalid`, with its `reason`: `noSigner`,
    /// `signerMalformed` or `notCanonicalizable`.
    DocumentInvalid(&'static str),
    /// `keys/sign-document:issuerMismatch`, naming `issuer` or `controller`.
    IssuerMismatch(&'static str),
    /// `keys/sign-document:purposeNotAuthorized`, naming the purpose.
    PurposeNotAuthorized(&'static str),
}

// ── keys/sign-jws ───────────────────────────────────────────────────────

/// A JWS payload as the request carried it.
#[derive(Debug, Clone, Copy)]
pub enum JwsPayload<'a> {
    /// `payload`: a JSON object, serialised with RFC 8785.
    Json(&'a Map<String, Value>),
    /// `payloadBase64Url`: used unchanged once checked canonical.
    Base64Url(&'a str),
}

/// Refuse the header members the custodian sets or never signs, and the
/// registered ones (`typ`, `cty`, `kid`, `x5c`, `x5t`, `x5t#S256`) whose value
/// is not of RFC 7515's type — and an `x5c` whose first certificate is not
/// `key`'s.
pub fn check_jws_header(header: &Map<String, Value>, key: &JwsKey) -> Result<(), FormatRefusal> {
    if let Some(member) = FORBIDDEN_HEADER_MEMBERS
        .iter()
        .find(|m| header.contains_key(**m))
    {
        return Err(FormatRefusal::HeaderMemberForbidden((*member).to_string()));
    }
    let invalid = |m: String| Err(FormatRefusal::InvalidArgument(m));
    for name in ["typ", "cty", "kid"] {
        if let Some(v) = header.get(name)
            && !v.is_string()
        {
            return invalid(format!("header `{name}` must be a string"));
        }
    }
    for name in ["x5t", "x5t#S256"] {
        if let Some(v) = header.get(name)
            && !v
                .as_str()
                .is_some_and(|s| URL_SAFE_NO_PAD.decode(s).is_ok())
        {
            return invalid(format!("header `{name}` must be a base64url string"));
        }
    }
    if let Some(chain) = header.get("x5c") {
        let Some(chain) = chain.as_array().filter(|c| !c.is_empty()) else {
            return invalid("header `x5c` must be a non-empty array of certificates".into());
        };
        let mut ders = Vec::with_capacity(chain.len());
        for (i, cert) in chain.iter().enumerate() {
            // RFC 7515 §4.1.6: standard base64 of the DER, not base64url.
            let Some(der) = cert.as_str().and_then(|s| STANDARD.decode(s).ok()) else {
                return invalid(format!("header `x5c`[{i}] is not a base64 certificate"));
            };
            ders.push(der);
        }
        match vta_sdk::x509_issuer::certificate_key(&ders[0]) {
            Ok(leaf) if &leaf == key => {}
            Ok(_) => {
                return invalid(
                    "the first `x5c` certificate does not carry the named key's public key".into(),
                );
            }
            Err(e) => return invalid(format!("header `x5c`[0]: {e}")),
        }
    }
    Ok(())
}

/// The JWS signing input, `BASE64URL(header) '.' BASE64URL(payload)`: the
/// header with `alg` added and both JSON halves serialised with RFC 8785, so
/// the bytes are a function of the request alone.
pub fn jws_signing_input(
    alg: &str,
    header: &Map<String, Value>,
    payload: JwsPayload<'_>,
) -> Result<String, FormatRefusal> {
    let mut protected = header.clone();
    protected.insert("alg".into(), Value::String(alg.to_string()));
    let header_json = jcs(&Value::Object(protected))
        .map_err(|e| FormatRefusal::InvalidArgument(format!("header: {e}")))?;
    let payload_segment = match payload {
        JwsPayload::Json(object) => {
            let object = Value::Object(object.clone());
            check_i_json(&object)?;
            URL_SAFE_NO_PAD.encode(jcs(&object).map_err(FormatRefusal::PayloadInvalid)?)
        }
        JwsPayload::Base64Url(segment) => {
            let canonical = URL_SAFE_NO_PAD
                .decode(segment)
                .ok()
                .is_some_and(|bytes| URL_SAFE_NO_PAD.encode(bytes) == segment);
            if !canonical {
                return Err(FormatRefusal::PayloadInvalid(
                    "payloadBase64Url is not the canonical unpadded base64url of any byte string"
                        .into(),
                ));
            }
            segment.to_string()
        }
    };
    Ok(format!(
        "{}.{payload_segment}",
        URL_SAFE_NO_PAD.encode(header_json)
    ))
}

fn jcs(value: &Value) -> Result<String, String> {
    serde_json_canonicalizer::to_string(value).map_err(|e| e.to_string())
}

/// RFC 8785 serialises every number as an IEEE 754 double; an integer beyond
/// 2⁵³ would be rounded into a different claim, so it is refused instead.
fn check_i_json(value: &Value) -> Result<(), FormatRefusal> {
    const MAX_EXACT: u64 = 1 << 53;
    match value {
        Value::Number(n) => {
            let exact = n
                .as_u64()
                .map(|u| u <= MAX_EXACT)
                .or_else(|| n.as_i64().map(|i| i.unsigned_abs() <= MAX_EXACT))
                .unwrap_or(true);
            if exact {
                Ok(())
            } else {
                Err(FormatRefusal::PayloadInvalid(format!(
                    "the number {n} cannot be serialised exactly (RFC 8785); send it as a string"
                )))
            }
        }
        Value::Array(items) => items.iter().try_for_each(check_i_json),
        Value::Object(members) => members.values().try_for_each(check_i_json),
        _ => Ok(()),
    }
}

// ── keys/sign-csr ───────────────────────────────────────────────────────

/// The public key a certificate request certifies, as its
/// `subjectPublicKeyInfo` carries it.
#[derive(Debug, Clone)]
pub enum CsrKey {
    /// An uncompressed SEC1 point (65 bytes).
    P256(Vec<u8>),
    /// A raw Ed25519 public key.
    Ed25519([u8; 32]),
}

impl CsrKey {
    /// The request's key from a key the custodian holds; `None` for a key type
    /// `keys/sign-csr/0.1` does not certify.
    pub fn from_jws_key(key: &JwsKey) -> Option<Self> {
        match key {
            JwsKey::Ed25519(k) => Some(Self::Ed25519(*k)),
            JwsKey::P256(compressed) => {
                use p256::elliptic_curve::sec1::ToSec1Point;
                let point = p256::PublicKey::from_sec1_bytes(compressed).ok()?;
                Some(Self::P256(point.to_sec1_point(false).as_bytes().to_vec()))
            }
            _ => None,
        }
    }
}

const OID_EC_PUBLIC_KEY: &[u64] = &[1, 2, 840, 10045, 2, 1];
const OID_PRIME256V1: &[u64] = &[1, 2, 840, 10045, 3, 1, 7];
const OID_ED25519: &[u64] = &[1, 3, 101, 112];
const OID_ECDSA_WITH_SHA256: &[u64] = &[1, 2, 840, 10045, 4, 3, 2];
const OID_EXTENSION_REQUEST: &[u64] = &[1, 2, 840, 113549, 1, 9, 14];
const OID_SUBJECT_ALT_NAME: &[u64] = &[2, 5, 29, 17];

/// How one subject attribute type is encoded, and the rule its value obeys.
struct AttributeRule {
    oid: &'static [u64],
    string: DnString,
    max_chars: usize,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum DnString {
    Utf8,
    Printable,
    Ia5,
}

fn attribute_rule(kind: &SignCsrRdnType) -> Option<AttributeRule> {
    let (oid, string, max_chars): (&'static [u64], _, _) = match kind {
        SignCsrRdnType::C => (&[2, 5, 4, 6], DnString::Printable, 2),
        SignCsrRdnType::St => (&[2, 5, 4, 8], DnString::Utf8, 128),
        SignCsrRdnType::L => (&[2, 5, 4, 7], DnString::Utf8, 128),
        SignCsrRdnType::O => (&[2, 5, 4, 10], DnString::Utf8, 64),
        SignCsrRdnType::Ou => (&[2, 5, 4, 11], DnString::Utf8, 64),
        SignCsrRdnType::OrganizationIdentifier => (&[2, 5, 4, 97], DnString::Utf8, 128),
        SignCsrRdnType::Cn => (&[2, 5, 4, 3], DnString::Utf8, 64),
        SignCsrRdnType::SerialNumber => (&[2, 5, 4, 5], DnString::Printable, 64),
        SignCsrRdnType::EmailAddress => (&[1, 2, 840, 113549, 1, 9, 1], DnString::Ia5, 255),
        _ => return None,
    };
    Some(AttributeRule {
        oid,
        string,
        max_chars,
    })
}

fn is_control(c: char) -> bool {
    matches!(c, '\u{0}'..='\u{1f}' | '\u{7f}'..='\u{9f}')
}

fn is_printable_string_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || " '()+,-./:=?".contains(c)
}

/// An ASCII mailbox, as `subjectAltNames.email`'s schema pattern states it.
fn is_mailbox(v: &str) -> bool {
    let Some((local, domain)) = v.split_once('@') else {
        return false;
    };
    !local.is_empty()
        && !domain.is_empty()
        && local.chars().all(|c| matches!(c, '!'..='?' | 'A'..='~'))
        && domain
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
}

/// Check every subject attribute against the specification's table, without
/// repairing any: a certificate names what the request named.
pub fn check_csr_subject(subject: &[SignCsrRdnAttribute]) -> Result<(), FormatRefusal> {
    for (index, attr) in subject.iter().enumerate() {
        let refuse = |reason: String| FormatRefusal::SubjectInvalid {
            member: "subject",
            index: Some(index),
            reason,
        };
        let value = attr.value.as_str();
        let Some(rule) = attribute_rule(&attr.type_) else {
            return Err(refuse(format!(
                "attribute type {} is not supported",
                attr.type_
            )));
        };
        let chars = value.chars().count();
        if chars == 0 || chars > rule.max_chars {
            return Err(refuse(format!(
                "{} must be 1 to {} characters",
                attr.type_, rule.max_chars
            )));
        }
        if value.chars().any(is_control) {
            return Err(refuse(format!(
                "{} contains a control character",
                attr.type_
            )));
        }
        let ok = match attr.type_ {
            SignCsrRdnType::C => value.chars().all(|c| c.is_ascii_uppercase()) && chars == 2,
            SignCsrRdnType::SerialNumber => value.chars().all(is_printable_string_char),
            SignCsrRdnType::EmailAddress => is_mailbox(value),
            _ => true,
        };
        if !ok {
            return Err(refuse(match attr.type_ {
                SignCsrRdnType::C => "C must be an ISO 3166-1 alpha-2 code, e.g. DE".into(),
                SignCsrRdnType::SerialNumber => {
                    "serialNumber must use the PrintableString characters only".into()
                }
                _ => "emailAddress must be an ASCII mailbox".into(),
            }));
        }
    }
    Ok(())
}

/// The DER `SubjectPublicKeyInfo` of `key`: RFC 5480 §2 for P-256 (the
/// uncompressed point under `id-ecPublicKey` / `secp256r1`), RFC 8410 §4 for
/// Ed25519.
pub fn subject_public_key_info(key: &CsrKey) -> Vec<u8> {
    yasna::construct_der(|w| {
        w.write_sequence(|w| match key {
            CsrKey::P256(point) => {
                w.next().write_sequence(|w| {
                    w.next()
                        .write_oid(&ObjectIdentifier::from_slice(OID_EC_PUBLIC_KEY));
                    w.next()
                        .write_oid(&ObjectIdentifier::from_slice(OID_PRIME256V1));
                });
                w.next().write_bitvec_bytes(point, point.len() * 8);
            }
            CsrKey::Ed25519(k) => {
                w.next().write_sequence(|w| {
                    w.next()
                        .write_oid(&ObjectIdentifier::from_slice(OID_ED25519));
                });
                w.next().write_bitvec_bytes(k, k.len() * 8);
            }
        });
    })
}

/// The DER `CertificationRequestInfo` (RFC 2986 §4.1) for `key`, naming
/// `subject` in the order given and requesting `alt_names` as the one
/// extension. Call [`check_csr_subject`] first.
pub fn certification_request_info(
    subject: &[SignCsrRdnAttribute],
    alt_names: Option<&SignCsrSubjectAltNames>,
    key: &CsrKey,
) -> Vec<u8> {
    yasna::construct_der(|w| {
        w.write_sequence(|w| {
            w.next().write_u8(0);
            // subject: one single-valued RDN per attribute, in order.
            w.next().write_sequence(|w| {
                for attr in subject {
                    let Some(rule) = attribute_rule(&attr.type_) else {
                        continue;
                    };
                    w.next().write_set(|w| {
                        w.next().write_sequence(|w| {
                            w.next().write_oid(&ObjectIdentifier::from_slice(rule.oid));
                            let value = attr.value.as_str();
                            match rule.string {
                                DnString::Utf8 => w.next().write_utf8_string(value),
                                DnString::Printable => w.next().write_printable_string(value),
                                DnString::Ia5 => w.next().write_ia5_string(value),
                            }
                        });
                    });
                }
            });
            // subjectPKInfo: the named key's own, never one the producer sent.
            w.next().write_der(&subject_public_key_info(key));
            // attributes [0]: empty, or one extensionRequest holding one
            // non-critical subjectAltName.
            w.next().write_tagged_implicit(Tag::context(0), |w| {
                w.write_set(|w| {
                    let Some(names) = alt_names else {
                        return;
                    };
                    let general_names = yasna::construct_der(|w| {
                        w.write_sequence(|w| {
                            for (tag, list) in [
                                (2, names.dns.iter().map(|n| n.as_str()).collect::<Vec<_>>()),
                                (6, names.uri.iter().map(|n| n.as_str()).collect()),
                                (1, names.email.iter().map(|n| n.as_str()).collect()),
                            ] {
                                for name in list {
                                    w.next().write_tagged_implicit(Tag::context(tag), |w| {
                                        w.write_ia5_string(name)
                                    });
                                }
                            }
                        });
                    });
                    w.next().write_sequence(|w| {
                        w.next()
                            .write_oid(&ObjectIdentifier::from_slice(OID_EXTENSION_REQUEST));
                        w.next().write_set(|w| {
                            w.next().write_sequence(|w| {
                                w.next().write_sequence(|w| {
                                    w.next().write_oid(&ObjectIdentifier::from_slice(
                                        OID_SUBJECT_ALT_NAME,
                                    ));
                                    w.next().write_bytes(&general_names);
                                });
                            });
                        });
                    });
                });
            });
        });
    })
}

/// The signed `CertificationRequest` as RFC 7468 PEM, from its info and the
/// signature over it: for P-256 the JOSE `r || s` the signing chokepoint
/// returns, re-encoded as the DER `Ecdsa-Sig-Value` PKCS#10 wants.
pub fn certification_request_pem(
    info: &[u8],
    key: &CsrKey,
    signature: &[u8],
) -> Result<String, String> {
    let (algorithm, signature): (&[u64], Vec<u8>) = match key {
        CsrKey::P256(_) => {
            let sig = p256::ecdsa::Signature::from_slice(signature)
                .map_err(|e| format!("P-256 signature: {e}"))?;
            (OID_ECDSA_WITH_SHA256, sig.to_der().as_bytes().to_vec())
        }
        CsrKey::Ed25519(_) => (OID_ED25519, signature.to_vec()),
    };
    let der = yasna::construct_der(|w| {
        w.write_sequence(|w| {
            w.next().write_der(info);
            w.next().write_sequence(|w| {
                w.next().write_oid(&ObjectIdentifier::from_slice(algorithm));
            });
            w.next().write_bitvec_bytes(&signature, signature.len() * 8);
        });
    });
    let body = STANDARD.encode(der);
    let mut pem = String::from("-----BEGIN CERTIFICATE REQUEST-----\n");
    for line in body.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(line).map_err(|e| e.to_string())?);
        pem.push('\n');
    }
    pem.push_str("-----END CERTIFICATE REQUEST-----\n");
    Ok(pem)
}

// ── keys/sign-document ──────────────────────────────────────────────────

/// A DID as `keys/sign-document` admits one: `did:<method>:<id>`, never a DID
/// URL with a path, query or fragment.
fn is_bare_did(s: &str) -> bool {
    let mut parts = s.splitn(3, ':');
    matches!(
        (parts.next(), parts.next(), parts.next()),
        (Some("did"), Some(method), Some(id))
            if !method.is_empty()
                && method.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
                && !id.is_empty()
    ) && !s.contains(['/', '?', '#'])
}

/// The DID a document names as its signer, after the checks that need nothing
/// but the document (`keys/sign-document` items 3 and 4, and the issuer
/// binding's rule that `issuer` and `controller` agree).
pub fn document_signer(document: &Value) -> Result<String, FormatRefusal> {
    let Some(obj) = document.as_object() else {
        return Err(FormatRefusal::DocumentInvalid("noSigner"));
    };
    if obj.contains_key("proof") {
        return Err(FormatRefusal::ProofPresent);
    }
    let issuer = match obj.get("issuer") {
        None => None,
        Some(Value::String(did)) => Some(did.as_str()),
        Some(Value::Object(o)) => match o.get("id") {
            Some(Value::String(did)) => Some(did.as_str()),
            _ => return Err(FormatRefusal::DocumentInvalid("signerMalformed")),
        },
        Some(_) => return Err(FormatRefusal::DocumentInvalid("signerMalformed")),
    };
    let controller = match obj.get("controller") {
        None => None,
        Some(Value::String(did)) => Some(did.as_str()),
        Some(Value::Array(items)) => match items.as_slice() {
            [Value::String(did)] => Some(did.as_str()),
            _ => return Err(FormatRefusal::DocumentInvalid("signerMalformed")),
        },
        Some(_) => return Err(FormatRefusal::DocumentInvalid("signerMalformed")),
    };
    let signer = match (issuer, controller) {
        (None, None) => return Err(FormatRefusal::DocumentInvalid("noSigner")),
        (Some(i), Some(c)) if i != c => return Err(FormatRefusal::IssuerMismatch("controller")),
        (Some(did), _) | (None, Some(did)) => did,
    };
    if issuer.is_some_and(|d| !is_bare_did(d)) || controller.is_some_and(|d| !is_bare_did(d)) {
        return Err(FormatRefusal::DocumentInvalid("signerMalformed"));
    }
    // RFC 8785 serialises every number as a double; one beyond 2^53 would be
    // signed as a different value, and is refused rather than repaired.
    if check_i_json(document).is_err() || jcs(document).is_err() {
        return Err(FormatRefusal::DocumentInvalid("notCanonicalizable"));
    }
    Ok(signer.to_string())
}

/// One verification method of a signer DID: its identifier, its Ed25519 key,
/// and the relationships its document lists it under.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignerMethod {
    pub id: String,
    pub key: [u8; 32],
    pub purposes: Vec<&'static str>,
}

/// The relationships a Data Integrity proof made here may be listed under.
pub const DOCUMENT_PROOF_PURPOSES: [&str; 2] = ["assertionMethod", "authentication"];

/// The Ed25519 key a verification method object publishes, if it publishes one.
fn method_key(vm: &Map<String, Value>) -> Option<[u8; 32]> {
    if let Some(mb) = vm.get("publicKeyMultibase").and_then(Value::as_str) {
        return vta_sdk::did_key::decode_ed25519_public_key_multibase(mb).ok();
    }
    let jwk = vm.get("publicKeyJwk")?.as_object()?;
    if jwk.get("kty")?.as_str()? != "OKP" || jwk.get("crv")?.as_str()? != "Ed25519" {
        return None;
    }
    URL_SAFE_NO_PAD
        .decode(jwk.get("x")?.as_str()?)
        .ok()?
        .try_into()
        .ok()
}

/// The Ed25519 verification methods `did`'s document lists, in the order it
/// lists them — in `verificationMethod` or embedded in a relationship — each
/// with the signing relationships that name it. A relative identifier
/// (`#key-1`) is read against `did`.
pub fn signer_methods(did: &str, document: &Value) -> Vec<SignerMethod> {
    let absolute = |id: &str| {
        if id.starts_with('#') {
            format!("{did}{id}")
        } else {
            id.to_string()
        }
    };
    let mut methods: Vec<SignerMethod> = Vec::new();
    let mut push = |vm: &Map<String, Value>| {
        let (Some(id), Some(key)) = (vm.get("id").and_then(Value::as_str), method_key(vm)) else {
            return;
        };
        let id = absolute(id);
        if !methods.iter().any(|m| m.id == id) {
            methods.push(SignerMethod {
                id,
                key,
                purposes: vec![],
            });
        }
    };
    for vm in document
        .get("verificationMethod")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_object)
    {
        push(vm);
    }
    for purpose in DOCUMENT_PROOF_PURPOSES {
        for entry in document
            .get(purpose)
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            if let Some(vm) = entry.as_object() {
                push(vm);
            }
        }
    }
    for purpose in DOCUMENT_PROOF_PURPOSES {
        for entry in document
            .get(purpose)
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let id = match entry {
                Value::String(id) => absolute(id),
                Value::Object(vm) => match vm.get("id").and_then(Value::as_str) {
                    Some(id) => absolute(id),
                    None => continue,
                },
                _ => continue,
            };
            if let Some(m) = methods.iter_mut().find(|m| m.id == id)
                && !m.purposes.contains(&purpose)
            {
                m.purposes.push(purpose);
            }
        }
    }
    methods
}

/// The methods of a `did:key`, read from the identifier itself: one Ed25519
/// key, listed under every signing relationship.
pub fn did_key_methods(did: &str) -> Option<Vec<SignerMethod>> {
    let mb = did.strip_prefix("did:key:")?;
    let key = vta_sdk::did_key::decode_ed25519_public_key_multibase(mb).ok()?;
    // An X25519 did:key decodes to 32 bytes too; only the Ed25519 codec signs.
    let (_, raw) = multibase::decode(mb).ok()?;
    if raw.get(..2) != Some(&[0xed, 0x01]) {
        return None;
    }
    Some(vec![SignerMethod {
        id: format!("{did}#{mb}"),
        key,
        purposes: DOCUMENT_PROOF_PURPOSES.to_vec(),
    }])
}

/// The proof configuration `keys/sign-document` builds (*The proof* item 1),
/// without `proofValue`.
pub fn document_proof_config(
    document: &Value,
    verification_method: &str,
    proof_purpose: &str,
    created: &str,
    challenge: Option<&str>,
    domain: Option<&str>,
) -> Value {
    let mut config = Map::new();
    if let Some(context) = document.get("@context") {
        config.insert("@context".into(), context.clone());
    }
    config.insert("type".into(), "DataIntegrityProof".into());
    config.insert("cryptosuite".into(), "eddsa-jcs-2022".into());
    config.insert("created".into(), created.into());
    config.insert("verificationMethod".into(), verification_method.into());
    config.insert("proofPurpose".into(), proof_purpose.into());
    if let Some(c) = challenge {
        config.insert("challenge".into(), c.into());
    }
    if let Some(d) = domain {
        config.insert("domain".into(), d.into());
    }
    Value::Object(config)
}

/// `eddsa-jcs-2022` hash data: `SHA-256(JCS(config)) || SHA-256(JCS(document))`.
pub fn eddsa_jcs_2022_hash_data(document: &Value, config: &Value) -> Result<[u8; 64], String> {
    use sha2::{Digest, Sha256};
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&Sha256::digest(jcs(config)?.as_bytes()));
    out[32..].copy_from_slice(&Sha256::digest(jcs(document)?.as_bytes()));
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use sha2::{Digest, Sha256};

    fn object(v: Value) -> Map<String, Value> {
        v.as_object().unwrap().clone()
    }

    /// The specification's own example: its header and payload segments, and
    /// the SHA-256 of the signing input its audit line records.
    #[test]
    fn the_spec_example_signing_input_is_reproduced() {
        let header = object(json!({
            "typ": "oauth-authz-req+jwt",
            "kid": "did:example:community-verifier#key-1"
        }));
        let payload = object(json!({
            "aud": "https://self-issued.me/v2",
            "client_id": "decentralized_identifier:did:example:community-verifier",
            "response_type": "vp_token",
            "response_mode": "direct_post.jwt",
            "response_uri": "https://community.example/v1/oid4vp/response/7d1e4c2a",
            "nonce": "q8vTt3yN5mQ0aW2f",
            "state": "7d1e4c2a",
            "dcql_query": { "credentials": [ {
                "id": "membership",
                "format": "dc+sd-jwt",
                "meta": { "vct_values": ["https://credentials.example/membership"] }
            } ] },
            "iat": 1791709200,
            "exp": 1791709500
        }));
        let input = jws_signing_input("ES256", &header, JwsPayload::Json(&payload)).unwrap();
        assert!(input.starts_with(
            "eyJhbGciOiJFUzI1NiIsImtpZCI6ImRpZDpleGFtcGxlOmNvbW11bml0eS12ZXJpZmllciNrZXktMSIsInR5cCI6Im9hdXRoLWF1dGh6LXJlcStqd3QifQ."
        ));
        assert_eq!(
            hex::encode(Sha256::digest(input.as_bytes())),
            "e0c236e3a90999a1ab54699f308c0ad0468405da185731762396cd733e031257"
        );
    }

    #[test]
    fn forbidden_and_mistyped_header_members_are_refused() {
        let key = JwsKey::Ed25519([7; 32]);
        for member in FORBIDDEN_HEADER_MEMBERS {
            let header = object(json!({ *member: "x" }));
            assert_eq!(
                check_jws_header(&header, &key),
                Err(FormatRefusal::HeaderMemberForbidden((*member).to_string()))
            );
        }
        for header in [
            json!({ "typ": 1 }),
            json!({ "kid": ["a"] }),
            json!({ "x5t": "not base64url!" }),
            json!({ "x5c": [] }),
            json!({ "x5c": ["***"] }),
            json!({ "x5c": [STANDARD.encode(b"not a certificate")] }),
        ] {
            assert!(
                matches!(
                    check_jws_header(&object(header.clone()), &key),
                    Err(FormatRefusal::InvalidArgument(_))
                ),
                "{header}"
            );
        }
        assert_eq!(
            check_jws_header(
                &object(json!({ "typ": "jwt", "profile_version": "x" })),
                &key
            ),
            Ok(())
        );
    }

    #[test]
    fn a_payload_that_cannot_be_signed_exactly_is_refused() {
        let header = Map::new();
        let big = object(json!({ "n": 9_007_199_254_740_993u64 }));
        assert!(matches!(
            jws_signing_input("EdDSA", &header, JwsPayload::Json(&big)),
            Err(FormatRefusal::PayloadInvalid(_))
        ));
        // "QR" decodes to one byte with non-zero trailing bits; "QQ" is canonical.
        assert!(matches!(
            jws_signing_input("EdDSA", &header, JwsPayload::Base64Url("QR")),
            Err(FormatRefusal::PayloadInvalid(_))
        ));
        let ok = jws_signing_input("EdDSA", &header, JwsPayload::Base64Url("QQ")).unwrap();
        assert!(ok.ends_with(".QQ"));
    }

    fn attr(type_: &str, value: &str) -> SignCsrRdnAttribute {
        serde_json::from_value(json!({ "type": type_, "value": value })).unwrap()
    }

    #[test]
    fn subject_rules_refuse_without_repairing() {
        for (i, bad) in [
            attr("C", "de"),
            attr("C", "DEU"),
            attr("CN", &"x".repeat(65)),
            attr("O", "Acme\u{7}"),
            attr("serialNumber", "a_b"),
            attr("emailAddress", "no-at-sign"),
        ]
        .into_iter()
        .enumerate()
        {
            let subject = vec![attr("C", "DE"), bad];
            match check_csr_subject(&subject) {
                Err(FormatRefusal::SubjectInvalid { member, index, .. }) => {
                    assert_eq!(member, "subject");
                    assert_eq!(index, Some(1), "case {i}");
                }
                other => panic!("case {i}: {other:?}"),
            }
        }
        check_csr_subject(&[
            attr("C", "DE"),
            attr("O", "Example Community e.V."),
            attr("organizationIdentifier", "LEIXG-5299000EXAMPLE000001"),
            attr("CN", "Example Community Verifier"),
        ])
        .unwrap();
    }
}
