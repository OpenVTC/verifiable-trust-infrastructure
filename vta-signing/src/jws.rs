//! `keys/sign-jws/0.1`: the bytes of a compact JWS and the rules for building
//! them.
//!
//! The signer builds the whole signing input itself (RFC 8785 header and
//! payload), writes `alg` from the key, and refuses the header members it never
//! signs. The caller's JSON is therefore not byte-for-byte what is signed: the
//! returned token is the artefact, and it is used as it is.
//!
//! A JWS is made in two phases so a signer that wraps the signature in its own
//! gates (the VTA's access control, key custody and audit) and one that holds
//! the key (a service signing with its own) build the same bytes:
//! [`prepare_jws`], then the signature however the key is held, then
//! [`finish_jws`]. [`sign_jws`] is the three in one call.

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use serde_json::{Map, Value};

use crate::canonical::{canonicalize, check_i_json};
use crate::{Algorithm, FormatRefusal, PublicKey, SignError, Signer, VerifyError};

/// Header members a producer may not send: the custodian sets `alg` itself, and
/// signs no `crit`, `b64`, `jwk`, `jku` or `x5u` (the specification's
/// *Forbidden header members*).
pub const FORBIDDEN_HEADER_MEMBERS: &[&str] = &["alg", "crit", "b64", "jwk", "jku", "x5u"];

/// A JWS payload as the request carried it.
#[derive(Debug, Clone, Copy)]
pub enum JwsPayload<'a> {
    /// `payload`: a JSON object, serialised with RFC 8785.
    Json(&'a Map<String, Value>),
    /// `payloadBase64Url`: used unchanged once checked canonical.
    Base64Url(&'a str),
}

/// An `x5c` leaf check that accepts no certificate chain, for a signer that
/// has no X.509 support.
pub fn refuse_x5c(_leaf_certificate: &[u8]) -> Result<bool, String> {
    Err("certificate chains are not supported here".to_string())
}

/// Refuse the header members the custodian sets or never signs, and the
/// registered ones (`typ`, `cty`, `kid`, `x5c`, `x5t`, `x5t#S256`) whose value
/// is not of RFC 7515's type — and an `x5c` whose first certificate is not the
/// signing key's.
///
/// Reading a certificate is not this crate's business, so `x5c_leaf_is_signer`
/// is handed the DER of the first certificate and says whether it carries the
/// signing key's public key (`Err` when it cannot be read). It runs only when
/// the header has an `x5c`.
pub fn check_jws_header(
    header: &Map<String, Value>,
    x5c_leaf_is_signer: impl FnOnce(&[u8]) -> Result<bool, String>,
) -> Result<(), FormatRefusal> {
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
            && v.as_str()
                .is_none_or(|s| URL_SAFE_NO_PAD.decode(s).is_err())
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
        match x5c_leaf_is_signer(&ders[0]) {
            Ok(true) => {}
            Ok(false) => {
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
    let header_json = canonicalize(&Value::Object(protected))
        .map_err(|e| FormatRefusal::InvalidArgument(format!("header: {e}")))?;
    let payload_segment = match payload {
        JwsPayload::Json(object) => {
            let object = Value::Object(object.clone());
            check_i_json(&object)?;
            URL_SAFE_NO_PAD.encode(canonicalize(&object).map_err(FormatRefusal::PayloadInvalid)?)
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

/// The signing input of a JWS and the algorithm it names: what is signed, before
/// it is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JwsSigningInput {
    text: String,
    algorithm: Algorithm,
}

impl JwsSigningInput {
    /// The bytes to sign.
    pub fn bytes(&self) -> &[u8] {
        self.text.as_bytes()
    }

    /// The algorithm the header names, which the signature must be made with.
    pub fn algorithm(&self) -> Algorithm {
        self.algorithm
    }
}

/// Check the header and build the signing input for a JWS signed with
/// `algorithm`. Nothing is signed; a refusal here means nothing ever will be.
pub fn prepare_jws(
    algorithm: Algorithm,
    header: &Map<String, Value>,
    payload: JwsPayload<'_>,
    x5c_leaf_is_signer: impl FnOnce(&[u8]) -> Result<bool, String>,
) -> Result<JwsSigningInput, FormatRefusal> {
    check_jws_header(header, x5c_leaf_is_signer)?;
    Ok(JwsSigningInput {
        text: jws_signing_input(algorithm.jose_name(), header, payload)?,
        algorithm,
    })
}

/// The compact JWS of `input` signed with `signature`.
pub fn finish_jws(input: &JwsSigningInput, signature: &[u8]) -> String {
    format!("{}.{}", input.text, URL_SAFE_NO_PAD.encode(signature))
}

/// A compact JWS signed by `signer`: the header is checked, `alg` comes from the
/// key, the signing input is built here, and the result is the token.
///
/// `x5c_leaf_is_signer` is as for [`check_jws_header`]; pass [`refuse_x5c`] to
/// accept no certificate chain.
pub fn sign_jws(
    signer: &dyn Signer,
    header: &Map<String, Value>,
    payload: JwsPayload<'_>,
    x5c_leaf_is_signer: impl FnOnce(&[u8]) -> Result<bool, String>,
) -> Result<String, SignError> {
    let input = prepare_jws(signer.algorithm(), header, payload, x5c_leaf_is_signer)?;
    let signature = signer.sign(input.bytes())?;
    Ok(finish_jws(&input, &signature))
}

/// A JWS that verified: its protected header and its payload bytes.
#[derive(Debug, Clone, PartialEq)]
pub struct VerifiedJws {
    pub header: Map<String, Value>,
    pub payload: Vec<u8>,
}

/// Verify a compact JWS against `key`: three segments, a protected header whose
/// `alg` is the key's and that names no critical extension (`crit`, `b64`),
/// and a signature over the first two.
pub fn verify_jws(compact: &str, key: &PublicKey) -> Result<VerifiedJws, VerifyError> {
    let malformed = |m: &str| VerifyError::Malformed(m.to_string());
    let mut parts = compact.split('.');
    let (Some(header_b64), Some(payload_b64), Some(signature_b64), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(malformed("a compact JWS has three segments"));
    };
    let decode = |segment: &str| {
        URL_SAFE_NO_PAD
            .decode(segment)
            .map_err(|_| malformed("a segment is not base64url"))
    };
    let header: Map<String, Value> = serde_json::from_slice(&decode(header_b64)?)
        .map_err(|_| malformed("the protected header is not a JSON object"))?;
    let alg = header
        .get("alg")
        .and_then(Value::as_str)
        .ok_or_else(|| malformed("the protected header has no alg"))?;
    // RFC 7515 §4.1.11: a verifier refuses a JWS whose critical extensions it
    // does not understand, and this one understands none. `b64` is one such
    // extension (RFC 7797): with `false` the payload segment is not base64url,
    // so reading it as such would verify one thing and return another. The
    // signer refuses both members (`FORBIDDEN_HEADER_MEMBERS`); so does this.
    if header.contains_key("crit") {
        return Err(malformed(
            "the protected header names critical extensions (`crit`), and none is understood",
        ));
    }
    if header.contains_key("b64") {
        return Err(malformed(
            "the protected header carries `b64` (RFC 7797), which is not understood",
        ));
    }
    if Algorithm::from_jose_name(alg) != Some(key.algorithm()) {
        return Err(VerifyError::Algorithm {
            expected: key.algorithm(),
            got: alg.to_string(),
        });
    }
    key.verify(
        format!("{header_b64}.{payload_b64}").as_bytes(),
        &decode(signature_b64)?,
    )?;
    Ok(VerifiedJws {
        header,
        payload: decode(payload_b64)?,
    })
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use sha2::{Digest, Sha256};

    use super::*;
    use crate::SigningSecret;

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
        for member in FORBIDDEN_HEADER_MEMBERS {
            let header = object(json!({ *member: "x" }));
            assert_eq!(
                check_jws_header(&header, refuse_x5c),
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
                    check_jws_header(&object(header.clone()), refuse_x5c),
                    Err(FormatRefusal::InvalidArgument(_))
                ),
                "{header}"
            );
        }
        assert_eq!(
            check_jws_header(
                &object(json!({ "typ": "jwt", "profile_version": "x" })),
                refuse_x5c
            ),
            Ok(())
        );
    }

    #[test]
    fn the_x5c_leaf_is_checked_by_the_caller_only_when_there_is_one() {
        let chain = json!({ "x5c": [STANDARD.encode(b"leaf"), STANDARD.encode(b"root")] });

        assert_eq!(
            check_jws_header(&object(chain.clone()), |leaf| {
                assert_eq!(leaf, b"leaf", "the first certificate is the leaf");
                Ok(true)
            }),
            Ok(())
        );
        assert!(matches!(
            check_jws_header(&object(chain.clone()), |_| Ok(false)),
            Err(FormatRefusal::InvalidArgument(m)) if m.contains("does not carry")
        ));
        assert!(matches!(
            check_jws_header(&object(chain), |_| Err("unreadable".to_string())),
            Err(FormatRefusal::InvalidArgument(m)) if m == "header `x5c`[0]: unreadable"
        ));
        check_jws_header(&object(json!({ "kid": "k" })), |_| {
            panic!("no x5c, no check")
        })
        .unwrap();
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

    #[test]
    fn a_json_payload_is_signed_in_canonical_form_and_a_base64url_one_as_given() {
        let header = object(json!({ "typ": "JWT" }));
        let payload = object(json!({ "b": 1, "a": 2 }));

        let from_json = jws_signing_input("EdDSA", &header, JwsPayload::Json(&payload)).unwrap();
        let given = URL_SAFE_NO_PAD.encode(r#"{"b":1,"a":2}"#);
        let from_segment =
            jws_signing_input("EdDSA", &header, JwsPayload::Base64Url(&given)).unwrap();

        assert!(from_json.ends_with(&URL_SAFE_NO_PAD.encode(r#"{"a":2,"b":1}"#)));
        assert!(
            from_segment.ends_with(&format!(".{given}")),
            "a given payload is not reserialised"
        );
    }

    #[test]
    fn a_token_signs_and_verifies_for_both_key_types() {
        for secret in [
            SigningSecret::ed25519([3; 32]),
            SigningSecret::p256_from_slice(&[5; 32]).unwrap(),
        ] {
            let header = object(json!({ "typ": "at+jwt", "kid": "key-1" }));
            let payload = object(json!({ "sub": "agent", "n": 1 }));

            let jws = sign_jws(&secret, &header, JwsPayload::Json(&payload), refuse_x5c).unwrap();

            let verified = verify_jws(&jws, &secret.public_key()).unwrap();
            assert_eq!(
                Value::Object(verified.header),
                json!({ "alg": secret.algorithm().jose_name(), "kid": "key-1", "typ": "at+jwt" })
            );
            assert_eq!(
                serde_json::from_slice::<Value>(&verified.payload).unwrap(),
                json!({ "n": 1, "sub": "agent" })
            );
        }
    }

    #[test]
    fn making_the_signature_yourself_gives_the_same_token_as_signing_in_one_call() {
        let secret = SigningSecret::ed25519([3; 32]);
        let header = object(json!({ "typ": "JWT" }));
        let payload = object(json!({ "a": 1 }));

        let input = prepare_jws(
            secret.algorithm(),
            &header,
            JwsPayload::Json(&payload),
            refuse_x5c,
        )
        .unwrap();
        let in_phases = finish_jws(&input, &secret.sign_message(input.bytes()));

        assert_eq!(input.algorithm(), Algorithm::EdDsa);
        assert_eq!(
            in_phases,
            sign_jws(&secret, &header, JwsPayload::Json(&payload), refuse_x5c).unwrap()
        );
    }

    #[test]
    fn a_token_does_not_verify_under_another_key_algorithm_or_after_tampering() {
        let secret = SigningSecret::ed25519([3; 32]);
        let jws = sign_jws(
            &secret,
            &Map::new(),
            JwsPayload::Base64Url("QQ"),
            refuse_x5c,
        )
        .unwrap();

        assert_eq!(
            verify_jws(&jws, &SigningSecret::ed25519([4; 32]).public_key()),
            Err(VerifyError::Signature)
        );
        assert!(matches!(
            verify_jws(
                &jws,
                &SigningSecret::p256_from_slice(&[5; 32])
                    .unwrap()
                    .public_key()
            ),
            Err(VerifyError::Algorithm { .. })
        ));
        let mut parts: Vec<String> = jws.split('.').map(str::to_string).collect();
        parts[1] = URL_SAFE_NO_PAD.encode("changed");
        assert_eq!(
            verify_jws(&parts.join("."), &secret.public_key()),
            Err(VerifyError::Signature)
        );
        for bad in ["a.b", "a.b.c.d", "!.!.!"] {
            assert!(
                matches!(
                    verify_jws(bad, &secret.public_key()),
                    Err(VerifyError::Malformed(_))
                ),
                "{bad}"
            );
        }
    }

    #[test]
    fn a_refused_header_signs_nothing() {
        let secret = SigningSecret::ed25519([3; 32]);
        let header = object(json!({ "alg": "none" }));

        assert_eq!(
            sign_jws(&secret, &header, JwsPayload::Base64Url("QQ"), refuse_x5c),
            Err(SignError::Format(FormatRefusal::HeaderMemberForbidden(
                "alg".to_string()
            )))
        );
    }

    /// RFC 7515 §4.1.11: a critical extension this verifier does not
    /// understand — any, here — fails verification, even under a valid
    /// signature. `b64: false` (RFC 7797) would otherwise verify one payload
    /// and return another.
    #[test]
    fn a_token_naming_a_critical_extension_does_not_verify() {
        let secret = SigningSecret::ed25519([3; 32]);
        for header in [
            json!({ "alg": "EdDSA", "crit": ["exp-policy"], "exp-policy": 1 }),
            json!({ "alg": "EdDSA", "b64": false, "crit": ["b64"] }),
            json!({ "alg": "EdDSA", "b64": true }),
        ] {
            let header_b64 = URL_SAFE_NO_PAD.encode(header.to_string());
            let input = format!("{header_b64}.QQ");
            let signature = secret.sign_message(input.as_bytes());
            let jws = format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature));
            assert!(
                matches!(
                    verify_jws(&jws, &secret.public_key()),
                    Err(VerifyError::Malformed(_))
                ),
                "{header}"
            );
        }
    }
}
