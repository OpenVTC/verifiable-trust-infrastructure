//! `keys/sign-jws/0.1`: the bytes of a compact JWS and the rules for building
//! them.
//!
//! The signer builds the whole signing input itself (RFC 8785 header and
//! payload), writes `alg` from the key, and refuses the header members it never
//! signs. The caller's JSON is therefore not byte-for-byte what is signed: the
//! returned token is the artefact, and it is used as it is.

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use serde_json::{Map, Value};

use crate::canonical::{canonicalize, check_i_json};
use crate::{FormatRefusal, SigningSecret};

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

/// The compact JWS of `signing_input` signed with `signature`.
pub fn compact(signing_input: &str, signature: &[u8]) -> String {
    format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(signature))
}

/// A compact JWS signed by `secret`: the header is checked, `alg` comes from
/// the key, the signing input is built here, and the result is the token.
///
/// `x5c_leaf_is_signer` is as for [`check_jws_header`]; pass [`refuse_x5c`] to
/// accept no certificate chain.
pub fn sign_jws(
    secret: &SigningSecret,
    header: &Map<String, Value>,
    payload: JwsPayload<'_>,
    x5c_leaf_is_signer: impl FnOnce(&[u8]) -> Result<bool, String>,
) -> Result<String, FormatRefusal> {
    check_jws_header(header, x5c_leaf_is_signer)?;
    let input = jws_signing_input(secret.algorithm().jose_name(), header, payload)?;
    Ok(compact(&input, &secret.sign(input.as_bytes())))
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::Verifier as _;
    use serde_json::json;
    use sha2::{Digest, Sha256};

    use super::*;

    fn object(v: Value) -> Map<String, Value> {
        v.as_object().unwrap().clone()
    }

    fn no_x5c() -> impl FnOnce(&[u8]) -> Result<bool, String> {
        refuse_x5c
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
                check_jws_header(&header, no_x5c()),
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
                    check_jws_header(&object(header.clone()), no_x5c()),
                    Err(FormatRefusal::InvalidArgument(_))
                ),
                "{header}"
            );
        }
        assert_eq!(
            check_jws_header(
                &object(json!({ "typ": "jwt", "profile_version": "x" })),
                no_x5c()
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
    fn an_ed25519_token_verifies_under_the_keys_public_half() {
        let secret = SigningSecret::ed25519([3; 32]);
        let header = object(json!({ "typ": "at+jwt", "kid": "key-1" }));
        let payload = object(json!({ "sub": "agent", "n": 1 }));

        let jws = sign_jws(&secret, &header, JwsPayload::Json(&payload), no_x5c()).unwrap();

        let parts: Vec<&str> = jws.split('.').collect();
        assert_eq!(parts.len(), 3);
        let protected: Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0]).unwrap()).unwrap();
        assert_eq!(
            protected,
            json!({ "alg": "EdDSA", "kid": "key-1", "typ": "at+jwt" })
        );
        let public: [u8; 32] = secret.public_key().try_into().unwrap();
        let signature =
            ed25519_dalek::Signature::from_slice(&URL_SAFE_NO_PAD.decode(parts[2]).unwrap())
                .unwrap();
        assert!(
            ed25519_dalek::VerifyingKey::from_bytes(&public)
                .unwrap()
                .verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &signature)
                .is_ok()
        );
    }

    #[test]
    fn a_p256_token_names_es256_and_verifies() {
        let secret = SigningSecret::p256_from_slice(&[5; 32]).unwrap();
        let header = object(json!({ "kid": "k" }));
        let payload = object(json!({ "a": 1 }));

        let jws = sign_jws(&secret, &header, JwsPayload::Json(&payload), no_x5c()).unwrap();

        let parts: Vec<&str> = jws.split('.').collect();
        let protected: Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0]).unwrap()).unwrap();
        assert_eq!(protected["alg"], "ES256");
        let verifying = p256::ecdsa::VerifyingKey::from_sec1_bytes(&secret.public_key()).unwrap();
        let signature =
            p256::ecdsa::Signature::from_slice(&URL_SAFE_NO_PAD.decode(parts[2]).unwrap()).unwrap();
        assert!(
            verifying
                .verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &signature)
                .is_ok()
        );
    }

    #[test]
    fn a_refused_header_signs_nothing() {
        let secret = SigningSecret::ed25519([3; 32]);
        let header = object(json!({ "alg": "none" }));

        assert_eq!(
            sign_jws(&secret, &header, JwsPayload::Base64Url("QQ"), no_x5c()),
            Err(FormatRefusal::HeaderMemberForbidden("alg".to_string()))
        );
    }
}
