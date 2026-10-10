//! Compact-JWS verification over a resolved public key — the one place an
//! SD-JWT-VC issuer signature or holder key-binding JWT is checked.
//!
//! Three signature algorithms, one per curve this workspace verifies on
//! behalf of a credential:
//!
//! | Key | JWS `alg` |
//! |---|---|
//! | Ed25519 | `EdDSA` (or the fully-specified `Ed25519`, RFC 9864) |
//! | P-256 | `ES256` |
//! | secp256k1 | `ES256K` (RFC 8812) |
//!
//! P-256 is what the Swiss swiyu stack and the EU EUDI profiles issue with
//! and bind holders to (#1988); secp256k1 is accepted alongside it so a
//! wallet keyed on that curve is not refused for the curve alone.
//!
//! # The algorithm comes from the key, never from the token
//!
//! A JWS names its own `alg`, and a verifier that believes it can be talked
//! into checking the signature under an algorithm the key was never meant for.
//! Here the key is resolved first — from the issuer's DID document, or from the
//! `cnf.jwk` the issuer signed — and the header's `alg` must be the one that
//! key's curve uses. A mismatch is refused before any signature work, as is a
//! header carrying `crit` (RFC 7515 §4.1.11: an extension this verifier does
//! not understand must not be ignored).
//!
//! Elliptic-curve keys are held as **compressed SEC1 points**, so the same key
//! reaches the same [`JwsKey`] — and the same `did:key` — whether it arrived as
//! a JWK, a `Multikey`, or an uncompressed point. A point is checked to lie on
//! its curve when a signature is verified against it.

use affinidi_data_integrity::ResolvedKey;
use affinidi_secrets_resolver::secrets::KeyType;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::Value;

/// Multicodec varint prefixes for the public keys a [`JwsKey`] can hold, as
/// written in a `did:key` (`ed25519-pub` 0xed, `p256-pub` 0x1200,
/// `secp256k1-pub` 0xe7).
const ED25519_PUB: [u8; 2] = [0xed, 0x01];
const P256_PUB: [u8; 2] = [0x80, 0x24];
const SECP256K1_PUB: [u8; 2] = [0xe7, 0x01];

/// Why a JWS, or the key that should verify it, was refused.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum JwsError {
    /// The token is not a well-formed compact JWS with a JSON header and
    /// payload.
    #[error("malformed JWS: {0}")]
    Malformed(String),
    /// The header's `alg` is not the algorithm the verifying key's curve
    /// signs with.
    #[error("JWS alg `{found}` does not match the {curve} key that must verify it (want {want})")]
    AlgMismatch {
        found: String,
        want: &'static str,
        curve: &'static str,
    },
    /// The header marks an extension critical (`crit`), which this verifier
    /// does not implement.
    #[error("JWS header carries `crit`, which this verifier does not support")]
    CriticalHeader,
    /// The key is not one this module verifies with, or is malformed.
    #[error("unsupported or malformed key: {0}")]
    Key(String),
    /// The issuer, or the verification method named for it, cannot be used.
    #[error("{0}")]
    Issuer(String),
    /// The signature did not verify under the key.
    #[error("signature did not verify")]
    BadSignature,
}

/// A public key a compact JWS can be verified against.
///
/// Elliptic-curve points are stored compressed (33 bytes), so equality and
/// [`Self::did_key`] do not depend on how the key was encoded on arrival.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum JwsKey {
    /// An Ed25519 public key — `alg: EdDSA`.
    Ed25519([u8; 32]),
    /// A P-256 public key as a compressed SEC1 point — `alg: ES256`.
    P256(Vec<u8>),
    /// A secp256k1 public key as a compressed SEC1 point — `alg: ES256K`.
    Secp256k1(Vec<u8>),
}

impl JwsKey {
    /// The key a DID verification method resolved to.
    ///
    /// Refuses any key type other than the three this module verifies with —
    /// an X25519 key-agreement key or an ML-DSA key signs no JWS here.
    pub fn from_resolved(key: &ResolvedKey) -> Result<Self, JwsError> {
        let bytes = key.public_key_bytes.as_slice();
        match key.key_type {
            KeyType::Ed25519 => {
                let arr: [u8; 32] = bytes.try_into().map_err(|_| {
                    JwsError::Key(format!("Ed25519 key is {} bytes, not 32", bytes.len()))
                })?;
                Ok(Self::Ed25519(arr))
            }
            KeyType::P256 => Ok(Self::P256(compress_sec1(bytes, "P-256")?)),
            KeyType::Secp256k1 => Ok(Self::Secp256k1(compress_sec1(bytes, "secp256k1")?)),
            other => Err(JwsError::Key(format!(
                "a {other:?} key does not verify JWS signatures here (Ed25519, P-256 and \
                 secp256k1 do)"
            ))),
        }
    }

    /// A public JWK — the `cnf.jwk` an issuer binds a holder to (RFC 7800).
    ///
    /// Accepts OKP/Ed25519 (RFC 8037) and EC with `crv` `P-256` or `secp256k1`.
    /// A JWK carrying a private component (`d`) is refused: a holder-binding
    /// key that discloses its private half binds nobody.
    pub fn from_jwk(jwk: &Value) -> Result<Self, JwsError> {
        if jwk.get("d").is_some() {
            return Err(JwsError::Key(
                "the JWK carries a private key (`d`); a binding key must be public".into(),
            ));
        }
        let member = |name: &str| -> Result<Vec<u8>, JwsError> {
            let s = jwk
                .get(name)
                .and_then(Value::as_str)
                .ok_or_else(|| JwsError::Key(format!("the JWK has no `{name}`")))?;
            URL_SAFE_NO_PAD
                .decode(s)
                .map_err(|e| JwsError::Key(format!("the JWK `{name}` is not base64url: {e}")))
        };
        let kty = jwk.get("kty").and_then(Value::as_str);
        let crv = jwk.get("crv").and_then(Value::as_str);
        match (kty, crv) {
            (Some("OKP"), Some("Ed25519")) => {
                let x = member("x")?;
                let arr: [u8; 32] = x.as_slice().try_into().map_err(|_| {
                    JwsError::Key(format!("the Ed25519 JWK `x` is {} bytes, not 32", x.len()))
                })?;
                Ok(Self::Ed25519(arr))
            }
            (Some("EC"), Some(crv @ ("P-256" | "secp256k1"))) => {
                let (x, y) = (member("x")?, member("y")?);
                if x.len() != 32 || y.len() != 32 {
                    return Err(JwsError::Key(format!(
                        "the {crv} JWK coordinates must be 32 bytes each (x={}, y={})",
                        x.len(),
                        y.len()
                    )));
                }
                let mut point = Vec::with_capacity(65);
                point.push(0x04);
                point.extend_from_slice(&x);
                point.extend_from_slice(&y);
                let compressed = compress_sec1(&point, crv)?;
                Ok(if crv == "P-256" {
                    Self::P256(compressed)
                } else {
                    Self::Secp256k1(compressed)
                })
            }
            _ => Err(JwsError::Key(format!(
                "a JWK with kty {kty:?} and crv {crv:?} is not supported (OKP/Ed25519, EC/P-256 \
                 and EC/secp256k1 are)"
            ))),
        }
    }

    /// The curve's name, for messages.
    #[must_use]
    pub fn curve(&self) -> &'static str {
        match self {
            Self::Ed25519(_) => "Ed25519",
            Self::P256(_) => "P-256",
            Self::Secp256k1(_) => "secp256k1",
        }
    }

    /// The JWS `alg` this key signs with.
    #[must_use]
    pub fn alg(&self) -> &'static str {
        match self {
            Self::Ed25519(_) => "EdDSA",
            Self::P256(_) => "ES256",
            Self::Secp256k1(_) => "ES256K",
        }
    }

    /// Whether `alg` names this key's algorithm. Ed25519 also answers to the
    /// fully-specified `Ed25519` of RFC 9864.
    #[must_use]
    pub fn accepts_alg(&self, alg: &str) -> bool {
        match self {
            Self::Ed25519(_) => matches!(alg, "EdDSA" | "Ed25519"),
            Self::P256(_) => alg == "ES256",
            Self::Secp256k1(_) => alg == "ES256K",
        }
    }

    /// The `did:key` that names this key.
    #[must_use]
    pub fn did_key(&self) -> String {
        let (prefix, bytes): (&[u8], &[u8]) = match self {
            Self::Ed25519(k) => (&ED25519_PUB, k),
            Self::P256(k) => (&P256_PUB, k),
            Self::Secp256k1(k) => (&SECP256K1_PUB, k),
        };
        let mb = multibase::encode(multibase::Base::Base58Btc, [prefix, bytes].concat());
        format!("did:key:{mb}")
    }

    /// Verify a compact JWS (`header.payload.signature`) under this key and
    /// return its payload.
    ///
    /// The header's `alg` must be this key's ([`Self::accepts_alg`]) and the
    /// header must not carry `crit`; both are checked before the signature.
    /// Ed25519 verifies strictly (no small-order keys, canonical `S`).
    pub fn verify_compact(&self, jws: &str) -> Result<Value, JwsError> {
        let mut parts = jws.split('.');
        let (Some(header_b64), Some(payload_b64), Some(sig_b64), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(JwsError::Malformed(
                "not three dot-separated segments".into(),
            ));
        };

        let header = decode_json(header_b64, "header")?;
        let alg = header
            .get("alg")
            .and_then(Value::as_str)
            .ok_or_else(|| JwsError::Malformed("header has no `alg`".into()))?;
        if !self.accepts_alg(alg) {
            return Err(JwsError::AlgMismatch {
                found: alg.to_string(),
                want: self.alg(),
                curve: self.curve(),
            });
        }
        if header.get("crit").is_some() {
            return Err(JwsError::CriticalHeader);
        }

        let signing_input = format!("{header_b64}.{payload_b64}");
        let sig = URL_SAFE_NO_PAD
            .decode(sig_b64)
            .map_err(|e| JwsError::Malformed(format!("signature is not base64url: {e}")))?;
        self.verify_signature(signing_input.as_bytes(), &sig)?;

        decode_json(payload_b64, "payload")
    }

    /// Verify a raw signature over `data`: 64 bytes for every curve here
    /// (Ed25519, or ECDSA `r || s` as JWS encodes it, RFC 7518 §3.4).
    fn verify_signature(&self, data: &[u8], sig: &[u8]) -> Result<(), JwsError> {
        let sig: [u8; 64] = sig.try_into().map_err(|_| {
            JwsError::Malformed(format!(
                "a {} signature is 64 bytes, this one is {}",
                self.alg(),
                sig.len()
            ))
        })?;
        match self {
            Self::Ed25519(key) => {
                let vk = ed25519_dalek::VerifyingKey::from_bytes(key)
                    .map_err(|e| JwsError::Key(format!("invalid Ed25519 key: {e}")))?;
                vk.verify_strict(data, &ed25519_dalek::Signature::from_bytes(&sig))
                    .map_err(|_| JwsError::BadSignature)
            }
            Self::P256(point) => affinidi_crypto::jose::signing::verify_p256(data, &sig, point)
                .map_err(|_| JwsError::BadSignature),
            Self::Secp256k1(point) => {
                affinidi_crypto::jose::signing::verify_secp256k1(data, &sig, point)
                    .map_err(|_| JwsError::BadSignature)
            }
        }
    }
}

/// The verification method an SD-JWT-VC issuer JWS was signed with, bound to
/// its `iss`.
///
/// - A `kid` must name a method of `iss`: an absolute DID URL under it, or a
///   bare `#fragment` read against it. A key of some *other* DID must not sign
///   a credential claiming this issuer.
/// - A `did:key` issuer has one key, the identifier, and that is the method
///   returned whatever fragment its `kid` carries (issuers here write
///   `{did}#key-0`), or with no `kid` at all.
/// - Any other DID publishes several keys, and the SD-JWT VC specification has
///   a DID issuer name the one that signed with a DID-URL `kid`. Without one
///   the credential is refused; guessing among the keys is not done here.
/// - `iss` must be a DID. An HTTPS issuer (JWT VC Issuer Metadata) is not
///   supported.
pub fn sd_jwt_issuer_method(header: &Value, iss: &str) -> Result<String, JwsError> {
    if !iss.starts_with("did:") || iss.contains('#') {
        return Err(JwsError::Issuer(format!(
            "issuer `{iss}` is not a DID; only DID issuers are supported"
        )));
    }
    let did_key_method = iss
        .strip_prefix("did:key:")
        .filter(|id| !id.is_empty())
        .map(|id| format!("{iss}#{id}"));
    match header.get("kid") {
        Some(Value::String(kid)) => {
            let vm = if kid.starts_with('#') {
                format!("{iss}{kid}")
            } else {
                kid.clone()
            };
            match vm.split_once('#') {
                Some((base, fragment)) if base == iss && !fragment.is_empty() => {
                    Ok(did_key_method.unwrap_or(vm))
                }
                _ => Err(JwsError::Issuer(format!(
                    "issuer kid `{kid}` is not a verification method of `iss` (`{iss}`)"
                ))),
            }
        }
        Some(_) => Err(JwsError::Issuer("issuer kid is not a string".into())),
        None => did_key_method.ok_or_else(|| {
            JwsError::Issuer(format!(
                "the issuer JWS has no `kid`; a `{iss}` issuer must name the verification \
                 method that signed with a DID-URL kid"
            ))
        }),
    }
}

/// Compress an SEC1 point (33-byte compressed or 65-byte uncompressed).
fn compress_sec1(bytes: &[u8], curve: &str) -> Result<Vec<u8>, JwsError> {
    match bytes {
        [0x02 | 0x03, rest @ ..] if rest.len() == 32 => Ok(bytes.to_vec()),
        [0x04, rest @ ..] if rest.len() == 64 => {
            let (x, y) = rest.split_at(32);
            let mut out = Vec::with_capacity(33);
            out.push(if y[31] & 1 == 0 { 0x02 } else { 0x03 });
            out.extend_from_slice(x);
            Ok(out)
        }
        _ => Err(JwsError::Key(format!(
            "a {curve} key must be a 33- or 65-byte SEC1 point, this one is {} bytes",
            bytes.len()
        ))),
    }
}

fn decode_json(segment: &str, what: &str) -> Result<Value, JwsError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(segment)
        .map_err(|e| JwsError::Malformed(format!("{what} is not base64url: {e}")))?;
    let value: Value = serde_json::from_slice(&bytes)
        .map_err(|e| JwsError::Malformed(format!("{what} is not JSON: {e}")))?;
    if !value.is_object() {
        return Err(JwsError::Malformed(format!("{what} is not a JSON object")));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// The issuer JWS of the IterationSeal SD-JWT-VC attached to #1988: ES256,
    /// issued by `did:web:validant.ai` with a throwaway P-256 key, published
    /// beside it as a JWK.
    const ISSUE_1988_JWS: &str = "eyJ0eXAiOiJkYytzZC1qd3QiLCJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJkaWQ6d2ViOnZhbGlkYW50LmFpIiwidmN0IjoiaHR0cHM6Ly92YWxpZGFudC5haS9jcmVkZW50aWFscy9JdGVyYXRpb25TZWFsIiwiYXNzZXNzbWVudF9pZCI6IjNmMmE5YzFlLThiNDctNGQyYS05ZTZmLTFjNWI3YTBkNGUyMSIsIml0ZXJhdGlvbl9udW1iZXIiOjIsImNvbnRyYWN0dWFsX21ldHJpYyI6ImRlbW9ncmFwaGljX3Bhcml0eSIsInZlcmRpY3QiOiJwYXNzIiwiYmFuZCI6ImFkZXF1YXRlIiwibGVpIjoiOTg0NTAwOUI2OERONzZJNUY1MTAiLCJwb2ludGluZyI6eyJib2R5IjoiTW9kZWwiLCJwYXRod2F5IjoiaGlyaW5nL0NWLXNjcmVlbmluZyIsImF1ZGllbmNlIjpbInN1YmplY3QiXX0sImFzc3VyYW5jZV9wcm9maWxlIjp7ImFjY2VzcyI6IkEzIiwiZXZpZGVuY2UiOiJFMiIsInZhbGlkaXR5IjoiVjIiLCJhc3N1cmFuY2VfY2xhc3MiOiJyZWFzb25hYmxlIiwiY2VpbGluZyI6InJlYXNvbmFibGUiLCJsaW1pdGluZyI6WyJhY2Nlc3MiLCJldmlkZW5jZSIsInZhbGlkaXR5Il0sIm1pbl9kZXRlY3RhYmxlX2VmZmVjdCI6MC4wNDMsImZyb250aWVyIjp7ImludGVydmVudGlvbmFsIjoibm90X29mZmVyZWQiLCJmdWxsX2xpbmVhZ2UiOiJub3Rfb2ZmZXJlZCIsImNvbnRpbnVvdXMiOiJub3Rfb2ZmZXJlZCJ9LCJjYWxpYnJhdGlvbiI6IjIwMjYtMDgifSwiY29udGVudF9oYXNoIjoiMzEwNTYzNzE4ZTA2ZjdjNzI0ODE2OGUyYjRiZTk1MjZlZDQ2MWExOWU3YjhhYmFjYWJiMWY5ZWYwZTkwYzE4ZCIsImlhdCI6MTc4NTk3NDQwMCwiZXhwIjoxODE3NTEwNDAwLCJfc2QiOlsiU2xfR0ZSRXFuMU9nSEd2Y1lLekNxSVM5SFBiZW01ZzhVaWphWDF3RExZSSJdLCJfc2RfYWxnIjoic2hhLTI1NiJ9.02oW1G8gG29v0lp4vGG3nweHVJ5mjq6guWhQjFmy_lmC69Zup4iYMJNQeOOU21pfq86qqBWjTqjnqCvGi7mL9g";

    fn issue_1988_key() -> JwsKey {
        JwsKey::from_jwk(&json!({
            "kty": "EC",
            "crv": "P-256",
            "x": "4l-EPRfWGZNnax8JVqmG0PQTKTEB-4GNomZXQcWow7E",
            "y": "WZeIPkJVmeEdc8FKcx1OeMt8dDYM59QHVMhVoCQFoNQ",
        }))
        .expect("the vector's issuer JWK")
    }

    fn b64(v: &Value) -> String {
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(v).unwrap())
    }

    /// Sign `header.payload` with `sign`, returning the compact JWS.
    fn compact(header: &Value, payload: &Value, sign: impl Fn(&[u8]) -> Vec<u8>) -> String {
        let input = format!("{}.{}", b64(header), b64(payload));
        let sig = sign(input.as_bytes());
        format!("{input}.{}", URL_SAFE_NO_PAD.encode(sig))
    }

    /// #1988: a real ES256 issuer signature from the swiyu-stack signer
    /// verifies, and yields the issuer-protected claims.
    #[test]
    fn the_issue_1988_es256_vector_verifies() {
        let payload = issue_1988_key()
            .verify_compact(ISSUE_1988_JWS)
            .expect("ES256 interop with the reporter's signer");
        assert_eq!(payload["iss"], "did:web:validant.ai");
        assert_eq!(payload["verdict"], "pass");
    }

    #[test]
    fn a_tampered_es256_payload_is_refused() {
        let mut parts: Vec<&str> = ISSUE_1988_JWS.split('.').collect();
        let forged = b64(&json!({"iss": "did:web:validant.ai", "verdict": "fail"}));
        parts[1] = &forged;
        let err = issue_1988_key()
            .verify_compact(&parts.join("."))
            .expect_err("a changed payload must not verify");
        assert!(matches!(err, JwsError::BadSignature), "{err}");
    }

    /// The algorithm comes from the key: an ES256 token never verifies under
    /// an Ed25519 key, nor an EdDSA token under a P-256 key, and the refusal
    /// says which — before any signature work.
    #[test]
    fn the_header_alg_must_be_the_keys() {
        let ed = JwsKey::Ed25519([7; 32]);
        let err = ed.verify_compact(ISSUE_1988_JWS).unwrap_err();
        assert!(
            matches!(err, JwsError::AlgMismatch { want: "EdDSA", .. }),
            "{err}"
        );

        let sk = ed25519_dalek::SigningKey::from_bytes(&[9; 32]);
        let eddsa = compact(&json!({"alg": "EdDSA"}), &json!({"a": 1}), |m| {
            use ed25519_dalek::Signer;
            sk.sign(m).to_bytes().to_vec()
        });
        let err = issue_1988_key().verify_compact(&eddsa).unwrap_err();
        assert!(
            matches!(err, JwsError::AlgMismatch { want: "ES256", .. }),
            "{err}"
        );
        // …and under its own key, it verifies (also as `Ed25519`, RFC 9864).
        JwsKey::Ed25519(sk.verifying_key().to_bytes())
            .verify_compact(&eddsa)
            .expect("EdDSA under its own key");
    }

    #[test]
    fn a_critical_header_is_refused() {
        let sk = ed25519_dalek::SigningKey::from_bytes(&[9; 32]);
        let token = compact(
            &json!({"alg": "EdDSA", "crit": ["b64"], "b64": false}),
            &json!({"a": 1}),
            |m| {
                use ed25519_dalek::Signer;
                sk.sign(m).to_bytes().to_vec()
            },
        );
        let err = JwsKey::Ed25519(sk.verifying_key().to_bytes())
            .verify_compact(&token)
            .unwrap_err();
        assert!(matches!(err, JwsError::CriticalHeader), "{err}");
    }

    /// ES256 round trip with a P-256 key minted here, and the same key reached
    /// from a JWK and from an uncompressed point is one key with one did:key.
    #[test]
    fn es256_round_trip_and_one_key_however_encoded() {
        let kp = affinidi_crypto::p256::generate(Some(&[0x31; 32])).unwrap();
        let token = compact(&json!({"alg": "ES256"}), &json!({"a": 1}), |m| {
            affinidi_crypto::p256::sign(&kp.private_bytes, m).unwrap()
        });
        let from_point =
            JwsKey::from_resolved(&ResolvedKey::new(KeyType::P256, kp.public_bytes.clone()))
                .unwrap();
        from_point.verify_compact(&token).expect("ES256 verifies");

        let mut jwk = serde_json::to_value(&kp.jwk).unwrap();
        jwk.as_object_mut().unwrap().remove("d");
        let from_jwk = JwsKey::from_jwk(&jwk).unwrap();
        assert_eq!(from_point, from_jwk);
        assert!(
            from_jwk.did_key().starts_with("did:key:zDn"),
            "{}",
            from_jwk.did_key()
        );
    }

    #[test]
    fn es256k_round_trip() {
        use k256::ecdsa::signature::Signer;
        let seed = [0x41; 32];
        let kp = affinidi_crypto::secp256k1::generate(Some(&seed)).unwrap();
        let sk = k256::ecdsa::SigningKey::from_slice(&seed).unwrap();
        let token = compact(&json!({"alg": "ES256K"}), &json!({"a": 1}), |m| {
            let sig: k256::ecdsa::Signature = sk.sign(m);
            sig.to_bytes().to_vec()
        });
        let mut jwk = serde_json::to_value(&kp.jwk).unwrap();
        jwk.as_object_mut().unwrap().remove("d");
        let key = JwsKey::from_jwk(&jwk).unwrap();
        key.verify_compact(&token).expect("ES256K verifies");
        assert!(
            key.did_key().starts_with("did:key:zQ3s"),
            "{}",
            key.did_key()
        );

        // An ES256 header on the same bytes is refused for its algorithm.
        let err = key
            .verify_compact(&token.replacen(
                &b64(&json!({"alg": "ES256K"})),
                &b64(&json!({"alg": "ES256"})),
                1,
            ))
            .unwrap_err();
        assert!(matches!(err, JwsError::AlgMismatch { .. }), "{err}");
    }

    #[test]
    fn a_jwk_carrying_a_private_key_is_refused() {
        let kp = affinidi_crypto::p256::generate(Some(&[0x31; 32])).unwrap();
        let err = JwsKey::from_jwk(&serde_json::to_value(&kp.jwk).unwrap()).unwrap_err();
        assert!(err.to_string().contains("private"), "{err}");
    }

    #[test]
    fn unsupported_keys_are_named() {
        let err =
            JwsKey::from_jwk(&json!({"kty": "EC", "crv": "P-384", "x": "", "y": ""})).unwrap_err();
        assert!(err.to_string().contains("not supported"), "{err}");
        let err =
            JwsKey::from_resolved(&ResolvedKey::new(KeyType::X25519, vec![0; 32])).unwrap_err();
        assert!(err.to_string().contains("does not verify"), "{err}");
    }

    /// The issuer method: a `kid` under `iss` (absolute or relative), a
    /// did:key's own key without one, and nothing guessed for a DID that
    /// publishes several keys.
    #[test]
    fn the_issuer_method_is_bound_to_iss() {
        let web = "did:web:validant.ai";
        assert_eq!(
            sd_jwt_issuer_method(&json!({"kid": "did:web:validant.ai#k1"}), web).unwrap(),
            "did:web:validant.ai#k1"
        );
        assert_eq!(
            sd_jwt_issuer_method(&json!({"kid": "#k1"}), web).unwrap(),
            "did:web:validant.ai#k1"
        );
        for bad in [
            json!({"kid": "did:web:evil.example#k1"}),
            json!({"kid": "did:web:validant.ai"}),
            json!({"kid": "did:web:validant.ai#"}),
            json!({"kid": 7}),
        ] {
            assert!(sd_jwt_issuer_method(&bad, web).is_err(), "{bad}");
        }
        // The #1988 vector's header: no kid on a did:web issuer.
        let err =
            sd_jwt_issuer_method(&json!({"typ": "dc+sd-jwt", "alg": "ES256"}), web).unwrap_err();
        assert!(err.to_string().contains("DID-URL kid"), "{err}");

        let dk = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";
        assert_eq!(
            sd_jwt_issuer_method(&json!({}), dk).unwrap(),
            format!("{dk}#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK")
        );
        // A did:key's own key whatever the kid's fragment, but still only a
        // kid under that did:key.
        assert_eq!(
            sd_jwt_issuer_method(&json!({"kid": format!("{dk}#key-0")}), dk).unwrap(),
            format!("{dk}#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK")
        );
        assert!(sd_jwt_issuer_method(&json!({"kid": "did:key:zOther#key-0"}), dk).is_err());
        assert!(sd_jwt_issuer_method(&json!({}), "https://issuer.example").is_err());
    }
}
