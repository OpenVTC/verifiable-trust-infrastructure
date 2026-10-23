//! `keys/sign-jws/0.1` — produce a compact JWS (a JWT) over a caller-supplied
//! JOSE header and claims set, signed by a stored key.
//!
//! Unlike [`super::sign::SignRequestBody`] this is **not** a general signing
//! oracle. The VTA builds the signing input itself —
//! `b64url(header).b64url(payload)` — and the finalized protected header is
//! constrained two ways before anything is signed:
//!
//! 1. its `typ` must be on [`JWS_ALLOWED_TYPS`], so the result can only ever be
//!    read as one of a small set of JWT profiles and never as a Data-Integrity
//!    credential proof, a task envelope, or an unframed assertion; and
//! 2. the VTA, not the caller, sets `alg` from the key, so a caller cannot
//!    request a signature under an algorithm the key does not implement or
//!    mislabel the one it does.
//!
//! The payload must be a JSON object (a JWT claims set); raw bytes go through
//! the opaque oracle, not here. Together these mean a signature this task
//! produces verifies as *an allow-listed JWT and nothing else*, which is what
//! lets a JWT-signing key be kept separate from a credential/issuer key.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use super::sign::SignAlgorithm;

/// The JOSE `typ` values this task will sign. Anything else is refused, so the
/// task can never be pointed at producing a credential or other non-JWT
/// artifact. The OAuth/OIDC entries are spelled exactly as the relevant RFCs
/// register them.
///
/// `gateway-issuer-attestation+jwt` is **not** IANA-registered — it is an
/// application type belonging to the Agent Gateway, which uses it to tell a
/// peer gateway which issuer DID stands behind a connection. It is listed for
/// the same reason the registered ones are: it names a JWT profile, so
/// permitting it widens nothing structurally. The alternative was the gateway
/// signing that artifact with a locally held key, which is the custody this
/// task exists to remove. Adding an application type here is only safe while
/// it is a JWT profile — anything that would be read as a credential proof or
/// a task envelope must stay off this list however convenient.
pub const JWS_ALLOWED_TYPS: &[&str] = &[
    "JWT",
    "at+jwt",
    "oauth-id-jag+jwt",
    "dpop+jwt",
    "logout+jwt",
    "gateway-issuer-attestation+jwt",
];

/// Body of a `keys/sign-jws/0.1` request.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct SignJwsRequestBody {
    /// Key ID to sign with. Authorized exactly as a `keys/sign` request is —
    /// per the key's context — so the same context-separation that walls off a
    /// signer's identities applies here.
    #[serde(rename = "keyId", alias = "key_id")]
    pub key_id: String,
    /// JOSE protected-header members supplied by the caller — e.g.
    /// `{ "typ": "JWT" }`. `typ` must be on [`JWS_ALLOWED_TYPS`]; when omitted
    /// it defaults to `"JWT"`. Any caller-supplied `alg` is ignored: the VTA
    /// sets it from the key.
    #[serde(default)]
    pub header: Value,
    /// JWT claims set — must be a JSON object.
    pub payload: Value,
    /// Signing algorithm (must match the key type).
    pub algorithm: SignAlgorithm,
}

/// Body of a `keys/sign-jws/0.1` result.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct SignJwsResultBody {
    /// Compact JWS: `b64url(header).b64url(payload).b64url(signature)`.
    pub jws: String,
}

/// Why a `keys/sign-jws` request was refused before any signing happened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignJwsError {
    /// `header` was present but not a JSON object.
    HeaderNotObject,
    /// `payload` was not a JSON object (a JWT claims set).
    PayloadNotObject,
    /// `header.typ` was present but not a string.
    TypNotString,
    /// `header.typ` is not on [`JWS_ALLOWED_TYPS`].
    TypNotAllowed(String),
}

impl std::fmt::Display for SignJwsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HeaderNotObject => write!(f, "header must be a JSON object"),
            Self::PayloadNotObject => {
                write!(f, "payload must be a JSON object (a JWT claims set)")
            }
            Self::TypNotString => write!(f, "header.typ must be a string"),
            Self::TypNotAllowed(t) => write!(
                f,
                "header.typ {t:?} is not a permitted JWT type; allowed: {JWS_ALLOWED_TYPS:?}"
            ),
        }
    }
}

impl std::error::Error for SignJwsError {}

/// The JOSE `alg` label for `algorithm`, spelled as the IANA JOSE registry does.
#[must_use]
pub fn jose_alg(algorithm: &SignAlgorithm) -> &'static str {
    match algorithm {
        SignAlgorithm::EdDSA => "EdDSA",
        SignAlgorithm::ES256 => "ES256",
    }
}

/// Validate the caller header's `typ` against [`JWS_ALLOWED_TYPS`] and return
/// the finalized protected header: the caller's members, with `typ` defaulted
/// to `"JWT"` and `alg` set by the VTA from `algorithm` (overriding any
/// caller-supplied `alg`).
///
/// This is the whole wall-off, done before the key is ever touched: a header
/// that is not an object, or whose `typ` is not allow-listed, is refused here.
pub fn finalize_protected_header(
    caller: &Value,
    algorithm: &SignAlgorithm,
) -> Result<Map<String, Value>, SignJwsError> {
    let mut header = match caller {
        Value::Null => Map::new(),
        Value::Object(m) => m.clone(),
        _ => return Err(SignJwsError::HeaderNotObject),
    };

    match header.get("typ") {
        None => {
            header.insert("typ".to_owned(), Value::String("JWT".to_owned()));
        }
        Some(Value::String(t)) => {
            if !JWS_ALLOWED_TYPS.contains(&t.as_str()) {
                return Err(SignJwsError::TypNotAllowed(t.clone()));
            }
        }
        Some(_) => return Err(SignJwsError::TypNotString),
    }

    header.insert(
        "alg".to_owned(),
        Value::String(jose_alg(algorithm).to_owned()),
    );
    Ok(header)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn defaults_typ_to_jwt_and_sets_alg() {
        let header = finalize_protected_header(&Value::Null, &SignAlgorithm::EdDSA).unwrap();
        assert_eq!(header.get("typ").unwrap(), "JWT");
        assert_eq!(header.get("alg").unwrap(), "EdDSA");
    }

    #[test]
    fn vta_sets_alg_overriding_caller() {
        let header =
            finalize_protected_header(&json!({ "alg": "none" }), &SignAlgorithm::ES256).unwrap();
        assert_eq!(header.get("alg").unwrap(), "ES256");
    }

    #[test]
    fn accepts_allow_listed_typ() {
        for typ in JWS_ALLOWED_TYPS {
            let header =
                finalize_protected_header(&json!({ "typ": typ }), &SignAlgorithm::EdDSA).unwrap();
            assert_eq!(header.get("typ").unwrap(), typ);
        }
    }

    #[test]
    fn refuses_non_allow_listed_typ() {
        let err = finalize_protected_header(&json!({ "typ": "vc+ld+json" }), &SignAlgorithm::EdDSA)
            .unwrap_err();
        assert_eq!(err, SignJwsError::TypNotAllowed("vc+ld+json".to_owned()));
    }

    #[test]
    fn refuses_non_object_header() {
        let err = finalize_protected_header(&json!("JWT"), &SignAlgorithm::EdDSA).unwrap_err();
        assert_eq!(err, SignJwsError::HeaderNotObject);
    }

    #[test]
    fn refuses_non_string_typ() {
        let err =
            finalize_protected_header(&json!({ "typ": 1 }), &SignAlgorithm::EdDSA).unwrap_err();
        assert_eq!(err, SignJwsError::TypNotString);
    }
}
