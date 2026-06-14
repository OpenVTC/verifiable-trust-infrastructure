//! Shared JWT / temporal / JWK helpers for the credential-exchange
//! issue + verify + pending submodules (split out of `exchange.rs`, P2.3).

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Utc};
use ed25519_dalek::VerifyingKey;
use serde_json::Value;
use vti_common::error::AppError;

/// Enforce W3C VCDM v2 temporal validity (`validFrom` / `validUntil`, RFC-3339).
pub(super) fn check_w3c_temporal(vc: &Value, now: DateTime<Utc>) -> Result<(), AppError> {
    if let Some(vf) = vc.get("validFrom").and_then(Value::as_str) {
        let vf = DateTime::parse_from_rfc3339(vf)
            .map_err(|e| AppError::Validation(format!("DI VC `validFrom` is not RFC-3339: {e}")))?;
        if now < vf {
            return Err(AppError::Validation(
                "DI VC is not yet valid (`validFrom` in the future)".into(),
            ));
        }
    }
    if let Some(vu) = vc.get("validUntil").and_then(Value::as_str) {
        let vu = DateTime::parse_from_rfc3339(vu).map_err(|e| {
            AppError::Validation(format!("DI VC `validUntil` is not RFC-3339: {e}"))
        })?;
        if now > vu {
            return Err(AppError::Validation(
                "DI VC has expired (`validUntil` in the past)".into(),
            ));
        }
    }
    Ok(())
}

/// Build a verifying key from an RFC 8037 OKP / Ed25519 JWK (the `cnf.jwk`).
pub(super) fn ed25519_from_okp_jwk(jwk: &Value) -> Result<VerifyingKey, AppError> {
    if jwk.get("kty").and_then(Value::as_str) != Some("OKP")
        || jwk.get("crv").and_then(Value::as_str) != Some("Ed25519")
    {
        return Err(AppError::Validation(
            "cnf.jwk is not an OKP / Ed25519 key".into(),
        ));
    }
    let x = jwk
        .get("x")
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::Validation("cnf.jwk has no `x`".into()))?;
    let bytes = URL_SAFE_NO_PAD
        .decode(x)
        .map_err(|e| AppError::Validation(format!("cnf.jwk `x` is not base64url: {e}")))?;
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| AppError::Validation("cnf.jwk `x` is not 32 bytes".into()))?;
    VerifyingKey::from_bytes(&arr)
        .map_err(|e| AppError::Validation(format!("cnf.jwk key is invalid: {e}")))
}

/// Enforce temporal validity over the presentation's protected claims.
pub(super) fn check_temporal(claims: &Value, now: DateTime<Utc>) -> Result<(), AppError> {
    let now_s = now.timestamp();
    if let Some(nbf) = claims.get("nbf").and_then(Value::as_i64)
        && now_s < nbf
    {
        return Err(AppError::Validation(
            "presentation is not yet valid (`nbf` in the future)".into(),
        ));
    }
    if let Some(exp) = claims.get("exp").and_then(Value::as_i64)
        && now_s > exp
    {
        return Err(AppError::Validation(
            "presentation has expired (`exp` in the past)".into(),
        ));
    }
    Ok(())
}

/// Decode a base64url JWT segment into JSON.
pub(super) fn decode_segment(segment: &str, what: &str) -> Result<Value, AppError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(segment)
        .map_err(|e| AppError::Validation(format!("{what} is not base64url: {e}")))?;
    serde_json::from_slice(&bytes)
        .map_err(|e| AppError::Validation(format!("{what} is not JSON: {e}")))
}

/// OID4VCI `aud` may be a single string or an array of strings; match either.
pub(super) fn aud_matches(aud: Option<&Value>, expected: &str) -> bool {
    match aud {
        Some(Value::String(s)) => s == expected,
        Some(Value::Array(items)) => items.iter().any(|v| v.as_str() == Some(expected)),
        _ => false,
    }
}
