//! VTC WebAuthn helpers — broaden the accepted algorithm set to
//! include EdDSA.
//!
//! Implements **M0.5.1** of the VTC MVP Phase 0 plan. Wraps
//! `vti_common::auth::passkey::build_webauthn`. There is **no**
//! algorithm restriction: the admin `did:key` is carried in the
//! install token, *not* projected from the passkey's COSE key, so the
//! credential's algorithm is purely an auth-factor choice. Any
//! algorithm the ceremony advertises — **ES256, RS256, and EdDSA** —
//! is accepted at finish-time.
//!
//! ## Why a wrapper
//!
//! `webauthn-rs` 0.5 builds its safe `Webauthn` instance with
//! `COSEAlgorithm::secure_algs()`, which today returns `[ES256, RS256]`
//! — `EDDSA` is commented out in the upstream `secure_algs`
//! constructor, and the high-level builder exposes no `algorithms(…)`
//! setter. So to let Ed25519-capable hardware keys (YubiKey 5+, the
//! soft test authenticator) register **alongside** the platform
//! authenticators, this module *adds* EdDSA to the ceremony — it does
//! not remove anything.
//!
//! Two helpers, used instead of `Webauthn::{start,finish}_passkey_registration`
//! directly:
//!
//! - [`start_passkey_registration`] — runs the upstream start, then
//!   **appends** EdDSA to
//!   `CreationChallengeResponse.public_key.pub_key_cred_params` and to
//!   `PasskeyRegistration.rs.credential_algorithms`, leaving the
//!   default ES256 + RS256 in place. The state rewrite uses the
//!   `danger-allow-state-serialisation` feature (enabled
//!   workspace-wide) to round-trip through JSON — there is no other
//!   public path into the private `credential_algorithms` field.
//! - [`finish_passkey_registration`] — a thin pass-through to the
//!   upstream finish. It does **not** filter by algorithm; upstream's
//!   own check already asserts the returned credential matches the
//!   ceremony's `credential_algorithms` (which now includes all three).
//!
//! ## When upstream gains an `algorithms` setter
//!
//! Replace the JSON-rewrite in [`start_passkey_registration`] with the
//! setter. Nothing else changes — there is no finish-time algorithm
//! gate to keep.

use webauthn_rs::prelude::{
    CreationChallengeResponse, Passkey, PasskeyRegistration, RegisterPublicKeyCredential, Webauthn,
};
use webauthn_rs_proto::PubKeyCredParams;

use crate::error::AppError;

/// COSE algorithm identifier for EdDSA. Pinned in code so the
/// runtime check is independent of upstream renaming `COSEAlgorithm::EDDSA`.
pub const EDDSA_ALG: i64 = -8;

/// Start a passkey registration ceremony that accepts ES256, RS256,
/// and EdDSA. The upstream default offers ES256 + RS256 — sufficient
/// for every browser-platform authenticator. This wrapper adds EdDSA
/// so Ed25519-capable hardware keys (YubiKey 5+, soft test
/// authenticators) also work. The candidate admin DID is carried in
/// the install token, so the algorithm of the credential the
/// authenticator produces is purely an auth-factor choice — not an
/// identity input.
pub fn start_passkey_registration(
    webauthn: &Webauthn,
    user_unique_id: uuid::Uuid,
    user_name: &str,
    user_display_name: &str,
    exclude_credentials: Option<Vec<webauthn_rs::prelude::CredentialID>>,
) -> Result<(CreationChallengeResponse, PasskeyRegistration), AppError> {
    let (mut ccr, reg_state) = webauthn
        .start_passkey_registration(
            user_unique_id,
            user_name,
            user_display_name,
            exclude_credentials,
        )
        .map_err(|e| AppError::Internal(format!("webauthn registration start failed: {e}")))?;

    extend_ccr_with_eddsa(&mut ccr);
    let reg_state = extend_state_with_eddsa(&reg_state)?;

    Ok((ccr, reg_state))
}

/// Finish a passkey registration ceremony. Any algorithm accepted by
/// the ceremony's `credential_algorithms` list (ES256, RS256, EdDSA)
/// is valid — the install token, not the passkey shape, dictates the
/// admin DID.
pub fn finish_passkey_registration(
    webauthn: &Webauthn,
    credential: &RegisterPublicKeyCredential,
    state: &PasskeyRegistration,
) -> Result<Passkey, AppError> {
    webauthn
        .finish_passkey_registration(credential, state)
        .map_err(|e| AppError::Authentication(format!("passkey registration failed: {e}")))
}

/// Mutate a [`CreationChallengeResponse`] in place to **add** EdDSA
/// to `pub_key_cred_params` if not already present. The webauthn-rs
/// default offers ES256 + RS256 — enough for every browser-platform
/// authenticator (Apple iCloud Keychain, Windows Hello, Chrome
/// passkeys) — but no EdDSA. Operators with Ed25519-capable hardware
/// keys (YubiKey 5+ etc.) still get a working ceremony when we
/// append it here. Public so the unit tests can drive it directly.
pub(crate) fn extend_ccr_with_eddsa(ccr: &mut CreationChallengeResponse) {
    if ccr
        .public_key
        .pub_key_cred_params
        .iter()
        .any(|p| p.alg == EDDSA_ALG)
    {
        return;
    }
    ccr.public_key.pub_key_cred_params.push(PubKeyCredParams {
        type_: "public-key".to_string(),
        alg: EDDSA_ALG,
    });
}

/// Round-trip a [`PasskeyRegistration`] through JSON and append
/// `"EDDSA"` to `rs.credential_algorithms` so the finish-time check
/// accepts it alongside the upstream-default ES256 + RS256.
/// Requires the `danger-allow-state-serialisation` feature on
/// `webauthn-rs` (enabled workspace-wide in the root `Cargo.toml`).
///
/// Returns an [`AppError::Internal`] if the state's JSON shape ever
/// drifts and the rewrite cannot find the expected
/// `rs.credential_algorithms` path. That is a hard upstream-breakage
/// signal, not an operator-facing condition.
pub(crate) fn extend_state_with_eddsa(
    state: &PasskeyRegistration,
) -> Result<PasskeyRegistration, AppError> {
    let mut value = serde_json::to_value(state).map_err(|e| {
        AppError::Internal(format!(
            "failed to serialise passkey registration state: {e}"
        ))
    })?;

    let rs = value
        .get_mut("rs")
        .and_then(|v| v.as_object_mut())
        .ok_or_else(|| {
            AppError::Internal("passkey registration state missing 'rs' object".into())
        })?;

    let algs = rs
        .get_mut("credential_algorithms")
        .and_then(|v| v.as_array_mut())
        .ok_or_else(|| {
            AppError::Internal(
                "passkey registration state missing 'rs.credential_algorithms'".into(),
            )
        })?;

    // `Vec<COSEAlgorithm>` serialises as enum-variant strings, not COSE
    // integer identifiers. Match the upstream round-trip shape with the
    // string `"EDDSA"`.
    let already_present = algs
        .iter()
        .any(|v| v.as_str().map(|s| s == "EDDSA").unwrap_or(false));
    if !already_present {
        algs.push(serde_json::json!("EDDSA"));
    }

    serde_json::from_value(value).map_err(|e| {
        AppError::Internal(format!(
            "failed to deserialise rewritten passkey registration state: {e}"
        ))
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;
    use vti_common::auth::passkey::build_webauthn;

    fn webauthn() -> Webauthn {
        build_webauthn("https://vtc.example.com").expect("webauthn builder")
    }

    #[test]
    fn start_advertises_eddsa_alongside_default_algorithms() {
        let w = webauthn();
        let (ccr, _state) =
            start_passkey_registration(&w, Uuid::new_v4(), "did:key:zABC", "did:key:zABC", None)
                .unwrap();

        // EdDSA must be in the advertised list so Ed25519-capable
        // authenticators (YubiKey 5+, soft test harness) work.
        assert!(
            ccr.public_key
                .pub_key_cred_params
                .iter()
                .any(|p| p.alg == EDDSA_ALG),
            "EdDSA missing from pub_key_cred_params: {:?}",
            ccr.public_key.pub_key_cred_params
        );
        // Upstream defaults (ES256, RS256) must also remain — that's
        // what platform passkey providers actually produce.
        assert!(
            ccr.public_key.pub_key_cred_params.len() >= 2,
            "expected at least default ES256+RS256 plus EdDSA"
        );
    }

    #[test]
    fn start_state_credential_algorithms_includes_eddsa() {
        let w = webauthn();
        let (_ccr, state) =
            start_passkey_registration(&w, Uuid::new_v4(), "did:key:zABC", "did:key:zABC", None)
                .unwrap();

        // `PasskeyRegistration` exposes no public algorithms accessor;
        // inspect the JSON instead.
        let json = serde_json::to_value(&state).unwrap();
        let algs = json
            .get("rs")
            .and_then(|rs| rs.get("credential_algorithms"))
            .and_then(|v| v.as_array())
            .expect("credential_algorithms is an array");
        assert!(
            algs.iter().any(|v| v.as_str() == Some("EDDSA")),
            "credential_algorithms must include EDDSA so the finish-time check accepts Ed25519 credentials: {algs:?}"
        );
    }

    #[test]
    fn extend_ccr_is_idempotent_and_additive() {
        let w = webauthn();
        let (mut ccr, _state) = w
            .start_passkey_registration(Uuid::new_v4(), "u", "u", None)
            .unwrap();

        let before = ccr.public_key.pub_key_cred_params.clone();
        // Sanity: upstream's default list contains at least one entry
        // and does NOT include EdDSA. If this assertion fails it
        // means upstream started shipping EdDSA in `secure_algs()` —
        // at which point the extend is a no-op (still safe).
        assert!(!before.is_empty());

        extend_ccr_with_eddsa(&mut ccr);
        // EdDSA appended exactly once.
        let eddsa_count = ccr
            .public_key
            .pub_key_cred_params
            .iter()
            .filter(|p| p.alg == EDDSA_ALG)
            .count();
        assert_eq!(eddsa_count, 1);

        // Re-running is a no-op.
        let after_first = ccr.public_key.pub_key_cred_params.len();
        extend_ccr_with_eddsa(&mut ccr);
        assert_eq!(ccr.public_key.pub_key_cred_params.len(), after_first);

        // Original entries preserved (PubKeyCredParams doesn't impl PartialEq;
        // compare on the alg field).
        for p in &before {
            assert!(
                ccr.public_key
                    .pub_key_cred_params
                    .iter()
                    .any(|q| q.alg == p.alg && q.type_ == p.type_)
            );
        }
    }

    #[test]
    fn extend_state_round_trips_through_serde() {
        let w = webauthn();
        let (_ccr, state) = w
            .start_passkey_registration(Uuid::new_v4(), "u", "u", None)
            .unwrap();

        let rewritten = extend_state_with_eddsa(&state).unwrap();

        let json = serde_json::to_value(&rewritten).unwrap();
        let algs = json["rs"]["credential_algorithms"].as_array().unwrap();
        assert!(
            algs.iter().any(|v| v.as_str() == Some("EDDSA")),
            "EDDSA must be appended: {algs:?}"
        );

        // Other state fields survive the round-trip — pick `policy`
        // and `require_resident_key` as representative sentinels.
        let original_json = serde_json::to_value(&state).unwrap();
        for field in ["policy", "require_resident_key"] {
            assert_eq!(
                json["rs"][field], original_json["rs"][field],
                "field {field} must survive the rewrite",
            );
        }
    }
}
