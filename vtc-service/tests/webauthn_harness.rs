//! Validation of the deterministic soft EdDSA authenticator harness
//! (`tests/common/webauthn_harness.rs`).
//!
//! Drives a full register + authenticate ceremony through `webauthn-rs`,
//! using the EdDSA-restricting wrappers from
//! `vtc_service::webauthn::start_eddsa_passkey_registration`. If this
//! test passes end-to-end then the harness produces wire output
//! `webauthn-rs-core` accepts and signatures `webauthn-rs` verifies —
//! which is the contract M0.5.2's install-claim integration tests
//! depend on.
//!
//! Also asserts the Ed25519 verifying-key bytes the harness returns
//! match the COSE public key webauthn-rs ultimately stores in the
//! `Passkey` — without that, callers can't reliably derive a `did:key`
//! from the registered credential.

mod common;

use base64::Engine;
use uuid::Uuid;
use vti_common::auth::passkey::build_webauthn;
use webauthn_rs::Webauthn;
use webauthn_rs_proto::COSEAlgorithm;

use vtc_service::webauthn::{finish_eddsa_passkey_registration, start_eddsa_passkey_registration};

use common::webauthn_harness::SoftEd25519Authenticator;

const RP_ORIGIN: &str = "https://vtc.example.com";

fn webauthn() -> Webauthn {
    build_webauthn(RP_ORIGIN).expect("webauthn builder")
}

#[test]
fn register_then_authenticate_completes_end_to_end() {
    let webauthn = webauthn();
    let mut authenticator = SoftEd25519Authenticator::new();

    // -- register ------------------------------------------------------
    let user_uuid = Uuid::new_v4();
    let (ccr, reg_state) = start_eddsa_passkey_registration(
        &webauthn,
        user_uuid,
        "did:key:zHarness",
        "did:key:zHarness",
        None,
    )
    .expect("start_eddsa_passkey_registration");

    let (register_cred, ed25519_pub) = authenticator.register(&ccr, RP_ORIGIN);

    let passkey = finish_eddsa_passkey_registration(&webauthn, &register_cred, &reg_state)
        .expect("finish_eddsa_passkey_registration");

    // Sanity: webauthn-rs registered an EdDSA passkey, not something
    // else that webauthn-rs core's algorithm filter let through.
    assert_eq!(passkey.cred_algorithm(), &COSEAlgorithm::EDDSA);

    // The verifying-key bytes the harness handed back must equal the
    // raw Ed25519 `x` coordinate webauthn-rs stored on the Passkey.
    // The COSE key shape is internal to `webauthn-rs-core`; we lift it
    // out via serde rather than depending on the `danger-credential-internals`
    // feature. Spec ref RFC 8152 §13.2: OKP `x` parameter is integer
    // key `-2`.
    let passkey_json = serde_json::to_value(&passkey).expect("passkey serialises");
    let cose_x = walk_eddsa_x(&passkey_json).unwrap_or_else(|| {
        panic!(
            "EDDSA `x` coordinate not found in Passkey JSON:\n{}",
            serde_json::to_string_pretty(&passkey_json).unwrap()
        )
    });
    assert_eq!(
        cose_x.as_slice(),
        ed25519_pub.as_slice(),
        "harness pubkey must match passkey's stored Ed25519 x coordinate",
    );

    // -- authenticate --------------------------------------------------
    let (rcr, auth_state) = webauthn
        .start_passkey_authentication(std::slice::from_ref(&passkey))
        .expect("start_passkey_authentication");

    let auth_cred = authenticator.authenticate(&rcr, RP_ORIGIN);

    let _auth_result = webauthn
        .finish_passkey_authentication(&auth_cred, &auth_state)
        .expect("finish_passkey_authentication");
    // Don't assert on `needs_update()` — it reflects flag drift the
    // RP should persist (counter, backup-eligibility) and is true on
    // the very first authentication after register. The contract
    // we're verifying here is "ceremony succeeds without error".
}

#[test]
fn second_authenticate_increments_sign_count() {
    let webauthn = webauthn();
    let mut authenticator = SoftEd25519Authenticator::new();

    let (ccr, reg_state) = start_eddsa_passkey_registration(
        &webauthn,
        Uuid::new_v4(),
        "did:key:zHarness2",
        "did:key:zHarness2",
        None,
    )
    .unwrap();
    let (register_cred, _ed25519_pub) = authenticator.register(&ccr, RP_ORIGIN);
    let passkey = finish_eddsa_passkey_registration(&webauthn, &register_cred, &reg_state).unwrap();

    // First authentication.
    let (rcr1, state1) = webauthn
        .start_passkey_authentication(std::slice::from_ref(&passkey))
        .unwrap();
    let auth1 = authenticator.authenticate(&rcr1, RP_ORIGIN);
    let result1 = webauthn
        .finish_passkey_authentication(&auth1, &state1)
        .unwrap();

    // Second authentication. The harness counter must monotonically
    // increase so webauthn-rs accepts the second assertion — a regression
    // here typically presents as `CredentialCounterUpdated` errors.
    let (rcr2, state2) = webauthn
        .start_passkey_authentication(std::slice::from_ref(&passkey))
        .unwrap();
    let auth2 = authenticator.authenticate(&rcr2, RP_ORIGIN);
    let result2 = webauthn
        .finish_passkey_authentication(&auth2, &state2)
        .unwrap();

    assert!(result1.counter() < result2.counter());
}

#[test]
fn register_panics_when_challenge_lacks_eddsa() {
    let webauthn = webauthn();
    let mut authenticator = SoftEd25519Authenticator::new();

    // Drive the upstream challenge directly (no EdDSA restriction). The
    // harness must refuse — it produces only EdDSA credentials, so
    // accepting a non-EdDSA challenge would silently emit a mismatched
    // attestation that webauthn-rs's finish-side validation rejects
    // with a misleading error.
    let (ccr, _state) = webauthn
        .start_passkey_registration(Uuid::new_v4(), "did:key:zNoEdDSA", "did:key:zNoEdDSA", None)
        .unwrap();
    assert!(
        !ccr.public_key
            .pub_key_cred_params
            .iter()
            .any(|p| p.alg == -8)
    );

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        authenticator.register(&ccr, RP_ORIGIN)
    }));
    assert!(result.is_err(), "harness must refuse non-EdDSA challenges");
}

/// Walk a JSON value looking for the COSE OKP `x` coordinate. The
/// upstream serde shape isn't documented and shifts between minor
/// versions of `webauthn-rs-core` (today it's
/// `cred.cred.key.EC_OKP.x` and serialised as a base64url-no-pad
/// string). Rather than pin to one shape, we recurse and pick the
/// first value at key `"x"` that decodes to 32 raw bytes.
fn walk_eddsa_x(value: &serde_json::Value) -> Option<Vec<u8>> {
    match value {
        serde_json::Value::Object(map) => {
            if let Some(x) = map.get("x")
                && let Some(bytes) = decode_x_value(x)
            {
                return Some(bytes);
            }
            for v in map.values() {
                if let Some(found) = walk_eddsa_x(v) {
                    return Some(found);
                }
            }
            None
        }
        serde_json::Value::Array(items) => items.iter().find_map(walk_eddsa_x),
        _ => None,
    }
}

fn decode_x_value(value: &serde_json::Value) -> Option<Vec<u8>> {
    // `Vec<u8>` form (older serde shapes).
    if let Ok(bytes) = serde_json::from_value::<Vec<u8>>(value.clone())
        && bytes.len() == 32
    {
        return Some(bytes);
    }
    // base64url-no-pad string form (current `webauthn-rs-core 0.5.5`
    // shape).
    if let Some(s) = value.as_str()
        && let Ok(bytes) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s)
        && bytes.len() == 32
    {
        return Some(bytes);
    }
    None
}
