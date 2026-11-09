//! Passkeys enrolled before the move to webauthn-rs 0.6 still load.
//!
//! A [`Passkey`] is stored as JSON (`vti_common::auth::passkey::store`), and
//! webauthn-rs 0.6 replaced the 0.5 `Base64UrlSafeData` byte fields with
//! `Vec<u8>` encoded as base64url only in human-readable formats. The records
//! below were written by webauthn-rs 0.5.5 through the VTC's own registration
//! (`vtc_service::webauthn::finish_passkey_registration`, the soft
//! authenticator in `common::webauthn_harness`). Each must still parse, name
//! the same credential and project to the same `did:key`: an administrator
//! whose stored passkey stopped loading would be locked out.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use vtc_service::webauthn::passkey_did_key;
use vti_common::auth::passkey::build_webauthn;
use webauthn_rs::prelude::Passkey;

/// (label, stored record, its credential id, the `did:key` it projected to.)
fn enrolled_under_0_5() -> Vec<(&'static str, serde_json::Value, &'static str, &'static str)> {
    vec![
        (
            "ed25519",
            serde_json::json!({
                "cred": {
                    "attestation": {
                        "data": "None",
                        "metadata": "None"
                    },
                    "attestation_format": "none",
                    "backup_eligible": false,
                    "backup_state": false,
                    "counter": 0,
                    "cred": {
                        "key": {
                            "EC_OKP": {
                                "curve": "ED25519",
                                "x": "M6sEXcmsNhFSuA-MXZDS8IAD9_QsdHl1yP_9dJjTWWE"
                            }
                        },
                        "type_": "EDDSA"
                    },
                    "cred_id": "Eq5lzRbDLWDuxMQ0bPWWJA",
                    "extensions": {
                        "appid": "NotRequested",
                        "cred_props": "Ignored",
                        "cred_protect": "Ignored",
                        "hmac_create_secret": "NotRequested"
                    },
                    "registration_policy": "required",
                    "transports": null,
                    "user_verified": true
                }
            }),
            "Eq5lzRbDLWDuxMQ0bPWWJA",
            "did:key:z6Mkhvx5xxarPerJAYqtDfRP1qGKMDP8bnGVDpCGUz89F64p",
        ),
        (
            "p256",
            serde_json::json!({
                "cred": {
                    "attestation": {
                        "data": "None",
                        "metadata": "None"
                    },
                    "attestation_format": "none",
                    "backup_eligible": false,
                    "backup_state": false,
                    "counter": 0,
                    "cred": {
                        "key": {
                            "EC_EC2": {
                                "curve": "SECP256R1",
                                "x": "ZMO0kGGtCRJp-ouLKf08LUeeXD248Y5hsGpYQdl6mWA",
                                "y": "Z5dordL_wVW0O_YVSMNBY16OWMdvg1zo4zow0IuWdJo"
                            }
                        },
                        "type_": "ES256"
                    },
                    "cred_id": "kqds9PMkW3okHzVsn3N-Aw",
                    "extensions": {
                        "appid": "NotRequested",
                        "cred_props": "Ignored",
                        "cred_protect": "Ignored",
                        "hmac_create_secret": "NotRequested"
                    },
                    "registration_policy": "required",
                    "transports": null,
                    "user_verified": true
                }
            }),
            "kqds9PMkW3okHzVsn3N-Aw",
            "did:key:zDnaeXDJu5d67W6q6A7YzjBaTcgVoH1kBfZex32727QpaQBPu",
        ),
    ]
}

#[test]
fn a_passkey_stored_by_webauthn_rs_0_5_still_loads() {
    let webauthn = build_webauthn("https://vtc.example.com").expect("webauthn builder");
    for (label, stored, cred_id, did_key) in enrolled_under_0_5() {
        let passkey: Passkey = serde_json::from_value(stored.clone())
            .unwrap_or_else(|e| panic!("{label}: a 0.5 record no longer parses: {e}"));

        assert_eq!(
            URL_SAFE_NO_PAD.encode(passkey.cred_id()),
            cred_id,
            "{label}: the credential id changed"
        );
        assert_eq!(
            passkey_did_key(&passkey).expect("a did:key"),
            did_key,
            "{label}: the public key changed"
        );
        // Written back, it reads the same, so a record rewritten after the
        // upgrade (a counter update) stays readable.
        assert_eq!(
            serde_json::to_value(&passkey).unwrap(),
            stored,
            "{label}: 0.6 writes a different record"
        );
        // And it can be offered in a ceremony.
        let (rcr, _state) = webauthn
            .start_passkey_authentication(std::slice::from_ref(&passkey))
            .expect("an authentication starts");
        assert_eq!(rcr.public_key.allow_credentials.len(), 1, "{label}");
    }
}
