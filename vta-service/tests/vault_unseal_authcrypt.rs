//! Regression pin for the forged-sender auth bypass on the vault secret-unseal path.
//!
//! `operations::vault::upsert::unseal_secret` unpacks a DIDComm-authcrypt JWE
//! and cross-checks the enclosed sender against the authenticated caller.
//! Because `atm.unpack` *also* accepts plaintext (and anoncrypt) envelopes —
//! each yielding an unauthenticated, attacker-controlled `from` — the function
//! must reject any envelope that isn't encrypted + authenticated *before* it
//! trusts `from`. Otherwise the "sealed" secret isn't actually sealed and the
//! sender cross-check is trivially satisfiable (forge `from == caller`).

use vta_service::operations::vault::upsert::{UnsealError, unseal_secret};
use vta_service::test_support::build_offline_atm;

#[tokio::test]
async fn plaintext_sealed_secret_is_rejected() {
    let atm = build_offline_atm().await;
    let caller = "did:key:z6MkVaultCaller";

    // A plaintext DIDComm envelope (a `type` field, no JWE/JWS layer) forging
    // `from` = the caller. `atm.unpack` parses it and returns metadata with
    // `authenticated: false`; the authcrypt guard must turn that into a
    // rejection rather than trusting the forged sender.
    let plaintext = serde_json::json!({
        "id": "attacker-supplied-id",
        "typ": "application/didcomm-plain+json",
        "type": "https://openvtc.org/vault/secret",
        "from": caller,
        "to": ["did:key:z6MkVtaServiceUnderTest"],
        "body": { "secret": "s3cr3t" },
    })
    .to_string();

    let err = unseal_secret(&atm, caller, &plaintext)
        .await
        .expect_err("a plaintext (non-authcrypt) sealed secret must be rejected");

    match err {
        UnsealError::UnpackFailed(msg) => assert!(
            msg.contains("authcrypt"),
            "rejection must come from the authcrypt guard, got: {msg}"
        ),
        UnsealError::MissingSender => {
            panic!("expected the authcrypt guard to fire before the missing-sender check")
        }
        UnsealError::SenderMismatch { .. } => {
            panic!("plaintext must be rejected as not-authcrypt, not reach the sender cross-check")
        }
        UnsealError::CleartextInvalid(_) => {
            panic!("plaintext must be rejected before body deserialisation")
        }
    }
}
