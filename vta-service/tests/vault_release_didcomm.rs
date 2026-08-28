//! The `vault/*` release paths, against a VTA that can actually pack.
//!
//! These three seal their answer into a DIDComm envelope addressed to the
//! caller, so the VTA needs an `ATM` with real secrets to pack with. The
//! ordinary in-process fixture has none — `vault/release` stops at "ATM not
//! configured", and an offline ATM gets as far as packing and no further.
//!
//! [`MockVta::start_with_transports`] is the harness that closes that: a real
//! embedded mediator, a `did:peer:2` VTA advertising DIDComm and TSP, and the
//! secrets behind it. The test does not have to *open* the sealed answer —
//! packing it is the part that was untested, and the response document's own
//! type is what the conformance gate reads.

#![cfg(feature = "transport-harness")]

use vta_service::test_support::MockVta;

/// Seed a vault entry with its secret already in place.
///
/// `vault/upsert` refuses a *create* with no `sealedSecret`, and sealing takes
/// an HPKE envelope addressed to this VTA. The release paths only need an entry
/// that exists, so seeding the create is the shorter road to the thing under
/// test.
async fn seed_entry(mock: &MockVta, id: &str, context_id: &str, login_url: &str) {
    use vti_common::vault::{
        PasswordLoginConfig, PasswordLoginFormat, SecretKind, SiteTarget, StoredVaultEntry,
        VaultEntry, VaultSecret, VaultStatus, put_stored_vault_entry,
    };
    let now = "2026-01-01T00:00:00Z".to_string();
    let entry = StoredVaultEntry {
        entry: VaultEntry {
            id: id.to_string(),
            context_id: context_id.to_string(),
            targets: vec![SiteTarget::WebOrigin {
                origin: "https://example.com".to_string(),
            }],
            label: "Release coverage".to_string(),
            secret_kind: SecretKind::Password,
            tags: Vec::new(),
            notes: None,
            favicon: None,
            selectors: Vec::new(),
            custom_field_names: Vec::new(),
            attachments: Vec::new(),
            expires_at: None,
            breached_at: None,
            password_changed_at: None,
            created_at: now.clone(),
            created_by: None,
            updated_at: now,
            updated_by: None,
            last_used_at: None,
            version: 1,
            principal_did: None,
            status: VaultStatus::Active,
            archived_at: None,
            deleted_at: None,
            grace_until: None,
        },
        secret: VaultSecret::Password {
            username: Some("alice".to_string()),
            password: "hunter2-very-secret".to_string(),
            totp: None,
            // `proxy-login` refuses an entry without one (`notProxyable`) and
            // points the caller at `vault/release` instead — the VTA cannot log
            // in on the holder's behalf if it does not know where or how.
            login_config: Some(PasswordLoginConfig {
                login_url: login_url.to_string(),
                format: PasswordLoginFormat::Json,
                username_field: Some("username".to_string()),
                password_field: Some("password".to_string()),
                totp_field: None,
                extra_fields: None,
                // Left unset: `effective_success_status` falls back to the
                // canonical [200, 204], which is what a caller who did not
                // override should get.
                success_status: None,
            }),
            secure_notes: None,
            custom_fields: Vec::new(),
        },
    };
    put_stored_vault_entry(&mock.ctx.vault_ks, &entry)
        .await
        .expect("seed the vault entry");
}

/// Seed an entry whose secret carries a DID-based signing identity.
///
/// `vault/sign-trust-task` refuses a password entry outright (`notSignable`):
/// there is no principal to sign as. Only the DID-bearing kinds have one, so
/// the signing path needs its own entry rather than a flag on the first.
async fn seed_signing_entry(mock: &MockVta, id: &str, context_id: &str, did: &str) {
    use vti_common::vault::{
        SecretKind, SiteTarget, StoredVaultEntry, VaultEntry, VaultSecret, VaultStatus,
        put_stored_vault_entry,
    };
    let now = "2026-01-01T00:00:00Z".to_string();
    let entry = StoredVaultEntry {
        entry: VaultEntry {
            id: id.to_string(),
            context_id: context_id.to_string(),
            targets: vec![SiteTarget::WebOrigin {
                origin: "https://signing.example".to_string(),
            }],
            label: "Signing coverage".to_string(),
            secret_kind: SecretKind::DidSelfIssued,
            tags: Vec::new(),
            notes: None,
            favicon: None,
            selectors: Vec::new(),
            custom_field_names: Vec::new(),
            attachments: Vec::new(),
            expires_at: None,
            breached_at: None,
            password_changed_at: None,
            created_at: now.clone(),
            created_by: None,
            updated_at: now,
            updated_by: None,
            last_used_at: None,
            version: 1,
            principal_did: Some(did.to_string()),
            status: VaultStatus::Active,
            archived_at: None,
            deleted_at: None,
            grace_until: None,
        },
        secret: VaultSecret::DidSelfIssued {
            did: did.to_string(),
            signing_key_id: format!("{did}#key-0"),
            secure_notes: None,
        },
    };
    put_stored_vault_entry(&mock.ctx.vault_ks, &entry)
        .await
        .expect("seed the signing vault entry");
}

// Names the deprecated 0.1 URIs on purpose: they are the canonical forms this
// covers, and they are still dispatched.
#[allow(deprecated)]
#[tokio::test]
async fn release_paths_seal_an_answer_to_the_caller() {
    // A stand-in for the third party. `proxy-login` really does log in — it is
    // the operation's whole point — so refusing to give it somewhere to log in
    // would test the failure path and call it coverage. 200 is the canonical
    // success status the entry falls back to.
    let third_party = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::method("POST"))
        .and(wiremock::matchers::path("/login"))
        .respond_with(
            wiremock::ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({ "session": "ok" })),
        )
        .mount(&third_party)
        .await;

    let mock = MockVta::start_with_transports().await;
    let client = mock.signing_client(0x50, "admin", vec![]).await;
    seed_entry(
        &mock,
        "release-cov-1",
        "ctx1",
        &format!("{}/login", third_party.uri()),
    )
    .await;
    // The VTA's own DID is the principal: it holds the key, so it is the only
    // identity this fixture can actually sign as.
    seed_signing_entry(&mock, "sign-cov-1", "ctx1", mock.vta_did()).await;

    client
        .dispatch_trust_task(
            vta_sdk::trust_tasks::TASK_VAULT_RELEASE_0_1,
            serde_json::json!({ "entryId": "release-cov-1" }),
            30,
        )
        .await
        .expect("vault/release");

    client
        .dispatch_trust_task(
            vta_sdk::trust_tasks::TASK_VAULT_PROXY_LOGIN_0_1,
            serde_json::json!({ "entryId": "release-cov-1" }),
            30,
        )
        .await
        .expect("vault/proxy-login");

    // `sign-trust-task` seals a *signed document* rather than a secret, but
    // takes the same route out: the entry's principal signs, and the answer
    // goes back inside an envelope addressed to the caller.
    client
        .dispatch_trust_task(
            vta_sdk::trust_tasks::TASK_VAULT_SIGN_TRUST_TASK_0_1,
            serde_json::json!({
                "entryId": "sign-cov-1",
                "unsignedEnvelope": {
                    "id": "urn:uuid:vault-signed-1",
                    "type": "https://trusttasks.org/spec/auth/whoami/0.1",
                    // Must equal the entry's `principalDid`: the VTA signs
                    // *as* that principal, so a document claiming a different
                    // issuer would carry a signature that contradicts it.
                    "issuer": mock.vta_did(),
                    "recipient": mock.vta_did(),
                    "issuedAt": "2026-01-01T00:00:00Z",
                    "payload": {},
                },
            }),
            30,
        )
        .await
        .expect("vault/sign-trust-task");

    mock.shutdown().await;
}
