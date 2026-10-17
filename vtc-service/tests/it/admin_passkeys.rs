//! End-to-end coverage for an administrator's own passkeys —
//! `auth/passkey/list/0.1`, `auth/passkey/enroll/{start,finish}/0.2` and
//! `auth/passkey/revoke/{start,finish}/0.1` — on the signed-document door.
//!
//! Each specification declares `proof` REQUIRED, and the `/v1/admin/passkeys/*`
//! bearer routes that served them were removed (#1641). Builds a fixture with a
//! fully-bootstrapped admin (one passkey, one ACL entry, audit writer wired) and
//! drives the tasks through `POST /v1/trust-tasks`, signed by the admin's own
//! `did:key`, with the soft EdDSA harness producing the WebAuthn assertions.

use axum::http::StatusCode;
use chrono::Utc;
use serde_json::{Value, json};
use uuid::Uuid;
use vtc_service::acl::{AdminAuthority, VtcAclEntry, VtcRole, store_acl_entry};
use vti_common::audit::{AuditEnvelope, AuditEvent};
use vti_common::auth::passkey::{
    build_webauthn,
    store::{PasskeyUser, store_credential_mapping, store_passkey_user},
};
use vti_rooms_dtg::test_support::Party;
use webauthn_rs::Webauthn;
use webauthn_rs::prelude::{CreationChallengeResponse, RequestChallengeResponse};

use vtc_service::acl::admin::{AdminEntry, RegisteredPasskey, get_admin_entry, store_admin_entry};
use vtc_service::test_support::TestVtc;

use crate::common::signed::{
    bearer_route_served, call, error_code, party_with_role, payload, post, unsigned,
};
use crate::common::webauthn_harness::SoftEd25519Authenticator;

/// Re-wrap the inner WebAuthn options as webauthn-rs's `{publicKey: …}`.
///
/// `enroll/start/0.2` and its siblings send the *inner* options — the value a
/// browser passes as `create({ publicKey: … })` — because that is what the
/// canonical `CredentialCreationOptions` describes. The soft-authenticator
/// harness deserialises webauthn-rs's wrapper type, so the test does the same
/// re-wrap a real client does, one line before calling the authenticator.
fn wrap_options<T: serde::de::DeserializeOwned>(inner: &Value) -> T {
    serde_json::from_value(json!({ "publicKey": inner })).expect("options re-wrap")
}

/// A webauthn-rs result as the browser's published JSON — what the console's
/// `serializeRegistration` / `serializeAssertion` send.
fn published(v: impl serde::Serialize) -> Value {
    fn strip_nulls(v: &mut Value) {
        if let Value::Object(map) = v {
            map.retain(|_, v| !v.is_null());
            map.values_mut().for_each(strip_nulls);
        }
    }
    let mut v = serde_json::to_value(v).unwrap();
    let obj = v.as_object_mut().unwrap();
    obj.remove("extensions");
    obj.insert("clientExtensionResults".into(), json!({}));
    strip_nulls(&mut v);
    v
}

const RP_ORIGIN: &str = "https://vtc.example.com";
const LIST_TASK: &str = "https://trusttasks.org/spec/auth/passkey/list/0.1";
const ENROLL_START_TASK: &str = "https://trusttasks.org/spec/auth/passkey/enroll/start/0.2";
const ENROLL_FINISH_TASK: &str = "https://trusttasks.org/spec/auth/passkey/enroll/finish/0.2";
const REVOKE_START_TASK: &str = "https://trusttasks.org/spec/auth/passkey/revoke/start/0.1";
const REVOKE_FINISH_TASK: &str = "https://trusttasks.org/spec/auth/passkey/revoke/finish/0.1";

struct Fixture {
    vtc: TestVtc,
    /// The bootstrapped administrator, who signs every document.
    admin: Party,
    /// Soft authenticator pre-loaded with the bootstrap passkey,
    /// ready to drive UV and additional-device ceremonies.
    authenticator: SoftEd25519Authenticator,
}

/// Build a fixture where:
/// - WebAuthn (via public_url) + audit writer are configured.
/// - One admin is pre-bootstrapped: PasskeyUser, AdminEntry, ACL
///   entry, credential mapping all match a single soft-authenticator
///   credential whose Ed25519 key we know.
async fn build_fixture(with_audit: bool) -> Fixture {
    let vtc = TestVtc::builder()
        .with_audit(with_audit)
        .with_public_url(RP_ORIGIN)
        .build()
        .await;

    // Run a real WebAuthn registration ceremony against the same RP as
    // the AppState's webauthn so the persisted PasskeyUser has a real
    // `Passkey` that subsequent UV-assertion flows can exercise. Mirrors
    // the post-bootstrap state M0.6.2 leaves the system in.
    let webauthn: Webauthn = build_webauthn(RP_ORIGIN).expect("webauthn builder");
    let mut authenticator = SoftEd25519Authenticator::new();
    let user_uuid = Uuid::new_v4();
    let (ccr, reg_state) = vtc_service::webauthn::start_passkey_registration(
        &webauthn,
        user_uuid,
        "did:key:zPlaceholder",
        "did:key:zPlaceholder",
        None,
    )
    .unwrap();
    let (register_cred, _) = authenticator.register(&ccr, RP_ORIGIN);
    let bootstrap_passkey =
        vtc_service::webauthn::finish_passkey_registration(&webauthn, &register_cred, &reg_state)
            .unwrap();
    let admin = Party::new();
    let bootstrap_cred_id_hex =
        hex::encode(<_ as AsRef<[u8]>>::as_ref(bootstrap_passkey.cred_id()));

    // Persist the post-bootstrap fixture state into the daemon keyspaces.
    let pk_user = PasskeyUser {
        user_uuid,
        did: admin.did.clone(),
        display_name: admin.did.clone(),
        credentials: vec![bootstrap_passkey],
    };
    store_passkey_user(&vtc.state.passkey_ks, &pk_user)
        .await
        .unwrap();
    store_credential_mapping(&vtc.state.passkey_ks, &bootstrap_cred_id_hex, user_uuid)
        .await
        .unwrap();
    let admin_entry = AdminEntry {
        did: admin.did.clone(),
        passkeys: vec![RegisteredPasskey {
            credential_id: bootstrap_cred_id_hex.clone(),
            label: "install".into(),
            transports: Vec::new(),
            registered_at: Utc::now(),
            last_used_at: None,
        }],
        extensions: Value::Null,
        created_at: Utc::now(),
    };
    store_admin_entry(&vtc.state.passkey_ks, &admin_entry)
        .await
        .unwrap();
    let acl_entry = VtcAclEntry {
        label: Some("install bootstrap".into()),
        ..VtcAclEntry::new(
            &admin.did,
            VtcRole::Admin,
            AdminAuthority::community_admin(),
            "did:key:vtc-install",
        )
    };
    store_acl_entry(&vtc.state.acl_ks, &acl_entry)
        .await
        .unwrap();

    Fixture {
        vtc,
        admin,
        authenticator,
    }
}

/// Run `enroll/{start,finish}` for a second passkey labelled `label`; the
/// finish reply.
async fn enrol_second(fix: &mut Fixture, label: &str) -> (StatusCode, Value) {
    let (status, start) = call(&fix.vtc, &fix.admin, ENROLL_START_TASK, json!({})).await;
    assert_eq!(status, StatusCode::OK, "start: {start}");
    let body = payload(&start).clone();
    let enrollment_id = body["enrollmentId"].as_str().unwrap().to_string();
    let register_options: CreationChallengeResponse = wrap_options(&body["options"]);
    let uv_options: RequestChallengeResponse = wrap_options(&body["uvOptions"]);
    let (register_response, _) = fix.authenticator.register(&register_options, RP_ORIGIN);
    let uv_response = fix.authenticator.authenticate(&uv_options, RP_ORIGIN);
    call(
        &fix.vtc,
        &fix.admin,
        ENROLL_FINISH_TASK,
        json!({
            "enrollmentId": enrollment_id,
            "credential": published(&register_response),
            "uvCredential": published(&uv_response),
            "deviceLabel": label,
        }),
    )
    .await
}

fn bogus_assertion() -> Value {
    json!({
        "id": "AAAA",
        "rawId": "AAAA",
        "response": {
            "authenticatorData": "AA",
            "clientDataJSON": "AA",
            "signature": "AA"
        },
        "type": "public-key",
        "clientExtensionResults": {}
    })
}

// ---------------------------------------------------------------------------
// list
// ---------------------------------------------------------------------------

#[tokio::test]
async fn list_returns_bootstrap_passkey() {
    let fix = build_fixture(true).await;
    let (status, doc) = call(&fix.vtc, &fix.admin, LIST_TASK, json!({})).await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    // `credentials`, the name `auth/passkey/list/0.1` publishes (#1112).
    let arr = payload(&doc)["credentials"].as_array().unwrap();
    assert_eq!(arr.len(), 1);
    // `deviceLabel`, the name the shared `RegisteredCredential` component
    // publishes — `label` was the storage row's name, never the wire's.
    assert_eq!(arr[0]["deviceLabel"], "install");
}

/// An admin who has enrolled no passkeys gets an empty list, not a refusal.
///
/// This is an entirely ordinary state, not an error: an operator who signs in
/// with their VTA wallet holds an ACL entry and no passkey enrolment, and this
/// page is the first place they land. Answering 404 made the console render
/// "FAILED TO LOAD PASSKEYS" directly above its own, correct, "No passkeys
/// registered" empty state — one page disagreeing with itself about whether
/// anything was wrong.
#[tokio::test]
async fn list_is_empty_for_an_admin_with_no_passkeys() {
    let fix = build_fixture(true).await;

    // A DID with the admin ACL role and no `AdminEntry`, which is exactly what
    // wallet sign-in produces.
    let wallet_admin = party_with_role(&fix.vtc, VtcRole::Admin, &[]).await;
    assert!(
        get_admin_entry(&fix.vtc.state.passkey_ks, &wallet_admin.did)
            .await
            .unwrap()
            .is_none(),
        "the premise of this test is an admin with no enrolment"
    );

    let (status, doc) = call(&fix.vtc, &wallet_admin, LIST_TASK, json!({})).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "an empty collection is not a refusal: {doc}"
    );
    assert_eq!(
        payload(&doc)["credentials"].as_array().map(Vec::len),
        Some(0),
        "the member must be present and empty, not absent: the console reads \
         `credentials.length`, and an absent member is a different failure"
    );
}

/// Each task names the signer's own passkeys, never another administrator's:
/// a second admin listing sees theirs (none), not the bootstrapped admin's.
#[tokio::test]
async fn list_shows_only_the_signers_own_passkeys() {
    let fix = build_fixture(true).await;
    let other = party_with_role(&fix.vtc, VtcRole::Admin, &[]).await;
    let (_, doc) = call(&fix.vtc, &other, LIST_TASK, json!({})).await;
    assert_eq!(payload(&doc)["credentials"], json!([]), "{doc}");
}

/// What the bearer routes' `AdminAuth` refused, the signed door refuses: a
/// signer whose ACL row makes it no administrator.
#[tokio::test]
async fn list_requires_admin_role() {
    let fix = build_fixture(true).await;
    let member = party_with_role(&fix.vtc, VtcRole::Member, &[]).await;
    let (status, doc) = call(&fix.vtc, &member, LIST_TASK, json!({})).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{doc}");
    assert_eq!(error_code(&doc), Some("permissionDenied"), "{doc}");
}

/// A signer the ACL does not know is refused.
#[tokio::test]
async fn list_refuses_a_signer_with_no_acl_entry() {
    let fix = build_fixture(true).await;
    let (status, doc) = call(&fix.vtc, &Party::new(), LIST_TASK, json!({})).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{doc}");
    assert_eq!(error_code(&doc), Some("permissionDenied"), "{doc}");
}

/// VTI-OPS-020: each of the five declares `proof` REQUIRED, so a document
/// naming the admin as issuer but carrying no proof is refused before it runs.
#[tokio::test]
async fn every_admin_passkey_task_refuses_an_unsigned_document() {
    let fix = build_fixture(true).await;
    for (task, body) in [
        (LIST_TASK, json!({})),
        (ENROLL_START_TASK, json!({})),
        (
            ENROLL_FINISH_TASK,
            json!({ "enrollmentId": "x", "credential": {} }),
        ),
        (REVOKE_START_TASK, json!({ "credentialId": "x" })),
        (
            REVOKE_FINISH_TASK,
            json!({ "revocationId": "x", "uvCredential": bogus_assertion() }),
        ),
    ] {
        let (status, doc) = post(&fix.vtc, &unsigned(&fix.admin, task, body)).await;
        assert_ne!(status, StatusCode::OK, "{task}: {doc}");
        assert!(error_code(&doc).is_some(), "{task}: {doc}");
    }
}

/// A console key acts for the administrator that enrolled it, exactly as it
/// does for every other administrator verb.
#[tokio::test]
async fn a_console_key_lists_its_administrators_passkeys() {
    let fix = build_fixture(true).await;
    let console = Party::new();
    vtc_service::acl::console_key::enrol_delegation(
        &fix.vtc.state.console_keys_ks,
        &fix.vtc.state.acl_ks,
        &console.did,
        &fix.admin.did,
        Some("test browser".into()),
        None,
    )
    .await
    .unwrap();
    let (status, doc) = call(&fix.vtc, &console, LIST_TASK, json!({})).await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    assert_eq!(
        payload(&doc)["credentials"].as_array().map(Vec::len),
        Some(1)
    );
}

/// The `/v1/admin/passkeys/*` bearer routes are gone (#1641).
#[tokio::test]
async fn the_admin_passkey_bearer_routes_are_gone() {
    let fix = build_fixture(true).await;
    for (method, path) in [
        ("GET", "/v1/admin/passkeys"),
        ("POST", "/v1/admin/passkeys/register/start"),
        ("POST", "/v1/admin/passkeys/register/finish"),
        ("POST", "/v1/admin/passkeys/revoke/start"),
        ("POST", "/v1/admin/passkeys/revoke/finish"),
    ] {
        assert!(
            !bearer_route_served(&fix.vtc, method, path).await,
            "{method} {path} is still served"
        );
    }
}

// ---------------------------------------------------------------------------
// enroll
// ---------------------------------------------------------------------------

#[tokio::test]
async fn register_succeeds_with_step_up_uv() {
    let mut fix = build_fixture(true).await;
    let (status, doc) = enrol_second(&mut fix, "yubikey").await;
    assert_eq!(status, StatusCode::OK, "finish: {doc}");
    let body = payload(&doc);
    assert!(!body["credentialId"].as_str().unwrap().is_empty());
    assert_eq!(body["subject"].as_str(), Some(fix.admin.did.as_str()));
    assert_eq!(body["deviceLabel"], "yubikey");

    // verify the AdminEntry now lists 2 passkeys
    let admin_entry = get_admin_entry(&fix.vtc.state.passkey_ks, &fix.admin.did)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(admin_entry.passkeys.len(), 2);
    assert!(admin_entry.passkeys.iter().any(|p| p.label == "yubikey"));
}

/// An administrator with no passkey has nothing to re-authenticate with, so no
/// authenticator can be added from the console: `reauthUnavailable`.
#[tokio::test]
async fn enroll_start_without_a_passkey_to_reauthenticate_is_refused() {
    let fix = build_fixture(true).await;
    let wallet_admin = party_with_role(&fix.vtc, VtcRole::Admin, &[]).await;
    let (status, doc) = call(&fix.vtc, &wallet_admin, ENROLL_START_TASK, json!({})).await;
    assert_ne!(status, StatusCode::OK, "{doc}");
    assert_eq!(
        error_code(&doc),
        Some("auth/passkey/enroll/start:reauthUnavailable"),
        "{doc}"
    );
}

#[tokio::test]
async fn register_finish_without_start_is_refused() {
    let fix = build_fixture(true).await;
    let bogus_cred = json!({
        "id": "AAAA",
        "rawId": "AAAA",
        "response": { "attestationObject": "AA", "clientDataJSON": "AA", "transports": [] },
        "type": "public-key",
        "clientExtensionResults": {}
    });
    let (status, doc) = call(
        &fix.vtc,
        &fix.admin,
        ENROLL_FINISH_TASK,
        json!({
            "enrollmentId": Uuid::new_v4().to_string(),
            "credential": bogus_cred,
            "uvCredential": bogus_assertion(),
            "deviceLabel": "bogus",
        }),
    )
    .await;
    assert_ne!(status, StatusCode::OK, "{doc}");
    assert_eq!(
        error_code(&doc),
        Some("auth/passkey/enroll/finish:enrollmentNotFound"),
        "{doc}"
    );
}

/// The step-up UV is not optional here, though the specification lets a first
/// enrolment omit it: there is no first enrolment on this door, and a finish
/// without it must not bind an authenticator.
#[tokio::test]
async fn register_finish_without_the_step_up_assertion_is_refused() {
    let mut fix = build_fixture(true).await;
    let (_, start) = call(&fix.vtc, &fix.admin, ENROLL_START_TASK, json!({})).await;
    let body = payload(&start).clone();
    let register_options: CreationChallengeResponse = wrap_options(&body["options"]);
    let (register_response, _) = fix.authenticator.register(&register_options, RP_ORIGIN);
    let (status, doc) = call(
        &fix.vtc,
        &fix.admin,
        ENROLL_FINISH_TASK,
        json!({
            "enrollmentId": body["enrollmentId"],
            "credential": published(&register_response),
        }),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{doc}");
    assert_eq!(error_code(&doc), Some("permissionDenied"), "{doc}");
    let entry = get_admin_entry(&fix.vtc.state.passkey_ks, &fix.admin.did)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(entry.passkeys.len(), 1, "nothing was bound");
}

#[tokio::test]
async fn register_rejects_when_uv_signed_by_wrong_authenticator() {
    use base64::Engine;

    let mut fix = build_fixture(true).await;
    let (_, start) = call(&fix.vtc, &fix.admin, ENROLL_START_TASK, json!({})).await;
    let body = payload(&start).clone();
    let enrollment_id = body["enrollmentId"].as_str().unwrap().to_string();
    let register_options: CreationChallengeResponse = wrap_options(&body["options"]);

    // New device produced by the legitimate harness (so the register half
    // passes), but the UV is a forged assertion over the right credential id
    // with a bogus signature. The server must fail its verification.
    let (register_response, _) = fix.authenticator.register(&register_options, RP_ORIGIN);
    let uv_options: RequestChallengeResponse = wrap_options(&body["uvOptions"]);
    let cred_id_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(uv_options.public_key.allow_credentials[0].id.as_ref() as &[u8]);
    let bogus_uv = json!({
        "id": cred_id_b64,
        "rawId": cred_id_b64,
        "response": {
            "authenticatorData": "AAAA",
            "clientDataJSON": "AAAA",
            "signature": "AAAA"
        },
        "type": "public-key",
        "clientExtensionResults": {}
    });

    let (status, doc) = call(
        &fix.vtc,
        &fix.admin,
        ENROLL_FINISH_TASK,
        json!({
            "enrollmentId": enrollment_id,
            "credential": published(&register_response),
            "uvCredential": bogus_uv,
            "deviceLabel": "evil",
        }),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{doc}");
    let entry = get_admin_entry(&fix.vtc.state.passkey_ks, &fix.admin.did)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(entry.passkeys.len(), 1, "nothing was bound");
}

#[tokio::test]
async fn register_is_refused_when_audit_writer_missing() {
    let mut fix = build_fixture(false).await;
    let (status, doc) = enrol_second(&mut fix, "x").await;
    assert_ne!(status, StatusCode::OK, "{doc}");
    let entry = get_admin_entry(&fix.vtc.state.passkey_ks, &fix.admin.did)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(entry.passkeys.len(), 1, "nothing was bound");
}

// ---------------------------------------------------------------------------
// revoke
// ---------------------------------------------------------------------------

/// Start, then finish, a revocation of `cred_id` with a genuine UV.
async fn revoke(fix: &mut Fixture, cred_id: &str) -> (StatusCode, Value) {
    let (status, start) = call(
        &fix.vtc,
        &fix.admin,
        REVOKE_START_TASK,
        json!({ "credentialId": cred_id }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "revoke start: {start}");
    let body = payload(&start).clone();
    let uv_options: RequestChallengeResponse = wrap_options(&body["uvOptions"]);
    let uv_response = fix.authenticator.authenticate(&uv_options, RP_ORIGIN);
    call(
        &fix.vtc,
        &fix.admin,
        REVOKE_FINISH_TASK,
        json!({
            "revocationId": body["revocationId"],
            "uvCredential": published(&uv_response),
        }),
    )
    .await
}

#[tokio::test]
async fn revoke_last_passkey_is_refused_last_credential() {
    let mut fix = build_fixture(true).await;
    let entry = get_admin_entry(&fix.vtc.state.passkey_ks, &fix.admin.did)
        .await
        .unwrap()
        .unwrap();
    let cred_id = entry.passkeys[0].credential_id.clone();

    // Refused because this would leave 0 passkeys.
    let (status, doc) = revoke(&mut fix, &cred_id).await;
    assert_ne!(status, StatusCode::OK, "revoke finish: {doc}");
    assert_eq!(
        error_code(&doc),
        Some("auth/passkey/revoke/finish:lastCredential"),
        "{doc}"
    );
}

#[tokio::test]
async fn revoke_after_register_succeeds_and_emits_audit_event() {
    let mut fix = build_fixture(true).await;
    let (status, doc) = enrol_second(&mut fix, "yk5").await;
    assert_eq!(status, StatusCode::OK, "register: {doc}");
    let new_cred_id = payload(&doc)["credentialId"].as_str().unwrap().to_string();

    // Now revoke the original bootstrap passkey (which is NOT the one we just
    // added). After this the admin still has the new device, so the >1 guard
    // is satisfied.
    let entry = get_admin_entry(&fix.vtc.state.passkey_ks, &fix.admin.did)
        .await
        .unwrap()
        .unwrap();
    let bootstrap_id = entry
        .passkeys
        .iter()
        .find(|p| p.credential_id != new_cred_id)
        .map(|p| p.credential_id.clone())
        .unwrap();

    let (status, doc) = revoke(&mut fix, &bootstrap_id).await;
    assert_eq!(status, StatusCode::OK, "revoke: {doc}");
    assert_eq!(payload(&doc)["remaining"], 1);

    // Verify AdminEntry now has exactly one passkey.
    let entry = get_admin_entry(&fix.vtc.state.passkey_ks, &fix.admin.did)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(entry.passkeys.len(), 1);
    assert_eq!(entry.passkeys[0].credential_id, new_cred_id);

    // Audit log should contain AdminPasskeyRegistered + AdminPasskeyRevoked
    let raw = fix
        .vtc
        .state
        .audit_ks
        .prefix_iter_raw(b"2".to_vec())
        .await
        .unwrap();
    let envelopes: Vec<AuditEnvelope> = raw
        .iter()
        .map(|(_, v)| serde_json::from_slice(v).unwrap())
        .collect();
    let mut saw_register = false;
    let mut saw_revoke = false;
    for env in &envelopes {
        match &env.event {
            AuditEvent::AdminPasskeyRegistered(_) => saw_register = true,
            AuditEvent::AdminPasskeyRevoked(_) => saw_revoke = true,
            _ => {}
        }
    }
    assert!(saw_register, "AdminPasskeyRegistered envelope missing");
    assert!(saw_revoke, "AdminPasskeyRevoked envelope missing");
}

#[tokio::test]
async fn revoke_rejects_unknown_credential_id() {
    let fix = build_fixture(true).await;
    let (status, doc) = call(
        &fix.vtc,
        &fix.admin,
        REVOKE_START_TASK,
        json!({ "credentialId": "deadbeef" }),
    )
    .await;
    assert_ne!(status, StatusCode::OK, "{doc}");
    assert_eq!(
        error_code(&doc),
        Some("auth/passkey/revoke/start:credentialNotFound"),
        "{doc}"
    );
}

/// Another administrator cannot revoke this one's passkey: the credential is
/// looked up among the *signer's* own.
#[tokio::test]
async fn revoke_names_only_the_signers_own_credentials() {
    let fix = build_fixture(true).await;
    let entry = get_admin_entry(&fix.vtc.state.passkey_ks, &fix.admin.did)
        .await
        .unwrap()
        .unwrap();
    let other = party_with_role(&fix.vtc, VtcRole::Admin, &[]).await;
    let (_, doc) = call(
        &fix.vtc,
        &other,
        REVOKE_START_TASK,
        json!({ "credentialId": entry.passkeys[0].credential_id }),
    )
    .await;
    assert_eq!(
        error_code(&doc),
        Some("auth/passkey/revoke/start:credentialNotFound"),
        "{doc}"
    );
}

#[tokio::test]
async fn revoke_finish_without_start_is_refused() {
    let fix = build_fixture(true).await;
    let (status, doc) = call(
        &fix.vtc,
        &fix.admin,
        REVOKE_FINISH_TASK,
        json!({
            "revocationId": Uuid::new_v4().to_string(),
            "uvCredential": bogus_assertion(),
        }),
    )
    .await;
    assert_ne!(status, StatusCode::OK, "{doc}");
    assert_eq!(
        error_code(&doc),
        Some("auth/passkey/revoke/finish:revocationNotFound"),
        "{doc}"
    );
}

// ---------------------------------------------------------------------------
// passkey login binds the browser key (#1641)
// ---------------------------------------------------------------------------

/// `POST` `body` to a passkey-login leg; the status, the body and the
/// `Set-Cookie` values.
async fn login_leg(fix: &Fixture, leg: &str, body: Value) -> (StatusCode, Value, Vec<String>) {
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use tower::ServiceExt;
    let task = format!("https://trusttasks.org/spec/auth/passkey/login/{leg}/0.2");
    let req = Request::builder()
        .method("POST")
        .uri(format!("/v1/auth/passkey-login/{leg}"))
        .header("Trust-Task", task)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let res = fix.vtc.router.clone().oneshot(req).await.unwrap();
    let status = res.status();
    let cookies = res
        .headers()
        .get_all(axum::http::header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok().map(str::to_string))
        .collect();
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        cookies,
    )
}

/// Run a passkey login with `ext`; the finish reply.
async fn passkey_login(fix: &mut Fixture, ext: Option<Value>) -> (StatusCode, Value, Vec<String>) {
    let (status, start, _) = login_leg(fix, "start", json!({})).await;
    assert_eq!(status, StatusCode::OK, "start: {start}");
    let options: RequestChallengeResponse = wrap_options(&start["options"]);
    let assertion = fix.authenticator.authenticate(&options, RP_ORIGIN);
    let mut body = json!({ "auth_id": start["authId"], "credential": assertion });
    if let Some(ext) = ext {
        body["ext"] = ext;
    }
    login_leg(fix, "finish", body).await
}

/// A console passkey login binds the browser key it names, which then signs
/// `auth/whoami/0.1` for that session — the cookie is not what answers.
#[tokio::test]
async fn a_passkey_login_binds_the_browser_key_to_its_session() {
    let mut fix = build_fixture(true).await;
    let browser = Party::new();
    let (status, body, cookies) = passkey_login(
        &mut fix,
        Some(json!({ "org.openvtc": { "sessionKey": browser.did } })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(cookies.iter().any(|c| c.starts_with("vtc_admin_session=")));
    let session_id = body["session"]["id"].as_str().unwrap().to_string();

    let (status, who) = call(
        &fix.vtc,
        &browser,
        "https://trusttasks.org/spec/auth/whoami/0.1",
        json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{who}");
    assert_eq!(who["payload"]["session"]["id"], session_id.as_str());
    assert_eq!(who["payload"]["session"]["subject"], fix.admin.did.as_str());
}

/// Without a key the login still works, and nothing can sign `whoami` for it.
#[tokio::test]
async fn a_passkey_login_with_no_browser_key_binds_none() {
    let mut fix = build_fixture(true).await;
    let (status, body, _) = passkey_login(&mut fix, None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, _) = call(
        &fix.vtc,
        &Party::new(),
        "https://trusttasks.org/spec/auth/whoami/0.1",
        json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

/// A key that is not an Ed25519 `did:key` is refused before the ceremony is
/// spent, and no session is minted.
#[tokio::test]
async fn a_passkey_login_refuses_a_malformed_browser_key() {
    let mut fix = build_fixture(true).await;
    let (status, body, cookies) = passkey_login(
        &mut fix,
        Some(json!({ "org.openvtc": { "sessionKey": "did:web:example.com" } })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(cookies.is_empty(), "{cookies:?}");
}
