//! What the VTA answers as a persona it collects for (VTI-NTF-086, VTI-NTF-087),
//! and the `vta/collection/*` handlers' declared codes. Every party is a
//! `did:key`, so every proof verifies with no network.

use super::*;
use crate::test_support::{admin_claims_for_context, did_for_seed, sign_received_as};
use trust_tasks_rs::TypeUri;
use vta_sdk::trust_tasks as uris;

const CTX: &str = "alice";
/// The originator, which holds an ACL entry so the policy counts it.
const COMMUNITY: u8 = 51;
/// A sender with standing here asking the persona for something else.
const ADMIN_SENDER: u8 = 52;

async fn setup() -> (AppState, tempfile::TempDir, CollectedIdentity) {
    let (state, dir) = crate::test_support::build_signing_test_app_state().await;
    crate::contexts::create_context(&state.contexts_ks, CTX, "Alice")
        .await
        .unwrap();
    // A derived (exportable) key: collecting loads the key into the session,
    // which an internal key never allows.
    let created = crate::operations::keys::create_key(
        &state.keys_ks,
        &state.internal_ks,
        &state.contexts_ks,
        &state.seed_store,
        &state.audit_sink,
        &state.acl_ks,
        &crate::test_support::super_admin_claims(),
        crate::operations::keys::CreateKeyParams {
            key_type: vta_keys::KeyType::Ed25519,
            internal: false,
            derivation_path: None,
            key_id: Some("alice-persona".into()),
            mnemonic: None,
            label: None,
            context_id: Some(CTX.into()),
        },
        "test",
    )
    .await
    .unwrap();
    let did = format!("did:key:{}", created.public_key);
    let vm = format!("{did}#{}", created.public_key);
    let secret = crate::operations::keys::key_secret_for_test_support(
        &state.keys_ks,
        &state.imported_ks,
        &state.contexts_ks,
        &*state.seed_store,
        &state.audit_sink,
        "alice-persona",
    )
    .await
    .unwrap();
    let signing = affinidi_tdk::secrets_resolver::secrets::Secret::from_multibase(
        &secret.private_key_multibase,
        Some(&vm),
    )
    .unwrap();
    for seed in [COMMUNITY, ADMIN_SENDER] {
        let mut entry =
            crate::acl::AclEntry::new(&did_for_seed(seed).0, crate::acl::Role::Admin, "t");
        entry.allowed_contexts = vec![CTX.to_string()];
        crate::acl::store_acl_entry(&state.acl_ks, &entry)
            .await
            .unwrap();
    }
    let me = CollectedIdentity {
        context_id: CTX.into(),
        identifier: did.clone(),
        log_did: did,
        signing: vec![signing],
    };
    (state, dir, me)
}

fn signed(type_uri: &str, seed: u8, recipient: &str, payload: Value) -> Value {
    let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let mut doc = json!({
        "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        "type": type_uri,
        "issuer": did_for_seed(seed).0,
        "recipient": recipient,
        "issuedAt": now,
        "payload": payload,
    });
    sign_received_as(seed, "assertionMethod", &now, &mut doc);
    doc
}

fn notification() -> Value {
    let until = (chrono::Utc::now() + chrono::Duration::days(7))
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    json!({
        "notificationId": "ntf-collected-1",
        "revision": 1,
        "kind": "election",
        "subject": {
            "heldBy": did_for_seed(COMMUNITY).0,
            "id": "board-2027",
            "openWith": "https://trusttasks.org/spec/vtc/elections/show/0.6",
        },
        "audience": did_for_seed(COMMUNITY).0,
        "status": "available",
        "relayable": false,
        "validUntil": until,
    })
}

async fn answer(state: &AppState, me: &CollectedIdentity, sender: u8, doc: &Value) -> Value {
    let reply = answer_collected(
        state,
        me,
        &did_for_seed(sender).0,
        &serde_json::to_vec(doc).unwrap(),
    )
    .await
    .expect("answered");
    serde_json::from_slice(&reply).unwrap()
}

/// The answer is the persona's: issued and signed as it, verifiable, and never
/// naming this VTA (VTI-NTF-086, VTI-NTF-087).
async fn assert_from_persona(state: &AppState, me: &CollectedIdentity, reply: &Value) {
    assert_eq!(reply["issuer"], me.identifier, "{reply:#}");
    let vta_did = state.config.read().await.vta_did.clone().unwrap();
    assert!(
        !reply.to_string().contains(&vta_did),
        "the answer names the VTA: {reply:#}"
    );
    let typed: TrustTask<Value> = serde_json::from_value(reply.clone()).unwrap();
    let signer =
        vti_common::auth::verify_trust_task_proof_with(&typed, &state.trust_task_vm_resolver())
            .await
            .expect("the persona's proof verifies");
    assert_eq!(signer.split('#').next(), Some(me.identifier.as_str()));
}

#[tokio::test]
async fn vti_ntf_086_a_collected_notification_is_held_and_answered_as_the_persona() {
    let (state, _dir, me) = setup().await;
    let doc = signed(
        uris::TASK_NOTIFICATIONS_NOTIFY_0_1,
        COMMUNITY,
        &me.identifier,
        json!({ "notification": notification() }),
    );
    let reply = answer(&state, &me, COMMUNITY, &doc).await;
    assert_eq!(
        reply["payload"]["notificationId"], "ntf-collected-1",
        "{reply:#}"
    );
    assert_eq!(reply["threadId"], doc["id"]);
    assert_from_persona(&state, &me, &reply).await;

    // Held in the persona's context, as a deposit would be.
    let auth = admin_claims_for_context(CTX);
    let page = crate::operations::notifications::list(
        &state,
        &auth,
        CTX,
        &Default::default(),
        None,
        None,
        chrono::Utc::now(),
    )
    .await
    .unwrap();
    assert_eq!(page.items.len(), 1);

    // A repeat is answered with the same receipt and holds nothing more.
    let again = answer(&state, &me, COMMUNITY, &doc).await;
    assert_eq!(again["payload"], reply["payload"]);
}

#[tokio::test]
async fn vti_ntf_087_any_other_operation_is_refused_as_not_served_whatever_the_senders_standing() {
    let (state, _dir, me) = setup().await;
    // An administrator of this very context asks the persona to list keys.
    let doc = signed(
        "https://trusttasks.org/spec/keys/list/0.2",
        ADMIN_SENDER,
        &me.identifier,
        json!({}),
    );
    let reply = answer(&state, &me, ADMIN_SENDER, &doc).await;
    assert_eq!(reply["payload"]["code"], "unsupportedType", "{reply:#}");
    assert_from_persona(&state, &me, &reply).await;
}

#[tokio::test]
async fn vti_ntf_086_a_notification_not_bound_to_its_sender_is_refused() {
    let (state, _dir, me) = setup().await;
    let doc = signed(
        uris::TASK_NOTIFICATIONS_NOTIFY_0_1,
        COMMUNITY,
        &me.identifier,
        json!({ "notification": notification() }),
    );
    // Delivered by somebody other than its issuer.
    let reply = answer(&state, &me, ADMIN_SENDER, &doc).await;
    assert_ne!(
        reply["type"],
        format!("{}#response", uris::TASK_NOTIFICATIONS_NOTIFY_0_1)
    );
    assert!(reply["payload"]["code"].is_string(), "{reply:#}");
    assert_from_persona(&state, &me, &reply).await;
}

#[tokio::test]
async fn an_error_or_reply_collected_for_a_persona_is_not_answered() {
    let (state, _dir, me) = setup().await;
    let error = json!({
        "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        "threadId": "urn:uuid:11111111-1111-1111-1111-111111111111",
        "type": "https://trusttasks.org/spec/trust-task-error/0.5",
        "payload": { "code": "permissionDenied", "message": "no" },
    });
    assert!(
        answer_collected(
            &state,
            &me,
            &did_for_seed(COMMUNITY).0,
            &serde_json::to_vec(&error).unwrap()
        )
        .await
        .is_none()
    );
}

fn task(uri: &str, payload: Value) -> TrustTask<Value> {
    let uri: TypeUri = uri.parse().unwrap();
    TrustTask::new(format!("urn:uuid:{}", uuid::Uuid::new_v4()), uri, payload)
}

fn code(out: &TrustTaskOutcome) -> String {
    serde_json::from_slice::<Value>(&out.body).unwrap()["payload"]["code"]
        .as_str()
        .unwrap_or_default()
        .to_string()
}

/// Every declared code of the three tasks, driven through the handlers.
#[tokio::test]
async fn declared_codes_reach_the_wire() {
    let (state, _dir, me) = setup().await;
    // A did:key persona is not a candidate (no mediated transport).
    let auth = admin_claims_for_context(CTX);
    let p = json!({ "contextId": CTX, "identifier": me.identifier });
    let out = handle_claim(
        &state,
        &auth,
        task(uris::TASK_VTA_COLLECTION_CLAIM_0_1, p.clone()),
    )
    .await;
    assert_eq!(code(&out), "vta/collection/claim:notCollectable");
    let out = handle_release(
        &state,
        &auth,
        task(uris::TASK_VTA_COLLECTION_RELEASE_0_1, p),
    )
    .await;
    assert_eq!(code(&out), "vta/collection/release:notCollectable");
    let outsider = admin_claims_for_context("elsewhere");
    let out = handle_list(
        &state,
        &outsider,
        task(
            uris::TASK_VTA_COLLECTION_LIST_0_1,
            json!({ "contextId": CTX }),
        ),
    )
    .await;
    assert_eq!(code(&out), "permissionDenied");
    let out = handle_list(
        &state,
        &auth,
        task(
            uris::TASK_VTA_COLLECTION_LIST_0_1,
            json!({ "contextId": CTX }),
        ),
    )
    .await;
    assert!(out.status.is_success());
}

/// `claimHeld` and `claimNotRenewable`, through the handler, on a persona that
/// advertises a mediator.
#[tokio::test]
async fn declared_claim_refusals_reach_the_wire() {
    use crate::operations::collection::tests::{MEDIATOR, seed_persona};
    let (state, _dir, _me) = setup().await;
    let persona = "did:webvh:QmWire:persona.example";
    seed_persona(&state, CTX, persona, Some(MEDIATOR)).await;
    let mut a = admin_claims_for_context(CTX);
    a.did = "did:key:z6MkClientA".into();
    let mut b = admin_claims_for_context(CTX);
    b.did = "did:key:z6MkClientB".into();
    let p = json!({ "contextId": CTX, "identifier": persona, "durationSeconds": 3600 });

    let out = handle_claim(
        &state,
        &a,
        task(uris::TASK_VTA_COLLECTION_CLAIM_0_1, p.clone()),
    )
    .await;
    assert!(out.status.is_success());
    let out = handle_claim(
        &state,
        &b,
        task(uris::TASK_VTA_COLLECTION_CLAIM_0_1, p.clone()),
    )
    .await;
    assert_eq!(code(&out), "vta/collection/claim:claimHeld");
    let out = handle_release(
        &state,
        &b,
        task(
            uris::TASK_VTA_COLLECTION_RELEASE_0_1,
            json!({ "contextId": CTX, "identifier": persona }),
        ),
    )
    .await;
    assert!(out.status.is_success());
    let out = handle_claim(&state, &a, task(uris::TASK_VTA_COLLECTION_CLAIM_0_1, p)).await;
    assert_eq!(code(&out), "vta/collection/claim:claimNotRenewable");
}
