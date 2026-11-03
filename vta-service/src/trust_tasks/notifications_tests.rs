//! The notifications slice through its own handlers: a notification or relay as an originator
//! and relayers sign it, delivered to a DID this VTA holds in a context, then listed, read and
//! dismissed by a client of that context. Every party is a `did:key`, so every proof verifies
//! with no network.

use super::*;
use crate::operations::persona::test_fixture as personas;
use crate::test_support::{admin_claims_for_context, did_for_seed, sign_received_as};
use trust_tasks_rs::TypeUri;
use vta_sdk::trust_tasks as uris;

const CTX: &str = "alice";
const OTHER: &str = "bob";
/// The originator — a community.
const COMMUNITY: u8 = 41;
/// A relayer — a member party of the community.
const PARTNER: u8 = 42;
/// A party nobody here has a relationship with.
const STRANGER: u8 = 43;

async fn state() -> (AppState, tempfile::TempDir, String) {
    let (state, dir) = crate::test_support::build_signing_test_app_state().await;
    for (id, name) in [(CTX, "Alice"), (OTHER, "Bob")] {
        crate::contexts::create_context(&state.contexts_ks, id, name)
            .await
            .expect("create context");
    }
    let persona = personas::did_key_persona(
        &state.keys_ks,
        &state.internal_ks,
        &state.contexts_ks,
        &state.acl_ks,
        &state.seed_store,
        &state.audit_sink,
        CTX,
        "alice-member",
    )
    .await;
    (state, dir, persona.did)
}

/// Give `seed`'s DID an ACL entry here: a relationship the policy counts (VTI-NTF-030).
async fn acl(state: &AppState, seed: u8) {
    let mut entry = crate::acl::AclEntry::new(&did_for_seed(seed).0, crate::acl::Role::Reader, "t");
    entry.allowed_contexts = vec![CTX.to_string()];
    crate::acl::store_acl_entry(&state.acl_ks, &entry)
        .await
        .unwrap();
}

fn now_secs() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

fn notification(id: &str, revision: u64, status: &str, relayable: bool) -> Value {
    let until = (chrono::Utc::now() + chrono::Duration::days(7))
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    json!({
        "notificationId": id,
        "revision": revision,
        "kind": "election",
        "subject": {
            "heldBy": did_for_seed(COMMUNITY).0,
            "id": "board-2027",
            "openWith": "https://trusttasks.org/spec/vtc/elections/show/0.6",
        },
        "audience": did_for_seed(PARTNER).0,
        "status": status,
        "relayable": relayable,
        "validUntil": until,
    })
}

/// A signed document of `type_uri` from `seed`'s DID to `recipient`, with a `.000Z`-free
/// timestamp, as received.
fn signed(type_uri: &str, seed: u8, recipient: &str, payload: Value) -> Value {
    let now = now_secs();
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

fn notify_doc(seed: u8, recipient: &str, n: Value) -> Value {
    signed(
        uris::TASK_NOTIFICATIONS_NOTIFY_0_1,
        seed,
        recipient,
        json!({ "notification": n }),
    )
}

fn relay_doc(seed: u8, recipient: &str, forwarded: Value) -> Value {
    signed(
        uris::TASK_NOTIFICATIONS_RELAY_0_1,
        seed,
        recipient,
        json!({ "forwarded": forwarded }),
    )
}

/// Deliver `received` as the spine would: parsed, with the received JSON recorded.
async fn deliver(state: &AppState, received: Value) -> TrustTaskOutcome {
    let doc: TrustTask<Value> = serde_json::from_value(received.clone()).unwrap();
    let auth = super::super::ceremony::ceremony_claims(doc.issuer.as_deref().unwrap());
    let relay = doc.type_uri.to_string() == uris::TASK_NOTIFICATIONS_RELAY_0_1;
    super::super::received::scope(std::sync::Arc::new(received), async move {
        if relay {
            handle_relay(state, &auth, doc).await
        } else {
            handle_notify(state, &auth, doc).await
        }
    })
    .await
}

fn task(uri: &str, payload: Value) -> TrustTask<Value> {
    let uri: TypeUri = uri.parse().unwrap();
    TrustTask::new(format!("urn:uuid:{}", uuid::Uuid::new_v4()), uri, payload)
}

fn body(out: &TrustTaskOutcome) -> Value {
    serde_json::from_slice(&out.body).expect("JSON")
}

fn ok(out: &TrustTaskOutcome) -> Value {
    let b = body(out);
    assert!(out.status.is_success(), "expected success, got {b:#}");
    b["payload"].clone()
}

fn code(out: &TrustTaskOutcome) -> String {
    body(out)["payload"]["code"]
        .as_str()
        .unwrap_or_default()
        .to_string()
}

async fn list(state: &AppState, ctx: &str, extra: Value) -> TrustTaskOutcome {
    let mut p = json!({ "contextId": ctx });
    for (k, v) in extra.as_object().unwrap() {
        p[k] = v.clone();
    }
    handle_list(
        state,
        &admin_claims_for_context(ctx),
        task(uris::TASK_VTA_NOTIFICATIONS_LIST_0_1, p),
    )
    .await
}

/// VTI-NTF-050: a notification from a party the principal has a relationship with is held in
/// the context of the DID it was addressed to, listed there, and read back with the document
/// exactly as received.
#[tokio::test]
async fn vti_ntf_050_a_notification_is_held_in_its_context_and_read_back_as_received() {
    let (state, _dir, member) = state().await;
    acl(&state, COMMUNITY).await;
    let sent = notify_doc(
        COMMUNITY,
        &member,
        notification("ntf-1", 1, "available", true),
    );
    let receipt = ok(&deliver(&state, sent.clone()).await);
    assert_eq!(receipt, json!({ "notificationId": "ntf-1", "revision": 1 }));

    let page = ok(&list(&state, CTX, json!({ "kind": "election" })).await);
    let items = page["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["originator"], json!(did_for_seed(COMMUNITY).0));
    assert_eq!(items[0]["relayedBy"], json!([]));
    assert_eq!(items[0]["addressee"], json!(member));
    let record_id = items[0]["recordId"].as_str().unwrap().to_string();

    let shown = ok(&handle_show(
        &state,
        &admin_claims_for_context(CTX),
        task(
            uris::TASK_VTA_NOTIFICATIONS_SHOW_0_1,
            json!({ "contextId": CTX, "recordId": record_id }),
        ),
    )
    .await);
    assert_eq!(shown["document"], sent, "the document exactly as received");
}

/// VTI-NTF-023 / VTI-NTF-030: a stranger's verified notification is declined, and answered with
/// exactly the receipt a held one gets.
#[tokio::test]
async fn vti_ntf_023_the_receipt_is_the_same_whether_held_or_declined() {
    let (state, _dir, member) = state().await;
    acl(&state, COMMUNITY).await;
    let held = ok(&deliver(
        &state,
        notify_doc(
            COMMUNITY,
            &member,
            notification("same", 1, "available", true),
        ),
    )
    .await);
    let declined = ok(&deliver(
        &state,
        notify_doc(
            STRANGER,
            &member,
            notification("same", 1, "available", true),
        ),
    )
    .await);
    assert_eq!(held, declined);
    let page = ok(&list(&state, CTX, json!({})).await);
    assert_eq!(
        page["items"].as_array().unwrap().len(),
        1,
        "only the held one"
    );
}

/// VTI-NTF-022 / VTI-NTF-024: one record per originator and notificationId; a higher revision
/// replaces it (a withdrawal leaves it lapsed), an equal or lower one changes nothing.
#[tokio::test]
async fn vti_ntf_022_a_higher_revision_replaces_and_a_lower_changes_nothing() {
    let (state, _dir, member) = state().await;
    acl(&state, COMMUNITY).await;
    ok(&deliver(
        &state,
        notify_doc(COMMUNITY, &member, notification("n", 1, "available", true)),
    )
    .await);
    ok(&deliver(
        &state,
        notify_doc(COMMUNITY, &member, notification("n", 2, "withdrawn", true)),
    )
    .await);
    ok(&deliver(
        &state,
        notify_doc(COMMUNITY, &member, notification("n", 1, "available", true)),
    )
    .await);

    assert!(
        ok(&list(&state, CTX, json!({})).await)["items"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    let lapsed = ok(&list(&state, CTX, json!({ "includeLapsed": true })).await);
    let items = lapsed["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["notification"]["revision"], 2);
    assert_eq!(items[0]["notification"]["status"], "withdrawn");
}

/// VTI-NTF-031 / VTI-NTF-042: a relay is held on the relayer's standing, never the
/// originator's, and every layer is checked — a forwarded document not addressed to its
/// relayer, or a notification that may not be relayed, is `chainInvalid`.
#[tokio::test]
async fn vti_ntf_042_a_relay_is_verified_layer_by_layer_and_held_on_the_relayers_standing() {
    let (state, _dir, member) = state().await;
    // Only the partner has standing; the originating community has none here.
    acl(&state, PARTNER).await;
    let partner = did_for_seed(PARTNER).0;
    let inner = notify_doc(COMMUNITY, &partner, notification("r", 1, "available", true));
    ok(&deliver(&state, relay_doc(PARTNER, &member, inner.clone())).await);
    let page = ok(&list(&state, CTX, json!({})).await);
    assert_eq!(page["items"][0]["relayedBy"], json!([partner]));
    assert_eq!(
        page["items"][0]["originator"],
        json!(did_for_seed(COMMUNITY).0)
    );

    // Forwarded by a party it was not addressed to.
    let out = deliver(&state, relay_doc(STRANGER, &member, inner)).await;
    assert_eq!(code(&out), "notifications/relay:chainInvalid");

    // A notification its originator said may not be relayed.
    let fixed = notify_doc(
        COMMUNITY,
        &partner,
        notification("x", 1, "available", false),
    );
    let out = deliver(&state, relay_doc(PARTNER, &member, fixed)).await;
    assert_eq!(code(&out), "notifications/relay:chainInvalid");

    // A forwarded layer whose proof no longer holds.
    let mut tampered = notify_doc(COMMUNITY, &partner, notification("t", 1, "available", true));
    tampered["payload"]["notification"]["subject"]["id"] = json!("another");
    let out = deliver(&state, relay_doc(PARTNER, &member, tampered)).await;
    assert_eq!(code(&out), "notifications/relay:chainInvalid");
}

/// VTI-NTF-042: more than four relays in all is refused.
#[tokio::test]
async fn vti_ntf_042_more_than_four_relays_is_refused() {
    let (state, _dir, member) = state().await;
    acl(&state, 50).await;
    // community → 46 → 47 → 48 → 49 → 50 → member: five relays.
    let mut layer = notify_doc(
        COMMUNITY,
        &did_for_seed(46).0,
        notification("d", 1, "available", true),
    );
    for (from, to) in [(46u8, 47u8), (47, 48), (48, 49), (49, 50)] {
        layer = relay_doc(from, &did_for_seed(to).0, layer);
    }
    let out = deliver(&state, relay_doc(50, &member, layer)).await;
    assert_eq!(code(&out), "notifications/relay:chainInvalid");
}

/// VTI-NTF-032: a notification whose period has ended is discarded, never held.
#[tokio::test]
async fn vti_ntf_032_a_lapsed_notification_is_not_held() {
    let (state, _dir, member) = state().await;
    acl(&state, COMMUNITY).await;
    let mut n = notification("old", 1, "available", true);
    n["validUntil"] = json!("2020-01-01T00:00:00Z");
    ok(&deliver(&state, notify_doc(COMMUNITY, &member, n)).await);
    let page = ok(&list(&state, CTX, json!({ "includeLapsed": true })).await);
    assert!(page["items"].as_array().unwrap().is_empty());
}

/// VTI-NTF-051: a party without standing in the context learns nothing of it, and a record of
/// one context is unknown in another.
#[tokio::test]
async fn vti_ntf_051_another_context_learns_nothing() {
    let (state, _dir, member) = state().await;
    acl(&state, COMMUNITY).await;
    ok(&deliver(
        &state,
        notify_doc(COMMUNITY, &member, notification("c", 1, "available", true)),
    )
    .await);
    let record_id = ok(&list(&state, CTX, json!({})).await)["items"][0]["recordId"]
        .as_str()
        .unwrap()
        .to_string();

    let out = handle_list(
        &state,
        &admin_claims_for_context(OTHER),
        task(
            uris::TASK_VTA_NOTIFICATIONS_LIST_0_1,
            json!({ "contextId": CTX }),
        ),
    )
    .await;
    assert_eq!(code(&out), "permissionDenied");
    let out = handle_show(
        &state,
        &admin_claims_for_context(OTHER),
        task(
            uris::TASK_VTA_NOTIFICATIONS_SHOW_0_1,
            json!({ "contextId": OTHER, "recordId": record_id }),
        ),
    )
    .await;
    assert_eq!(code(&out), "vta/notifications/show:notificationUnknown");
}

/// VTI-NTF-052: dismissal takes a notification out of the default list, says whether it
/// changed anything, and leaves it readable and listable when asked for.
#[tokio::test]
async fn vti_ntf_052_dismissal_hides_without_discarding() {
    let (state, _dir, member) = state().await;
    acl(&state, COMMUNITY).await;
    ok(&deliver(
        &state,
        notify_doc(COMMUNITY, &member, notification("z", 1, "available", true)),
    )
    .await);
    let record_id = ok(&list(&state, CTX, json!({})).await)["items"][0]["recordId"]
        .as_str()
        .unwrap()
        .to_string();
    let claims = admin_claims_for_context(CTX);
    let dismiss = || {
        handle_dismiss(
            &state,
            &claims,
            task(
                uris::TASK_VTA_NOTIFICATIONS_DISMISS_0_1,
                json!({ "contextId": CTX, "recordId": record_id }),
            ),
        )
    };
    assert_eq!(ok(&dismiss().await)["changed"], true);
    assert_eq!(ok(&dismiss().await)["changed"], false);
    assert!(
        ok(&list(&state, CTX, json!({})).await)["items"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    let all = ok(&list(&state, CTX, json!({ "includeDismissed": true })).await);
    assert_eq!(all["items"][0]["state"], "dismissed");
    assert!(all["items"][0]["dismissedAt"].is_string());
}

/// `vta/notifications/dismiss:notificationUnknown`: a record this VTA holds nowhere, or in
/// another context, is the declared refusal.
#[tokio::test]
async fn vti_ntf_052_dismissing_an_unknown_record_is_notification_unknown() {
    let (state, _dir, _member) = state().await;
    let out = handle_dismiss(
        &state,
        &admin_claims_for_context(CTX),
        task(
            uris::TASK_VTA_NOTIFICATIONS_DISMISS_0_1,
            json!({ "contextId": CTX, "recordId": "hn-0000000000000000" }),
        ),
    )
    .await;
    assert_eq!(code(&out), "vta/notifications/dismiss:notificationUnknown");
}

/// VTI-NTF-041: four relays in all is the bound, and a delivery that reaches it is held — a
/// relayer that received the notification through three relays may relay it once more.
#[tokio::test]
async fn vti_ntf_041_a_fourth_relay_is_accepted() {
    let (state, _dir, member) = state().await;
    acl(&state, 49).await;
    // community → 46 → 47 → 48 → 49 → member: four relays.
    let mut layer = notify_doc(
        COMMUNITY,
        &did_for_seed(46).0,
        notification("four", 1, "available", true),
    );
    for (from, to) in [(46u8, 47u8), (47, 48), (48, 49)] {
        layer = relay_doc(from, &did_for_seed(to).0, layer);
    }
    ok(&deliver(&state, relay_doc(49, &member, layer)).await);
    let page = ok(&list(&state, CTX, json!({})).await);
    assert_eq!(page["items"][0]["relayedBy"].as_array().unwrap().len(), 4);
}

// ─── vta/notifications/deposit/0.1 (VTI-NTF-054 – 056) ─────────────────────────

/// Deposit `document` as a client holding `claims` in `context`.
async fn deposit(
    state: &AppState,
    claims: &AuthClaims,
    context: &str,
    document: Value,
) -> TrustTaskOutcome {
    handle_deposit(
        state,
        claims,
        task(
            uris::TASK_VTA_NOTIFICATIONS_DEPOSIT_0_1,
            json!({ "contextId": context, "document": document }),
        ),
    )
    .await
}

/// VTI-NTF-055: a document a client deposits for a persona DID is held exactly as a direct
/// delivery would be — in the DID's context, with the document whole as the client received
/// it — and answered with the same receipt.
#[tokio::test]
async fn vti_ntf_055_a_deposited_notification_is_held_as_if_delivered_directly() {
    let (state, _dir, member) = state().await;
    acl(&state, COMMUNITY).await;
    let sent = notify_doc(
        COMMUNITY,
        &member,
        notification("dep-1", 1, "available", true),
    );
    let receipt = ok(&deposit(&state, &admin_claims_for_context(CTX), CTX, sent.clone()).await);
    assert_eq!(receipt, json!({ "notificationId": "dep-1", "revision": 1 }));

    let page = ok(&list(&state, CTX, json!({})).await);
    let items = page["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["originator"], json!(did_for_seed(COMMUNITY).0));
    let record_id = items[0]["recordId"].as_str().unwrap().to_string();
    let shown = ok(&handle_show(
        &state,
        &admin_claims_for_context(CTX),
        task(
            uris::TASK_VTA_NOTIFICATIONS_SHOW_0_1,
            json!({ "contextId": CTX, "recordId": record_id }),
        ),
    )
    .await);
    assert_eq!(shown["document"], sent, "the document exactly as deposited");

    // A repeat of the same document: the same receipt, still one record (retry class 2).
    let again = ok(&deposit(&state, &admin_claims_for_context(CTX), CTX, sent).await);
    assert_eq!(again, receipt);
    assert_eq!(
        ok(&list(&state, CTX, json!({})).await)["items"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
}

/// VTI-NTF-055: the acceptance policy counts the party that delivered the document, never the
/// depositing client — a client with standing cannot make the VTA hold a stranger's
/// notification — and the receipt does not say it was declined (VTI-NTF-023). A relay is
/// counted on its last relayer, as a direct one is.
#[tokio::test]
async fn vti_ntf_055_the_depositing_client_is_never_the_relationship_counted() {
    let (state, _dir, member) = state().await;
    let from_stranger = notify_doc(
        STRANGER,
        &member,
        notification("dep-s", 1, "available", true),
    );
    let receipt = ok(&deposit(&state, &admin_claims_for_context(CTX), CTX, from_stranger).await);
    assert_eq!(receipt, json!({ "notificationId": "dep-s", "revision": 1 }));
    assert!(
        ok(&list(&state, CTX, json!({ "includeLapsed": true })).await)["items"]
            .as_array()
            .unwrap()
            .is_empty(),
        "declined: the stranger has no relationship with the principal"
    );

    acl(&state, PARTNER).await;
    let partner = did_for_seed(PARTNER).0;
    let inner = notify_doc(
        COMMUNITY,
        &partner,
        notification("dep-r", 1, "available", true),
    );
    ok(&deposit(
        &state,
        &admin_claims_for_context(CTX),
        CTX,
        relay_doc(PARTNER, &member, inner),
    )
    .await);
    let page = ok(&list(&state, CTX, json!({})).await);
    assert_eq!(page["items"][0]["relayedBy"], json!([partner]));
}

/// VTI-NTF-056 (consumer item 1): a client without standing in the named context is refused
/// before the document is read.
#[tokio::test]
async fn vti_ntf_056_a_deposit_needs_standing_in_the_context() {
    let (state, _dir, member) = state().await;
    acl(&state, COMMUNITY).await;
    let sent = notify_doc(
        COMMUNITY,
        &member,
        notification("dep-p", 1, "available", true),
    );
    let out = deposit(&state, &admin_claims_for_context(OTHER), CTX, sent).await;
    assert_eq!(code(&out), "permissionDenied");
}

/// `vta/notifications/deposit:notAddressedHere` (VTI-NTF-056): a document addressed to a DID
/// this VTA holds no keys of, or to one it holds in another context, holds nothing.
#[tokio::test]
async fn vti_ntf_056_a_document_not_addressed_to_a_did_held_in_the_context_is_refused() {
    let (state, _dir, member) = state().await;
    acl(&state, COMMUNITY).await;
    let elsewhere = notify_doc(
        COMMUNITY,
        &did_for_seed(STRANGER).0,
        notification("dep-a", 1, "available", true),
    );
    let out = deposit(&state, &admin_claims_for_context(CTX), CTX, elsewhere).await;
    assert_eq!(code(&out), "vta/notifications/deposit:notAddressedHere");

    // Addressed to the persona, which is held in CTX — not in OTHER.
    let sent = notify_doc(
        COMMUNITY,
        &member,
        notification("dep-b", 1, "available", true),
    );
    let out = deposit(&state, &admin_claims_for_context(OTHER), OTHER, sent).await;
    assert_eq!(code(&out), "vta/notifications/deposit:notAddressedHere");
}

/// `vta/notifications/deposit:documentInvalid` (consumer item 3): a document that would not
/// have been accepted had it been delivered directly — a broken proof, a type that is not a
/// notification, one past its acceptance window at the hand-over, a relay with a misaddressed
/// layer — holds nothing.
#[tokio::test]
async fn vti_ntf_055_a_document_a_direct_delivery_would_refuse_is_document_invalid() {
    let (state, _dir, member) = state().await;
    acl(&state, COMMUNITY).await;
    acl(&state, PARTNER).await;
    let claims = admin_claims_for_context(CTX);

    let mut tampered = notify_doc(
        COMMUNITY,
        &member,
        notification("i-1", 1, "available", true),
    );
    tampered["payload"]["notification"]["subject"]["id"] = json!("another");
    let out = deposit(&state, &claims, CTX, tampered).await;
    assert_eq!(code(&out), "vta/notifications/deposit:documentInvalid");

    let not_a_notification = signed(
        uris::TASK_VTA_NOTIFICATIONS_LIST_0_1,
        COMMUNITY,
        &member,
        json!({ "contextId": CTX }),
    );
    let out = deposit(&state, &claims, CTX, not_a_notification).await;
    assert_eq!(code(&out), "vta/notifications/deposit:documentInvalid");

    // Signed two hours ago: outside the acceptance window at the time of the deposit.
    let stale_at = (chrono::Utc::now() - chrono::Duration::hours(2))
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let mut stale = json!({
        "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        "type": uris::TASK_NOTIFICATIONS_NOTIFY_0_1,
        "issuer": did_for_seed(COMMUNITY).0,
        "recipient": member,
        "issuedAt": stale_at,
        "payload": { "notification": notification("i-3", 1, "available", true) },
    });
    sign_received_as(COMMUNITY, "authentication", &stale_at, &mut stale);
    let out = deposit(&state, &claims, CTX, stale).await;
    assert_eq!(code(&out), "vta/notifications/deposit:documentInvalid");

    let inner = notify_doc(
        COMMUNITY,
        &did_for_seed(STRANGER).0,
        notification("i-4", 1, "available", true),
    );
    let out = deposit(&state, &claims, CTX, relay_doc(PARTNER, &member, inner)).await;
    assert_eq!(code(&out), "vta/notifications/deposit:documentInvalid");

    assert!(
        ok(&list(&state, CTX, json!({ "includeLapsed": true })).await)["items"]
            .as_array()
            .unwrap()
            .is_empty()
    );
}
