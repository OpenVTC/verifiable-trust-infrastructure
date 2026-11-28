//! The member's calendar through its own handlers (VTI-CAL-001 – 071): standing per context,
//! the declared refusals, alerts, feeds (served on their REST route), receipts verified and kept
//! as received. Every party is a `did:key`, so every proof verifies with no network; entries
//! are written straight into the store as a sync would have left them.

use super::*;
use crate::operations::calendar::{self as cal, Entry};
use crate::operations::persona::test_fixture as personas;
use crate::test_support::{admin_claims_for_context, did_for_seed, sign_received_as};
use axum::extract::{Path, State};
use axum::response::IntoResponse;
use chrono::{Duration, Utc};
use trust_tasks_rs::TypeUri;
use vta_sdk::trust_tasks as uris;

const CTX: &str = "alice";
const OTHER: &str = "bob";
/// The community — a `did:key`, so its proof verifies offline.
const COMMUNITY: u8 = 51;
const EVENT: &str = "evt_AAAAAAAAAAAAAAAA";
const OTHER_EVENT: &str = "evt_BBBBBBBBBBBBBBBB";
const REGISTER_RESPONSE: &str =
    "https://trusttasks.org/spec/vtc/events/registrations/register/0.2#response";

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
    state.config.write().await.public_url = Some("https://vta.example".into());
    (state, dir, persona.did)
}

fn community() -> String {
    did_for_seed(COMMUNITY).0
}

/// An entry as a sync of `ctx` would have left it, starting `days` from now.
async fn put_entry(state: &AppState, ctx: &str, event_id: &str, title: &str, days: i64) {
    let start = (Utc::now() + Duration::days(days))
        .naive_utc()
        .format("%Y-%m-%dT%H:%M:%S")
        .to_string();
    let e = Entry {
        context_id: ctx.to_string(),
        community: community(),
        identifier: format!("did:key:z6Mk{ctx}member"),
        event_id: event_id.to_string(),
        event: json!({
            "eventId": event_id,
            "title": title,
            "when": { "start": start, "timeZone": "Etc/UTC", "duration": "PT2H" },
            "status": "published",
            "sequence": 1,
        }),
        registration: json!({ "status": "going" }),
        read_at: Utc::now(),
        fired_sequence: 0,
        fired: Vec::new(),
    };
    cal::put_entry(&state.calendar_ks, &e).await.unwrap();
}

/// The creator of a feed holds an ACL entry in `ctx` (VTI-CAL-055 reads it at every fetch).
async fn creator_in(state: &AppState, ctx: &str) {
    let did = admin_claims_for_context(ctx).did;
    let mut entry = crate::acl::AclEntry::new(&did, crate::acl::Role::Admin, "t");
    entry.allowed_contexts = vec![ctx.to_string()];
    crate::acl::store_acl_entry(&state.acl_ks, &entry)
        .await
        .unwrap();
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

fn now_secs() -> String {
    Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// GET the feed route the way axum would.
async fn fetch(state: &AppState, token: &str) -> (axum::http::StatusCode, String, String) {
    let resp = crate::routes::calendar_feed::calendar_feed_handler(
        State(state.clone()),
        Path(format!("{token}.ics")),
    )
    .await
    .into_response();
    let status = resp.status();
    let ct = resp
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    (status, ct, String::from_utf8(bytes.to_vec()).unwrap())
}

fn token_of(url: &str) -> String {
    url.rsplit('/')
        .next()
        .unwrap()
        .trim_end_matches(".ics")
        .to_string()
}

async fn create_feed(state: &AppState, payload: Value) -> TrustTaskOutcome {
    handle_feeds_create(
        state,
        &admin_claims_for_context(CTX),
        task(uris::TASK_VTA_CALENDAR_FEEDS_CREATE_0_1, payload),
    )
    .await
}

fn in_days(days: i64) -> String {
    (Utc::now() + Duration::days(days)).to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

// ─── standing (VTI-CAL-001, VTI-CAL-002) ─────────────────────────────────

/// VTI-CAL-001 / VTI-CAL-002: a listing answers only for the contexts the caller has standing
/// in. Naming another context is not an error — it is simply not answered for — and a task
/// about one context the caller has no standing in is refused before anything is read.
#[tokio::test]
async fn vti_cal_002_a_listing_answers_only_for_contexts_with_standing() {
    let (state, _dir, _) = state().await;
    put_entry(&state, CTX, EVENT, "Soldering night", 2).await;
    put_entry(&state, OTHER, OTHER_EVENT, "Bob's secret", 3).await;
    let alice = admin_claims_for_context(CTX);

    let all = ok(&handle_list(
        &state,
        &alice,
        task(uris::TASK_VTA_CALENDAR_LIST_0_1, json!({})),
    )
    .await);
    let items = all["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["contextId"], CTX);
    assert!(!all.to_string().contains("Bob's secret"));

    let named = ok(&handle_list(
        &state,
        &alice,
        task(
            uris::TASK_VTA_CALENDAR_LIST_0_1,
            json!({ "contextIds": [OTHER] }),
        ),
    )
    .await);
    assert_eq!(
        named,
        json!({ "items": [] }),
        "no count, no error, no marked omission"
    );

    let out = handle_settings_show(
        &state,
        &alice,
        task(
            uris::TASK_VTA_CALENDAR_SETTINGS_SHOW_0_1,
            json!({ "contextId": OTHER }),
        ),
    )
    .await;
    assert_eq!(code(&out), "permissionDenied");
}

/// VTI-CAL-023: overlapping entries the caller may see are marked as overlapping.
#[tokio::test]
async fn vti_cal_023_overlaps_are_marked() {
    let (state, _dir, _) = state().await;
    put_entry(&state, CTX, EVENT, "One", 2).await;
    put_entry(&state, CTX, OTHER_EVENT, "Two", 2).await;
    let page = ok(&handle_list(
        &state,
        &admin_claims_for_context(CTX),
        task(uris::TASK_VTA_CALENDAR_LIST_0_1, json!({})),
    )
    .await);
    let items = page["items"].as_array().unwrap();
    assert_eq!(items.len(), 2);
    assert!(items.iter().all(|i| i["overlaps"] == true));
}

/// `list` and `export` refuse a range whose end is not after its start.
#[tokio::test]
async fn vti_cal_list_and_export_refuse_an_inverted_range() {
    let (state, _dir, _) = state().await;
    let alice = admin_claims_for_context(CTX);
    let range = json!({ "from": in_days(2), "to": in_days(1) });
    let out = handle_list(
        &state,
        &alice,
        task(uris::TASK_VTA_CALENDAR_LIST_0_1, range.clone()),
    )
    .await;
    assert_eq!(code(&out), "vta/calendar/list:rangeInvalid");
    let out = handle_export(
        &state,
        &alice,
        task(uris::TASK_VTA_CALENDAR_EXPORT_0_1, range),
    )
    .await;
    assert_eq!(code(&out), "vta/calendar/export:rangeInvalid");
}

// ─── settings, sync, alerts, busy times ──────────────────────────────────

/// VTI-CAL-010: reading is off until the context turns it on; a context whose reading is off is
/// not read. Quiet hours name a real zone (VTI-CAL-042).
#[tokio::test]
async fn vti_cal_010_sync_is_off_until_turned_on_and_quiet_hours_are_checked() {
    let (state, _dir, _) = state().await;
    let alice = admin_claims_for_context(CTX);
    let shown = ok(&handle_settings_show(
        &state,
        &alice,
        task(
            uris::TASK_VTA_CALENDAR_SETTINGS_SHOW_0_1,
            json!({ "contextId": CTX }),
        ),
    )
    .await);
    assert_eq!(shown["settings"]["sync"], false);

    let out = handle_settings_update(
        &state,
        &alice,
        task(
            uris::TASK_VTA_CALENDAR_SETTINGS_UPDATE_0_1,
            json!({ "contextId": CTX,
                    "quietHours": { "startsAt": "22:00", "endsAt": "07:00", "timeZone": "Nowhere/Atlantis" } }),
        ),
    )
    .await;
    assert_eq!(code(&out), "vta/calendar/settings/update:quietHoursInvalid");

    let updated = ok(&handle_settings_update(
        &state,
        &alice,
        task(
            uris::TASK_VTA_CALENDAR_SETTINGS_UPDATE_0_1,
            json!({ "contextId": CTX, "sync": true, "defaultReminderMinutes": [30],
                    "quietHours": { "startsAt": "22:00", "endsAt": "07:00", "timeZone": "Europe/Berlin" } }),
        ),
    )
    .await);
    assert_eq!(updated["settings"]["sync"], true);
    assert_eq!(updated["settings"]["updatedBy"], json!(alice.did));

    // With no membership credential in the context there is nothing to read.
    let synced = ok(&handle_sync(
        &state,
        &alice,
        task(
            uris::TASK_VTA_CALENDAR_SYNC_0_1,
            json!({ "contextId": CTX }),
        ),
    )
    .await);
    assert_eq!(synced, json!({ "results": [] }));
}

/// VTI-CAL-041: an alert is set only for an event the calendar holds, and overrides the
/// context's default; clearing it returns to the default.
#[tokio::test]
async fn vti_cal_041_an_alert_needs_a_held_event_and_overrides_the_default() {
    let (state, _dir, _) = state().await;
    let alice = admin_claims_for_context(CTX);
    let set = |event: &str, minutes: Value| {
        task(
            uris::TASK_VTA_CALENDAR_ALERTS_SET_0_1,
            json!({ "contextId": CTX, "community": community(), "eventId": event,
                    "reminderMinutes": minutes }),
        )
    };
    let out = handle_alerts_set(&state, &alice, set(EVENT, json!([15]))).await;
    assert_eq!(code(&out), "vta/calendar/alerts/set:eventNotHeld");

    put_entry(&state, CTX, EVENT, "Soldering night", 2).await;
    ok(&handle_alerts_set(&state, &alice, set(EVENT, json!([15, 60]))).await);
    let page = ok(&handle_list(
        &state,
        &alice,
        task(uris::TASK_VTA_CALENDAR_LIST_0_1, json!({})),
    )
    .await);
    assert_eq!(page["items"][0]["reminderSource"], "alert");

    let clear = || {
        task(
            uris::TASK_VTA_CALENDAR_ALERTS_CLEAR_0_1,
            json!({ "contextId": CTX, "community": community(), "eventId": EVENT }),
        )
    };
    assert_eq!(
        ok(&handle_alerts_clear(&state, &alice, clear()).await)["changed"],
        true
    );
    assert_eq!(
        ok(&handle_alerts_clear(&state, &alice, clear()).await)["changed"],
        false
    );
}

/// VTI-CAL-060: busy times come from the synced calendar, so sharing them needs sync on.
#[tokio::test]
async fn vti_cal_060_sharing_busy_times_needs_sync() {
    let (state, _dir, _) = state().await;
    let alice = admin_claims_for_context(CTX);
    let share = || {
        task(
            uris::TASK_VTA_CALENDAR_BUSY_SHARE_0_1,
            json!({ "contextId": CTX, "target": { "holder": community(), "pageId": "office-hours" },
                    "enabled": true }),
        )
    };
    let out = handle_busy_share(&state, &alice, share()).await;
    assert_eq!(code(&out), "vta/calendar/busy/share:syncOff");

    ok(&handle_settings_update(
        &state,
        &alice,
        task(
            uris::TASK_VTA_CALENDAR_SETTINGS_UPDATE_0_1,
            json!({ "contextId": CTX, "sync": true }),
        ),
    )
    .await);
    let shared = ok(&handle_busy_share(&state, &alice, share()).await);
    assert_eq!(shared["share"]["enabled"], true);
}

// ─── feeds (VTI-CAL-050 – 055) ───────────────────────────────────────────

/// VTI-CAL-051 / 052 / 054: the address is returned once and never listed; an unknown, revoked
/// or expired address is answered alike; each read is recorded; a feed expires within a year.
#[tokio::test]
async fn vti_cal_052_a_feed_is_served_until_revoked_and_answered_alike_after() {
    let (state, _dir, _) = state().await;
    creator_in(&state, CTX).await;
    put_entry(&state, CTX, EVENT, "Soldering night", 2).await;

    let out = create_feed(
        &state,
        json!({ "label": "Phone", "contextIds": [CTX], "expiresAt": in_days(400) }),
    )
    .await;
    assert_eq!(code(&out), "vta/calendar/feeds/create:expiryInvalid");

    let created = ok(&create_feed(
        &state,
        json!({ "label": "Phone", "contextIds": [CTX], "expiresAt": in_days(30) }),
    )
    .await);
    let url = created["url"].as_str().unwrap();
    assert!(url.starts_with("https://vta.example/calendar/feeds/"));
    let token = token_of(url);
    assert_eq!(token.len(), 64, "256 bits (VTI-CAL-051)");
    let feed_id = created["feed"]["feedId"].as_str().unwrap().to_string();

    let (status, ct, ics) = fetch(&state, &token).await;
    assert_eq!(status, axum::http::StatusCode::OK);
    assert!(ct.starts_with("text/calendar"));
    assert!(ics.contains("SUMMARY:Soldering night"));

    let listed = ok(&handle_feeds_list(
        &state,
        &admin_claims_for_context(CTX),
        task(uris::TASK_VTA_CALENDAR_FEEDS_LIST_0_1, json!({})),
    )
    .await);
    assert_eq!(listed["items"][0]["fetchCount"], 1, "VTI-CAL-054");
    assert!(listed["items"][0].get("lastFetchedAt").is_some());
    assert!(!listed.to_string().contains(&token), "never the address");

    let unknown = fetch(&state, &"0".repeat(64)).await;
    assert_eq!(unknown.0, axum::http::StatusCode::NOT_FOUND);

    let revoke = || {
        task(
            uris::TASK_VTA_CALENDAR_FEEDS_REVOKE_0_1,
            json!({ "feedId": feed_id }),
        )
    };
    ok(&handle_feeds_revoke(&state, &admin_claims_for_context(CTX), revoke()).await);
    let after = fetch(&state, &token).await;
    assert_eq!(
        (after.0, after.2),
        (unknown.0, unknown.2),
        "revoked reads as unknown"
    );

    let out = handle_feeds_revoke(&state, &admin_claims_for_context(CTX), revoke()).await;
    assert_eq!(code(&out), "vta/calendar/feeds/revoke:alreadyRevoked");
    let out = handle_feeds_revoke(
        &state,
        &admin_claims_for_context(CTX),
        task(
            uris::TASK_VTA_CALENDAR_FEEDS_REVOKE_0_1,
            json!({ "feedId": "feed_CCCCCCCCCCCCCCCCCCCCCC" }),
        ),
    )
    .await;
    assert_eq!(code(&out), "vta/calendar/feeds/revoke:feedNotFound");
    // A feed over a context the caller has no standing in is not theirs to see.
    let out = handle_feeds_revoke(&state, &admin_claims_for_context(OTHER), revoke()).await;
    assert_eq!(code(&out), "vta/calendar/feeds/revoke:feedNotFound");
}

/// VTI-CAL-053: titles and times only, a `busy` feed not even titles, never the identifier the
/// entry was read as, and event UIDs that differ between feeds.
#[tokio::test]
async fn vti_cal_053_a_feed_carries_titles_and_times_only_and_uids_differ_between_feeds() {
    let (state, _dir, _) = state().await;
    creator_in(&state, CTX).await;
    put_entry(&state, CTX, EVENT, "Soldering night", 2).await;
    let make = |detail: &str| json!({ "label": "Phone", "contextIds": [CTX], "expiresAt": in_days(30), "detail": detail });
    let a = token_of(
        ok(&create_feed(&state, make("titles")).await)["url"]
            .as_str()
            .unwrap(),
    );
    let b = token_of(
        ok(&create_feed(&state, make("busy")).await)["url"]
            .as_str()
            .unwrap(),
    );
    let (_, _, ics_a) = fetch(&state, &a).await;
    let (_, _, ics_b) = fetch(&state, &b).await;
    assert!(ics_a.contains("Soldering night"));
    assert!(
        !ics_b.contains("Soldering night"),
        "busy detail drops titles"
    );
    for ics in [&ics_a, &ics_b] {
        assert!(!ics.contains("member"), "never the identifier");
        assert!(!ics.contains(&community()), "never the community's DID");
    }
    let uid = |ics: &str| {
        ics.lines()
            .find(|l| l.starts_with("UID:"))
            .unwrap()
            .to_string()
    };
    assert_ne!(uid(&ics_a), uid(&ics_b));
}

/// VTI-CAL-055: a feed stops covering a context when its creator loses standing there.
#[tokio::test]
async fn vti_cal_055_a_feed_follows_its_creators_standing() {
    let (state, _dir, _) = state().await;
    creator_in(&state, CTX).await;
    put_entry(&state, CTX, EVENT, "Soldering night", 2).await;
    let token = token_of(
        ok(&create_feed(
            &state,
            json!({ "label": "Phone", "contextIds": [CTX], "expiresAt": in_days(30) }),
        )
        .await)["url"]
            .as_str()
            .unwrap(),
    );
    assert!(fetch(&state, &token).await.2.contains("Soldering night"));
    creator_in(&state, OTHER).await;
    assert!(!fetch(&state, &token).await.2.contains("Soldering night"));
}

/// A VTA keeps a bounded number of live feeds.
#[tokio::test]
async fn vti_cal_feeds_are_bounded() {
    let (state, _dir, _) = state().await;
    let payload = json!({ "label": "Phone", "contextIds": [CTX], "expiresAt": in_days(30) });
    for _ in 0..cal::MAX_LIVE_FEEDS {
        ok(&create_feed(&state, payload.clone()).await);
    }
    let out = create_feed(&state, payload).await;
    assert_eq!(code(&out), "vta/calendar/feeds/create:limitReached");
}

// ─── receipts (VTI-CAL-030 – 032) ────────────────────────────────────────

fn reply(recipient: &str, type_uri: &str) -> Value {
    let now = now_secs();
    let mut doc = json!({
        "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        "type": type_uri,
        "issuer": community(),
        "recipient": recipient,
        "issuedAt": now,
        "threadId": "urn:uuid:7c1e0f0a-0000-4000-8000-000000000001",
        "payload": { "registration": { "status": "going" }, "event": { "eventId": EVENT } },
    });
    sign_received_as(COMMUNITY, "assertionMethod", &now, &mut doc);
    doc
}

async fn deposit(state: &AppState, ctx: &str, document: Value) -> TrustTaskOutcome {
    let received = json!({
        "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        "type": uris::TASK_VTA_CALENDAR_RECEIPTS_DEPOSIT_0_1,
        "payload": { "contextId": ctx, "document": document },
    });
    let doc: TrustTask<Value> = serde_json::from_value(received.clone()).unwrap();
    let auth = admin_claims_for_context(ctx);
    super::super::received::scope(std::sync::Arc::new(received), async move {
        handle_receipts_deposit(state, &auth, doc).await
    })
    .await
}

/// VTI-CAL-030: a community's signed reply, addressed to an identifier this VTA holds, is
/// verified and kept exactly as received, once.
#[tokio::test]
async fn vti_cal_030_a_reply_is_verified_and_kept_as_received_once() {
    let (state, _dir, member) = state().await;
    let sent = reply(&member, REGISTER_RESPONSE);
    let first = ok(&deposit(&state, CTX, sent.clone()).await);
    assert_eq!(first["alreadyKept"], false);
    assert_eq!(first["receipt"]["community"], json!(community()));
    assert_eq!(first["receipt"]["eventId"], EVENT);
    let again = ok(&deposit(&state, CTX, sent.clone()).await);
    assert_eq!(again["alreadyKept"], true);
    assert_eq!(again["receipt"]["receiptId"], first["receipt"]["receiptId"]);

    let listed = ok(&handle_receipts_list(
        &state,
        &admin_claims_for_context(CTX),
        task(
            uris::TASK_VTA_CALENDAR_RECEIPTS_LIST_0_1,
            json!({ "contextId": CTX }),
        ),
    )
    .await);
    assert_eq!(listed["items"].as_array().unwrap().len(), 1);
    assert_eq!(listed["items"][0]["document"], sent, "exactly as received");
}

/// VTI-CAL-030: what is not a reply about a registration, what is addressed elsewhere, and what
/// the issuer did not sign are refused.
#[tokio::test]
async fn vti_cal_030_a_reply_not_addressed_here_or_not_signed_is_refused() {
    let (state, _dir, member) = state().await;
    let out = deposit(
        &state,
        CTX,
        reply(
            &member,
            "https://trusttasks.org/spec/vtc/events/list/0.2#response",
        ),
    )
    .await;
    assert_eq!(code(&out), "vta/calendar/receipts/deposit:notAReply");

    let out = deposit(&state, CTX, reply(&did_for_seed(77).0, REGISTER_RESPONSE)).await;
    assert_eq!(code(&out), "vta/calendar/receipts/deposit:notAddressed");
    // The persona is held in CTX, not in OTHER.
    let out = deposit(&state, OTHER, reply(&member, REGISTER_RESPONSE)).await;
    assert_eq!(code(&out), "vta/calendar/receipts/deposit:notAddressed");

    let mut tampered = reply(&member, REGISTER_RESPONSE);
    tampered["payload"]["registration"]["status"] = json!("declined");
    let out = deposit(&state, CTX, tampered).await;
    assert_eq!(code(&out), "proofInvalid");
}

/// VTI-CAL-001: deleting a context takes its calendar with it and leaves every feed.
#[tokio::test]
async fn vti_cal_001_a_context_deletion_purges_its_calendar() {
    let (state, _dir, _) = state().await;
    put_entry(&state, CTX, EVENT, "Soldering night", 2).await;
    ok(&create_feed(
        &state,
        json!({ "label": "Phone", "contextIds": [CTX], "expiresAt": in_days(30) }),
    )
    .await);
    let removed = cal::purge_context(&state.calendar_ks, CTX).await.unwrap();
    assert_eq!(removed, 2, "the entry, and the feed left covering nothing");
    assert!(
        cal::entries(&state.calendar_ks, CTX)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(cal::feeds(&state.calendar_ks).await.unwrap().is_empty());
}
