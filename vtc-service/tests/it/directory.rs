//! Integration coverage for the member directory (`vtc/directory/*`) through
//! real signed documents: the spine's proof check, the signer's standing read
//! now, the field schema, cards, and the projection each viewer is shown.
//!
//! Each declared error code is driven here and asserted on (#1600), which is
//! what the error-code census reads.

use axum::http::StatusCode;
use serde_json::{Value, json};
use vti_rooms_dtg::test_support::Party;

use crate::common::signed::{call, party_with_role, post, seed_role};
use vtc_service::acl::VtcRole;
use vtc_service::members::{Member, store_member};
use vtc_service::policy::default::install_defaults;
use vtc_service::test_support::{TEST_VTC_DID, TestVtc};

const SPEC: &str = "https://trusttasks.org/spec/vtc/directory";

fn task(name: &str) -> String {
    format!("{SPEC}/{name}/0.1")
}

use trust_tasks_rs::specs::vtc::directory as d;

// The declared codes, read from the generated bindings.
const DIRECTORY_QUERY_ERR_NOT_FOUND: &str = d::query::v0_1::error_codes::NOT_FOUND.code;
const DEFINE_ERR_FIELD_EXISTS: &str = d::fields::define::v0_1::error_codes::FIELD_EXISTS.code;
const DEFINE_ERR_RESERVED_KEY: &str = d::fields::define::v0_1::error_codes::RESERVED_KEY.code;
const DEFINE_ERR_ABOVE_CEILING: &str = d::fields::define::v0_1::error_codes::ABOVE_CEILING.code;
const DEFINE_ERR_VALUE_INVALID: &str = d::fields::define::v0_1::error_codes::VALUE_INVALID.code;
const DEFINE_ERR_TOO_MANY_FIELDS: &str = d::fields::define::v0_1::error_codes::TOO_MANY_FIELDS.code;
const UPDATE_ERR_FIELD_UNKNOWN: &str = d::fields::update::v0_1::error_codes::FIELD_UNKNOWN.code;
const UPDATE_ERR_FIELD_RETIRED: &str = d::fields::update::v0_1::error_codes::FIELD_RETIRED.code;
const UPDATE_ERR_ABOVE_CEILING: &str = d::fields::update::v0_1::error_codes::ABOVE_CEILING.code;
const UPDATE_ERR_VALUE_INVALID: &str = d::fields::update::v0_1::error_codes::VALUE_INVALID.code;
const RETIRE_ERR_FIELD_UNKNOWN: &str = d::fields::retire::v0_1::error_codes::FIELD_UNKNOWN.code;
const RETIRE_ERR_FIELD_RETIRED: &str = d::fields::retire::v0_1::error_codes::FIELD_RETIRED.code;
const RETIRE_ERR_BASE_FIELD: &str = d::fields::retire::v0_1::error_codes::BASE_FIELD.code;
const CARD_SHOW_ERR_NOT_MEMBER: &str = d::card::show::v0_1::error_codes::NOT_MEMBER.code;
const CARD_UPDATE_ERR_NOT_MEMBER: &str = d::card::update::v0_1::error_codes::NOT_MEMBER.code;
const CARD_UPDATE_ERR_SUPERSEDED: &str = d::card::update::v0_1::error_codes::SUPERSEDED.code;
const CARD_UPDATE_ERR_FIELD_UNKNOWN: &str = d::card::update::v0_1::error_codes::FIELD_UNKNOWN.code;
const CARD_UPDATE_ERR_FIELD_RETIRED: &str = d::card::update::v0_1::error_codes::FIELD_RETIRED.code;
const CARD_UPDATE_ERR_FIELD_NOT_WRITABLE: &str =
    d::card::update::v0_1::error_codes::FIELD_NOT_WRITABLE.code;
const CARD_UPDATE_ERR_VALUE_INVALID: &str = d::card::update::v0_1::error_codes::VALUE_INVALID.code;
const CARD_UPDATE_ERR_VALUE_REFUSED: &str = d::card::update::v0_1::error_codes::VALUE_REFUSED.code;
const CARD_UPDATE_ERR_ABOVE_CEILING: &str = d::card::update::v0_1::error_codes::ABOVE_CEILING.code;
const CARD_UPDATE_ERR_NOT_AVAILABLE: &str = d::card::update::v0_1::error_codes::NOT_AVAILABLE.code;
const ASSERT_ERR_NOT_FOUND: &str = d::card::assert::v0_1::error_codes::NOT_FOUND.code;
const ASSERT_ERR_FIELD_UNKNOWN: &str = d::card::assert::v0_1::error_codes::FIELD_UNKNOWN.code;
const ASSERT_ERR_FIELD_RETIRED: &str = d::card::assert::v0_1::error_codes::FIELD_RETIRED.code;
const ASSERT_ERR_FIELD_NOT_WRITABLE: &str =
    d::card::assert::v0_1::error_codes::FIELD_NOT_WRITABLE.code;
const ASSERT_ERR_VALUE_INVALID: &str = d::card::assert::v0_1::error_codes::VALUE_INVALID.code;
const ASSERT_ERR_VALUE_REFUSED: &str = d::card::assert::v0_1::error_codes::VALUE_REFUSED.code;
const LIST_ERR_QUERY_TOO_SHORT: &str = d::entries::list::v0_1::error_codes::QUERY_TOO_SHORT.code;
const LIST_ERR_CURSOR_INVALID: &str = d::entries::list::v0_1::error_codes::CURSOR_INVALID.code;
const LIST_ERR_NOT_FOUND: &str = d::entries::list::v0_1::error_codes::NOT_FOUND.code;
const LIST_ERR_RATE_LIMITED: &str = d::entries::list::v0_1::error_codes::RATE_LIMITED.code;
const SHOW_ERR_NOT_FOUND: &str = d::entries::show::v0_1::error_codes::NOT_FOUND.code;

/// The error code carried by a `trust-task-error` payload.
fn tt_error_code(body: &Value) -> &str {
    body["code"].as_str().unwrap_or_default()
}

struct Fixture {
    vtc: TestVtc,
    admin: Party,
}

async fn build_fixture() -> Fixture {
    let vtc = TestVtc::builder()
        .with_audit(true)
        .with_public_url("https://vtc.example.com")
        .build()
        .await;
    // The directory reads the active `directory` and `directoryWrite`
    // policies, so the bundled defaults must be installed (boot does this).
    install_defaults(&vtc.state.policies_ks, &vtc.state.active_policies_ks)
        .await
        .expect("install default policies");
    let admin = party_with_role(&vtc, VtcRole::Admin, &[]).await;
    Fixture { vtc, admin }
}

/// A member: an ACL row of community role `member` and a member record.
async fn member(fix: &Fixture) -> Party {
    let p = Party::new();
    seed_member(fix, &p.did).await;
    p
}

async fn seed_member(fix: &Fixture, did: &str) {
    seed_role(&fix.vtc, did, VtcRole::Member, &[]).await;
    store_member(&fix.vtc.state.members_ks, &Member::fresh(did))
        .await
        .unwrap();
}

/// Send `name` signed by `from`; the reply's status and payload.
async fn send(fix: &Fixture, from: &Party, name: &str, payload: Value) -> (StatusCode, Value) {
    let (status, doc) = call(&fix.vtc, from, &task(name), payload).await;
    (status, doc["payload"].clone())
}

async fn ok(fix: &Fixture, from: &Party, name: &str, payload: Value) -> Value {
    let (status, body) = send(fix, from, name, payload).await;
    assert_eq!(status, StatusCode::OK, "{name}: {body}");
    body
}

/// `from`'s card: its entry id.
async fn entry_of(fix: &Fixture, from: &Party) -> String {
    ok(fix, from, "card/show", json!({})).await["card"]["entryId"]
        .as_str()
        .unwrap()
        .to_string()
}

async fn define(fix: &Fixture, field: Value) -> (StatusCode, Value) {
    send(fix, &fix.admin, "fields/define", json!({ "field": field })).await
}

fn text_field(key: &str) -> Value {
    json!({
        "key": key, "label": "A field", "type": "text", "source": "member",
        "ceiling": "members", "defaultVisibility": "members", "searchable": true,
    })
}

// ─── query/0.1, through the projection ────────────────────────────────────

/// An administrator addresses a member by DID and sees the derived fields.
#[tokio::test]
async fn an_administrator_queries_a_member_by_did() {
    let fix = build_fixture().await;
    seed_member(&fix, "did:key:zSubject").await;
    let body = ok(
        &fix,
        &fix.admin,
        "query",
        json!({ "subject": "did:key:zSubject" }),
    )
    .await;
    assert_eq!(body["subject"], "did:key:zSubject");
    assert_eq!(body["fields"]["did"], "did:key:zSubject");
    assert_eq!(body["fields"]["role"], "member");
    assert!(body["fields"]["joinedAt"].is_string(), "{body}");
}

/// A member may not ask "is this DID a member?" of a member who has not shown
/// their DID — the answer is the one `notFound` a stranger's DID gets. Once
/// the subject shows their DID to members, the same query answers.
#[tokio::test]
async fn a_member_queries_only_a_did_its_member_chose_to_show() {
    let fix = build_fixture().await;
    let viewer = member(&fix).await;
    let subject = member(&fix).await;
    let (_, hidden) = send(&fix, &viewer, "query", json!({ "subject": subject.did })).await;
    assert_eq!(
        tt_error_code(&hidden),
        DIRECTORY_QUERY_ERR_NOT_FOUND,
        "{hidden}"
    );
    let (_, ghost) = send(
        &fix,
        &viewer,
        "query",
        json!({ "subject": "did:key:zGhost" }),
    )
    .await;
    assert_eq!(hidden["message"], ghost["message"], "indistinguishable");

    ok(
        &fix,
        &subject,
        "card/update",
        json!({ "values": { "displayName": "Sam" }, "visibility": { "did": "members" } }),
    )
    .await;
    let body = ok(&fix, &viewer, "query", json!({ "subject": subject.did })).await;
    assert_eq!(body["fields"]["did"], subject.did);
    assert_eq!(body["fields"]["displayName"], "Sam");
    assert!(
        body["fields"].get("joinedAt").is_none(),
        "withheld means absent"
    );
}

/// A signer the community holds no entry for is refused.
#[tokio::test]
async fn a_stranger_is_rejected() {
    let fix = build_fixture().await;
    seed_member(&fix, "did:key:zSubject").await;
    let (_, body) = send(
        &fix,
        &Party::new(),
        "query",
        json!({ "subject": "did:key:zSubject" }),
    )
    .await;
    assert_eq!(body["code"], "permissionDenied", "{body}");
}

/// Make `source` the active `directory` policy.
async fn activate_policy(fix: &Fixture, purpose: vtc_service::policy::PolicyPurpose, source: &str) {
    use sha2::{Digest, Sha256};
    use vtc_service::policy::{Policy, set_active_policy_id, store_policy};
    let id = uuid::Uuid::new_v4();
    let now = chrono::Utc::now();
    store_policy(
        &fix.vtc.state.policies_ks,
        &Policy {
            id,
            purpose,
            rego_source: source.into(),
            sha256: Sha256::digest(source.as_bytes()).into(),
            activated_at: Some(now),
            author_did: fix.admin.did.clone(),
            created_at: now,
            version: 99,
            name: None,
            description: None,
        },
    )
    .await
    .unwrap();
    set_active_policy_id(&fix.vtc.state.active_policies_ks, purpose, id)
        .await
        .unwrap();
}

/// "Nothing visible to this caller" — a policy deny, or an allow that keeps no
/// field — is the same `notFound` as a missing member, with the same message.
#[tokio::test]
async fn nothing_visible_is_indistinguishable_from_no_such_member() {
    let fix = build_fixture().await;
    seed_member(&fix, "did:key:zSubject").await;
    let (_, missing) = send(
        &fix,
        &fix.admin,
        "query",
        json!({ "subject": "did:key:zGhost" }),
    )
    .await;
    assert_eq!(
        tt_error_code(&missing),
        DIRECTORY_QUERY_ERR_NOT_FOUND,
        "{missing}"
    );
    let said = |b: &Value| {
        (
            b["code"].clone(),
            b["message"].clone(),
            b["details"].clone(),
        )
    };
    for policy in [
        "package vtc.directory\nimport rego.v1\n\
         decision := {\"effect\": \"deny\", \"with\": {\"code\": \"not-a-member\"}}\n",
        "package vtc.directory\nimport rego.v1\n\
         decision := {\"effect\": \"allow\", \"with\": {\"fields\": []}}\n",
    ] {
        activate_policy(&fix, vtc_service::policy::PolicyPurpose::Directory, policy).await;
        for subject in ["did:key:zSubject", "did:key:zGhost"] {
            let (_, body) = send(&fix, &fix.admin, "query", json!({ "subject": subject })).await;
            assert_eq!(
                tt_error_code(&body),
                DIRECTORY_QUERY_ERR_NOT_FOUND,
                "{subject}: {body}"
            );
            assert_eq!(
                said(&body),
                said(&missing),
                "{subject}: the refusal must not differ"
            );
        }
    }
}

// ─── fields ───────────────────────────────────────────────────────────────

/// Every member reads the schema; only an administrator sees retired fields.
#[tokio::test]
async fn the_schema_is_read_by_members_and_retired_fields_by_administrators() {
    let fix = build_fixture().await;
    let m = member(&fix).await;
    let body = ok(&fix, &m, "fields/list", json!({})).await;
    let keys: Vec<&str> = body["fields"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["key"].as_str().unwrap())
        .collect();
    assert!(
        keys.contains(&"displayName") && keys.contains(&"did"),
        "{keys:?}"
    );
    assert_eq!(body["listingDefaults"]["defaultListing"], "listed");

    assert_eq!(
        define(&fix, text_field("org.example.gone")).await.0,
        StatusCode::OK
    );
    ok(
        &fix,
        &fix.admin,
        "fields/retire",
        json!({ "key": "org.example.gone", "reason": "r" }),
    )
    .await;
    let to_member = ok(&fix, &m, "fields/list", json!({ "includeRetired": true })).await;
    assert!(!to_member.to_string().contains("org.example.gone"));
    let to_admin = ok(
        &fix,
        &fix.admin,
        "fields/list",
        json!({ "includeRetired": true }),
    )
    .await;
    assert!(to_admin.to_string().contains("org.example.gone"));
}

/// A member may not change the schema.
#[tokio::test]
async fn only_a_directory_administrator_defines_fields() {
    let fix = build_fixture().await;
    let m = member(&fix).await;
    let (_, body) = send(
        &fix,
        &m,
        "fields/define",
        json!({ "field": text_field("org.example.a") }),
    )
    .await;
    assert_eq!(body["code"], "permissionDenied", "{body}");
}

#[tokio::test]
async fn define_refuses_what_its_specification_declares() {
    let fix = build_fixture().await;
    assert_eq!(
        define(&fix, text_field("org.example.a")).await.0,
        StatusCode::OK
    );
    let (_, b) = define(&fix, text_field("org.example.a")).await;
    assert_eq!(tt_error_code(&b), DEFINE_ERR_FIELD_EXISTS, "{b}");
    let (_, b) = define(&fix, text_field("employer")).await;
    assert_eq!(tt_error_code(&b), DEFINE_ERR_RESERVED_KEY, "{b}");
    let mut wide = text_field("org.example.b");
    wide["defaultVisibility"] = json!("public");
    let (_, b) = define(&fix, wide).await;
    assert_eq!(tt_error_code(&b), DEFINE_ERR_ABOVE_CEILING, "{b}");
    let mut facet = text_field("org.example.c");
    facet["facet"] = json!(true);
    let (_, b) = define(&fix, facet).await;
    assert_eq!(tt_error_code(&b), DEFINE_ERR_VALUE_INVALID, "{b}");
    assert_eq!(b["details"]["field"], "org.example.c");
}

/// VTI-DIR-016: at most 64 active community fields.
#[tokio::test]
async fn define_refuses_a_sixty_fifth_field() {
    let fix = build_fixture().await;
    // Two administrators share the work: the document door admits a burst of
    // sixty from one signer, which is not what this tests.
    let second = party_with_role(&fix.vtc, VtcRole::Admin, &[]).await;
    for i in 0..64 {
        let by = if i % 2 == 0 { &fix.admin } else { &second };
        let (status, b) = send(
            &fix,
            by,
            "fields/define",
            json!({ "field": text_field(&format!("org.example.f{i}")) }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{i}: {b}");
    }
    let (_, b) = define(&fix, text_field("org.example.oneMore")).await;
    assert_eq!(tt_error_code(&b), DEFINE_ERR_TOO_MANY_FIELDS, "{b}");
}

#[tokio::test]
async fn update_refuses_what_its_specification_declares() {
    let fix = build_fixture().await;
    let up = |p: Value| send(&fix, &fix.admin, "fields/update", p);
    let (_, b) = up(json!({ "key": "org.example.none" })).await;
    assert_eq!(tt_error_code(&b), UPDATE_ERR_FIELD_UNKNOWN, "{b}");
    let (_, b) = up(json!({ "key": "did", "defaultVisibility": "public" })).await;
    assert_eq!(tt_error_code(&b), UPDATE_ERR_ABOVE_CEILING, "{b}");
    define(&fix, text_field("org.example.a")).await;
    let (_, b) = up(json!({ "key": "org.example.a", "enabled": false })).await;
    assert_eq!(tt_error_code(&b), UPDATE_ERR_VALUE_INVALID, "{b}");
    ok(
        &fix,
        &fix.admin,
        "fields/retire",
        json!({ "key": "org.example.a", "reason": "r" }),
    )
    .await;
    let (_, b) = up(json!({ "key": "org.example.a", "label": "B" })).await;
    assert_eq!(tt_error_code(&b), UPDATE_ERR_FIELD_RETIRED, "{b}");
}

/// A narrowing applies at once; a widening parks in the action list for the
/// other holders of `vtc.directory.admin` (VTI-DIR-024).
#[tokio::test]
async fn a_narrowing_applies_and_a_widening_is_held() {
    let fix = build_fixture().await;
    let body = ok(
        &fix,
        &fix.admin,
        "fields/update",
        json!({ "key": "bio", "ceiling": "members", "reason": "narrow" }),
    )
    .await;
    assert_eq!(body["field"]["ceiling"], "members");
    // A second administrator exists, so widening needs their agreement.
    let _other = party_with_role(&fix.vtc, VtcRole::Admin, &[]).await;
    let (_, doc) = call(
        &fix.vtc,
        &fix.admin,
        &task("fields/update"),
        json!({ "key": "bio", "ceiling": "public", "reason": "widen" }),
    )
    .await;
    assert!(
        !doc["type"]
            .as_str()
            .unwrap_or_default()
            .ends_with("#response"),
        "a widening is not applied straight away: {doc}"
    );
    let list = ok(&fix, &fix.admin, "fields/list", json!({})).await;
    let bio = list["fields"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["key"] == "bio")
        .unwrap()
        .clone();
    assert_eq!(bio["ceiling"], "members", "unchanged until agreed");
}

#[tokio::test]
async fn retire_refuses_what_its_specification_declares() {
    let fix = build_fixture().await;
    let retire = |k: &str| {
        send(
            &fix,
            &fix.admin,
            "fields/retire",
            json!({ "key": k, "reason": "r" }),
        )
    };
    let (_, b) = retire("org.example.none").await;
    assert_eq!(tt_error_code(&b), RETIRE_ERR_FIELD_UNKNOWN, "{b}");
    let (_, b) = retire("bio").await;
    assert_eq!(tt_error_code(&b), RETIRE_ERR_BASE_FIELD, "{b}");
    define(&fix, text_field("org.example.a")).await;
    let first = retire("org.example.a").await;
    assert_eq!(first.0, StatusCode::OK, "{}", first.1);
    assert_eq!(first.1["field"]["state"], "retired");
    let (_, b) = retire("org.example.a").await;
    assert_eq!(tt_error_code(&b), RETIRE_ERR_FIELD_RETIRED, "{b}");
}

// ─── cards ────────────────────────────────────────────────────────────────

/// Every member has a card, made the first time they read it.
#[tokio::test]
async fn a_member_reads_their_own_card() {
    let fix = build_fixture().await;
    let m = member(&fix).await;
    let body = ok(&fix, &m, "card/show", json!({})).await;
    assert_eq!(body["card"]["revision"], 0);
    assert_eq!(body["card"]["discoverability"]["listing"], "listed");
    assert_eq!(body["missingRequired"], json!(["displayName"]));
    let again = ok(&fix, &m, "card/show", json!({})).await;
    assert_eq!(again["card"]["entryId"], body["card"]["entryId"], "stable");
}

#[tokio::test]
async fn card_tasks_answer_only_members() {
    let fix = build_fixture().await;
    let stranger = Party::new();
    let (_, b) = send(&fix, &stranger, "card/show", json!({})).await;
    assert_eq!(tt_error_code(&b), CARD_SHOW_ERR_NOT_MEMBER, "{b}");
    let (_, b) = send(
        &fix,
        &stranger,
        "card/update",
        json!({ "values": { "displayName": "X" } }),
    )
    .await;
    assert_eq!(tt_error_code(&b), CARD_UPDATE_ERR_NOT_MEMBER, "{b}");
}

#[tokio::test]
async fn card_update_refuses_what_its_specification_declares() {
    let fix = build_fixture().await;
    let m = member(&fix).await;
    let up = |p: Value| send(&fix, &m, "card/update", p);
    let (_, b) = up(json!({ "values": { "org.example.none": "x" } })).await;
    assert_eq!(tt_error_code(&b), CARD_UPDATE_ERR_FIELD_UNKNOWN, "{b}");
    let (_, b) = up(json!({ "values": { "role": "admin" } })).await;
    assert_eq!(tt_error_code(&b), CARD_UPDATE_ERR_FIELD_NOT_WRITABLE, "{b}");
    let (_, b) = up(json!({ "values": { "displayName": "x".repeat(65) } })).await;
    assert_eq!(tt_error_code(&b), CARD_UPDATE_ERR_VALUE_INVALID, "{b}");
    let (_, b) = up(json!({ "visibility": { "did": "public" } })).await;
    assert_eq!(tt_error_code(&b), CARD_UPDATE_ERR_ABOVE_CEILING, "{b}");
    assert_eq!(b["details"]["ceiling"], "members");
    let (_, b) = up(json!({
        "discoverability": { "listing": "listed", "search": "byName", "external": true }
    }))
    .await;
    assert_eq!(tt_error_code(&b), CARD_UPDATE_ERR_NOT_AVAILABLE, "{b}");

    ok(
        &fix,
        &fix.admin,
        "fields/update",
        json!({ "key": "pronouns", "enabled": false }),
    )
    .await;
    let (_, b) = up(json!({ "values": { "pronouns": "they/them" } })).await;
    assert_eq!(tt_error_code(&b), CARD_UPDATE_ERR_FIELD_RETIRED, "{b}");
}

/// VTI-DIR-012: an update issued before the one in force is refused, and so
/// is one naming a revision the card has moved past.
#[tokio::test]
async fn an_older_update_is_superseded() {
    let fix = build_fixture().await;
    let m = member(&fix).await;
    // Signed now but sent second, after one issued a minute later.
    let mut stale = vta_sdk::trust_task_sign::build_unsigned(
        &task("card/update"),
        json!({ "values": { "displayName": "Old" } }),
        &m.did,
        TEST_VTC_DID,
    )
    .unwrap();
    stale.issued_at = Some(chrono::Utc::now() - chrono::Duration::seconds(60));
    let key =
        vta_sdk::trust_task_sign::HolderKey::from_did_key(&m.did, &m.secret_multibase).unwrap();
    vta_sdk::trust_task_sign::sign_in_place_with(&mut stale, &key)
        .await
        .unwrap();
    ok(
        &fix,
        &m,
        "card/update",
        json!({ "values": { "displayName": "New" } }),
    )
    .await;
    let (_, reply) = post(&fix.vtc, &serde_json::to_value(stale).unwrap()).await;
    let b = &reply["payload"];
    assert_eq!(tt_error_code(b), CARD_UPDATE_ERR_SUPERSEDED, "{b}");
    let (_, b) = send(&fix, &m, "card/update", json!({ "expectedRevision": 0 })).await;
    assert_eq!(tt_error_code(&b), CARD_UPDATE_ERR_SUPERSEDED, "{b}");
    assert_eq!(b["details"]["revision"], 1);
}

/// A `directoryWrite` policy may refuse a value; it is never asked about a
/// change that only narrows.
#[tokio::test]
async fn the_community_policy_refuses_a_value() {
    let fix = build_fixture().await;
    let m = member(&fix).await;
    activate_policy(
        &fix,
        vtc_service::policy::PolicyPurpose::DirectoryWrite,
        "package vtc.directory_write\nimport rego.v1\n\
         default decision := {\"effect\": \"allow\"}\n\
         decision := {\"effect\": \"deny\", \"with\": {\"code\": \"no\", \"field\": \"displayName\", \
         \"reason\": \"names are not allowed today\"}} if { input.card.values.displayName }\n",
    )
    .await;
    let (_, b) = send(
        &fix,
        &m,
        "card/update",
        json!({ "values": { "displayName": "X" } }),
    )
    .await;
    assert_eq!(tt_error_code(&b), CARD_UPDATE_ERR_VALUE_REFUSED, "{b}");
    assert_eq!(b["details"]["field"], "displayName");
    // Hiding the entry only narrows: never refused.
    ok(
        &fix,
        &m,
        "card/update",
        json!({ "discoverability": { "listing": "hidden", "search": "off", "external": false } }),
    )
    .await;
}

/// An administrator asserts `admin`-sourced values and learns nothing else of
/// the card.
#[tokio::test]
async fn an_administrator_asserts_a_value() {
    let fix = build_fixture().await;
    let m = member(&fix).await;
    let entry = entry_of(&fix, &m).await;
    define(
        &fix,
        json!({
            "key": "org.example.chapter", "label": "Chapter", "type": "enum", "source": "admin",
            "ceiling": "members", "defaultVisibility": "members", "facet": true,
            "constraints": { "options": [
                { "value": "sydney", "label": "Sydney" }, { "value": "berlin", "label": "Berlin" }
            ]},
        }),
    )
    .await;
    let body = ok(
        &fix,
        &fix.admin,
        "card/assert",
        json!({ "entryId": entry, "values": { "org.example.chapter": "sydney" }, "reason": "moved" }),
    )
    .await;
    assert_eq!(body["written"], json!(["org.example.chapter"]));
    assert!(body.get("card").is_none());
    let mine = ok(&fix, &m, "card/show", json!({})).await;
    assert_eq!(mine["card"]["values"]["org.example.chapter"], "sydney");
    // The member reads it and cannot change it.
    let (_, b) = send(
        &fix,
        &m,
        "card/update",
        json!({ "values": { "org.example.chapter": "berlin" } }),
    )
    .await;
    assert_eq!(tt_error_code(&b), CARD_UPDATE_ERR_FIELD_NOT_WRITABLE, "{b}");
}

#[tokio::test]
async fn card_assert_refuses_what_its_specification_declares() {
    let fix = build_fixture().await;
    let m = member(&fix).await;
    let entry = entry_of(&fix, &m).await;
    define(
        &fix,
        json!({
            "key": "org.example.grade", "label": "Grade", "type": "text", "source": "admin",
            "ceiling": "members", "defaultVisibility": "members",
            "constraints": { "maxLength": 3 },
        }),
    )
    .await;
    let assert = |values: Value, entry: &str| {
        send(
            &fix,
            &fix.admin,
            "card/assert",
            json!({ "entryId": entry, "values": values, "reason": "r" }),
        )
    };
    let (_, b) = assert(
        json!({ "org.example.grade": "A" }),
        "dir_AAAAAAAAAAAAAAAAAAAAAA",
    )
    .await;
    assert_eq!(tt_error_code(&b), ASSERT_ERR_NOT_FOUND, "{b}");
    let (_, b) = assert(json!({ "org.example.none": "A" }), &entry).await;
    assert_eq!(tt_error_code(&b), ASSERT_ERR_FIELD_UNKNOWN, "{b}");
    let (_, b) = assert(json!({ "displayName": "A" }), &entry).await;
    assert_eq!(tt_error_code(&b), ASSERT_ERR_FIELD_NOT_WRITABLE, "{b}");
    let (_, b) = assert(json!({ "org.example.grade": "ABCD" }), &entry).await;
    assert_eq!(tt_error_code(&b), ASSERT_ERR_VALUE_INVALID, "{b}");

    activate_policy(
        &fix,
        vtc_service::policy::PolicyPurpose::DirectoryWrite,
        "package vtc.directory_write\nimport rego.v1\n\
         decision := {\"effect\": \"deny\", \"with\": {\"code\": \"frozen\"}}\n",
    )
    .await;
    let (_, b) = assert(json!({ "org.example.grade": "A" }), &entry).await;
    assert_eq!(tt_error_code(&b), ASSERT_ERR_VALUE_REFUSED, "{b}");

    ok(
        &fix,
        &fix.admin,
        "fields/retire",
        json!({ "key": "org.example.grade", "reason": "r" }),
    )
    .await;
    let (_, b) = assert(json!({ "org.example.grade": "A" }), &entry).await;
    assert_eq!(tt_error_code(&b), ASSERT_ERR_FIELD_RETIRED, "{b}");
}

// ─── entries ──────────────────────────────────────────────────────────────

async fn named(fix: &Fixture, name: &str, extra: Value) -> Party {
    let p = member(fix).await;
    let mut payload = json!({ "values": { "displayName": name } });
    if let Value::Object(m) = extra {
        for (k, v) in m {
            payload[k] = v;
        }
    }
    ok(fix, &p, "card/update", payload).await;
    p
}

fn names(body: &Value) -> Vec<String> {
    body["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| {
            i["fields"]["displayName"]
                .as_str()
                .unwrap_or("?")
                .to_string()
        })
        .collect()
}

/// Browsing lists `listed` cards with a name; a search also finds `findable`
/// ones; nobody finds a `hidden` one but the administrators.
#[tokio::test]
async fn browse_search_and_hidden_entries() {
    let fix = build_fixture().await;
    let viewer = named(&fix, "Viewer", json!({})).await;
    named(&fix, "Ana Listed", json!({})).await;
    named(
        &fix,
        "Ana Findable",
        json!({ "discoverability": { "listing": "findable", "search": "byName", "external": false } }),
    )
    .await;
    named(
        &fix,
        "Ana Hidden",
        json!({ "discoverability": { "listing": "hidden", "search": "byName", "external": false } }),
    )
    .await;
    let _nameless = member(&fix).await;

    let browse = ok(&fix, &viewer, "entries/list", json!({})).await;
    assert_eq!(names(&browse), vec!["Ana Listed", "Viewer"]);
    // A member is shown name and role by default, nothing else (VTI-DIR-041).
    let first = &browse["items"][0]["fields"];
    assert_eq!(
        first.as_object().unwrap().keys().collect::<Vec<_>>(),
        vec!["displayName", "role"]
    );

    let search = ok(&fix, &viewer, "entries/list", json!({ "query": "ana" })).await;
    assert_eq!(names(&search), vec!["Ana Findable", "Ana Listed"]);

    let admin = ok(&fix, &fix.admin, "entries/list", json!({ "query": "ana" })).await;
    assert_eq!(
        names(&admin),
        vec!["Ana Findable", "Ana Hidden", "Ana Listed"]
    );
}

/// VTI-DIR-044: a DID is never a member's search key, even one they may see.
#[tokio::test]
async fn a_member_cannot_search_by_did() {
    let fix = build_fixture().await;
    let viewer = named(&fix, "Viewer", json!({})).await;
    let shown = named(&fix, "Shown", json!({ "visibility": { "did": "members" } })).await;
    let body = ok(&fix, &viewer, "entries/list", json!({ "query": shown.did })).await;
    assert!(body["items"].as_array().unwrap().is_empty(), "{body}");
    let admin = ok(
        &fix,
        &fix.admin,
        "entries/list",
        json!({ "query": shown.did }),
    )
    .await;
    assert_eq!(names(&admin), vec!["Shown"]);
}

#[tokio::test]
async fn list_refuses_what_its_specification_declares() {
    let fix = build_fixture().await;
    let viewer = named(&fix, "Viewer", json!({})).await;
    let (_, b) = send(&fix, &fix.admin, "entries/list", json!({ "query": "ab" })).await;
    assert_eq!(tt_error_code(&b), LIST_ERR_QUERY_TOO_SHORT, "{b}");
    let (_, b) = send(
        &fix,
        &viewer,
        "entries/list",
        json!({ "group": "grp_AAAAAAAAAAAAAAAAAAAAAA" }),
    )
    .await;
    assert_eq!(tt_error_code(&b), LIST_ERR_NOT_FOUND, "{b}");
}

/// VTI-DIR-112: a cursor resumes only the question it was issued for, for
/// the caller it was issued to.
#[tokio::test]
async fn a_cursor_is_bound_to_its_question_and_caller() {
    let fix = build_fixture().await;
    let viewer = named(&fix, "Viewer", json!({})).await;
    for n in ["A", "B", "C"] {
        named(&fix, &format!("Member {n}"), json!({})).await;
    }
    let page = ok(&fix, &viewer, "entries/list", json!({ "limit": 1 })).await;
    let cursor = page["nextCursor"]
        .as_str()
        .expect("more than one page")
        .to_string();
    let next = ok(
        &fix,
        &viewer,
        "entries/list",
        json!({ "limit": 1, "cursor": cursor }),
    )
    .await;
    assert_ne!(names(&next), names(&page));
    let (_, b) = send(
        &fix,
        &viewer,
        "entries/list",
        json!({ "limit": 1, "cursor": cursor, "query": "member" }),
    )
    .await;
    assert_eq!(tt_error_code(&b), LIST_ERR_CURSOR_INVALID, "{b}");
    let other = named(&fix, "Other", json!({})).await;
    let (_, b) = send(
        &fix,
        &other,
        "entries/list",
        json!({ "limit": 1, "cursor": cursor }),
    )
    .await;
    assert_eq!(tt_error_code(&b), LIST_ERR_CURSOR_INVALID, "{b}");
}

/// VTI-DIR-114: a caller's reads are counted, whatever they find.
#[tokio::test]
async fn reading_too_often_is_rate_limited() {
    let vtc = TestVtc::builder()
        .with_audit(true)
        .with_directory(vtc_service::directory::model::Settings {
            list_rate_per_minute: 3,
            ..Default::default()
        })
        .build()
        .await;
    install_defaults(&vtc.state.policies_ks, &vtc.state.active_policies_ks)
        .await
        .unwrap();
    let admin = party_with_role(&vtc, VtcRole::Admin, &[]).await;
    let fix = Fixture { vtc, admin };
    let viewer = member(&fix).await;
    let mut limited = None;
    for _ in 0..4 {
        let (_, b) = send(&fix, &viewer, "entries/list", json!({})).await;
        if !tt_error_code(&b).is_empty() {
            limited = Some(b);
            break;
        }
    }
    let b = limited.expect("the fourth read in a minute is refused");
    assert_eq!(tt_error_code(&b), LIST_ERR_RATE_LIMITED, "{b}");
}

/// Facets are offered on visible facet fields only, and a count below the
/// threshold is never exact (VTI-DIR-113).
#[tokio::test]
async fn facets_hide_small_counts() {
    let fix = build_fixture().await;
    define(
        &fix,
        json!({
            "key": "org.example.city", "label": "City", "type": "enum", "source": "member",
            "ceiling": "members", "defaultVisibility": "members", "facet": true,
            "constraints": { "options": [
                { "value": "syd", "label": "Sydney" }, { "value": "ber", "label": "Berlin" }
            ]},
        }),
    )
    .await;
    let viewer = named(&fix, "Viewer", json!({})).await;
    for i in 0..5 {
        named(
            &fix,
            &format!("S{i}"),
            json!({ "values": { "displayName": format!("S{i}"), "org.example.city": "syd" } }),
        )
        .await;
    }
    named(
        &fix,
        "B0",
        json!({ "values": { "displayName": "B0", "org.example.city": "ber" } }),
    )
    .await;
    let body = ok(&fix, &viewer, "entries/list", json!({})).await;
    assert_eq!(
        body["facets"],
        json!([{ "field": "org.example.city", "values": [
            { "value": "ber", "fewerThan": 5 },
            { "value": "syd", "count": 5 },
        ]}])
    );
    let filtered = ok(
        &fix,
        &viewer,
        "entries/list",
        json!({ "filters": [{ "field": "org.example.city", "values": ["ber"] }] }),
    )
    .await;
    assert_eq!(names(&filtered), vec!["B0"]);
}

/// An entry by identifier: members see what its member shows them; a hidden
/// one, a missing one and one showing nothing are the same `notFound`. Only
/// those who administer membership address an entry by DID.
#[tokio::test]
async fn show_by_entry_and_by_did() {
    let fix = build_fixture().await;
    let viewer = named(&fix, "Viewer", json!({})).await;
    let subject = named(&fix, "Subject", json!({})).await;
    let entry = entry_of(&fix, &subject).await;
    let body = ok(&fix, &viewer, "entries/show", json!({ "entryId": entry })).await;
    assert_eq!(body["entry"]["fields"]["displayName"], "Subject");
    assert!(body["entry"].get("connected").is_none());

    let (_, b) = send(&fix, &viewer, "entries/show", json!({ "did": subject.did })).await;
    assert_eq!(b["code"], "permissionDenied", "{b}");
    let by_did = ok(
        &fix,
        &fix.admin,
        "entries/show",
        json!({ "did": subject.did }),
    )
    .await;
    assert_eq!(by_did["entry"]["entryId"], entry);

    let (_, missing) = send(
        &fix,
        &viewer,
        "entries/show",
        json!({ "entryId": "dir_AAAAAAAAAAAAAAAAAAAAAA" }),
    )
    .await;
    assert_eq!(tt_error_code(&missing), SHOW_ERR_NOT_FOUND, "{missing}");
    ok(
        &fix,
        &subject,
        "card/update",
        json!({ "discoverability": { "listing": "hidden", "search": "off", "external": false } }),
    )
    .await;
    let (_, hidden) = send(&fix, &viewer, "entries/show", json!({ "entryId": entry })).await;
    assert_eq!(tt_error_code(&hidden), SHOW_ERR_NOT_FOUND, "{hidden}");
    assert_eq!(hidden["message"], missing["message"]);
}

/// VTI-DIR-111: a member without a live entry is never projected to members,
/// by browsing or by identifier.
#[tokio::test]
async fn a_member_without_a_live_entry_leaves_the_directory() {
    let fix = build_fixture().await;
    let viewer = named(&fix, "Viewer", json!({})).await;
    let leaver = named(&fix, "Leaver", json!({})).await;
    let entry = entry_of(&fix, &leaver).await;
    vtc_service::acl::delete_acl_entry(&fix.vtc.state.acl_ks, &leaver.did)
        .await
        .unwrap();
    let (_, b) = send(&fix, &viewer, "entries/show", json!({ "entryId": entry })).await;
    assert_eq!(tt_error_code(&b), SHOW_ERR_NOT_FOUND, "{b}");
    let browse = ok(&fix, &viewer, "entries/list", json!({})).await;
    assert_eq!(names(&browse), vec!["Viewer"]);
}

// ─── the disclosure statement (VTI-DIR-130) ─────────────────────────────────

const MANIFEST_0_4: &str = "https://trusttasks.org/spec/vtc/join-requests/manifest/0.4";
const MANIFEST_0_3: &str = "https://trusttasks.org/spec/vtc/join-requests/manifest/0.3";

/// An unsigned document of `type_uri`, as a prospective applicant who has not
/// identified themselves sends it.
fn anonymous(type_uri: &str, payload: Value) -> Value {
    json!({
        "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        "type": type_uri,
        "recipient": TEST_VTC_DID,
        "issuedAt": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "expiresAt": "2099-01-01T00:00:00Z",
        "payload": payload,
    })
}

async fn read_anonymously(fix: &Fixture, type_uri: &str) -> (StatusCode, Value) {
    let (status, doc) = post(&fix.vtc, &anonymous(type_uri, json!({}))).await;
    (status, doc["payload"].clone())
}

#[tokio::test]
async fn anyone_reads_what_the_directory_discloses_before_applying() {
    let fix = build_fixture().await;
    let (status, body) = read_anonymously(&fix, &task("disclosure")).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["communityDid"], TEST_VTC_DID);
    let statement = &body["disclosure"];

    // The base schema as this build ships it: a name members see, a DID that
    // stays with administrators until its member chooses, the features this
    // build does not have stated as absent, and external cards — served, and
    // on unless the operator turns them off — stated as present.
    let name = statement["fields"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["key"] == "displayName")
        .expect("the name field is stated");
    assert_eq!(name["defaultVisibility"], "members");
    assert_eq!(statement["newCard"]["listing"], "listed");
    assert_eq!(statement["adminNotes"], false);
    assert_eq!(statement["externalCards"], true);
    assert!(statement.get("groups").is_none());
    assert_eq!(
        statement["statementDigest"].as_str().unwrap(),
        vtc_service::directory::disclosure::statement_digest(statement).unwrap(),
        "a reader can recompute the digest from what it received"
    );
}

#[tokio::test]
async fn the_statement_follows_the_configuration_at_once() {
    let fix = build_fixture().await;
    let before = read_anonymously(&fix, &task("disclosure")).await.1["disclosure"].clone();

    let (status, body) = define(&fix, text_field("org.example.employer")).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let after = read_anonymously(&fix, &task("disclosure")).await.1["disclosure"].clone();
    assert!(
        after["fields"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["key"] == "org.example.employer"),
        "a field defined now is in the next statement"
    );
    assert_ne!(before["statementDigest"], after["statementDigest"]);

    // Retired: hidden from every projection, so gone from the statement.
    ok(
        &fix,
        &fix.admin,
        "fields/retire",
        json!({ "key": "org.example.employer", "reason": "no longer asked" }),
    )
    .await;
    let retired = read_anonymously(&fix, &task("disclosure")).await.1["disclosure"].clone();
    assert_eq!(
        retired, before,
        "the same configuration is the same statement"
    );
}

#[tokio::test]
async fn the_join_manifest_carries_the_same_statement_from_0_4() {
    let fix = build_fixture().await;
    let statement = read_anonymously(&fix, &task("disclosure")).await.1["disclosure"].clone();

    let (status, manifest) = read_anonymously(&fix, MANIFEST_0_4).await;
    assert_eq!(status, StatusCode::OK, "{manifest}");
    assert_eq!(manifest["directoryDisclosure"], statement);

    let (status, older) = read_anonymously(&fix, MANIFEST_0_3).await;
    assert_eq!(status, StatusCode::OK, "{older}");
    assert!(
        older.get("directoryDisclosure").is_none(),
        "0.3 has no member for the statement"
    );
    assert_eq!(older["criteria"], manifest["criteria"]);
}

/// A community that answers its join criteria only to callers it can identify
/// answers the statement on the same terms: never stricter, never looser.
#[tokio::test]
async fn the_statement_is_as_public_as_the_join_criteria() {
    use vtc_service::community::join_discovery::{JoinDiscovery, store_join_discovery};
    let fix = build_fixture().await;
    store_join_discovery(
        &fix.vtc.state.community_ks,
        &JoinDiscovery { public: false },
    )
    .await
    .unwrap();

    for uri in [task("disclosure"), MANIFEST_0_4.to_string()] {
        let (status, body) = read_anonymously(&fix, &uri).await;
        assert_ne!(status, StatusCode::OK, "{uri}: {body}");
        assert_eq!(tt_error_code(&body), "permissionDenied", "{uri}: {body}");
    }

    // Identified, by anyone — not only a member.
    let stranger = Party::new();
    let (status, body) = send(&fix, &stranger, "disclosure", json!({})).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body["disclosure"]["statementDigest"].is_string());
}

#[tokio::test]
async fn the_requests_carry_nothing() {
    let fix = build_fixture().await;
    for uri in [
        task("disclosure"),
        MANIFEST_0_4.to_string(),
        MANIFEST_0_3.to_string(),
    ] {
        let (status, doc) = post(
            &fix.vtc,
            &anonymous(&uri, json!({ "fields": ["displayName"] })),
        )
        .await;
        assert_ne!(status, StatusCode::OK, "{uri}: {doc}");
        assert_eq!(
            tt_error_code(&doc["payload"]),
            "malformedRequest",
            "{uri}: {doc}"
        );
    }
}
