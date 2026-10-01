//! The administration surfaces that had only bearer REST, as signed Trust
//! Tasks (`trust_tasks::surface_tasks`): the community's presentation to
//! applicants, the schema registry, the vetting reads, the host's rooms.
//! (Edge suspend/restore are in `relationships.rs`; a join request's vetting
//! and the credential query in `join_requests.rs`.)
//!
//! Each verb is answered for the role its bearer route took (its reply
//! matching the published `#response` schema), refused unsigned and below
//! that role, and — where the route is gone — not served over bearer REST.

use axum::http::StatusCode;
use serde_json::{Value, json};

use crate::common::signed::{
    admin, bearer_route_served, call, error_code, party_with_role, payload, post, unsigned,
};
use vtc_service::acl::VtcRole;
use vtc_service::test_support::TestVtc;

const SPEC: &str = "https://trusttasks.org/spec/vtc/";

fn t(slug: &str) -> String {
    format!("{SPEC}{slug}")
}

async fn vtc() -> TestVtc {
    TestVtc::builder().with_audit(true).build().await
}

/// Every moved verb with a payload it succeeds on, and whether any entry (not
/// just an administrator) may send it.
fn verbs() -> Vec<(String, Value, bool)> {
    vec![
        (t("community/branding/show/0.1"), json!({}), true),
        (
            t("community/branding/update/0.1"),
            json!({ "branding": { "displayName": "Kernel Devs", "accentColor": "#AA3300" } }),
            false,
        ),
        (
            t("community/requested-attributes/show/0.1"),
            json!({}),
            true,
        ),
        (
            t("community/requested-attributes/update/0.1"),
            json!({ "requestedAttributes": [ { "type": "name.display", "required": true } ] }),
            false,
        ),
        (t("community/join-discovery/show/0.1"), json!({}), true),
        (
            t("community/join-discovery/update/0.1"),
            json!({ "joinDiscovery": { "public": false } }),
            false,
        ),
        (
            t("schemas/register/0.1"),
            json!({ "typeUri": "StatementCredential", "dtgType": "StatementCredential", "kind": "accepts" }),
            false,
        ),
        (t("schemas/list/0.1"), json!({}), false),
        (t("schemas/accepts/list/0.1"), json!({}), false),
        (t("vetting/vetters/grants/list/0.1"), json!({}), false),
        (t("vetting/auto-grant/show/0.1"), json!({}), false),
        (
            t("vetting/auto-grant/update/0.1"),
            json!({ "enabled": false, "sweepMinutes": 30 }),
            false,
        ),
        (t("vetting/revocations/list/0.1"), json!({}), false),
        (t("rooms/list/0.1"), json!({}), false),
    ]
}

#[tokio::test]
async fn an_administrator_is_answered_on_every_verb() {
    let vtc = vtc().await;
    let admin = admin(&vtc).await;
    for (task, body, _) in verbs() {
        let (status, doc) = call(&vtc, &admin, &task, body).await;
        assert_eq!(status, StatusCode::OK, "{task}: {doc}");
    }
}

/// The presentation reads took any session; every other verb took
/// `AdminAuth`. A moderator is refused the latter, and an unsigned document is
/// refused everything.
#[tokio::test]
async fn below_the_routes_role_and_unsigned_are_refused() {
    let vtc = vtc().await;
    let moderator = party_with_role(&vtc, VtcRole::Moderator, &[]).await;
    for (task, body, any_entry) in verbs() {
        let (status, doc) = call(&vtc, &moderator, &task, body.clone()).await;
        if any_entry {
            assert_eq!(status, StatusCode::OK, "{task}: {doc}");
        } else {
            assert_eq!(status, StatusCode::FORBIDDEN, "{task}: {doc}");
        }
        let (status, doc) = post(&vtc, &unsigned(&moderator, &task, body)).await;
        assert!(
            status.is_client_error() && error_code(&doc).is_some(),
            "{task} unsigned: {status} {doc}"
        );
    }
    // A stranger holds no entry at all.
    let stranger = vti_rooms_dtg::test_support::Party::new();
    let (status, _) = call(
        &vtc,
        &stranger,
        &t("community/branding/show/0.1"),
        json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn the_schema_registry_round_trips_with_its_declared_codes() {
    let vtc = vtc().await;
    let admin = admin(&vtc).await;
    let schema = json!({ "type": "object" });
    let (status, doc) = call(
        &vtc,
        &admin,
        &t("schemas/register/0.1"),
        json!({ "typeUri": "StatementCredential", "kind": "accepts", "credentialSchema": schema }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    assert_eq!(payload(&doc)["schema"]["typeUri"], "StatementCredential");

    let (_, doc) = call(
        &vtc,
        &admin,
        &t("schemas/list/0.1"),
        json!({ "kind": "accepts" }),
    )
    .await;
    assert_eq!(
        payload(&doc)["items"][0]["hasCredentialSchema"],
        true,
        "{doc}"
    );
    let (_, doc) = call(
        &vtc,
        &admin,
        &t("schemas/list/0.1"),
        json!({ "kind": "issues" }),
    )
    .await;
    assert_eq!(payload(&doc)["items"], json!([]), "{doc}");

    let (_, doc) = call(
        &vtc,
        &admin,
        &t("schemas/show/0.1"),
        json!({ "typeUri": "StatementCredential" }),
    )
    .await;
    assert_eq!(payload(&doc)["schema"]["credentialSchema"], schema, "{doc}");

    let (_, doc) = call(
        &vtc,
        &admin,
        &t("schemas/accepts/register/0.1"),
        json!({
            "id": "membership",
            "query": { "credentials": [ { "id": "m", "format": "ldp_vc",
                       "meta": { "type_values": ["StatementCredential"] } } ] },
        }),
    )
    .await;
    assert_eq!(payload(&doc)["criterion"]["id"], "membership", "{doc}");
    let (_, doc) = call(
        &vtc,
        &admin,
        &t("schemas/accepts/show/0.1"),
        json!({ "id": "membership" }),
    )
    .await;
    assert_eq!(payload(&doc)["criterion"]["id"], "membership", "{doc}");
    let (_, doc) = call(
        &vtc,
        &admin,
        &t("schemas/accepts/delete/0.1"),
        json!({ "id": "membership" }),
    )
    .await;
    assert_eq!(payload(&doc)["id"], "membership", "{doc}");
    let (_, doc) = call(
        &vtc,
        &admin,
        &t("schemas/accepts/show/0.1"),
        json!({ "id": "membership" }),
    )
    .await;
    assert_eq!(
        error_code(&doc),
        Some("vtc/schemas/accepts/show:notFound"),
        "{doc}"
    );

    let (_, doc) = call(
        &vtc,
        &admin,
        &t("schemas/delete/0.1"),
        json!({ "typeUri": "StatementCredential" }),
    )
    .await;
    assert_eq!(payload(&doc)["typeUri"], "StatementCredential", "{doc}");
    for task in ["schemas/show/0.1", "schemas/delete/0.1"] {
        let (_, doc) = call(
            &vtc,
            &admin,
            &t(task),
            json!({ "typeUri": "StatementCredential" }),
        )
        .await;
        let code = error_code(&doc).unwrap_or_default().to_string();
        assert!(code.ends_with(":notFound"), "{task}: {doc}");
    }
    let (_, doc) = call(
        &vtc,
        &admin,
        &t("schemas/register/0.1"),
        json!({ "typeUri": "X", "kind": "issues", "credentialSchema": { "type": 7 } }),
    )
    .await;
    assert_eq!(
        error_code(&doc),
        Some("vtc/schemas/register:invalidCredentialSchema"),
        "{doc}"
    );
}

#[tokio::test]
async fn the_presentation_updates_are_read_back() {
    let vtc = vtc().await;
    let admin = admin(&vtc).await;
    call(
        &vtc,
        &admin,
        &t("community/branding/update/0.1"),
        json!({ "branding": { "displayName": "Kernel Devs" } }),
    )
    .await;
    let (_, doc) = call(&vtc, &admin, &t("community/branding/show/0.1"), json!({})).await;
    assert_eq!(payload(&doc)["branding"]["displayName"], "Kernel Devs");

    call(
        &vtc,
        &admin,
        &t("community/join-discovery/update/0.1"),
        json!({ "joinDiscovery": { "public": false } }),
    )
    .await;
    let (_, doc) = call(
        &vtc,
        &admin,
        &t("community/join-discovery/show/0.1"),
        json!({}),
    )
    .await;
    assert_eq!(payload(&doc)["joinDiscovery"]["public"], false);

    let (_, doc) = call(
        &vtc,
        &admin,
        &t("community/requested-attributes/update/0.1"),
        json!({ "requestedAttributes": [ { "type": "name.display" }, { "type": "name.display" } ] }),
    )
    .await;
    assert_eq!(
        error_code(&doc),
        Some("vtc/community/requested-attributes/update:duplicateType"),
        "{doc}"
    );
}

/// A listing pages by `limit`, and a cursor it did not issue is refused.
#[tokio::test]
async fn listings_page_and_refuse_a_foreign_cursor() {
    let vtc = vtc().await;
    let admin = admin(&vtc).await;
    for uri in ["A", "B", "C"] {
        call(
            &vtc,
            &admin,
            &t("schemas/register/0.1"),
            json!({ "typeUri": uri, "kind": "issues" }),
        )
        .await;
    }
    let (_, first) = call(&vtc, &admin, &t("schemas/list/0.1"), json!({ "limit": 2 })).await;
    assert_eq!(payload(&first)["items"].as_array().unwrap().len(), 2);
    let cursor = payload(&first)["nextCursor"].as_str().unwrap().to_string();
    let (_, second) = call(
        &vtc,
        &admin,
        &t("schemas/list/0.1"),
        json!({ "limit": 2, "cursor": cursor }),
    )
    .await;
    assert_eq!(payload(&second)["items"][0]["typeUri"], "C", "{second}");
    assert!(payload(&second).get("nextCursor").is_none());
    let (status, _) = call(
        &vtc,
        &admin,
        &t("schemas/list/0.1"),
        json!({ "cursor": "not-a-cursor" }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn the_moved_bearer_routes_are_gone_and_the_client_routes_stay() {
    let vtc = vtc().await;
    for (method, path) in [
        ("GET", "/v1/community/join-discovery"),
        ("PUT", "/v1/community/join-discovery"),
        ("GET", "/v1/schemas"),
        ("POST", "/v1/schemas"),
        ("GET", "/v1/schemas/accepts"),
        ("POST", "/v1/schemas/accepts"),
        ("GET", "/v1/rooms"),
        ("POST", "/v1/join-requests/query"),
        // `vtc-client` used to call these; #1858 moved the vetting admin
        // reads (grants list, auto-grant, revocations) and the community
        // branding + requested-attributes reads to signed-only Trust Tasks
        // (`trust_tasks::surface_tasks`), so `vtc-client` signs them instead
        // and their admin-bearer REST mounts have no caller left either.
        ("GET", "/v1/community/branding"),
        ("GET", "/v1/community/requested-attributes"),
        ("GET", "/v1/vetting/vetters"),
        ("GET", "/v1/vetting/auto-grant"),
        ("GET", "/v1/vetting/revocations"),
    ] {
        assert!(
            !bearer_route_served(&vtc, method, path).await,
            "{method} {path} is still served"
        );
    }
}

// ─── the codes the specifications declare ───────────────────────────────

const REQUESTED_ERR_DUPLICATE_TYPE: &str =
    "vtc/community/requested-attributes/update:duplicateType";
const SCHEMAS_REGISTER_ERR_INVALID_CREDENTIAL_SCHEMA: &str =
    "vtc/schemas/register:invalidCredentialSchema";
const SCHEMAS_SHOW_ERR_NOT_FOUND: &str = "vtc/schemas/show:notFound";
const SCHEMAS_DELETE_ERR_NOT_FOUND: &str = "vtc/schemas/delete:notFound";
const SCHEMAS_DELETE_ERR_IN_USE: &str = "vtc/schemas/delete:inUse";
const ACCEPTS_REGISTER_ERR_INVALID_QUERY: &str = "vtc/schemas/accepts/register:invalidQuery";
const ACCEPTS_REGISTER_ERR_UNREGISTERED_TYPE: &str =
    "vtc/schemas/accepts/register:unregisteredType";
const ACCEPTS_REGISTER_ERR_UNREGISTERED_STATEMENT_TYPE: &str =
    "vtc/schemas/accepts/register:unregisteredStatementType";
const ACCEPTS_REGISTER_ERR_INVALID_VETTING: &str = "vtc/schemas/accepts/register:invalidVetting";
const ACCEPTS_SHOW_ERR_NOT_FOUND: &str = "vtc/schemas/accepts/show:notFound";
const ACCEPTS_DELETE_ERR_NOT_FOUND: &str = "vtc/schemas/accepts/delete:notFound";
const SUSPEND_ERR_NOT_FOUND: &str = "vtc/relationships/suspend:notFound";
const SUSPEND_ERR_ALREADY_SUSPENDED: &str = "vtc/relationships/suspend:alreadySuspended";
const SUSPEND_ERR_TERMINAL: &str = "vtc/relationships/suspend:terminal";
const RESTORE_ERR_NOT_FOUND: &str = "vtc/relationships/restore:notFound";
const RESTORE_ERR_NOT_SUSPENDED: &str = "vtc/relationships/restore:notSuspended";
const RESTORE_ERR_TERMINAL: &str = "vtc/relationships/restore:terminal";
const JOIN_VETTING_ERR_NOT_FOUND: &str = "vtc/join-requests/vetting/show:notFound";
const JOIN_QUERY_ERR_CRITERION_NOT_FOUND: &str = "vtc/join-requests/query:criterionNotFound";

/// A refusal's declared code.
fn tt_error_code(doc: &Value) -> Option<&str> {
    error_code(doc)
}

const STATEMENT_TYPE: &str = "https://example.test/predicates/vetted/1";

/// A DCQL query naming `vct` as the credential type it accepts.
fn query_for(vct: &str) -> Value {
    json!({ "credentials": [ { "id": "c", "format": "dc+sd-jwt", "meta": { "vct_values": [vct] } } ] })
}

fn vetting(statement_type: &str, min_by_method: Value) -> Value {
    json!({
        "version": "0.1",
        "statementType": statement_type,
        "minStatements": 1,
        "minByMethod": min_by_method,
        "acceptedMethods": ["video"],
        "eligibleVetters": { "role": "vetter" },
    })
}

#[tokio::test]
async fn the_presentation_and_registry_codes_are_answered() {
    let vtc = vtc().await;
    let admin = admin(&vtc).await;
    let (_, doc) = call(
        &vtc,
        &admin,
        &t("community/requested-attributes/update/0.1"),
        json!({ "requestedAttributes": [ { "type": "name.display" }, { "type": "name.display" } ] }),
    )
    .await;
    assert_eq!(
        tt_error_code(&doc),
        Some(REQUESTED_ERR_DUPLICATE_TYPE),
        "{doc}"
    );

    let (_, doc) = call(
        &vtc,
        &admin,
        &t("schemas/register/0.1"),
        json!({ "typeUri": "X", "kind": "issues", "credentialSchema": { "type": 7 } }),
    )
    .await;
    assert_eq!(
        tt_error_code(&doc),
        Some(SCHEMAS_REGISTER_ERR_INVALID_CREDENTIAL_SCHEMA),
        "{doc}"
    );
    let missing = json!({ "typeUri": "Nothing" });
    let (_, doc) = call(&vtc, &admin, &t("schemas/show/0.1"), missing.clone()).await;
    assert_eq!(
        tt_error_code(&doc),
        Some(SCHEMAS_SHOW_ERR_NOT_FOUND),
        "{doc}"
    );
    let (_, doc) = call(&vtc, &admin, &t("schemas/delete/0.1"), missing).await;
    assert_eq!(
        tt_error_code(&doc),
        Some(SCHEMAS_DELETE_ERR_NOT_FOUND),
        "{doc}"
    );
    let (_, doc) = call(
        &vtc,
        &admin,
        &t("schemas/accepts/show/0.1"),
        json!({ "id": "none" }),
    )
    .await;
    assert_eq!(
        tt_error_code(&doc),
        Some(ACCEPTS_SHOW_ERR_NOT_FOUND),
        "{doc}"
    );
    let (_, doc) = call(
        &vtc,
        &admin,
        &t("schemas/accepts/delete/0.1"),
        json!({ "id": "none" }),
    )
    .await;
    assert_eq!(
        tt_error_code(&doc),
        Some(ACCEPTS_DELETE_ERR_NOT_FOUND),
        "{doc}"
    );

    // The Accepts refusals, in the order the specification lists them.
    let register = |body: Value| {
        let (vtc, admin) = (&vtc, &admin);
        async move {
            call(vtc, admin, &t("schemas/accepts/register/0.1"), body)
                .await
                .1
        }
    };
    let doc = register(json!({ "id": "c", "query": { "credentials": "not a list" } })).await;
    assert_eq!(
        tt_error_code(&doc),
        Some(ACCEPTS_REGISTER_ERR_INVALID_QUERY),
        "{doc}"
    );
    let doc = register(json!({ "id": "c", "query": query_for("Unregistered") })).await;
    assert_eq!(
        tt_error_code(&doc),
        Some(ACCEPTS_REGISTER_ERR_UNREGISTERED_TYPE),
        "{doc}"
    );
    call(
        &vtc,
        &admin,
        &t("schemas/register/0.1"),
        json!({ "typeUri": "Vetted", "kind": "accepts" }),
    )
    .await;
    let doc = register(json!({
        "id": "c",
        "query": query_for("Vetted"),
        "vetting": vetting(STATEMENT_TYPE, json!({})),
    }))
    .await;
    assert_eq!(
        tt_error_code(&doc),
        Some(ACCEPTS_REGISTER_ERR_UNREGISTERED_STATEMENT_TYPE),
        "{doc}"
    );
    let (status, doc) = call(
        &vtc,
        &admin,
        "https://trusttasks.org/spec/vtc/endorsement-types/register/0.1",
        json!({ "typeUri": STATEMENT_TYPE, "description": "A member vetted this person" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    let doc = register(json!({
        "id": "c",
        "query": query_for("Vetted"),
        "vetting": vetting(STATEMENT_TYPE, json!({ "inPerson": 1 })),
    }))
    .await;
    assert_eq!(
        tt_error_code(&doc),
        Some(ACCEPTS_REGISTER_ERR_INVALID_VETTING),
        "{doc}"
    );

    // A type a criterion's query names cannot be deleted from under it.
    let doc = register(json!({ "id": "c", "query": query_for("Vetted") })).await;
    assert_eq!(payload(&doc)["criterion"]["id"], "c", "{doc}");
    let (_, doc) = call(
        &vtc,
        &admin,
        &t("schemas/delete/0.1"),
        json!({ "typeUri": "Vetted" }),
    )
    .await;
    assert_eq!(
        tt_error_code(&doc),
        Some(SCHEMAS_DELETE_ERR_IN_USE),
        "{doc}"
    );
    assert_eq!(
        payload(&doc)["details"]["criterionIds"],
        json!(["c"]),
        "{doc}"
    );
}

/// Seed an edge from `issuer` to `subject`, returning its id.
async fn edge(vtc: &TestVtc, issuer: &str, subject: &str) -> uuid::Uuid {
    use vtc_service::relationships::{Relationship, store_relationship};
    let id = uuid::Uuid::new_v4();
    let vrc = json!({ "type": ["VerifiableCredential"], "issuer": issuer,
                      "credentialSubject": { "id": subject } });
    let rel = Relationship {
        id,
        issuer_did: issuer.into(),
        subject_did: subject.into(),
        vrc_jsonld: vrc,
        vrc_digest_multibase: "zQmSeeded".into(),
        created_at: chrono::Utc::now(),
        persona: None,
        lifecycle: Default::default(),
    };
    store_relationship(
        &vtc.state.relationships_ks,
        &vtc.state.relationships_by_did_ks,
        &rel,
    )
    .await
    .unwrap();
    id
}

#[tokio::test]
async fn the_lifecycle_and_join_codes_are_answered() {
    let vtc = vtc().await;
    let admin = admin(&vtc).await;
    let issuer = party_with_role(&vtc, VtcRole::Member, &[]).await;
    let stranger = party_with_role(&vtc, VtcRole::Member, &[]).await;
    let id = edge(&vtc, &issuer.did, "did:key:z6MkSurfaceSubject").await;
    let suspend = t("relationships/suspend/0.1");
    let restore = t("relationships/restore/0.1");
    let on = json!({ "id": id.to_string() });

    // Neither the issuer nor an administrator: as if there were no edge.
    let (_, doc) = call(&vtc, &stranger, &suspend, on.clone()).await;
    assert_eq!(tt_error_code(&doc), Some(SUSPEND_ERR_NOT_FOUND), "{doc}");
    let (_, doc) = call(&vtc, &stranger, &restore, on.clone()).await;
    assert_eq!(tt_error_code(&doc), Some(RESTORE_ERR_NOT_FOUND), "{doc}");

    let (_, doc) = call(&vtc, &issuer, &restore, on.clone()).await;
    assert_eq!(
        tt_error_code(&doc),
        Some(RESTORE_ERR_NOT_SUSPENDED),
        "{doc}"
    );
    let (status, doc) = call(&vtc, &issuer, &suspend, on.clone()).await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    let (_, doc) = call(&vtc, &issuer, &suspend, on.clone()).await;
    assert_eq!(
        tt_error_code(&doc),
        Some(SUSPEND_ERR_ALREADY_SUSPENDED),
        "{doc}"
    );

    // Withdrawn is terminal: neither verb records past it.
    vtc_service::relationships::record_lifecycle_event(
        &vtc.state.relationships_ks,
        &vtc.state.relationships_by_did_ks,
        id,
        vtc_service::relationships::LifecycleEventKind::Withdrawn { reason: None },
        chrono::Utc::now(),
    )
    .await
    .unwrap();
    let (_, doc) = call(&vtc, &admin, &suspend, on.clone()).await;
    assert_eq!(tt_error_code(&doc), Some(SUSPEND_ERR_TERMINAL), "{doc}");
    let (_, doc) = call(&vtc, &admin, &restore, on).await;
    assert_eq!(tt_error_code(&doc), Some(RESTORE_ERR_TERMINAL), "{doc}");

    let (_, doc) = call(
        &vtc,
        &admin,
        &t("join-requests/vetting/show/0.1"),
        json!({ "id": uuid::Uuid::new_v4().to_string() }),
    )
    .await;
    assert_eq!(
        tt_error_code(&doc),
        Some(JOIN_VETTING_ERR_NOT_FOUND),
        "{doc}"
    );
    let (_, doc) = call(
        &vtc,
        &admin,
        &t("join-requests/query/0.1"),
        json!({ "holderDid": "did:key:z6MkHolder", "criterionId": "does-not-exist" }),
    )
    .await;
    assert_eq!(
        tt_error_code(&doc),
        Some(JOIN_QUERY_ERR_CRITERION_NOT_FOUND),
        "{doc}"
    );
}
