//! Integration coverage for `/v1/endorsement-types/*` +
//! `/v1/credentials/endorsements/*` (Phase 4 M4.8).
//!
//! Covers:
//! - type registry: register happy / reserved / duplicate /
//!   delete with-in-use / delete OK / list
//! - issue: type-not-registered / non-issuer / happy path
//!   (with status-list slot allocation + audit emission)
//! - revoke: admin / non-admin-non-issuer / idempotent
//! - show / list pagination

use affinidi_status_list::StatusPurpose;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use chrono::Utc;
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;
use uuid::Uuid;
use vti_common::audit::{AuditEnvelope, AuditEvent};
use vti_common::auth::session::now_epoch;

use vti_rooms_dtg::test_support::Party;

use vtc_service::acl::{VtcAclEntry, VtcRole, store_acl_entry};
use vtc_service::endorsement_types::{EndorsementType, get_type, store_type};
use vtc_service::members::{Member, store_member};
use vtc_service::status_list;
use vtc_service::test_support::TestVtc;

const PUBLIC_URL: &str = "https://vtc.example.com";
const REGISTER_TASK: &str = "https://trusttasks.org/spec/vtc/endorsement-types/register/0.1";
const DELETE_TYPE_TASK: &str = "https://trusttasks.org/spec/vtc/endorsement-types/delete/0.1";
const ISSUE_TASK: &str = "https://trusttasks.org/spec/vtc/endorsements/issue/0.1";
const REVOKE_TASK: &str = "https://trusttasks.org/spec/vtc/endorsements/revoke/0.1";
const SHOW_TASK: &str = "https://trusttasks.org/spec/vtc/endorsements/show/0.1";
const SCHEMA_REGISTER_TASK: &str = "https://trusttasks.org/spec/vtc/schemas/register/0.1";
const ACCEPTS_REGISTER_TASK: &str = "https://trusttasks.org/spec/vtc/schemas/accepts/register/0.2";
const ACCEPTS_DELETE_TASK: &str = "https://trusttasks.org/spec/vtc/schemas/accepts/delete/0.1";
const ADMIN_DID: &str = "did:key:zEndAdmin";
const ISSUER_DID: &str = "did:key:zEndIssuer";
const MEMBER_DID: &str = "did:key:zEndMember";
const SUBJECT_DID: &str = "did:key:zEndSubject";

struct Fixture {
    router: axum::Router,
    /// Every endorsement-type write, and every endorsement verb, is a signed
    /// document only; these sign them.
    admin: Party,
    member: Party,
    issuer: Party,
    audit_ks: vti_common::store::KeyspaceHandle,
    endorsements_ks: vti_common::store::KeyspaceHandle,
    // Owns the temp data dir + serves `router`'s state; must outlive them.
    _vtc: TestVtc,
}

async fn build() -> Fixture {
    let vtc = TestVtc::builder()
        .with_audit(true)
        .with_signers(true)
        .with_public_url(PUBLIC_URL)
        .build()
        .await;

    vtc_service::policy::default::install_defaults(
        &vtc.state.policies_ks,
        &vtc.state.active_policies_ks,
    )
    .await
    .unwrap();
    for purpose in [StatusPurpose::Revocation, StatusPurpose::Suspension] {
        let url = format!("{PUBLIC_URL}/v1/status-lists/{purpose}");
        status_list::ensure_initial(&vtc.state.status_lists_ks, purpose, url)
            .await
            .unwrap();
    }

    let now = now_epoch();
    for (did, role) in [
        (ADMIN_DID, VtcRole::Admin),
        (ISSUER_DID, VtcRole::Issuer),
        (MEMBER_DID, VtcRole::Member),
        (SUBJECT_DID, VtcRole::Member),
    ] {
        store_acl_entry(
            &vtc.state.acl_ks,
            &VtcAclEntry {
                did: did.into(),
                admin: role.implied_authority(),
                delegated_by: None,
                role,
                label: None,
                created_at: now,
                created_by: "did:key:vtc-install".into(),
                updated_at: None,
                updated_by: None,
                expires_at: None,
                resource_grants: Vec::new(),
                label_set_by_subject: false,
            },
        )
        .await
        .unwrap();
        store_member(&vtc.state.members_ks, &Member::fresh(did))
            .await
            .unwrap();
    }

    let admin = Party::new();
    let member = Party::new();
    let issuer = Party::new();
    for (who, role) in [
        (&admin, VtcRole::Admin),
        (&member, VtcRole::Member),
        (&issuer, VtcRole::Issuer),
    ] {
        store_acl_entry(
            &vtc.state.acl_ks,
            &VtcAclEntry {
                did: who.did.clone(),
                admin: role.implied_authority(),
                delegated_by: None,
                role,
                label: None,
                created_at: now,
                created_by: "did:key:vtc-install".into(),
                updated_at: None,
                updated_by: None,
                expires_at: None,
                resource_grants: Vec::new(),
                label_set_by_subject: false,
            },
        )
        .await
        .unwrap();
    }

    let audit_ks = vtc.state.audit_ks.clone();
    let endorsements_ks = vtc.state.endorsements_ks.clone();
    let router = vtc.router.clone();

    Fixture {
        router,
        admin,
        member,
        issuer,
        audit_ks,
        endorsements_ks,
        _vtc: vtc,
    }
}

async fn body_value(resp: axum::response::Response) -> (StatusCode, Value) {
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let v: Value = serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| json!({ "raw": String::from_utf8_lossy(&bytes) }));
    (status, v)
}

// ─── Type registry ───────────────────────────────────────
//
// `register` and `delete` are signed documents at `POST /v1/trust-tasks`; the
// helpers answer `(status, payload)`, where a refusal's payload carries its
// `code` and `message`.

async fn signed_task(
    fix: &Fixture,
    from: &Party,
    task: &str,
    payload: Value,
) -> (StatusCode, Value) {
    let (status, payload, _) = signed_task_with_doc(fix, from, task, payload).await;
    (status, payload)
}

/// [`signed_task`], also handing back the signed request document.
async fn signed_task_with_doc(
    fix: &Fixture,
    from: &Party,
    task: &str,
    payload: Value,
) -> (StatusCode, Value, Value) {
    let mut doc = vta_sdk::trust_task_sign::build_unsigned(
        task,
        payload,
        &from.did,
        vtc_service::test_support::TEST_VTC_DID,
    )
    .unwrap();
    let key = vta_sdk::trust_task_sign::HolderKey::from_did_key(&from.did, &from.secret_multibase)
        .unwrap();
    vta_sdk::trust_task_sign::sign_in_place_with(&mut doc, &key)
        .await
        .unwrap();
    let req = Request::builder()
        .method("POST")
        .uri("/v1/trust-tasks")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&doc).unwrap()))
        .unwrap();
    let (status, body) = body_value(fix.router.clone().oneshot(req).await.unwrap()).await;
    (
        status,
        body["payload"].clone(),
        serde_json::to_value(&doc).unwrap(),
    )
}

#[tokio::test]
async fn register_happy_path() {
    let fix = build().await;
    let (status, v) = register(
        &fix,
        json!({
            "typeUri": "https://example.com/v1/skills/rust",
            "description": "Rust expertise"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{v}");
    // `{endorsementType: …}` since #1059 — the row was returned bare until
    // the witness compared the handler with its own schema.
    assert_eq!(
        v["endorsementType"]["typeUri"],
        "https://example.com/v1/skills/rust"
    );
}

#[tokio::test]
async fn register_rejects_reserved_uri() {
    let fix = build().await;
    let (status, body) = register(&fix, json!({ "typeUri": "role:vetter" })).await;
    assert!(status.is_client_error(), "{body}");
    assert_eq!(rest_error_code(&body), REGISTER_ERR_RESERVED, "{body}");
}

#[tokio::test]
async fn register_rejects_duplicate() {
    let fix = build().await;
    let uri = "https://example.com/v1/skills/rust";
    let (status, body) = register(&fix, json!({ "typeUri": uri })).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    // A second register fails.
    let (status, body) = register(&fix, json!({ "typeUri": uri })).await;
    assert!(status.is_client_error(), "{body}");
    assert_eq!(rest_error_code(&body), REGISTER_ERR_EXISTS, "{body}");
}

#[tokio::test]
async fn register_requires_admin() {
    let fix = build().await;
    let (status, body) = signed_task(
        &fix,
        &fix.member,
        REGISTER_TASK,
        json!({ "typeUri": "https://x/t" }),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
}

#[tokio::test]
async fn delete_type_404_when_unknown() {
    let fix = build().await;
    let (status, body) = delete_type(&fix, "https://x/t").await;
    assert!(status.is_client_error(), "{body}");
    assert_eq!(rest_error_code(&body), DELETE_ERR_NOT_FOUND, "{body}");
}

// ─── Issue ───────────────────────────────────────────────

async fn register_type(fix: &Fixture, uri: &str) {
    let (status, body) = register(fix, json!({ "typeUri": uri })).await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn issue_rejects_unregistered_type() {
    let fix = build().await;
    // `typeNotRegistered` is a declared code, so it rides the framework's
    // flat 422 bucket for extended codes over the signed door (not the REST
    // route's old 400).
    let (status, body) = issue(&fix, "https://unregistered.example/t", json!({ "x": 1 })).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert_eq!(
        rest_error_code(&body),
        ISSUE_ERR_TYPE_NOT_REGISTERED,
        "{body}"
    );
}

#[tokio::test]
async fn issue_rejects_non_issuer_non_admin() {
    let fix = build().await;
    register_type(&fix, "https://example.com/v1/skills/rust").await;
    let (status, body) = signed_task(
        &fix,
        &fix.member,
        ISSUE_TASK,
        json!({
            "subjectDid": SUBJECT_DID,
            "typeUri": "https://example.com/v1/skills/rust",
            "claim": { "level": "expert" }
        }),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
}

#[tokio::test]
async fn issue_happy_path_issuer_mints_credential() {
    let fix = build().await;
    let uri = "https://example.com/v1/skills/rust";
    register_type(&fix, uri).await;
    let (status, v) = issue(&fix, uri, json!({ "level": "expert", "since": "2020" })).await;
    // Every success over the signed door answers 200, not the REST route's
    // old 201.
    assert_eq!(status, StatusCode::OK, "{v}");
    assert!(v["endorsement"]["endorsementId"].is_string());
    // vtc/endorsements/issue/0.1, "The credential issued": a DTG statement by
    // the community, as itself, under the registered predicate.
    let credential = &v["credential"];
    assert_eq!(
        credential["@context"],
        json!([
            dtg_credentials::W3C_VC_V2_CONTEXT,
            dtg_credentials::DTG_CONTEXT_V1
        ])
    );
    assert_eq!(
        credential["type"],
        json!([
            "VerifiableCredential",
            "DTGCredential",
            "StatementCredential"
        ])
    );
    assert_eq!(credential["issuerScope"], "public");
    assert_eq!(credential["credentialSubject"]["id"], SUBJECT_DID);
    assert_eq!(credential["credentialSubject"]["predicate"], uri);
    assert_eq!(
        credential["credentialSubject"]["object"],
        json!({ "value": { "level": "expert", "since": "2020" } })
    );
    assert!(credential["credentialStatus"].is_object());
    // The row carries a *reference* — identifier and lifetime — and the
    // credential itself is a sibling that only this call returns. #1098 put
    // it inside the reference, which made every listing embed a signed
    // credential per row; trustoverip/dtgwg-trust-tasks-tf#262 split the two.
    let issued = &v["endorsement"]["issued"];
    assert!(
        issued["credential"].is_null(),
        "a read reference must not embed the credential: {v}"
    );
    assert!(v["credential"].is_object(), "got {v}");
    let cred_id = issued["credentialId"].as_str().expect("credentialId");
    assert!(cred_id.starts_with("urn:uuid:"), "got {cred_id}");
    // The reference names the credential returned beside it.
    assert_eq!(v["credential"]["id"], issued["credentialId"]);
    assert!(issued["expiresAt"].is_string(), "got {v}");

    // Audit: CustomEndorsementIssued + VecIssued both emitted.
    let pairs = fix.audit_ks.prefix_iter_raw(Vec::new()).await.unwrap();
    let mut saw_issued = false;
    let mut saw_vec = false;
    for (_k, raw) in pairs {
        let env: AuditEnvelope = serde_json::from_slice(&raw).unwrap();
        match env.event {
            AuditEvent::CustomEndorsementIssued(d) if d.endorsement_type == uri => {
                saw_issued = true;
            }
            AuditEvent::VecIssued(d) if d.credential_type == "StatementCredential" => {
                saw_vec = true;
            }
            _ => {}
        }
    }
    assert!(saw_issued, "must emit CustomEndorsementIssued");
    assert!(saw_vec, "must emit VecIssued for accounting");
}

#[tokio::test]
async fn issue_rejects_unknown_subject() {
    let fix = build().await;
    let uri = "https://example.com/v1/t";
    register_type(&fix, uri).await;
    let (status, body) = signed_task(
        &fix,
        &fix.issuer,
        ISSUE_TASK,
        json!({
            "subjectDid": "did:key:zStranger",
            "typeUri": uri,
            "claim": { "x": 1 }
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
}

#[tokio::test]
async fn delete_type_refused_while_live_endorsement_exists() {
    let fix = build().await;
    let uri = "https://example.com/v1/skills/rust";
    register_type(&fix, uri).await;
    // Issue an endorsement of that type.
    let (status, v) = issue(&fix, uri, json!({ "level": "expert" })).await;
    assert_eq!(status, StatusCode::OK, "{v}");

    // Try to delete the type — must be refused `inUse`.
    let (status, body) = delete_type(&fix, uri).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert_eq!(rest_error_code(&body), DELETE_ERR_IN_USE, "{body}");
}

/// The symmetric partner of `register_accepts`' check that a criterion's
/// `statementType` is registered. Without this, deleting the type strands the
/// criterion in exactly the state registration forbids: it keeps advertising a
/// type the community no longer recognises, and can no longer be saved again.
#[tokio::test]
async fn delete_type_refused_while_a_criterion_names_it() {
    let fix = build().await;
    let uri = "https://example.com/v1/identity-vetting";
    register_type(&fix, uri).await;
    register_vetting_criterion(&fix, "kernel-developer", uri).await;

    let (status, body) = delete_type(&fix, uri).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert_eq!(rest_error_code(&body), DELETE_ERR_IN_USE, "{body}");
    // The console renders this text verbatim, so the criterion must be named:
    // "it is in use" the operator cannot act on.
    let message = body.to_string();
    assert!(
        message.contains("kernel-developer"),
        "409 must name the criterion that blocks the delete: {message}"
    );

    // Removing the criterion releases the type — the guard is not sticky.
    let (status, body) = signed_task(
        &fix,
        &fix.admin,
        ACCEPTS_DELETE_TASK,
        json!({ "id": "kernel-developer" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let (status, body) = delete_type(&fix, uri).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["typeUri"], uri);
}

/// `vtc/endorsement-types/delete/0.1`, signed by the fixture's admin.
async fn delete_type(fix: &Fixture, uri: &str) -> (StatusCode, Value) {
    signed_task(fix, &fix.admin, DELETE_TYPE_TASK, json!({ "typeUri": uri })).await
}

/// An endorsement type's `claimSchema` must not make the service read a local
/// file (or fetch a URL) while it is compiled either.
///
/// #1660 turned the `jsonschema` resolvers off and held that manifest honest
/// for `/v1/schemas` and for `validate_instance`. #1657 then added a third
/// caller-supplied schema to the same compiler: `check_schema`, run when an
/// endorsement type is registered. It makes the same `validator_for` call, so
/// it has the same exposure and needs the same guard — otherwise restoring the
/// features would be caught on two paths out of three.
///
/// The referenced file really exists and really is a valid schema, so this
/// registration would succeed if the resolver were on.
#[tokio::test]
async fn a_claim_schema_with_an_external_ref_is_refused_rather_than_fetched() {
    let fix = build().await;

    let dir = tempfile::tempdir().expect("temp dir");
    let target = dir.path().join("ref-target.json");
    std::fs::write(&target, br#"{"type": "string"}"#).expect("write target");
    assert!(target.exists());

    let uri = "https://example.com/v1/skills/external-ref";
    let (status, body) = register(
        &fix,
        json!({
            "typeUri": uri,
            "claimSchema": { "$ref": format!("file://{}", target.display()) },
        }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a claimSchema with a file:// $ref must be refused, not resolved: {body}"
    );
    assert_eq!(
        rest_error_code(&body),
        trust_tasks_rs::StandardCode::MalformedRequest.as_str(),
        "{body}"
    );
    assert!(
        get_type(&fix._vtc.state.endorsement_types_ks, uri)
            .await
            .unwrap()
            .is_none(),
        "a refused registration must not store the type"
    );

    // The network case: refused at compile rather than attempted. The address
    // is unroutable, so a regression shows up as a refusal that takes a
    // connect timeout rather than as a pass.
    let (status, _) = register(
        &fix,
        json!({
            "typeUri": "https://example.com/v1/skills/external-ref-http",
            "claimSchema": { "$ref": "http://127.0.0.1:1/schema.json" },
        }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "an http:// $ref must not be fetched"
    );

    // An ordinary internal $ref still registers — this removes remote
    // resolution, not `$ref` itself.
    let (status, body) = register(
        &fix,
        json!({
            "typeUri": "https://example.com/v1/skills/internal-ref",
            "claimSchema": {
                "type": "object",
                "$defs": { "level": { "type": "integer" } },
                "properties": { "level": { "$ref": "#/$defs/level" } },
            },
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

/// A `credentialSchema` supplied by an admin must not make the service read a
/// local file (or fetch a URL) while compiling it.
///
/// The `jsonschema` crate enables `resolve-http`/`resolve-file` by default;
/// the workspace manifest turns both off, because every schema this service
/// compiles arrives from a caller. The referenced file really exists and is a
/// valid schema, so this registration would succeed if the resolver were on.
#[tokio::test]
async fn register_schema_refuses_an_external_ref() {
    let fix = build().await;

    let dir = tempfile::tempdir().expect("temp dir");
    let target = dir.path().join("ref-target.json");
    std::fs::write(&target, br#"{"type": "string"}"#).expect("write target");

    let (status, body) = signed_task(
        &fix,
        &fix.admin,
        SCHEMA_REGISTER_TASK,
        json!({
            "typeUri": "https://example.test/ExternalRefCredential",
            "dtgType": "ExternalRefCredential",
            "kind": "issues",
            "credentialSchema": { "$ref": format!("file://{}", target.display()) },
        }),
    )
    .await;
    assert!(
        !status.is_success(),
        "a schema with a file:// $ref must be refused, not resolved: {body}"
    );
    assert_eq!(
        body["code"], "vtc/schemas/register:invalidCredentialSchema",
        "{body}"
    );
}

/// An Accepts criterion counting statements of `statement_type`. The DCQL
/// query references `StatementCredential`, so that per-type schema is
/// registered first — `store_accepts` refuses a dangling type reference.
async fn register_vetting_criterion(fix: &Fixture, id: &str, statement_type: &str) {
    let (status, body) = signed_task(
        fix,
        &fix.admin,
        SCHEMA_REGISTER_TASK,
        json!({
            "typeUri": "StatementCredential",
            "dtgType": "StatementCredential",
            "kind": "accepts",
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "register schema: {body}");

    let (status, body) = signed_task(
        fix,
        &fix.admin,
        ACCEPTS_REGISTER_TASK,
        json!({
                "id": id,
                "description": "Two vetters, at least one in person",
                "admission": "automatic",
                "vetting": {
                    "version": "0.1",
                    "statementType": statement_type,
                    "minStatements": 2,
                    "minByMethod": { "inPerson": 1 },
                    "acceptedMethods": ["inPerson", "video"],
                    "maxStatementAge": "P120D",
                    "eligibleVetters": { "role": "vetter" },
                },
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "register criterion: {body}");
}

// ─── Revoke ──────────────────────────────────────────────

#[tokio::test]
async fn revoke_issuer_can_retract() {
    let fix = build().await;
    let uri = "https://example.com/v1/t";
    register_type(&fix, uri).await;
    let (_, v) = issue(&fix, uri, json!({ "x": 1 })).await;
    let id = v["endorsement"]["endorsementId"]
        .as_str()
        .unwrap()
        .to_string();

    let (status, body) = signed_task(
        &fix,
        &fix.issuer,
        REVOKE_TASK,
        json!({ "endorsementId": id }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // Audit: CustomEndorsementRevoked + StatusListFlipped.
    let pairs = fix.audit_ks.prefix_iter_raw(Vec::new()).await.unwrap();
    let mut saw_revoked = false;
    let mut saw_flipped = false;
    for (_k, raw) in pairs {
        let env: AuditEnvelope = serde_json::from_slice(&raw).unwrap();
        match env.event {
            AuditEvent::CustomEndorsementRevoked(_) => saw_revoked = true,
            AuditEvent::StatusListFlipped(d) if d.revoked => saw_flipped = true,
            _ => {}
        }
    }
    assert!(saw_revoked);
    assert!(saw_flipped);
    let _ = fix.endorsements_ks;
}

/// `vtc/endorsements/revoke/0.1` Conformance 3: re-revoking is
/// `alreadyRevoked` (409), and the bit is not re-flipped nor the revocation
/// re-audited. It used to answer 200 with the first receipt, which the
/// specification calls out as the pre-migration divergence to correct.
#[tokio::test]
async fn re_revoking_is_the_declared_already_revoked() {
    let fix = build().await;
    let uri = "https://example.com/v1/t";
    register_type(&fix, uri).await;
    let (_, v) = issue(&fix, uri, json!({ "x": 1 })).await;
    let id = v["endorsement"]["endorsementId"]
        .as_str()
        .unwrap()
        .to_string();

    let revoke = || {
        signed_task(
            &fix,
            &fix.admin,
            REVOKE_TASK,
            json!({ "endorsementId": id }),
        )
    };
    let (status, body) = revoke().await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let audit_rows = fix
        .audit_ks
        .prefix_iter_raw(Vec::new())
        .await
        .unwrap()
        .len();

    // Declared codes ride the signed door's flat 422 bucket, not the REST
    // route's old 409.
    let (status, body) = revoke().await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert_eq!(rest_error_code(&body), REVOKE_ERR_ALREADY_REVOKED, "{body}");
    assert_eq!(
        fix.audit_ks
            .prefix_iter_raw(Vec::new())
            .await
            .unwrap()
            .len(),
        audit_rows,
        "a refused re-revoke must not re-audit"
    );
}

#[tokio::test]
async fn revoke_non_admin_non_issuer_forbidden() {
    let fix = build().await;
    let uri = "https://example.com/v1/t";
    register_type(&fix, uri).await;
    let (_, v) = issue(&fix, uri, json!({ "x": 1 })).await;
    let id = v["endorsement"]["endorsementId"]
        .as_str()
        .unwrap()
        .to_string();

    let (status, body) = signed_task(
        &fix,
        &fix.member,
        REVOKE_TASK,
        json!({ "endorsementId": id }),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
}

/// `GET /credentials/endorsements/{id}` had **no test at all** before #1093,
/// which is how it returned the bare row past a published schema that wraps
/// it. Issue one, read it back, and assert the envelope — `endorsement` is
/// the member `vtc/endorsements/show/0.1` names.
#[tokio::test]
async fn show_wraps_the_row_in_an_endorsement_envelope() {
    let fix = build().await;
    let uri = "https://example.com/v1/skills/rust";
    register_type(&fix, uri).await;

    let (status, issued) = issue(&fix, uri, json!({ "level": "expert" })).await;
    assert_eq!(status, StatusCode::OK, "{issued}");
    let id = issued["endorsement"]["endorsementId"].as_str().unwrap();

    let (status, v) =
        signed_task(&fix, &fix.issuer, SHOW_TASK, json!({ "endorsementId": id })).await;
    assert_eq!(status, StatusCode::OK, "{v}");

    // The envelope, not the bare row: `v["id"]` must be absent precisely
    // because the row now sits one level down.
    assert!(v["id"].is_null(), "row must not be at the top level: {v}");
    assert_eq!(v["endorsement"]["endorsementId"], id);
    assert_eq!(v["endorsement"]["subjectDid"], SUBJECT_DID);
}

// ---------------------------------------------------------------------------
// #1600 — the codes the endorsement-type and endorsement tasks declare, read
// from the generated bindings.
// ---------------------------------------------------------------------------

use trust_tasks_rs::specs::vtc::endorsement_types as et_spec;
use trust_tasks_rs::specs::vtc::endorsements as end_spec;

const REGISTER_ERR_INVALID_URI: &str = et_spec::register::v0_1::error_codes::INVALID_URI.code;
const REGISTER_ERR_RESERVED: &str = et_spec::register::v0_1::error_codes::RESERVED.code;
const REGISTER_ERR_EXISTS: &str = et_spec::register::v0_1::error_codes::EXISTS.code;
const DELETE_ERR_NOT_FOUND: &str = et_spec::delete::v0_1::error_codes::NOT_FOUND.code;
const DELETE_ERR_IN_USE: &str = et_spec::delete::v0_1::error_codes::IN_USE.code;
const ISSUE_ERR_TYPE_NOT_REGISTERED: &str =
    end_spec::issue::v0_1::error_codes::TYPE_NOT_REGISTERED.code;
const ISSUE_ERR_CLAIM_TOO_LARGE: &str = end_spec::issue::v0_1::error_codes::CLAIM_TOO_LARGE.code;
const ISSUE_ERR_CLAIM_SCHEMA_VIOLATION: &str =
    end_spec::issue::v0_1::error_codes::CLAIM_SCHEMA_VIOLATION.code;
const ISSUE_ERR_STATUS_LIST_EXHAUSTED: &str =
    end_spec::issue::v0_1::error_codes::STATUS_LIST_EXHAUSTED.code;
const ISSUE_ERR_PREDICATE_NOT_ISSUABLE: &str =
    end_spec::issue::v0_1::error_codes::PREDICATE_NOT_ISSUABLE.code;
const LIST_ERR_INVALID_CURSOR: &str = end_spec::list::v0_1::error_codes::INVALID_CURSOR.code;
const SHOW_ERR_NOT_FOUND: &str = end_spec::show::v0_1::error_codes::NOT_FOUND.code;
const REVOKE_ERR_NOT_FOUND: &str = end_spec::revoke::v0_1::error_codes::NOT_FOUND.code;
const REVOKE_ERR_ALREADY_REVOKED: &str = end_spec::revoke::v0_1::error_codes::ALREADY_REVOKED.code;

const LIST_TASK: &str = "https://trusttasks.org/spec/vtc/endorsements/list/0.1";

/// The extended error code carried by a REST error body (`{"error", "code"}`).
fn rest_error_code(body: &Value) -> &str {
    body["code"].as_str().unwrap_or_default()
}

/// `vtc/endorsement-types/register/0.1`, signed by the fixture's admin.
async fn register(fix: &Fixture, body: Value) -> (StatusCode, Value) {
    signed_task(fix, &fix.admin, REGISTER_TASK, body).await
}

/// `vtc/endorsements/issue/0.1`, signed by the fixture's issuer.
async fn issue(fix: &Fixture, type_uri: &str, claim: Value) -> (StatusCode, Value) {
    signed_task(
        fix,
        &fix.issuer,
        ISSUE_TASK,
        json!({ "subjectDid": SUBJECT_DID, "typeUri": type_uri, "claim": claim }),
    )
    .await
}

/// An empty (or all-whitespace) `typeUri`, or one over 512 bytes, is
/// `invalidUri`; 400 unchanged. The 512-byte boundary itself registers.
#[tokio::test]
async fn an_empty_or_oversized_type_uri_is_the_declared_invalid_uri() {
    let fix = build().await;
    for uri in [
        "".to_string(),
        "   ".to_string(),
        format!("https://x/{}", "a".repeat(512)),
    ] {
        let (status, body) = register(&fix, json!({ "typeUri": uri })).await;
        assert!(status.is_client_error(), "{body}");
        // An empty or oversized URI may already fail the payload schema.
        assert!(
            [REGISTER_ERR_INVALID_URI, "malformedRequest"].contains(&rest_error_code(&body)),
            "{body}"
        );
    }
    let at_cap = format!("https://x/{}", "a".repeat(512 - "https://x/".len()));
    let (status, body) = register(&fix, json!({ "typeUri": at_cap })).await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

/// A registered `typeUri` is a predicate IRI. A bare term or a CURIE can never
/// match a statement's predicate, so it is `invalidUri`.
#[tokio::test]
async fn a_type_uri_that_is_not_a_predicate_iri_is_the_declared_invalid_uri() {
    let fix = build().await;
    for uri in ["IdentityVetting", "dtg:endorses", "urn"] {
        let (status, body) = register(&fix, json!({ "typeUri": uri })).await;
        assert!(status.is_client_error(), "{uri}: {body}");
        assert_eq!(
            rest_error_code(&body),
            REGISTER_ERR_INVALID_URI,
            "{uri}: {body}"
        );
    }
}

/// The DTG VSC registry's core predicates are accepted from first boot.
#[tokio::test]
async fn the_core_predicates_are_seeded() {
    let fix = build().await;
    for iri in vtc_service::endorsement_types::DEFAULT_ACCEPTED_PREDICATES {
        assert!(
            get_type(&fix._vtc.state.endorsement_types_ks, iri)
                .await
                .unwrap()
                .is_some(),
            "{iri} is accepted out of the box"
        );
    }
}

/// `witnessed/1` and `presented/1` are registered — the community counts
/// statements under them — but their profiles require a `taskContext` citing
/// the exchange the statement was made in, and their issuer is the party that
/// ran it, never the community. So they are `predicateNotIssuable` here.
#[tokio::test]
async fn a_task_bound_predicate_is_the_declared_predicate_not_issuable() {
    let fix = build().await;
    for iri in [dtg_credentials::WITNESSED_V1, dtg_credentials::PRESENTED_V1] {
        let (status, body) = issue(&fix, iri, json!({ "community": "did:web:x" })).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{iri}: {body}");
        assert_eq!(
            rest_error_code(&body),
            ISSUE_ERR_PREDICATE_NOT_ISSUABLE,
            "{iri}: {body}"
        );
    }
}

/// The community's own identity check, as registry `vetted/1` defines it: none
/// of the vetter-only members.
fn community_check_claim(community: &str) -> Value {
    json!({
        "community": community,
        "method": "inPerson",
        "documentClasses": ["nationalId"],
        "claimsVerified": ["name.legal"],
        "livenessConfirmed": true
    })
}

/// Under `vetted/1` the community records its own identity check: a DTG
/// statement issued by the community (`public`), citing this issue request
/// by `taskContext` and `taskDigestMultibase`, on the community's status list
/// and revocable through `vtc/endorsements/revoke/0.1` like any other row.
#[tokio::test]
async fn the_community_records_its_own_identity_check_as_a_vetted_statement() {
    let fix = build().await;
    let community = vtc_service::test_support::TEST_VTC_DID;
    let (status, v, request) = signed_task_with_doc(
        &fix,
        &fix.issuer,
        ISSUE_TASK,
        json!({
            "subjectDid": SUBJECT_DID,
            "typeUri": dtg_credentials::VETTED_V1,
            "claim": community_check_claim(community)
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{v}");
    let credential = &v["credential"];
    assert_eq!(
        credential["type"],
        json!([
            "VerifiableCredential",
            "DTGCredential",
            "StatementCredential"
        ])
    );
    assert_eq!(credential["issuer"], community);
    assert_eq!(credential["issuerScope"], "public");
    assert_eq!(credential["credentialSubject"]["id"], SUBJECT_DID);
    assert_eq!(
        credential["credentialSubject"]["predicate"],
        dtg_credentials::VETTED_V1
    );
    assert_eq!(
        credential["credentialSubject"]["object"]["value"],
        community_check_claim(community)
    );
    assert!(credential["credentialStatus"].is_object());

    // The citation names the request the community recorded the check in.
    assert_eq!(credential["taskContext"], request["id"]);
    assert_eq!(
        credential["taskDigestMultibase"],
        dtg_credentials::task_digest_multibase_json(&request).unwrap()
    );
    // And it parses as the catalog's own vetted/1 statement, citing that
    // request.
    let parsed: dtg_credentials::DTGCredential =
        serde_json::from_value(credential.clone()).unwrap();
    assert!(parsed.cites_task(&request).unwrap());

    // The signed statement is kept on the row, so it can be delivered to its
    // subject again. Delivery itself is best effort: this subject's DID does
    // not resolve, its delivery failed, and the issue still succeeded.
    let id = v["endorsement"]["endorsementId"].as_str().unwrap();
    let row = vtc_service::endorsements::get_endorsement(
        &fix.endorsements_ks,
        Uuid::parse_str(id).unwrap(),
    )
    .await
    .unwrap()
    .expect("the row");
    assert_eq!(row.credential.as_ref(), Some(credential));

    // Revocable like any other row.
    let (status, body) = signed_task(
        &fix,
        &fix.admin,
        REVOKE_TASK,
        json!({ "endorsementId": id }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

/// The community records only its own checks, and carries none of the
/// vetter-only members: a claim naming another community, carrying any of
/// `identityCommitment`, `cardDigestMultibase` or `declaredRelationship`, or
/// not a `vetted/1` object value at all, is the declared
/// `claimSchemaViolation`, and nothing is minted.
#[tokio::test]
async fn a_vetted_claim_the_community_cannot_make_is_the_declared_claim_schema_violation() {
    let fix = build().await;
    let ours = || community_check_claim(vtc_service::test_support::TEST_VTC_DID);
    let with = |member: &str, value: Value| {
        let mut claim = ours();
        claim[member] = value;
        claim
    };
    let mut all_three = ours();
    all_three["identityCommitment"] = json!("zCommitment");
    all_three["cardDigestMultibase"] = json!("zCard");
    all_three["declaredRelationship"] = json!("none");
    for claim in [
        community_check_claim("did:webvh:other-community.example"),
        with("pseudonym", json!("p-1")),
        with("identityCommitment", json!("zCommitment")),
        with("cardDigestMultibase", json!("zCard")),
        with("declaredRelationship", json!("none")),
        all_three,
        json!({ "method": "inPerson" }),
    ] {
        let (status, body) = issue(&fix, dtg_credentials::VETTED_V1, claim.clone()).await;
        assert!(status.is_client_error(), "{claim}: {body}");
        assert_eq!(
            rest_error_code(&body),
            ISSUE_ERR_CLAIM_SCHEMA_VIOLATION,
            "{claim}: {body}"
        );
    }
    assert!(
        fix.endorsements_ks
            .prefix_iter_raw(Vec::new())
            .await
            .unwrap()
            .is_empty(),
        "a refused claim mints nothing"
    );
}

/// Issue the community's own check about `subject`, carrying `ext`.
async fn issue_check_with_ext(fix: &Fixture, subject: &str, ext: Value) -> (StatusCode, Value) {
    signed_task(
        fix,
        &fix.issuer,
        ISSUE_TASK,
        json!({
            "subjectDid": subject,
            "typeUri": dtg_credentials::VETTED_V1,
            "claim": community_check_claim(vtc_service::test_support::TEST_VTC_DID),
            "ext": ext
        }),
    )
    .await
}

fn uniqueness(pseudonym: &str) -> Value {
    json!({ "org.openvtc.uniqueness": { "pseudonym": pseudonym } })
}

/// `ext.org.openvtc.uniqueness` binds the person's pseudonym to the subject
/// server-side at issue — never in the credential. The same pseudonym for a
/// second member is refused (`taskFailed`, reason `conflict`) with nothing
/// minted, and revoking the statement releases the binding.
#[tokio::test]
async fn a_uniqueness_pseudonym_is_bound_at_issue_and_released_on_revoke() {
    use vtc_service::members::pseudonym;
    let fix = build().await;
    let members = fix._vtc.state.members_ks.clone();

    let (status, v) = issue_check_with_ext(&fix, SUBJECT_DID, uniqueness("person-1")).await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert!(
        !v["credential"].to_string().contains("person-1"),
        "the pseudonym is never written into the credential: {v}"
    );
    assert!(pseudonym::is_bound(&members, SUBJECT_DID).await.unwrap());
    let held = pseudonym::holder(
        &members,
        vtc_service::test_support::TEST_VTC_DID,
        "person-1",
    )
    .await
    .unwrap()
    .expect("bound");
    assert_eq!(held.member_did, SUBJECT_DID);

    // The same person under another member DID.
    let rows_before = fix
        .endorsements_ks
        .prefix_iter_raw(Vec::new())
        .await
        .unwrap()
        .len();
    let (status, body) = issue_check_with_ext(&fix, MEMBER_DID, uniqueness("person-1")).await;
    assert!(!status.is_success(), "{body}");
    assert_eq!(body["details"]["reason"], "conflict", "{body}");
    assert!(!pseudonym::is_bound(&members, MEMBER_DID).await.unwrap());
    assert_eq!(
        fix.endorsements_ks
            .prefix_iter_raw(Vec::new())
            .await
            .unwrap()
            .len(),
        rows_before,
        "a refused binding mints nothing"
    );

    // Revoking the community's check releases the binding.
    let id = v["endorsement"]["endorsementId"].as_str().unwrap();
    let (status, body) = signed_task(
        &fix,
        &fix.admin,
        REVOKE_TASK,
        json!({ "endorsementId": id }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(!pseudonym::is_bound(&members, SUBJECT_DID).await.unwrap());
}

/// The extension is read only under `vetted/1`, and only in its one shape.
#[tokio::test]
async fn a_misplaced_or_malformed_uniqueness_extension_is_refused() {
    let fix = build().await;
    let uri = "https://example.com/v1/skills/rust";
    register_type(&fix, uri).await;
    let (status, body) = signed_task(
        &fix,
        &fix.issuer,
        ISSUE_TASK,
        json!({
            "subjectDid": SUBJECT_DID,
            "typeUri": uri,
            "claim": { "level": "expert" },
            "ext": uniqueness("person-1")
        }),
    )
    .await;
    assert!(status.is_client_error(), "{body}");
    for ext in [
        json!({ "org.openvtc.uniqueness": { "pseudonym": "" } }),
        json!({ "org.openvtc.uniqueness": { "pseudonym": 7 } }),
        json!({ "org.openvtc.uniqueness": { "pseudonym": "p", "extra": 1 } }),
        json!({ "org.openvtc.uniqueness": "p" }),
    ] {
        let (status, body) = issue_check_with_ext(&fix, SUBJECT_DID, ext.clone()).await;
        assert!(status.is_client_error(), "{ext}: {body}");
    }
    assert!(
        !vtc_service::members::pseudonym::is_bound(&fix._vtc.state.members_ks, SUBJECT_DID)
            .await
            .unwrap()
    );
}

/// The retired `IdentityVerificationCredential` type is neither reserved nor
/// issuable any more: it is not a predicate IRI, so registration refuses it as
/// such, and issuance finds no predicate by that name.
#[tokio::test]
async fn the_retired_identity_verification_type_is_not_issuable() {
    let fix = build().await;
    let (status, body) = issue(
        &fix,
        "IdentityVerificationCredential",
        json!({ "method": "inPerson" }),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert_eq!(
        rest_error_code(&body),
        ISSUE_ERR_TYPE_NOT_REGISTERED,
        "{body}"
    );
    let (status, body) =
        register(&fix, json!({ "typeUri": "IdentityVerificationCredential" })).await;
    assert!(status.is_client_error(), "{body}");
    assert_eq!(rest_error_code(&body), REGISTER_ERR_INVALID_URI, "{body}");
}

/// A claim over 8 KiB is `claimTooLarge` (400, unchanged).
#[tokio::test]
async fn a_claim_over_the_cap_is_the_declared_claim_too_large() {
    let fix = build().await;
    let uri = "https://example.com/v1/skills/large";
    register_type(&fix, uri).await;
    let (status, body) = issue(&fix, uri, json!({ "blob": "x".repeat(8 * 1024) })).await;
    // `claimTooLarge` is a declared code, so it rides the framework's flat
    // 422 bucket for extended codes over the signed door (not the REST
    // route's old 400).
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert_eq!(rest_error_code(&body), ISSUE_ERR_CLAIM_TOO_LARGE, "{body}");
}

/// A type that declares a `claimSchema` binds its claims: one that fails it is
/// `claimSchemaViolation` (400) and issues nothing; one that satisfies it
/// issues. Before #1600 the schema was stored at registration and never read.
#[tokio::test]
async fn a_claim_failing_the_type_claim_schema_is_the_declared_violation() {
    let fix = build().await;
    let uri = "https://example.com/v1/skills/level";
    let (status, body) = register(
        &fix,
        json!({
            "typeUri": uri,
            "claimSchema": {
                "type": "object",
                "required": ["level"],
                "properties": { "level": { "enum": ["novice", "expert"] } }
            }
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    for bad in [json!({ "level": "wizard" }), json!({ "other": 1 })] {
        let (status, body) = issue(&fix, uri, bad.clone()).await;
        // `claimSchemaViolation` is a declared code, so it rides the flat 422
        // bucket for extended codes over the signed door (not the REST
        // route's old 400).
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{bad}: {body}");
        assert_eq!(
            rest_error_code(&body),
            ISSUE_ERR_CLAIM_SCHEMA_VIOLATION,
            "{bad}: {body}"
        );
    }
    assert!(
        fix.endorsements_ks
            .prefix_iter_raw(Vec::new())
            .await
            .unwrap()
            .is_empty(),
        "a refused claim must not persist an endorsement"
    );

    let (status, body) = issue(&fix, uri, json!({ "level": "expert" })).await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

/// A `claimSchema` that is not itself valid JSON Schema is refused at
/// registration, naming the part of the document that is wrong.
///
/// `vtc/endorsement-types/register/0.1` declares no code for this —
/// `invalidUri`, `reserved` and `exists` are its three, and none is about the
/// schema — so the refusal carries the framework's `malformedRequest` (SPEC
/// §8.3). Before this, the document was stored unread; #1649 made
/// `vtc/endorsements/issue/0.1` enforce it, which turned a malformed one into
/// an opaque 500 on every issuance of the type.
#[tokio::test]
async fn a_claim_schema_that_is_not_a_json_schema_is_refused_at_registration() {
    let fix = build().await;
    let malformed = trust_tasks_rs::StandardCode::MalformedRequest.as_str();

    for (n, (schema, names)) in [
        (json!({ "type": "not-a-type" }), "/type"),
        (
            json!({ "type": "object", "properties": { "level": { "type": "intiger" } } }),
            "/properties/level/type",
        ),
        (json!({ "required": "level" }), "/required"),
        // Not an object at all: the payload schema refuses it first.
        (json!(true), "true is not of type"),
    ]
    .into_iter()
    .enumerate()
    {
        let uri = format!("https://example.com/v1/skills/bad-{n}");
        let (status, body) = register(&fix, json!({ "typeUri": uri, "claimSchema": schema })).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{schema}: {body}");
        assert_eq!(rest_error_code(&body), malformed, "{schema}: {body}");
        let message = body["message"].as_str().unwrap_or_default();
        assert!(
            (message.contains("claimSchema is not a valid JSON Schema")
                || message.contains("payload failed schema validation"))
                && message.contains(names),
            "the refusal must name the bad part — {schema}: {body}"
        );
        // Nothing was stored, so the type is still free to register properly.
        assert!(
            get_type(&fix._vtc.state.endorsement_types_ks, &uri)
                .await
                .unwrap()
                .is_none(),
            "a refused registration must not store the type"
        );
    }

    // The same URI registers once the schema is a schema, and a type with no
    // `claimSchema` at all is untouched by the check.
    let (status, body) = register(
        &fix,
        json!({
            "typeUri": "https://example.com/v1/skills/bad-0",
            "claimSchema": { "type": "object", "properties": { "level": { "type": "integer" } } }
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = register(&fix, json!({ "typeUri": "https://example.com/v1/plain" })).await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

/// A type whose **stored** `claimSchema` will not compile answers issuance with
/// a 5xx that names the type and says the type is at fault — not a bare 500,
/// and not `claimSchemaViolation`, which means the caller's claim failed a
/// valid schema and would send the operator to fix the wrong thing.
///
/// Registration refuses such a schema now, so the row is written straight into
/// the keyspace: the fixed path cannot produce one.
#[tokio::test]
async fn a_type_with_a_corrupt_stored_claim_schema_names_the_type_not_the_claim() {
    let fix = build().await;
    let uri = "https://example.com/v1/skills/corrupt";
    store_type(
        &fix._vtc.state.endorsement_types_ks,
        &EndorsementType {
            type_uri: uri.into(),
            claim_schema: Some(json!({ "type": "intiger" })),
            description: None,
            created_at: Utc::now(),
            created_by_did: ADMIN_DID.into(),
        },
    )
    .await
    .unwrap();

    let (status, body) = issue(&fix, uri, json!({ "level": "expert" })).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{body}");
    assert_eq!(
        rest_error_code(&body),
        "internalError",
        "a broken type is not one of issue/0.1's declared claim faults: {body}"
    );
    // The framework's `internalError` never repeats the cause to the caller —
    // "no message may reveal consumer-internal state"
    // (`trust_tasks::helpers::app_error_to_reject`) — so the detail naming the
    // type and telling an operator to re-register it goes to the service log,
    // not this reply, unlike the old REST route's raw `AppError::Internal`
    // body.
    let message = body["message"].as_str().unwrap_or_default();
    assert!(
        !message.contains(uri) && !message.contains("invalid stored claimSchema"),
        "an internalError reply must not leak the cause: {body}"
    );
    assert!(
        fix.endorsements_ks
            .prefix_iter_raw(Vec::new())
            .await
            .unwrap()
            .is_empty(),
        "nothing is issued against a type whose schema cannot be read"
    );

    // Re-registering the type with a schema that compiles is the documented
    // fix, and issuance works again afterwards.
    let (status, body) = delete_type(&fix, uri).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = register(
        &fix,
        json!({ "typeUri": uri, "claimSchema": { "type": "object" } }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = issue(&fix, uri, json!({ "level": "expert" })).await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

/// With every revocation slot handed out, issuing is `statusListExhausted` —
/// a declared code, so it rides the framework's flat 422 bucket for extended
/// codes over the signed door (not the REST route's old 500).
#[tokio::test]
async fn a_full_revocation_list_is_the_declared_status_list_exhausted() {
    let fix = build().await;
    let uri = "https://example.com/v1/skills/full";
    register_type(&fix, uri).await;
    status_list::with_locked(
        &fix._vtc.state.status_lists_ks,
        StatusPurpose::Revocation,
        |row| {
            row.assigned.iter_mut().for_each(|a| *a = true);
            Ok(())
        },
    )
    .await
    .unwrap();

    let (status, body) = issue(&fix, uri, json!({ "x": 1 })).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert_eq!(
        rest_error_code(&body),
        ISSUE_ERR_STATUS_LIST_EXHAUSTED,
        "{body}"
    );
}

/// A cursor this community did not sign is `invalidCursor` — a declared code,
/// so it rides the signed door's flat 422 bucket (not the REST route's old
/// 400).
#[tokio::test]
async fn a_forged_cursor_is_the_declared_invalid_cursor() {
    let fix = build().await;
    let (status, body) = signed_task(
        &fix,
        &fix.admin,
        LIST_TASK,
        json!({ "cursor": "bm90LWEtY3Vyc29y" }),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert_eq!(rest_error_code(&body), LIST_ERR_INVALID_CURSOR, "{body}");
}

/// An unknown endorsement id is `notFound` to show and to revoke — a
/// declared code (422, not the REST route's old 404). Revoke now checks the
/// caller's capability first, so a member who may not revoke gets
/// `permissionDenied` (403) whether or not the id exists.
#[tokio::test]
async fn an_unknown_endorsement_is_the_declared_not_found() {
    let fix = build().await;
    let id = Uuid::new_v4().to_string();

    let (status, body) =
        signed_task(&fix, &fix.admin, SHOW_TASK, json!({ "endorsementId": id })).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert_eq!(rest_error_code(&body), SHOW_ERR_NOT_FOUND, "{body}");

    let (status, body) = signed_task(
        &fix,
        &fix.admin,
        REVOKE_TASK,
        json!({ "endorsementId": id }),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert_eq!(rest_error_code(&body), REVOKE_ERR_NOT_FOUND, "{body}");

    let (status, body) = signed_task(
        &fix,
        &fix.member,
        REVOKE_TASK,
        json!({ "endorsementId": id }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "the capability check precedes the lookup: {body}"
    );
}

/// The bearer route enforces the bounds the signed door does, so the two doors
/// agree about what registers (#1641 batch 4).
///
/// `description` is the task's published `maxLength: 1024`, which the signed
/// door's schema check already held and this route did not. `claimSchema` is
/// capped at 32 KiB serialised — the task publishes no bound, but a schema
/// that registered here and could not fit a 64 KiB signed document would be
/// the two doors disagreeing.
#[tokio::test]
async fn registration_enforces_its_size_bounds() {
    let fix = build().await;
    let malformed = trust_tasks_rs::StandardCode::MalformedRequest.as_str();

    let (status, body) = register(
        &fix,
        json!({
            "typeUri": "https://example.com/v1/skills/long-description",
            "description": "x".repeat(1025),
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(rest_error_code(&body), malformed, "{body}");

    let (status, body) = register(
        &fix,
        json!({
            "typeUri": "https://example.com/v1/skills/huge-schema",
            "claimSchema": {
                "type": "object",
                // `CLAIM_SCHEMA_MAX_BYTES` (32 KiB); the padding alone reaches it.
                "description": "x".repeat(32 * 1024),
            },
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(rest_error_code(&body), malformed, "{body}");

    // At the bound itself, both register.
    let (status, body) = register(
        &fix,
        json!({
            "typeUri": "https://example.com/v1/skills/max-description",
            "description": "x".repeat(1024),
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
}
