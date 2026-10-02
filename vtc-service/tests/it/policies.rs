//! Integration coverage for the `policy/*` Trust Tasks (Phase 2 M2.3).
//!
//! Acceptance bullets from `phase-2-todo.md` M2.3.1:
//! - Happy upload + bad-Rego rejection.
//! - Activate-after-upload swaps the active pointer.
//! - Test-without-activate doesn't mutate state.
//!
//! Plus auxiliary coverage: re-activate-same-id conflict, activate
//! unknown id not-found, and audit envelope emission on the two
//! state-changing endpoints.
//!
//! The admin bearer routes these tests used to drive are gone (#1834): every
//! verb here is a signed document, sent with [`crate::common::signed::call`] and
//! read back through [`reply`], which recovers the REST status the retired
//! route answered with — success from the verb's own contract, and a
//! refusal from the error code the signed door still carries.

use serde_json::{Value, json};
use uuid::Uuid;
use vti_common::store::KeyspaceHandle;

use axum::http::StatusCode;
use vtc_service::policy::{PolicyPurpose, get_active_policy_id, get_policy};
use vtc_service::test_support::TestVtc;

const UPLOAD_TASK: &str = "https://trusttasks.org/spec/policy/upsert/0.2";
const ACTIVATE_TASK: &str = "https://trusttasks.org/spec/policy/activate/0.1";
const LIST_TASK: &str = "https://trusttasks.org/spec/policy/list/0.2";
const SHOW_TASK: &str = "https://trusttasks.org/spec/policy/get/0.1";
/// Replaces the old REST simulator's `?purpose=X&status=active` lookup: the
/// per-purpose active binding, read directly off the active pointers rather
/// than filtered out of a paginated listing.
const ACTIVE_TASK: &str = "https://trusttasks.org/spec/policy/active/0.1";

// Test fixtures must live in the package their declared purpose expects
// (P1.5: a join policy in `vtc.test` is now rejected at upload as a
// silent-deny footgun). These exercise generic upload/activate/list
// mechanics, so they just need a valid `allow` rule in the right package.
const JOIN_ALLOW_POLICY: &str = "\
package vtc.join

import rego.v1

default allow := false

allow if input.role == \"admin\"
";

const JOIN_ALT_POLICY: &str = "\
package vtc.join

import rego.v1

default allow := true
";

const REMOVAL_POLICY: &str = "\
package vtc.removal

import rego.v1

default allow := true
";

struct Fixture {
    /// The key every document here is signed by: an unrestricted
    /// administrator (`policy/*` reads its authority from the signer's own
    /// ACL row now, not a bearer session).
    signer: crate::common::second_party::GatedAdmin,
    policies_ks: KeyspaceHandle,
    active_policies_ks: KeyspaceHandle,
    audit_ks: KeyspaceHandle,
    // Owns the temp data dir + serves the router; must outlive them.
    _vtc: TestVtc,
}

async fn build_fixture() -> Fixture {
    // A public URL and signers, because writing a `join` or `removal` policy
    // takes the signer's passkey gesture and a second administrator's consent
    // (VTI-VTC-022) — which `GatedAdmin` supplies.
    let vtc = TestVtc::builder()
        .with_audit(true)
        .with_signers(true)
        .with_public_url("https://vtc.example.com")
        .build()
        .await;
    let signer = crate::common::second_party::GatedAdmin::new(&vtc).await;

    let policies_ks = vtc.state.policies_ks.clone();
    let active_policies_ks = vtc.state.active_policies_ks.clone();
    let audit_ks = vtc.state.audit_ks.clone();

    Fixture {
        signer,
        policies_ks,
        active_policies_ks,
        audit_ks,
        _vtc: vtc,
    }
}

/// The status the retired REST route would have answered with: `success` on
/// the happy path, or the status its equivalent error used to carry, read off
/// the signed door's error `code` (there is no REST status to read anymore).
fn status_for_code(code: &str) -> StatusCode {
    if code.ends_with(":notFound") {
        StatusCode::NOT_FOUND
    } else if code.ends_with(":versionConflict") || code.ends_with(":alreadyActive") {
        StatusCode::CONFLICT
    } else if code == "permissionDenied" {
        StatusCode::FORBIDDEN
    } else if code == "malformedRequest" || code.contains(':') {
        StatusCode::BAD_REQUEST
    } else {
        StatusCode::UNPROCESSABLE_ENTITY
    }
}

/// A signed document's reply, as the retired REST route would have answered
/// it: `success` on a `#response`, or the mapped status + a REST-shaped
/// `{"error": ...}` body on a `trust-task-error`.
fn reply(doc: &Value, success: StatusCode) -> (StatusCode, Value) {
    match crate::common::signed::error_code(doc) {
        Some(code) => {
            let payload = &doc["payload"];
            (
                status_for_code(code),
                json!({ "error": payload["message"] }),
            )
        }
        None => (success, doc["payload"].clone()),
    }
}

async fn upsert(fix: &Fixture, body: Value) -> (StatusCode, Value) {
    let (_, doc) = fix.signer.call(&fix._vtc, UPLOAD_TASK, body).await;
    let success = if doc["payload"]["created"] == false {
        StatusCode::OK
    } else {
        StatusCode::CREATED
    };
    reply(&doc, success)
}

async fn show(fix: &Fixture, id: &str) -> (StatusCode, Value) {
    let (_, doc) = crate::common::signed::call(
        &fix._vtc,
        &fix.signer.requester,
        SHOW_TASK,
        json!({ "id": id }),
    )
    .await;
    reply(&doc, StatusCode::OK)
}

/// Activate `id`. `purpose` mirrors what a caller supplies; `None` reads it
/// off the stored revision first, exactly as the retired route did.
async fn activate(fix: &Fixture, id: &str, purpose: Option<&str>) -> (StatusCode, Value) {
    let mut payload = json!({ "id": id });
    match purpose {
        Some(p) => payload["purpose"] = json!(p),
        None => {
            let (_, got) = show(fix, id).await;
            if let Some(p) = got["policy"]["ext"]["org.openvtc.purpose"].as_str() {
                payload["purpose"] = json!(p);
            }
        }
    }
    let (_, doc) = fix.signer.call(&fix._vtc, ACTIVATE_TASK, payload).await;
    reply(&doc, StatusCode::OK)
}

/// List policies, optionally narrowed by purpose (`ext.org.openvtc.purpose`
/// — canonical `policy/list/0.2` has no purpose field of its own).
async fn list(fix: &Fixture, purpose: Option<&str>) -> (StatusCode, Value) {
    let mut payload = json!({});
    if let Some(p) = purpose {
        payload["ext"] = json!({ "org.openvtc.purpose": p });
    }
    let (_, doc) =
        crate::common::signed::call(&fix._vtc, &fix.signer.requester, LIST_TASK, payload).await;
    reply(&doc, StatusCode::OK)
}

/// `policy/active/0.1`: the per-purpose active bindings, optionally narrowed
/// to one purpose.
async fn active(fix: &Fixture, purpose: Option<&str>) -> (StatusCode, Value) {
    let mut payload = json!({});
    if let Some(p) = purpose {
        payload["purpose"] = json!(p);
    }
    let (_, doc) =
        crate::common::signed::call(&fix._vtc, &fix.signer.requester, ACTIVE_TASK, payload).await;
    reply(&doc, StatusCode::OK)
}

async fn upload_policy(fix: &Fixture, purpose: &str, source: &str) -> Value {
    let (status, body) = upsert(
        fix,
        json!({ "name": purpose, "module": source, "ext": { "org.openvtc.purpose": purpose } }),
    )
    .await;
    // Canonical upsert: 201 on a new lineage, 200 on a revision.
    assert!(
        status == StatusCode::CREATED || status == StatusCode::OK,
        "expected 201/200 from upsert, got {status}",
    );
    body["policy"].clone()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Acceptance bullet 1a: happy upload. The 201 response carries
/// id/sha256/purpose/version and the policy row is persisted to
/// fjall.
#[tokio::test]
async fn upload_happy_path_persists_policy() {
    let fix = build_fixture().await;
    let body = upload_policy(&fix, "join", JOIN_ALLOW_POLICY).await;
    let id: Uuid = body["id"].as_str().unwrap().parse().unwrap();

    assert_eq!(body["ext"]["org.openvtc.purpose"], "join");
    assert_eq!(body["version"], 1);
    let sha = body["ext"]["org.openvtc.sha256"].as_str().unwrap();
    assert_eq!(sha.len(), 64);
    assert!(
        sha.chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    );

    // Row persisted with same id + matching SHA.
    let stored = get_policy(&fix.policies_ks, id).await.unwrap().unwrap();
    assert_eq!(stored.id, id);
    assert_eq!(stored.purpose, PolicyPurpose::Join);
    assert_eq!(hex::encode(stored.sha256), sha);
    assert_eq!(stored.version, 1);
    assert!(
        stored.activated_at.is_none(),
        "upload must not activate the row"
    );

    // No active pointer was flipped.
    assert!(
        get_active_policy_id(&fix.active_policies_ks, PolicyPurpose::Join)
            .await
            .unwrap()
            .is_none(),
        "upload must not mutate the active pointer"
    );
}

/// Acceptance bullet 1b: bad-Rego rejection. A malformed source
/// surfaces as a refusal, and the id from the error message is
/// meaningful for the operator.
#[tokio::test]
async fn upload_bad_rego_returns_400() {
    let fix = build_fixture().await;
    let (status, body) = upsert(
        &fix,
        json!({ "name": "join", "module": "@@@ not rego @@@", "ext": { "org.openvtc.purpose": "join" } }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let msg = body["error"].as_str().unwrap_or_default();
    assert!(
        msg.contains("rego compile failed"),
        "error body should explain the compile failure: {body}"
    );
}

/// P1.5: a policy whose Rego package doesn't match its declared
/// purpose is rejected at upload — it would compile + activate cleanly
/// then evaluate to `undefined` (silent host default-deny) for the
/// whole ceremony.
#[tokio::test]
async fn upload_rejects_purpose_package_mismatch() {
    let fix = build_fixture().await;
    // purpose=join, but the module lives in vtc.removal.
    let mismatched = "package vtc.removal\nimport rego.v1\ndefault allow := false\n";
    let (status, body) = upsert(
        &fix,
        json!({ "name": "join", "module": mismatched, "ext": { "org.openvtc.purpose": "join" } }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let msg = body["error"].as_str().unwrap_or_default();
    assert!(
        msg.contains("vtc.join"),
        "error must name the expected package: {body}"
    );
}

/// Acceptance bullet 2: activate-after-upload swaps the active
/// pointer and stamps `activated_at` on the row.
#[tokio::test]
async fn activate_swaps_active_pointer() {
    let fix = build_fixture().await;
    let uploaded = upload_policy(&fix, "join", JOIN_ALLOW_POLICY).await;
    let id: Uuid = uploaded["id"].as_str().unwrap().parse().unwrap();

    let (status, body) = activate(&fix, &id.to_string(), None).await;
    assert_eq!(status, StatusCode::OK);

    assert_eq!(body["activated"], id.to_string());
    assert_eq!(body["purpose"], "join");
    assert!(
        body["previousPolicyId"].is_null(),
        "first activation must have null predecessor: {body}"
    );

    // Active pointer + activated_at populated.
    assert_eq!(
        get_active_policy_id(&fix.active_policies_ks, PolicyPurpose::Join)
            .await
            .unwrap(),
        Some(id)
    );
    let stored = get_policy(&fix.policies_ks, id).await.unwrap().unwrap();
    assert!(
        stored.activated_at.is_some(),
        "activate must stamp activated_at"
    );
}

/// Second activation of the same id for the same purpose is refused
/// (`policy/activate:alreadyActive`). Re-activating a *different* id
/// later swaps cleanly (covered in `activate_replaces_predecessor`).
#[tokio::test]
async fn activate_same_id_twice_returns_409() {
    let fix = build_fixture().await;
    let uploaded = upload_policy(&fix, "join", JOIN_ALLOW_POLICY).await;
    let id = uploaded["id"].as_str().unwrap().to_string();

    for expected in [StatusCode::OK, StatusCode::CONFLICT] {
        let (status, body) = activate(&fix, &id, None).await;
        assert_eq!(status, expected, "{body}");
    }
}

/// Activating a different revision after a prior one records the
/// predecessor on the response + audit envelope.
#[tokio::test]
async fn activate_replaces_predecessor() {
    let fix = build_fixture().await;
    let first = upload_policy(&fix, "join", JOIN_ALLOW_POLICY).await;
    let first_id = first["id"].as_str().unwrap().to_string();
    let second = upload_policy(&fix, "join", JOIN_ALT_POLICY).await;
    let second_id = second["id"].as_str().unwrap().to_string();
    assert_eq!(second["version"], 2, "second upload bumps version");

    // Activate first, then second.
    for id in [&first_id, &second_id] {
        let (status, _) = activate(&fix, id, None).await;
        assert_eq!(status, StatusCode::OK, "activating {id}");
    }

    // Active pointer is now second; predecessor returned by the
    // activate-second response is first.
    assert_eq!(
        get_active_policy_id(&fix.active_policies_ks, PolicyPurpose::Join)
            .await
            .unwrap(),
        Some(second_id.parse().unwrap())
    );
}

/// Activating an unknown id is refused with `policy/activate:notFound`.
#[tokio::test]
async fn activate_unknown_id_returns_404() {
    let fix = build_fixture().await;
    let ghost = Uuid::new_v4();
    // No stored revision to read a purpose off, so name one explicitly —
    // the not-found refusal is about the id, not the purpose.
    let (status, _) = activate(&fix, &ghost.to_string(), Some("join")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// Upload + activate each emit one audit envelope of their own. A `join`
/// policy decides authority, so the gesture and consent it takes are audited
/// beside them (VTI-VTC-022); those rows are the gate's, not the verb's, and
/// are not counted here.
#[tokio::test]
async fn upload_and_activate_emit_audit_envelopes() {
    let fix = build_fixture().await;
    let count = |variant: &'static str| {
        let ks = fix.audit_ks.clone();
        async move {
            ks.prefix_iter_raw(Vec::new())
                .await
                .unwrap()
                .into_iter()
                .filter_map(|(_, v)| {
                    serde_json::from_slice::<vti_common::audit::AuditEnvelope>(&v).ok()
                })
                .filter(|env| env.event.variant_name() == variant)
                .count()
        }
    };

    let uploaded = upload_policy(&fix, "join", JOIN_ALLOW_POLICY).await;
    let id = uploaded["id"].as_str().unwrap().to_string();
    assert_eq!(
        count("PolicyUploaded").await,
        1,
        "upload must emit exactly one audit envelope"
    );

    let (status, _) = activate(&fix, &id, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        count("PolicyActivated").await,
        1,
        "activate must emit exactly one audit envelope"
    );
}

// ---------------------------------------------------------------------------
// Read endpoints (M2.4)
// ---------------------------------------------------------------------------

/// Every uploaded policy comes back. Each item carries the full row.
#[tokio::test]
async fn list_returns_all_policies() {
    let fix = build_fixture().await;
    let a = upload_policy(&fix, "join", JOIN_ALLOW_POLICY).await;
    let _b = upload_policy(&fix, "removal", REMOVAL_POLICY).await;
    let a_id = a["id"].as_str().unwrap().to_string();

    // Activate one of them — exercised for its own sake below via
    // `list_filters_by_status`; here it's just part of a realistic fixture.
    let (status, _) = activate(&fix, &a_id, None).await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = list(&fix, None).await;
    assert_eq!(status, StatusCode::OK);

    let items = body["policies"].as_array().expect("items array");
    assert_eq!(items.len(), 2);
    assert!(items.iter().any(|i| i["id"] == a_id));
    // Full row visibility — Rego source is in the response.
    assert!(items.iter().all(|i| i["module"].is_string()));
}

/// A purpose filter (`ext.org.openvtc.purpose`) narrows the listing to that
/// purpose only.
#[tokio::test]
async fn list_filters_by_purpose() {
    let fix = build_fixture().await;
    upload_policy(&fix, "join", JOIN_ALLOW_POLICY).await;
    upload_policy(&fix, "removal", REMOVAL_POLICY).await;

    let (status, body) = list(&fix, Some("removal")).await;
    assert_eq!(status, StatusCode::OK);
    let items = body["policies"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["ext"]["org.openvtc.purpose"], "removal");
}

/// The active/archived distinction, read the way a canonical caller reads it
/// now: `policy/active/0.1` for "what is active for this purpose", and a
/// purpose-scoped listing for everything else that purpose has on file. The
/// retired route's own `status=active`/`status=archived` filters had no
/// canonical equivalent (`policy/list/0.2` carries no `status` field) and are
/// gone with it.
#[tokio::test]
async fn list_filters_by_status() {
    let fix = build_fixture().await;
    let join = upload_policy(&fix, "join", JOIN_ALLOW_POLICY).await;
    let removal = upload_policy(&fix, "removal", REMOVAL_POLICY).await;
    let join_id = join["id"].as_str().unwrap().to_string();
    let removal_id = removal["id"].as_str().unwrap().to_string();

    // Activate only the join row.
    let (status, _) = activate(&fix, &join_id, None).await;
    assert_eq!(status, StatusCode::OK);

    // "active" → policy/active/0.1 names just the join binding.
    let (status, active_body) = active(&fix, Some("join")).await;
    assert_eq!(status, StatusCode::OK);
    let bindings = active_body["bindings"].as_array().unwrap();
    assert_eq!(bindings.len(), 1);
    assert_eq!(bindings[0]["policy"]["id"], join_id);

    // "archived" → the removal purpose's own listing, none of which is
    // active (nothing under `removal` was ever activated here).
    let (status, removal_list) = list(&fix, Some("removal")).await;
    assert_eq!(status, StatusCode::OK);
    let items = removal_list["policies"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["id"], removal_id);
}

/// `policy/active/0.1` names each purpose's own binding exactly, whichever
/// purpose is asked for — the direct replacement for the old REST
/// simulator's `?purpose=X&status=active&limit=1` lookup. That lookup's
/// pagination bug (a small `limit` could drop a purpose's active row
/// entirely) has no analogue here: this task reads the per-purpose active
/// pointers directly rather than filtering a paginated scan.
#[tokio::test]
async fn active_binding_is_exact_per_purpose() {
    let fix = build_fixture().await;
    let join = upload_policy(&fix, "join", JOIN_ALLOW_POLICY).await;
    let removal = upload_policy(&fix, "removal", REMOVAL_POLICY).await;
    let join_id = join["id"].as_str().unwrap().to_string();
    let removal_id = removal["id"].as_str().unwrap().to_string();

    for id in [&join_id, &removal_id] {
        let (status, _) = activate(&fix, id, None).await;
        assert_eq!(status, StatusCode::OK);
    }

    for (purpose, id) in [("join", &join_id), ("removal", &removal_id)] {
        let (status, body) = active(&fix, Some(purpose)).await;
        assert_eq!(status, StatusCode::OK);
        let bindings = body["bindings"].as_array().unwrap();
        assert_eq!(bindings.len(), 1, "{purpose}: exactly one binding");
        assert_eq!(bindings[0]["policy"]["id"], *id, "{purpose}: active id");
    }
}

/// `policy/get/0.1` returns the full row.
#[tokio::test]
async fn show_returns_full_row() {
    let fix = build_fixture().await;
    let uploaded = upload_policy(&fix, "join", JOIN_ALLOW_POLICY).await;
    let id = uploaded["id"].as_str().unwrap();

    let (status, outer) = show(&fix, id).await;
    assert_eq!(status, StatusCode::OK);

    let body = &outer["policy"];
    assert_eq!(body["id"], id);
    assert_eq!(body["ext"]["org.openvtc.purpose"], "join");
    assert_eq!(body["version"], 1);
    assert!(body["module"].as_str().unwrap().contains("default allow"));
}

/// `policy/get/0.1` is refused for unknown ids (`policy/get:notFound`).
#[tokio::test]
async fn show_unknown_id_returns_404() {
    let fix = build_fixture().await;
    let ghost = Uuid::new_v4();
    let (status, _) = show(&fix, &ghost.to_string()).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}
