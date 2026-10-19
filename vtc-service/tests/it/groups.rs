//! The community's groups (`vtc/groups/{create,update,delete,list,show}/0.1`),
//! driven through the signed-document door as an administrator's and a
//! member's clients do.
//!
//! The community's VTA is a stand-in: it mints each group a `did:key` identity
//! and answers `keys/sign-document` with the document it was given and a proof,
//! which is all this community reads of either. Each declared error code is
//! driven here and asserted on (#1600), which is what the error-code census
//! reads.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use axum::http::StatusCode;
use chrono::Utc;
use serde_json::{Value, json};
use trust_tasks_rs::TrustTask;
use vti_rooms_dtg::test_support::Party;

use vtc_service::acl::VtcRole;
use vtc_service::config::GroupsConfig;
use vtc_service::members::{Member, store_member};
use vtc_service::rooms::vta_storage::{PeerError, VtaChannel};
use vtc_service::test_support::{TEST_VTC_DID, TestVtc};

use crate::common::signed::{call, error_code, seed_role};

use trust_tasks_rs::specs::vtc::groups as g;

const CREATE_ERR_RULE_INVALID: &str = g::create::v0_1::error_codes::RULE_INVALID.code;
const CREATE_ERR_KIND_NOT_SERVED: &str = g::create::v0_1::error_codes::KIND_NOT_SERVED.code;
const CREATE_ERR_SETTINGS_INVALID: &str = g::create::v0_1::error_codes::SETTINGS_INVALID.code;
const CREATE_ERR_POLICY_REFUSED: &str = g::create::v0_1::error_codes::POLICY_REFUSED.code;
const CREATE_ERR_NO_KEY_HOLDER: &str = g::create::v0_1::error_codes::NO_KEY_HOLDER.code;
const CREATE_ERR_KEY_HOLDER_UNAVAILABLE: &str =
    g::create::v0_1::error_codes::KEY_HOLDER_UNAVAILABLE.code;
const CREATE_ERR_KEY_HOLDER_REFUSED: &str = g::create::v0_1::error_codes::KEY_HOLDER_REFUSED.code;
const UPDATE_ERR_NOT_FOUND: &str = g::update::v0_1::error_codes::NOT_FOUND.code;
const UPDATE_ERR_RULE_INVALID: &str = g::update::v0_1::error_codes::RULE_INVALID.code;
const UPDATE_ERR_SETTINGS_INVALID: &str = g::update::v0_1::error_codes::SETTINGS_INVALID.code;
const DELETE_ERR_NOT_FOUND: &str = g::delete::v0_1::error_codes::NOT_FOUND.code;
const LIST_ERR_CURSOR_INVALID: &str = g::list::v0_1::error_codes::CURSOR_INVALID.code;
const SHOW_ERR_NOT_FOUND: &str = g::show::v0_1::error_codes::NOT_FOUND.code;

const SPEC: &str = "https://trusttasks.org/spec/vtc/groups";
const MINT: &str = "https://trusttasks.org/spec/vta/webvh/dids/create/1.1";
const SIGN_DOCUMENT: &str = "https://trusttasks.org/spec/keys/sign-document/0.1";
const UNKNOWN_GROUP: &str = "grp_UnknownUnknownUnknown";

fn task(name: &str) -> String {
    format!("{SPEC}/{name}/0.1")
}

/// A `trust-task-error` reply's code — the census reads witnesses by this name.
fn tt_error_code(doc: &Value) -> &str {
    error_code(doc).unwrap_or_default()
}

// ─── the community's VTA, standing in ───────────────────────────────────

#[derive(Clone)]
enum Script {
    Silent,
    Refuse(&'static str),
}

#[derive(Default)]
struct VtaState {
    calls: Vec<(String, Value)>,
    scripted: HashMap<String, Script>,
}

#[derive(Clone, Default)]
struct FakeVta(Arc<Mutex<VtaState>>);

impl FakeVta {
    fn script(&self, type_uri: &str, s: Script) {
        self.0
            .lock()
            .unwrap()
            .scripted
            .insert(type_uri.to_string(), s);
    }

    fn calls_of(&self, type_uri: &str) -> Vec<Value> {
        self.0
            .lock()
            .unwrap()
            .calls
            .iter()
            .filter(|(t, _)| t == type_uri)
            .map(|(_, p)| p.clone())
            .collect()
    }
}

fn reply(type_uri: &str, payload: Value) -> TrustTask<Value> {
    serde_json::from_value(json!({
        "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        "type": type_uri,
        "threadId": "urn:uuid:00000000-0000-4000-8000-000000000001",
        "issuer": "did:example:community-vta",
        "recipient": TEST_VTC_DID,
        "issuedAt": Utc::now().to_rfc3339(),
        "payload": payload,
    }))
    .unwrap()
}

#[async_trait]
impl VtaChannel for FakeVta {
    async fn exchange(
        &self,
        type_uri: &str,
        payload: &Value,
        _timeout: Duration,
    ) -> Result<TrustTask<Value>, PeerError> {
        let scripted = {
            let mut st = self.0.lock().unwrap();
            st.calls.push((type_uri.to_string(), payload.clone()));
            st.scripted.remove(type_uri)
        };
        match scripted {
            Some(Script::Silent) => {
                return Err(PeerError::Transient("no answer within the timeout".into()));
            }
            Some(Script::Refuse(code)) => {
                return Ok(reply(
                    "https://trusttasks.org/spec/trust-task-error/0.5",
                    json!({ "code": code, "message": "refused by the stand-in" }),
                ));
            }
            None => {}
        }
        let answer = match type_uri {
            MINT => {
                let did = Party::new().did;
                json!({
                    "did": did,
                    "contextId": payload["contextId"],
                    "scid": "QmScid",
                    "portable": true,
                    "signingKeyId": format!("{did}#key-1"),
                    "kaKeyId": format!("{did}#key-2"),
                    "preRotationKeyCount": 0,
                    "createdAt": Utc::now().to_rfc3339(),
                    "serverId": payload["serverId"],
                })
            }
            SIGN_DOCUMENT => {
                let mut document = payload["document"].clone();
                document["proof"] = json!({
                    "type": "DataIntegrityProof",
                    "cryptosuite": "eddsa-jcs-2022",
                    "verificationMethod": payload["keyId"],
                    "proofPurpose": "assertionMethod",
                    "created": Utc::now().to_rfc3339(),
                    "proofValue": "z3a4b5c6d7e8f9",
                });
                json!({
                    "proof": document["proof"].clone(),
                    "document": document,
                    "keyId": payload["keyId"],
                    "signerDid": payload["document"]["issuer"],
                })
            }
            other => panic!("the stand-in serves no {other}"),
        };
        Ok(reply(&format!("{type_uri}#response"), answer))
    }
}

// ─── the community ──────────────────────────────────────────────────────

struct Fixture {
    vtc: TestVtc,
    vta: FakeVta,
    admin: Party,
    member: Party,
}

fn config() -> GroupsConfig {
    GroupsConfig {
        context: Some("vtc".into()),
        webvh_server: Some("hosting".into()),
        ..Default::default()
    }
}

async fn fixture_with(groups: Option<GroupsConfig>, with_vta: bool) -> Fixture {
    let vta = FakeVta::default();
    let mut builder = TestVtc::builder()
        .vtc_did(TEST_VTC_DID)
        .with_public_url("https://vtc.example.com")
        .with_signers(true)
        .with_audit(true);
    if let Some(c) = groups {
        builder = builder.with_groups(c);
    }
    if with_vta {
        builder = builder.with_community_key_holder(Arc::new(vta.clone()));
    }
    let vtc = builder.build().await;
    // The community's revocation list, which a group's authority takes a slot in.
    vtc_service::status_list::ensure_initial(
        &vtc.state.status_lists_ks,
        affinidi_status_list::StatusPurpose::Revocation,
        "https://vtc.example.com/v1/status-lists/revocation".to_string(),
    )
    .await
    .unwrap();
    vtc_service::policy::default::install_defaults(
        &vtc.state.policies_ks,
        &vtc.state.active_policies_ks,
    )
    .await
    .unwrap();
    let admin = crate::common::signed::admin(&vtc).await;
    let member = Party::new();
    seed_role(&vtc, &member.did, VtcRole::Member, &[]).await;
    store_member(&vtc.state.members_ks, &Member::fresh(&member.did))
        .await
        .unwrap();
    Fixture {
        vtc,
        vta,
        admin,
        member,
    }
}

async fn fixture() -> Fixture {
    fixture_with(Some(config()), true).await
}

async fn activate_policy(fix: &Fixture, source: &str) {
    use sha2::{Digest, Sha256};
    use vtc_service::policy::{Policy, PolicyPurpose, set_active_policy_id, store_policy};
    let id = uuid::Uuid::new_v4();
    let now = Utc::now();
    store_policy(
        &fix.vtc.state.policies_ks,
        &Policy {
            id,
            purpose: PolicyPurpose::Groups,
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
    set_active_policy_id(&fix.vtc.state.active_policies_ks, PolicyPurpose::Groups, id)
        .await
        .unwrap();
}

fn static_group(name: &str, visibility: &str, show_members: &str) -> Value {
    json!({
        "name": name,
        "kind": "static",
        "joinPolicy": "request",
        "visibility": visibility,
        "showMembers": show_members,
        "reason": "the working group starts",
    })
}

impl Fixture {
    async fn as_admin(&self, name: &str, payload: Value) -> (StatusCode, Value) {
        call(&self.vtc, &self.admin, &task(name), payload).await
    }

    async fn as_member(&self, name: &str, payload: Value) -> (StatusCode, Value) {
        call(&self.vtc, &self.member, &task(name), payload).await
    }

    async fn create(&self, visibility: &str, show_members: &str) -> Value {
        let (status, doc) = self
            .as_admin(
                "create",
                static_group("Identity WG", visibility, show_members),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{doc}");
        doc["payload"]["group"].clone()
    }
}

#[tokio::test]
async fn an_administrator_creates_a_group_its_vta_holds_the_keys_of() {
    let fix = fixture().await;
    let group = fix.create("members", "groupMembers").await;
    assert!(group["groupId"].as_str().unwrap().starts_with("grp_"));
    assert!(group["groupDid"].as_str().unwrap().starts_with("did:"));
    assert_eq!(group["kind"], "static");
    assert_eq!(group["carriesAuthority"], false);
    // The manager sees the authority's expiry; nobody manages it by grant yet.
    assert!(
        group["credentialAuthorityValidUntil"].is_string(),
        "{group}"
    );
    assert_eq!(group["managers"], json!([]));
    assert_eq!(group["memberCount"], 0);

    // Minted from the vtc-group template, then the community's authority over
    // it signed as the community — never as the group, never locally.
    let mint = fix.vta.calls_of(MINT);
    assert_eq!(mint.len(), 1);
    assert_eq!(mint[0]["template"], "vtc-group");
    assert!(
        mint[0]["templateVars"].get("LABEL").is_none(),
        "{}",
        mint[0]
    );
    let signed = fix.vta.calls_of(SIGN_DOCUMENT);
    assert_eq!(signed.len(), 1);
    let vac = &signed[0]["document"];
    assert_eq!(vac["issuer"], TEST_VTC_DID);
    assert_eq!(vac["credentialSubject"]["id"], group["groupDid"]);
    assert!(
        vac["type"]
            .as_array()
            .unwrap()
            .contains(&json!("AuthorityCredential"))
    );
    assert!(vac["credentialStatus"].is_object(), "{vac}");
    assert!(
        signed[0]["keyId"]
            .as_str()
            .unwrap()
            .starts_with(TEST_VTC_DID)
    );
}

#[tokio::test]
async fn create_refuses_what_its_specification_declares() {
    let fix = fixture().await;

    let mut with_rule = static_group("A", "members", "members");
    with_rule["rule"] = json!({ "all": [{ "fact": "personhood", "op": "exists" }] });
    let (_, b) = fix.as_admin("create", with_rule).await;
    assert_eq!(tt_error_code(&b), CREATE_ERR_RULE_INVALID, "{b}");

    // A dynamic group reading a field a member writes.
    let reads_card = json!({
        "name": "Sydney", "kind": "dynamic", "visibility": "members", "showMembers": "members",
        "rule": { "all": [{ "fact": "field", "field": "bio", "op": "exists" }] },
        "reason": "chapter",
    });
    let (_, b) = fix.as_admin("create", reads_card).await;
    assert_eq!(tt_error_code(&b), CREATE_ERR_RULE_INVALID, "{b}");

    // A well-formed dynamic group: not served here.
    let dynamic = json!({
        "name": "Verified", "kind": "dynamic", "visibility": "members", "showMembers": "members",
        "rule": { "all": [{ "fact": "personhood", "op": "equals", "value": true }] },
        "reason": "verified people",
    });
    let (_, b) = fix.as_admin("create", dynamic).await;
    assert_eq!(tt_error_code(&b), CREATE_ERR_KIND_NOT_SERVED, "{b}");

    let (_, b) = fix
        .as_admin("create", static_group("B", "groupMembers", "members"))
        .await;
    assert_eq!(tt_error_code(&b), CREATE_ERR_SETTINGS_INVALID, "{b}");

    // The VTA does not answer: nothing stored, the DID named if one was minted.
    fix.vta.script(MINT, Script::Silent);
    let (_, b) = fix
        .as_admin("create", static_group("C", "members", "members"))
        .await;
    assert_eq!(tt_error_code(&b), CREATE_ERR_KEY_HOLDER_UNAVAILABLE, "{b}");
    fix.vta.script(SIGN_DOCUMENT, Script::Silent);
    let (_, b) = fix
        .as_admin("create", static_group("C", "members", "members"))
        .await;
    assert_eq!(tt_error_code(&b), CREATE_ERR_KEY_HOLDER_UNAVAILABLE, "{b}");
    assert!(
        b["payload"]["details"]["groupDid"].is_string(),
        "a minted DID is named so an operator can retire it: {b}"
    );

    fix.vta
        .script(SIGN_DOCUMENT, Script::Refuse("permissionDenied"));
    let (_, b) = fix
        .as_admin("create", static_group("D", "members", "members"))
        .await;
    assert_eq!(tt_error_code(&b), CREATE_ERR_KEY_HOLDER_REFUSED, "{b}");
    assert_eq!(b["payload"]["details"]["code"], "permissionDenied", "{b}");

    // Nothing above stored a group.
    let (_, list) = fix.as_admin("list", json!({})).await;
    assert_eq!(list["payload"]["items"], json!([]), "{list}");

    // The community's policy may refuse.
    activate_policy(
        &fix,
        r#"package vtc.groups
import rego.v1
decision := {"effect": "deny", "with": {"code": "closed", "reason": "no new groups"}}
"#,
    )
    .await;
    let (_, b) = fix
        .as_admin("create", static_group("E", "members", "members"))
        .await;
    assert_eq!(tt_error_code(&b), CREATE_ERR_POLICY_REFUSED, "{b}");
}

#[tokio::test]
async fn create_without_a_key_holder_is_refused() {
    let fix = fixture_with(None, true).await;
    let (_, b) = fix
        .as_admin("create", static_group("A", "members", "members"))
        .await;
    assert_eq!(tt_error_code(&b), CREATE_ERR_NO_KEY_HOLDER, "{b}");
    let fix = fixture_with(Some(config()), false).await;
    let (_, b) = fix
        .as_admin("create", static_group("A", "members", "members"))
        .await;
    assert_eq!(tt_error_code(&b), CREATE_ERR_NO_KEY_HOLDER, "{b}");
}

#[tokio::test]
async fn a_member_may_not_create_a_group() {
    let fix = fixture().await;
    let (_, b) = fix
        .as_member("create", static_group("A", "members", "members"))
        .await;
    assert_eq!(tt_error_code(&b), "permissionDenied", "{b}");
}

#[tokio::test]
async fn update_refuses_what_its_specification_declares() {
    let fix = fixture().await;
    let group = fix.create("members", "groupMembers").await;
    let id = group["groupId"].as_str().unwrap();

    let (_, b) = fix
        .as_admin("update", json!({ "groupId": UNKNOWN_GROUP, "name": "X" }))
        .await;
    assert_eq!(tt_error_code(&b), UPDATE_ERR_NOT_FOUND, "{b}");
    let (_, b) = fix
        .as_admin(
            "update",
            json!({ "groupId": id, "rule": { "all": [{ "fact": "personhood", "op": "exists" }] } }),
        )
        .await;
    assert_eq!(tt_error_code(&b), UPDATE_ERR_RULE_INVALID, "{b}");
    let (_, b) = fix
        .as_admin("update", json!({ "groupId": id, "visibility": "admins" }))
        .await;
    assert_eq!(tt_error_code(&b), UPDATE_ERR_SETTINGS_INVALID, "{b}");

    // A member who may see the group, but does not manage it.
    let (_, b) = fix
        .as_member("update", json!({ "groupId": id, "name": "Mine now" }))
        .await;
    assert_eq!(tt_error_code(&b), "permissionDenied", "{b}");

    let (status, doc) = fix
        .as_admin(
            "update",
            json!({ "groupId": id, "name": "Identity Working Group", "showMembers": "admins" }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    assert_eq!(doc["payload"]["group"]["name"], "Identity Working Group");
    assert_eq!(doc["payload"]["group"]["showMembers"], "admins");
}

#[tokio::test]
async fn delete_refuses_what_its_specification_declares() {
    let fix = fixture().await;
    let (_, b) = fix
        .as_admin(
            "delete",
            json!({ "groupId": UNKNOWN_GROUP, "reason": "gone" }),
        )
        .await;
    assert_eq!(tt_error_code(&b), DELETE_ERR_NOT_FOUND, "{b}");

    let group = fix.create("members", "members").await;
    let id = group["groupId"].as_str().unwrap();
    let (status, doc) = fix
        .as_admin("delete", json!({ "groupId": id, "reason": "wound up" }))
        .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    assert_eq!(doc["payload"]["state"], "deleted");
    let (_, b) = fix.as_admin("show", json!({ "groupId": id })).await;
    assert_eq!(tt_error_code(&b), SHOW_ERR_NOT_FOUND, "{b}");
}

#[tokio::test]
async fn a_group_the_caller_may_not_see_is_absent() {
    let fix = fixture().await;
    let open = fix.create("members", "members").await;
    let staff = fix.create("admins", "admins").await;

    // A member sees the members' group, without its managers or authority.
    let (_, list) = fix.as_member("list", json!({})).await;
    let items = list["payload"]["items"].as_array().unwrap();
    assert_eq!(items.len(), 1, "{list}");
    assert_eq!(items[0]["group"]["groupId"], open["groupId"]);
    assert_eq!(items[0]["myMembership"], "none");
    assert!(items[0]["group"].get("managers").is_none());
    assert!(
        items[0]["group"]
            .get("credentialAuthorityValidUntil")
            .is_none()
    );
    assert_eq!(items[0]["group"]["memberCount"], 0);

    // One it may not see answers as one that does not exist.
    let (_, b) = fix
        .as_member("show", json!({ "groupId": staff["groupId"] }))
        .await;
    assert_eq!(tt_error_code(&b), SHOW_ERR_NOT_FOUND, "{b}");
    let (_, b) = fix
        .as_member("show", json!({ "groupId": UNKNOWN_GROUP }))
        .await;
    assert_eq!(tt_error_code(&b), SHOW_ERR_NOT_FOUND, "{b}");
    let (_, b) = fix
        .as_member(
            "update",
            json!({ "groupId": staff["groupId"], "name": "x" }),
        )
        .await;
    assert_eq!(tt_error_code(&b), UPDATE_ERR_NOT_FOUND, "{b}");

    // A stranger reads nothing.
    let stranger = Party::new();
    let (_, b) = call(&fix.vtc, &stranger, &task("list"), json!({})).await;
    assert_eq!(tt_error_code(&b), "permissionDenied", "{b}");
}

#[tokio::test]
async fn list_pages_with_a_cursor_bound_to_its_caller() {
    let fix = fixture().await;
    for _ in 0..3 {
        fix.create("members", "members").await;
    }
    let (_, first) = fix.as_admin("list", json!({ "limit": 2 })).await;
    assert_eq!(first["payload"]["items"].as_array().unwrap().len(), 2);
    let cursor = first["payload"]["nextCursor"].as_str().unwrap().to_string();
    let (_, second) = fix
        .as_admin("list", json!({ "limit": 2, "cursor": cursor }))
        .await;
    assert_eq!(
        second["payload"]["items"].as_array().unwrap().len(),
        1,
        "{second}"
    );

    // Another caller, or other filters, cannot use it.
    let (_, b) = fix
        .as_member("list", json!({ "limit": 2, "cursor": cursor }))
        .await;
    assert_eq!(tt_error_code(&b), LIST_ERR_CURSOR_INVALID, "{b}");
    let (_, b) = fix
        .as_admin(
            "list",
            json!({ "limit": 2, "cursor": cursor, "mine": true }),
        )
        .await;
    assert_eq!(tt_error_code(&b), LIST_ERR_CURSOR_INVALID, "{b}");
}
