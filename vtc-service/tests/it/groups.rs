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
const ADD_ERR_NOT_FOUND: &str = g::members::add::v0_1::error_codes::NOT_FOUND.code;
const ADD_ERR_ENTRY_NOT_FOUND: &str = g::members::add::v0_1::error_codes::ENTRY_NOT_FOUND.code;
const ADD_ERR_ALREADY_MEMBER: &str = g::members::add::v0_1::error_codes::ALREADY_MEMBER.code;
const ADD_ERR_KEY_HOLDER_UNAVAILABLE: &str =
    g::members::add::v0_1::error_codes::KEY_HOLDER_UNAVAILABLE.code;
const ADD_ERR_KEY_HOLDER_REFUSED: &str =
    g::members::add::v0_1::error_codes::KEY_HOLDER_REFUSED.code;
const REMOVE_ERR_NOT_FOUND: &str = g::members::remove::v0_1::error_codes::NOT_FOUND.code;
const REMOVE_ERR_NOT_IN_GROUP: &str = g::members::remove::v0_1::error_codes::NOT_IN_GROUP.code;
const MEMBERS_LIST_ERR_NOT_FOUND: &str = g::members::list::v0_1::error_codes::NOT_FOUND.code;
const MEMBERS_LIST_ERR_CURSOR_INVALID: &str =
    g::members::list::v0_1::error_codes::CURSOR_INVALID.code;
const JOIN_ERR_NOT_FOUND: &str = g::join::v0_1::error_codes::NOT_FOUND.code;
const JOIN_ERR_NOT_JOINABLE: &str = g::join::v0_1::error_codes::NOT_JOINABLE.code;
const JOIN_ERR_ALREADY_MEMBER: &str = g::join::v0_1::error_codes::ALREADY_MEMBER.code;
const JOIN_ERR_REQUEST_PENDING: &str = g::join::v0_1::error_codes::REQUEST_PENDING.code;
const JOIN_ERR_POLICY_REFUSED: &str = g::join::v0_1::error_codes::POLICY_REFUSED.code;
const JOIN_ERR_KEY_HOLDER_UNAVAILABLE: &str =
    g::join::v0_1::error_codes::KEY_HOLDER_UNAVAILABLE.code;
const JOIN_ERR_KEY_HOLDER_REFUSED: &str = g::join::v0_1::error_codes::KEY_HOLDER_REFUSED.code;
const LEAVE_ERR_NOT_FOUND: &str = g::leave::v0_1::error_codes::NOT_FOUND.code;
const LEAVE_ERR_NOT_IN_GROUP: &str = g::leave::v0_1::error_codes::NOT_IN_GROUP.code;
const REQUESTS_LIST_ERR_NOT_FOUND: &str = g::requests::list::v0_1::error_codes::NOT_FOUND.code;
const REQUESTS_LIST_ERR_CURSOR_INVALID: &str =
    g::requests::list::v0_1::error_codes::CURSOR_INVALID.code;
const DECIDE_ERR_NOT_FOUND: &str = g::requests::decide::v0_1::error_codes::NOT_FOUND.code;
const DECIDE_ERR_ALREADY_DECIDED: &str =
    g::requests::decide::v0_1::error_codes::ALREADY_DECIDED.code;
const DECIDE_ERR_SELF_DECISION: &str = g::requests::decide::v0_1::error_codes::SELF_DECISION.code;
const DECIDE_ERR_KEY_HOLDER_UNAVAILABLE: &str =
    g::requests::decide::v0_1::error_codes::KEY_HOLDER_UNAVAILABLE.code;
const DECIDE_ERR_KEY_HOLDER_REFUSED: &str =
    g::requests::decide::v0_1::error_codes::KEY_HOLDER_REFUSED.code;
const MANAGERS_ADD_ERR_NOT_FOUND: &str = g::managers::add::v0_1::error_codes::NOT_FOUND.code;
const MANAGERS_ADD_ERR_ENTRY_NOT_FOUND: &str =
    g::managers::add::v0_1::error_codes::ENTRY_NOT_FOUND.code;
const MANAGERS_ADD_ERR_ALREADY_MANAGER: &str =
    g::managers::add::v0_1::error_codes::ALREADY_MANAGER.code;
const MANAGERS_REMOVE_ERR_NOT_FOUND: &str = g::managers::remove::v0_1::error_codes::NOT_FOUND.code;
const MANAGERS_REMOVE_ERR_NOT_MANAGER: &str =
    g::managers::remove::v0_1::error_codes::NOT_MANAGER.code;
const UNKNOWN_ENTRY: &str = "dir_UnknownUnknownUnknown";

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

/// `who`'s directory entry, made by reading their own card.
async fn entry_of(vtc: &TestVtc, who: &Party) -> String {
    let (status, doc) = call(
        vtc,
        who,
        "https://trusttasks.org/spec/vtc/directory/card/show/0.1",
        json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    doc["payload"]["card"]["entryId"]
        .as_str()
        .unwrap()
        .to_string()
}

/// Appoint `who` a manager of `group_id` as `vtc/groups/managers/add` would: a
/// resource grant on their entry, delegated by `granter`.
async fn appoint(vtc: &TestVtc, who: &Party, group_id: &str, granter: &str) {
    let mut entry = vtc_service::acl::get_acl_entry(&vtc.state.acl_ks, &who.did)
        .await
        .unwrap()
        .unwrap();
    entry.resource_grants.push(
        serde_json::from_value(json!({
            "capability": "vtc.groups.manage",
            "resource": format!("group:{group_id}"),
            "delegatedBy": granter,
            "grantedAt": Utc::now(),
        }))
        .unwrap(),
    );
    vtc_service::acl::store_acl_entry(&vtc.state.acl_ks, &entry)
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

    /// A new active member, with a directory entry.
    async fn another_member(&self) -> (Party, String) {
        let p = Party::new();
        seed_role(&self.vtc, &p.did, VtcRole::Member, &[]).await;
        store_member(&self.vtc.state.members_ks, &Member::fresh(&p.did))
            .await
            .unwrap();
        let entry = entry_of(&self.vtc, &p).await;
        (p, entry)
    }

    async fn group(&self, join_policy: &str, visibility: &str, show_members: &str) -> String {
        let mut body = static_group("Identity WG", visibility, show_members);
        body["joinPolicy"] = json!(join_policy);
        let (status, doc) = self.as_admin("create", body).await;
        assert_eq!(status, StatusCode::OK, "{doc}");
        doc["payload"]["group"]["groupId"]
            .as_str()
            .unwrap()
            .to_string()
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
    // No transport, said explicitly: a VTA left to its default would try to
    // add `#tsp` to a document that names no mediator, and refuse the mint.
    assert_eq!(mint[0]["addTspService"], false, "{}", mint[0]);
    assert_eq!(mint[0]["addMediatorService"], false, "{}", mint[0]);
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

// ─── membership ─────────────────────────────────────────────────────────

#[tokio::test]
async fn a_member_joins_an_open_group_and_its_did_issues_their_credential() {
    let fix = fixture().await;
    let group_id = fix.group("open", "members", "members").await;
    let (status, doc) = fix.as_member("join", json!({ "groupId": group_id })).await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    assert_eq!(doc["payload"]["outcome"], "joined");
    assert!(doc["payload"]["credentialId"].is_string(), "{doc}");
    assert!(
        doc["payload"]["member"]["credentialValidUntil"].is_string(),
        "{doc}"
    );

    // Signed by the VTA as the group — its own key, never the community's.
    let (_, show) = fix.as_admin("show", json!({ "groupId": group_id })).await;
    let group_did = show["payload"]["group"]["groupDid"].clone();
    let signed = fix.vta.calls_of(SIGN_DOCUMENT);
    let vmc = &signed.last().unwrap()["document"];
    assert_eq!(vmc["issuer"], group_did);
    assert_eq!(vmc["credentialSubject"]["id"], fix.member.did.as_str());
    assert!(
        vmc.get("credentialStatus").is_none(),
        "no status list per group: {vmc}"
    );
    assert!(
        signed.last().unwrap()["keyId"]
            .as_str()
            .unwrap()
            .starts_with(group_did.as_str().unwrap())
    );

    let (_, mine) = fix.as_member("list", json!({ "mine": true })).await;
    assert_eq!(
        mine["payload"]["items"][0]["myMembership"], "member",
        "{mine}"
    );
    assert_eq!(mine["payload"]["items"][0]["group"]["memberCount"], 1);
}

#[tokio::test]
async fn members_add_refuses_what_its_specification_declares() {
    let fix = fixture().await;
    let group_id = fix.group("closed", "members", "members").await;
    let (_, entry) = fix.another_member().await;

    let (_, b) = fix
        .as_admin(
            "members/add",
            json!({ "groupId": UNKNOWN_GROUP, "entryId": entry }),
        )
        .await;
    assert_eq!(tt_error_code(&b), ADD_ERR_NOT_FOUND, "{b}");
    let (_, b) = fix
        .as_admin(
            "members/add",
            json!({ "groupId": group_id, "entryId": UNKNOWN_ENTRY }),
        )
        .await;
    assert_eq!(tt_error_code(&b), ADD_ERR_ENTRY_NOT_FOUND, "{b}");

    fix.vta.script(SIGN_DOCUMENT, Script::Silent);
    let (_, b) = fix
        .as_admin(
            "members/add",
            json!({ "groupId": group_id, "entryId": entry }),
        )
        .await;
    assert_eq!(tt_error_code(&b), ADD_ERR_KEY_HOLDER_UNAVAILABLE, "{b}");
    fix.vta
        .script(SIGN_DOCUMENT, Script::Refuse("permissionDenied"));
    let (_, b) = fix
        .as_admin(
            "members/add",
            json!({ "groupId": group_id, "entryId": entry }),
        )
        .await;
    assert_eq!(tt_error_code(&b), ADD_ERR_KEY_HOLDER_REFUSED, "{b}");
    // Nothing was recorded either time.
    let (_, members) = fix
        .as_admin("members/list", json!({ "groupId": group_id }))
        .await;
    assert_eq!(members["payload"]["items"], json!([]), "{members}");

    let (status, doc) = fix
        .as_admin(
            "members/add",
            json!({ "groupId": group_id, "entryId": entry }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    assert_eq!(doc["payload"]["member"]["source"], "added");
    let (_, b) = fix
        .as_admin(
            "members/add",
            json!({ "groupId": group_id, "entryId": entry }),
        )
        .await;
    assert_eq!(tt_error_code(&b), ADD_ERR_ALREADY_MEMBER, "{b}");

    // A member who does not manage the group.
    let (_, b) = fix
        .as_member(
            "members/add",
            json!({ "groupId": group_id, "entryId": entry }),
        )
        .await;
    assert_eq!(tt_error_code(&b), "permissionDenied", "{b}");
}

#[tokio::test]
async fn members_remove_refuses_what_its_specification_declares() {
    let fix = fixture().await;
    let group_id = fix.group("closed", "members", "members").await;
    let (_, entry) = fix.another_member().await;
    let (_, b) = fix
        .as_admin(
            "members/remove",
            json!({ "groupId": UNKNOWN_GROUP, "entryId": entry }),
        )
        .await;
    assert_eq!(tt_error_code(&b), REMOVE_ERR_NOT_FOUND, "{b}");
    let (_, b) = fix
        .as_admin(
            "members/remove",
            json!({ "groupId": group_id, "entryId": entry }),
        )
        .await;
    assert_eq!(tt_error_code(&b), REMOVE_ERR_NOT_IN_GROUP, "{b}");

    fix.as_admin(
        "members/add",
        json!({ "groupId": group_id, "entryId": entry }),
    )
    .await;
    let (status, doc) = fix
        .as_admin(
            "members/remove",
            json!({ "groupId": group_id, "entryId": entry }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    assert_eq!(doc["payload"]["state"], "removed");
    assert!(doc["payload"]["credentialValidUntil"].is_string(), "{doc}");
}

#[tokio::test]
async fn members_list_refuses_what_its_specification_declares() {
    let fix = fixture().await;
    let hidden = fix.group("closed", "admins", "admins").await;
    let staff_list = fix.group("closed", "members", "admins").await;
    let open = fix.group("open", "members", "members").await;

    let (_, b) = fix
        .as_member("members/list", json!({ "groupId": hidden }))
        .await;
    assert_eq!(tt_error_code(&b), MEMBERS_LIST_ERR_NOT_FOUND, "{b}");
    let (_, b) = fix
        .as_member("members/list", json!({ "groupId": staff_list }))
        .await;
    assert_eq!(tt_error_code(&b), "permissionDenied", "{b}");

    for _ in 0..3 {
        let (_, entry) = fix.another_member().await;
        fix.as_admin("members/add", json!({ "groupId": open, "entryId": entry }))
            .await;
    }
    let (_, first) = fix
        .as_member("members/list", json!({ "groupId": open, "limit": 2 }))
        .await;
    let items = first["payload"]["items"].as_array().unwrap();
    assert_eq!(items.len(), 2, "{first}");
    // Another member's credential is theirs and the managers' to see.
    assert!(items[0].get("credentialValidUntil").is_none(), "{first}");
    let cursor = first["payload"]["nextCursor"].as_str().unwrap().to_string();
    let (_, b) = fix
        .as_admin("members/list", json!({ "groupId": open, "cursor": cursor }))
        .await;
    assert_eq!(tt_error_code(&b), MEMBERS_LIST_ERR_CURSOR_INVALID, "{b}");
    let (_, second) = fix
        .as_member("members/list", json!({ "groupId": open, "cursor": cursor }))
        .await;
    assert_eq!(
        second["payload"]["items"].as_array().unwrap().len(),
        1,
        "{second}"
    );
}

#[tokio::test]
async fn join_refuses_what_its_specification_declares() {
    let fix = fixture().await;
    let closed = fix.group("closed", "members", "members").await;
    let open = fix.group("open", "members", "members").await;
    let by_request = fix.group("request", "members", "members").await;
    let hidden = fix.group("open", "admins", "admins").await;

    let (_, b) = fix.as_member("join", json!({ "groupId": hidden })).await;
    assert_eq!(tt_error_code(&b), JOIN_ERR_NOT_FOUND, "{b}");
    let (_, b) = fix.as_member("join", json!({ "groupId": closed })).await;
    assert_eq!(tt_error_code(&b), JOIN_ERR_NOT_JOINABLE, "{b}");

    fix.vta.script(SIGN_DOCUMENT, Script::Silent);
    let (_, b) = fix.as_member("join", json!({ "groupId": open })).await;
    assert_eq!(tt_error_code(&b), JOIN_ERR_KEY_HOLDER_UNAVAILABLE, "{b}");
    fix.vta
        .script(SIGN_DOCUMENT, Script::Refuse("permissionDenied"));
    let (_, b) = fix.as_member("join", json!({ "groupId": open })).await;
    assert_eq!(tt_error_code(&b), JOIN_ERR_KEY_HOLDER_REFUSED, "{b}");

    let (status, _) = fix.as_member("join", json!({ "groupId": open })).await;
    assert_eq!(status, StatusCode::OK);
    let (_, b) = fix.as_member("join", json!({ "groupId": open })).await;
    assert_eq!(tt_error_code(&b), JOIN_ERR_ALREADY_MEMBER, "{b}");

    let (status, doc) = fix
        .as_member(
            "join",
            json!({ "groupId": by_request, "message": "I work on identity." }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    assert_eq!(doc["payload"]["outcome"], "requested");
    // The note is for the managers.
    assert!(doc["payload"]["request"].get("message").is_none(), "{doc}");
    let (_, b) = fix
        .as_member("join", json!({ "groupId": by_request }))
        .await;
    assert_eq!(tt_error_code(&b), JOIN_ERR_REQUEST_PENDING, "{b}");

    activate_policy(
        &fix,
        r#"package vtc.groups
import rego.v1
decision := {"effect": "deny", "with": {"code": "full", "reason": "this group is full"}}
"#,
    )
    .await;
    let (other, _) = fix.another_member().await;
    let (_, b) = call(&fix.vtc, &other, &task("join"), json!({ "groupId": open })).await;
    assert_eq!(tt_error_code(&b), JOIN_ERR_POLICY_REFUSED, "{b}");
}

#[tokio::test]
async fn leave_refuses_what_its_specification_declares() {
    let fix = fixture().await;
    let open = fix.group("open", "members", "members").await;
    let by_request = fix.group("request", "members", "members").await;
    let hidden = fix.group("open", "admins", "admins").await;

    let (_, b) = fix.as_member("leave", json!({ "groupId": hidden })).await;
    assert_eq!(tt_error_code(&b), LEAVE_ERR_NOT_FOUND, "{b}");
    let (_, b) = fix.as_member("leave", json!({ "groupId": open })).await;
    assert_eq!(tt_error_code(&b), LEAVE_ERR_NOT_IN_GROUP, "{b}");

    fix.as_member("join", json!({ "groupId": by_request }))
        .await;
    let (_, doc) = fix
        .as_member("leave", json!({ "groupId": by_request }))
        .await;
    assert_eq!(doc["payload"]["state"], "requestWithdrawn", "{doc}");

    fix.as_member("join", json!({ "groupId": open })).await;
    let (_, doc) = fix.as_member("leave", json!({ "groupId": open })).await;
    assert_eq!(doc["payload"]["state"], "left", "{doc}");
}

#[tokio::test]
async fn requests_list_refuses_what_its_specification_declares() {
    let fix = fixture().await;
    let by_request = fix.group("request", "members", "members").await;
    let (_, b) = fix
        .as_member("requests/list", json!({ "groupId": by_request }))
        .await;
    assert_eq!(tt_error_code(&b), REQUESTS_LIST_ERR_NOT_FOUND, "{b}");

    for _ in 0..3 {
        let (p, _) = fix.another_member().await;
        call(
            &fix.vtc,
            &p,
            &task("join"),
            json!({ "groupId": by_request, "message": "hi" }),
        )
        .await;
    }
    let (_, first) = fix
        .as_admin(
            "requests/list",
            json!({ "groupId": by_request, "limit": 2 }),
        )
        .await;
    let items = first["payload"]["items"].as_array().unwrap();
    assert_eq!(items.len(), 2, "{first}");
    assert_eq!(
        items[0]["request"]["message"], "hi",
        "the managers read the note"
    );
    let cursor = first["payload"]["nextCursor"].as_str().unwrap().to_string();
    let (_, b) = fix
        .as_admin("requests/list", json!({ "cursor": cursor, "limit": 2 }))
        .await;
    assert_eq!(tt_error_code(&b), REQUESTS_LIST_ERR_CURSOR_INVALID, "{b}");
    let (_, second) = fix
        .as_admin(
            "requests/list",
            json!({ "groupId": by_request, "cursor": cursor, "limit": 2 }),
        )
        .await;
    assert_eq!(
        second["payload"]["items"].as_array().unwrap().len(),
        1,
        "{second}"
    );
}

#[tokio::test]
async fn requests_decide_refuses_what_its_specification_declares() {
    let fix = fixture().await;
    let by_request = fix.group("request", "members", "members").await;
    let (_, b) = fix
        .as_admin(
            "requests/decide",
            json!({ "requestId": "greq_UnknownUnknownUnknown", "decision": "approve" }),
        )
        .await;
    assert_eq!(tt_error_code(&b), DECIDE_ERR_NOT_FOUND, "{b}");

    let (_, asked) = fix
        .as_member("join", json!({ "groupId": by_request }))
        .await;
    let request_id = asked["payload"]["request"]["requestId"]
        .as_str()
        .unwrap()
        .to_string();
    fix.vta.script(SIGN_DOCUMENT, Script::Silent);
    let (_, b) = fix
        .as_admin(
            "requests/decide",
            json!({ "requestId": request_id, "decision": "approve" }),
        )
        .await;
    assert_eq!(tt_error_code(&b), DECIDE_ERR_KEY_HOLDER_UNAVAILABLE, "{b}");
    fix.vta
        .script(SIGN_DOCUMENT, Script::Refuse("permissionDenied"));
    let (_, b) = fix
        .as_admin(
            "requests/decide",
            json!({ "requestId": request_id, "decision": "approve" }),
        )
        .await;
    assert_eq!(tt_error_code(&b), DECIDE_ERR_KEY_HOLDER_REFUSED, "{b}");

    let (status, doc) = fix
        .as_admin(
            "requests/decide",
            json!({ "requestId": request_id, "decision": "approve" }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    assert_eq!(doc["payload"]["request"]["state"], "approved");
    assert_eq!(doc["payload"]["member"]["source"], "requestApproved");
    let (_, b) = fix
        .as_admin(
            "requests/decide",
            json!({ "requestId": request_id, "decision": "decline" }),
        )
        .await;
    assert_eq!(tt_error_code(&b), DECIDE_ERR_ALREADY_DECIDED, "{b}");

    // A manager of the group who asked to join it may not decide it.
    let (manager, _) = fix.another_member().await;
    appoint(&fix.vtc, &manager, &by_request, &fix.admin.did).await;
    let (_, own) = call(
        &fix.vtc,
        &manager,
        &task("join"),
        json!({ "groupId": by_request }),
    )
    .await;
    let own_id = own["payload"]["request"]["requestId"]
        .as_str()
        .unwrap()
        .to_string();
    let (_, b) = call(
        &fix.vtc,
        &manager,
        &task("requests/decide"),
        json!({ "requestId": own_id, "decision": "approve" }),
    )
    .await;
    assert_eq!(tt_error_code(&b), DECIDE_ERR_SELF_DECISION, "{b}");
}

/// A card field shown only to the member's groups reaches someone in a group
/// with them — and only through a group whose member list they may see.
#[tokio::test]
async fn the_directory_groups_audience_counts_only_groups_whose_members_one_may_see() {
    let fix = fixture().await;
    let shared = fix.group("closed", "members", "groupMembers").await;
    let quiet = fix.group("closed", "members", "admins").await;
    let (alice, alice_entry) = fix.another_member().await;
    let (bob, bob_entry) = fix.another_member().await;
    let (carol, carol_entry) = fix.another_member().await;
    for (g, e) in [
        (&shared, &alice_entry),
        (&shared, &bob_entry),
        (&quiet, &alice_entry),
        (&quiet, &carol_entry),
    ] {
        let (status, doc) = fix
            .as_admin("members/add", json!({ "groupId": g, "entryId": e }))
            .await;
        assert_eq!(status, StatusCode::OK, "{doc}");
    }
    let (status, doc) = call(
        &fix.vtc,
        &alice,
        "https://trusttasks.org/spec/vtc/directory/card/update/0.1",
        json!({
            "values": { "pronouns": "she/her" },
            "visibility": { "pronouns": "groups" },
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    let show = |who: &Party| {
        let who = Party {
            did: who.did.clone(),
            secret_multibase: who.secret_multibase.clone(),
            secret: who.secret.clone(),
        };
        let vtc = &fix.vtc;
        let entry = alice_entry.clone();
        async move {
            let (_, doc) = call(
                vtc,
                &who,
                "https://trusttasks.org/spec/vtc/directory/entries/show/0.1",
                json!({ "entryId": entry }),
            )
            .await;
            doc["payload"]["entry"]["fields"]["pronouns"].clone()
        }
    };
    assert_eq!(
        show(&bob).await,
        "she/her",
        "bob shares a group whose members he sees"
    );
    assert_eq!(
        show(&carol).await,
        Value::Null,
        "carol shares only a group that hides its members from her"
    );
}

#[tokio::test]
async fn a_departure_ends_every_membership_and_request() {
    let fix = fixture().await;
    let open = fix.group("open", "members", "members").await;
    let by_request = fix.group("request", "members", "members").await;
    let entry = entry_of(&fix.vtc, &fix.member).await;
    fix.as_member("join", json!({ "groupId": open })).await;
    fix.as_member("join", json!({ "groupId": by_request }))
        .await;
    let ended = vtc_service::groups::on_departure(fix.vtc.state.directory.ks(), &entry)
        .await
        .unwrap();
    assert_eq!(ended, 1);
    assert!(
        vtc_service::groups::groups_of(fix.vtc.state.directory.ks(), &entry)
            .await
            .unwrap()
            .is_empty()
    );
    let (_, requests) = fix
        .as_admin(
            "requests/list",
            json!({ "groupId": by_request, "state": "withdrawn" }),
        )
        .await;
    assert_eq!(
        requests["payload"]["items"].as_array().unwrap().len(),
        1,
        "{requests}"
    );
}

// ─── managers ───────────────────────────────────────────────────────────

#[tokio::test]
async fn managers_add_refuses_what_its_specification_declares() {
    let fix = fixture().await;
    let group_id = fix.group("closed", "members", "members").await;
    let (carol, carol_entry) = fix.another_member().await;

    let (_, b) = fix
        .as_admin(
            "managers/add",
            json!({ "groupId": UNKNOWN_GROUP, "entryId": carol_entry }),
        )
        .await;
    assert_eq!(tt_error_code(&b), MANAGERS_ADD_ERR_NOT_FOUND, "{b}");
    let (_, b) = fix
        .as_admin(
            "managers/add",
            json!({ "groupId": group_id, "entryId": UNKNOWN_ENTRY }),
        )
        .await;
    assert_eq!(tt_error_code(&b), MANAGERS_ADD_ERR_ENTRY_NOT_FOUND, "{b}");

    let (status, doc) = fix
        .as_admin(
            "managers/add",
            json!({ "groupId": group_id, "entryId": carol_entry, "reason": "she convenes it" }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    assert_eq!(doc["payload"]["managers"], json!([carol_entry]));
    let (_, b) = fix
        .as_admin(
            "managers/add",
            json!({ "groupId": group_id, "entryId": carol_entry }),
        )
        .await;
    assert_eq!(tt_error_code(&b), MANAGERS_ADD_ERR_ALREADY_MANAGER, "{b}");

    // A member with no administrative role now manages that one group …
    let (_, dave_entry) = fix.another_member().await;
    let (status, doc) = call(
        &fix.vtc,
        &carol,
        &task("members/add"),
        json!({ "groupId": group_id, "entryId": dave_entry }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    // … and may appoint a co-manager of it, but creates no group.
    let (_, b) = call(
        &fix.vtc,
        &carol,
        &task("create"),
        static_group("Hers", "members", "members"),
    )
    .await;
    assert_eq!(tt_error_code(&b), "permissionDenied", "{b}");
}

#[tokio::test]
async fn managers_remove_refuses_what_its_specification_declares() {
    let fix = fixture().await;
    let group_id = fix.group("closed", "members", "members").await;
    let (carol, carol_entry) = fix.another_member().await;
    let (dave, dave_entry) = fix.another_member().await;
    for e in [&carol_entry, &dave_entry] {
        fix.as_admin("managers/add", json!({ "groupId": group_id, "entryId": e }))
            .await;
    }

    let (_, b) = fix
        .as_admin(
            "managers/remove",
            json!({ "groupId": UNKNOWN_GROUP, "entryId": carol_entry }),
        )
        .await;
    assert_eq!(tt_error_code(&b), MANAGERS_REMOVE_ERR_NOT_FOUND, "{b}");
    let (_, member_entry) = fix.another_member().await;
    let (_, b) = fix
        .as_admin(
            "managers/remove",
            json!({ "groupId": group_id, "entryId": member_entry }),
        )
        .await;
    assert_eq!(tt_error_code(&b), MANAGERS_REMOVE_ERR_NOT_MANAGER, "{b}");

    // Managers of one group do not remove one another.
    let (_, b) = call(
        &fix.vtc,
        &carol,
        &task("managers/remove"),
        json!({ "groupId": group_id, "entryId": dave_entry }),
    )
    .await;
    assert_eq!(tt_error_code(&b), "permissionDenied", "{b}");
    // A manager steps down.
    let (status, doc) = call(
        &fix.vtc,
        &dave,
        &task("managers/remove"),
        json!({ "groupId": group_id, "entryId": dave_entry }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    assert_eq!(doc["payload"]["managers"], json!([carol_entry]));
}

/// A manager appointed by a manager who then loses the group is reviewed, and
/// withdrawn at the review's deadline unless someone re-affirms it.
#[tokio::test]
async fn an_appointment_whose_granter_no_longer_covers_it_is_reviewed_then_withdrawn() {
    let fix = fixture().await;
    let group_id = fix.group("closed", "members", "members").await;
    let (carol, carol_entry) = fix.another_member().await;
    let (dave, dave_entry) = fix.another_member().await;
    fix.as_admin(
        "managers/add",
        json!({ "groupId": group_id, "entryId": carol_entry }),
    )
    .await;
    let (status, doc) = call(
        &fix.vtc,
        &carol,
        &task("managers/add"),
        json!({ "groupId": group_id, "entryId": dave_entry }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    // Carol steps down: she no longer stands behind Dave's appointment.
    call(
        &fix.vtc,
        &carol,
        &task("managers/remove"),
        json!({ "groupId": group_id, "entryId": carol_entry }),
    )
    .await;

    let state = &fix.vtc.state;
    assert_eq!(
        vtc_service::groups::managers::sweep(state).await.unwrap(),
        0
    );
    let mut entry = vtc_service::acl::get_acl_entry(&state.acl_ks, &dave.did)
        .await
        .unwrap()
        .unwrap();
    let review = entry.resource_grants[0]
        .review
        .clone()
        .expect("under review");
    assert_eq!(review.granter, carol.did);
    // Still in force while under review.
    let (status, _) = call(
        &fix.vtc,
        &dave,
        &task("members/list"),
        json!({ "groupId": group_id }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // The deadline passes with nobody re-affirming it.
    entry.resource_grants[0].review.as_mut().unwrap().deadline =
        Utc::now() - chrono::Duration::minutes(1);
    vtc_service::acl::store_acl_entry(&state.acl_ks, &entry)
        .await
        .unwrap();
    assert_eq!(
        vtc_service::groups::managers::sweep(state).await.unwrap(),
        1
    );
    let (_, b) = call(
        &fix.vtc,
        &dave,
        &task("members/add"),
        json!({ "groupId": group_id, "entryId": carol_entry }),
    )
    .await;
    assert_eq!(tt_error_code(&b), "permissionDenied", "{b}");
}

#[tokio::test]
async fn the_sweeper_renews_a_groups_authority_and_its_members_credentials_before_they_lapse() {
    use vtc_service::groups;
    let fix = fixture().await;
    let group_id = fix.group("open", "members", "members").await;
    let (status, doc) = fix.as_member("join", json!({ "groupId": group_id })).await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    let entry_id = entry_of(&fix.vtc, &fix.member).await;
    let state = &fix.vtc.state;
    let ks = state.directory.ks();
    let now = Utc::now();

    // Nothing is due yet.
    let report = groups::renewal::sweep(state, now).await.unwrap();
    assert!(report.authorities.is_empty() && report.credentials.is_empty());

    // Both near their expiry.
    let mut group = groups::get(ks, &group_id).await.unwrap().unwrap();
    let old = group.authority.clone().unwrap();
    group.authority.as_mut().unwrap().valid_until = now + chrono::Duration::days(5);
    groups::put(ks, &group).await.unwrap();
    let mut m = groups::membership(ks, &group_id, &entry_id)
        .await
        .unwrap()
        .unwrap();
    let old_credential = m.credential_id.clone().unwrap();
    m.credential_valid_until = Some(now + chrono::Duration::days(2));
    groups::put_membership(ks, &m).await.unwrap();

    // The VTA does not answer the authority's renewal: it waits out a backoff,
    // and the member's credential is renewed all the same.
    fix.vta.script(SIGN_DOCUMENT, Script::Silent);
    let report = groups::renewal::sweep(state, now).await.unwrap();
    assert_eq!(report.failed, vec![group_id.clone()]);
    assert_eq!(
        report.credentials,
        vec![(group_id.clone(), entry_id.clone())]
    );
    let m = groups::membership(ks, &group_id, &entry_id)
        .await
        .unwrap()
        .unwrap();
    assert_ne!(m.credential_id.as_deref(), Some(old_credential.as_str()));
    assert!(m.credential_valid_until.unwrap() > now + chrono::Duration::days(29));
    let signed = fix.vta.calls_of(SIGN_DOCUMENT);
    let vmc = &signed.last().unwrap()["document"];
    assert_eq!(vmc["credentialSubject"]["id"], fix.member.did.as_str());

    let report = groups::renewal::sweep(state, now).await.unwrap();
    assert!(report.failed.is_empty() && report.authorities.is_empty());

    // After the backoff, the authority is renewed in the slot it always held.
    let later = now + chrono::Duration::hours(7);
    let report = groups::renewal::sweep(state, later).await.unwrap();
    assert_eq!(report.authorities, vec![group_id.clone()]);
    let group = groups::get(ks, &group_id).await.unwrap().unwrap();
    let renewed = group.authority.clone().unwrap();
    assert_ne!(renewed.credential_id, old.credential_id);
    assert_eq!(renewed.status_list_index, old.status_list_index);
    assert!(renewed.valid_until > later + chrono::Duration::days(364));
    let vac = group.authority_credential.unwrap();
    assert_eq!(vac["credentialSubject"]["id"], group.group_did.as_str());
    assert_eq!(
        vac["credentialStatus"]["statusListIndex"]
            .as_str()
            .map(str::to_string),
        Some(old.status_list_index.to_string()),
        "{vac}"
    );
}

#[tokio::test]
async fn a_member_who_left_the_community_is_not_renewed() {
    use vtc_service::groups;
    let fix = fixture().await;
    let group_id = fix.group("open", "members", "members").await;
    fix.as_member("join", json!({ "groupId": group_id })).await;
    let entry_id = entry_of(&fix.vtc, &fix.member).await;
    let state = &fix.vtc.state;
    let ks = state.directory.ks();
    let now = Utc::now();
    let mut m = groups::membership(ks, &group_id, &entry_id)
        .await
        .unwrap()
        .unwrap();
    m.credential_valid_until = Some(now + chrono::Duration::days(1));
    groups::put_membership(ks, &m).await.unwrap();
    vtc_service::acl::delete_acl_entry(&state.acl_ks, &fix.member.did)
        .await
        .unwrap();

    let signs = fix.vta.calls_of(SIGN_DOCUMENT).len();
    let report = groups::renewal::sweep(state, now).await.unwrap();
    assert!(report.credentials.is_empty() && report.failed.is_empty());
    assert_eq!(fix.vta.calls_of(SIGN_DOCUMENT).len(), signs);
}
