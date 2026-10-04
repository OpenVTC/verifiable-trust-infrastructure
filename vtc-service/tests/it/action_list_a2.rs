//! The administrator action list, phase A2
//! (`docs/05-design-notes/vtc-action-list.md` §8.2, §8.3b, §11):
//!
//! - **VTI-VTC-023** — every offline access-control write an operator makes is
//!   raised at the next boot as an `acknowledge` item that every administrator
//!   holding a role when it was made must acknowledge; an emergency bootstrap's
//!   is for the administrators it installed.
//! - **VTI-APV-019** — every reduction of an administrator, once it lands,
//!   sends the subject `vtc/members/authority-reduced-notice` (never beside the
//!   removal notice); one nobody but the requester and the subject could
//!   consent to waits out a cooling-off, lands by itself, is audited at
//!   `Critical`, and the first of two administrators to act wins.
//! - **VTI-APV-017** — `approverSigned` decision evidence is verified; an
//!   execution interrupted by a crash is reconciled from the effect it
//!   recorded (CLAUDE.md R2.1).
//! - The new administrator an action makes is issued a step-up approver invite.

use axum::http::StatusCode;
use serde_json::{Value, json};
use vti_rooms_dtg::test_support::Party;

use vtc_service::acl::{VtcAclEntry, VtcRole, get_acl_entry, store_acl_entry};
use vtc_service::admin_actions::ActionRecord;
use vtc_service::admin_actions::codes::*;
use vtc_service::ceremony::authority_reduced_notice::sent_for_test as notices;
use vtc_service::ceremony::authority_reduction_pending_notice::sent_for_test as pending_notices;
use vtc_service::members::{Member, store_member};
use vtc_service::test_support::TestVtc;

use crate::common::second_party::{
    Gesturer, decide, decision_payload, parked_action, show_action, step_up_request,
};
use crate::common::signed::{assert_conforms, error_code, post, signed, signed_to};

/// A `trust-task-error` reply's code — the census reads witnesses by this name.
fn tt_error_code(doc: &Value) -> Option<&str> {
    error_code(doc)
}

const RP_ORIGIN: &str = "https://vtc.example.com";
const GRANT: &str = "https://trusttasks.org/spec/acl/grant/0.1";
const REVOKE: &str = "https://trusttasks.org/spec/acl/revoke/0.1";
const UPDATE: &str = "https://trusttasks.org/spec/acl/update/0.1";
const CHANGE_ROLE: &str = "https://trusttasks.org/spec/acl/change-role/0.1";
const ADMIN_REMOVE: &str = "https://trusttasks.org/spec/vtc/members/admin-remove/0.1";
const PATCH: &str = "https://trusttasks.org/spec/config/patch/0.1";
const LIST: &str = "https://trusttasks.org/spec/vtc/admin/actions/list/0.1";
const SHOW: &str = "https://trusttasks.org/spec/vtc/admin/actions/show/0.1";
const CANCEL: &str = "https://trusttasks.org/spec/vtc/admin/actions/cancel/0.1";
const ACKNOWLEDGE: &str = "https://trusttasks.org/spec/vtc/admin/actions/acknowledge/0.1";
const DECISION_V0_2: &str = "https://trusttasks.org/spec/task-consent/decision/0.2";
const ATTEST: &str = "https://trusttasks.org/spec/auth/step-up/approver/attest/0.1";
const LIST_V0_2: &str = "https://trusttasks.org/spec/vtc/admin/actions/list/0.2";
const SHOW_V0_2: &str = "https://trusttasks.org/spec/vtc/admin/actions/show/0.2";
const CANCEL_V0_2: &str = "https://trusttasks.org/spec/vtc/admin/actions/cancel/0.2";
const ACKNOWLEDGE_V0_2: &str = "https://trusttasks.org/spec/vtc/admin/actions/acknowledge/0.2";
/// The record type an operator's offline write is named by (VTI-VTC-023).
const OFFLINE_WRITE: &str = "https://trusttasks.org/spec/vtc/operator/offline-write/0.1";
const UPSERT: &str = "https://trusttasks.org/spec/policy/upsert/0.2";
const COOLING_OFF_KEY: &str = "acl.removal_cooling_off";

struct Fixture {
    vtc: TestVtc,
    gesturer: Gesturer,
}

async fn fixture() -> Fixture {
    let vtc = TestVtc::builder()
        .with_public_url(RP_ORIGIN)
        .with_signers(true)
        .with_audit(true)
        .with_install_signer(std::sync::Arc::new(
            vtc_service::install::InstallTokenSigner::from_master_seed(&[0xAB; 64]).unwrap(),
        ))
        .build()
        .await;
    vtc_service::policy::default::install_defaults(
        &vtc.state.policies_ks,
        &vtc.state.active_policies_ks,
    )
    .await
    .unwrap();
    for purpose in [
        affinidi_status_list::StatusPurpose::Revocation,
        affinidi_status_list::StatusPurpose::Suspension,
    ] {
        vtc_service::status_list::ensure_initial(
            &vtc.state.status_lists_ks,
            purpose,
            format!("{RP_ORIGIN}/v1/status-lists/{purpose}"),
        )
        .await
        .unwrap();
    }
    Fixture {
        vtc,
        gesturer: Gesturer::new(),
    }
}

fn row(did: &str, role: VtcRole, scopes: &[&str]) -> VtcAclEntry {
    VtcAclEntry {
        did: did.to_string(),
        admin: vtc_service::acl::legacy_seed_authority(&role, scopes),
        delegated_by: None,
        role,
        label: None,
        created_at: 0,
        created_by: "did:key:vtc-install".into(),
        updated_at: None,
        updated_by: None,
        expires_at: None,
        resource_grants: Vec::new(),
        label_set_by_subject: false,
        suspension: None,
    }
}

async fn seed(fix: &Fixture, role: VtcRole, scopes: &[&str]) -> Party {
    let party = Party::new();
    store_acl_entry(&fix.vtc.state.acl_ks, &row(&party.did, role, scopes))
        .await
        .unwrap();
    party
}

async fn admin(fix: &Fixture) -> Party {
    seed(fix, VtcRole::Admin, &[]).await
}

async fn requester(fix: &mut Fixture) -> Party {
    let party = admin(fix).await;
    fix.gesturer.enrol(&fix.vtc, &party.did).await;
    party
}

async fn entry(fix: &Fixture, did: &str) -> Option<VtcAclEntry> {
    get_acl_entry(&fix.vtc.state.acl_ks, did).await.unwrap()
}

async fn vtc_did(fix: &Fixture) -> String {
    fix.vtc.state.config.read().await.vtc_did.clone().unwrap()
}

/// Send `doc`, answering a step-up with `by`'s passkey: the reply after.
async fn submit(fix: &mut Fixture, by: &Party, doc: &Value) -> (StatusCode, Value) {
    let (status, reply) = post(&fix.vtc, doc).await;
    if step_up_request(&reply).is_none() {
        return (status, reply);
    }
    fix.gesturer.gesture(&fix.vtc, by, &reply).await;
    post(&fix.vtc, doc).await
}

async fn park(fix: &mut Fixture, by: &Party, doc: &Value) -> String {
    let (status, reply) = submit(fix, by, doc).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{reply}");
    parked_action(&reply).unwrap_or_else(|| panic!("parked: {reply}"))
}

async fn action(fix: &Fixture, who: &Party, id: &str) -> Value {
    let (status, reply) = show_action(&fix.vtc, who, id).await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    assert_conforms(SHOW, &reply);
    reply["payload"]["action"].clone()
}

async fn list(fix: &Fixture, who: &Party, view: &str) -> Value {
    let (status, reply) = post(&fix.vtc, &signed(who, LIST, json!({ "view": view })).await).await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    assert_conforms(LIST, &reply);
    reply["payload"].clone()
}

/// `vtc/admin/actions/show/0.2` as `who`: the action, held to the 0.2 schema.
async fn action_v0_2(fix: &Fixture, who: &Party, id: &str) -> Value {
    let (status, reply) = post(
        &fix.vtc,
        &signed(who, SHOW_V0_2, json!({ "actionId": id })).await,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    assert_conforms(SHOW_V0_2, &reply);
    reply["payload"]["action"].clone()
}

async fn list_v0_2(fix: &Fixture, who: &Party, view: &str) -> Value {
    let (status, reply) = post(
        &fix.vtc,
        &signed(who, LIST_V0_2, json!({ "view": view })).await,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    assert_conforms(LIST_V0_2, &reply);
    reply["payload"].clone()
}

async fn acknowledge(fix: &Fixture, who: &Party, id: &str) -> (StatusCode, Value) {
    post(
        &fix.vtc,
        &signed(who, ACKNOWLEDGE, json!({ "actionId": id })).await,
    )
    .await
}

async fn record(fix: &Fixture, id: &str) -> ActionRecord {
    fix.vtc
        .state
        .admin_actions_ks
        .get(format!("action:{id}"))
        .await
        .unwrap()
        .expect("the action is stored")
}

async fn put_record(fix: &Fixture, rec: &ActionRecord) {
    fix.vtc
        .state
        .admin_actions_ks
        .insert(format!("action:{}", rec.id), rec)
        .await
        .unwrap();
}

async fn audit_events(fix: &Fixture) -> Vec<vti_common::audit::AuditEnvelope> {
    fix.vtc
        .state
        .audit_ks
        .prefix_iter_raw(Vec::new())
        .await
        .unwrap()
        .into_iter()
        .filter_map(|(_, v)| serde_json::from_slice::<vti_common::audit::AuditEnvelope>(&v).ok())
        .collect()
}

async fn audit_count(fix: &Fixture, variant: &str) -> usize {
    audit_events(fix)
        .await
        .iter()
        .filter(|e| e.event.variant_name() == variant)
        .count()
}

async fn patch(fix: &Fixture, by: &Party, key: &str, value: Value) {
    let (status, reply) = post(
        &fix.vtc,
        &signed(by, PATCH, json!({ "overrides": { key: value } })).await,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{reply}");
}

/// End a cooling-off now, and run the sweep that lands it.
async fn land_now(fix: &Fixture, id: &str) {
    let mut rec = record(fix, id).await;
    rec.cooling_off_until = Some(1);
    put_record(fix, &rec).await;
    vtc_service::admin_actions::sweep_once(&fix.vtc.state)
        .await
        .unwrap();
}

/// Activate a removal policy that allows every removal (the default refuses to
/// remove an administrator).
async fn allow_every_removal(fix: &Fixture) {
    use vtc_service::policy::{Policy, PolicyPurpose, set_active_policy_id, store_policy};
    let src = "package vtc.removal\nimport rego.v1\n\
               default decision := {\"effect\": \"allow\", \"with\": {\"disposition\": \"tombstone\"}}\n";
    let id = uuid::Uuid::new_v4();
    let sha: [u8; 32] = {
        use sha2::{Digest, Sha256};
        Sha256::digest(src.as_bytes()).into()
    };
    store_policy(
        &fix.vtc.state.policies_ks,
        &Policy {
            id,
            purpose: PolicyPurpose::Removal,
            rego_source: src.into(),
            sha256: sha,
            activated_at: Some(chrono::Utc::now()),
            author_did: "did:key:test".into(),
            created_at: chrono::Utc::now(),
            version: 99,
            name: None,
            description: None,
        },
    )
    .await
    .unwrap();
    set_active_policy_id(
        &fix.vtc.state.active_policies_ks,
        PolicyPurpose::Removal,
        id,
    )
    .await
    .unwrap();
}

// ─── VTI-VTC-023: operator writes are acknowledged ─────────────────────────

/// Every offline writer — `vtc acl add`, `vtc admin invite`, `vtc
/// create-did-key --admin`, `vtc acl remove`, `vtc admin enrol-approver` —
/// raises one acknowledge item at the next boot, for every administrator who
/// held a role when it was made. It has no expiry and no threshold; the
/// console's banner reads the unacknowledged ones off the list; acknowledging
/// is audited; once all have acknowledged it completes. Raised once, however
/// many boots.
#[tokio::test]
async fn vti_vtc_023_every_offline_writer_raises_an_acknowledge_item() {
    let fix = fixture().await;
    let a = admin(&fix).await;
    let scoped = seed(&fix, VtcRole::Admin, &["ctx-a"]).await;
    let store = &fix.vtc.store;
    let (x1, x2, x3, x4) = (Party::new(), Party::new(), Party::new(), Party::new());
    for (command, action, did, role) in [
        ("vtc acl add", "grant", &x1.did, Some(VtcRole::Admin)),
        ("vtc admin invite", "grant", &x2.did, Some(VtcRole::Admin)),
        (
            "vtc create-did-key --admin",
            "grant",
            &x3.did,
            Some(VtcRole::Admin),
        ),
        ("vtc acl remove", "remove", &x4.did, None),
    ] {
        vtc_service::install::record_offline_acl_write(
            store,
            command,
            action,
            did,
            role.as_ref(),
            &[],
        )
        .await
        .unwrap();
    }
    vtc_service::step_up_approver::mint_offline_invite(store, RP_ORIGIN, &a.did, 900)
        .await
        .unwrap();

    vtc_service::server::audit_offline_break_glass(&fix.vtc.state).await;
    // A second boot raises nothing more: the markers were cleared once raised.
    vtc_service::server::audit_offline_break_glass(&fix.vtc.state).await;
    assert_eq!(audit_count(&fix, "AclBreakGlassWritten").await, 5);

    let page = list(&fix, &a, "waitingForMe").await;
    let items = page["actions"].as_array().unwrap();
    assert_eq!(items.len(), 5, "{page}");
    assert_eq!(page["counts"]["waitingForMe"], 5);
    // The banner's data: every one is still unacknowledged by `a`.
    assert_eq!(
        page["ext"]["org.openvtc"]["operatorWritesUnacknowledged"]
            .as_array()
            .unwrap()
            .len(),
        5
    );
    let mut commands: Vec<&str> = Vec::new();
    for item in items {
        assert_eq!(item["category"], "acknowledge", "{item}");
        assert_eq!(item["kind"], "operator.offlineWrite");
        assert_eq!(item["callerRole"], "acknowledger");
        assert!(item.get("expiresAt").is_none(), "never expires: {item}");
        assert!(item.get("threshold").is_none(), "{item}");
        assert!(item.get("challenge").is_none(), "{item}");
        assert_eq!(item["approversRemaining"], 2, "a and the scoped admin");
        assert_eq!(
            item["summary"]["fields"]["command"]["value"],
            item["payload"]["command"]
        );
        // Named by the record type, with the record as its payload — never a
        // Trust Task it did not run (trust-tasks-tf #719).
        assert_eq!(item["typeUri"], OFFLINE_WRITE, "{item}");
        {
            use trust_tasks_rs::validate::ValidatedPayload as _;
            trust_tasks_rs::specs::vtc::operator::offline_write::v0_1::Payload::validate_value(
                &item["payload"],
            )
            .unwrap_or_else(|e| panic!("not an offline-write record: {e}\n{item}"));
        }
        assert_eq!(
            item["payload"]["host"].as_str().map(str::is_empty),
            Some(false)
        );
        commands.push(item["payload"]["command"].as_str().unwrap());
    }
    commands.sort_unstable();
    assert_eq!(
        commands,
        [
            "aclAdd",
            "aclRemove",
            "adminInvite",
            "createDidKeyAdmin",
            "enrolApprover",
        ]
    );
    // Each names the DID it changed.
    let removed = items
        .iter()
        .find(|i| i["payload"]["command"] == "aclRemove")
        .unwrap();
    assert_eq!(removed["payload"]["dids"], json!([x4.did]));
    // 0.2 renders the same item; acknowledging there answers a 0.2 Action.
    let shown = action_v0_2(&fix, &a, removed["actionId"].as_str().unwrap()).await;
    assert_eq!(shown["category"], "acknowledge");
    assert_eq!(shown["typeUri"], OFFLINE_WRITE);

    // `a` acknowledges one: recorded, still open for the scoped admin.
    let id = items[0]["actionId"].as_str().unwrap().to_string();
    let (status, reply) = acknowledge(&fix, &a, &id).await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    assert_conforms(ACKNOWLEDGE, &reply);
    let acked = &reply["payload"]["action"];
    assert_eq!(acked["status"], "open");
    assert_eq!(acked["approvals"][0]["subject"], a.did.as_str());
    assert_eq!(acked["approversRemaining"], 1);
    // Again: the earlier acknowledgement stands.
    let (_, again) = acknowledge(&fix, &a, &id).await;
    assert_eq!(
        tt_error_code(&again),
        Some(ACKNOWLEDGE_ALREADY_ACKNOWLEDGED),
        "{again}"
    );
    // The scoped admin completes it, at 0.2.
    let (_, reply) = post(
        &fix.vtc,
        &signed(&scoped, ACKNOWLEDGE_V0_2, json!({ "actionId": id })).await,
    )
    .await;
    assert_conforms(ACKNOWLEDGE_V0_2, &reply);
    let done = &reply["payload"]["action"];
    assert_eq!(done["status"], "completed", "{reply}");
    assert_eq!(done["closedReason"], "acknowledged");

    // An administrator who did not hold a role when the write was made sees
    // it, but is not asked.
    let newcomer = admin(&fix).await;
    let other = items[1]["actionId"].as_str().unwrap();
    assert_eq!(
        action(&fix, &newcomer, other).await["callerRole"],
        "observer"
    );
    let (_, refused) = acknowledge(&fix, &newcomer, other).await;
    assert_eq!(
        tt_error_code(&refused),
        Some(ACKNOWLEDGE_NOT_ACKNOWLEDGEABLE),
        "{refused}"
    );

    // Minus anyone who has since lost every admin role: with the scoped admin
    // gone, `a` alone completes the next.
    vtc_service::acl::delete_acl_entry(&fix.vtc.state.acl_ks, &scoped.did)
        .await
        .unwrap();
    let (_, reply) = acknowledge(&fix, &a, other).await;
    assert_eq!(reply["payload"]["action"]["status"], "completed", "{reply}");

    let page = list(&fix, &a, "waitingForMe").await;
    assert_eq!(page["counts"]["waitingForMe"], 3);
    let stages = audit_events(&fix)
        .await
        .into_iter()
        .filter(|e| match &e.event {
            vti_common::audit::AuditEvent::TaskConsentRecorded(d) => d.stage == "acknowledged",
            _ => false,
        })
        .count();
    assert_eq!(stages, 3, "every acknowledgement is audited");
}

/// An emergency bootstrap wiped the administrators it would have told, so its
/// item is for the new ones: nobody can acknowledge it at boot, and the first
/// administrator installed afterwards is asked to.
#[tokio::test]
async fn vti_vtc_023_an_emergency_bootstrap_is_acknowledged_by_the_new_administrators() {
    let fix = fixture().await;
    fix.vtc
        .state
        .install_store
        .mark_emergency_pending(vtc_service::install::PendingEmergencyBootstrap {
            operator_hostname: "ops-host-1".into(),
            invoked_at: chrono::Utc::now(),
            dids: vec![
                "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH".into(),
                "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK".into(),
            ],
        })
        .await
        .unwrap();
    vtc_service::server::audit_offline_break_glass(&fix.vtc.state).await;
    vtc_service::server::audit_offline_break_glass(&fix.vtc.state).await;
    assert_eq!(audit_count(&fix, "EmergencyBootstrapInvoked").await, 1);
    assert!(
        fix.vtc
            .state
            .install_store
            .peek_pending_emergency()
            .await
            .unwrap()
            .is_none(),
        "the marker is cleared once raised"
    );

    // The administrator the recovery installed.
    let founder = admin(&fix).await;
    let page = list(&fix, &founder, "waitingForMe").await;
    let items = page["actions"].as_array().unwrap();
    assert_eq!(items.len(), 1, "{page}");
    let item = &items[0];
    assert_eq!(item["category"], "acknowledge");
    assert_eq!(item["typeUri"], OFFLINE_WRITE);
    assert_eq!(item["payload"]["command"], "emergencyBootstrap");
    assert_eq!(item["payload"]["host"], "ops-host-1");
    assert_eq!(
        item["payload"]["dids"],
        json!([
            "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH",
            "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
        ])
    );
    assert_eq!(item["callerRole"], "acknowledger");
    let (_, reply) = acknowledge(&fix, &founder, item["actionId"].as_str().unwrap()).await;
    assert_eq!(reply["payload"]["action"]["status"], "completed", "{reply}");
    assert_eq!(reply["payload"]["action"]["closedReason"], "acknowledged");
    // It stays in History.
    let history = list(&fix, &founder, "history").await;
    assert_eq!(history["actions"].as_array().unwrap().len(), 1);
}

/// `vtc/operator/offline-write/0.1` is a record type: an acknowledge item
/// names it, nobody sends it. A document of that type, even from an
/// administrator, is not dispatched — it answers `unsupportedType`, like every
/// other embedded-only type.
#[tokio::test]
async fn an_offline_write_record_sent_on_its_own_is_unsupported() {
    let fix = fixture().await;
    let a = admin(&fix).await;
    let (status, reply) = post(
        &fix.vtc,
        &signed(
            &a,
            OFFLINE_WRITE,
            json!({
                "command": "aclAdd",
                "dids": [Party::new().did],
                "host": "vtc-host-1",
                "at": "2026-10-03T09:00:00Z",
            }),
        )
        .await,
    )
    .await;
    assert_ne!(status, StatusCode::OK, "{reply}");
    assert_eq!(error_code(&reply), Some("unsupportedType"), "{reply}");
}

// ─── VTI-APV-019: the authority-reduced notice ─────────────────────────────

/// A reduction that ran on a third administrator's consent: `revoked`,
/// `consented`, decided by the requester — sent once it lands.
#[tokio::test]
async fn vti_apv_019_a_consented_revocation_sends_the_notice() {
    let mut fix = fixture().await;
    let a = requester(&mut fix).await;
    let subject = admin(&fix).await;
    let third = admin(&fix).await;
    let id = park(
        &mut fix,
        &a,
        &signed(
            &a,
            REVOKE,
            json!({ "subject": subject.did, "reason": "rotation" }),
        )
        .await,
    )
    .await;
    assert!(notices(&subject.did).is_empty(), "nothing before it lands");
    let (status, ack) = decide(&fix.vtc, &third, &id, "approve").await;
    assert_eq!(status, StatusCode::OK, "{ack}");
    assert!(entry(&fix, &subject.did).await.is_none());
    let sent = notices(&subject.did);
    assert_eq!(sent.len(), 1, "{sent:?}");
    assert_eq!(sent[0]["code"], "revoked");
    assert_eq!(sent[0]["agreement"], "consented");
    // The administrative role it held (`acl/_shared/0.2` names it).
    assert_eq!(sent[0]["previousRole"], "community-admin");
    assert!(sent[0].get("resultingRole").is_none());
    assert_eq!(sent[0]["decidedBy"], a.did.as_str());
    assert_eq!(sent[0]["reason"], "rotation");
    assert_eq!(audit_count(&fix, "AuthorityReducedUnopposed").await, 0);
}

/// The paths where no consent was needed — an administrator holding nothing
/// authority-conferring (a moderator) revoked, demoted, narrowed — each send
/// the notice with its own code, and `unopposed`: nobody but the decider
/// reviewed it.
#[tokio::test]
async fn vti_apv_019_each_direct_reduction_sends_the_notice_with_its_code() {
    let mut fix = fixture().await;
    let a = requester(&mut fix).await;

    let revoked = seed(&fix, VtcRole::Moderator, &[]).await;
    let (status, reply) = submit(
        &mut fix,
        &a,
        &signed(&a, REVOKE, json!({ "subject": revoked.did })).await,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    let sent = notices(&revoked.did);
    assert_eq!(sent.len(), 1, "{sent:?}");
    assert_eq!(sent[0]["code"], "revoked");
    assert_eq!(sent[0]["agreement"], "unopposed");

    let demoted = seed(&fix, VtcRole::Moderator, &[]).await;
    let (status, reply) = submit(
        &mut fix,
        &a,
        &signed(
            &a,
            CHANGE_ROLE,
            json!({ "subject": demoted.did, "fromRole": "moderator", "toRole": "member" }),
        )
        .await,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    let sent = notices(&demoted.did);
    assert_eq!(sent.len(), 1, "{sent:?}");
    assert_eq!(sent[0]["code"], "demoted");
    assert_eq!(sent[0]["resultingRole"], "member");

    // Narrowed: an expiry put on a permanent entry.
    let narrowed = seed(&fix, VtcRole::Moderator, &[]).await;
    let (status, reply) = submit(
        &mut fix,
        &a,
        &signed(
            &a,
            UPDATE,
            json!({ "subject": narrowed.did, "expiresAt": "2099-01-01T00:00:00Z" }),
        )
        .await,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    let sent = notices(&narrowed.did);
    assert_eq!(sent.len(), 1, "{sent:?}");
    assert_eq!(sent[0]["code"], "narrowed");
    assert_eq!(sent[0]["resultingRole"], "moderator");

    // A non-administrator's reduction is not an authority reduction.
    let moderator = seed(&fix, VtcRole::Member, &[]).await;
    let (status, _) = post(
        &fix.vtc,
        &signed(&a, REVOKE, json!({ "subject": moderator.did })).await,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(notices(&moderator.did).is_empty());
}

/// Removing an administrator from the community sends the removal notice —
/// never the authority-reduced notice beside it.
#[tokio::test]
async fn vti_apv_019_an_admin_remove_sends_no_authority_reduced_notice() {
    let mut fix = fixture().await;
    let a = requester(&mut fix).await;
    store_member(&fix.vtc.state.members_ks, &Member::fresh(&a.did))
        .await
        .unwrap();
    let target = seed(&fix, VtcRole::Admin, &["ctx-a"]).await;
    store_member(&fix.vtc.state.members_ks, &Member::fresh(&target.did))
        .await
        .unwrap();
    allow_every_removal(&fix).await;
    let (status, reply) = submit(
        &mut fix,
        &a,
        &signed(&a, ADMIN_REMOVE, json!({ "did": target.did })).await,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    assert!(entry(&fix, &target.did).await.is_none());
    assert!(
        notices(&target.did).is_empty(),
        "the removal notice covers it; never both"
    );
}

// ─── VTI-APV-019 / §8.2: the two-administrator cooling-off ─────────────────

/// With nobody but requester and subject, the removal is parked for a
/// cooling-off both can see: no threshold, no expiry, lands by itself. The
/// subject is shown it coming. When it lands it is audited `Critical` and the
/// subject is sent the notice, `unopposed`.
#[tokio::test]
async fn vti_apv_019_a_two_admin_removal_cools_off_then_lands() {
    let mut fix = fixture().await;
    let a = requester(&mut fix).await;
    let b = admin(&fix).await;
    let (status, reply) = submit(
        &mut fix,
        &a,
        &signed(&a, REVOKE, json!({ "subject": b.did })).await,
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{reply}");
    let id = parked_action(&reply).expect("parked");
    assert!(
        reply["payload"]["ext"]["org.openvtc"]["coolingOffUntil"].is_string(),
        "{reply}"
    );
    assert!(entry(&fix, &b.did).await.is_some(), "nothing removed yet");
    // The subject is told now, before it lands — and nothing is reduced yet.
    let pending = pending_notices(&b.did);
    assert_eq!(pending.len(), 1, "{pending:?}");
    assert_eq!(pending[0]["actionId"], id.as_str());
    assert_eq!(pending[0]["code"], "revoked");
    assert_eq!(pending[0]["previousRole"], "admin");
    assert_eq!(pending[0]["decidedBy"], a.did.as_str());
    assert!(pending[0]["landsAt"].is_string());
    assert!(
        notices(&b.did).is_empty(),
        "the reduced notice waits for the landing"
    );

    let mine = action(&fix, &a, &id).await;
    assert_eq!(mine["category"], "approval");
    assert_eq!(mine["callerRole"], "requester");
    assert!(
        mine.get("threshold").is_none(),
        "nobody can approve: {mine}"
    );
    assert!(mine.get("expiresAt").is_none(), "it lands, never lapses");
    assert_eq!(mine["approversRemaining"], 0);
    assert!(mine["ext"]["org.openvtc"]["coolingOff"]["landsAt"].is_string());
    assert_eq!(
        list(&fix, &a, "requestedByMe").await["counts"]["requestedByMe"],
        1
    );

    // The subject sees it coming — in its list's banner data and by `show` —
    // and has nothing to decide.
    let theirs = list(&fix, &b, "waitingForMe").await;
    assert_eq!(theirs["counts"]["waitingForMe"], 0);
    let against = &theirs["ext"]["org.openvtc"]["coolingOffAgainstMe"];
    assert_eq!(against[0]["actionId"], id.as_str(), "{theirs}");
    assert_eq!(against[0]["requester"], a.did.as_str());
    let seen = action(&fix, &b, &id).await;
    assert_eq!(seen["callerRole"], "observer");
    assert!(seen.get("challenge").is_none());
    assert_eq!(seen["ext"]["org.openvtc"]["coolingOff"]["againstYou"], true);

    // Not due yet: the sweep leaves it.
    vtc_service::admin_actions::sweep_once(&fix.vtc.state)
        .await
        .unwrap();
    assert!(entry(&fix, &b.did).await.is_some());

    // 0.2 says it in the schema's own terms (trust-tasks-tf #719): category
    // `coolingOff`, `landsAt`, cancellable by the requester, no ext workaround.
    let mine = action_v0_2(&fix, &a, &id).await;
    assert_eq!(mine["category"], "coolingOff", "{mine}");
    assert_eq!(mine["callerRole"], "requester");
    assert_eq!(mine["cancellableBy"], "requester");
    assert!(mine["landsAt"].is_string());
    for absent in ["threshold", "expiresAt", "approversRemaining", "challenge"] {
        assert!(mine.get(absent).is_none(), "{absent}: {mine}");
    }
    assert!(
        mine["ext"]["org.openvtc"].get("coolingOff").is_none(),
        "{mine}"
    );
    // The subject: `callerRole: subject`, in `all`, never in `waitingForMe`.
    let seen = action_v0_2(&fix, &b, &id).await;
    assert_eq!(seen["callerRole"], "subject", "{seen}");
    assert!(seen.get("challenge").is_none());
    let waiting = list_v0_2(&fix, &b, "waitingForMe").await;
    assert_eq!(waiting["counts"]["waitingForMe"], 0);
    assert!(
        waiting["actions"].as_array().unwrap().is_empty(),
        "{waiting}"
    );
    let all = list_v0_2(&fix, &b, "all").await;
    assert!(
        all["actions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|x| x["actionId"] == id.as_str() && x["callerRole"] == "subject"),
        "{all}"
    );

    land_now(&fix, &id).await;
    assert!(entry(&fix, &b.did).await.is_none(), "landed");
    let done = action(&fix, &a, &id).await;
    assert_eq!(done["status"], "completed", "{done}");
    // 0.1 can only say `thresholdMet`; 0.2 says what happened.
    assert_eq!(done["closedReason"], "thresholdMet");
    let landed = action_v0_2(&fix, &a, &id).await;
    assert_eq!(landed["closedReason"], "landedAfterCoolingOff", "{landed}");
    assert_eq!(landed["category"], "coolingOff");
    assert!(landed.get("cancellableBy").is_none(), "closed: {landed}");
    // The subject, removed, is no administrator any more; the requester's
    // History keeps it.
    let history = list_v0_2(&fix, &a, "history").await;
    assert!(
        history["actions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|x| x["actionId"] == id.as_str() && x["closedReason"] == "landedAfterCoolingOff"),
        "{history}"
    );
    assert!(
        done["ext"]["org.openvtc"]["closedMessage"]
            .as_str()
            .unwrap()
            .contains("unopposed")
    );
    let severities: Vec<_> = audit_events(&fix)
        .await
        .into_iter()
        .filter(|e| e.event.variant_name() == "AuthorityReducedUnopposed")
        .map(|e| e.event.severity())
        .collect();
    assert_eq!(severities, vec![vti_common::audit::AuditSeverity::Critical]);
    let sent = notices(&b.did);
    assert_eq!(sent.len(), 1, "{sent:?}");
    assert_eq!(sent[0]["agreement"], "unopposed");
    assert_eq!(sent[0]["code"], "revoked");
}

/// The requester can withdraw it during the cooling-off; nothing lands.
#[tokio::test]
async fn vti_apv_019_the_requester_cancels_a_cooling_off() {
    let mut fix = fixture().await;
    let a = requester(&mut fix).await;
    let b = admin(&fix).await;
    let id = park(
        &mut fix,
        &a,
        &signed(&a, REVOKE, json!({ "subject": b.did })).await,
    )
    .await;
    // The subject cannot withdraw it.
    let (_, refused) = post(
        &fix.vtc,
        &signed(&b, CANCEL, json!({ "actionId": id })).await,
    )
    .await;
    assert_eq!(
        tt_error_code(&refused),
        Some(CANCEL_NOT_REQUESTER),
        "{refused}"
    );
    let (status, reply) = post(
        &fix.vtc,
        &signed(&a, CANCEL_V0_2, json!({ "actionId": id })).await,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    assert_conforms(CANCEL_V0_2, &reply);
    assert_eq!(
        reply["payload"]["action"]["closedReason"],
        "cancelledByRequester"
    );
    land_now(&fix, &id).await;
    assert!(entry(&fix, &b.did).await.is_some(), "nothing removed");
    assert_eq!(action(&fix, &a, &id).await["status"], "cancelled");
    // Told it was coming; never told it landed, because it did not.
    assert_eq!(pending_notices(&b.did).len(), 1);
    assert!(notices(&b.did).is_empty());
}

/// First to act wins, by suspension (§8.2): once the cooling-off is raised the
/// subject is suspended, so its answering request to remove the requester is
/// refused outright — it never gets to raise one — the earlier request keeps
/// its cooling-off, and the subject's other open actions are invalidated with
/// its authority.
#[tokio::test]
async fn vti_apv_019_the_first_of_two_administrators_to_act_wins() {
    let mut fix = fixture().await;
    let a = requester(&mut fix).await;
    let b = requester(&mut fix).await;
    // B already has an action waiting on A.
    let pending = park(
        &mut fix,
        &b,
        &signed(
            &b,
            GRANT,
            json!({ "entry": { "subject": Party::new().did, "role": "admin", "scopes": [] } }),
        )
        .await,
    )
    .await;
    let first = park(
        &mut fix,
        &a,
        &signed(&a, REVOKE, json!({ "subject": b.did })).await,
    )
    .await;

    // B answers by asking to remove A: refused, because B is suspended.
    let (status, reply) = post(
        &fix.vtc,
        &signed(&b, REVOKE, json!({ "subject": a.did })).await,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{reply}");
    assert!(
        reply.to_string().contains("suspended pending its removal"),
        "said plainly: {reply}"
    );
    assert!(entry(&fix, &a.did).await.is_some(), "the later one did not");
    assert!(entry(&fix, &b.did).await.is_some(), "the earlier one waits");
    assert_eq!(action(&fix, &a, &first).await["status"], "open");
    land_now(&fix, &first).await;
    assert!(entry(&fix, &b.did).await.is_none(), "then lands");
    assert_eq!(action(&fix, &a, &first).await["status"], "completed");
    let gone = action(&fix, &a, &pending).await;
    assert_eq!(gone["status"], "cancelled", "{gone}");
    assert_eq!(gone["closedReason"], "invalidated");
}

/// A cooling-off of zero lands the reduction at once (the stop-gap
/// behaviour), still audited `Critical` and noticed; the key is live and
/// bounded to a week.
#[tokio::test]
async fn vti_apv_019_a_zero_cooling_off_lands_at_once() {
    let mut fix = fixture().await;
    let a = requester(&mut fix).await;
    let b = admin(&fix).await;
    let (status, reply) = post(
        &fix.vtc,
        &signed(
            &a,
            PATCH,
            json!({ "overrides": { COOLING_OFF_KEY: 8 * 24 * 3600 } }),
        )
        .await,
    )
    .await;
    assert!(
        reply.to_string().contains("between 0 and 604800"),
        "{status} {reply}"
    );
    patch(&fix, &a, COOLING_OFF_KEY, json!(0)).await;
    let (status, reply) = submit(
        &mut fix,
        &a,
        &signed(&a, REVOKE, json!({ "subject": b.did })).await,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    assert!(entry(&fix, &b.did).await.is_none());
    assert_eq!(audit_count(&fix, "AuthorityReducedUnopposed").await, 1);
    assert_eq!(notices(&b.did)[0]["agreement"], "unopposed");
}

// ─── approverSigned decision evidence (VTI-APV-017 over APV-015) ───────────

/// The approver's own step-up approver vouching for their decision: accepted
/// when it is a `decision`-purpose statement over the decision's challenge and
/// digest by an approver bound to the decision's signer; refused for the wrong
/// purpose, the wrong digest, or an approver bound to nobody.
#[tokio::test]
async fn vti_apv_017_approver_signed_decision_evidence_is_verified() {
    let mut fix = fixture().await;
    let a = requester(&mut fix).await;
    let b = admin(&fix).await;
    let device = Party::new();
    vtc_service::acl::approver::bind_for_test(&fix.vtc.state, &b.did, &device.did)
        .await
        .unwrap();
    let subject = Party::new();
    let id = park(
        &mut fix,
        &a,
        &signed(
            &a,
            GRANT,
            json!({ "entry": { "subject": subject.did, "role": "admin", "scopes": [] } }),
        )
        .await,
    )
    .await;
    let shown = action(&fix, &b, &id).await;
    let base = decision_payload(&shown, "approve");
    let audience = vtc_did(&fix).await;
    let challenge = base["challenge"].clone();
    let statement = async |by: &Party, purpose: &str, bound_to: Value| {
        signed_to(
            by,
            &audience,
            ATTEST,
            json!({
                "purpose": purpose,
                "subject": b.did,
                "audience": audience,
                "challenge": challenge,
                "boundTo": bound_to,
            }),
        )
        .await
    };
    let with = |st: Value| {
        let mut p = base.clone();
        p["evidence"] = json!({ "kind": "approverSigned", "statement": st });
        p
    };
    let digest = base["payloadDigest"].clone();

    for (st, why) in [
        (
            statement(&device, "stepUp", digest.clone()).await,
            "statementInvalid",
        ),
        (
            statement(&device, "decision", json!("zNotTheDigest1234567")).await,
            "statementInvalid",
        ),
        (
            statement(&Party::new(), "decision", digest.clone()).await,
            "approverNotBound",
        ),
    ] {
        let (_, reply) = post(&fix.vtc, &signed(&b, DECISION_V0_2, with(st)).await).await;
        assert_eq!(
            tt_error_code(&reply),
            Some("task-consent/decision:evidenceInvalid"),
            "{reply}"
        );
        assert_eq!(reply["payload"]["details"]["reason"], why, "{reply}");
        assert_eq!(action(&fix, &a, &id).await["status"], "open");
    }

    let good = statement(&device, "decision", digest.clone()).await;
    let (status, ack) = post(
        &fix.vtc,
        &signed(&b, DECISION_V0_2, with(good.clone())).await,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{ack}");
    assert_eq!(ack["payload"]["status"], "granted", "{ack}");
    assert!(
        entry(&fix, &subject.did)
            .await
            .unwrap()
            .is_community_admin()
    );
    let rec = record(&fix, &id).await;
    assert_eq!(
        rec.approvals[0].evidence.as_deref(),
        Some(format!("approverSigned:{}", device.did).as_str())
    );
}

// ─── crash-safe execution (CLAUDE.md R2.1) ─────────────────────────────────

/// An action a crash left `executing`: reconciled from the effect it recorded
/// — `failed` when nothing was written, `completed` when its effect is in
/// place — never by age.
#[tokio::test]
async fn an_interrupted_execution_is_reconciled_from_its_effect() {
    let mut fix = fixture().await;
    let a = requester(&mut fix).await;
    let _b = admin(&fix).await;
    let grant = |s: &str| json!({ "entry": { "subject": s, "role": "admin", "scopes": [] } });

    // Did not land: nothing written.
    let s1 = Party::new();
    let id1 = park(&mut fix, &a, &signed(&a, GRANT, grant(&s1.did)).await).await;
    // Landed, with its effect recorded.
    let s2 = Party::new();
    let id2 = park(&mut fix, &a, &signed(&a, GRANT, grant(&s2.did)).await).await;
    // Landed in the instant before its record: the state it writes moved.
    let s3 = Party::new();
    let id3 = park(&mut fix, &a, &signed(&a, GRANT, grant(&s3.did)).await).await;

    let now = chrono::Utc::now().timestamp() as u64;
    for id in [&id1, &id2, &id3] {
        let mut rec = record(&fix, id).await;
        rec.status = vtc_service::admin_actions::Status::Executing;
        rec.executing_since = Some(now);
        rec.execution_id = Some(format!("exe-crashed-{id}"));
        put_record(&fix, &rec).await;
    }
    fix.vtc
        .state
        .admin_actions_ks
        .insert_raw(
            format!("effect:{id2}"),
            format!("exe-crashed-{id2}").into_bytes(),
        )
        .await
        .unwrap();
    store_acl_entry(&fix.vtc.state.acl_ks, &row(&s3.did, VtcRole::Admin, &[]))
        .await
        .unwrap();

    vtc_service::admin_actions::sweep_once(&fix.vtc.state)
        .await
        .unwrap();
    let one = action(&fix, &a, &id1).await;
    assert_eq!(one["status"], "failed", "{one}");
    assert!(
        one["ext"]["org.openvtc"]["closedMessage"]
            .as_str()
            .unwrap()
            .contains("nothing took effect")
    );
    assert!(entry(&fix, &s1.did).await.is_none());
    assert_eq!(action(&fix, &a, &id2).await["status"], "completed");
    assert_eq!(action(&fix, &a, &id3).await["status"], "completed");
}

/// `policy/upsert` adds a revision and moves no state pin (only `activate`
/// moves the active pointer the pin reads), so a crash between its write and
/// its effect marker used to be reconciled `failed` although the revision was
/// stored. The revision an execution writes is keyed by the action and the
/// execution, so it is its own evidence: found, the action is `completed`;
/// absent, `failed` (CLAUDE.md R2.1).
#[tokio::test]
async fn an_interrupted_policy_upsert_is_reconciled_from_its_revision() {
    use vtc_service::policy::{Policy, PolicyPurpose, store_policy};
    let mut fix = fixture().await;
    let a = requester(&mut fix).await;
    let _b = admin(&fix).await;
    let module = |name: &str| {
        json!({
            "name": name,
            "module": "package vtc.removal\nimport rego.v1\n\
                       default decision := {\"effect\": \"deny\", \"with\": {\"code\": \"frozen\"}}\n",
            "ext": { "org.openvtc.purpose": "removal" },
        })
    };
    // Its revision landed; the marker did not.
    let written = park(&mut fix, &a, &signed(&a, UPSERT, module("written")).await).await;
    // Interrupted before it wrote anything.
    let unwritten = park(&mut fix, &a, &signed(&a, UPSERT, module("unwritten")).await).await;

    let now = chrono::Utc::now().timestamp() as u64;
    for id in [&written, &unwritten] {
        let mut rec = record(&fix, id).await;
        rec.status = vtc_service::admin_actions::Status::Executing;
        rec.executing_since = Some(now);
        rec.execution_id = Some(format!("exe-crashed-{id}"));
        put_record(&fix, &rec).await;
    }
    let revision =
        vtc_service::admin_actions::policy_revision_id(&written, &format!("exe-crashed-{written}"));
    store_policy(
        &fix.vtc.state.policies_ks,
        &Policy {
            id: revision,
            purpose: PolicyPurpose::Removal,
            rego_source: "package vtc.removal\n".into(),
            sha256: [0; 32],
            activated_at: None,
            author_did: a.did.clone(),
            created_at: chrono::Utc::now(),
            version: 7,
            name: Some("written".into()),
            description: None,
        },
    )
    .await
    .unwrap();
    // No marker for either, and the pin has not moved.
    assert!(
        fix.vtc
            .state
            .admin_actions_ks
            .get_raw(format!("effect:{written}"))
            .await
            .unwrap()
            .is_none()
    );

    vtc_service::admin_actions::sweep_once(&fix.vtc.state)
        .await
        .unwrap();
    let done = action(&fix, &a, &written).await;
    assert_eq!(done["status"], "completed", "{done}");
    assert!(
        done["ext"]["org.openvtc"]["closedMessage"]
            .as_str()
            .unwrap()
            .contains("took effect"),
        "{done}"
    );
    let failed = action(&fix, &a, &unwritten).await;
    assert_eq!(failed["status"], "failed", "{failed}");
}

/// An executed `policy/upsert` stores its revision under the id derived from
/// its action and execution — the evidence reconciliation reads.
#[tokio::test]
async fn an_executed_policy_upsert_stores_its_revision_under_the_execution() {
    let mut fix = fixture().await;
    let a = requester(&mut fix).await;
    let b = admin(&fix).await;
    let doc = signed(
        &a,
        UPSERT,
        json!({
            "name": "removal",
            "module": "package vtc.removal\nimport rego.v1\n\
                       default decision := {\"effect\": \"deny\", \"with\": {\"code\": \"frozen\"}}\n",
            "ext": { "org.openvtc.purpose": "removal" },
        }),
    )
    .await;
    let id = park(&mut fix, &a, &doc).await;
    let (_, ack) = decide(&fix.vtc, &b, &id, "approve").await;
    assert_eq!(ack["payload"]["status"], "granted", "{ack}");
    let rec = record(&fix, &id).await;
    let execution = rec.execution_id.expect("persisted with its execution");
    let revision = vtc_service::admin_actions::policy_revision_id(&id, &execution);
    let stored = vtc_service::policy::get_policy(&fix.vtc.state.policies_ks, revision)
        .await
        .unwrap()
        .expect("the revision is keyed by the execution");
    assert_eq!(stored.name.as_deref(), Some("removal"));
}

/// The operation an action executes records its effect, naming the action and
/// the execution, in the audit log.
#[tokio::test]
async fn an_executed_action_records_its_effect_with_its_execution() {
    let mut fix = fixture().await;
    let a = requester(&mut fix).await;
    let b = admin(&fix).await;
    let subject = Party::new();
    let id = park(
        &mut fix,
        &a,
        &signed(
            &a,
            GRANT,
            json!({ "entry": { "subject": subject.did, "role": "admin", "scopes": [] } }),
        )
        .await,
    )
    .await;
    decide(&fix.vtc, &b, &id, "approve").await;
    let exec = record(&fix, &id).await.execution_id.expect("persisted");
    let rows: Vec<_> = audit_events(&fix)
        .await
        .into_iter()
        .filter_map(|e| match e.event {
            vti_common::audit::AuditEvent::AdminActionEffect(d) => Some(d),
            _ => None,
        })
        .collect();
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].action_id, id);
    assert_eq!(rows[0].execution_id, exec);
    assert_eq!(rows[0].task, GRANT);
}

// ─── pushes are off by default (§11.6) ─────────────────────────────────────

/// `acl.consent_request_push` is off unless the community turns it on, and a
/// `config/patch` binds it live.
#[tokio::test]
async fn consent_request_pushes_are_off_by_default_and_live() {
    let fix = fixture().await;
    let a = admin(&fix).await;
    let store = vtc_service::config_store::ConfigStore::new(fix.vtc.state.config_ks.clone());
    let cfg = fix.vtc.state.config.read().await.clone();
    assert!(
        !vtc_service::config_store::live_consent_request_push(&cfg, &store)
            .await
            .unwrap()
    );
    patch(&fix, &a, "acl.consent_request_push", json!(true)).await;
    assert!(
        vtc_service::config_store::live_consent_request_push(&cfg, &store)
            .await
            .unwrap()
    );
    let (_, refused) = post(
        &fix.vtc,
        &signed(
            &a,
            PATCH,
            json!({ "overrides": { "acl.consent_request_push": "yes" } }),
        )
        .await,
    )
    .await;
    assert!(refused.to_string().contains("true or false"), "{refused}");
}

// ─── the new administrator's approver invite (§6c, §11.4) ──────────────────

/// An action that makes an unrestricted administrator mints a step-up approver
/// invite for them on completion, shown to its requester once.
#[tokio::test]
async fn a_new_administrator_is_issued_an_approver_invite() {
    let mut fix = fixture().await;
    let a = requester(&mut fix).await;
    let b = admin(&fix).await;
    let subject = Party::new();
    let id = park(
        &mut fix,
        &a,
        &signed(
            &a,
            GRANT,
            json!({ "entry": { "subject": subject.did, "role": "admin", "scopes": [] } }),
        )
        .await,
    )
    .await;
    decide(&fix.vtc, &b, &id, "approve").await;
    let first = action(&fix, &a, &id).await;
    let invite = &first["ext"]["org.openvtc"]["approverInvite"];
    assert!(
        invite["url"].as_str().unwrap().starts_with(RP_ORIGIN),
        "{first}"
    );
    assert!(invite["claimCode"].is_string());
    assert!(invite["inviteId"].is_string());
    // Not to anyone else, and only once.
    assert!(
        action(&fix, &b, &id).await["ext"]["org.openvtc"]
            .get("approverInvite")
            .is_none()
    );
    assert!(
        action(&fix, &a, &id).await["ext"]["org.openvtc"]
            .get("approverInvite")
            .is_none(),
        "shown once"
    );
    let invited = audit_events(&fix).await.into_iter().any(|e| match e.event {
        vti_common::audit::AuditEvent::StepUpApproverChanged(d) => {
            d.stage == "invited" && d.subject == subject.did
        }
        _ => false,
    });
    assert!(invited, "the invite is audited");
}
