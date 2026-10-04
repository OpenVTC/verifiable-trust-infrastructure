//! **Single-administrator mode** — **VTI-APV-022**.
//!
//! With `[acl] single_admin_mode = true`, an operation that would wait in the
//! action list for another administrator's approval (VTI-APV-018, -020,
//! VTI-VTC-022) runs on the requester's operation-bound gesture (VTI-APV-015)
//! instead, audited at `Critical` and entered in the history marked
//! `consentWaived` — whether or not other administrators' entries exist: the
//! mode states they are all one person (VTI-APV-022). Design:
//! `docs/05-design-notes/vtc-action-list.md` §8.5.

use axum::http::StatusCode;
use serde_json::{Value, json};
use vti_common::audit::AuditEvent;
use vti_rooms_dtg::test_support::Party;

use vtc_service::acl::{VtcAclEntry, VtcRole, get_acl_entry, store_acl_entry};
use vtc_service::test_support::TestVtc;

use crate::common::second_party::{Gesturer, parked_action, step_up_request};
use crate::common::signed::{post, signed};

const RP_ORIGIN: &str = "https://vtc.example.com";
const GRANT: &str = "https://trusttasks.org/spec/acl/grant/0.1";
const REVOKE: &str = "https://trusttasks.org/spec/acl/revoke/0.1";
const PATCH: &str = "https://trusttasks.org/spec/config/patch/0.1";
const UPSERT: &str = "https://trusttasks.org/spec/policy/upsert/0.2";
const CREATE_INVITE: &str = "https://trusttasks.org/spec/vtc/admin/invites/create/0.1";
const LIST: &str = "https://trusttasks.org/spec/vtc/admin/actions/list/0.1";
const THRESHOLD_KEY: &str = "acl.unrestricted_admin_consent_threshold";

struct Fixture {
    vtc: TestVtc,
    gesturer: Gesturer,
}

async fn fixture(single_admin_mode: bool) -> Fixture {
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
    // Host configuration, as `config.toml` would set it at start.
    vtc.state.config.write().await.acl.single_admin_mode = single_admin_mode;
    Fixture {
        vtc,
        gesturer: Gesturer::new(),
    }
}

async fn admin(fix: &Fixture) -> Party {
    let party = Party::new();
    store_acl_entry(
        &fix.vtc.state.acl_ks,
        &VtcAclEntry {
            did: party.did.clone(),
            admin: vtc_service::acl::legacy_seed_authority::<&str>(&VtcRole::Admin, &[]),
            delegated_by: None,
            role: VtcRole::Admin,
            label: None,
            created_at: 0,
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
    party
}

/// The community's administrator, with a passkey to make the gesture.
async fn requester(fix: &mut Fixture) -> Party {
    let party = admin(fix).await;
    fix.gesturer.enrol(&fix.vtc, &party.did).await;
    party
}

async fn entry(fix: &Fixture, did: &str) -> Option<VtcAclEntry> {
    get_acl_entry(&fix.vtc.state.acl_ks, did).await.unwrap()
}

/// Send `doc` as `by`, answering the gesture it asks for; the reply after.
async fn submit(fix: &mut Fixture, by: &Party, doc: &Value) -> (StatusCode, Value) {
    let (status, reply) = post(&fix.vtc, doc).await;
    if step_up_request(&reply).is_none() {
        return (status, reply);
    }
    fix.gesturer.gesture(&fix.vtc, by, &reply).await;
    post(&fix.vtc, doc).await
}

async fn list(fix: &Fixture, who: &Party, view: &str) -> Value {
    let (status, reply) = post(&fix.vtc, &signed(who, LIST, json!({ "view": view })).await).await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    crate::common::signed::assert_conforms(LIST, &reply);
    reply["payload"].clone()
}

/// Every `SingleAdminMode` audit row's `event`, and its severity.
async fn mode_rows(fix: &Fixture) -> Vec<vti_common::audit::SingleAdminModeData> {
    fix.vtc
        .state
        .audit_ks
        .prefix_iter_raw(Vec::new())
        .await
        .unwrap()
        .into_iter()
        .filter_map(|(_, v)| serde_json::from_slice::<vti_common::audit::AuditEnvelope>(&v).ok())
        .filter_map(|env| match env.event {
            AuditEvent::SingleAdminMode(d) => {
                assert_eq!(
                    AuditEvent::SingleAdminMode(d.clone()).severity(),
                    vti_common::audit::AuditSeverity::Critical
                );
                Some(d)
            }
            _ => None,
        })
        .collect()
}

async fn waived(fix: &Fixture) -> Vec<vti_common::audit::SingleAdminModeData> {
    mode_rows(fix)
        .await
        .into_iter()
        .filter(|d| d.event == "consentWaived")
        .collect()
}

/// Nothing open: the operation did not park.
async fn assert_nothing_open(fix: &Fixture, who: &Party) {
    let open = list(fix, who, "requestedByMe").await;
    assert_eq!(open["actions"], json!([]), "nothing parked: {open}");
}

// ─── the sole administrator ──────────────────────────────────────────────

/// VTI-APV-022 / VTI-APV-018: in single-administrator mode the sole
/// administrator grants authority on their own operation-bound gesture — no
/// action parked, a `Critical` waiver row naming the operation, and a history
/// entry marked `consentWaived`.
#[tokio::test]
async fn vti_apv_022_a_sole_admin_grants_on_their_own_gesture() {
    let mut fix = fixture(true).await;
    let a = requester(&mut fix).await;
    let subject = Party::new();
    let doc = signed(
        &a,
        GRANT,
        json!({ "entry": { "subject": subject.did, "role": "admin", "scopes": [] } }),
    )
    .await;

    // The gesture is still asked for first (VTI-APV-015).
    let (status, reply) = post(&fix.vtc, &doc).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{reply}");
    assert!(
        step_up_request(&reply).is_some(),
        "the gesture first: {reply}"
    );
    assert!(entry(&fix, &subject.did).await.is_none());

    let (status, reply) = submit(&mut fix, &a, &doc).await;
    assert_eq!(status, StatusCode::OK, "executes at once: {reply}");
    assert!(parked_action(&reply).is_none(), "{reply}");
    assert!(
        entry(&fix, &subject.did)
            .await
            .unwrap()
            .is_community_admin()
    );
    assert_nothing_open(&fix, &a).await;

    let rows = waived(&fix).await;
    assert_eq!(rows.len(), 1, "one waiver, audited: {rows:?}");
    assert_eq!(rows[0].requirement.as_deref(), Some("VTI-APV-018"));
    assert_eq!(rows[0].task.as_deref(), Some(GRANT));
    assert!(rows[0].digest.is_some());

    // Reported to the administrator (item 3), and the operation is in the
    // history, marked.
    let history = list(&fix, &a, "history").await;
    assert_eq!(history["ext"]["org.openvtc"]["singleAdminMode"], true);
    let done = &history["actions"][0];
    assert_eq!(done["status"], "completed", "{history}");
    assert_eq!(done["kind"], "acl.grant.authority");
    assert_eq!(
        done["ext"]["org.openvtc"]["consentWaived"]["mode"], "singleAdministrator",
        "{done}"
    );
    assert!(
        done.get("threshold").is_none(),
        "nobody's threshold: {done}"
    );
}

/// VTI-APV-022 / VTI-APV-018: an administrator invite, likewise.
#[tokio::test]
async fn vti_apv_022_a_sole_admin_invites_an_administrator() {
    let mut fix = fixture(true).await;
    let a = requester(&mut fix).await;
    let invitee = Party::new();
    let (status, reply) = submit(
        &mut fix,
        &a,
        &signed(&a, CREATE_INVITE, json!({ "did": invitee.did })).await,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    assert!(
        entry(&fix, &invitee.did)
            .await
            .unwrap()
            .is_community_admin()
    );
    assert_nothing_open(&fix, &a).await;
    assert_eq!(waived(&fix).await.len(), 1);
}

/// VTI-APV-022 / VTI-APV-020: lowering the consent threshold.
#[tokio::test]
async fn vti_apv_022_a_sole_admin_lowers_the_threshold() {
    let mut fix = fixture(true).await;
    let a = requester(&mut fix).await;
    // A threshold left at 2 by a community that has since shrunk to one.
    vtc_service::config_store::ConfigStore::new(fix.vtc.state.config_ks.clone())
        .put(THRESHOLD_KEY, &json!(2))
        .await
        .unwrap();
    let (status, reply) = submit(
        &mut fix,
        &a,
        &signed(&a, PATCH, json!({ "overrides": { THRESHOLD_KEY: 1 } })).await,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    assert_eq!(
        reply["payload"]["applied"],
        json!([THRESHOLD_KEY]),
        "{reply}"
    );
    assert_eq!(
        vtc_service::acl::admin_consent::threshold(&fix.vtc.state)
            .await
            .unwrap(),
        1
    );
    assert_nothing_open(&fix, &a).await;
    let rows = waived(&fix).await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].requirement.as_deref(), Some("VTI-APV-020"));
}

/// VTI-APV-022 / VTI-VTC-022: replacing an authority-deciding policy.
#[tokio::test]
async fn vti_apv_022_a_sole_admin_changes_an_authority_policy() {
    let mut fix = fixture(true).await;
    let a = requester(&mut fix).await;
    let src = "package vtc.removal\nimport rego.v1\n\
               default decision := {\"effect\": \"deny\", \"with\": {\"code\": \"frozen\"}}\n";
    let (status, reply) = submit(
        &mut fix,
        &a,
        &signed(
            &a,
            UPSERT,
            json!({ "name": "removal", "module": src, "ext": { "org.openvtc.purpose": "removal" } }),
        )
        .await,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    assert_nothing_open(&fix, &a).await;
    let rows = waived(&fix).await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].requirement.as_deref(), Some("VTI-VTC-022"));
}

// ─── one person, many identifiers ─────────────────────────────────────────

/// VTI-APV-022: a second administrator's entry does not bring consent back —
/// the mode waives it whether or not other administrators' entries exist,
/// since one person may hold one per device. The grant runs on the
/// requester's gesture, audited at `Critical`.
#[tokio::test]
async fn vti_apv_022_a_second_admins_entry_does_not_bring_consent_back() {
    let mut fix = fixture(true).await;
    let a = requester(&mut fix).await;
    let _b = admin(&fix).await;
    let subject = Party::new();
    let (status, reply) = submit(
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
    assert_eq!(status, StatusCode::OK, "executes at once: {reply}");
    assert!(parked_action(&reply).is_none(), "{reply}");
    assert!(entry(&fix, &subject.did).await.is_some());
    assert_nothing_open(&fix, &a).await;
    assert_eq!(waived(&fix).await.len(), 1);
}

/// Without the mode, a sole administrator is refused as before, told how to
/// add a second — and the action list says the mode is off.
#[tokio::test]
async fn without_the_mode_a_sole_admin_is_refused_as_before() {
    let mut fix = fixture(false).await;
    let a = requester(&mut fix).await;
    let (status, reply) = post(
        &fix.vtc,
        &signed(
            &a,
            GRANT,
            json!({ "entry": { "subject": Party::new().did, "role": "admin", "scopes": [] } }),
        )
        .await,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{reply}");
    assert!(reply.to_string().contains("vtc acl add"), "{reply}");
    assert_eq!(
        list(&fix, &a, "all").await["ext"]["org.openvtc"]["singleAdminMode"],
        false
    );
    assert!(waived(&fix).await.is_empty());
}

/// A reduction (VTI-APV-019) keeps its cooling-off in the mode: its subject is
/// another administrator, who is told and sees it coming. The cooling-off is a
/// delay, not a consent (`vtc-action-list.md` §8.5).
#[tokio::test]
async fn vti_apv_022_a_reduction_keeps_its_cooling_off() {
    let mut fix = fixture(true).await;
    let a = requester(&mut fix).await;
    let b = admin(&fix).await;
    let (status, reply) = submit(
        &mut fix,
        &a,
        &signed(&a, REVOKE, json!({ "subject": b.did })).await,
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "cooling off: {reply}");
    assert!(parked_action(&reply).is_some(), "{reply}");
    assert!(entry(&fix, &b.did).await.is_some());
    assert!(waived(&fix).await.is_empty());
}

// ─── boot (item 4) ───────────────────────────────────────────────────────

/// VTI-APV-022 item 4: `Critical` when the mode takes effect, at every start
/// with it in effect, and when host configuration removes it.
#[tokio::test]
async fn vti_apv_022_boot_audits_the_mode_in_effect_and_its_changes() {
    let fix = fixture(false).await;
    let state = &fix.vtc.state;
    let events = |rows: Vec<vti_common::audit::SingleAdminModeData>| {
        rows.into_iter().map(|d| d.event).collect::<Vec<_>>()
    };

    // Off, never seen before: nothing to say.
    vtc_service::acl::single_admin::audit_on_boot(state)
        .await
        .unwrap();
    assert!(mode_rows(&fix).await.is_empty());

    // Turned on by the host: it takes effect, and is in effect.
    state.config.write().await.acl.single_admin_mode = true;
    vtc_service::acl::single_admin::audit_on_boot(state)
        .await
        .unwrap();
    let mut seen = events(mode_rows(&fix).await);
    seen.sort();
    assert_eq!(seen, vec!["enabled", "inEffect"]);

    // A restart with it still on: in effect again, no change.
    vtc_service::acl::single_admin::audit_on_boot(state)
        .await
        .unwrap();
    let mut seen = events(mode_rows(&fix).await);
    seen.sort();
    assert_eq!(seen, vec!["enabled", "inEffect", "inEffect"]);

    // Turned off by the host.
    state.config.write().await.acl.single_admin_mode = false;
    vtc_service::acl::single_admin::audit_on_boot(state)
        .await
        .unwrap();
    let mut seen = events(mode_rows(&fix).await);
    seen.sort();
    assert_eq!(seen, vec!["disabled", "enabled", "inEffect", "inEffect"]);
}
