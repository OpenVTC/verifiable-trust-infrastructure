//! `vtc/notifications/{list,show,relay}/0.1` through the Trust Task spine (VTI-NTF-070 – 074):
//! a community's administrators read the notifications addressed to it and decide a relay of
//! one to its members. Each refusal a task declares is driven and its code asserted (the
//! error-code census names these tests).

use std::sync::Arc;

use axum::http::StatusCode;
use chrono::{Duration, SecondsFormat, Utc};
use serde_json::{Value, json};
use vtc_service::acl::{
    AdminAuthority, AdminRole, CapabilityScope, VtcAclEntry, VtcRole, get_acl_entry,
    store_acl_entry,
};
use vtc_service::credentials::LocalSigner;
use vtc_service::policy::default::install_defaults;
use vtc_service::test_support::TestVtc;
use vti_rooms_dtg::test_support::Party;
use vti_vtn::identity::Identity;

use crate::common::second_party::{GatedAdmin, step_up_request};
use crate::common::signed::{call, error_code, post, seed_role, signed_to};

const NOTIFY: &str = "https://trusttasks.org/spec/notifications/notify/0.1";
const LIST: &str = "https://trusttasks.org/spec/vtc/notifications/list/0.1";
const SHOW: &str = "https://trusttasks.org/spec/vtc/notifications/show/0.1";
const RELAY: &str = "https://trusttasks.org/spec/vtc/notifications/relay/0.1";

const SHOW_ERR_UNKNOWN: &str = "vtc/notifications/show:notificationUnknown";
const RELAY_ERR_UNKNOWN: &str = "vtc/notifications/relay:notificationUnknown";
const RELAY_ERR_NOT_RELAYABLE: &str = "vtc/notifications/relay:notRelayable";
const RELAY_ERR_LAPSED: &str = "vtc/notifications/relay:lapsed";
const RELAY_ERR_NOT_ACKNOWLEDGED: &str = "vtc/notifications/relay:disclosureNotAcknowledged";
const RELAY_ERR_GROUP_UNKNOWN: &str = "vtc/notifications/relay:groupUnknown";

const MINE: &str = "grp_MMMMMMMMMMMMMMMMMMMMMM";
const OTHER: &str = "grp_OOOOOOOOOOOOOOOOOOOOOO";

fn tt_error_code(doc: &Value) -> &str {
    error_code(doc).unwrap_or_default()
}

struct Fixture {
    vtc: TestVtc,
    did: String,
    admin: GatedAdmin,
    originator: Party,
}

async fn fixture() -> Fixture {
    let seed = [0x52; 32];
    let did = Identity::from_ed25519_seed(&seed).did().to_string();
    let vtc = TestVtc::builder()
        .vtc_did(did.clone())
        .with_credential_signer(Arc::new(LocalSigner::from_ed25519_seed(did.clone(), &seed)))
        .with_audit(true)
        .with_public_url("https://vtc.example.com")
        .build()
        .await;
    install_defaults(&vtc.state.policies_ks, &vtc.state.active_policies_ks)
        .await
        .unwrap();
    let admin = GatedAdmin::new(&vtc).await;
    // The originator holds an ACL entry here: a party the stated policy counts (VTI-NTF-034).
    let originator = Party::new();
    seed_role(&vtc, &originator.did, VtcRole::Member, &[]).await;
    let now = Utc::now();
    for id in [MINE, OTHER] {
        let group: vtc_service::groups::Group = serde_json::from_value(json!({
            "groupId": id, "groupDid": Identity::generate().did(), "signingKeyId": "k",
            "name": id, "joinPolicy": "closed", "visibility": "members", "showMembers": "admins",
            "issuesCredentials": false, "createdAt": now, "updatedAt": now,
        }))
        .unwrap();
        vtc_service::groups::put(vtc.state.directory.ks(), &group)
            .await
            .unwrap();
    }
    Fixture {
        vtc,
        did,
        admin,
        originator,
    }
}

fn notification(id: &str, revision: u64, status: &str, relayable: bool, kind: &str) -> Value {
    json!({ "notification": {
        "notificationId": id,
        "revision": revision,
        "kind": kind,
        "subject": {
            "heldBy": "did:web:community.example",
            "id": "board-2027",
            "openWith": "https://trusttasks.org/spec/vtc/elections/show/0.6",
        },
        "audience": "did:web:partner.example",
        "status": status,
        "relayable": relayable,
        "validUntil": (Utc::now() + Duration::days(7)).to_rfc3339_opts(SecondsFormat::Secs, true),
    }})
}

impl Fixture {
    /// The originator notifies the community, over the open door; returns the record id.
    async fn notified(&self, n: Value) -> String {
        let doc = signed_to(&self.originator, &self.did, NOTIFY, n.clone()).await;
        let (status, reply) = post(&self.vtc, &doc).await;
        assert_eq!(status, StatusCode::OK, "{reply:#}");
        let id = &n["notification"]["notificationId"];
        let (_, page) = call(
            &self.vtc,
            &self.admin.requester,
            LIST,
            json!({ "includeLapsed": true }),
        )
        .await;
        page["payload"]["items"]
            .as_array()
            .unwrap()
            .iter()
            .find(|i| i["notification"]["notificationId"] == *id)
            .expect("held")["recordId"]
            .as_str()
            .unwrap()
            .to_string()
    }

    async fn as_admin(&self, type_uri: &str, payload: Value) -> (StatusCode, Value) {
        call(&self.vtc, &self.admin.requester, type_uri, payload).await
    }
}

/// An administrator holding only `entry_admin`, plus `grants` as resource grants.
async fn administrator(vtc: &TestVtc, admin: AdminAuthority, grants: &[(&str, &str)]) -> Party {
    let p = Party::new();
    let mut e = VtcAclEntry::new(&p.did, VtcRole::Member, admin, "test");
    for (capability, resource) in grants {
        e.resource_grants.push(
            serde_json::from_value(json!({
                "capability": capability,
                "resource": resource,
                "delegatedBy": "did:key:vtc-install",
                "grantedAt": "2026-10-20T00:00:00Z",
            }))
            .unwrap(),
        );
    }
    store_acl_entry(&vtc.state.acl_ks, &e).await.unwrap();
    p
}

/// An active member: an ACL entry and a member record.
async fn member(vtc: &TestVtc) -> Party {
    let p = Party::new();
    seed_role(vtc, &p.did, VtcRole::Member, &[]).await;
    let m: vtc_service::members::Member =
        serde_json::from_value(json!({ "did": p.did, "joinedAt": Utc::now().to_rfc3339() }))
            .unwrap();
    vtc_service::members::store_member(&vtc.state.members_ks, &m)
        .await
        .unwrap();
    p
}

/// VTI-NTF-070: holders of `vtc.notifications.read` list and read what the community holds —
/// with whether it may be relayed, what a relay discloses, and the document as received — and
/// nobody else does.
#[tokio::test]
async fn vti_ntf_070_administrators_list_and_read_received_notifications() {
    let f = fixture().await;
    let record = f
        .notified(notification("n-read", 1, "available", true, "election"))
        .await;
    let (_, page) = f.as_admin(LIST, json!({ "kind": "election" })).await;
    let item = &page["payload"]["items"][0];
    assert_eq!(item["recordId"], json!(record));
    assert_eq!(item["originator"], json!(f.originator.did));
    assert_eq!(item["mayRelay"], true);
    assert!(item["relayDisclosure"].is_string());
    assert_eq!(item["relayDecisions"], json!([]));

    let (status, shown) = f.as_admin(SHOW, json!({ "recordId": record })).await;
    assert_eq!(status, StatusCode::OK, "{shown:#}");
    assert_eq!(
        shown["payload"]["document"]["issuer"],
        json!(f.originator.did)
    );

    let (_, unknown) = f
        .as_admin(SHOW, json!({ "recordId": "rn-0000000000000000" }))
        .await;
    assert_eq!(tt_error_code(&unknown), SHOW_ERR_UNKNOWN);

    // A moderator holds neither capability.
    let moderator =
        administrator(&f.vtc, AdminAuthority::for_role(AdminRole::Moderator), &[]).await;
    let (_, refused) = call(&f.vtc, &moderator, LIST, json!({})).await;
    assert_eq!(tt_error_code(&refused), "permissionDenied");
}

/// VTI-NTF-071 / VTI-NTF-046: each refusal the relay declares, and the acknowledgement the
/// disclosure needs.
#[tokio::test]
async fn vti_ntf_071_a_relay_decision_is_refused_for_each_declared_reason() {
    let f = fixture().await;
    let role = json!({ "scope": "role", "role": "moderator" });

    let (_, r) = f
        .as_admin(
            RELAY,
            json!({ "recordId": "rn-0000000000000000", "recipients": role }),
        )
        .await;
    assert_eq!(tt_error_code(&r), RELAY_ERR_UNKNOWN);

    let fixed = f
        .notified(notification("n-fixed", 1, "available", false, "election"))
        .await;
    let (_, r) = f
        .as_admin(
            RELAY,
            json!({ "recordId": fixed, "recipients": role, "disclosureAcknowledged": true }),
        )
        .await;
    assert_eq!(tt_error_code(&r), RELAY_ERR_NOT_RELAYABLE);

    let gone = f
        .notified(notification("n-gone", 1, "available", true, "election"))
        .await;
    f.notified(notification("n-gone", 2, "withdrawn", true, "election"))
        .await;
    let (_, r) = f
        .as_admin(
            RELAY,
            json!({ "recordId": gone, "recipients": role, "disclosureAcknowledged": true }),
        )
        .await;
    assert_eq!(tt_error_code(&r), RELAY_ERR_LAPSED);

    let open = f
        .notified(notification("n-open", 1, "available", true, "election"))
        .await;
    let (_, r) = f
        .as_admin(RELAY, json!({ "recordId": open, "recipients": role }))
        .await;
    assert_eq!(tt_error_code(&r), RELAY_ERR_NOT_ACKNOWLEDGED);
    assert!(r["payload"]["details"]["relayDisclosure"].is_string());

    let (_, r) = f
        .as_admin(
            RELAY,
            json!({
                "recordId": open,
                "recipients": { "scope": "group", "groupId": "grp_NNNNNNNNNNNNNNNNNNNNNN" },
                "disclosureAcknowledged": true,
            }),
        )
        .await;
    assert_eq!(tt_error_code(&r), RELAY_ERR_GROUP_UNKNOWN);

    // Acknowledged: relayed to the role's active holders — nobody yet — and audited.
    let (status, ok) = f
        .as_admin(
            RELAY,
            json!({ "recordId": open, "recipients": role, "disclosureAcknowledged": true }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{ok:#}");
    assert_eq!(ok["payload"]["recipientCount"], 0);
    assert_eq!(ok["payload"]["revision"], 1);
}

/// VTI-NTF-071 / Appendix C.3: `vtc.notifications.relay` qualified by a group permits a relay
/// to that group only.
#[tokio::test]
async fn vti_ntf_071_a_group_qualified_relayer_reaches_only_its_group() {
    let f = fixture().await;
    let record = f
        .notified(notification(
            "n-grp",
            1,
            "available",
            true,
            "example.org:news",
        ))
        .await;
    // A community administrator whose relay is listed at one group only.
    let mut authority = AdminAuthority::for_role(AdminRole::CommunityAdmin);
    authority.capabilities = CapabilityScope::listed(vec![
        serde_json::from_value(json!({
            "capability": "vtc.notifications.relay",
            "resource": format!("group:{MINE}"),
        }))
        .unwrap(),
    ])
    .unwrap();
    let manager = administrator(&f.vtc, authority, &[]).await;
    assert!(
        get_acl_entry(&f.vtc.state.acl_ks, &manager.did)
            .await
            .unwrap()
            .is_some()
    );
    let to =
        |g: &str| json!({ "recordId": record, "recipients": { "scope": "group", "groupId": g } });

    let (status, ok) = call(&f.vtc, &manager, RELAY, to(MINE)).await;
    assert_eq!(status, StatusCode::OK, "{ok:#}");
    let (_, refused) = call(&f.vtc, &manager, RELAY, to(OTHER)).await;
    assert_eq!(tt_error_code(&refused), "permissionDenied");
    let (_, refused) = call(
        &f.vtc,
        &manager,
        RELAY,
        json!({ "recordId": record, "recipients": { "scope": "allMembers" } }),
    )
    .await;
    assert_eq!(tt_error_code(&refused), "permissionDenied");
}

/// VTI-NTF-074 / VTI-NTF-072 / VTI-NTF-073: a decision naming every member takes the
/// requester's step-up; it reaches the active members but never the originator, answers how
/// many it added and never whom, and a repeat adds nobody.
#[tokio::test]
async fn vti_ntf_074_relaying_to_all_members_takes_a_step_up() {
    let f = fixture().await;
    let _a = member(&f.vtc).await;
    let _b = member(&f.vtc).await;
    let record = f
        .notified(notification("n-all", 1, "available", true, "election"))
        .await;
    let all = json!({
        "recordId": record,
        "recipients": { "scope": "allMembers" },
        "disclosureAcknowledged": true,
    });

    let (_, refused) = f.as_admin(RELAY, all.clone()).await;
    assert!(
        step_up_request(&refused).is_some(),
        "a decision naming every member asks for a step-up first: {refused:#}"
    );

    let (status, ok) = f.admin.call(&f.vtc, RELAY, all.clone()).await;
    assert_eq!(status, StatusCode::OK, "{ok:#}");
    assert_eq!(ok["payload"]["recipientCount"], 2);
    assert!(
        !ok.to_string().contains(&_a.did),
        "never names whom it reached"
    );

    let (_, again) = f.admin.call(&f.vtc, RELAY, all).await;
    assert_eq!(again["payload"]["recipientCount"], 0);

    let (_, page) = f.as_admin(LIST, json!({})).await;
    let decisions = &page["payload"]["items"][0]["relayDecisions"];
    assert_eq!(decisions.as_array().unwrap().len(), 2);
    assert_eq!(decisions[0]["recipientCount"], 2);
    assert!(!page.to_string().contains(&_b.did));
}
