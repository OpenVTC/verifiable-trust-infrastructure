//! The administrator's community verbs as signed Trust Tasks
//! (`trust_tasks::community_tasks`): the community's own reads, the member
//! roster, the join queue, the relationship graph, the directory, recognition
//! checks, and invitation credentials.
//!
//! Each verb is driven through `POST /v1/trust-tasks` exactly as the console
//! sends it, and held to the same four things as `admin_verbs_spine.rs`: a
//! signed, authorized document is answered (and its answer matches the
//! published `#response` schema); an unsigned one and one from a signer the
//! community does not know are refused; a signer whose role the bearer route
//! refused is refused; and the bearer route is gone.


use axum::http::StatusCode;
use serde_json::{Value, json};
use vti_rooms_dtg::test_support::Party;

use crate::common::signed::{
    admin, bearer_route_served_as, call, error_code, party_with_role, payload, post, seed_role,
    unsigned,
};
use vtc_service::acl::VtcRole;
use vtc_service::members::{Member, store_member};
use vtc_service::test_support::{TEST_VTC_DID, TestVtc};

const PROFILE_SHOW: &str = "https://trusttasks.org/spec/vtc/community/profile/show/0.1";
const CEREMONIES_LIST: &str = "https://trusttasks.org/spec/vtc/ceremonies/list/0.1";
const DIRECTORY_QUERY: &str = "https://trusttasks.org/spec/vtc/directory/query/0.1";
const ENDORSEMENT_TYPES_LIST: &str = "https://trusttasks.org/spec/vtc/endorsement-types/list/0.1";
const RECOGNITION_CHECK: &str = "https://trusttasks.org/spec/vtc/recognition/check/0.1";
const MEMBERS_LIST: &str = "https://trusttasks.org/spec/vtc/members/list/0.1";
const MEMBERS_REMOVED: &str = "https://trusttasks.org/spec/vtc/members/removed/0.1";
const MEMBERS_SHOW: &str = "https://trusttasks.org/spec/vtc/members/show/0.1";
const MEMBERS_SOLICIT_VMC: &str = "https://trusttasks.org/spec/vtc/members/solicit-vmc/0.1";
const JOIN_REQUESTS_LIST: &str = "https://trusttasks.org/spec/vtc/join-requests/list/0.1";
const JOIN_REQUESTS_SHOW: &str = "https://trusttasks.org/spec/vtc/join-requests/show/0.1";
const RELATIONSHIPS_GRAPH: &str = "https://trusttasks.org/spec/vtc/relationships/graph/0.2";
const INVITATIONS_ISSUE: &str = "https://trusttasks.org/spec/vtc/invitations/issue/0.1";
const INVITATIONS_LIST: &str = "https://trusttasks.org/spec/vtc/invitations/list/0.1";
const INVITATIONS_REVOKE: &str = "https://trusttasks.org/spec/vtc/invitations/revoke/0.1";
const INVITATIONS_DELIVER: &str = "https://trusttasks.org/spec/vtc/invitations/deliver/0.1";

/// A current member these documents read and act on.
const TARGET: &str = "did:key:z6MkCommunityTarget";
/// Who an invitation is for.
const INVITEE: &str = "did:key:z6MkProspectiveMember";

/// A VTC every verb here can succeed on: audit (the paginated listings key
/// their cursors off it), signers (invitations), the default policies (the
/// directory), a profile, a member and a pending join request.
async fn vtc() -> (TestVtc, String) {
    let vtc = TestVtc::builder()
        .with_audit(true)
        .with_signers(true)
        .with_public_url("https://vtc.example.com")
        .build()
        .await;
    vtc_service::policy::default::install_defaults(
        &vtc.state.policies_ks,
        &vtc.state.active_policies_ks,
    )
    .await
    .expect("install default policies");
    // Issuing an invitation allocates a revocation slot.
    for purpose in [
        affinidi_status_list::StatusPurpose::Revocation,
        affinidi_status_list::StatusPurpose::Suspension,
    ] {
        let url = format!("https://vtc.example.com/v1/status-lists/{purpose}");
        vtc_service::status_list::ensure_initial(&vtc.state.status_lists_ks, purpose, url)
            .await
            .unwrap();
    }
    vtc_service::community::store_profile(
        &vtc.state.community_ks,
        &vtc_service::community::CommunityProfile::new(TEST_VTC_DID, "Example Community"),
    )
    .await
    .unwrap();
    seed_role(&vtc, TARGET, VtcRole::Member, &[]).await;
    store_member(&vtc.state.members_ks, &Member::fresh(TARGET))
        .await
        .unwrap();
    let request = vtc_service::join::JoinRequest::new("did:key:z6MkApplicant", json!({}));
    vtc_service::join::storage::store_join_request(&vtc.state.join_requests_ks, &request)
        .await
        .unwrap();
    (vtc, request.id.to_string())
}

/// Issue an invitation as `by`, returning its id.
async fn invitation(vtc: &TestVtc, by: &Party) -> String {
    let (_, doc) = call(vtc, by, INVITATIONS_ISSUE, json!({ "subjectDid": INVITEE })).await;
    payload(&doc)["vic"]["id"]
        .as_str()
        .unwrap_or_else(|| panic!("an issued invitation: {doc}"))
        .to_string()
}

/// Every moved verb, with a payload it succeeds on against [`vtc`], and the
/// least role the route admitted.
fn verbs(request_id: &str, invitation_id: &str) -> Vec<(&'static str, Value, Least)> {
    vec![
        (PROFILE_SHOW, json!({}), Least::Member),
        (CEREMONIES_LIST, json!({}), Least::Member),
        (DIRECTORY_QUERY, json!({ "subject": TARGET }), Least::Member),
        (ENDORSEMENT_TYPES_LIST, json!({}), Least::Admin),
        (
            RECOGNITION_CHECK,
            json!({ "did": "did:web:other.example" }),
            Least::Admin,
        ),
        (MEMBERS_LIST, json!({ "limit": 10 }), Least::Admin),
        (MEMBERS_REMOVED, json!({}), Least::Admin),
        (MEMBERS_SHOW, json!({ "did": TARGET }), Least::Admin),
        (
            MEMBERS_SOLICIT_VMC,
            json!({ "memberDid": TARGET }),
            Least::Admin,
        ),
        (
            JOIN_REQUESTS_LIST,
            json!({ "status": "pending" }),
            Least::Admin,
        ),
        (
            JOIN_REQUESTS_SHOW,
            json!({ "id": request_id }),
            Least::Admin,
        ),
        (RELATIONSHIPS_GRAPH, json!({}), Least::Admin),
        (
            INVITATIONS_ISSUE,
            json!({ "subjectDid": INVITEE }),
            Least::Inviter,
        ),
        (INVITATIONS_LIST, json!({}), Least::Inviter),
        (
            INVITATIONS_REVOKE,
            json!({ "id": invitation_id }),
            Least::Inviter,
        ),
        (
            INVITATIONS_DELIVER,
            json!({ "id": invitation_id, "channel": "offer" }),
            Least::Inviter,
        ),
    ]
}

/// The least role a verb's route admitted.
#[derive(Clone, Copy, PartialEq)]
enum Least {
    /// Any entry.
    Member,
    /// `Admin`, `Moderator` or `Issuer`.
    Inviter,
    /// `Admin`.
    Admin,
}

/// A VTC of its own per verb: `revoke` would leave nothing for `deliver`.
#[tokio::test]
async fn every_moved_verb_answers_an_authorized_signer() {
    for i in 0..verbs("", "").len() {
        let (vtc, request_id) = vtc().await;
        let admin = admin(&vtc).await;
        let needs_invitation =
            matches!(verbs("", "")[i].0, INVITATIONS_REVOKE | INVITATIONS_DELIVER);
        let invitation_id = if needs_invitation {
            invitation(&vtc, &admin).await
        } else {
            String::new()
        };
        let (uri, body, _) = verbs(&request_id, &invitation_id).swap_remove(i);
        if uri == MEMBERS_SOLICIT_VMC {
            // Its success is a push to the member, which this fixture has no
            // route to; `solicit_vmc_reaches_the_member_push` holds it.
            continue;
        }
        let (status, doc) = call(&vtc, &admin, uri, body).await;
        assert_eq!(status, StatusCode::OK, "{uri}: {doc}");
        assert_eq!(error_code(&doc), None, "{uri}: {doc}");
        assert!(
            doc.get("proof").is_some(),
            "{uri}: the answer is signed: {doc}"
        );
    }
}

/// The reads any entry may make, and the inviter verbs a `Moderator` may send,
/// answer those members too — the parties their routes' handlers admitted.
#[tokio::test]
async fn the_member_and_inviter_verbs_answer_those_members() {
    let (vtc, request_id) = vtc().await;
    let member = party_with_role(&vtc, VtcRole::Member, &[]).await;
    let moderator = party_with_role(&vtc, VtcRole::Moderator, &[]).await;
    for (uri, body, least) in verbs(&request_id, "x") {
        let by = match least {
            Least::Member => &member,
            Least::Inviter if uri == INVITATIONS_LIST => &moderator,
            _ => continue,
        };
        let (_, doc) = call(&vtc, by, uri, body).await;
        assert_eq!(error_code(&doc), None, "{uri}: {doc}");
    }
}

/// A `Moderator` or `Issuer` manages only the invitations it issued: another
/// inviter's (an administrator's here) is absent from its list, and revoking
/// or delivering it is refused exactly as an invitation that does not exist
/// is. It cannot confer a role by invitation either. An administrator sees
/// and acts on every invitation.
#[tokio::test]
async fn an_inviter_below_admin_manages_only_its_own_invitations() {
    let (vtc, _) = vtc().await;
    let admin = admin(&vtc).await;
    let unknown = "urn:uuid:00000000-0000-4000-8000-000000000000";
    for role in [VtcRole::Moderator, VtcRole::Issuer] {
        let inviter = party_with_role(&vtc, role.clone(), &[]).await;
        let theirs = invitation(&vtc, &admin).await;
        let own = {
            let (_, doc) = call(
                &vtc,
                &inviter,
                INVITATIONS_ISSUE,
                json!({ "subjectDid": format!("{INVITEE}{role}") }),
            )
            .await;
            payload(&doc)["vic"]["id"]
                .as_str()
                .unwrap_or_else(|| panic!("{role}: an issued invitation: {doc}"))
                .to_string()
        };

        let ids = |doc: &Value| -> Vec<String> {
            payload(doc)["invitations"]
                .as_array()
                .unwrap_or_else(|| panic!("a list: {doc}"))
                .iter()
                .map(|i| i["id"].as_str().unwrap().to_string())
                .collect()
        };
        let (_, doc) = call(&vtc, &inviter, INVITATIONS_LIST, json!({})).await;
        assert_eq!(ids(&doc), vec![own.clone()], "{role}: {doc}");
        let (_, doc) = call(&vtc, &admin, INVITATIONS_LIST, json!({})).await;
        let all = ids(&doc);
        assert!(all.contains(&own) && all.contains(&theirs), "{doc}");

        let refusal = |doc: &Value| {
            (
                payload(doc)["code"].clone(),
                payload(doc)["details"]["reason"].clone(),
            )
        };
        for (uri, extra) in [
            (INVITATIONS_REVOKE, json!({})),
            (INVITATIONS_DELIVER, json!({ "channel": "offer" })),
        ] {
            let with = |id: &str| {
                let mut body = extra.clone();
                body["id"] = json!(id);
                body
            };
            let (_, foreign) = call(&vtc, &inviter, uri, with(&theirs)).await;
            let (_, missing) = call(&vtc, &inviter, uri, with(unknown)).await;
            assert!(error_code(&foreign).is_some(), "{role} {uri}: {foreign}");
            assert_eq!(
                refusal(&foreign),
                refusal(&missing),
                "{role} {uri}: another inviter's invitation must read as absent"
            );
        }
        // Still live: the refused revoke did nothing, so the admin can deliver it.
        let (_, doc) = call(
            &vtc,
            &admin,
            INVITATIONS_DELIVER,
            json!({ "id": theirs, "channel": "offer" }),
        )
        .await;
        assert_eq!(error_code(&doc), None, "{doc}");
        // Its own it may revoke.
        let (_, doc) = call(&vtc, &inviter, INVITATIONS_REVOKE, json!({ "id": own })).await;
        assert_eq!(error_code(&doc), None, "{role}: {doc}");

        for granted in ["moderator", "issuer", "custom:editor"] {
            let (_, doc) = call(
                &vtc,
                &inviter,
                INVITATIONS_ISSUE,
                json!({ "subjectDid": format!("{INVITEE}{role}x"), "role": granted }),
            )
            .await;
            assert_eq!(
                error_code(&doc),
                Some("permissionDenied"),
                "{role} granting {granted}: {doc}"
            );
        }
    }
}

#[tokio::test]
async fn every_moved_verb_refuses_an_unsigned_document() {
    let (vtc, request_id) = vtc().await;
    let admin = admin(&vtc).await;
    for (uri, body, _) in verbs(&request_id, "urn:uuid:00000000-0000-0000-0000-000000000000") {
        let (_, doc) = post(&vtc, &unsigned(&admin, uri, body)).await;
        assert_eq!(error_code(&doc), Some("proofRequired"), "{uri}: {doc}");
    }
}

#[tokio::test]
async fn every_moved_verb_refuses_a_signer_the_community_does_not_know() {
    let (vtc, request_id) = vtc().await;
    let stranger = Party::new();
    for (uri, body, _) in verbs(&request_id, "urn:uuid:00000000-0000-0000-0000-000000000000") {
        let (_, doc) = call(&vtc, &stranger, uri, body).await;
        assert_eq!(error_code(&doc), Some("permissionDenied"), "{uri}: {doc}");
    }
}

/// A member is refused the administrator's verbs and the inviter verbs.
#[tokio::test]
async fn the_admin_and_inviter_verbs_refuse_a_member() {
    let (vtc, request_id) = vtc().await;
    let member = party_with_role(&vtc, VtcRole::Member, &[]).await;
    for (uri, body, least) in verbs(&request_id, "urn:uuid:00000000-0000-0000-0000-000000000000") {
        if least == Least::Member {
            continue;
        }
        let (_, doc) = call(&vtc, &member, uri, body).await;
        assert_eq!(error_code(&doc), Some("permissionDenied"), "{uri}: {doc}");
    }
}

/// A `Moderator` may invite but not run the administrator's reads.
#[tokio::test]
async fn the_admin_verbs_refuse_a_moderator() {
    let (vtc, request_id) = vtc().await;
    let moderator = party_with_role(&vtc, VtcRole::Moderator, &[]).await;
    for (uri, body, least) in verbs(&request_id, "x") {
        if least != Least::Admin {
            continue;
        }
        let (_, doc) = call(&vtc, &moderator, uri, body).await;
        assert_eq!(error_code(&doc), Some("permissionDenied"), "{uri}: {doc}");
    }
}

#[tokio::test]
async fn the_bearer_routes_are_gone() {
    let (vtc, request_id) = vtc().await;
    for (method, path, task) in [
        ("GET", "/v1/community/profile".to_string(), PROFILE_SHOW),
        ("GET", "/v1/ceremonies".to_string(), CEREMONIES_LIST),
        ("GET", format!("/v1/directory/{TARGET}"), DIRECTORY_QUERY),
        (
            "GET",
            "/v1/endorsement-types".to_string(),
            ENDORSEMENT_TYPES_LIST,
        ),
        (
            "GET",
            "/v1/recognition/check?did=did:web:x".to_string(),
            RECOGNITION_CHECK,
        ),
        ("GET", "/v1/members/removed".to_string(), MEMBERS_REMOVED),
        ("GET", format!("/v1/members/{TARGET}"), MEMBERS_SHOW),
        (
            "POST",
            format!("/v1/members/{TARGET}/request-vmc"),
            MEMBERS_SOLICIT_VMC,
        ),
        (
            "GET",
            format!("/v1/join-requests/{request_id}"),
            JOIN_REQUESTS_SHOW,
        ),
        (
            "GET",
            "/v1/relationships/graph".to_string(),
            RELATIONSHIPS_GRAPH,
        ),
        ("POST", "/v1/invitations".to_string(), INVITATIONS_ISSUE),
        ("GET", "/v1/invitations".to_string(), INVITATIONS_LIST),
        (
            "DELETE",
            "/v1/invitations/urn:uuid:x".to_string(),
            INVITATIONS_REVOKE,
        ),
        (
            "POST",
            "/v1/invitations/deliver".to_string(),
            INVITATIONS_DELIVER,
        ),
    ] {
        assert!(
            !bearer_route_served_as(&vtc, method, &path, task).await,
            "{method} {path} is still served"
        );
    }
}

/// The member and join-request listings have no bearer route either.
#[tokio::test]
async fn the_listings_have_no_bearer_route() {
    let (vtc, _) = vtc().await;
    assert!(!bearer_route_served_as(&vtc, "GET", "/v1/members", MEMBERS_LIST).await);
    assert!(!bearer_route_served_as(&vtc, "GET", "/v1/join-requests", JOIN_REQUESTS_LIST).await);
}

/// An issued invitation carries a bearer credential, and a delivered offer a
/// code: the duplicate-execution record keeps neither, so a redelivered
/// document is answered without them.
#[tokio::test]
async fn a_redelivered_issue_does_not_hand_the_credential_out_again() {
    let (vtc, _) = vtc().await;
    let admin = admin(&vtc).await;
    let doc =
        crate::common::signed::signed(&admin, INVITATIONS_ISSUE, json!({ "subjectDid": INVITEE })).await;
    let (status, first) = post(&vtc, &doc).await;
    assert_eq!(status, StatusCode::OK, "{first}");
    assert!(payload(&first)["vic"].is_object(), "{first}");
    let (status, again) = post(&vtc, &doc).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{again}");
}

/// `solicit-vmc` authorizes an administrator and runs the operation: an
/// unknown member is the task's declared `notFound`, and a current one gets as
/// far as the push, which this fixture's member advertises no transport for.
#[tokio::test]
async fn solicit_vmc_reaches_the_member_push() {
    let (vtc, _) = vtc().await;
    let admin = admin(&vtc).await;
    let (_, doc) = call(
        &vtc,
        &admin,
        MEMBERS_SOLICIT_VMC,
        json!({ "memberDid": "did:key:z6MkNotAMember" }),
    )
    .await;
    assert_eq!(
        error_code(&doc),
        Some(trust_tasks_rs::specs::vtc::members::solicit_vmc::v0_1::error_codes::NOT_FOUND.code),
        "{doc}"
    );
    let (_, doc) = call(
        &vtc,
        &admin,
        MEMBERS_SOLICIT_VMC,
        json!({ "memberDid": TARGET }),
    )
    .await;
    assert!(
        doc["payload"]["message"]
            .as_str()
            .is_some_and(|m| m.contains("no matching protocol")),
        "the push was attempted: {doc}"
    );
}
