//! Peer identity vetting, end to end: the journey an admin, two vetters and two
//! applicants take through a community, as one runnable story.
//!
//! Read it top to bottom as documentation of the flow. Every step says who acts
//! and what crosses the wire; the assertions are what each party can rely on
//! afterwards. It runs in process against the real router, with `did:key`
//! identities throughout — the community's own DID included, so an applicant's
//! client can check the community's signatures with no network.
//!
//! 1. **The admin sets up the community**: registers the Vetting Statement
//!    type and publishes an Accepts criterion that requires two vetters, one of
//!    them in person.
//! 2. **The community names vetters**: the admin grants Carol the vetter role;
//!    a `vetterEligibility` policy that trusts members of 30 days' standing,
//!    run by the automatic-grant sweep, names Dave (and not Erin, who joined
//!    last week).
//! 3. **Vetters publish profiles**, and an applicant finds them by language,
//!    country and event dates.
//! 4. **Alice gathers statements**: for each vetter she checks the vetter's
//!    eligibility presentation (and its revocation status), shows a Vetting
//!    Card bound to that session, and receives a signed Vetting Statement she
//!    verifies against her card.
//! 5. **Alice applies**, presenting both statements and naming the
//!    requirements she gathered against (`requirementsDigest`); the community
//!    admits her, and the admin can read the vetting facts it decided on.
//! 6. **Carol withdraws her statement**; the admin sees the withdrawal touches
//!    Alice's membership (`needsReview`).
//! 7. **The admin revokes Dave's grant**: Bob, who gathered a statement from
//!    Dave before that, sees Dave's credential is now revoked, and the
//!    community no longer counts Dave's statement.
//!
//! Delivering a grant credential again over the community's messaging is the
//! second test, `a_resend_delivers_the_live_grant_credential_again`, which
//! needs the in-process DIDComm harness.

use std::sync::Arc;

use affinidi_data_integrity::{DataIntegrityProof, SignOptions};
use affinidi_tdk::secrets_resolver::secrets::Secret;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use chrono::{Duration, Utc};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;
use uuid::Uuid;
use vta_sdk::protocols::credential_exchange::{ISSUE as CREDENTIAL_ISSUE_TYPE, IssueBody};
use vta_sdk::protocols::join_requests::JOIN_REQUEST_MANIFEST_0_2_TYPE;
use vta_sdk::protocols::vetting::session::v0_1::VettingCardClaim;
use vta_sdk::protocols::vetting::{
    VETTED_PREDICATE, VETTER_ROLE_ACTION, VETTING_REVOKE_STATEMENT_TYPE, VETTING_VETTER_LIST_TYPE,
    VETTING_VETTER_PROFILE_TYPE, VettedObjectValue, VettingMethod, VettingRelationship,
};
use vta_sdk::trust_task_proof::TrustTaskVmResolver;
use vta_sdk::vetting::card::{
    CardDraft, CardExpectations, VerifiedVettingCard, new_commitment_salt, sign_card, verify_card,
};
use vta_sdk::vetting::eligibility::{
    EligibilityExpectations, build_eligibility_vp, verify_eligibility_vp,
};
use vta_sdk::vetting::requirements::requirements_digest;
use vta_sdk::vetting::statement::{IssuerScope, StatementDraft, sign_statement, verify_statement};
use vta_sdk::vetting::status::{StatusCheck, check_credential_status};
use vtc_service::acl::{VtcAclEntry, VtcRole, store_acl_entry};
use vtc_service::test_support::{MockVtcDidcomm, TestJoinClient, TestVtc};

const ACCEPTS_REGISTER_TASK: &str = "https://trusttasks.org/spec/vtc/schemas/accepts/register/0.1";
const JOIN_VETTING_SHOW_TASK: &str =
    "https://trusttasks.org/spec/vtc/join-requests/vetting/show/0.1";
const AUTO_GRANT_UPDATE_TASK: &str =
    "https://trusttasks.org/spec/vtc/vetting/auto-grant/update/0.1";
const VETTER_GRANTS_LIST_TASK: &str =
    "https://trusttasks.org/spec/vtc/vetting/vetters/grants/list/0.1";
const REVOCATIONS_LIST_TASK: &str = "https://trusttasks.org/spec/vtc/vetting/revocations/list/0.1";
const RP_ORIGIN: &str = "https://kernel-vtc.example";
const ADMIN_DID: &str = "did:key:zKernelAdmin";

const COMMUNITY_SEED: [u8; 32] = [0xC0; 32];
const CAROL_SEED: [u8; 32] = [0x11; 32];
const DAVE_SEED: [u8; 32] = [0x22; 32];
const ERIN_SEED: [u8; 32] = [0x33; 32];
const ALICE_SEED: [u8; 32] = [0xA1; 32];
const BOB_SEED: [u8; 32] = [0xB0; 32];
/// The administrator's key, for the admin verbs that are signed documents.
const ADMIN_SEED: [u8; 32] = [0xAD; 32];

const SUBMIT_TASK: &str = "https://trusttasks.org/spec/vtc/join-requests/submit/0.2";
const GRANT_TASK: &str = "https://trusttasks.org/spec/vtc/vetting/vetters/grant/0.1";
const RESEND_0_2_TASK: &str = "https://trusttasks.org/spec/vtc/vetting/vetters/resend/0.2";
const ENDORSEMENT_REVOKE_TASK: &str = "https://trusttasks.org/spec/vtc/endorsements/revoke/0.1";
const ENDORSEMENT_TYPE_REGISTER_TASK: &str =
    "https://trusttasks.org/spec/vtc/endorsement-types/register/0.1";
const POLICY_UPLOAD_TASK: &str = "https://trusttasks.org/spec/policy/upsert/0.2";
const POLICY_ACTIVATE_TASK: &str = "https://trusttasks.org/spec/policy/activate/0.1";

/// The community's own policy for naming vetters automatically: any active
/// member of at least 30 days' standing whose admission is not under review.
const TENURED_MEMBERS_VET: &str = "package vtc.vetter_eligibility\n\
import rego.v1\n\
\n\
default decision := {\"effect\": \"deny\"}\n\
\n\
decision := {\"effect\": \"allow\"} if {\n\
\tinput.status == \"active\"\n\
\tinput.underReview == false\n\
\tinput.tenureDays >= 30\n\
}\n";

// ---------------------------------------------------------------------------
// The journey
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_community_vets_applicants_through_members_it_names_vetters() {
    let community = kernel_community().await;
    let c = &community;

    // -----------------------------------------------------------------------
    // 1. The admin sets up the community.
    // -----------------------------------------------------------------------

    // Statements count only under a predicate the community accepts. The
    // registry's `vetted/1` is seeded at first boot, so registering it again
    // is the declared `exists`…
    let (_, body) = c
        .admin_document(
            ENDORSEMENT_TYPE_REGISTER_TASK,
            json!({
                "typeUri": VETTED_PREDICATE,
                "description": "A member verified this person's identity",
            }),
        )
        .await;
    assert!(
        body.to_string()
            .contains("vtc/endorsement-types/register:exists"),
        "vetted/1 is accepted out of the box: {body}"
    );

    // …and the criterion says how many a join needs. Every number is the
    // community's policy.
    let (status, body) = c
        .admin_document(
            ACCEPTS_REGISTER_TASK,
            json!({
                "id": "kernel-developer",
                "description": "Two vetters, at least one in person",
                "query": { "credentials": [ { "id": "vetting", "format": "ldp_vc",
                           "meta": { "type_values": ["StatementCredential"] } } ] },
                "vetting": {
                    "version": "0.1",
                    "statementType": VETTED_PREDICATE,
                    "minStatements": 2,
                    "minByMethod": { "inPerson": 1 },
                    "acceptedMethods": ["inPerson", "video"],
                    "requiredClaims": ["name.legal"],
                    "maxStatementAge": "P120D",
                    "eligibleVetters": { "role": "vetter" },
                    "independence": { "requireConsistentIdentityCommitment": true }
                }
            }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "vetting criterion: {body}");

    // -----------------------------------------------------------------------
    // 2. The community names its vetters.
    // -----------------------------------------------------------------------

    // Three founding members: Carol and Dave of two months' standing, Erin of
    // three days'.
    let carol = Person::new(CAROL_SEED);
    let dave = Person::new(DAVE_SEED);
    let erin = Person::new(ERIN_SEED);
    c.seed_member(&carol.did, 60).await;
    c.seed_member(&dave.did, 60).await;
    c.seed_member(&erin.did, 3).await;

    // The admin names Carol a vetter. The community issues her a revocable
    // vetter role credential and answers with the grant.
    let (status, carol_grant) = c
        .admin_document(GRANT_TASK, json!({ "memberDid": carol.did }))
        .await;
    assert_eq!(status, StatusCode::OK, "grant Carol: {carol_grant}");

    // The community's own policy names the rest: members of 30 days. The
    // sweep is off until an admin turns it on.
    c.activate_vetter_policy(TENURED_MEMBERS_VET).await;
    let (status, body) = c
        .admin_document(
            AUTO_GRANT_UPDATE_TASK,
            json!({ "enabled": true, "sweepMinutes": 60, "validitySeconds": 180 * 86_400 }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "auto-grant: {body}");
    // In production the sweep runs on its timer; here it runs once, now.
    let sweep = vtc_service::vetting::auto_grant::run_sweep(&c.state)
        .await
        .expect("sweep");
    assert_eq!(
        (sweep.granted, sweep.revoked, sweep.errors),
        (1, 0, 0),
        "Dave is granted; Carol already holds a grant; Erin is too new"
    );

    let (_, grants) = c.admin_document(VETTER_GRANTS_LIST_TASK, json!({})).await;
    let grant_of = |did: &str| {
        grants["items"]
            .as_array()
            .unwrap()
            .iter()
            .find(|g| g["memberDid"] == did)
            .cloned()
    };
    let carol_row = grant_of(&carol.did).expect("Carol's grant is listed");
    assert_eq!(
        (carol_row["origin"].as_str(), carol_row["live"].as_bool()),
        (Some("manual"), Some(true))
    );
    let dave_row = grant_of(&dave.did).expect("Dave's grant is listed");
    assert_eq!(
        (dave_row["origin"].as_str(), dave_row["live"].as_bool()),
        (Some("auto"), Some(true))
    );
    assert!(
        grant_of(&erin.did).is_none(),
        "the policy did not name Erin"
    );

    // -----------------------------------------------------------------------
    // 3. Vetters publish profiles; an applicant finds them.
    // -----------------------------------------------------------------------

    let (status, body) = c
        .post_document(
            CAROL_SEED,
            VETTING_VETTER_PROFILE_TYPE,
            json!({
                "listed": true,
                "displayName": "Carol M.",
                "languages": ["en", "de-AT"],
                "location": { "country": "AT", "city": "Vienna" },
                "methods": ["inPerson", "video"],
                "acceptsDocumentation": ["passport", "nationalId"],
                "contactHint": "Ask for a ticket at the kernel-vtc table.",
                "events": [ { "name": "Kernel Maintainers Summit",
                              "startDate": day(20), "endDate": day(22),
                              "location": { "country": "AT", "city": "Vienna" } } ]
            }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "Carol's profile: {body}");
    let (status, body) = c
        .post_document(
            DAVE_SEED,
            VETTING_VETTER_PROFILE_TYPE,
            json!({
                "listed": true,
                "displayName": "Dave L.",
                "languages": ["fr"],
                "location": { "country": "FR", "city": "Lyon" },
                "methods": ["video"],
                "acceptsDocumentation": ["passport"],
                "events": [ { "name": "Open Source Summit", "startDate": day(60), "endDate": day(61) } ]
            }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "Dave's profile: {body}");

    // Alice is not a member, but she has a DID, so she may look. Each filter
    // narrows the listing to the vetter it describes.
    for (filters, expected) in [
        (json!({ "language": "de" }), &carol.did),
        (json!({ "country": "FR" }), &dave.did),
        (
            json!({ "eventFrom": day(19), "eventTo": day(25) }),
            &carol.did,
        ),
    ] {
        let (status, body) = c
            .post_document(ALICE_SEED, VETTING_VETTER_LIST_TYPE, filters.clone())
            .await;
        assert_eq!(status, StatusCode::OK, "list {filters}: {body}");
        let listed: Vec<&str> = body["payload"]["vetters"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v["vetterDid"].as_str().unwrap())
            .collect();
        assert_eq!(listed, vec![expected.as_str()], "filters {filters}");
    }

    // -----------------------------------------------------------------------
    // 4. Alice gathers two statements.
    // -----------------------------------------------------------------------

    // She reads the requirements from manifest 0.2 and records their digest,
    // recomputing it to be sure it describes what she received.
    let (status, manifest) = c
        .post_document(ALICE_SEED, JOIN_REQUEST_MANIFEST_0_2_TYPE, json!({}))
        .await;
    assert_eq!(status, StatusCode::OK, "manifest: {manifest}");
    let criterion = &manifest["payload"]["criteria"][0];
    let digest = criterion["requirementsDigest"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(requirements_digest(criterion).unwrap(), digest);

    // One commitment salt for the whole application, so every vetter attests
    // to the same claimed identity.
    let alice = Applicant::new(ALICE_SEED, "Alice Example");

    // Before any session her client checks each vetter really is one: the
    // presentation answers her request and carries a role credential this
    // community signed, and the community's status list says it is live.
    assert!(matches!(
        c.check_vetter(&carol, &alice).await,
        StatusCheck::Active
    ));
    assert!(matches!(
        c.check_vetter(&dave, &alice).await,
        StatusCheck::Active
    ));

    // One session per vetter: Carol meets her in person, Dave on video.
    let from_carol = c
        .vetting_session(&carol, &alice, VettingMethod::InPerson)
        .await;
    let from_dave = c.vetting_session(&dave, &alice, VettingMethod::Video).await;

    // -----------------------------------------------------------------------
    // 5. Alice applies and is admitted.
    // -----------------------------------------------------------------------

    let (status, verdict) = c
        .post_document(
            ALICE_SEED,
            SUBMIT_TASK,
            json!({
                "vp": {
                    "type": "VerifiablePresentation",
                    "holder": alice.did,
                    "verifiableCredential": [from_carol.clone(), from_dave.clone()],
                },
                "registryConsent": false,
                "extensions": { "requirementsDigest": digest },
            }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "submit: {verdict}");
    assert_eq!(
        verdict["payload"]["verdict"]["effect"], "allow",
        "{verdict}"
    );
    let alice_request = verdict["payload"]["requestId"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(
        vtc_service::members::get_member(&c.state.members_ks, &alice.did)
            .await
            .unwrap()
            .is_some(),
        "Alice is a member"
    );

    // The admin reads the facts the decision rested on.
    let (status, facts) = c
        .admin_document(JOIN_VETTING_SHOW_TASK, json!({ "id": alice_request }))
        .await;
    assert_eq!(status, StatusCode::OK, "{facts}");
    let vetting = &facts["vetting"];
    assert_eq!(vetting["satisfied"], true, "{facts}");
    assert_eq!(vetting["criterionId"], "kernel-developer");
    assert_eq!(vetting["requirementsDigest"], digest.as_str());
    assert_eq!(vetting["applicantDigestMatches"], true);
    assert_eq!(vetting["distinctCountedVetters"], 2);
    assert_eq!(vetting["byMethod"], json!({ "inPerson": 1, "video": 1 }));
    assert!(
        vetting["statements"]
            .as_array()
            .unwrap()
            .iter()
            .all(|s| s["counted"] == true && s["withdrawnNow"] == false),
        "{facts}"
    );

    // -----------------------------------------------------------------------
    // 6. Carol withdraws her statement.
    // -----------------------------------------------------------------------

    // Carol names the statement by id and digest; only its signer can
    // withdraw it.
    let resolver = TrustTaskVmResolver::did_key_only();
    let carols_statement = verify_statement(&from_carol, Utc::now(), &resolver)
        .await
        .unwrap();
    let (status, body) = c
        .post_document(
            CAROL_SEED,
            VETTING_REVOKE_STATEMENT_TYPE,
            json!({
                "statementId": carols_statement.id(),
                "statementDigestMultibase": carols_statement.digest_multibase(),
                "reason": "newInformation",
            }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "withdraw: {body}");

    // The admin sees it touches a standing membership.
    let (status, revocations) = c.admin_document(REVOCATIONS_LIST_TASK, json!({})).await;
    assert_eq!(status, StatusCode::OK, "{revocations}");
    let notice = &revocations["items"][0];
    assert_eq!(notice["issuer"], carol.did.as_str());
    assert_eq!(notice["reviewState"], "needsReview");
    assert_eq!(notice["affectedMembers"], json!([alice.did]));
    assert_eq!(notice["affectedJoinRequests"], json!([alice_request]));
    let (_, facts) = c
        .admin_document(JOIN_VETTING_SHOW_TASK, json!({ "id": alice_request }))
        .await;
    let withdrawn: Vec<&str> = facts["vetting"]["statements"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|s| s["withdrawnNow"] == true)
        .map(|s| s["issuer"].as_str().unwrap())
        .collect();
    assert_eq!(withdrawn, vec![carol.did.as_str()]);

    // -----------------------------------------------------------------------
    // 7. A revoked grant stops a vetter's statement counting.
    // -----------------------------------------------------------------------

    // Bob gathers his statements while both grants stand.
    let bob = Applicant::new(BOB_SEED, "Bob Example");
    let bob_from_carol = c
        .vetting_session(&carol, &bob, VettingMethod::InPerson)
        .await;
    let bob_from_dave = c.vetting_session(&dave, &bob, VettingMethod::Video).await;

    // Then the admin withdraws Dave's grant — the automatic one — by its
    // endorsement id.
    let dave_grant = dave_row["endorsementId"].as_str().unwrap();
    let (status, body) = c
        .admin_document(
            ENDORSEMENT_REVOKE_TASK,
            json!({ "endorsementId": dave_grant }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "revoke Dave's grant: {body}");

    // Bob's client can see it: Dave's presentation still verifies, but the
    // community's status list now says his credential is revoked.
    assert!(matches!(
        c.check_vetter(&dave, &bob).await,
        StatusCheck::Revoked
    ));

    // And the community will not count Dave's statement, whenever it was
    // signed: Bob is one statement short.
    let (status, verdict) = c
        .post_document(
            BOB_SEED,
            SUBMIT_TASK,
            json!({
                "vp": {
                    "type": "VerifiablePresentation",
                    "holder": bob.did,
                    "verifiableCredential": [bob_from_carol, bob_from_dave],
                },
                "registryConsent": false,
                "extensions": { "requirementsDigest": digest },
            }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "Bob's submit: {verdict}");
    assert_eq!(
        verdict["payload"]["verdict"]["effect"], "requestMore",
        "{verdict}"
    );
    assert_eq!(
        verdict["payload"]["verdict"]["with"]["needs"],
        json!(["vetting:statements:1"])
    );
    let bob_request = verdict["payload"]["requestId"].as_str().unwrap();
    let (_, facts) = c
        .admin_document(JOIN_VETTING_SHOW_TASK, json!({ "id": bob_request }))
        .await;
    let daves = facts["vetting"]["statements"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["issuer"] == dave.did.as_str())
        .expect("Dave's statement is in the facts");
    assert_eq!(daves["counted"], false, "{facts}");
    assert_eq!(daves["eligible"], false);
    assert!(
        daves["failures"]
            .as_array()
            .unwrap()
            .contains(&json!("issuer-not-vetter")),
        "{facts}"
    );
}

/// A vetter whose wallet lost the grant credential gets the same credential
/// again — nothing new is issued — while the grant is live, and nothing once
/// it is revoked.
///
/// Delivery needs the community's messaging running, so this runs on the
/// in-process mediator harness; the vetter is a connected DIDComm peer.
#[tokio::test]
async fn a_resend_delivers_the_live_grant_credential_again() {
    let mock = MockVtcDidcomm::start().await;
    let vetter = mock.connect_registry_peer().await;
    let vetter_did = vetter.did().to_string();
    let state = &mock.vtc.state;
    let purpose = affinidi_status_list::StatusPurpose::Revocation;
    vtc_service::status_list::ensure_initial(
        &state.status_lists_ks,
        purpose,
        format!("https://vtc.test/v1/status-lists/{purpose}"),
    )
    .await
    .expect("status list");
    seed_member_row(&mock.vtc, &vetter_did, 60).await;
    // A signing-capable admin identity: the grant, the resend-on-behalf and
    // the revoke are all signed documents only, which need a `did:key` a real
    // secret backs.
    store_acl_entry(
        &mock.vtc.state.acl_ks,
        &VtcAclEntry {
            did: did_key(ADMIN_SEED).0,
            role: VtcRole::Admin,
            label: Some("signing admin".into()),
            allowed_contexts: vec![],
            created_at: vtc_service::auth::session::now_epoch(),
            created_by: "did:key:vtc-install".into(),
            updated_at: None,
            updated_by: None,
            expires_at: None,
        },
    )
    .await
    .unwrap();
    let router = &mock.vtc.router;

    // The admin names the peer a vetter; the grant credential is pushed to it.
    let (status, grant) = admin_document(
        router,
        mock.vtc_did(),
        ADMIN_SEED,
        GRANT_TASK,
        json!({ "memberDid": vetter_did }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "grant: {grant}");
    let delivered = next_issued_credential(&vetter).await;
    assert_eq!(delivered["id"], grant["credentialId"]);

    // Asked to resend on the vetter's behalf (`memberDid`), the community
    // hands the same credential to the transport again.
    let (status, resent) = admin_document(
        router,
        mock.vtc_did(),
        ADMIN_SEED,
        RESEND_0_2_TASK,
        json!({ "memberDid": vetter_did }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "resend: {resent}");
    assert_eq!(resent["credentialId"], grant["credentialId"]);
    assert_eq!(resent["validUntil"], grant["validUntil"]);
    let again = next_issued_credential(&vetter).await;
    assert_eq!(again, delivered, "the same credential, not a new one");

    // Once the grant is revoked there is nothing to resend.
    let (status, body) = admin_document(
        router,
        mock.vtc_did(),
        ADMIN_SEED,
        ENDORSEMENT_REVOKE_TASK,
        json!({ "endorsementId": grant["endorsementId"].as_str().unwrap() }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "revoke: {body}");
    // `notGranted` is a declared code, so it rides the signed door's flat 422
    // bucket, not the old admin REST route's 404.
    let (status, body) = admin_document(
        router,
        mock.vtc_did(),
        ADMIN_SEED,
        RESEND_0_2_TASK,
        json!({ "memberDid": vetter_did }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "resend after revoke: {body}"
    );

    vetter.shutdown().await;
    mock.shutdown().await;
}

// ---------------------------------------------------------------------------
// The parties
// ---------------------------------------------------------------------------

/// A member who vets: a `did:key` and its signing secret.
struct Person {
    did: String,
    key: Secret,
}

impl Person {
    fn new(seed: [u8; 32]) -> Self {
        let (did, key) = did_key(seed);
        Self { did, key }
    }
}

/// An applicant: the join DID and one commitment salt per application.
struct Applicant {
    did: String,
    key: Secret,
    legal_name: &'static str,
    salt: String,
}

impl Applicant {
    fn new(seed: [u8; 32], legal_name: &'static str) -> Self {
        let (did, key) = did_key(seed);
        Self {
            did,
            key,
            legal_name,
            salt: new_commitment_salt().expect("salt"),
        }
    }
}

/// The community under test.
struct Community {
    router: axum::Router,
    state: vtc_service::server::AppState,
    did: String,
    _vtc: TestVtc,
}

/// A community whose DID is a `did:key`, signing its credentials and status
/// lists with that key, with the default policies and status lists a daemon
/// installs at boot.
async fn kernel_community() -> Community {
    let (did, key) = did_key(COMMUNITY_SEED);
    let signer = Arc::new(vtc_service::credentials::LocalSigner::new(did.clone(), key));
    let vtc = TestVtc::builder()
        .vtc_did(did.clone())
        .with_audit(true)
        .with_public_url(RP_ORIGIN)
        .with_credential_signer(signer)
        .build()
        .await;
    vtc_service::policy::default::install_defaults(
        &vtc.state.policies_ks,
        &vtc.state.active_policies_ks,
    )
    .await
    .expect("default policies");
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
        .expect("status list");
    }
    let now = vtc_service::auth::session::now_epoch();
    store_acl_entry(
        &vtc.state.acl_ks,
        &VtcAclEntry {
            did: did_key(ADMIN_SEED).0,
            role: VtcRole::Admin,
            label: Some("kernel community admin's key".into()),
            allowed_contexts: vec![],
            created_at: now,
            created_by: "did:key:vtc-install".into(),
            updated_at: None,
            updated_by: None,
            expires_at: None,
        },
    )
    .await
    .unwrap();
    Community {
        router: vtc.router.clone(),
        state: vtc.state.clone(),
        did,
        _vtc: vtc,
    }
}

impl Community {
    /// An admin verb that is a signed document only: signed by the admin's
    /// key; the reply's status and payload.
    async fn admin_document(&self, typ: &str, payload: Value) -> (StatusCode, Value) {
        let (status, doc) = self.post_document(ADMIN_SEED, typ, payload).await;
        (status, doc["payload"].clone())
    }

    /// A Trust Task document from the holder of `seed`, addressed to this
    /// community and posted to `/v1/trust-tasks`. The holder's proof over the
    /// document is its authentication.
    async fn post_document(
        &self,
        seed: [u8; 32],
        typ: &str,
        payload: Value,
    ) -> (StatusCode, Value) {
        let (did, secret) = did_key(seed);
        // Whole seconds, `Z`: the community verifies the proof over the
        // document as it parses it, and a timestamp that does not survive that
        // round trip unchanged (`+00:00`, sub-second digits) breaks the proof.
        let now = Utc::now();
        let stamp = |t: chrono::DateTime<Utc>| t.format("%Y-%m-%dT%H:%M:%SZ").to_string();
        let mut doc = json!({
            "type": typ,
            "id": format!("urn:uuid:{}", Uuid::new_v4()),
            "issuer": did,
            "recipient": self.did,
            "issuedAt": stamp(now),
            "expiresAt": stamp(now + Duration::hours(1)),
            "payload": payload,
        });
        let proof = DataIntegrityProof::sign(&doc, &secret, SignOptions::new())
            .await
            .expect("sign document");
        doc["proof"] = serde_json::to_value(proof).unwrap();
        let req = Request::builder()
            .method("POST")
            .uri("/v1/trust-tasks")
            .header("content-type", "application/json")
            .body(Body::from(doc.to_string()))
            .unwrap();
        read(self.router.clone().oneshot(req).await.expect("oneshot")).await
    }

    /// A member admitted `days_ago`, as a founding member would be.
    async fn seed_member(&self, did: &str, days_ago: i64) {
        seed_member_row(&self._vtc, did, days_ago).await;
    }

    /// Upload `source` as the `vetterEligibility` policy and activate it.
    async fn activate_vetter_policy(&self, source: &str) {
        let (status, body) = self
            .admin_document(
                POLICY_UPLOAD_TASK,
                json!({
                    "name": "tenured-members-vet",
                    "module": source,
                    "ext": { "org.openvtc.purpose": "vetterEligibility" }
                }),
            )
            .await;
        assert!(status.is_success(), "upload policy: {body}");
        let id = body["policy"]["id"].as_str().expect("policy id");
        let (status, body) = self
            .admin_document(
                POLICY_ACTIVATE_TASK,
                json!({ "id": id, "purpose": "vetterEligibility" }),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "activate policy: {body}");
    }

    /// The applicant's pre-session check of a vetter (`vetting/request`): the
    /// vetter answers with an eligibility presentation over their grant
    /// credential; the applicant verifies it, then asks the community's status
    /// list whether the credential still stands.
    async fn check_vetter(&self, vetter: &Person, applicant: &Applicant) -> StatusCheck {
        // The request's `id` is the challenge; its `joinDid` the domain.
        let request_id = format!("urn:uuid:{}", Uuid::new_v4());

        // Vetter: present the role credential the community delivered.
        let credential = self.grant_credential(&vetter.did).await;
        let vp = build_eligibility_vp(&vetter.key, vec![credential], &request_id, &applicant.did)
            .await
            .expect("eligibility presentation");

        // Applicant: it answers this request, and the community signed it.
        let resolver = TrustTaskVmResolver::did_key_only();
        let verified = verify_eligibility_vp(
            &vp,
            &EligibilityExpectations {
                vetter: &vetter.did,
                community: &self.did,
                role: "vetter",
                challenge: &request_id,
                domain: &applicant.did,
                now: Utc::now(),
            },
            &resolver,
        )
        .await
        .expect("the vetter's eligibility presentation verifies");

        // Applicant: and it has not been revoked. The client owns the fetch;
        // here it is the community's router.
        let router = self.router.clone();
        let fetch = async |url: &str| -> Result<Value, String> {
            let path = url
                .strip_prefix(RP_ORIGIN)
                .ok_or_else(|| format!("unexpected status list URL {url}"))?;
            let req = Request::builder()
                .uri(path)
                .body(Body::empty())
                .map_err(|e| e.to_string())?;
            let res = router
                .clone()
                .oneshot(req)
                .await
                .map_err(|e| e.to_string())?;
            let (status, body) = read(res).await;
            if status.is_success() {
                Ok(body)
            } else {
                Err(format!("status list fetch {status}: {body}"))
            }
        };
        check_credential_status(
            verified
                .credential_status()
                .expect("a vetter grant carries a status entry"),
            &self.did,
            fetch,
            &resolver,
        )
        .await
    }

    /// One vetting session between `vetter` and `applicant`, returning the
    /// statement the applicant keeps.
    async fn vetting_session(
        &self,
        vetter: &Person,
        applicant: &Applicant,
        method: VettingMethod,
    ) -> Value {
        let resolver = TrustTaskVmResolver::did_key_only();
        let required = vec!["name.legal".to_string()];

        // Vetter: open the session (`vetting/session`) with a fresh challenge.
        let session_id = format!("urn:uuid:{}", Uuid::new_v4());
        let challenge = new_commitment_salt().expect("challenge");
        // The session document as the vetter sent it — what the statement
        // cites by `taskContext` and `taskDigestMultibase`.
        let session = json!({
            "id": session_id,
            "type": "https://trusttasks.org/spec/vetting/session/0.1",
            "threadId": session_id,
            "issuer": vetter.did,
            "recipient": applicant.did,
            "issuedAt": Utc::now().to_rfc3339(),
            "payload": { "method": method.to_string(), "challenge": challenge },
        });

        // Applicant: a card for this vetter and this session only.
        let card = sign_card(
            CardDraft {
                id: format!("urn:uuid:{}", Uuid::new_v4()),
                publisher: applicant.did.clone(),
                audience: vetter.did.clone(),
                community: self.did.clone(),
                challenge: challenge.clone(),
                domain: self.did.clone(),
                issued_at: Utc::now(),
                validity: Duration::minutes(15),
                claims: vec![
                    VettingCardClaim::try_from(
                        VettingCardClaim::builder()
                            .type_("name.legal")
                            .value(json!(applicant.legal_name))
                            .provenance("selfAsserted"),
                    )
                    .expect("a claim of the published shape"),
                ],
                identity_types: required.clone(),
                salt: applicant.salt.clone(),
            },
            &applicant.key,
        )
        .await
        .expect("sign card");

        // Vetter: the card is bound to them and to this session; they check
        // the person in front of them matches it, then sign the statement.
        let expectations = CardExpectations {
            audience: &vetter.did,
            publisher: &applicant.did,
            community: &self.did,
            challenge: &challenge,
            domain: &self.did,
            required_claims: &required,
            now: Utc::now(),
        };
        let checked: VerifiedVettingCard = verify_card(&card, &expectations, &resolver)
            .await
            .expect("the vetter accepts the card");
        let now = Utc::now();
        let statement = sign_statement(
            StatementDraft {
                id: format!("urn:uuid:{}", Uuid::new_v4()),
                issuer: vetter.did.clone(),
                issuer_scope: IssuerScope::Directed,
                subject: applicant.did.clone(),
                value: VettedObjectValue {
                    community: self.did.clone(),
                    method,
                    document_classes: vec!["passport".try_into().unwrap()],
                    claims_verified: vec!["name.legal".try_into().unwrap()],
                    liveness_confirmed: true,
                    identity_commitment: Some(
                        checked.card().identity_commitment.as_str().to_owned(),
                    ),
                    card_digest_multibase: Some(checked.digest_multibase().to_string()),
                    declared_relationship: Some(VettingRelationship::None),
                    attestation_text_digest: None,
                },
                valid_from: now,
                valid_until: now + Duration::days(90),
                session: session.clone(),
            },
            &vetter.key,
        )
        .await
        .expect("sign statement");

        // Applicant: the statement verifies and attests to the card she showed.
        let own_card = verify_card(&card, &expectations, &resolver).await.unwrap();
        verify_statement(&statement, Utc::now(), &resolver)
            .await
            .expect("the statement verifies")
            .check_against_card(&own_card)
            .expect("the statement is about the card the applicant showed");
        verify_statement(&statement, Utc::now(), &resolver)
            .await
            .unwrap()
            .check_against_session(&session)
            .expect("the statement cites the session it was made in");
        statement
    }

    /// The grant credential the community issued `did`, as the vetter's wallet
    /// holds it.
    async fn grant_credential(&self, did: &str) -> Value {
        vtc_service::endorsements::endorsements_for_subject(
            &self.state.endorsements_ks,
            did,
            VETTER_ROLE_ACTION,
        )
        .await
        .expect("read grants")
        .into_iter()
        .find_map(|g| g.credential)
        .expect("the grant keeps its credential")
    }
}

// ---------------------------------------------------------------------------
// Plumbing
// ---------------------------------------------------------------------------

fn did_key(seed: [u8; 32]) -> (String, Secret) {
    let mut secret = Secret::generate_ed25519(None, Some(&seed));
    let pub_mb = secret.get_public_keymultibase().expect("pubkey multibase");
    let did = format!("did:key:{pub_mb}");
    secret.id = format!("{did}#{pub_mb}");
    (did, secret)
}

fn day(offset: i64) -> String {
    (Utc::now() + Duration::days(offset))
        .format("%Y-%m-%d")
        .to_string()
}

/// A member row and ACL entry for `did`, admitted `days_ago`.
async fn seed_member_row(vtc: &TestVtc, did: &str, days_ago: i64) {
    let mut member = vtc_service::members::Member::fresh(did);
    member.joined_at = Utc::now() - Duration::days(days_ago);
    vtc_service::members::storage::store_member(&vtc.state.members_ks, &member)
        .await
        .expect("store member");
    store_acl_entry(
        &vtc.state.acl_ks,
        &VtcAclEntry {
            did: did.into(),
            role: VtcRole::Member,
            label: None,
            allowed_contexts: vec![],
            created_at: vtc_service::auth::session::now_epoch(),
            created_by: ADMIN_DID.into(),
            updated_at: None,
            updated_by: None,
            expires_at: None,
        },
    )
    .await
    .expect("store acl");
}

/// Sign `typ`/`payload` as `admin_did` (from `seed`) and post it to
/// `vtc_did`'s single Trust Task document endpoint — the free-function twin of
/// [`Community::post_document`] for a test that only has a bare `TestVtc`, not
/// the `Community` fixture.
async fn admin_document(
    router: &axum::Router,
    vtc_did: &str,
    seed: [u8; 32],
    typ: &str,
    payload: Value,
) -> (StatusCode, Value) {
    let (did, secret) = did_key(seed);
    let now = Utc::now();
    let stamp = |t: chrono::DateTime<Utc>| t.format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let mut doc = json!({
        "type": typ,
        "id": format!("urn:uuid:{}", Uuid::new_v4()),
        "issuer": did,
        "recipient": vtc_did,
        "issuedAt": stamp(now),
        "expiresAt": stamp(now + Duration::hours(1)),
        "payload": payload,
    });
    let proof = DataIntegrityProof::sign(&doc, &secret, SignOptions::new())
        .await
        .expect("sign document");
    doc["proof"] = serde_json::to_value(proof).unwrap();
    let req = Request::builder()
        .method("POST")
        .uri("/v1/trust-tasks")
        .header("content-type", "application/json")
        .body(Body::from(doc.to_string()))
        .unwrap();
    let (status, doc) = read(router.clone().oneshot(req).await.expect("oneshot")).await;
    (status, doc["payload"].clone())
}

async fn read(res: axum::response::Response) -> (StatusCode, Value) {
    let status = res.status();
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

/// The next `credential-exchange/issue` pushed to `peer`, unwrapped.
async fn next_issued_credential(peer: &TestJoinClient) -> Value {
    let (typ, body) = peer
        .next_pushed(std::time::Duration::from_secs(30))
        .await
        .expect("a credential was pushed to the vetter");
    assert_eq!(typ, CREDENTIAL_ISSUE_TYPE);
    let issue: IssueBody = serde_json::from_value(body).expect("issue body");
    issue
        .credential_response
        .expect("credential_response")
        .credential
        .expect("credential")
}

const SHOW_TASK: &str = "https://trusttasks.org/spec/vtc/vetting/vetters/show/0.1";

/// #1651 (Keyring VTI-Q3): the four answers the listing cannot give.
///
/// A vetter who never published a profile and one whose grant was revoked are
/// both simply absent from `vetters/list`, so an applicant whose vetter went
/// quiet could not tell which had happened. This asks by DID instead, and each
/// status carries the members its specification attaches to it.
#[tokio::test]
async fn a_by_did_lookup_tells_revoked_from_unlisted_from_never_a_vetter() {
    let c = &kernel_community().await;
    let carol = Person::new([0xC0; 32]);
    let stranger = Person::new([0x5A; 32]);
    c.seed_member(&carol.did, 40).await;

    let show = async |did: &str| -> Value {
        let (status, body) = c
            .admin_document(SHOW_TASK, json!({ "vetterDid": did }))
            .await;
        assert_eq!(status, StatusCode::OK, "show {did}: {body}");
        body
    };

    // Nobody this community has ever granted: `none`, and nothing to identify.
    // It says nothing about whether the DID is a member — that is not what was
    // asked, and `stranger` is not one.
    let body = show(&stranger.did).await;
    assert_eq!(body["status"], "none");
    assert_eq!(body["vetterDid"], stranger.did);
    assert!(body.get("grantId").is_none(), "nothing to identify: {body}");

    // A member who is not a vetter answers `none` too, and is indistinguishable
    // from the stranger above. That is deliberate: the caller asked about
    // vetting, so membership is not theirs to learn here.
    assert_eq!(show(&carol.did).await["status"], "none");

    // Granted: `live`, with the grant's expiry — and `listed: false`, because
    // she has published no profile. That member is the one that separates
    // "chose not to be listed" from "not a vetter", which is the whole point.
    let (status, grant) = c
        .admin_document(GRANT_TASK, json!({ "memberDid": carol.did }))
        .await;
    assert_eq!(status, StatusCode::OK, "grant Carol: {grant}");

    let body = show(&carol.did).await;
    assert_eq!(body["status"], "live");
    assert_eq!(body["listed"], false, "no profile yet: {body}");
    assert!(body["grantId"].is_string(), "{body}");
    assert!(body["validUntil"].is_string(), "{body}");
    assert!(body.get("revokedAt").is_none(), "not revoked: {body}");

    // She publishes a listed profile: still `live`, now `listed: true`.
    let (status, body) = c
        .post_document(
            [0xC0; 32],
            VETTING_VETTER_PROFILE_TYPE,
            json!({
                "listed": true,
                "languages": ["de"],
                "methods": ["inPerson"],
                "acceptsDocumentation": ["passport"],
                "events": [],
            }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "Carol's profile: {body}");
    assert_eq!(show(&carol.did).await["listed"], true);

    // The admin withdraws the grant. `revoked`, with `revokedAt` — and no
    // `listed`, which belongs to a live grant only. A client branching on the
    // members rather than the status must not read this as an expiry.
    let grant_id = show(&carol.did).await["grantId"]
        .as_str()
        .unwrap()
        .to_owned();
    let (status, body) = c
        .admin_document(
            ENDORSEMENT_REVOKE_TASK,
            json!({ "endorsementId": grant_id }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "revoke Carol's grant: {body}");

    let body = show(&carol.did).await;
    assert_eq!(body["status"], "revoked");
    assert_eq!(body["grantId"], grant_id, "the grant that was withdrawn");
    assert!(body["revokedAt"].is_string(), "{body}");
    assert!(body.get("listed").is_none(), "live-only member: {body}");
    // The reason is the community's own record and is never disclosed here.
    assert!(body.get("reason").is_none(), "{body}");

    // And the listing agrees she is gone from it, which is exactly the
    // ambiguity this task resolves: absent there, `revoked` here.
    let (status, listing) = c
        .admin_document(
            "https://trusttasks.org/spec/vtc/vetting/vetters/list/0.1",
            json!({}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "listing: {listing}");
    let listed: Vec<&str> = listing["vetters"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v["vetterDid"].as_str())
        .collect();
    assert!(!listed.contains(&carol.did.as_str()), "{listing}");
}

/// The two statuses a grant reaches without anyone calling a route, and the
/// order between them when a grant is both.
///
/// `revoked` outranks `expired` because the two say different things: one is
/// the community withdrawing trust, the other is a grant nobody renewed. A
/// vetter told `expired` would reasonably ask for a renewal; one told `revoked`
/// would not.
#[tokio::test]
async fn a_lapsed_grant_reads_expired_and_a_withdrawn_one_still_reads_revoked() {
    use vtc_service::endorsements::{Endorsement, store_endorsement};

    let c = &kernel_community().await;
    let frank = Person::new([0xF7; 32]);
    c.seed_member(&frank.did, 40).await;

    // A grant that simply ran out: written straight to the store, because
    // nothing in the API can issue one already lapsed.
    let lapsed = Endorsement {
        id: uuid::Uuid::new_v4(),
        endorsement_type: "role:vetter".into(),
        issuer_did: c.did.clone(),
        subject_did: frank.did.clone(),
        claim: json!({ "role": "vetter" }),
        status_list_index: 4001,
        credential_id: format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        created_at: Utc::now() - chrono::Duration::days(400),
        revoked_at: None,
        valid_until: Some(Utc::now() - chrono::Duration::days(35)),
        auto_granted: false,
        credential: None,
    };
    store_endorsement(&c.state.endorsements_ks, &lapsed)
        .await
        .expect("seed a lapsed grant");

    let show = async |did: &str| -> Value {
        let (status, body) = c
            .admin_document(SHOW_TASK, json!({ "vetterDid": did }))
            .await;
        assert_eq!(status, StatusCode::OK, "show {did}: {body}");
        body
    };

    let body = show(&frank.did).await;
    assert_eq!(body["status"], "expired");
    assert_eq!(body["grantId"], lapsed.id.to_string());
    assert!(body["validUntil"].is_string(), "when it ran out: {body}");
    assert!(body.get("revokedAt").is_none(), "it lapsed, not withdrawn");
    assert!(body.get("listed").is_none(), "live-only member: {body}");

    // Now a second grant, newer, withdrawn. Both are in the record and both
    // have ended, and the answer is the stronger statement.
    let withdrawn = Endorsement {
        id: uuid::Uuid::new_v4(),
        created_at: Utc::now() - chrono::Duration::days(10),
        valid_until: Some(Utc::now() - chrono::Duration::days(1)),
        revoked_at: Some(Utc::now() - chrono::Duration::days(2)),
        status_list_index: 4002,
        credential_id: format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        ..lapsed.clone()
    };
    store_endorsement(&c.state.endorsements_ks, &withdrawn)
        .await
        .expect("seed a withdrawn grant");

    let body = show(&frank.did).await;
    assert_eq!(
        body["status"], "revoked",
        "withdrawal outranks expiry: {body}"
    );
    assert_eq!(body["grantId"], withdrawn.id.to_string());
    assert!(body["revokedAt"].is_string(), "{body}");
    assert!(
        body.get("validUntil").is_none(),
        "the revocation ended it, not the expiry: {body}"
    );
}
