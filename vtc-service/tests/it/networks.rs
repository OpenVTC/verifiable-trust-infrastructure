//! `vtc/networks/*` through the Trust Task spine, against a fake Verifiable Trust Network
//! that checks every signature the community sends. Each refusal a task declares is driven
//! and its code asserted (the error-code census names these tests).

use std::sync::Arc;

use axum::extract::State as AxState;
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{Duration, Utc};
use serde_json::{Value, json};
use tokio::sync::Mutex;
use vtc_service::credentials::LocalSigner;
use vtc_service::policy::default::install_defaults;
use vtc_service::test_support::TestVtc;
use vti_vtn::credentials::{listing_vsc, membership_offer};
use vti_vtn::identity::Identity;
use vti_vtn::model::{EntryKind, Framework};
use vti_vtn::status::credential_status;
use vti_vtn::verify::{
    AUTHENTICATION, LocalDidKeyResolver, verify_acknowledgement, verify_document,
    verify_repudiation,
};

use crate::common::second_party::GatedAdmin;

const JOIN: &str = "https://trusttasks.org/spec/vtc/networks/join/0.1";
const REPUDIATE: &str = "https://trusttasks.org/spec/vtc/networks/repudiate/0.1";
const LEAVE: &str = "https://trusttasks.org/spec/vtc/networks/leave/0.1";
const REGISTER: &str = "https://trusttasks.org/spec/vtc/networks/groups/register/0.1";
const SHOW: &str = "https://trusttasks.org/spec/vtc/networks/show/0.1";

const JOIN_ERR_NOT_LISTED: &str = "vtc/networks/join:notListed";
const JOIN_ERR_NETWORK_MISMATCH: &str = "vtc/networks/join:networkMismatch";
const JOIN_ERR_ROLE_UNASSIGNED: &str = "vtc/networks/join:roleUnassigned";
const JOIN_ERR_UNKNOWN_GROUP: &str = "vtc/networks/join:unknownGroup";
const JOIN_ERR_NETWORK_REFUSED: &str = "vtc/networks/join:networkRefused";
const REPUDIATE_ERR_NOT_LISTED: &str = "vtc/networks/repudiate:notListed";
const REPUDIATE_ERR_NETWORK_MISMATCH: &str = "vtc/networks/repudiate:networkMismatch";
const REPUDIATE_ERR_IS_MEMBER: &str = "vtc/networks/repudiate:isMember";
const REPUDIATE_ERR_NETWORK_REFUSED: &str = "vtc/networks/repudiate:networkRefused";
const LEAVE_ERR_NOT_MEMBER: &str = "vtc/networks/leave:notMember";
const LEAVE_ERR_NETWORK_REFUSED: &str = "vtc/networks/leave:networkRefused";
const REGISTER_ERR_NOT_MEMBER: &str = "vtc/networks/groups/register:notMember";
const REGISTER_ERR_UNKNOWN_GROUP: &str = "vtc/networks/groups/register:unknownGroup";
const REGISTER_ERR_NETWORK_REFUSED: &str = "vtc/networks/groups/register:networkRefused";

fn tt_error_code(body: &Value) -> &str {
    body["payload"]["code"].as_str().unwrap_or_default()
}

#[derive(Default, Clone, Copy)]
struct Refuse {
    session: bool,
    groups: bool,
    repudiate: bool,
}

struct Net {
    identity: Identity,
    required: bool,
    refuse: Refuse,
    listing: Value,
    offer: dtg_credentials::DTGCredential,
    grant: Option<Value>,
    has_admins: bool,
}

type Shared = Arc<Mutex<Net>>;

async fn fake_network(community: &str, required: bool) -> (String, String, Shared) {
    let identity = Identity::generate();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let at = Utc::now() - Duration::seconds(60);
    let mut listing = listing_vsc(
        identity.did(),
        community,
        EntryKind::Community,
        &Framework {
            iri: format!("{url}/gf"),
            version: "1.0".into(),
        },
        at,
        credential_status(&url, 0),
    )
    .unwrap();
    identity.sign_credential(&mut listing).await.unwrap();
    let offer = membership_offer(
        identity.did(),
        community,
        at,
        Some(at + Duration::days(30)),
        json!([]),
    );
    let did = identity.did().to_string();
    let shared: Shared = Arc::new(Mutex::new(Net {
        identity,
        required,
        refuse: Refuse::default(),
        listing: serde_json::to_value(listing).unwrap(),
        offer,
        grant: None,
        has_admins: false,
    }));

    async fn profile(AxState(s): AxState<Shared>) -> Json<Value> {
        let n = s.lock().await;
        Json(
            json!({ "did": n.identity.did(), "profile": { "name": "WHN" },
                     "roles": [{ "name": "admins", "required": n.required }] }),
        )
    }
    /// `vtn/*` Trust Tasks, answered as a network does: the request's proof must be its
    /// issuer's, for `authentication`, addressed to this network. `refuse.session` refuses
    /// the community outright, as a network that does not list it.
    /// Every answer signed by the network for `authentication`, as the spine signs it.
    async fn tasks(AxState(s): AxState<Shared>, doc: Json<Value>) -> (StatusCode, Json<Value>) {
        let identity = s.lock().await.identity.clone();
        let (status, Json(answer)) = answer(AxState(s), doc).await;
        let signed = identity
            .sign_document_for(answer, AUTHENTICATION)
            .await
            .unwrap();
        (status, Json(signed))
    }

    async fn answer(
        AxState(s): AxState<Shared>,
        Json(doc): Json<Value>,
    ) -> (StatusCode, Json<Value>) {
        let mut n = s.lock().await;
        let me = n.identity.did().to_string();
        let issuer = doc["issuer"].as_str().unwrap_or_default().to_string();
        let kind = doc["type"].as_str().unwrap_or_default().to_string();
        let slug = kind
            .trim_start_matches("https://trusttasks.org/spec/")
            .rsplit_once('/')
            .map(|(s, _)| s.to_string())
            .unwrap_or_default();
        let answer = |payload: Value| {
            (
                StatusCode::OK,
                Json(json!({
                    "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
                    "type": format!("{kind}#response"),
                    "issuer": me,
                    "recipient": issuer,
                    "threadId": doc["id"],
                    "issuedAt": Utc::now(),
                    "payload": payload,
                })),
            )
        };
        let refuse = |code: &str| {
            (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(json!({
                    "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
                    "type": "https://trusttasks.org/spec/trust-task-error/0.6",
                    "issuer": me,
                    "threadId": doc["id"],
                    "payload": { "code": code, "message": code },
                })),
            )
        };
        if n.refuse.session
            || doc["recipient"].as_str() != Some(me.as_str())
            || verify_document(&doc, &issuer, AUTHENTICATION, &LocalDidKeyResolver)
                .await
                .is_err()
        {
            return refuse("permissionDenied");
        }
        let entry = |n: &Net, state: &str| {
            let mut e = json!({
                "did": issuer, "kind": "community", "state": state,
                "acknowledged": state == "acknowledged", "profile": {}, "listing": n.listing,
            });
            if let Some(g) = &n.grant {
                e["grant"] = g.clone();
            }
            e
        };
        let p = doc["payload"].clone();
        match slug.as_str() {
            "vtn/entries/show" => {
                let state = if n.grant.is_some() {
                    "acknowledged"
                } else {
                    "listed"
                };
                answer(json!({ "entry": entry(&n, state) }))
            }
            "vtn/membership/offer" => {
                answer(json!({ "offer": serde_json::to_value(&n.offer).unwrap() }))
            }
            "vtn/groups/register" => {
                if n.refuse.groups {
                    return refuse("vtn/groups/register:unknownRole");
                }
                let Ok(reg) = vti_vtn::groups::verify_registration(
                    &doc,
                    &issuer,
                    &me,
                    &LocalDidKeyResolver,
                    Utc::now(),
                )
                .await
                else {
                    return refuse("malformedRequest");
                };
                let mut acc = vti_vtn::groups::acceptance(
                    &me,
                    &reg.group,
                    &doc,
                    Utc::now() - Duration::seconds(30),
                    json!([]),
                )
                .unwrap();
                n.identity.sign_credential(&mut acc).await.unwrap();
                n.has_admins |= reg.role == "admins";
                answer(json!({ "group": {
                    "member": issuer, "role": reg.role, "group": reg.group,
                    "endpoint": reg.endpoint, "registration": doc, "acceptance": acc,
                    "registeredAt": Utc::now(),
                } }))
            }
            "vtn/membership/acknowledge" => {
                if n.required && !n.has_admins {
                    return refuse("vtn/membership/acknowledge:rolesUnregistered");
                }
                if verify_acknowledgement(
                    &p["acknowledgement"],
                    &n.offer,
                    &issuer,
                    &LocalDidKeyResolver,
                    Utc::now(),
                )
                .await
                .is_err()
                {
                    return refuse("vtn/membership/acknowledge:acknowledgementInvalid");
                }
                let mut grant = n.offer.clone();
                n.identity.sign_credential(&mut grant).await.unwrap();
                n.grant = Some(serde_json::to_value(grant).unwrap());
                answer(json!({ "entry": entry(&n, "acknowledged") }))
            }
            "vtn/membership/repudiate" => {
                if n.refuse.repudiate {
                    return refuse("vtn/membership/repudiate:repudiationInvalid");
                }
                if verify_repudiation(
                    &p["repudiation"],
                    &issuer,
                    &me,
                    &n.listing,
                    n.grant.as_ref(),
                    &LocalDidKeyResolver,
                    Utc::now(),
                )
                .await
                .is_err()
                {
                    return refuse("vtn/membership/repudiate:repudiationInvalid");
                }
                answer(json!({ "entry": entry(&n, "repudiated") }))
            }
            _ => refuse("unsupportedType"),
        }
    }

    let app = Router::new()
        .route("/.well-known/vtn", get(profile))
        .route(vti_vtn::tasks::TRUST_TASKS_PATH, post(tasks))
        .with_state(shared.clone());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (url, did, shared)
}

struct Fixture {
    vtc: TestVtc,
    admin: GatedAdmin,
    did: String,
}

async fn fixture() -> Fixture {
    let seed = [0x51; 32];
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
    // A group with a DID of its own, to serve the network's admins.
    let now = Utc::now();
    let group: vtc_service::groups::Group = serde_json::from_value(json!({
        "groupId": "admins", "groupDid": Identity::generate().did(), "signingKeyId": "k",
        "name": "Admins", "joinPolicy": "closed", "visibility": "members", "showMembers": "admins",
        "issuesCredentials": true, "createdAt": now, "updatedAt": now,
    }))
    .unwrap();
    vtc_service::groups::put(vtc.state.directory.ks(), &group)
        .await
        .unwrap();
    Fixture { vtc, admin, did }
}

impl Fixture {
    async fn call(&self, type_uri: &str, payload: Value) -> (StatusCode, Value) {
        self.admin.call(&self.vtc, type_uri, payload).await
    }
}

fn admins() -> Value {
    json!([{ "role": "admins", "groupId": "admins" }])
}

#[tokio::test]
async fn join_refusals_say_why() {
    let f = fixture().await;
    let (url, network, net) = fake_network(&f.did, true).await;

    let (_, r) = f
        .call(
            JOIN,
            json!({ "url": url, "network": "did:key:z6MkOther", "groups": admins() }),
        )
        .await;
    assert_eq!(tt_error_code(&r), JOIN_ERR_NETWORK_MISMATCH, "{r}");
    let (_, r) = f
        .call(JOIN, json!({ "url": url, "network": network }))
        .await;
    assert_eq!(tt_error_code(&r), JOIN_ERR_ROLE_UNASSIGNED, "{r}");
    assert_eq!(r["payload"]["details"]["role"], "admins");
    let (_, r) = f.call(JOIN, json!({ "url": url, "network": network, "groups": [{ "role": "admins", "groupId": "nope" }] })).await;
    assert_eq!(tt_error_code(&r), JOIN_ERR_UNKNOWN_GROUP, "{r}");

    net.lock().await.refuse.session = true;
    let (_, r) = f
        .call(
            JOIN,
            json!({ "url": url, "network": network, "groups": admins() }),
        )
        .await;
    assert_eq!(tt_error_code(&r), JOIN_ERR_NOT_LISTED, "{r}");
    net.lock().await.refuse = Refuse {
        groups: true,
        ..Refuse::default()
    };
    let (_, r) = f
        .call(
            JOIN,
            json!({ "url": url, "network": network, "groups": admins() }),
        )
        .await;
    assert_eq!(tt_error_code(&r), JOIN_ERR_NETWORK_REFUSED, "{r}");

    net.lock().await.refuse = Refuse::default();
    let (status, r) = f
        .call(
            JOIN,
            json!({ "url": url, "network": network, "groups": admins() }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{r}");
    assert_eq!(r["payload"]["membership"]["state"], "acknowledged");
    let (status, r) = f.call(SHOW, json!({ "network": network })).await;
    assert_eq!(status, StatusCode::OK, "{r}");
    assert_eq!(r["payload"]["membership"]["groups"][0]["role"], "admins");
}

#[tokio::test]
async fn repudiate_refusals_say_why() {
    let f = fixture().await;
    let (url, network, net) = fake_network(&f.did, false).await;

    let (_, r) = f
        .call(
            REPUDIATE,
            json!({ "url": url, "network": "did:key:z6MkOther" }),
        )
        .await;
    assert_eq!(tt_error_code(&r), REPUDIATE_ERR_NETWORK_MISMATCH, "{r}");
    net.lock().await.refuse.session = true;
    let (_, r) = f
        .call(REPUDIATE, json!({ "url": url, "network": network }))
        .await;
    assert_eq!(tt_error_code(&r), REPUDIATE_ERR_NOT_LISTED, "{r}");
    net.lock().await.refuse = Refuse {
        repudiate: true,
        ..Refuse::default()
    };
    let (_, r) = f
        .call(REPUDIATE, json!({ "url": url, "network": network }))
        .await;
    assert_eq!(tt_error_code(&r), REPUDIATE_ERR_NETWORK_REFUSED, "{r}");

    net.lock().await.refuse = Refuse::default();
    let (status, r) = f
        .call(
            JOIN,
            json!({ "url": url, "network": network, "groups": admins() }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{r}");
    let (_, r) = f
        .call(REPUDIATE, json!({ "url": url, "network": network }))
        .await;
    assert_eq!(tt_error_code(&r), REPUDIATE_ERR_IS_MEMBER, "{r}");
}

#[tokio::test]
async fn leave_and_register_refusals_say_why() {
    let f = fixture().await;
    let (url, network, net) = fake_network(&f.did, false).await;

    let (_, r) = f.call(LEAVE, json!({ "network": network })).await;
    assert_eq!(tt_error_code(&r), LEAVE_ERR_NOT_MEMBER, "{r}");
    let (_, r) = f
        .call(
            REGISTER,
            json!({ "network": network, "role": "admins", "groupId": "admins" }),
        )
        .await;
    assert_eq!(tt_error_code(&r), REGISTER_ERR_NOT_MEMBER, "{r}");

    let (status, r) = f
        .call(JOIN, json!({ "url": url, "network": network }))
        .await;
    assert_eq!(status, StatusCode::OK, "{r}");
    let (_, r) = f
        .call(
            REGISTER,
            json!({ "network": network, "role": "admins", "groupId": "nope" }),
        )
        .await;
    assert_eq!(tt_error_code(&r), REGISTER_ERR_UNKNOWN_GROUP, "{r}");
    net.lock().await.refuse.groups = true;
    let (_, r) = f
        .call(
            REGISTER,
            json!({ "network": network, "role": "admins", "groupId": "admins" }),
        )
        .await;
    assert_eq!(tt_error_code(&r), REGISTER_ERR_NETWORK_REFUSED, "{r}");
    net.lock().await.refuse = Refuse::default();
    let (status, r) = f
        .call(
            REGISTER,
            json!({ "network": network, "role": "admins", "groupId": "admins" }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{r}");
    assert_eq!(r["payload"]["membership"]["groups"][0]["role"], "admins");

    net.lock().await.refuse.repudiate = true;
    let (_, r) = f.call(LEAVE, json!({ "network": network })).await;
    assert_eq!(tt_error_code(&r), LEAVE_ERR_NETWORK_REFUSED, "{r}");
    net.lock().await.refuse = Refuse::default();
    let (status, r) = f
        .call(LEAVE, json!({ "network": network, "reason": "merged" }))
        .await;
    assert_eq!(status, StatusCode::OK, "{r}");
    assert_eq!(r["payload"]["membership"]["state"], "departed");
}
