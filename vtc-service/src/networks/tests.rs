//! The community's side of VTN membership, against a fake network built from `vti_vtn`.
//! The fake network checks every signature the community sends, as a real one does.

use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::State as AxState;
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{Duration, Utc};
use serde_json::{Value, json};
use tokio::sync::Mutex;
use vti_vtn::credentials::{listing_vsc, membership_offer};
use vti_vtn::identity::Identity;
use vti_vtn::model::{EntryKind, Framework};
use vti_vtn::relay::{self, Envelope, Outgoing};
use vti_vtn::status::credential_status;
use vti_vtn::verify::{
    AUTHENTICATION, LocalDidKeyResolver, Repudiated, verify_acknowledgement, verify_document,
    verify_repudiation,
};

use super::*;
use crate::credentials::LocalSigner;
use crate::test_support::TestVtc;

const SEED: [u8; 32] = [0x42; 32];

/// What the fake network knows.
struct Net {
    identity: Identity,
    /// Signs answers in the network's name instead of its own key: a forger.
    answer_key: Option<Identity>,
    required: bool,
    listing: Value,
    offer: dtg_credentials::DTGCredential,
    grant: Option<Value>,
    groups: HashMap<String, Value>,
    repudiations: Vec<(Repudiated, Value)>,
}

type Shared = Arc<Mutex<Net>>;

async fn fake_network(community: &str, required: bool) -> (String, Identity, Shared) {
    let identity = Identity::generate();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let now = Utc::now() - Duration::seconds(60);
    let mut listing = listing_vsc(
        identity.did(),
        community,
        EntryKind::Community,
        &Framework {
            iri: format!("{url}/gf"),
            version: "1.0".into(),
        },
        now,
        credential_status(&url, 0),
    )
    .unwrap();
    identity.sign_credential(&mut listing).await.unwrap();
    let offer = membership_offer(
        identity.did(),
        community,
        now,
        Some(now + Duration::days(365)),
        credential_status(&url, 1),
    );
    let shared: Shared = Arc::new(Mutex::new(Net {
        identity: identity.clone(),
        answer_key: None,
        required,
        listing: serde_json::to_value(listing).unwrap(),
        offer,
        grant: None,
        groups: HashMap::new(),
        repudiations: Vec::new(),
    }));

    async fn profile(AxState(s): AxState<Shared>) -> Json<Value> {
        let n = s.lock().await;
        Json(json!({
            "did": n.identity.did(),
            "profile": { "name": "World Health Network" },
            "roles": [{ "name": "admins", "required": n.required }],
        }))
    }
    /// `vtn/*` Trust Tasks, as a network answers them: the request's proof must be its
    /// issuer's, for `authentication`, and the request addressed to this network.
    /// Every answer signed by the network for `authentication`, as the spine signs it.
    async fn tasks(
        AxState(s): AxState<Shared>,
        doc: Json<Value>,
    ) -> (axum::http::StatusCode, Json<Value>) {
        let identity = {
            let n = s.lock().await;
            n.answer_key.clone().unwrap_or_else(|| n.identity.clone())
        };
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
    ) -> (axum::http::StatusCode, Json<Value>) {
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
            Json(json!({
                "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
                "type": format!("{kind}#response"),
                "issuer": me,
                "recipient": issuer,
                "threadId": doc["id"],
                "issuedAt": Utc::now(),
                "payload": payload,
            }))
        };
        let refuse = |code: &str| {
            (
                axum::http::StatusCode::UNPROCESSABLE_ENTITY,
                Json(json!({
                    "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
                    "type": "https://trusttasks.org/spec/trust-task-error/0.6",
                    "issuer": me,
                    "threadId": doc["id"],
                    "payload": { "code": code, "message": code },
                })),
            )
        };
        if doc["recipient"].as_str() != Some(me.as_str())
            || verify_document(&doc, &issuer, AUTHENTICATION, &LocalDidKeyResolver)
                .await
                .is_err()
        {
            return refuse("permissionDenied");
        }
        let p = &doc["payload"];
        let ok = axum::http::StatusCode::OK;
        // The community's `IndexEntry`, as a network publishes it.
        let entry = |n: &Net, state: &str| {
            let mut e = json!({
                "did": issuer,
                "kind": "community",
                "state": state,
                "acknowledged": state == "acknowledged",
                "profile": {},
                "listing": n.listing,
            });
            if let Some(g) = &n.grant {
                e["grant"] = g.clone();
            }
            e
        };
        match slug.as_str() {
            "vtn/entries/show" => (
                ok,
                answer(
                    json!({ "entry": entry(&n, if n.grant.is_some() { "acknowledged" } else { "listed" }) }),
                ),
            ),
            "vtn/membership/offer" => (
                ok,
                answer(json!({ "offer": serde_json::to_value(&n.offer).unwrap() })),
            ),
            "vtn/groups/register" => {
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
                n.groups.insert(reg.role.clone(), doc.clone());
                (
                    ok,
                    answer(json!({ "group": {
                        "member": issuer,
                        "role": reg.role,
                        "group": reg.group,
                        "endpoint": reg.endpoint,
                        "registration": doc,
                        "acceptance": acc,
                        "registeredAt": Utc::now(),
                    } })),
                )
            }
            "vtn/membership/acknowledge" => {
                if n.required && !n.groups.contains_key("admins") {
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
                let grant = serde_json::to_value(grant).unwrap();
                n.grant = Some(grant.clone());
                (ok, answer(json!({ "entry": entry(&n, "acknowledged") })))
            }
            "vtn/membership/repudiate" => {
                let Ok(target) = verify_repudiation(
                    &p["repudiation"],
                    &issuer,
                    &me,
                    &n.listing,
                    n.grant.as_ref(),
                    &LocalDidKeyResolver,
                    Utc::now(),
                )
                .await
                else {
                    return refuse("vtn/membership/repudiate:repudiationInvalid");
                };
                n.repudiations.push((target, p["repudiation"].clone()));
                let state = match target {
                    Repudiated::Listing => "repudiated",
                    Repudiated::Grant => "departed",
                };
                (ok, answer(json!({ "entry": entry(&n, state) })))
            }
            _ => refuse("unsupportedType"),
        }
    }

    let app = Router::new()
        .route("/.well-known/vtn", get(profile))
        .route(vti_vtn::tasks::TRUST_TASKS_PATH, post(tasks))
        .with_state(shared.clone());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (url, identity, shared)
}

/// A community with a `did:key` identity, signing with `LocalSigner`, auditing.
async fn community() -> (TestVtc, String) {
    let did = Identity::from_ed25519_seed(&SEED).did().to_string();
    let signer = Arc::new(LocalSigner::from_ed25519_seed(did.clone(), &SEED));
    let vtc = TestVtc::builder()
        .vtc_did(did.clone())
        .with_credential_signer(signer)
        .with_audit(true)
        .with_public_url("https://community.example")
        .build()
        .await;
    (vtc, did)
}

/// A group with a DID of its own, and `members` as its active members.
async fn admins_group(state: &AppState, members: &[&str]) -> String {
    let group_did = Identity::generate().did().to_string();
    let now = Utc::now();
    let group: crate::groups::Group = serde_json::from_value(json!({
        "groupId": "admins", "groupDid": group_did, "signingKeyId": "admins-key", "name": "Admins",
        "joinPolicy": "closed", "visibility": "members", "showMembers": "admins",
        "issuesCredentials": true, "createdAt": now, "updatedAt": now,
    }))
    .unwrap();
    let ks = state.directory.ks();
    crate::groups::put(ks, &group).await.unwrap();
    for did in members {
        let card = crate::directory::cards::ensure(ks, did, &state.directory.settings(), None)
            .await
            .unwrap();
        crate::groups::put_membership(
            ks,
            &serde_json::from_value(json!({
                "groupId": "admins", "entryId": card.entry_id, "source": "added",
                "since": now, "state": "active",
            }))
            .unwrap(),
        )
        .await
        .unwrap();
    }
    group_did
}

fn admins() -> Vec<(String, String)> {
    vec![("admins".to_string(), "admins".to_string())]
}

async fn audit_events(state: &AppState) -> Vec<NetworkMembershipChangedData> {
    state
        .audit_ks
        .prefix_iter_raw(Vec::new())
        .await
        .unwrap()
        .into_iter()
        .filter_map(|(_, v)| serde_json::from_slice::<vtc_audit::AuditEnvelope>(&v).ok())
        .filter_map(|env| match env.event {
            AuditEvent::NetworkMembershipChanged(d) => Some(d),
            _ => None,
        })
        .collect()
}

#[tokio::test]
async fn join_registers_groups_and_acknowledges() {
    let (vtc, did) = community().await;
    let state = &vtc.state;
    let member = Identity::generate();
    let group_did = admins_group(state, &[member.did()]).await;
    let (url, network, net) = fake_network(&did, true).await;

    // A required role with no group assigned: refused before anything is sent.
    let err = join(state, "did:example:admin", &url, network.did(), &[])
        .await
        .unwrap_err();
    assert!(
        matches!(err, NetError::RoleUnassigned(ref r) if r == "admins"),
        "{err}"
    );
    // The URL answering as another network: refused before signing.
    let err = join(
        state,
        "did:example:admin",
        &url,
        "did:key:z6MkOther",
        &admins(),
    )
    .await
    .unwrap_err();
    assert!(matches!(err, NetError::Mismatch(_)), "{err}");
    // An unknown group.
    let err = join(
        state,
        "did:example:admin",
        &url,
        network.did(),
        &[("admins".into(), "nope".into())],
    )
    .await
    .unwrap_err();
    assert!(matches!(err, NetError::UnknownGroup(_)), "{err}");

    let m = join(state, "did:example:admin", &url, network.did(), &admins())
        .await
        .unwrap();
    assert_eq!(m.state, State::Acknowledged);
    assert_eq!(m.name.as_deref(), Some("World Health Network"));
    assert_eq!(m.groups.len(), 1);
    let g = &m.groups[0];
    assert_eq!(g.group_did, group_did);
    assert_eq!(g.endpoint, "https://community.example/v1/trust-tasks");
    assert_eq!(
        g.registration["issuer"], did,
        "the community registers, not the group"
    );
    assert_eq!(g.acceptance["issuer"], network.did());
    assert!(net.lock().await.grant.is_some());
    assert_eq!(load(state, network.did()).await.unwrap().unwrap(), m);

    // Joining twice is refused.
    let err = join(state, "did:example:admin", &url, network.did(), &admins())
        .await
        .unwrap_err();
    assert!(matches!(err, NetError::AlreadyMember), "{err}");

    // The membership record is the shared schema's NetworkMembership.
    let body = json!({ "membership": serde_json::to_value(&m).unwrap() });
    <vti_specs::vtc::networks::show::v0_2::Response as trust_tasks_rs::validate::ValidatedPayload>::validate_value(&body)
        .unwrap();

    let events = audit_events(state).await;
    assert!(
        events
            .iter()
            .any(|e| e.event == "joined" && e.network == network.did())
    );
}

#[tokio::test]
async fn a_broadcast_is_delivered_once_and_only_by_the_network() {
    let (vtc, did) = community().await;
    let state = &vtc.state;
    let member = Identity::generate();
    let group_did = admins_group(state, &[member.did()]).await;
    let (url, network, _net) = fake_network(&did, false).await;
    join(state, "did:example:admin", &url, network.did(), &admins())
        .await
        .unwrap();

    let message = relay::new_message(
        &network,
        &Outgoing {
            role: "admins".into(),
            class: "notice".into(),
            subject: "Exercise".into(),
            body: "09:00 UTC".into(),
            reply_to: None,
        },
        Duration::hours(1),
        Utc::now(),
    )
    .await
    .unwrap();
    let id = message["id"].as_str().unwrap().to_string();
    let hop = relay::new_hop(&network, &id, &group_did, "admins", 0)
        .await
        .unwrap();
    let envelope = Envelope {
        message: message.clone(),
        hops: vec![hop],
    };

    let receipt = deliver(state, network.did(), "admins", envelope.clone())
        .await
        .unwrap();
    assert_eq!(receipt["status"], "delivered");
    let again = deliver(state, network.did(), "admins", envelope.clone())
        .await
        .unwrap();
    assert_eq!(again["status"], "duplicate");
    let relayed = audit_events(state).await;
    let e = relayed
        .iter()
        .find(|e| e.event == "broadcastRelayed")
        .unwrap();
    assert_eq!(e.message_id.as_deref(), Some(id.as_str()));

    // A role this community registered no group for with the network.
    assert!(matches!(
        deliver(state, network.did(), "clinical", envelope.clone()).await,
        Err(NetError::RoleUnregistered(_))
    ));

    // A network the community is not a member of.
    let rogue = Identity::generate();
    let m2 = relay::new_message(
        &rogue,
        &Outgoing {
            role: "admins".into(),
            class: "notice".into(),
            subject: "x".into(),
            body: "y".into(),
            reply_to: None,
        },
        Duration::hours(1),
        Utc::now(),
    )
    .await
    .unwrap();
    let id2 = m2["id"].as_str().unwrap().to_string();
    let env2 = Envelope {
        hops: vec![
            relay::new_hop(&rogue, &id2, &group_did, "admins", 0)
                .await
                .unwrap(),
        ],
        message: m2,
    };
    assert!(matches!(
        deliver(state, rogue.did(), "admins", env2.clone()).await,
        Err(NetError::NotMember)
    ));
    // The network delivering an envelope whose last hop is not its own.
    assert!(matches!(
        deliver(state, network.did(), "admins", env2).await,
        Err(NetError::Rejected(_))
    ));

    // Addressed to another group.
    let m3 = relay::new_message(
        &network,
        &Outgoing {
            role: "admins".into(),
            class: "notice".into(),
            subject: "x".into(),
            body: "y".into(),
            reply_to: None,
        },
        Duration::hours(1),
        Utc::now(),
    )
    .await
    .unwrap();
    let id3 = m3["id"].as_str().unwrap().to_string();
    let env3 = Envelope {
        hops: vec![
            relay::new_hop(&network, &id3, "did:key:z6MkElsewhere", "admins", 0)
                .await
                .unwrap(),
        ],
        message: m3,
    };
    assert!(matches!(
        deliver(state, network.did(), "admins", env3).await,
        Err(NetError::Rejected(_))
    ));
}

#[tokio::test]
async fn evidence_is_only_for_members_of_the_group() {
    let (vtc, did) = community().await;
    let state = &vtc.state;
    let member = Identity::generate();
    admins_group(state, &[member.did()]).await;
    let (url, network, _net) = fake_network(&did, false).await;
    join(state, "did:example:admin", &url, network.did(), &admins())
        .await
        .unwrap();

    let links = evidence(state, member.did(), None, None).await.unwrap();
    assert_eq!(links.len(), 1);
    assert_eq!(links[0]["network"], network.did());
    assert_eq!(links[0]["acceptance"]["issuer"], network.did());
    // The chain link verifies as a network would check it for a room pass.
    let link: vti_vtn::rooms::ChainLink = serde_json::from_value(json!({
        "registration": links[0]["registration"], "acceptance": links[0]["acceptance"],
    }))
    .unwrap();
    let verified = vti_vtn::rooms::verify_link(&link, &LocalDidKeyResolver, Utc::now())
        .await
        .unwrap();
    assert_eq!(verified.owner, did);

    let stranger = Identity::generate();
    assert!(
        evidence(state, stranger.did(), None, None)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn leaving_repudiates_the_grant_and_stops_relaying() {
    let (vtc, did) = community().await;
    let state = &vtc.state;
    let group_did = admins_group(state, &[]).await;
    let (url, network, net) = fake_network(&did, false).await;
    join(state, "did:example:admin", &url, network.did(), &admins())
        .await
        .unwrap();

    let m = leave(
        state,
        "did:example:admin",
        network.did(),
        Some("merged".into()),
    )
    .await
    .unwrap();
    assert_eq!(m.state, State::Departed);
    assert_eq!(net.lock().await.repudiations[0].0, Repudiated::Grant);
    assert!(matches!(
        leave(state, "a", network.did(), None).await,
        Err(NetError::NotMember)
    ));

    let message = relay::new_message(
        &network,
        &Outgoing {
            role: "admins".into(),
            class: "notice".into(),
            subject: "x".into(),
            body: "y".into(),
            reply_to: None,
        },
        Duration::hours(1),
        Utc::now(),
    )
    .await
    .unwrap();
    let id = message["id"].as_str().unwrap().to_string();
    let env = Envelope {
        hops: vec![
            relay::new_hop(&network, &id, &group_did, "admins", 0)
                .await
                .unwrap(),
        ],
        message,
    };
    // Left: the network is no longer one this community delivers for.
    assert!(matches!(
        deliver(state, network.did(), "admins", env).await,
        Err(NetError::NotMember)
    ));
    assert!(
        audit_events(state)
            .await
            .iter()
            .any(|e| e.event == "left" && e.reason.as_deref() == Some("merged"))
    );
}

#[tokio::test]
async fn repudiating_a_listing() {
    let (vtc, did) = community().await;
    let state = &vtc.state;
    let (url, network, net) = fake_network(&did, false).await;
    let m = repudiate(state, "did:example:admin", &url, network.did(), None)
        .await
        .unwrap();
    assert_eq!(m.state, State::Repudiated);
    assert_eq!(net.lock().await.repudiations[0].0, Repudiated::Listing);
    // A repudiated listing can still be accepted later; a member cannot repudiate.
    join(state, "did:example:admin", &url, network.did(), &[])
        .await
        .unwrap();
    assert!(matches!(
        repudiate(state, "a", &url, network.did(), None).await,
        Err(NetError::IsMember)
    ));
}

#[tokio::test]
async fn an_answer_not_signed_by_the_network_is_a_mismatch() {
    let (vtc, did) = community().await;
    let state = &vtc.state;
    let member = Identity::generate();
    admins_group(state, &[member.did()]).await;
    let (url, network, net) = fake_network(&did, true).await;
    // The URL answers in the network's name, signed by another key.
    net.lock().await.answer_key = Some(Identity::generate());

    let err = join(state, "did:example:admin", &url, network.did(), &admins())
        .await
        .unwrap_err();
    assert!(matches!(err, NetError::Mismatch(_)), "{err}");
    assert!(load(state, network.did()).await.unwrap().is_none());
}
