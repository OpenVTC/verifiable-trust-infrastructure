//! The community's side of VTN membership, against a fake network built from `vti_vtn`.
//! The fake network checks every signature the community sends, as a real one does.

use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::{Path, State as AxState};
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
    async fn challenge(AxState(s): AxState<Shared>, Json(b): Json<Value>) -> Json<Value> {
        let n = s.lock().await;
        Json(
            json!({ "challenge": format!("c-{}", b["did"]), "audience": n.identity.did(), "expiresAt": Utc::now() }),
        )
    }
    async fn session(
        AxState(s): AxState<Shared>,
        Json(b): Json<Value>,
    ) -> Result<Json<Value>, axum::http::StatusCode> {
        let n = s.lock().await;
        let doc = &b["authentication"];
        let did = doc["did"].as_str().unwrap_or_default();
        if doc["audience"].as_str() != Some(n.identity.did()) {
            return Err(axum::http::StatusCode::UNAUTHORIZED);
        }
        verify_document(doc, did, AUTHENTICATION, &LocalDidKeyResolver)
            .await
            .map_err(|_| axum::http::StatusCode::UNAUTHORIZED)?;
        Ok(Json(
            json!({ "token": "session", "did": did, "role": "listed" }),
        ))
    }
    async fn entry(AxState(s): AxState<Shared>, Path(_did): Path<String>) -> Json<Value> {
        let n = s.lock().await;
        Json(json!({ "listing": n.listing, "grant": n.grant }))
    }
    async fn offer_handler(AxState(s): AxState<Shared>, Path(_did): Path<String>) -> Json<Value> {
        Json(serde_json::to_value(&s.lock().await.offer).unwrap())
    }
    async fn groups(
        AxState(s): AxState<Shared>,
        Path(did): Path<String>,
        Json(b): Json<Value>,
    ) -> Result<Json<Value>, axum::http::StatusCode> {
        let mut n = s.lock().await;
        let reg = vti_vtn::groups::verify_registration(
            &b["registration"],
            &did,
            n.identity.did(),
            &LocalDidKeyResolver,
            Utc::now(),
        )
        .await
        .map_err(|_| axum::http::StatusCode::UNPROCESSABLE_ENTITY)?;
        let mut acc = vti_vtn::groups::acceptance(
            n.identity.did(),
            &reg.group,
            &b["registration"],
            Utc::now() - Duration::seconds(30),
            json!([]),
        )
        .unwrap();
        n.identity.sign_credential(&mut acc).await.unwrap();
        n.groups.insert(reg.role.clone(), b["registration"].clone());
        Ok(Json(json!({ "acceptance": { "credential": acc } })))
    }
    async fn acknowledge(
        AxState(s): AxState<Shared>,
        Path(did): Path<String>,
        Json(b): Json<Value>,
    ) -> Result<Json<Value>, axum::http::StatusCode> {
        let mut n = s.lock().await;
        if n.required && !n.groups.contains_key("admins") {
            return Err(axum::http::StatusCode::UNPROCESSABLE_ENTITY);
        }
        verify_acknowledgement(
            &b["acknowledgement"],
            &n.offer,
            &did,
            &LocalDidKeyResolver,
            Utc::now(),
        )
        .await
        .map_err(|_| axum::http::StatusCode::UNPROCESSABLE_ENTITY)?;
        let mut grant = n.offer.clone();
        n.identity.sign_credential(&mut grant).await.unwrap();
        let grant = serde_json::to_value(grant).unwrap();
        n.grant = Some(grant.clone());
        Ok(Json(json!({ "state": "acknowledged", "grant": grant })))
    }
    async fn repudiate(
        AxState(s): AxState<Shared>,
        Path(did): Path<String>,
        Json(b): Json<Value>,
    ) -> Result<Json<Value>, axum::http::StatusCode> {
        let mut n = s.lock().await;
        let target = verify_repudiation(
            &b["repudiation"],
            &did,
            n.identity.did(),
            &n.listing,
            n.grant.as_ref(),
            &LocalDidKeyResolver,
            Utc::now(),
        )
        .await
        .map_err(|_| axum::http::StatusCode::UNPROCESSABLE_ENTITY)?;
        n.repudiations.push((target, b["repudiation"].clone()));
        Ok(Json(json!({ "state": "repudiated" })))
    }

    let app = Router::new()
        .route("/.well-known/vtn", get(profile))
        .route("/v1/auth/challenge", post(challenge))
        .route("/v1/auth/session", post(session))
        .route("/v1/entries/{did}", get(entry))
        .route("/v1/entries/{did}/offer", get(offer_handler))
        .route("/v1/entries/{did}/groups", post(groups))
        .route("/v1/entries/{did}/acknowledge", post(acknowledge))
        .route("/v1/entries/{did}/repudiate", post(repudiate))
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
        .filter_map(|(_, v)| serde_json::from_slice::<vti_common::audit::AuditEnvelope>(&v).ok())
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
    assert_eq!(
        g.endpoint,
        "https://community.example/v1/networks/relay/admins"
    );
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
    <vti_specs::vtc::networks::show::v0_1::Response as trust_tasks_rs::validate::ValidatedPayload>::validate_value(&body)
        .unwrap();

    let events = audit_events(state).await;
    assert!(
        events
            .iter()
            .any(|e| e.event == "joined" && e.network == network.did())
    );
}

#[tokio::test]
async fn a_broadcast_is_relayed_once_and_only_from_the_network() {
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

    let receipt = relay(state, "admins", envelope.clone()).await.unwrap();
    assert_eq!(receipt["status"], "delivered");
    let again = relay(state, "admins", envelope.clone()).await.unwrap();
    assert_eq!(again["status"], "duplicate");
    let relayed = audit_events(state).await;
    let e = relayed
        .iter()
        .find(|e| e.event == "broadcastRelayed")
        .unwrap();
    assert_eq!(e.message_id.as_deref(), Some(id.as_str()));

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
        relay(state, "admins", env2).await,
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
        relay(state, "admins", env3).await,
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
    assert!(matches!(
        relay(state, "admins", env).await,
        Err(NetError::Rejected(_))
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
