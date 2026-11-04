//! Collection claims, the listing and the plan (VTI-NTF-080 – 093), against a
//! real store. Personas are seeded as `did:webvh` records with a log whose
//! document advertises a mediator; no socket is opened — [`FakeSession`]
//! stands in for one and records whether it was closed.

use super::*;
use crate::test_support::{admin_claims_for_context, build_signing_test_app_state};
use std::sync::atomic::AtomicUsize;

const CTX: &str = "alice";
const OTHER: &str = "bob";
pub(crate) const MEDIATOR: &str = "did:web:mediator.example";
const PERSONA: &str = "did:webvh:QmPersonaOne:persona.example";
const PERSONA2: &str = "did:webvh:QmPersonaTwo:persona.example";

fn client(did: &str, context: &str) -> AuthClaims {
    let mut c = admin_claims_for_context(context);
    c.did = did.to_string();
    c
}

fn document(did: &str, mediator: Option<&str>) -> serde_json::Value {
    let mut doc = serde_json::json!({
        "id": did,
        "verificationMethod": [{
            "id": format!("{did}#key-0"),
            "type": "Multikey",
            "controller": did,
            "publicKeyMultibase": "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
        }],
        "authentication": [format!("{did}#key-0")],
    });
    if let Some(m) = mediator {
        doc["service"] = serde_json::json!([{
            "id": format!("{did}#didcomm"),
            "type": "DIDCommMessaging",
            "serviceEndpoint": [{ "uri": m, "accept": ["didcomm/v2"] }],
        }]);
    }
    doc
}

/// A persona `did` held in `context`, advertising `mediator`.
pub(crate) async fn seed_persona(
    state: &AppState,
    context: &str,
    did: &str,
    mediator: Option<&str>,
) {
    let now = Utc::now();
    let record = vta_sdk::webvh::WebvhDidRecord {
        did: did.to_string(),
        server_id: "serverless".into(),
        mnemonic: String::new(),
        scid: did.split(':').nth(2).unwrap_or_default().to_string(),
        context_id: context.to_string(),
        portable: false,
        log_entry_count: 1,
        pre_rotation_count: 0,
        next_fragment_id: 1,
        created_at: now,
        updated_at: now,
    };
    crate::webvh_store::store_did(&state.webvh_ks, &record)
        .await
        .unwrap();
    let entry = serde_json::json!({
        "versionId": "1-QmHash",
        "versionTime": "2026-01-01T00:00:00Z",
        "parameters": { "method": "did:webvh:1.0", "scid": "QmPersona", "updateKeys": [] },
        "state": document(did, mediator),
        "proof": [],
    });
    crate::webvh_store::store_did_log(&state.webvh_ks, did, &entry.to_string())
        .await
        .unwrap();
}

async fn state() -> (AppState, tempfile::TempDir) {
    let (state, dir) = build_signing_test_app_state().await;
    for (id, name) in [(CTX, "Alice"), (OTHER, "Bob")] {
        crate::contexts::create_context(&state.contexts_ks, id, name)
            .await
            .unwrap();
    }
    seed_persona(&state, CTX, PERSONA, Some(MEDIATOR)).await;
    (state, dir)
}

/// A connection that records how often it was closed.
struct FakeSession {
    closed: Arc<AtomicUsize>,
}

impl CollectingSession for FakeSession {
    fn close(&self) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(async move {
            self.closed.fetch_add(1, Ordering::SeqCst);
        })
    }
    fn fingerprint(&self) -> &str {
        "fp"
    }
}

fn fake() -> (Arc<dyn CollectingSession>, Arc<AtomicUsize>) {
    let closed = Arc::new(AtomicUsize::new(0));
    (
        Arc::new(FakeSession {
            closed: Arc::clone(&closed),
        }),
        closed,
    )
}

#[tokio::test]
async fn vti_ntf_080_candidates_are_the_mediated_personas_less_the_excluded() {
    let (state, _dir) = state().await;
    // No mediated transport: not collected for.
    seed_persona(&state, CTX, "did:webvh:QmNoService:persona.example", None).await;
    // A DID holding an ACL entry collects for itself.
    seed_persona(&state, CTX, "did:webvh:QmNode:node.example", Some(MEDIATOR)).await;
    let entry = crate::acl::AclEntry::new(
        "did:webvh:QmNode:node.example",
        crate::acl::Role::Admin,
        "t",
    );
    crate::acl::store_acl_entry(&state.acl_ks, &entry)
        .await
        .unwrap();
    // Provisioned for another party.
    seed_persona(
        &state,
        CTX,
        "did:webvh:QmGiven:given.example",
        Some(MEDIATOR),
    )
    .await;
    mark_provisioned(&state.collection_ks, "did:webvh:QmGiven:given.example")
        .await
        .unwrap();
    // The VTA's own DID.
    let own = state.config.read().await.vta_did.clone().unwrap();
    seed_persona(&state, CTX, &own, Some(MEDIATOR)).await;

    let found: Vec<String> = candidates(&state, Some(CTX))
        .await
        .unwrap()
        .into_iter()
        .map(|c| c.identifier)
        .collect();
    assert_eq!(found, vec![PERSONA.to_string()]);
    let c = &candidates(&state, None).await.unwrap()[0];
    assert_eq!(c.mediator_did, MEDIATOR);
}

#[tokio::test]
async fn vti_ntf_093_off_by_default_and_listed_as_disabled_while_claims_still_work() {
    let (state, _dir) = state().await;
    assert!(!state.collection.enabled(), "collection by default is off");
    let auth = client("did:key:z6MkClientA", CTX);
    let page = list(
        &state,
        &auth,
        CTX,
        &ListFilter::default(),
        None,
        None,
        Utc::now(),
    )
    .await
    .unwrap();
    assert_eq!(page.items.len(), 1);
    assert_eq!(
        page.items[0].to_wire()["notCollectedReason"],
        "disabled",
        "{:?}",
        page.items
    );
    // Claims are served whatever the setting.
    let grant = claim(&state, &auth, CTX, PERSONA, Some(3600), Utc::now())
        .await
        .unwrap();
    assert!(!grant.renewed);
    let page = list(
        &state,
        &auth,
        CTX,
        &ListFilter::default(),
        None,
        None,
        Utc::now(),
    )
    .await
    .unwrap();
    let wire = page.items[0].to_wire();
    assert_eq!(wire["collector"], "client");
    assert_eq!(wire["claim"]["claimant"], "did:key:z6MkClientA");
}

#[tokio::test]
async fn vti_ntf_093_the_setting_is_audited_once_when_it_changes() {
    let (state, _dir) = state().await;
    record_setting(&state).await.unwrap();
    assert_eq!(
        state.collection_ks.get::<bool>(SETTING_KEY).await.unwrap(),
        Some(false)
    );
    state.collection.set_enabled(true);
    record_setting(&state).await.unwrap();
    assert_eq!(
        state.collection_ks.get::<bool>(SETTING_KEY).await.unwrap(),
        Some(true)
    );
    // Applying the same value again changes nothing.
    record_setting(&state).await.unwrap();
}

#[tokio::test]
async fn vti_ntf_082_a_grant_closes_the_vtas_connection_before_it_answers() {
    let (state, _dir) = state().await;
    state.collection.set_enabled(true);
    let (session, closed) = fake();
    state.collection.insert(PERSONA, session).unwrap();
    assert!(state.collection.is_collecting(PERSONA));

    let auth = client("did:key:z6MkClientA", CTX);
    claim(&state, &auth, CTX, PERSONA, None, Utc::now())
        .await
        .unwrap();
    assert_eq!(closed.load(Ordering::SeqCst), 1, "closed before the answer");
    assert!(!state.collection.is_collecting(PERSONA));
}

#[tokio::test]
async fn one_socket_per_did_a_second_session_is_refused() {
    let control = CollectionControl::new(true);
    let (a, _) = fake();
    let (b, _) = fake();
    control.insert(PERSONA, a).unwrap();
    assert_eq!(
        control.insert(PERSONA, b),
        Err(InsertRefused::AlreadyCollecting)
    );
    assert_eq!(control.collecting(), vec![PERSONA.to_string()]);
}

#[tokio::test]
async fn vti_ntf_082_lease_bounds_renewal_and_claim_held() {
    let (state, _dir) = state().await;
    let a = client("did:key:z6MkClientA", CTX);
    let b = client("did:key:z6MkClientB", CTX);
    let now = Utc::now();
    // Asking for more than the stated maximum is granted the maximum.
    let g = claim(&state, &a, CTX, PERSONA, Some(i64::MAX), now)
        .await
        .unwrap();
    let max = state.config.read().await.collection.stated_max_claim_secs() as i64;
    assert!((g.ends_at - now).num_seconds() <= max);
    // The same client renews.
    let r = claim(&state, &a, CTX, PERSONA, Some(600), now)
        .await
        .unwrap();
    assert!(r.renewed);
    // Another client is refused while it is in force.
    assert!(matches!(
        claim(&state, &b, CTX, PERSONA, None, now).await,
        Err(CollectionError::ClaimHeld)
    ));
    // Once it has ended, anyone with standing may claim.
    let later = r.ends_at + Duration::seconds(1);
    assert!(claim(&state, &b, CTX, PERSONA, None, later).await.is_ok());
}

#[tokio::test]
async fn vti_ntf_084_release_by_another_party_makes_the_claim_unrenewable() {
    let (state, _dir) = state().await;
    let a = client("did:key:z6MkClientA", CTX);
    let b = client("did:key:z6MkClientB", CTX);
    let now = Utc::now();
    let g = claim(&state, &a, CTX, PERSONA, Some(3600), now)
        .await
        .unwrap();
    let r = release(&state, &b, CTX, PERSONA, now).await.unwrap();
    assert_eq!(r.ends_at, Some(g.ends_at), "ends at its end, not at once");
    assert!(matches!(
        claim(&state, &a, CTX, PERSONA, None, now).await,
        Err(CollectionError::ClaimNotRenewable)
    ));
    // The VTA stays off until the end plus its skew.
    let rec = get_claim(&state.collection_ks, CTX, PERSONA)
        .await
        .unwrap()
        .unwrap();
    assert!(rec.keeps_vta_off(g.ends_at + Duration::seconds(1), Duration::seconds(60)));
    assert!(!rec.keeps_vta_off(g.ends_at + Duration::seconds(61), Duration::seconds(60)));
}

#[tokio::test]
async fn vti_ntf_084_release_by_the_claimant_ends_at_once() {
    let (state, _dir) = state().await;
    let a = client("did:key:z6MkClientA", CTX);
    let now = Utc::now();
    claim(&state, &a, CTX, PERSONA, Some(3600), now)
        .await
        .unwrap();
    let r = release(&state, &a, CTX, PERSONA, now).await.unwrap();
    assert!(r.ends_at.is_some());
    let rec = get_claim(&state.collection_ks, CTX, PERSONA)
        .await
        .unwrap()
        .unwrap();
    let after = now + Duration::seconds(1);
    assert!(!rec.in_force(after));
    assert!(
        !rec.keeps_vta_off(after, Duration::seconds(60)),
        "no skew wait"
    );
    // A second release has nothing in force and changes nothing.
    assert_eq!(
        release(&state, &a, CTX, PERSONA, after)
            .await
            .unwrap()
            .ends_at,
        None
    );
}

#[tokio::test]
async fn vti_ntf_082_standing_and_collectability_are_checked() {
    let (state, _dir) = state().await;
    let outsider = client("did:key:z6MkOutsider", OTHER);
    assert!(matches!(
        claim(&state, &outsider, CTX, PERSONA, None, Utc::now()).await,
        Err(CollectionError::PermissionDenied)
    ));
    assert!(matches!(
        list(
            &state,
            &outsider,
            CTX,
            &ListFilter::default(),
            None,
            None,
            Utc::now()
        )
        .await,
        Err(CollectionError::PermissionDenied)
    ));
    let a = client("did:key:z6MkClientA", CTX);
    let own = state.config.read().await.vta_did.clone().unwrap();
    for did in [own.as_str(), "did:webvh:QmUnknown:x.example", PERSONA2] {
        assert!(
            matches!(
                claim(&state, &a, CTX, did, None, Utc::now()).await,
                Err(CollectionError::NotCollectable)
            ),
            "{did}"
        );
        assert!(
            matches!(
                release(&state, &a, CTX, did, Utc::now()).await,
                Err(CollectionError::NotCollectable)
            ),
            "{did}"
        );
    }
    // A persona of another context is not collectable in this one.
    seed_persona(&state, OTHER, PERSONA2, Some(MEDIATOR)).await;
    assert!(matches!(
        claim(&state, &a, CTX, PERSONA2, None, Utc::now()).await,
        Err(CollectionError::NotCollectable)
    ));
}

#[test]
fn vti_ntf_088_the_plan_applies_the_bound_conflicts_and_claims() {
    let cand = |ctx: &str, did: &str| Candidate {
        context_id: ctx.into(),
        identifier: did.into(),
        log_did: did.into(),
        mediator_did: MEDIATOR.into(),
        document: serde_json::Value::Null,
    };
    let cands = vec![
        cand(CTX, "did:webvh:a:x"),
        cand(CTX, "did:webvh:b:x"),
        cand(CTX, "did:webvh:c:x"),
        cand(OTHER, "did:webvh:d:x"),
    ];
    let now = Utc::now();
    let mut claims = HashMap::new();
    claims.insert(
        "did:webvh:a:x".to_string(),
        ClaimRecord {
            context_id: CTX.into(),
            log_did: "did:webvh:a:x".into(),
            claimant: "did:key:z6MkA".into(),
            granted_at: now,
            ends_at: now + Duration::hours(1),
            released_by: None,
        },
    );
    let mut conflicts = HashMap::new();
    conflicts.insert(
        "did:webvh:b:x".to_string(),
        ConflictRecord {
            context_id: CTX.into(),
            log_did: "did:webvh:b:x".into(),
            since: now,
            closures: 5,
        },
    );
    let inputs = PlanInputs {
        claims: &claims,
        conflicts: &conflicts,
        enabled: true,
        max_identifiers: 1,
        skew: Duration::seconds(60),
        now,
    };
    let p = plan(&cands, &inputs);
    assert!(matches!(p[0], Assignment::Client(_)));
    assert_eq!(p[1], Assignment::Nobody(NotCollected::Conflict));
    assert_eq!(p[2], Assignment::Vta { open_now: true });
    assert_eq!(
        p[3],
        Assignment::Nobody(NotCollected::Limit),
        "the bound spans contexts"
    );

    let off = plan(
        &cands,
        &PlanInputs {
            enabled: false,
            ..inputs
        },
    );
    assert!(
        matches!(off[0], Assignment::Client(_)),
        "a claim is shown while off"
    );
    assert_eq!(off[2], Assignment::Nobody(NotCollected::Disabled));
}

#[test]
fn vti_ntf_084_the_vta_waits_out_its_skew_after_a_claim_ends() {
    let now = Utc::now();
    let ended = ClaimRecord {
        context_id: CTX.into(),
        log_did: PERSONA.into(),
        claimant: "did:key:z6MkA".into(),
        granted_at: now - Duration::hours(2),
        ends_at: now - Duration::seconds(10),
        released_by: None,
    };
    let cands = vec![Candidate {
        context_id: CTX.into(),
        identifier: PERSONA.into(),
        log_did: PERSONA.into(),
        mediator_did: MEDIATOR.into(),
        document: serde_json::Value::Null,
    }];
    let claims: HashMap<_, _> = [(PERSONA.to_string(), ended)].into();
    let p = plan(
        &cands,
        &PlanInputs {
            claims: &claims,
            conflicts: &HashMap::new(),
            enabled: true,
            max_identifiers: 10,
            skew: Duration::seconds(60),
            now,
        },
    );
    assert_eq!(p[0], Assignment::Vta { open_now: false });
}

#[tokio::test]
async fn vti_ntf_084_a_rollover_carries_the_claim() {
    let (state, _dir) = state().await;
    let a = client("did:key:z6MkClientA", CTX);
    claim(&state, &a, CTX, PERSONA, None, Utc::now())
        .await
        .unwrap();
    assert_eq!(
        carry_claims(
            &state.collection_ks,
            "did:key:z6MkClientA",
            "did:key:z6MkClientA2"
        )
        .await
        .unwrap(),
        1
    );
    let rec = get_claim(&state.collection_ks, CTX, PERSONA)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(rec.claimant, "did:key:z6MkClientA2");
}

#[tokio::test]
async fn vti_ntf_090_a_deleted_context_ends_its_claims() {
    let (state, _dir) = state().await;
    let a = client("did:key:z6MkClientA", CTX);
    claim(&state, &a, CTX, PERSONA, None, Utc::now())
        .await
        .unwrap();
    assert_eq!(purge_context(&state.collection_ks, CTX).await.unwrap(), 1);
    assert!(
        get_claim(&state.collection_ks, CTX, PERSONA)
            .await
            .unwrap()
            .is_none()
    );
    // A claim on an identifier that is no longer a candidate is swept.
    claim(&state, &a, CTX, PERSONA, None, Utc::now())
        .await
        .unwrap();
    assert_eq!(sweep(&state, &[], Utc::now()).await.unwrap(), 1);
}

#[tokio::test]
async fn vti_ntf_091_listing_filters_and_pages() {
    let (state, _dir) = state().await;
    seed_persona(&state, CTX, PERSONA2, Some(MEDIATOR)).await;
    let a = client("did:key:z6MkClientA", CTX);
    claim(&state, &a, CTX, PERSONA, None, Utc::now())
        .await
        .unwrap();
    let only_none = ListFilter {
        collector: Some("none".into()),
        ..Default::default()
    };
    let page = list(&state, &a, CTX, &only_none, None, None, Utc::now())
        .await
        .unwrap();
    assert_eq!(page.items.len(), 1);
    assert_eq!(page.items[0].identifier, PERSONA2);

    let first = list(
        &state,
        &a,
        CTX,
        &ListFilter::default(),
        None,
        Some(1),
        Utc::now(),
    )
    .await
    .unwrap();
    assert_eq!(first.items.len(), 1);
    let cursor = first.next_cursor.expect("a second page");
    let second = list(
        &state,
        &a,
        CTX,
        &ListFilter::default(),
        Some(&cursor),
        Some(1),
        Utc::now(),
    )
    .await
    .unwrap();
    assert_eq!(second.items.len(), 1);
    assert_ne!(first.items[0].identifier, second.items[0].identifier);
    assert!(second.next_cursor.is_none());
    // A cursor for other filters is refused.
    assert!(matches!(
        list(&state, &a, CTX, &only_none, Some(&cursor), None, Utc::now()).await,
        Err(CollectionError::CursorInvalid)
    ));
}
