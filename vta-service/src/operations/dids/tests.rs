//! The engines and the one listing over them. did:webs is exercised end to end
//! in `trust_tasks/webs_tests.rs`, where a real key event log is made.

use super::primary::{ClassConflict, class_conflict, is_node_identity};
use super::*;
use crate::test_support::{
    admin_claims_for_context, build_signing_test_app_state, super_admin_claims,
};

const MB: &str = "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";

async fn seed_did_key(state: &crate::server::AppState, mb: &str, context: Option<&str>) -> String {
    let did = format!("did:key:{mb}");
    vta_keys::save_key_record(
        &state.keys_ks,
        &format!("{did}#{mb}"),
        "m/26'/0'/0'",
        vta_sdk::keys::KeyType::Ed25519,
        mb,
        "holder",
        context,
        None,
    )
    .await
    .unwrap();
    did
}

#[cfg(feature = "webvh")]
async fn seed_webvh(state: &crate::server::AppState, scid: &str, context: &str) -> String {
    let did = format!("did:webvh:{scid}:host.example:{context}");
    let now = chrono::Utc::now();
    let record = vta_sdk::webvh::WebvhDidRecord {
        did: did.clone(),
        server_id: "prod".into(),
        mnemonic: context.into(),
        scid: scid.into(),
        context_id: context.into(),
        portable: false,
        log_entry_count: 1,
        pre_rotation_count: 0,
        next_fragment_id: 2,
        created_at: now,
        updated_at: now,
    };
    crate::webvh_store::store_did(&state.webvh_ks, &record)
        .await
        .unwrap();
    did
}

async fn context(state: &crate::server::AppState, id: &str, did: Option<&str>) {
    let mut c = crate::contexts::create_context(&state.contexts_ks, id, id)
        .await
        .unwrap();
    if let Some(did) = did {
        c.did = Some(did.to_string());
        crate::contexts::store_context(&state.contexts_ks, &c)
            .await
            .unwrap();
    }
}

#[tokio::test]
async fn a_did_key_is_summarised_from_its_own_key_record_and_nothing_else() {
    let (state, _dir) = build_signing_test_app_state().await;
    context(&state, "alice", None).await;
    let did = seed_did_key(&state, MB, Some("alice")).await;
    // A key that names another identity's method is that identity's, not a did:key.
    vta_keys::save_key_record(
        &state.keys_ks,
        "did:key:z6MkOther#key-0",
        "m/26'/0'/1'",
        vta_sdk::keys::KeyType::Ed25519,
        "z6MkOther",
        "",
        Some("alice"),
        None,
    )
    .await
    .unwrap();

    let all = list(
        DidStores::from_state(&state),
        &super_admin_claims(),
        &DidFilter::default(),
    )
    .await
    .unwrap();
    let keys: Vec<_> = all.iter().filter(|s| s.method == "key").collect();
    assert_eq!(keys.len(), 1, "{all:#?}");
    let s = keys[0];
    assert_eq!(s.did, did);
    assert_eq!(s.context_id.as_deref(), Some("alice"));
    assert_eq!(
        s.signing_key_id.as_deref(),
        Some(format!("{did}#{MB}").as_str())
    );
    assert_eq!(s.label.as_deref(), Some("holder"));
    assert!(s.method_details.is_none());
    assert!(!s.primary);
}

#[tokio::test]
async fn a_caller_sees_only_the_contexts_it_reaches_and_get_says_not_found_alike() {
    let (state, _dir) = build_signing_test_app_state().await;
    context(&state, "alice", None).await;
    context(&state, "bob", None).await;
    let alices = seed_did_key(&state, MB, Some("alice")).await;
    let stores = DidStores::from_state(&state);
    let bob = admin_claims_for_context("bob");

    let seen = list(stores, &bob, &DidFilter::default()).await.unwrap();
    assert!(seen.iter().all(|s| s.did != alices), "{seen:#?}");

    // Narrowed to a context it cannot reach: an empty page, not a refusal.
    let narrowed = list(
        stores,
        &bob,
        &DidFilter {
            context_id: Some("alice".into()),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert!(narrowed.is_empty());

    // Unreachable and absent answer the same.
    assert_eq!(get(stores, &bob, &alices).await.unwrap(), None);
    assert_eq!(
        get(stores, &bob, "did:key:z6MkNobodyHasThis")
            .await
            .unwrap(),
        None
    );
    assert!(
        get(stores, &admin_claims_for_context("alice"), &alices)
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn an_identity_in_no_context_is_for_an_unrestricted_caller_only() {
    let (state, _dir) = build_signing_test_app_state().await;
    context(&state, "alice", None).await;
    let loose = seed_did_key(&state, MB, None).await;
    let stores = DidStores::from_state(&state);
    assert_eq!(
        get(stores, &admin_claims_for_context("alice"), &loose)
            .await
            .unwrap(),
        None
    );
    assert!(
        get(stores, &super_admin_claims(), &loose)
            .await
            .unwrap()
            .is_some()
    );
}

#[cfg(feature = "webvh")]
#[tokio::test]
async fn every_engine_answers_one_listing_and_the_filters_narrow_it() {
    let (state, _dir) = build_signing_test_app_state().await;
    let webvh = seed_webvh(&state, "QmAlice", "alice").await;
    context(&state, "alice", Some(&webvh)).await;
    let key = seed_did_key(&state, MB, Some("alice")).await;
    let stores = DidStores::from_state(&state);
    let admin = admin_claims_for_context("alice");

    let all = list(stores, &admin, &DidFilter::default()).await.unwrap();
    let dids: Vec<&str> = all.iter().map(|s| s.did.as_str()).collect();
    assert_eq!(dids, [key.as_str(), webvh.as_str()], "sorted by DID");

    let w = all.iter().find(|s| s.did == webvh).unwrap();
    assert_eq!(w.method, "webvh");
    assert!(w.primary, "the context names it as its own");
    assert_eq!(w.server_id.as_deref(), Some("prod"));
    let details = w.method_details.as_ref().unwrap();
    assert_eq!(details["scid"], "QmAlice");
    assert_eq!(details["mnemonic"], "alice");

    let only_webvh = list(
        stores,
        &admin,
        &DidFilter {
            methods: Some(vec!["webvh".into()]),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(only_webvh.len(), 1);
    let on_server = list(
        stores,
        &admin,
        &DidFilter {
            server_id: Some("prod".into()),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(
        on_server.len(),
        1,
        "a did:key is published through no server"
    );

    // The wire form keys `methodDetails` by the method.
    let v = w.to_value();
    assert_eq!(v["methodDetails"]["webvh"]["scid"], "QmAlice");
    assert!(
        v.get("class").is_none(),
        "no class is recorded, so none is said"
    );
}

#[cfg(feature = "webvh")]
#[tokio::test]
async fn context_dids_name_every_engines_identities_in_that_context() {
    let (state, _dir) = build_signing_test_app_state().await;
    context(&state, "alice", None).await;
    context(&state, "bob", None).await;
    let webvh = seed_webvh(&state, "QmAlice", "alice").await;
    let key = seed_did_key(&state, MB, Some("alice")).await;
    seed_webvh(&state, "QmBob", "bob").await;
    let mut dids: Vec<String> = context_dids(DidStores::from_state(&state), "alice")
        .await
        .unwrap()
        .into_iter()
        .map(|(_, d)| d)
        .collect();
    dids.sort();
    assert_eq!(dids, [key, webvh]);
}

#[test]
fn a_did_is_matched_to_its_engine_by_kind() {
    assert_eq!(
        for_did("did:key:z6Mk").map(|e| e.methods()),
        Some(&["key"][..])
    );
    #[cfg(feature = "webvh")]
    {
        assert!(for_did("did:webvh:Qm:host").is_some());
        assert!(for_did("did:scid:vh:1:Qm").is_some());
    }
    #[cfg(feature = "webs")]
    assert_eq!(
        for_did("did:webs:host:E1").map(|e| e.methods()),
        Some(&["webs"][..])
    );
    assert!(
        for_did("did:peer:2.Vz6Mk").is_none(),
        "did:peer is not listed"
    );
}

#[tokio::test]
async fn the_class_guard_keeps_a_node_identity_from_a_persona() {
    let (state, _dir) = build_signing_test_app_state().await;
    let stores = DidStores::from_state(&state);
    let mut config = state.config.read().await.clone();
    config.vta_did = Some("did:webvh:QmVta:vta.example".into());
    let node = config.vta_did.clone();

    // This VTA's own DID is a service identity: a persona may not take its place.
    let c = class_conflict(
        stores,
        &config,
        node.as_deref(),
        "did:webs:h:EP",
        Some("persona"),
    )
    .await
    .unwrap();
    assert!(
        matches!(c, Some(ClassConflict::NeedsService { .. })),
        "{c:?}"
    );
    assert_eq!(c.unwrap().required_class(), Some("service"));
    assert!(is_node_identity(&config, node.as_deref()));

    // No recorded class on the candidate: not refused on class.
    let c = class_conflict(stores, &config, node.as_deref(), "did:key:z6Mk", None)
        .await
        .unwrap();
    assert_eq!(c, None);
    // Nothing to replace: nothing to conflict with.
    let c = class_conflict(stores, &config, None, "did:webs:h:EP", Some("persona"))
        .await
        .unwrap();
    assert_eq!(c, None);
}
