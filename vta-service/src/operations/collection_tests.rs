//! Collection claims, the listing, the plan and each context's setting
//! (VTI-NTF-080 – 098), against a
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
async fn vti_ntf_094_on_by_default_with_no_record_and_listed_as_collected_by_the_vta() {
    let (state, _dir) = state().await;
    assert!(
        !state.collection.suspended(),
        "not suspended unless suspended"
    );
    assert!(
        get_setting(&state.collection_ks, CTX)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        context_collects_by_default(&state.collection_ks, CTX)
            .await
            .unwrap()
    );
    let auth = client("did:key:z6MkClientA", CTX);
    let view = show_setting(&state, &auth, CTX).await.unwrap();
    assert!(view.collect_by_default);
    assert!(!view.suspended_by_operator);
    assert_eq!(view.changed, None, "never changed");
    let wire = view.to_wire();
    assert!(wire.get("changedBy").is_none() && wire.get("changedAt").is_none());
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
    assert_eq!(page.items[0].to_wire()["collector"], "vta");
}

#[tokio::test]
async fn vti_ntf_097_disabled_is_listed_as_disabled_while_claims_still_work() {
    let (state, _dir) = state().await;
    let auth = client("did:key:z6MkClientA", CTX);
    set_setting(&state, &auth, CTX, false, Utc::now())
        .await
        .unwrap();
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
async fn vti_ntf_095_disabling_closes_the_contexts_connections_before_it_answers() {
    let (state, _dir) = state().await;
    // A persona of another context is left alone: the setting is per context.
    seed_persona(&state, OTHER, PERSONA2, Some(MEDIATOR)).await;
    let (mine, mine_closed) = fake();
    let (theirs, theirs_closed) = fake();
    state.collection.insert(PERSONA, mine).unwrap();
    state.collection.insert(PERSONA2, theirs).unwrap();

    let admin = client("did:key:z6MkAdminA", CTX);
    let now = Utc::now();
    let change = set_setting(&state, &admin, CTX, false, now).await.unwrap();
    assert!(change.changed);
    assert_eq!(change.closed, 1);
    assert_eq!(
        mine_closed.load(Ordering::SeqCst),
        1,
        "closed before the answer"
    );
    assert!(!state.collection.is_collecting(PERSONA));
    assert_eq!(theirs_closed.load(Ordering::SeqCst), 0);
    assert!(state.collection.is_collecting(PERSONA2));
    assert!(!change.setting.collect_by_default);
    assert_eq!(
        change.setting.changed,
        Some(("did:key:z6MkAdminA".to_string(), whole_seconds(now)))
    );

    // The plan now gives nobody the context's persona; the other context's is
    // still the VTA's.
    let plan = current_plan(&state, Utc::now()).await.unwrap();
    for (c, a) in &plan {
        if c.context_id == CTX {
            assert_eq!(*a, Assignment::Nobody(NotCollected::Disabled));
        } else {
            assert!(matches!(a, Assignment::Vta { .. }), "{a:?}");
        }
    }
    // Audited with who and what.
    let rows = crate::operations::audit::successful_rows_on_channel(
        &state.audit_ks,
        "collection.setting.disabled",
        "trust-task",
    )
    .await
    .unwrap();
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].actor, "did:key:z6MkAdminA");
    assert_eq!(rows[0].context_id.as_deref(), Some(CTX));
}

#[tokio::test]
async fn vti_ntf_095_the_same_value_changes_nothing() {
    let (state, _dir) = state().await;
    let admin = client("did:key:z6MkAdminA", CTX);
    // Enabling a context that was never changed: already enabled.
    let change = set_setting(&state, &admin, CTX, true, Utc::now())
        .await
        .unwrap();
    assert!(!change.changed);
    assert_eq!(change.setting.changed, None, "still never changed");
    assert!(
        get_setting(&state.collection_ks, CTX)
            .await
            .unwrap()
            .is_none()
    );

    let first = set_setting(&state, &admin, CTX, false, Utc::now())
        .await
        .unwrap();
    let other = client("did:key:z6MkAdminB", CTX);
    let again = set_setting(&state, &other, CTX, false, Utc::now() + Duration::hours(1))
        .await
        .unwrap();
    assert!(!again.changed);
    assert_eq!(
        again.setting, first.setting,
        "who last changed it is not moved by a request that changed nothing"
    );
    let rows = crate::operations::audit::successful_rows_on_channel(
        &state.audit_ks,
        "collection.setting.disabled",
        "trust-task",
    )
    .await
    .unwrap();
    assert_eq!(rows.len(), 1, "one change, one row");
}

#[tokio::test]
async fn vti_ntf_095_enabling_resumes_including_after_a_conflict() {
    let (state, _dir) = state().await;
    let admin = client("did:key:z6MkAdminA", CTX);
    set_setting(&state, &admin, CTX, false, Utc::now())
        .await
        .unwrap();
    record_conflict(
        &state.collection_ks,
        &ConflictRecord {
            context_id: CTX.into(),
            log_did: PERSONA.into(),
            since: Utc::now(),
            closures: 5,
        },
    )
    .await
    .unwrap();
    let change = set_setting(&state, &admin, CTX, true, Utc::now())
        .await
        .unwrap();
    assert!(change.changed);
    assert_eq!(change.conflicts_cleared, 1, "VTI-NTF-085 cleared");
    assert!(
        get_conflict(&state.collection_ks, CTX, PERSONA)
            .await
            .unwrap()
            .is_none()
    );
    let plan = current_plan(&state, Utc::now()).await.unwrap();
    assert_eq!(plan[0].1, Assignment::Vta { open_now: true });
}

#[tokio::test]
async fn vti_ntf_095_only_administrative_authority_over_the_context_may_change_it() {
    let (state, _dir) = state().await;
    // A child of CTX, so an admin of CTX is an ancestor's admin.
    let mut child = crate::contexts::create_context(&state.contexts_ks, "tmp-child", "Sub")
        .await
        .unwrap();
    child.id = format!("{CTX}/sub");
    crate::contexts::store_context(&state.contexts_ks, &child)
        .await
        .unwrap();
    let sub = format!("{CTX}/sub");

    // Standing without an administrative role: may read, may not change.
    let mut reader = client("did:key:z6MkReader", CTX);
    reader.role = crate::acl::Role::Application;
    assert!(show_setting(&state, &reader, CTX).await.is_ok());
    assert!(matches!(
        set_setting(&state, &reader, CTX, false, Utc::now()).await,
        Err(CollectionError::PermissionDenied)
    ));
    // Another context's admin: neither.
    let other_admin = client("did:key:z6MkOtherAdmin", OTHER);
    assert!(matches!(
        show_setting(&state, &other_admin, CTX).await,
        Err(CollectionError::PermissionDenied)
    ));
    assert!(matches!(
        set_setting(&state, &other_admin, CTX, false, Utc::now()).await,
        Err(CollectionError::PermissionDenied)
    ));
    // An ancestor's admin may change a descendant's setting, which is that
    // context's alone: neither the ancestor nor anything else changes.
    let ancestor_admin = client("did:key:z6MkAncestor", CTX);
    assert!(
        set_setting(&state, &ancestor_admin, &sub, false, Utc::now())
            .await
            .unwrap()
            .changed
    );
    assert!(
        context_collects_by_default(&state.collection_ks, CTX)
            .await
            .unwrap(),
        "not inherited upward"
    );
    // And the descendant's setting is not inherited from the ancestor's.
    set_setting(&state, &ancestor_admin, &sub, true, Utc::now())
        .await
        .unwrap();
    set_setting(&state, &ancestor_admin, CTX, false, Utc::now())
        .await
        .unwrap();
    assert!(
        context_collects_by_default(&state.collection_ks, &sub)
            .await
            .unwrap(),
        "not inherited downward"
    );
    // A super-administrator may change any context's.
    let root = crate::test_support::super_admin_claims();
    assert!(
        set_setting(&state, &root, OTHER, false, Utc::now())
            .await
            .unwrap()
            .changed
    );
    // A context that does not exist is not found, not created.
    assert!(matches!(
        set_setting(&state, &root, "nowhere", false, Utc::now()).await,
        Err(CollectionError::App(AppError::NotFound(_)))
    ));
    assert!(
        get_setting(&state.collection_ks, "nowhere")
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn vti_ntf_098_suspension_disables_everything_and_changes_no_setting() {
    let (state, _dir) = state().await;
    seed_persona(&state, OTHER, PERSONA2, Some(MEDIATOR)).await;
    let admin = client("did:key:z6MkAdminA", CTX);
    set_setting(&state, &admin, CTX, false, Utc::now())
        .await
        .unwrap();
    state.collection.set_suspended(true);
    record_suspension(&state).await.unwrap();
    let plan = current_plan(&state, Utc::now()).await.unwrap();
    assert!(
        plan.iter()
            .all(|(_, a)| *a == Assignment::Nobody(NotCollected::Disabled)),
        "{plan:?}"
    );
    // Shown, and no context's setting moved.
    let view = show_setting(&state, &client("did:key:z6MkB", OTHER), OTHER)
        .await
        .unwrap();
    assert!(view.suspended_by_operator);
    assert!(view.collect_by_default, "the suspension changes no setting");
    assert!(
        !show_setting(&state, &admin, CTX)
            .await
            .unwrap()
            .collect_by_default
    );
    // A change made while suspended is stored and answered, and collects
    // nothing (Consumer item 7).
    let change = set_setting(&state, &admin, CTX, true, Utc::now())
        .await
        .unwrap();
    assert!(change.changed && change.setting.suspended_by_operator);
    let plan = current_plan(&state, Utc::now()).await.unwrap();
    assert!(
        plan.iter()
            .all(|(_, a)| *a == Assignment::Nobody(NotCollected::Disabled))
    );
    // Lifting it never enables a context its setting disables.
    set_setting(&state, &admin, CTX, false, Utc::now())
        .await
        .unwrap();
    state.collection.set_suspended(false);
    record_suspension(&state).await.unwrap();
    for (c, a) in current_plan(&state, Utc::now()).await.unwrap() {
        if c.context_id == CTX {
            assert_eq!(a, Assignment::Nobody(NotCollected::Disabled));
        } else {
            assert!(matches!(a, Assignment::Vta { .. }));
        }
    }
    // Engaging and lifting are each audited once.
    for action in ["collection.suspended", "collection.suspension_lifted"] {
        let rows =
            crate::operations::audit::successful_rows_on_channel(&state.audit_ks, action, "config")
                .await
                .unwrap();
        assert_eq!(rows.len(), 1, "{action}");
    }
    record_suspension(&state).await.unwrap();
    let rows = crate::operations::audit::successful_rows_on_channel(
        &state.audit_ks,
        "collection.suspension_lifted",
        "config",
    )
    .await
    .unwrap();
    assert_eq!(rows.len(), 1, "an unchanged boot audits nothing");
}

#[tokio::test]
async fn vti_ntf_098_a_first_boot_unsuspended_audits_nothing_and_drops_the_retired_row() {
    let (state, _dir) = state().await;
    state
        .collection_ks
        .insert(RETIRED_SETTING_KEY, &false)
        .await
        .unwrap();
    record_suspension(&state).await.unwrap();
    assert!(
        state
            .collection_ks
            .get_raw(RETIRED_SETTING_KEY)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        state
            .collection_ks
            .get::<bool>(SUSPENSION_KEY)
            .await
            .unwrap(),
        Some(false)
    );
}

#[tokio::test]
async fn vti_ntf_094_the_setting_survives_a_restart() {
    let (state, dir) = state().await;
    let admin = client("did:key:z6MkAdminA", CTX);
    set_setting(&state, &admin, CTX, false, Utc::now())
        .await
        .unwrap();
    state.store.persist().await.unwrap();
    let data_dir = state.config.read().await.store.data_dir.clone();
    drop(state);
    // The store opened again, as the next boot opens it: the setting is what
    // was stored, not anything the first process held.
    let store = crate::store::Store::open(&vti_common::config::StoreConfig { data_dir })
        .expect("reopen store");
    let ks = store.keyspace(crate::keyspaces::COLLECTION).unwrap();
    assert!(!context_collects_by_default(&ks, CTX).await.unwrap());
    assert!(context_collects_by_default(&ks, OTHER).await.unwrap());
    drop(dir);
}

/// A provisioned integration's `did:webvh`, as provision-integration left one
/// before it recorded `provisioned:` — the evidence `backfill_provisioned`
/// reads: its key labelled with the holder's `did:key`, or an export audited on
/// the `provision-integration` channel.
async fn seed_old_integration(state: &AppState, did: &str, labelled: bool) {
    seed_persona(state, CTX, did, Some(MEDIATOR)).await;
    if labelled {
        crate::keys::save_key_record(
            &state.keys_ks,
            &format!("{did}#key-0"),
            "m/26'/2'/0'/9'",
            vta_sdk::keys::KeyType::Ed25519,
            "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
            "did:key:z6MkHolderEphemeral signing key",
            Some(CTX),
            Some(0),
        )
        .await
        .unwrap();
    } else {
        vta_audit::record(
            &state.audit_sink,
            "key.secret_export",
            "did:key:z6MkRelayer",
            Some(&format!("{did}#key-0")),
            "success",
            Some("provision-integration"),
            Some(CTX),
        )
        .await
        .unwrap();
    }
}

#[tokio::test]
async fn vti_ntf_080_the_upgrade_backfill_records_earlier_integrations_once() {
    let (state, _dir) = state().await;
    const BY_LABEL: &str = "did:webvh:QmOldLabel:old.example";
    const BY_AUDIT: &str = "did:webvh:QmOldAudit:old.example";
    seed_old_integration(&state, BY_LABEL, true).await;
    seed_old_integration(&state, BY_AUDIT, false).await;
    // A persona with an ordinary label is not an integration.
    crate::keys::save_key_record(
        &state.keys_ks,
        &format!("{PERSONA}#key-0"),
        "m/26'/2'/0'/1'",
        vta_sdk::keys::KeyType::Ed25519,
        "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
        "alice signing key",
        Some(CTX),
        Some(0),
    )
    .await
    .unwrap();

    let record = backfill_provisioned(&state).await.unwrap().expect("ran");
    let mut recorded = record.recorded.clone();
    recorded.sort();
    assert_eq!(recorded, vec![BY_AUDIT.to_string(), BY_LABEL.to_string()]);
    let found: Vec<String> = candidates(&state, Some(CTX))
        .await
        .unwrap()
        .into_iter()
        .map(|c| c.identifier)
        .collect();
    assert_eq!(
        found,
        vec![PERSONA.to_string()],
        "only the persona is collected for"
    );

    // Once: a second run changes nothing and reports nothing.
    assert!(backfill_provisioned(&state).await.unwrap().is_none());
    let rows = crate::operations::audit::successful_rows_on_channel(
        &state.audit_ks,
        "collection.provisioned_backfilled",
        "boot",
    )
    .await
    .unwrap();
    assert_eq!(rows.len(), 1);
}

#[test]
fn provisioned_key_labels_are_recognised_exactly() {
    assert!(provisioned_key_label("did:key:z6MkAbc signing key"));
    assert!(provisioned_key_label("did:key:z6MkAbc key-agreement key"));
    assert!(!provisioned_key_label("alice signing key"));
    assert!(!provisioned_key_label("did:key:z6MkAbc signing key #2"));
    assert!(!provisioned_key_label("my did:key:z6MkAbc signing key"));
    assert!(!provisioned_key_label("genesis pre-rotation #0"));
}

#[tokio::test]
async fn vti_ntf_082_a_grant_closes_the_vtas_connection_before_it_answers() {
    let (state, _dir) = state().await;
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
    let control = CollectionControl::new(false);
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
        disabled_contexts: &HashSet::new(),
        suspended: false,
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

    let suspended = plan(
        &cands,
        &PlanInputs {
            suspended: true,
            ..inputs
        },
    );
    assert!(
        matches!(suspended[0], Assignment::Client(_)),
        "a claim is shown while suspended"
    );
    assert_eq!(suspended[2], Assignment::Nobody(NotCollected::Disabled));
    assert_eq!(suspended[3], Assignment::Nobody(NotCollected::Disabled));

    // A context's own setting disables that context alone, and frees the bound
    // for the others (VTI-NTF-094).
    let mine_off: HashSet<String> = [CTX.to_string()].into();
    let off = plan(
        &cands,
        &PlanInputs {
            disabled_contexts: &mine_off,
            ..inputs
        },
    );
    assert!(matches!(off[0], Assignment::Client(_)));
    assert_eq!(off[2], Assignment::Nobody(NotCollected::Disabled));
    assert_eq!(off[3], Assignment::Vta { open_now: true });
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
            disabled_contexts: &HashSet::new(),
            suspended: false,
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
    // And its setting: a context created again under the id starts enabled
    // (VTI-NTF-094).
    set_setting(&state, &a, CTX, false, Utc::now())
        .await
        .unwrap();
    assert_eq!(purge_context(&state.collection_ks, CTX).await.unwrap(), 1);
    assert!(
        get_setting(&state.collection_ks, CTX)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn vti_ntf_091_listing_filters_and_pages() {
    let (state, _dir) = state().await;
    seed_persona(&state, CTX, PERSONA2, Some(MEDIATOR)).await;
    let a = client("did:key:z6MkClientA", CTX);
    claim(&state, &a, CTX, PERSONA, None, Utc::now())
        .await
        .unwrap();
    let only_vta = ListFilter {
        collector: Some("vta".into()),
        ..Default::default()
    };
    let page = list(&state, &a, CTX, &only_vta, None, None, Utc::now())
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
        list(&state, &a, CTX, &only_vta, Some(&cursor), None, Utc::now()).await,
        Err(CollectionError::CursorInvalid)
    ));
}
