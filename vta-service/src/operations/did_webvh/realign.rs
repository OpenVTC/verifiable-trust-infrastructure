//! Realign a DID's key records with the verification methods it publishes.
//!
//! ## What this repairs
//!
//! A key record's id **is** a verification-method id. `save_entity_key_records`
//! says so, and [`vta_sdk::did_secrets::select_secret_kid`] rule 1 depends on
//! it: the kid a mediator matches inbound JWE recipients against is the record
//! id, on the reasoning that "the DID document decided what the key is called".
//!
//! Create asserted `#key-0` / `#key-1` instead of reading the document it had
//! just published, so every DID minted from a template that numbers its methods
//! differently — `room` and `room-host` number from `#key-1` — stored records
//! under names its own document does not carry. `document::minted_vm_ids` fixes
//! that going forward. This fixes the DIDs already published.
//!
//! ## Why the agent computes the names
//!
//! `keys/rename` cannot express the repair, and that is deliberate: its
//! `validate_identifier` gate exists so a rename is "not a back door into
//! VM-shaped or namespace-colliding names", with a test pinning it. A caller
//! who could write `{someone-elses-did}#key-0` as a store key could squat the
//! kid of a DID that has not minted its keys yet.
//!
//! So no name here is caller-supplied. Every target comes out of the DID's own
//! published log, and every record is matched to a method by
//! **`publicKeyMultibase`** — the one identifier that survives whatever the
//! record is currently called. That is what lets this recover a key someone has
//! already renamed away from its verification-method id, which is otherwise
//! unreachable: no caller-facing call can name it again.
//!
//! ## It plans, then applies
//!
//! Nothing is written until every move is known to be safe, so a conflict
//! leaves the keystore exactly as it was rather than half-moved. `dry_run`
//! returns the same plan without applying it, which is what an operator should
//! read before letting anything touch key records.

use tracing::info;

use vta_sdk::keys::KeyRecord;
pub use vta_sdk::protocols::did_management::realign::{RealignDidKeysResultBody, RealignedKey};

use crate::auth::AuthClaims;
use crate::error::AppError;
use crate::keys;
use crate::store::KeyspaceHandle;
use crate::webvh_store;

/// Rewrite `did`'s key records onto the verification-method ids its current
/// published document carries.
///
/// Admin, and scoped to the DID's own context like every other operation on
/// this record. `dry_run` returns the plan without writing.
///
/// Takes the two keyspaces it reads rather than [`WebvhDeps`](super::WebvhDeps):
/// this repair touches no resolver, no seed store and no transport, and a
/// parameter list that says so is one a test can satisfy without standing up a
/// DIDComm bridge to prove that a record moved.
pub async fn realign_did_key_records(
    keys_ks: &KeyspaceHandle,
    webvh_ks: &KeyspaceHandle,
    audit: &vta_audit::SharedAuditSink,
    auth: &AuthClaims,
    did: &str,
    dry_run: bool,
    channel: &str,
) -> Result<RealignDidKeysResultBody, AppError> {
    auth.require_admin()?;

    let mut record = webvh_store::get_did(webvh_ks, did)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("webvh DID not found: {did}")))?;
    auth.require_context(&record.context_id)?;

    // The DID's own log, not a resolution: this agent published it, and a
    // repair that depends on the network is a repair that cannot run when the
    // network is what is broken.
    let did_log = webvh_store::get_did_log(webvh_ks, did)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("no local log for {did}")))?;
    let document = crate::operations::protocol::document::current_document_from_log(&did_log)
        .map_err(|e| AppError::Internal(format!("read the current document of {did}: {e}")))?;

    let methods = document
        .get("verificationMethod")
        .and_then(serde_json::Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();

    let mut moved: Vec<RealignedKey> = Vec::new();
    let mut already_aligned: Vec<String> = Vec::new();
    let mut unmatched: Vec<String> = Vec::new();
    // Held until the whole plan is known, so a conflict on the last method does
    // not leave the first three moved.
    let mut plan: Vec<(String, KeyRecord)> = Vec::new();

    for method in methods {
        let Some(vm_id) = method.get("id").and_then(serde_json::Value::as_str) else {
            continue;
        };
        let Some(public_key) = method
            .get("publicKeyMultibase")
            .and_then(serde_json::Value::as_str)
        else {
            // A method this agent cannot match on key material — a JWK, say.
            unmatched.push(vm_id.to_string());
            continue;
        };

        let Some(mut held) =
            crate::operations::keys::find_key_by_public_multibase(keys_ks, public_key).await?
        else {
            unmatched.push(vm_id.to_string());
            continue;
        };

        if held.key_id == vm_id {
            already_aligned.push(vm_id.to_string());
            continue;
        }

        moved.push(RealignedKey {
            from: held.key_id.clone(),
            to: vm_id.to_string(),
            public_key: public_key.to_string(),
        });

        // A label that was the old verification-method id follows the id.
        // `select_secret_kid` rule 2 adopts a VM-shaped label as the kid, so a
        // stale one is a second wrong answer left behind by the repair; a label
        // an operator wrote is theirs and is left alone.
        let vm_prefix = format!("{did}#");
        if held
            .label
            .as_deref()
            .is_some_and(|l| l.starts_with(&vm_prefix))
        {
            held.label = Some(vm_id.to_string());
        }
        held.key_id = vm_id.to_string();
        held.updated_at = chrono::Utc::now();
        plan.push((moved.last().unwrap().from.clone(), held));
    }

    // ── The plan has to be checked as a whole, because the moves interleave ──
    //
    // A room's two records move `#key-0` → `#key-1` and `#key-1` → `#key-2`,
    // so the signing key's destination is occupied *by the other record in
    // this plan* — and the general case is a cycle, which no ordering unpicks.
    // A per-move "is the target free?" check therefore refuses the very shape
    // this repair exists for. What must be refused is a target held by a key
    // that is **not** moving: two keys claiming one verification method is the
    // confusion being repaired, and guessing which the document meant is not
    // this function's decision to take.
    let vacating: std::collections::HashSet<&str> =
        plan.iter().map(|(from, _)| from.as_str()).collect();
    for (_, updated) in &plan {
        if let Some(sitting) = keys_ks
            .get::<KeyRecord>(keys::store_key(&updated.key_id))
            .await?
            && sitting.public_key != updated.public_key
            && !vacating.contains(sitting.key_id.as_str())
        {
            return Err(AppError::Conflict(format!(
                "{} is already held by a different key ({}), which this repair does not move; \
                 nothing was changed",
                updated.key_id, sitting.key_id
            )));
        }
    }

    let next_fragment_id = super::document::highest_key_fragment(&document).map_or(2, |n| n + 1);

    if dry_run {
        return Ok(RealignDidKeysResultBody {
            did: did.to_string(),
            moved,
            already_aligned,
            unmatched,
            next_fragment_id,
            dry_run: true,
        });
    }

    // Write every destination first, then drop the sources that nothing landed
    // on. The order matters for what a crash in the middle leaves behind: this
    // way it is a *duplicate* record, which the next run collapses, rather than
    // a key with no record at all — and private key material whose record is
    // gone is material nothing can find again.
    let destinations: std::collections::HashSet<String> =
        plan.iter().map(|(_, r)| r.key_id.clone()).collect();
    for (from, updated) in &plan {
        keys_ks
            .insert(keys::store_key(&updated.key_id), updated)
            .await?;
        info!(channel, did = %did, old_id = %from, new_id = %updated.key_id, "key record realigned");
    }
    for (from, _) in &plan {
        if !destinations.contains(from) {
            keys_ks.remove(keys::store_key(from)).await?;
        }
    }

    for (_, updated) in plan {
        let to = updated.key_id.clone();
        crate::audit::record_best_effort(
            audit,
            "key.realign",
            &auth.did,
            Some(&to),
            "success",
            Some(channel),
            Some(&record.context_id),
        )
        .await;
    }

    if record.next_fragment_id != next_fragment_id {
        record.next_fragment_id = next_fragment_id;
        record.updated_at = chrono::Utc::now();
        webvh_store::store_did(webvh_ks, &record).await?;
    }

    Ok(RealignDidKeysResultBody {
        did: did.to_string(),
        moved,
        already_aligned,
        unmatched,
        next_fragment_id,
        dry_run: false,
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use chrono::Utc;
    use didwebvh_rs::create::{CreateDIDConfig, create_did};
    use didwebvh_rs::parameters::Parameters as WebVHParameters;
    use serde_json::json;
    use vta_sdk::keys::{KeyStatus, KeyType};
    use vti_common::acl::Role;

    use super::*;
    use crate::store::KeyspaceHandle;
    use vta_sdk::webvh::WebvhDidRecord;

    /// A room-shaped DID: a **real** published log whose document numbers its
    /// methods from `#key-1`, exactly as the `room` and `room-host` templates
    /// do. Built through `create_did` rather than hand-written, so the repair is
    /// tested against a log the resolver would accept.
    async fn published_room_did(
        keys_ks: &KeyspaceHandle,
        webvh_ks: &KeyspaceHandle,
    ) -> (String, String, String) {
        let mut signing = affinidi_tdk::secrets_resolver::secrets::Secret::generate_ed25519(
            None,
            Some(&[3u8; 32]),
        );
        let signing_pub = signing
            .get_public_keymultibase()
            .expect("signing multibase");
        signing.id = format!("did:key:{signing_pub}#{signing_pub}");
        let ka_pub = affinidi_tdk::secrets_resolver::secrets::Secret::generate_ed25519(
            None,
            Some(&[4u8; 32]),
        )
        .to_x25519()
        .expect("x25519")
        .get_public_keymultibase()
        .expect("ka multibase");

        let document = json!({
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": "{DID}",
            "verificationMethod": [
                { "id": "{DID}#key-1", "type": "Multikey", "controller": "{DID}", "publicKeyMultibase": signing_pub },
                { "id": "{DID}#key-2", "type": "Multikey", "controller": "{DID}", "publicKeyMultibase": ka_pub },
            ],
            "authentication": ["{DID}#key-1"],
            "assertionMethod": ["{DID}#key-1"],
            "keyAgreement": ["{DID}#key-2"],
        });

        let cfg = CreateDIDConfig::builder()
            .address("https://example.invalid/rooms/northwind/did.jsonl")
            .authorization_key(signing)
            .did_document(document)
            .parameters(WebVHParameters {
                update_keys: Some(Arc::new(vec![signing_pub.clone().into()])),
                ..Default::default()
            })
            .build()
            .expect("create config");
        let result = create_did(cfg).await.expect("create did");
        let did = result.did().to_string();
        let log = serde_json::to_string(result.log_entry()).expect("serialise log");

        webvh_store::store_did_log(webvh_ks, &did, &log)
            .await
            .expect("store log");
        let now = Utc::now();
        webvh_store::store_did(
            webvh_ks,
            &WebvhDidRecord {
                did: did.clone(),
                server_id: "serverless".into(),
                mnemonic: String::new(),
                scid: "irrelevant".into(),
                context_id: "rooms".into(),
                portable: false,
                log_entry_count: 1,
                pre_rotation_count: 0,
                // What create stored: two methods, numbered from zero — the
                // assumption this repair exists because of.
                next_fragment_id: 2,
                created_at: now,
                updated_at: now,
            },
        )
        .await
        .expect("store did record");

        // And the records as create wrote them: `#key-0` / `#key-1` over a
        // document that says `#key-1` / `#key-2`.
        plant(
            keys_ks,
            &format!("{did}#key-0"),
            KeyType::Ed25519,
            &signing_pub,
            Some(&format!("{did}#key-0")),
        )
        .await;
        plant(
            keys_ks,
            &format!("{did}#key-1"),
            KeyType::X25519,
            &ka_pub,
            Some(&format!("{did}#key-1")),
        )
        .await;

        (did, signing_pub, ka_pub)
    }

    async fn plant(
        keys_ks: &KeyspaceHandle,
        key_id: &str,
        key_type: KeyType,
        public_key: &str,
        label: Option<&str>,
    ) {
        keys::save_key_record(
            keys_ks,
            key_id,
            "m/26'/2'/48'/0'",
            key_type,
            public_key,
            label.unwrap_or(key_id),
            Some("rooms"),
            Some(0),
        )
        .await
        .expect("plant key record");
    }

    fn admin_of(context: &str) -> AuthClaims {
        AuthClaims {
            did: "did:key:z6MkRoomsAdmin".into(),
            role: Role::Admin,
            allowed_contexts: vec![context.into()],
            session_id: "test".into(),
            access_expires_at: 0,
            issued_at: 0,
            amr: Vec::new(),
            acr: String::new(),
        }
    }

    async fn held(keys_ks: &KeyspaceHandle, key_id: &str) -> Option<KeyRecord> {
        keys_ks
            .get::<KeyRecord>(keys::store_key(key_id))
            .await
            .expect("read record")
    }

    /// The repair, end to end: after it, every method the document publishes
    /// names a record this agent holds.
    #[tokio::test]
    async fn key_records_take_the_names_the_document_publishes() {
        let ts = crate::test_support::open_test_store().await;
        let (did, signing_pub, ka_pub) = published_room_did(&ts.keys_ks, &ts.webvh_ks).await;

        let result = realign_did_key_records(
            &ts.keys_ks,
            &ts.webvh_ks,
            &ts.audit,
            &admin_of("rooms"),
            &did,
            false,
            "test",
        )
        .await
        .expect("realign");

        assert_eq!(
            result.moved.len(),
            2,
            "both records were misnamed: {result:?}"
        );
        assert!(result.unmatched.is_empty(), "{:?}", result.unmatched);

        // The claim, stated as the thing that was actually broken: the
        // document's signing method now resolves to the agent's ed25519 key,
        // and its keyAgreement method to the x25519 one. Before the repair,
        // `#key-1` named the x25519 key while the document said it was the
        // signing key — one name, two keys.
        let signing = held(&ts.keys_ks, &format!("{did}#key-1"))
            .await
            .expect("#key-1 held");
        assert_eq!(signing.public_key, signing_pub);
        assert_eq!(signing.key_type, KeyType::Ed25519);

        let ka = held(&ts.keys_ks, &format!("{did}#key-2"))
            .await
            .expect("#key-2 held");
        assert_eq!(ka.public_key, ka_pub);
        assert_eq!(ka.key_type, KeyType::X25519);

        // And the old names are gone rather than duplicated — two records for
        // one key is the same ambiguity wearing different clothes.
        assert!(held(&ts.keys_ks, &format!("{did}#key-0")).await.is_none());
    }

    /// The case that motivated this being an agent-side repair at all: a key
    /// someone already renamed away from its verification-method id. No
    /// caller-facing call can name it again — `keys/rename` refuses `:` and `#`
    /// — so matching on the public key is the only way back.
    #[tokio::test]
    async fn a_key_renamed_away_from_its_method_id_is_still_found() {
        let ts = crate::test_support::open_test_store().await;
        let (did, _signing_pub, ka_pub) = published_room_did(&ts.keys_ks, &ts.webvh_ks).await;

        // Exactly what an operator gets today by trying to fix the numbering
        // by hand: the rename lands under a plain label, and the key is adrift.
        let renamed = keys::store_key("vdr-host-key-2");
        assert!(
            ts.keys_ks
                .swap(keys::store_key(&format!("{did}#key-1")), renamed, &{
                    let mut r = held(&ts.keys_ks, &format!("{did}#key-1"))
                        .await
                        .expect("held");
                    r.key_id = "vdr-host-key-2".into();
                    r
                })
                .await
                .expect("swap"),
        );

        let result = realign_did_key_records(
            &ts.keys_ks,
            &ts.webvh_ks,
            &ts.audit,
            &admin_of("rooms"),
            &did,
            false,
            "test",
        )
        .await
        .expect("realign");

        assert!(
            result
                .moved
                .iter()
                .any(|m| m.from == "vdr-host-key-2" && m.to == format!("{did}#key-2")),
            "the renamed key was not recovered: {result:?}",
        );
        let ka = held(&ts.keys_ks, &format!("{did}#key-2"))
            .await
            .expect("#key-2 held");
        assert_eq!(ka.public_key, ka_pub);
        // The label followed the id: `select_secret_kid` rule 2 adopts a
        // VM-shaped label as the kid, so a stale one is a second wrong answer.
        assert_eq!(ka.label.as_deref(), Some(&*format!("{did}#key-2")));
    }

    /// `next_fragment_id` is repaired too. Left at 2, this DID's first rotation
    /// would allocate `#key-2` — the id its keyAgreement method is published
    /// under.
    #[tokio::test]
    async fn the_rotation_counter_clears_the_published_methods() {
        let ts = crate::test_support::open_test_store().await;
        let (did, _, _) = published_room_did(&ts.keys_ks, &ts.webvh_ks).await;

        let result = realign_did_key_records(
            &ts.keys_ks,
            &ts.webvh_ks,
            &ts.audit,
            &admin_of("rooms"),
            &did,
            false,
            "test",
        )
        .await
        .expect("realign");

        assert_eq!(result.next_fragment_id, 3);
        let record = webvh_store::get_did(&ts.webvh_ks, &did)
            .await
            .expect("get")
            .expect("record");
        assert_eq!(
            record.next_fragment_id, 3,
            "the counter was reported but not stored"
        );
    }

    /// A dry run is a plan. The point of offering one is that an operator can
    /// read what would move before anything touches key custody — so it must
    /// write nothing, including the counter.
    #[tokio::test]
    async fn a_dry_run_writes_nothing() {
        let ts = crate::test_support::open_test_store().await;
        let (did, _, _) = published_room_did(&ts.keys_ks, &ts.webvh_ks).await;

        let result = realign_did_key_records(
            &ts.keys_ks,
            &ts.webvh_ks,
            &ts.audit,
            &admin_of("rooms"),
            &did,
            true,
            "test",
        )
        .await
        .expect("realign");

        assert_eq!(result.moved.len(), 2, "the plan is still reported");
        assert!(result.dry_run);
        assert!(
            held(&ts.keys_ks, &format!("{did}#key-0")).await.is_some(),
            "a record moved"
        );
        assert!(
            held(&ts.keys_ks, &format!("{did}#key-2")).await.is_none(),
            "a record was written"
        );
        let record = webvh_store::get_did(&ts.webvh_ks, &did)
            .await
            .expect("get")
            .expect("record");
        assert_eq!(record.next_fragment_id, 2, "the counter was written");
    }

    /// Running it twice is running it once. A repair an operator is afraid to
    /// re-run is one they will not run.
    #[tokio::test]
    async fn a_second_run_has_nothing_left_to_do() {
        let ts = crate::test_support::open_test_store().await;
        let (did, _, _) = published_room_did(&ts.keys_ks, &ts.webvh_ks).await;
        let auth = admin_of("rooms");

        realign_did_key_records(
            &ts.keys_ks,
            &ts.webvh_ks,
            &ts.audit,
            &auth,
            &did,
            false,
            "test",
        )
        .await
        .expect("first realign");
        let again = realign_did_key_records(
            &ts.keys_ks,
            &ts.webvh_ks,
            &ts.audit,
            &auth,
            &did,
            false,
            "test",
        )
        .await
        .expect("second realign");

        assert!(again.moved.is_empty(), "{:?}", again.moved);
        assert_eq!(again.already_aligned.len(), 2);
    }

    /// The context scoping every other operation on this record enforces. A
    /// repair that rewrites key custody must not be the one place an admin of
    /// another context can reach.
    #[tokio::test]
    async fn an_admin_of_another_context_is_refused() {
        let ts = crate::test_support::open_test_store().await;
        let (did, _, _) = published_room_did(&ts.keys_ks, &ts.webvh_ks).await;

        let err = realign_did_key_records(
            &ts.keys_ks,
            &ts.webvh_ks,
            &ts.audit,
            &admin_of("somewhere-else"),
            &did,
            false,
            "test",
        )
        .await
        .expect_err("cross-context admin must be refused");
        assert!(matches!(err, AppError::Forbidden(_)), "got {err:?}");
        assert!(
            held(&ts.keys_ks, &format!("{did}#key-0")).await.is_some(),
            "a record moved anyway"
        );
    }

    /// A method whose key this agent does not hold is reported, not skipped:
    /// "nothing to move" and "that key is not here" are different answers, and
    /// only one of them means the repair is complete.
    #[tokio::test]
    async fn a_method_this_agent_holds_no_key_for_is_named() {
        let ts = crate::test_support::open_test_store().await;
        let (did, _, ka_pub) = published_room_did(&ts.keys_ks, &ts.webvh_ks).await;
        ts.keys_ks
            .remove(keys::store_key(&format!("{did}#key-1")))
            .await
            .expect("drop the x25519 record");

        let result = realign_did_key_records(
            &ts.keys_ks,
            &ts.webvh_ks,
            &ts.audit,
            &admin_of("rooms"),
            &did,
            false,
            "test",
        )
        .await
        .expect("realign");

        assert_eq!(result.unmatched, vec![format!("{did}#key-2")]);
        assert_eq!(result.moved.len(), 1);
        assert!(
            crate::operations::keys::find_key_by_public_multibase(&ts.keys_ks, &ka_pub)
                .await
                .expect("lookup")
                .is_none(),
        );
    }

    /// Two keys claiming one verification method is the confusion this
    /// repairs, so it refuses rather than guessing — and refuses before
    /// writing, leaving the keystore exactly as it was.
    #[tokio::test]
    async fn a_method_already_held_by_a_different_key_refuses_everything() {
        let ts = crate::test_support::open_test_store().await;
        let (did, _, _) = published_room_did(&ts.keys_ks, &ts.webvh_ks).await;
        plant(
            &ts.keys_ks,
            &format!("{did}#key-2"),
            KeyType::X25519,
            "z6LSsomeOtherKeyEntirely",
            None,
        )
        .await;

        let err = realign_did_key_records(
            &ts.keys_ks,
            &ts.webvh_ks,
            &ts.audit,
            &admin_of("rooms"),
            &did,
            false,
            "test",
        )
        .await
        .expect_err("a collision must refuse");
        assert!(matches!(err, AppError::Conflict(_)), "got {err:?}");

        // Nothing moved — including the signing key, whose own move was safe.
        assert!(held(&ts.keys_ks, &format!("{did}#key-0")).await.is_some());
        assert!(held(&ts.keys_ks, &format!("{did}#key-1")).await.is_some());
    }

    /// The floor: a DID whose records already match is left alone entirely.
    #[tokio::test]
    async fn a_correctly_named_did_is_untouched() {
        let ts = crate::test_support::open_test_store().await;
        let (did, _, _) = published_room_did(&ts.keys_ks, &ts.webvh_ks).await;
        let auth = admin_of("rooms");
        realign_did_key_records(
            &ts.keys_ks,
            &ts.webvh_ks,
            &ts.audit,
            &auth,
            &did,
            false,
            "test",
        )
        .await
        .expect("realign");
        let before = held(&ts.keys_ks, &format!("{did}#key-1"))
            .await
            .expect("held")
            .updated_at;

        let again = realign_did_key_records(
            &ts.keys_ks,
            &ts.webvh_ks,
            &ts.audit,
            &auth,
            &did,
            false,
            "test",
        )
        .await
        .expect("realign");

        assert!(again.moved.is_empty());
        assert_eq!(
            held(&ts.keys_ks, &format!("{did}#key-1"))
                .await
                .expect("held")
                .updated_at,
            before,
            "an aligned record was rewritten",
        );
    }

    /// Unused in the assertions above but load-bearing for the shape: the
    /// planted records are what create actually writes.
    #[tokio::test]
    async fn the_fixture_reproduces_the_defect() {
        let ts = crate::test_support::open_test_store().await;
        let (did, signing_pub, _) = published_room_did(&ts.keys_ks, &ts.webvh_ks).await;
        let mislabelled = held(&ts.keys_ks, &format!("{did}#key-1"))
            .await
            .expect("held");
        assert_eq!(mislabelled.key_type, KeyType::X25519);
        assert_eq!(
            held(&ts.keys_ks, &format!("{did}#key-0"))
                .await
                .expect("held")
                .public_key,
            signing_pub,
            "the document calls this key #key-1; the keystore calls it #key-0",
        );
        assert_eq!(mislabelled.status, KeyStatus::Active);
    }
}
