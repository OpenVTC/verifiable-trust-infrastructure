//! Integration test for the consent-records subsystem (task 1.3.5,
//! `docs/05-design-notes/vti-credential-architecture.md` §7a).
//!
//! Exercises the *public* `vta_service::vault::consent` API exactly as a
//! caller would, through the crate boundary and over a real on-disk `Store`:
//! build + sign a consent receipt, persist it, read it back (re-verifying the
//! holder Data Integrity proof), withdraw it (re-signed), and gate disclosure
//! through `authorizes`.
//!
//! This complements the in-module unit tests by proving the lifecycle is wired
//! end-to-end across the crate boundary with a real keyspace.

use affinidi_crypto::did_key;
use affinidi_secrets_resolver::secrets::Secret;
use chrono::{Duration, Utc};
use ed25519_dalek::SigningKey;
use vta_service::vault::consent::{self, ConsentGrant, ConsentStatusType};
use vta_service::vault::{ConsentRecord, authorizes};

use vti_common::config::StoreConfig;
use vti_common::store::{KeyspaceHandle, Store};

/// A holder `did:key` plus the VTA-managed signing `Secret`, derived from a
/// fixed seed so the proof's verification method lands under the DID.
fn holder_identity(seed: [u8; 32]) -> (String, Secret) {
    let sk = SigningKey::from_bytes(&seed);
    let pub_bytes = sk.verifying_key().to_bytes();
    let did = did_key::ed25519_pub_to_did_key(&pub_bytes);
    let vm = format!("{did}#{}", did.strip_prefix("did:key:").unwrap());
    let mut secret = Secret::generate_ed25519(Some(&vm), Some(&seed));
    secret.id = vm;
    (did, secret)
}

fn fresh_vault() -> (tempfile::TempDir, Store, KeyspaceHandle) {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = Store::open(&StoreConfig {
        data_dir: dir.path().to_path_buf(),
    })
    .expect("open store");
    // An at-rest key proves the consent record (holder DID, verifier DID,
    // reveal set) is encrypted on disk, like every other vault value.
    let ks = store
        .keyspace("vault")
        .expect("vault keyspace")
        .with_encryption([9u8; 32]);
    (dir, store, ks)
}

#[tokio::test]
async fn consent_lifecycle_end_to_end() {
    let (_dir, _store, vault) = fresh_vault();
    let (holder, key) = holder_identity([11u8; 32]);
    let verifier = "did:web:acme-verifier.example";
    let now = Utc::now();
    let valid_until = now + Duration::hours(1);

    // create — build + sign + store.
    let grant = ConsentGrant {
        holder_did: &holder,
        verifier_did: verifier,
        purpose: "join the Acme community",
        claims: vec!["givenName".into(), "memberSince".into()],
        valid_until,
    };
    let rec: ConsentRecord = consent::create(&vault, &grant, &key).await.unwrap();

    // The signed receipt carries every gating field and verifies.
    rec.verify_proof().expect("DI proof valid");
    assert_eq!(rec.data_subject, holder);
    assert_eq!(rec.process.recipient, verifier);
    assert_eq!(rec.process.purpose, "join the Acme community");
    assert_eq!(
        rec.process.personal_data,
        vec!["givenName".to_string(), "memberSince".to_string()]
    );
    assert!(rec.is_given());

    // get — re-verifies the proof and round-trips.
    let got = consent::get(&vault, &rec.identifier)
        .await
        .unwrap()
        .expect("present");
    assert_eq!(got, rec);

    // authorizes — true only for the right verifier + a claims subset.
    assert!(authorizes(&got, verifier, &["givenName".into()], now));
    assert!(authorizes(
        &got,
        verifier,
        &["givenName".into(), "memberSince".into()],
        now
    ));
    // NEGATIVE: a different verifier, or a claim outside the reveal set.
    assert!(!authorizes(
        &got,
        "did:web:evil.example",
        &["givenName".into()],
        now
    ));
    assert!(!authorizes(&got, verifier, &["dateOfBirth".into()], now));

    // withdraw — appends a re-signed ConsentWithdrawn event; authority gone.
    let withdrawn = consent::withdraw(&vault, &rec.identifier, &key)
        .await
        .unwrap()
        .expect("record exists");
    assert!(!withdrawn.is_given());
    assert_eq!(
        withdrawn.status.last().unwrap().event_type,
        ConsentStatusType::ConsentWithdrawn
    );
    withdrawn.verify_proof().expect("re-signed proof valid");
    assert!(
        !authorizes(&withdrawn, verifier, &["givenName".into()], now),
        "withdrawn record authorizes nothing"
    );

    // The withdrawn state is persisted.
    let reloaded = consent::get(&vault, &rec.identifier)
        .await
        .unwrap()
        .expect("present");
    assert!(!reloaded.is_given());

    // list — the holder's own local audit surface.
    let all = consent::list(&vault).await.unwrap();
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].identifier, rec.identifier);
}

#[tokio::test]
async fn expired_consent_authorizes_nothing_end_to_end() {
    let (_dir, _store, vault) = fresh_vault();
    let (holder, key) = holder_identity([12u8; 32]);
    let verifier = "did:web:acme-verifier.example";
    // Validity window already in the past.
    let valid_until = Utc::now() - Duration::minutes(1);

    let grant = ConsentGrant {
        holder_did: &holder,
        verifier_did: verifier,
        purpose: "join",
        claims: vec!["givenName".into()],
        valid_until,
    };
    let rec = consent::create(&vault, &grant, &key).await.unwrap();

    // Even with the right verifier and an in-scope claim, expiry denies.
    assert!(
        !authorizes(&rec, verifier, &["givenName".into()], Utc::now()),
        "an expired consent record must authorize nothing"
    );
}
