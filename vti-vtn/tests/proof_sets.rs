//! A VTC holding a post-quantum key signs with a proof set: one Ed25519 and one ML-DSA-44
//! proof. Every proof must verify, from a key of the issuer, for the expected purpose.

use std::collections::HashMap;

use affinidi_data_integrity::signer::Signer;
use affinidi_data_integrity::{DataIntegrityProof, SignOptions};
use affinidi_secrets_resolver::secrets::Secret;
use chrono::{Duration, Utc};
use dtg_credentials::DTGCredential;
use vti_vtn::VtnError;
use vti_vtn::verify::{KeyFuture, KeyResolver, verify_signed_by};

const DID: &str = "did:example:community";

struct Keys(HashMap<String, Vec<u8>>);

impl KeyResolver for Keys {
    fn resolve<'a>(&'a self, vm: &'a str, _purpose: &'a str) -> KeyFuture<'a> {
        Box::pin(async move {
            self.0
                .get(vm)
                .cloned()
                .ok_or_else(|| VtnError::Rejected(format!("unknown key {vm}")))
        })
    }
}

async fn signed_with(secrets: &[&Secret], purpose: &str) -> serde_json::Value {
    let vmc = DTGCredential::new_vmc(
        DID.into(),
        "did:example:member".into(),
        Utc::now() - Duration::seconds(5),
        None,
        false,
    )
    .with_id("urn:uuid:00000000-0000-4000-8000-000000000001");
    let mut doc = serde_json::to_value(&vmc).unwrap();
    let signers: Vec<&dyn Signer> = secrets.iter().map(|s| *s as &dyn Signer).collect();
    let proofs = DataIntegrityProof::sign_multi(
        &doc,
        &signers,
        SignOptions::new().with_proof_purpose(purpose),
    )
    .await
    .unwrap();
    doc["proof"] = serde_json::to_value(proofs).unwrap();
    doc
}

#[tokio::test]
async fn a_proof_set_verifies_and_every_proof_counts() {
    let ed = Secret::generate_ed25519(Some(&format!("{DID}#key-0")), Some(&[1; 32]));
    let pq = Secret::generate_ml_dsa_44(Some(&format!("{DID}#key-2")), Some(&[2; 32]));
    let keys = Keys(HashMap::from([
        (ed.id.clone(), ed.get_public_bytes().to_vec()),
        (pq.id.clone(), pq.get_public_bytes().to_vec()),
    ]));

    let both = signed_with(&[&ed, &pq], "assertionMethod").await;
    assert!(both["proof"].is_array());
    verify_signed_by(&both, DID, &keys, Utc::now())
        .await
        .unwrap();

    // One proof from a key that is not the issuer's: the set fails.
    let stranger = Secret::generate_ed25519(Some("did:example:stranger#key-0"), Some(&[3; 32]));
    let mixed = signed_with(&[&ed, &stranger], "assertionMethod").await;
    assert!(
        verify_signed_by(&mixed, DID, &keys, Utc::now())
            .await
            .is_err()
    );

    // Signed for the wrong purpose.
    let auth = signed_with(&[&ed, &pq], "authentication").await;
    assert!(
        verify_signed_by(&auth, DID, &keys, Utc::now())
            .await
            .is_err()
    );
}
