//! The credential flow end to end, without a service: listing, offer, acknowledgement,
//! grant, and repudiation, each verified the way the service verifies them.

use chrono::{Duration, Utc};
use vti_vtn::credentials::{listing_vsc, member, membership_offer};
use vti_vtn::identity::Identity;
use vti_vtn::model::{EntryKind, Framework};
use vti_vtn::status::credential_status;
use vti_vtn::verify::{
    LocalDidKeyResolver, Repudiated, verify_acknowledgement, verify_repudiation, verify_signed_by,
};

fn framework() -> Framework {
    Framework {
        iri: "https://example.org/whn/gf".into(),
        version: "1.0".into(),
    }
}

#[tokio::test]
async fn listing_offer_ack_grant_and_departure() {
    let network = Identity::generate();
    let vtc = Identity::generate();
    let now = Utc::now() - Duration::seconds(5);
    let base = "http://vtn.example";

    // Listing: signed by the network, about the VTC, needing nothing from it.
    let mut listing = listing_vsc(
        network.did(),
        vtc.did(),
        EntryKind::Community,
        &framework(),
        now,
        credential_status(base, 0),
    )
    .unwrap();
    network.sign_credential(&mut listing).await.unwrap();
    let listing_json = serde_json::to_value(&listing).unwrap();
    verify_signed_by(
        &listing_json,
        network.did(),
        &LocalDidKeyResolver,
        Utc::now(),
    )
    .await
    .unwrap();

    // Offer: unsigned grant claims (A2).
    let mut offer = membership_offer(
        network.did(),
        vtc.did(),
        now,
        Some(now + Duration::days(365)),
        credential_status(base, 1),
    );
    let offer_json = serde_json::to_value(&offer).unwrap();
    assert!(offer_json.get("proof").is_none());

    // The VTC acknowledges the unsigned offer.
    let ack = member::acknowledge(&offer_json, &vtc, now, Some(now + Duration::days(30)))
        .await
        .unwrap();
    let ack_json = serde_json::to_value(&ack).unwrap();
    verify_acknowledgement(
        &ack_json,
        &offer,
        vtc.did(),
        &LocalDidKeyResolver,
        Utc::now(),
    )
    .await
    .unwrap();

    // The network signs the same claims; the acknowledgement still matches.
    network.sign_credential(&mut offer).await.unwrap();
    let grant_json = serde_json::to_value(&offer).unwrap();
    assert!(ack.acknowledges(&offer).unwrap());
    dtg_credentials::verify_grant_with_public_key(
        &grant_json,
        &affinidi_data_integrity::did_vm::resolve_did_key(
            offer
                .credential()
                .proof
                .as_ref()
                .unwrap()
                .verification_method
                .as_str(),
        )
        .unwrap()
        .public_key_bytes,
        Utc::now(),
    )
    .unwrap();

    // Departure: the VTC repudiates the grant.
    let departure = member::repudiate(&grant_json, &vtc, now).await.unwrap();
    let target = verify_repudiation(
        &serde_json::to_value(&departure).unwrap(),
        vtc.did(),
        network.did(),
        &listing_json,
        Some(&grant_json),
        &LocalDidKeyResolver,
        Utc::now(),
    )
    .await
    .unwrap();
    assert_eq!(target, Repudiated::Grant);
}

#[tokio::test]
async fn acknowledgement_from_someone_else_is_rejected() {
    let network = Identity::generate();
    let vtc = Identity::generate();
    let imposter = Identity::generate();
    let now = Utc::now() - Duration::seconds(5);

    let offer = membership_offer(network.did(), vtc.did(), now, None, serde_json::json!([]));
    let offer_json = serde_json::to_value(&offer).unwrap();
    // The imposter cannot build an acknowledgement of a grant naming somebody else.
    assert!(
        member::acknowledge(&offer_json, &imposter, now, None)
            .await
            .is_err()
    );
    // Nor can a genuine acknowledgement be passed off as from another party.
    let ack = member::acknowledge(&offer_json, &vtc, now, None)
        .await
        .unwrap();
    let err = verify_acknowledgement(
        &serde_json::to_value(&ack).unwrap(),
        &offer,
        imposter.did(),
        &LocalDidKeyResolver,
        Utc::now(),
    )
    .await;
    assert!(err.is_err());
}

#[tokio::test]
async fn repudiating_a_listing() {
    let network = Identity::generate();
    let vtc = Identity::generate();
    let now = Utc::now() - Duration::seconds(5);
    let mut listing = listing_vsc(
        network.did(),
        vtc.did(),
        EntryKind::Network,
        &framework(),
        now,
        credential_status("http://vtn.example", 0),
    )
    .unwrap();
    network.sign_credential(&mut listing).await.unwrap();
    let listing_json = serde_json::to_value(&listing).unwrap();

    let repudiation = member::repudiate(&listing_json, &vtc, now).await.unwrap();
    let target = verify_repudiation(
        &serde_json::to_value(&repudiation).unwrap(),
        vtc.did(),
        network.did(),
        &listing_json,
        None,
        &LocalDidKeyResolver,
        Utc::now(),
    )
    .await
    .unwrap();
    assert_eq!(target, Repudiated::Listing);
}

/// A listing carries the registry's `lists/1` predicate and an `object.value` that
/// `listing.schema.json` accepts: exactly `nodeType` (`VTC` | `VTN`) and `framework`.
#[test]
fn listing_matches_the_registered_lists_profile() {
    let network = Identity::generate();
    let party = Identity::generate();
    for (kind, node_type) in [(EntryKind::Community, "VTC"), (EntryKind::Network, "VTN")] {
        let listing = listing_vsc(
            network.did(),
            party.did(),
            kind,
            &framework(),
            Utc::now(),
            credential_status("http://vtn.example", 0),
        )
        .unwrap();
        let json = serde_json::to_value(&listing).unwrap();
        let subject = &json["credentialSubject"];
        assert_eq!(
            subject["predicate"],
            "https://registry.trustoverip.org/dtg/vsc/lists/1"
        );
        assert_eq!(
            subject["object"]["value"],
            serde_json::json!({
                "nodeType": node_type,
                "framework": { "iri": "https://example.org/whn/gf", "version": "1.0" },
            })
        );
        assert_eq!(EntryKind::from_node_type(node_type), Some(kind));
    }
}

/// A member that declares `directed` for its DID, as a community configured so does.
struct DirectedMember(Identity);

impl vti_vtn::identity::Party for DirectedMember {
    fn did(&self) -> &str {
        self.0.did()
    }

    fn sign_for<'a>(
        &'a self,
        document: serde_json::Value,
        purpose: &'a str,
    ) -> vti_vtn::identity::SignFuture<'a> {
        vti_vtn::identity::Party::sign_for(&self.0, document, purpose)
    }

    fn issuer_scope(&self) -> dtg_credentials::IssuerScope {
        dtg_credentials::IssuerScope::Directed
    }
}

/// A community is `directed` at minimum: one declaring `directed` acknowledges and
/// departs exactly as a `public` one does, and its credentials say `directed`.
#[tokio::test]
async fn a_directed_member_acknowledges_and_departs() {
    let network = Identity::generate();
    let vtc = DirectedMember(Identity::generate());
    let did = vti_vtn::identity::Party::did(&vtc).to_string();
    let now = Utc::now() - Duration::seconds(5);
    let base = "http://vtn.example";

    let mut listing = listing_vsc(
        network.did(),
        &did,
        EntryKind::Community,
        &framework(),
        now,
        credential_status(base, 0),
    )
    .unwrap();
    network.sign_credential(&mut listing).await.unwrap();
    let listing_json = serde_json::to_value(&listing).unwrap();

    let mut offer = membership_offer(
        network.did(),
        &did,
        now,
        Some(now + Duration::days(365)),
        credential_status(base, 1),
    );
    let offer_json = serde_json::to_value(&offer).unwrap();

    let ack = member::acknowledge_as(&offer_json, &vtc, now, None)
        .await
        .unwrap();
    assert_eq!(ack["issuerScope"], "directed");
    verify_acknowledgement(&ack, &offer, &did, &LocalDidKeyResolver, Utc::now())
        .await
        .unwrap();

    network.sign_credential(&mut offer).await.unwrap();
    let grant_json = serde_json::to_value(&offer).unwrap();
    let departure = member::repudiate_as(&grant_json, &vtc, now).await.unwrap();
    assert_eq!(departure["issuerScope"], "directed");
    let target = verify_repudiation(
        &departure,
        &did,
        network.did(),
        &listing_json,
        Some(&grant_json),
        &LocalDidKeyResolver,
        Utc::now(),
    )
    .await
    .unwrap();
    assert_eq!(target, Repudiated::Grant);
}
