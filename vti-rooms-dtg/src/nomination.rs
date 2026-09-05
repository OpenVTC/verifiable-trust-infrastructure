//! Verifying a succession nomination.
//!
//! The gate `rooms/owner/claim` rests on. A claim is a takeover — whoever holds a valid
//! nomination can take a dormant room — and what makes that tolerable is that the *previous
//! owner issued it themselves*, in advance. A host verifies a decision; it never makes one
//! about who should own a room.
//!
//! # A nomination is a VAC, and it grants nothing
//!
//! It is an authority credential the room issues to its successor, granting
//! [`ACTION_SUCCEED`] at the room's own scope. That word is deliberately one no room task
//! accepts: a nomination confers no power at all while the owner is present, and becomes
//! redeemable only through `rooms/owner/claim` against a room that has gone dormant.
//!
//! Modelling it as a VAC rather than a bespoke document is what buys the structural checks
//! for free — that the chain's root reaches *the room* and not some party the host happens
//! to recognise, that no link widens what its parent granted, that every link is in its
//! window. Those are the properties that make a nomination worth anything, they are already
//! implemented and tested in [`dtg_credentials::authority::verify_chain`], and a second
//! hand-rolled copy would differ from it in some detail nobody notices until it matters.
//!
//! # What is deliberately not checked here
//!
//! **Whether the room is claimable.** That is a question about the room's lifecycle rather
//! than about the credential, the host answers it from its own clock, and keeping them
//! apart means a nomination presented early reads as "the owner is still here" rather than
//! "your credential is bad" — which is the difference between an answer a successor can act
//! on and one that sends them looking for a new nomination.

use dtg_credentials::authority::verify_chain;
use vti_common::error::AppError;
use vti_rooms::authz::ACTION_SUCCEED;

use crate::{VerificationKeys, chain_refusal, open_credential};

/// A verified nomination.
///
/// Constructible only by [`verify`], so a caller cannot reach ownership transfer holding
/// something nobody checked.
#[derive(Debug)]
pub struct VerifiedNomination {
    successor: String,
}

impl VerifiedNomination {
    /// The party the room nominated — established by the credential, never asserted by the
    /// sender.
    pub fn successor(&self) -> &str {
        &self.successor
    }
}

/// Verify a nomination for `room_id` presented by `claimant`.
pub async fn verify(
    encoded: &str,
    room_id: &str,
    claimant: &str,
    keys: &dyn VerificationKeys,
) -> Result<VerifiedNomination, AppError> {
    let nomination = open_credential(encoded, "the nomination", keys).await?;

    // Both the governing party and the requested scope are the room. A nomination issued by
    // the community the room belongs to, or by its host, or by a previous owner personally,
    // reaches nothing here — which is the same rule every other room credential lives under,
    // and the reason a room can change hosts without reissuing anything.
    let verified = verify_chain(
        std::slice::from_ref(&nomination),
        room_id,
        room_id,
        ACTION_SUCCEED,
        claimant,
        chrono::Utc::now(),
    )
    .map_err(|e| chain_refusal(room_id, e))?;

    // `verify_chain` uses `claimant` only for the audience check; it does not require the
    // grant to name them. Without this a nomination would be a bearer token, and anyone who
    // ever observed one could take the room the moment it went dormant.
    if verified.subject != claimant {
        return Err(AppError::Forbidden(format!(
            "the nomination names `{}`, not the party claiming; a nomination is not \
             transferable",
            verified.subject
        )));
    }

    Ok(VerifiedNomination {
        successor: verified.subject,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use affinidi_tdk::dids::{DID, KeyType};
    use chrono::{Duration, Utc};
    use dtg_credentials::DTGCredential;

    use crate::signed::DidKeyResolver;

    struct Fixture {
        room_did: String,
        room_secret: affinidi_tdk::secrets_resolver::secrets::Secret,
        successor_did: String,
    }

    async fn fixture() -> Fixture {
        let (room_did, room_secret) = DID::generate_did_key(KeyType::Ed25519).expect("room key");
        let (successor_did, _) = DID::generate_did_key(KeyType::Ed25519).expect("successor key");
        Fixture {
            room_did,
            room_secret,
            successor_did,
        }
    }

    /// Mint a nomination, with every knob a test might want to turn wrong.
    async fn nomination(
        issuer: &str,
        signer: &affinidi_tdk::secrets_resolver::secrets::Secret,
        subject: &str,
        scope: &str,
        actions: Vec<String>,
        valid_until: Option<chrono::DateTime<Utc>>,
    ) -> String {
        let now = Utc::now();
        let mut vac = DTGCredential::new_vac(
            issuer.to_string(),
            subject.to_string(),
            scope.to_string(),
            actions,
            now - Duration::minutes(1),
            valid_until,
        )
        .expect("build the nomination")
        .with_id("urn:uuid:vac-nomination");
        vac.sign(signer, None).await.expect("sign");
        serde_json::to_string(&vac).expect("serialise")
    }

    async fn good(f: &Fixture) -> String {
        nomination(
            &f.room_did,
            &f.room_secret,
            &f.successor_did,
            &f.room_did,
            vec![ACTION_SUCCEED.into()],
            Some(Utc::now() + Duration::days(365)),
        )
        .await
    }

    /// The one that must pass, or every refusal below proves nothing.
    #[tokio::test]
    async fn the_room_s_own_nomination_verifies() {
        let f = fixture().await;
        let verified = verify(
            &good(&f).await,
            &f.room_did,
            &f.successor_did,
            &DidKeyResolver,
        )
        .await
        .expect("the room nominated this party");
        assert_eq!(verified.successor(), f.successor_did);
    }

    /// The property the whole design rests on: a nomination is worth something because it
    /// reaches *the room*, not because a host recognises the issuer.
    #[tokio::test]
    async fn a_nomination_from_anyone_but_the_room_reaches_nothing() {
        let f = fixture().await;
        let (impostor_did, impostor_secret) =
            DID::generate_did_key(KeyType::Ed25519).expect("impostor key");

        // Perfectly valid as a credential. Signed correctly, in date, naming the right
        // party — and it names the right room's scope, which is exactly the document
        // anyone can write.
        let forged = nomination(
            &impostor_did,
            &impostor_secret,
            &f.successor_did,
            &f.room_did,
            vec![ACTION_SUCCEED.into()],
            Some(Utc::now() + Duration::days(365)),
        )
        .await;

        verify(&forged, &f.room_did, &f.successor_did, &DidKeyResolver)
            .await
            .expect_err("a self-issued nomination for someone else's room is worthless");
    }

    /// Without this a nomination is a bearer token: anyone who ever saw one could take the
    /// room the moment it went dormant.
    #[tokio::test]
    async fn a_nomination_is_not_transferable() {
        let f = fixture().await;
        let (opportunist, _) = DID::generate_did_key(KeyType::Ed25519).expect("key");

        let err = verify(&good(&f).await, &f.room_did, &opportunist, &DidKeyResolver)
            .await
            .expect_err("presenting someone else's nomination confers nothing");
        assert!(
            format!("{err}").contains("not transferable"),
            "the refusal should say why: {err}"
        );
    }

    /// A nomination for one room says nothing about another. Both are the room's own
    /// credentials; only one is about this room.
    #[tokio::test]
    async fn a_nomination_for_another_room_does_not_carry() {
        let f = fixture().await;
        let (other_room, _) = DID::generate_did_key(KeyType::Ed25519).expect("other room");

        let elsewhere = nomination(
            &f.room_did,
            &f.room_secret,
            &f.successor_did,
            &other_room,
            vec![ACTION_SUCCEED.into()],
            Some(Utc::now() + Duration::days(365)),
        )
        .await;

        verify(&elsewhere, &f.room_did, &f.successor_did, &DidKeyResolver)
            .await
            .expect_err("a nomination scoped to another room does not claim this one");
    }

    /// The spec's advice — nominations SHOULD expire — is only advice if an expired one
    /// still works.
    #[tokio::test]
    async fn an_expired_nomination_is_refused() {
        let f = fixture().await;
        let stale = nomination(
            &f.room_did,
            &f.room_secret,
            &f.successor_did,
            &f.room_did,
            vec![ACTION_SUCCEED.into()],
            Some(Utc::now() - Duration::days(1)),
        )
        .await;

        verify(&stale, &f.room_did, &f.successor_did, &DidKeyResolver)
            .await
            .expect_err("a standing right to take the room should not outlive its window");
    }

    /// The separation that keeps `succeed` inert. An ordinary admin grant — the one a
    /// co-admin legitimately holds — must not double as a nomination, or every admin is a
    /// silent successor.
    #[tokio::test]
    async fn an_admin_grant_is_not_a_nomination() {
        let f = fixture().await;
        let admin = nomination(
            &f.room_did,
            &f.room_secret,
            &f.successor_did,
            &f.room_did,
            vec![
                "read".into(),
                "write".into(),
                "curate".into(),
                "admin".into(),
            ],
            Some(Utc::now() + Duration::days(365)),
        )
        .await;

        verify(&admin, &f.room_did, &f.successor_did, &DidKeyResolver)
            .await
            .expect_err("holding admin today is not the same as being named successor");
    }

    /// And the converse, which is the reason `succeed` is not an `Action`: a nomination
    /// confers no power in the room it nominates for.
    #[tokio::test]
    async fn a_nomination_confers_nothing_in_the_room() {
        let f = fixture().await;
        let nom = good(&f).await;

        let room = vti_rooms::Room {
            room_id: f.room_did.clone(),
            owner_did: "did:key:z6MkSomeoneElse".into(),
            visibility: vti_rooms::Visibility::Open,
            epoch: 1,
            next_version: 1,
            retention_days: 90,
            epoch_expires_at: None,
            created_at: 0,
            updated_at: 0,
        };
        let verifier = crate::DtgChainVerifier::without_zk(Box::new(DidKeyResolver));

        for action in [
            vti_rooms::authz::Action::Read,
            vti_rooms::authz::Action::Write,
            vti_rooms::authz::Action::Curate,
            vti_rooms::authz::Action::Admin,
        ] {
            vti_rooms::authz::ChainVerifier::verify(
                &verifier,
                &room,
                &vti_rooms::wire::AuthorityPresentation {
                    membership: nom.clone(),
                    authority: vec![nom.clone()],
                    subject_binding: None,
                },
                action,
                &f.successor_did,
            )
            .await
            .expect_err("a nomination grants `succeed`, which no room action accepts");
        }
    }
}
