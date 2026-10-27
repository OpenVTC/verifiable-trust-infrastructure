//! Whether a room profile's author could say what the room is called.
//!
//! `RoomProfileStatement` (`rooms/_shared/0.1`) item 3. A host stores a profile record under
//! `write`, like any record, because on a sealed tier it cannot tell the profile from
//! anything else — so every member able to write could put a record at the profile's
//! location. What stops them renaming the room is that **readers** check the statement's own
//! authority chain, and this is that check:
//!
//! - at most [`vti_rooms::profile::MAX_AUTHORITY_LINKS`] links, leaf first;
//! - every link's proof made with a key its own `issuer` lists for `assertionMethod`
//!   ([`crate::open_credential`], the same opener a host's verifier uses);
//! - the last link issued by the room, no link widening its parent, the whole conferring
//!   `curate` or `admin` at the room's scope (`dtg_credentials::authority::verify_chain`,
//!   with the room as both governing party and scope);
//! - the leaf's subject equal to the body's `author`, which stands in for a host's presenter
//!   binding;
//! - every link valid **at the statement's `issuedAt`**, not at the moment of reading —
//!   revocation is not retroactive, and a profile written while its author held the standing
//!   stays the room's after they leave.
//!
//! Nothing is fetched: a link the statement does not carry is not looked for.

use chrono::{DateTime, Utc};
use dtg_credentials::authority::verify_chain;
use vti_common::error::AppError;

use crate::VerificationKeys;

/// The actions that let a statement name the room. `write` alone never does: every member
/// able to add a record could otherwise rename the room for everyone.
pub const NAMING_ACTIONS: [&str; 2] = ["curate", "admin"];

/// What a verified profile authority chain established.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileAuthority {
    /// The action the chain was found to confer — `curate`, else `admin`.
    pub action: &'static str,
    /// The `id` of every link, leaf first, where the link carries one — what a reader holding
    /// a revocation list compares against it.
    pub link_ids: Vec<String>,
}

/// Verify `authority` (leaf first) as conferring `curate` or `admin` on `author` at room
/// `room_id`, every link valid at `issued_at`.
///
/// Every failure is [`AppError::Forbidden`], with the specifics for an operator's log; a
/// reader reports it as `noAuthority` whichever link failed.
pub async fn verify_profile_authority(
    authority: &[String],
    room_id: &str,
    author: &str,
    issued_at: DateTime<Utc>,
    keys: &dyn VerificationKeys,
) -> Result<ProfileAuthority, AppError> {
    if authority.is_empty() {
        return Err(AppError::Forbidden(
            "the statement carries no authority chain".into(),
        ));
    }
    if authority.len() > vti_rooms::profile::MAX_AUTHORITY_LINKS {
        return Err(AppError::Forbidden(format!(
            "the statement's authority chain is {} links, more than the {} a presentation may \
             carry",
            authority.len(),
            vti_rooms::profile::MAX_AUTHORITY_LINKS
        )));
    }

    // Every link's proof, before any of them is trusted to say anything about the others.
    let mut chain = Vec::with_capacity(authority.len());
    for (index, encoded) in authority.iter().enumerate() {
        chain.push(
            crate::open_credential(encoded, &format!("authority credential {index}"), keys)
                .await
                .map_err(|e| AppError::Forbidden(e.to_string()))?,
        );
    }

    let mut refusals = Vec::new();
    for action in NAMING_ACTIONS {
        match verify_chain(&chain, room_id, room_id, action, author, issued_at) {
            Ok(_) => {
                return Ok(ProfileAuthority {
                    action,
                    link_ids: chain
                        .iter()
                        .filter_map(|c| c.credential().id.clone())
                        .collect(),
                });
            }
            Err(e) => refusals.push(format!("{action}: {e}")),
        }
    }
    Err(AppError::Forbidden(format!(
        "the statement's authority chain does not confer `curate` or `admin` on `{author}` in \
         room `{room_id}` at {issued_at}: {}",
        refusals.join("; ")
    )))
}

#[cfg(all(test, feature = "test-support"))]
mod tests {
    use super::*;
    use crate::test_support::{Party, RoomFixture};
    use chrono::Duration;
    use dtg_credentials::{DTGCredential, IssuerScope};
    use vti_common::auth::ProofPurpose;
    use vti_rooms::Visibility;

    /// `did:key` resolution: a key is its own document.
    struct DidKeys;

    #[async_trait::async_trait]
    impl VerificationKeys for DidKeys {
        async fn public_key(&self, vm: &str, _purpose: ProofPurpose) -> Result<Vec<u8>, AppError> {
            let did = vm.split('#').next().unwrap_or_default();
            let mb = did
                .strip_prefix("did:key:")
                .ok_or_else(|| AppError::NotFound(format!("not a did:key: {did}")))?;
            vta_sdk::did_key::decode_ed25519_public_key_multibase(mb)
                .map(|k| k.to_vec())
                .map_err(|e| AppError::NotFound(format!("{e}")))
        }
    }

    async fn grant(
        room: &Party,
        subject: &str,
        actions: &[&str],
        from: DateTime<Utc>,
        until: DateTime<Utc>,
    ) -> String {
        let mut vac = DTGCredential::new_vac(
            room.did.clone(),
            IssuerScope::Public,
            subject.into(),
            room.did.clone(),
            actions.iter().map(|a| a.to_string()).collect(),
            from,
            until,
        )
        .expect("a VAC")
        .with_id(format!(
            "urn:example:vac:{}:{}",
            actions.join("-"),
            from.timestamp()
        ));
        vac.sign(&room.secret, None).await.expect("sign");
        serde_json::to_string(&vac).unwrap()
    }

    /// The owner's chain confers `curate` and `admin`: accepted, as `curate`.
    #[tokio::test]
    async fn a_curator_or_admin_may_name_the_room() {
        let f = RoomFixture::new(Visibility::Attributed).await;
        let got = verify_profile_authority(
            &f.owner_chain,
            &f.room.room_id,
            &f.owner.did,
            Utc::now(),
            &DidKeys,
        )
        .await
        .expect("the owner may name the room");
        assert_eq!(got.action, "curate");
        assert_eq!(got.link_ids, vec!["urn:uuid:vac-owner".to_string()]);

        let admin_only = grant(
            &f.room_key,
            &f.successor.did,
            &["read", "write", "admin"],
            Utc::now() - Duration::hours(1),
            Utc::now() + Duration::hours(1),
        )
        .await;
        let got = verify_profile_authority(
            &[admin_only],
            &f.room.room_id,
            &f.successor.did,
            Utc::now(),
            &DidKeys,
        )
        .await
        .expect("admin names the room too");
        assert_eq!(got.action, "admin");
    }

    /// The forged rename: a member holding `write` — enough to store the record — cannot name
    /// the room.
    #[tokio::test]
    async fn write_alone_never_names_the_room() {
        let f = RoomFixture::new(Visibility::Attributed).await;
        let writer = grant(
            &f.room_key,
            &f.successor.did,
            &["read", "write"],
            Utc::now() - Duration::hours(1),
            Utc::now() + Duration::hours(1),
        )
        .await;
        let err = verify_profile_authority(
            &[writer],
            &f.room.room_id,
            &f.successor.did,
            Utc::now(),
            &DidKeys,
        )
        .await
        .expect_err("write is not curate");
        assert!(err.to_string().contains("does not confer"), "{err}");
    }

    /// The leaf must be the author's: a curator's chain carried in somebody else's body is
    /// not their authority.
    #[tokio::test]
    async fn the_chain_must_be_the_authors() {
        let f = RoomFixture::new(Visibility::Attributed).await;
        verify_profile_authority(
            &f.owner_chain,
            &f.room.room_id,
            &f.successor.did,
            Utc::now(),
            &DidKeys,
        )
        .await
        .expect_err("the owner's chain does not let the successor name the room");
    }

    /// Validity is judged at `issuedAt`: a grant that has since lapsed still stands for a
    /// statement made while it was live, and a statement dated after it lapsed does not.
    #[tokio::test]
    async fn validity_is_judged_at_issued_at_not_now() {
        let f = RoomFixture::new(Visibility::Attributed).await;
        let now = Utc::now();
        let lapsed = grant(
            &f.room_key,
            &f.successor.did,
            &["read", "write", "curate"],
            now - Duration::days(10),
            now - Duration::days(5),
        )
        .await;
        verify_profile_authority(
            std::slice::from_ref(&lapsed),
            &f.room.room_id,
            &f.successor.did,
            now - Duration::days(7),
            &DidKeys,
        )
        .await
        .expect("written while the grant was live");
        verify_profile_authority(&[lapsed], &f.room.room_id, &f.successor.did, now, &DidKeys)
            .await
            .expect_err("dated after the grant lapsed");
    }

    /// A chain a member issued themselves, however complete, is not the room's.
    #[tokio::test]
    async fn a_self_issued_grant_names_nothing() {
        let f = RoomFixture::new(Visibility::Attributed).await;
        let mallory = Party::new();
        let forged = grant(
            &mallory,
            &mallory.did,
            &["curate", "admin"],
            Utc::now() - Duration::hours(1),
            Utc::now() + Duration::hours(1),
        )
        .await;
        verify_profile_authority(
            &[forged],
            &f.room.room_id,
            &mallory.did,
            Utc::now(),
            &DidKeys,
        )
        .await
        .expect_err("not rooted in the room");
    }

    #[tokio::test]
    async fn an_empty_or_overlong_chain_is_refused() {
        let f = RoomFixture::new(Visibility::Attributed).await;
        verify_profile_authority(&[], &f.room.room_id, &f.owner.did, Utc::now(), &DidKeys)
            .await
            .expect_err("empty");
        let nine = vec![f.owner_chain[0].clone(); 9];
        let err =
            verify_profile_authority(&nine, &f.room.room_id, &f.owner.did, Utc::now(), &DidKeys)
                .await
                .expect_err("nine links");
        assert!(err.to_string().contains("9 links"), "{err}");
    }
}
