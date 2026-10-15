//! One membership per person — the uniqueness half of a PHC.
//!
//! DTG Credentials §Personhood Credentials defines a PHC as a VMC from a VTC
//! "whose governance enforces: real human personhood; **exactly one membership
//! per person**". The first half is evidence a community can gather itself; the
//! second is not.
//!
//! ## Why a community cannot do this alone
//!
//! Nothing in the credential graph distinguishes one person holding two DIDs
//! from two people. Not the VMC, not an endorsement, not a presentation — a
//! member who joins twice under two identities presents two perfectly valid
//! sets of evidence, and every check passes twice. The community needs an
//! anchor that is *stable per human*, and it has to come from outside.
//!
//! That anchor is a **pseudonym**: an identity-verification provider that can
//! actually deduplicate people — a state eID scheme, a biometric provider, a
//! bank — derives a deterministic value per (person, community). The same
//! person coming back yields the same pseudonym; a different community yields
//! an unlinkable one. This is the rate-limiting-identifier construction from
//! [Personhood Credentials (Adler et al. 2024)](https://arxiv.org/abs/2408.07892),
//! which the spec's own PHC definition cites.
//!
//! So this module does not establish uniqueness. It *enforces* the uniqueness
//! an IDVP established, by refusing a second membership that presents a
//! pseudonym already claimed here. The strength of the guarantee is the IDVP's,
//! which is why [`crate::community::PersonhoodGovernance::accepted_idvps`]
//! exists and why a community claiming PHC status must publish one.
//!
//! ## What is stored, and what is not
//!
//! The pseudonym itself is never written down. A stable per-person identifier
//! sitting in a database is a correlation target — precisely what the
//! construction exists to avoid — so the key is a salted digest and the raw
//! value is dropped after the check. What remains is "some person, already
//! known to us, holds this membership", which is the whole question being
//! asked.
//!
//! Rows live in the `members` keyspace under [`PSEUDONYM_PREFIX`] rather than a
//! keyspace of their own, which puts them in `BACKED_UP` alongside the members
//! they constrain. That coupling is deliberate and matches
//! `CONSUMED_INVITATIONS`: a claim that did not survive a restore would let a
//! restored community admit the duplicate it had already refused.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use sha2::{Digest, Sha256};
use uuid::Uuid;
use vti_common::error::AppError;
use vti_common::store::{Batch, KeyspaceHandle};

/// Storage prefix for pseudonym claims, inside the `members` keyspace.
pub const PSEUDONYM_PREFIX: &str = "personhood_pseudonym:";

/// Domain separation for the stored digest. Keeps a pseudonym digest from
/// colliding with any other SHA-256 this workspace computes over the same
/// bytes.
const DOMAIN_TAG: &[u8] = b"vtc-personhood-pseudonym/v1\0";

/// A claimed pseudonym.
///
/// Deliberately holds no copy of the pseudonym — see the module docs. The
/// member DID is kept because a claim is only useful if the community can say
/// *whose* it is when releasing it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PseudonymClaim {
    /// The member this pseudonym is bound to.
    pub member_did: String,
    pub claimed_at: DateTime<Utc>,
    /// The `vetted/1` statement the community issued when it bound this
    /// pseudonym itself ([`claim_for_statement`]): the row
    /// `vtc/endorsements/revoke/0.1` withdraws, which releases the binding.
    /// Absent for a claim made from an accepted provider's credential at
    /// personhood assert, and on every claim written before this existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endorsement_id: Option<Uuid>,
}

/// Storage key for a pseudonym in a community.
///
/// The community DID is inside the digest, not merely alongside it. A VTC
/// serves one community, so this changes nothing operationally — but it means
/// two communities' stores cannot be diffed against each other to discover that
/// the same person is in both, which is exactly the correlation a
/// community-scoped pseudonym is meant to prevent.
fn key(community_did: &str, pseudonym: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN_TAG);
    hasher.update(community_did.as_bytes());
    hasher.update([0u8]);
    hasher.update(pseudonym.as_bytes());
    format!("{PSEUDONYM_PREFIX}{}", hex::encode(hasher.finalize()))
}

/// Who currently holds `pseudonym` in this community, if anyone.
pub async fn holder(
    members_ks: &KeyspaceHandle,
    community_did: &str,
    pseudonym: &str,
) -> Result<Option<PseudonymClaim>, AppError> {
    let raw = members_ks.get_raw(key(community_did, pseudonym)).await?;
    let Some(bytes) = raw else { return Ok(None) };
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|e| AppError::Internal(format!("PseudonymClaim decode: {e}")))
}

/// How many times a claim re-reads the rows it checks after another writer
/// changed one between the read and the conditional write. An attempt is lost
/// only to another claim or release on the same pseudonym that was applied;
/// the bound only stops a pathological stream of them from holding a caller.
const CLAIM_ATTEMPTS: usize = 64;

fn already_held() -> AppError {
    AppError::Conflict("this person already holds a membership in this community".into())
}

/// The claim at `key` as stored (plaintext, for a `require_unchanged`
/// precondition) and as parsed.
async fn read_claim(
    members_ks: &KeyspaceHandle,
    key: &str,
) -> Result<Option<(Vec<u8>, PseudonymClaim)>, AppError> {
    let Some(bytes) = members_ks.get_raw(key).await? else {
        return Ok(None);
    };
    let claim = serde_json::from_slice(&bytes)
        .map_err(|e| AppError::Internal(format!("PseudonymClaim decode: {e}")))?;
    Ok(Some((bytes, claim)))
}

/// Bind `pseudonym` to `member_did`, or report who already holds it.
///
/// Re-claiming for the **same** member succeeds: a member who asserts
/// personhood twice — a second challenge, a renewed credential — is not a
/// second person, and refusing them would make the second assertion fail with
/// a message about duplicate humans.
///
/// Returns `Err(AppError::Conflict)` when another member holds it. The message
/// deliberately does not name that member: "this person is already here" is the
/// answer to the question, and "…and they are `did:key:z…`" is a disclosure the
/// asker has no claim to — the same enumeration-resistance discipline the vault
/// lifecycle applies.
pub async fn claim(
    members_ks: &KeyspaceHandle,
    community_did: &str,
    pseudonym: &str,
    member_did: &str,
) -> Result<(), AppError> {
    claim_all(members_ks, community_did, &[pseudonym], member_did).await
}

/// Bind every one of `pseudonyms` to `member_did`, all or nothing — [`claim`]
/// for each, as one conditional store batch.
///
/// Each pseudonym's write applies only while its row is still what was checked
/// (absent, or this member's own claim), so of two members racing for one
/// pseudonym exactly one is bound and the other gets `Conflict`. A check then
/// an insert let both pass the check, the later insert silently re-pointing
/// the claim — two memberships for one person. And because the batch is
/// all-or-nothing, a member refused on one pseudonym is left holding none of
/// the others: claiming one by one bound the earlier ones before the refusal.
pub async fn claim_all(
    members_ks: &KeyspaceHandle,
    community_did: &str,
    pseudonyms: &[&str],
    member_did: &str,
) -> Result<(), AppError> {
    let mut keys: Vec<String> = pseudonyms.iter().map(|p| key(community_did, p)).collect();
    keys.sort();
    keys.dedup();
    if keys.is_empty() {
        return Ok(());
    }
    for _ in 0..CLAIM_ATTEMPTS {
        let mut batch = Batch::new();
        for k in &keys {
            match read_claim(members_ks, k).await? {
                Some((_, existing)) if existing.member_did != member_did => {
                    return Err(already_held());
                }
                Some((raw, _)) => batch.require_unchanged(k.clone(), raw),
                None => batch.require_absent(k.clone()),
            };
            batch.insert(
                k.clone(),
                &PseudonymClaim {
                    member_did: member_did.to_string(),
                    claimed_at: Utc::now(),
                    endorsement_id: None,
                },
            )?;
        }
        if members_ks.apply_batch(batch).await?.is_applied() {
            return Ok(());
        }
    }
    Err(AppError::Conflict(
        "a personhood pseudonym kept changing while it was being claimed".into(),
    ))
}

/// Whether [`claim_for_statement`] wrote a new binding or found one already
/// held by the same member.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatementClaim {
    /// No one held the pseudonym; it is now bound to the member.
    Bound,
    /// The member already held it. A binding from an accepted provider's
    /// credential is left as it was; one from an earlier statement now
    /// follows this one.
    AlreadyHeld,
}

/// Bind `pseudonym` to `member_did` at the moment the community records its
/// own identity check (`vtc/endorsements/issue/0.1` under `vetted/1`), tagged
/// with that statement's `endorsement_id`.
///
/// The pseudonym comes from the operator who made the check, never from the
/// credential: a `vetted/1` value has no member for it, and the community
/// does not write one into anything it signs. Like [`claim`], only a digest is
/// stored, the same member re-claiming succeeds, and the write is conditional
/// on the row still being what was checked, so two members racing for one
/// pseudonym cannot both be bound.
///
/// A same-member binding from an accepted provider's credential is left
/// untagged, so revoking the statement does not release uniqueness the
/// provider established. A same-member binding from an earlier statement is
/// re-tagged to this one.
///
/// # Errors
///
/// `AppError::Conflict` when another member holds the pseudonym, worded as
/// [`claim`] words it.
pub async fn claim_for_statement(
    members_ks: &KeyspaceHandle,
    community_did: &str,
    pseudonym: &str,
    member_did: &str,
    endorsement_id: Uuid,
) -> Result<StatementClaim, AppError> {
    let k = key(community_did, pseudonym);
    for _ in 0..CLAIM_ATTEMPTS {
        let mut batch = Batch::new();
        let outcome = match read_claim(members_ks, &k).await? {
            Some((_, c)) if c.member_did != member_did => return Err(already_held()),
            Some((_, c)) if c.endorsement_id.is_none() => return Ok(StatementClaim::AlreadyHeld),
            Some((raw, _)) => {
                batch.require_unchanged(k.clone(), raw);
                StatementClaim::AlreadyHeld
            }
            None => {
                batch.require_absent(k.clone());
                StatementClaim::Bound
            }
        };
        batch.insert(
            k.clone(),
            &PseudonymClaim {
                member_did: member_did.to_string(),
                claimed_at: Utc::now(),
                endorsement_id: Some(endorsement_id),
            },
        )?;
        if members_ks.apply_batch(batch).await?.is_applied() {
            return Ok(outcome);
        }
    }
    Err(AppError::Conflict(
        "a personhood pseudonym kept changing while it was being claimed".into(),
    ))
}

/// Every readable claim, with its storage key and stored bytes.
async fn all_claims(
    members_ks: &KeyspaceHandle,
) -> Result<Vec<(Vec<u8>, Vec<u8>, PseudonymClaim)>, AppError> {
    let rows = members_ks
        .prefix_iter_raw(PSEUDONYM_PREFIX.as_bytes())
        .await?;
    Ok(rows
        .into_iter()
        .filter_map(|(key, bytes)| {
            serde_json::from_slice::<PseudonymClaim>(&bytes)
                .ok()
                .map(|c| (key, bytes, c))
        })
        .collect())
}

/// Remove a claim only while it is still the row a scan read — a release
/// decided on one claim never deletes a different one written since.
async fn remove_if_unchanged(
    members_ks: &KeyspaceHandle,
    key: Vec<u8>,
    bytes: Vec<u8>,
) -> Result<bool, AppError> {
    let mut batch = Batch::new();
    batch.require_unchanged(key.clone(), bytes).remove(key);
    Ok(members_ks.apply_batch(batch).await?.is_applied())
}

/// Whether the community holds a pseudonym binding for `member_did` — the
/// uniqueness fact a personhood assertion over the community's own `vetted/1`
/// statement relies on, since that statement carries no pseudonym itself.
///
/// Scans, for the reason [`release_for_member`] does: the key is a digest of
/// a pseudonym nobody kept, so there is no index from member back to key.
pub async fn is_bound(members_ks: &KeyspaceHandle, member_did: &str) -> Result<bool, AppError> {
    Ok(all_claims(members_ks)
        .await?
        .iter()
        .any(|(_, _, c)| c.member_did == member_did))
}

/// Release the binding the community made when it issued the `vetted/1`
/// statement `endorsement_id` — the statement was revoked, so the check it
/// recorded no longer stands. Returns how many were freed (0 or 1 in
/// practice). Claims from an accepted provider's credential are untagged and
/// never released here.
pub async fn release_for_statement(
    members_ks: &KeyspaceHandle,
    endorsement_id: Uuid,
) -> Result<usize, AppError> {
    let mut freed = 0usize;
    for (key, bytes, claim) in all_claims(members_ks).await? {
        if claim.endorsement_id == Some(endorsement_id)
            && remove_if_unchanged(members_ks, key, bytes).await?
        {
            freed += 1;
        }
    }
    Ok(freed)
}

/// Release a claim by pseudonym, so that person may join again.
///
/// Rarely what a caller wants — holding the raw pseudonym means having just
/// been handed one in a presentation. [`release_for_member`] is the operational
/// path. Idempotent: releasing an unclaimed pseudonym is a no-op.
pub async fn release(
    members_ks: &KeyspaceHandle,
    community_did: &str,
    pseudonym: &str,
) -> Result<(), AppError> {
    // A batch, so it is ordered against a claim's conditional write.
    let mut batch = Batch::new();
    batch.remove(key(community_did, pseudonym));
    members_ks.apply_batch(batch).await?;
    Ok(())
}

/// Release every claim held by `member_did`, returning how many were freed.
///
/// ## When this runs, and when it must not
///
/// On **purge** — the member is gone and the person behind them may return.
/// Not on personhood revoke, and not on leaving.
///
/// Revoke withdraws the community's assertion that this member is a person; it
/// is not evidence that the human stopped existing, and they are still a member.
/// Leaving is the same. If either released the claim, one-membership-per-person
/// would be defeated by revoking or leaving and coming back under a fresh DID —
/// which is precisely the move the rule exists to stop.
///
/// ## Why this scans
///
/// The claim is stored under a digest of the pseudonym, and the pseudonym is
/// deliberately not kept anywhere — so there is no index from member back to
/// key. The alternative is storing the digest on the member row, which is one
/// more thing to keep in sync for a rare operation. Purging a member is not a
/// hot path, and the scan is bounded by the number of people who have ever
/// asserted personhood here.
pub async fn release_for_member(
    members_ks: &KeyspaceHandle,
    member_did: &str,
) -> Result<usize, AppError> {
    let rows = members_ks
        .prefix_iter_raw(PSEUDONYM_PREFIX.as_bytes())
        .await?;
    let mut freed = 0usize;
    for (key, bytes) in rows {
        let Ok(claim) = serde_json::from_slice::<PseudonymClaim>(&bytes) else {
            // A row we cannot read is a row we must not delete on a guess —
            // it may belong to somebody else, and freeing it would admit a
            // duplicate. Leave it and let the decode failure surface elsewhere.
            continue;
        };
        if claim.member_did == member_did && remove_if_unchanged(members_ks, key, bytes).await? {
            freed += 1;
        }
    }
    Ok(freed)
}

/// Pull the pseudonyms out of a presentation's credentials, keeping only those
/// issued by a provider this community accepts.
///
/// One shape is read: `credentialSubject.pseudonym` of an identity credential
/// from an accepted provider, whatever its schema. The community's own
/// identity check is a `vetted/1` statement, whose `object.value` the registry
/// fixes and which has no pseudonym member: its uniqueness is the binding the
/// community made server-side when it issued the statement
/// ([`claim_for_statement`], read back by [`is_bound`]).
///
/// The issuer filter is the load-bearing part. Without it, any issuer could
/// mint a credential carrying whatever pseudonym they liked — including one
/// they knew to be unclaimed — and uniqueness would mean nothing. `vp_claims`
/// is the projection `extract_vp_claims` produces, so `issuer` may be a string
/// or an object with an `id`.
pub fn extract(vp_claims: &JsonValue, accepted_idvps: &[String]) -> Vec<String> {
    let Some(credentials) = vp_claims.get("credentials").and_then(|c| c.as_array()) else {
        return Vec::new();
    };

    credentials
        .iter()
        .filter(|cred| {
            let issuer = cred
                .get("issuer")
                .and_then(|i| i.as_str().or_else(|| i.get("id").and_then(|v| v.as_str())));
            issuer.is_some_and(|did| accepted_idvps.iter().any(|a| a == did))
        })
        .filter_map(|cred| {
            let subject = cred.get("credentialSubject")?;
            subject
                .get("pseudonym")
                .and_then(|p| p.as_str())
                .filter(|p| !p.is_empty())
                .map(str::to_owned)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const COMMUNITY: &str = "did:webvh:acme.example";
    const IDVP: &str = "did:webvh:idvp.example";
    const ALICE: &str = "did:key:zAlice";
    const BOB: &str = "did:key:zBob";

    fn temp_ks() -> (KeyspaceHandle, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let cfg = vti_common::config::StoreConfig {
            data_dir: dir.path().to_path_buf(),
        };
        let store = vti_common::store::Store::open(&cfg).expect("store");
        (store.keyspace("members-test").expect("ks"), dir)
    }

    // ─── storage ─────────────────────────────────────────────────────────

    /// The first claim succeeds and is readable back.
    #[tokio::test]
    async fn a_first_claim_binds_the_pseudonym() {
        let (ks, _dir) = temp_ks();
        claim(&ks, COMMUNITY, "p-1", ALICE).await.expect("claim");

        let held = holder(&ks, COMMUNITY, "p-1")
            .await
            .expect("read")
            .expect("claimed");
        assert_eq!(held.member_did, ALICE);
    }

    /// The point of the module: a second person presenting the same
    /// pseudonym is refused.
    #[tokio::test]
    async fn a_second_person_cannot_claim_the_same_pseudonym() {
        let (ks, _dir) = temp_ks();
        claim(&ks, COMMUNITY, "p-1", ALICE).await.expect("claim");

        let err = claim(&ks, COMMUNITY, "p-1", BOB)
            .await
            .expect_err("the same person may not join twice");
        assert!(matches!(err, AppError::Conflict(_)), "{err:?}");
    }

    /// The refusal must not disclose who holds it. "Someone is already here"
    /// answers the question; naming them hands an enumeration primitive to
    /// anyone who can guess a pseudonym.
    #[tokio::test]
    async fn the_refusal_does_not_name_the_holder() {
        let (ks, _dir) = temp_ks();
        claim(&ks, COMMUNITY, "p-1", ALICE).await.expect("claim");

        let err = claim(&ks, COMMUNITY, "p-1", BOB)
            .await
            .expect_err("refused");
        assert!(
            !err.to_string().contains(ALICE),
            "the holder must not be named: {err}"
        );
    }

    /// Re-asserting as the same member is not a duplicate. A second challenge
    /// or a renewed credential is the same person, and refusing it would fail
    /// with a message about duplicate humans.
    #[tokio::test]
    async fn the_same_member_may_reclaim() {
        let (ks, _dir) = temp_ks();
        claim(&ks, COMMUNITY, "p-1", ALICE).await.expect("first");
        claim(&ks, COMMUNITY, "p-1", ALICE)
            .await
            .expect("re-asserting is not a second person");
    }

    /// Release frees the pseudonym for a fresh claim — the revoke path.
    #[tokio::test]
    async fn release_frees_the_pseudonym() {
        let (ks, _dir) = temp_ks();
        claim(&ks, COMMUNITY, "p-1", ALICE).await.expect("claim");
        release(&ks, COMMUNITY, "p-1").await.expect("release");

        assert!(holder(&ks, COMMUNITY, "p-1").await.expect("read").is_none());
        claim(&ks, COMMUNITY, "p-1", BOB)
            .await
            .expect("released pseudonyms are reclaimable");
    }

    /// Releasing something unclaimed is a no-op — a revoke that runs twice is
    /// not an error.
    #[tokio::test]
    async fn releasing_an_unclaimed_pseudonym_is_a_noop() {
        let (ks, _dir) = temp_ks();
        release(&ks, COMMUNITY, "never-claimed")
            .await
            .expect("idempotent");
    }

    /// Purge frees exactly that member's claims and nobody else's — the
    /// operational release path, which has no pseudonym in hand.
    #[tokio::test]
    async fn releasing_for_a_member_frees_only_their_claims() {
        let (ks, _dir) = temp_ks();
        claim(&ks, COMMUNITY, "p-alice-1", ALICE).await.expect("a1");
        claim(&ks, COMMUNITY, "p-alice-2", ALICE).await.expect("a2");
        claim(&ks, COMMUNITY, "p-bob", BOB).await.expect("b");

        let freed = release_for_member(&ks, ALICE).await.expect("release");
        assert_eq!(freed, 2, "both of Alice's claims");

        assert!(holder(&ks, COMMUNITY, "p-alice-1").await.unwrap().is_none());
        assert!(holder(&ks, COMMUNITY, "p-alice-2").await.unwrap().is_none());
        assert!(
            holder(&ks, COMMUNITY, "p-bob").await.unwrap().is_some(),
            "purging one member must not free another's claim"
        );
    }

    /// Releasing for a member who holds nothing frees nothing and does not
    /// error — most purges are of members who never asserted personhood.
    #[tokio::test]
    async fn releasing_for_a_member_with_no_claims_is_a_noop() {
        let (ks, _dir) = temp_ks();
        claim(&ks, COMMUNITY, "p-bob", BOB).await.expect("b");

        assert_eq!(release_for_member(&ks, ALICE).await.expect("release"), 0);
        assert!(holder(&ks, COMMUNITY, "p-bob").await.unwrap().is_some());
    }

    /// The scan must not trip over unrelated rows sharing the keyspace. The
    /// `members` keyspace holds member records too, and a prefix scan that
    /// mistook one for a claim would delete a member on purge.
    #[tokio::test]
    async fn the_scan_ignores_rows_outside_the_prefix() {
        let (ks, _dir) = temp_ks();
        ks.insert(
            "member:did:key:zAlice".to_string(),
            &json!({ "did": ALICE }),
        )
        .await
        .expect("unrelated row");
        claim(&ks, COMMUNITY, "p-alice", ALICE)
            .await
            .expect("claim");

        assert_eq!(release_for_member(&ks, ALICE).await.expect("release"), 1);
        assert!(
            ks.get_raw("member:did:key:zAlice".to_string())
                .await
                .expect("read")
                .is_some(),
            "a member row must survive a pseudonym release"
        );
    }

    /// The raw pseudonym must not appear in the key. It is a stable
    /// per-person identifier; a store full of them is the correlation target
    /// the whole construction exists to avoid.
    /// The community's own binding: a first statement binds, a second member
    /// presenting the same pseudonym is refused, the binding is found by
    /// member DID, and revoking the statement releases it — but not a binding
    /// an accepted provider's credential made.
    #[tokio::test]
    async fn a_statement_binding_is_found_by_member_and_released_by_its_statement() {
        let (ks, _dir) = temp_ks();
        let first = Uuid::new_v4();
        assert_eq!(
            claim_for_statement(&ks, COMMUNITY, "p-1", ALICE, first)
                .await
                .unwrap(),
            StatementClaim::Bound
        );
        assert!(is_bound(&ks, ALICE).await.unwrap());
        assert!(!is_bound(&ks, BOB).await.unwrap());
        assert!(matches!(
            claim_for_statement(&ks, COMMUNITY, "p-1", BOB, Uuid::new_v4()).await,
            Err(AppError::Conflict(_))
        ));

        // A second statement for the same member takes the binding over.
        let second = Uuid::new_v4();
        assert_eq!(
            claim_for_statement(&ks, COMMUNITY, "p-1", ALICE, second)
                .await
                .unwrap(),
            StatementClaim::AlreadyHeld
        );
        assert_eq!(release_for_statement(&ks, first).await.unwrap(), 0);
        assert_eq!(release_for_statement(&ks, second).await.unwrap(), 1);
        assert!(!is_bound(&ks, ALICE).await.unwrap());

        // A provider's binding is left untagged, so no statement releases it.
        claim(&ks, COMMUNITY, "p-2", ALICE).await.unwrap();
        let third = Uuid::new_v4();
        assert_eq!(
            claim_for_statement(&ks, COMMUNITY, "p-2", ALICE, third)
                .await
                .unwrap(),
            StatementClaim::AlreadyHeld
        );
        assert_eq!(release_for_statement(&ks, third).await.unwrap(), 0);
        assert!(is_bound(&ks, ALICE).await.unwrap());
    }

    #[test]
    fn the_stored_key_does_not_contain_the_pseudonym() {
        let k = key(COMMUNITY, "national-id-hash-12345");
        assert!(!k.contains("national-id-hash-12345"), "{k}");
        assert!(k.starts_with(PSEUDONYM_PREFIX));
    }

    /// The community is inside the digest, so two communities' stores cannot
    /// be diffed to find people who are in both.
    #[test]
    fn the_same_pseudonym_keys_differently_per_community() {
        assert_ne!(key(COMMUNITY, "p-1"), key("did:webvh:other.example", "p-1"));
    }

    // ─── extraction ──────────────────────────────────────────────────────

    fn vp_with(issuer: &str, subject: JsonValue) -> JsonValue {
        json!({
            "holder": ALICE,
            "credentials": [{
                "type": ["VerifiableCredential"],
                "issuer": issuer,
                "credentialSubject": subject,
            }]
        })
    }

    /// A plain IDVC carrying the claim on the subject.
    #[test]
    fn a_plain_idvc_pseudonym_is_read() {
        let vp = vp_with(IDVP, json!({ "id": ALICE, "pseudonym": "p-1" }));
        assert_eq!(extract(&vp, &[IDVP.into()]), vec!["p-1".to_string()]);
    }

    /// The community's own identity check is a `vetted/1` statement: its
    /// `object.value` carries no pseudonym, so it establishes no uniqueness —
    /// even when the community lists itself as an accepted provider.
    #[test]
    fn a_community_vetted_statement_carries_no_pseudonym() {
        let vp = json!({
            "holder": ALICE,
            "credentials": [{
                "type": ["VerifiableCredential", "DTGCredential", "StatementCredential"],
                "issuer": COMMUNITY,
                "credentialSubject": {
                    "id": ALICE,
                    "predicate": dtg_credentials::VETTED_V1,
                    "object": { "value": { "community": COMMUNITY, "method": "inPerson" } }
                }
            }]
        });
        assert!(extract(&vp, &[COMMUNITY.into()]).is_empty());
    }

    /// **The load-bearing filter.** Without it, any issuer could mint a
    /// credential carrying a pseudonym they knew to be unclaimed, and
    /// uniqueness would mean nothing at all.
    #[test]
    fn a_pseudonym_from_an_unaccepted_issuer_is_ignored() {
        let vp = vp_with(
            "did:key:zRandomStranger",
            json!({ "id": ALICE, "pseudonym": "p-1" }),
        );
        assert!(
            extract(&vp, &[IDVP.into()]).is_empty(),
            "only accepted providers may establish uniqueness"
        );
    }

    /// An issuer given as an object with `id` — the other shape
    /// `extract_vp_claims` passes through.
    #[test]
    fn an_object_issuer_is_matched_on_its_id() {
        let vp = json!({
            "holder": ALICE,
            "credentials": [{
                "issuer": { "id": IDVP, "name": "Example IDVP" },
                "credentialSubject": { "id": ALICE, "pseudonym": "p-1" },
            }]
        });
        assert_eq!(extract(&vp, &[IDVP.into()]), vec!["p-1".to_string()]);
    }

    /// No accepted providers means nothing can establish uniqueness — an
    /// empty list is "we have published none", not "we accept anyone".
    #[test]
    fn an_empty_accepted_list_accepts_nothing() {
        let vp = vp_with(IDVP, json!({ "id": ALICE, "pseudonym": "p-1" }));
        assert!(extract(&vp, &[]).is_empty());
    }

    /// A credential without the claim contributes nothing rather than an
    /// empty-string pseudonym, which would collide with every other blank.
    #[test]
    fn a_credential_without_a_pseudonym_contributes_nothing() {
        let vp = vp_with(IDVP, json!({ "id": ALICE }));
        assert!(extract(&vp, &[IDVP.into()]).is_empty());

        let blank = vp_with(IDVP, json!({ "id": ALICE, "pseudonym": "" }));
        assert!(
            extract(&blank, &[IDVP.into()]).is_empty(),
            "an empty pseudonym is absent, not a value everyone shares"
        );
    }
    /// One person, two identities racing to join: exactly one is bound. A
    /// check then an insert let both pass, the later re-pointing the claim.
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn racing_claims_bind_a_pseudonym_to_exactly_one_member() {
        let (ks, _dir) = temp_ks();
        for round in 0..40 {
            let pseudonym = format!("race-{round}");
            let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(16));
            let mut tasks = Vec::new();
            for i in 0..16 {
                let (ks, barrier, pseudonym) = (ks.clone(), barrier.clone(), pseudonym.clone());
                tasks.push(tokio::spawn(async move {
                    let member = format!("did:key:zMember{i}");
                    barrier.wait().await;
                    if i % 2 == 0 {
                        claim(&ks, COMMUNITY, &pseudonym, &member).await.is_ok()
                    } else {
                        claim_for_statement(&ks, COMMUNITY, &pseudonym, &member, Uuid::new_v4())
                            .await
                            .is_ok()
                    }
                }));
            }
            let mut bound = 0;
            for t in tasks {
                bound += t.await.unwrap() as usize;
            }
            assert_eq!(bound, 1, "one pseudonym, {bound} members bound");
        }
    }

    /// A member refused on one pseudonym holds none of the others they
    /// presented: claiming is all or nothing.
    #[tokio::test]
    async fn a_refused_multi_claim_binds_nothing() {
        let (ks, _dir) = temp_ks();
        claim(&ks, COMMUNITY, "p-2", BOB).await.unwrap();
        let err = claim_all(&ks, COMMUNITY, &["p-1", "p-2", "p-3"], ALICE)
            .await
            .unwrap_err();
        assert!(matches!(err, AppError::Conflict(_)), "{err}");
        assert!(holder(&ks, COMMUNITY, "p-1").await.unwrap().is_none());
        assert!(holder(&ks, COMMUNITY, "p-3").await.unwrap().is_none());
        assert_eq!(
            holder(&ks, COMMUNITY, "p-2")
                .await
                .unwrap()
                .unwrap()
                .member_did,
            BOB
        );
    }

    /// Two members racing over overlapping pseudonym sets: the loser holds
    /// none of its set, never a part of it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn racing_multi_claims_are_all_or_nothing() {
        let (ks, _dir) = temp_ks();
        for round in 0..40 {
            let (a, b, c) = (
                format!("a{round}"),
                format!("b{round}"),
                format!("c{round}"),
            );
            let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(2));
            let t1 = {
                let (ks, barrier, a, b) = (ks.clone(), barrier.clone(), a.clone(), b.clone());
                tokio::spawn(async move {
                    barrier.wait().await;
                    claim_all(&ks, COMMUNITY, &[&a, &b], ALICE).await.is_ok()
                })
            };
            let t2 = {
                let (ks, barrier, b, c) = (ks.clone(), barrier.clone(), b.clone(), c.clone());
                tokio::spawn(async move {
                    barrier.wait().await;
                    claim_all(&ks, COMMUNITY, &[&b, &c], BOB).await.is_ok()
                })
            };
            let (alice, bob) = (t1.await.unwrap(), t2.await.unwrap());
            assert!(alice ^ bob, "exactly one of the overlapping claims wins");
            let held = |p: String| {
                let ks = ks.clone();
                async move {
                    holder(&ks, COMMUNITY, &p)
                        .await
                        .unwrap()
                        .map(|c| c.member_did)
                }
            };
            if alice {
                assert_eq!(
                    held(c.clone()).await,
                    None,
                    "Bob kept part of a refused claim"
                );
            } else {
                assert_eq!(
                    held(a.clone()).await,
                    None,
                    "Alice kept part of a refused claim"
                );
            }
        }
    }
}
