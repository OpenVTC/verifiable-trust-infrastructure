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
use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;

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
    if let Some(existing) = holder(members_ks, community_did, pseudonym).await?
        && existing.member_did != member_did
    {
        return Err(AppError::Conflict(
            "this person already holds a membership in this community".into(),
        ));
    }
    members_ks
        .insert(
            key(community_did, pseudonym),
            &PseudonymClaim {
                member_did: member_did.to_string(),
                claimed_at: Utc::now(),
            },
        )
        .await
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
    members_ks.remove(key(community_did, pseudonym)).await
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
        if claim.member_did == member_did {
            members_ks.remove(key).await?;
            freed += 1;
        }
    }
    Ok(freed)
}

/// Pull the pseudonyms out of a presentation's credentials, keeping only those
/// issued by a provider this community accepts.
///
/// Two shapes are read, because a community may be its own IDVP or may rely on
/// a foreign one:
///
/// - `credentialSubject.pseudonym` — a plain IDVC, whatever its schema.
/// - `credentialSubject.endorsement.claim.pseudonym` — this community's own
///   endorsement machinery, where operator claims live under `endorsement.claim`.
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
                .or_else(|| {
                    subject
                        .get("endorsement")
                        .and_then(|e| e.get("claim"))
                        .and_then(|c| c.get("pseudonym"))
                })
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

    /// This community's own endorsement shape, where operator claims sit
    /// under `endorsement.claim`.
    #[test]
    fn an_endorsement_pseudonym_is_read() {
        let vp = vp_with(
            COMMUNITY,
            json!({
                "id": ALICE,
                "endorsement": {
                    "type": "IdentityVerification",
                    "claim": { "method": "in-person-id", "pseudonym": "p-2" }
                }
            }),
        );
        assert_eq!(extract(&vp, &[COMMUNITY.into()]), vec!["p-2".to_string()]);
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
}
