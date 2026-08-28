//! Verifying the digest binding on a Verifiable Witness Credential.
//!
//! A VWC asserts that its issuer witnessed *one specific* relationship. The
//! only thing that says *which* is `credentialSubject.digest`: a digest over
//! the witnessed VRC, in the form DTG Credentials specifies (SHA-256 over the
//! RFC 8785 canonicalization, wrapped as a `sha2-256` multihash and
//! multibase-encoded).
//!
//! Until this module existed, nothing recomputed it. The ceremony engine took
//! `WitnessCredential` as a policy fact carrying trusted-issuer, validity and
//! holder-binding predicates, and reasoned to a decision on the *assertion*
//! that a witness credential was present — with no code path that could have
//! established which edge, if any, it witnessed. DTG Credentials Security
//! Considerations 4 is explicit that without recomputing the digest against
//! the referenced VRC, a VWC "should not be treated as evidence of which edge
//! was witnessed".
//!
//! ## Recomputed, not compared to a stored digest
//!
//! [`resolve_binding`] recomputes the digest from each stored VRC body rather
//! than comparing against the `vrc_digest_multibase` column. The column is the
//! right thing to *index* on and the wrong thing to *verify* against: it was
//! written by an earlier version of this service, under whatever digest recipe
//! was current then. The relationship rows still carry the migration note
//! saying the form used to be bare lowercase hex over a recursive key sort.
//! Trusting the column would make this check assert that two stored strings
//! agree, which is not the claim being made.
//!
//! ## Decoded bytes, not encoded strings
//!
//! Security Considerations 4 requires the comparison to be on decoded digest
//! bytes. This is not pedantry: multibase is a *family* of encodings, and the
//! same 34-byte multihash is `z...` in base58btc and `f...` in base16. Two
//! conforming implementations can assert the identical digest in strings that
//! are not equal, and a string comparison rejects a valid witness. It fails in
//! the safe direction, which is exactly why it would survive a long time
//! undetected.

use serde_json::Value as JsonValue;
use uuid::Uuid;
use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;

use crate::credentials::ingress::digest_multibase;
use crate::relationships::Relationship;

/// The host's verdict on a VWC's digest binding, resolved before policy runs.
///
/// Follows the same division of labour as `issuer_trusted` and the resolved
/// `CredentialStatus`: the host does the work that needs keys, storage or a
/// network, and the policy branches on a settled state. A policy that had to
/// recompute a digest itself would be a policy doing cryptography.
///
/// The variants distinguish four genuinely different situations, because
/// collapsing them loses the distinction a verifier most needs — between a
/// credential that witnessed *something this service cannot see* and one that
/// witnessed *nothing*.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", tag = "state")]
pub enum WitnessBinding {
    /// The asserted digest decodes, and a stored relationship's VRC recomputes
    /// to the same bytes. This is the only variant that establishes *which*
    /// edge was witnessed, so it is the only one carrying an id.
    Bound { relationship_id: Uuid },
    /// The digest decodes and is well-formed, but no relationship this service
    /// holds recomputes to it.
    ///
    /// Not an accusation. A witness may legitimately attest an edge published
    /// on another VTC, and a verifier that treats this as forgery refuses
    /// honest evidence. It is surfaced so the policy can decide, which is the
    /// same reason `CredentialStatus::Unknown` exists rather than a guess.
    Unresolved,
    /// The credential asserts no `credentialSubject.digest` at all. A VWC
    /// without one witnesses nothing in particular.
    Absent,
    /// A digest is present but is not a decodable multibase multihash, or does
    /// not name `sha2-256`. Distinguished from [`Self::Unresolved`] because
    /// this one cannot be explained by an honest edge held elsewhere.
    Malformed,
}

impl WitnessBinding {
    /// Whether this binding establishes which edge was witnessed. The one
    /// predicate a policy needs in the common case.
    pub fn is_bound(&self) -> bool {
        matches!(self, Self::Bound { .. })
    }
}

/// Multihash header for `sha2-256`: code `0x12`, digest length `0x20`.
const SHA2_256_MULTIHASH_PREFIX: [u8; 2] = [0x12, 0x20];

/// Decode a multibase-encoded `sha2-256` multihash to its raw bytes.
///
/// Rejects anything that is not exactly the 34 bytes DTG Credentials names.
/// A digest of a different length, or one announcing a different hash
/// function, is not a weaker version of this claim — it is a different claim,
/// and accepting it would let the algorithm be chosen by the party being
/// checked.
fn decode_sha256_multihash(encoded: &str) -> Option<[u8; 34]> {
    let (_base, bytes) = multibase::decode(encoded).ok()?;
    let bytes: [u8; 34] = bytes.try_into().ok()?;
    (bytes[..2] == SHA2_256_MULTIHASH_PREFIX).then_some(bytes)
}

/// Whether two multibase digests denote the same bytes, regardless of the base
/// each was encoded in.
///
/// The whole point of the function: `multibase::decode` on both sides, then
/// compare. `a == b` on the strings answers a different question.
pub fn digests_match(asserted: &str, recomputed: &str) -> bool {
    match (
        decode_sha256_multihash(asserted),
        decode_sha256_multihash(recomputed),
    ) {
        (Some(a), Some(b)) => a == b,
        _ => false,
    }
}

/// Read the asserted digest out of a verified credential's claims.
///
/// Accepts it at `credentialSubject.digest` (a DI VC, where `claims` is the
/// whole credential) or at `digest` (an SD-JWT-VC, where `claims` is already
/// the subject). Both shapes reach the ceremony `Credential` fact through the
/// same field, so both have to be read here rather than at one call site.
fn asserted_digest(claims: &JsonValue) -> Option<&str> {
    claims
        .get("credentialSubject")
        .and_then(|s| s.get("digest"))
        .or_else(|| claims.get("digest"))
        .and_then(JsonValue::as_str)
}

/// Resolve a presented VWC's digest binding against the relationships this
/// service holds.
///
/// Walks the primary keyspace the way `find_by_hash` does, and for the same
/// reason: there is no digest-keyed secondary index yet. The scan cost is the
/// same one idempotent publish already pays, and it buys the property that
/// matters — every candidate is compared by *recomputing* from its stored VRC,
/// so the answer does not depend on a column written under an older recipe.
pub async fn resolve_binding(
    relationships_ks: &KeyspaceHandle,
    claims: &JsonValue,
) -> Result<WitnessBinding, AppError> {
    let Some(asserted) = asserted_digest(claims) else {
        return Ok(WitnessBinding::Absent);
    };
    if decode_sha256_multihash(asserted).is_none() {
        return Ok(WitnessBinding::Malformed);
    }
    for rel in crate::relationships::storage::list_all(relationships_ks).await? {
        if recomputes_to(&rel, asserted) {
            return Ok(WitnessBinding::Bound {
                relationship_id: rel.id,
            });
        }
    }
    Ok(WitnessBinding::Unresolved)
}

/// Whether this relationship's stored VRC recomputes to the asserted digest.
///
/// A VRC that will not canonicalize cannot match anything, and is skipped
/// rather than propagated: one unserializable row must not make every witness
/// in the community unverifiable.
fn recomputes_to(rel: &Relationship, asserted: &str) -> bool {
    match digest_multibase(&rel.vrc_jsonld) {
        Ok(recomputed) => digests_match(asserted, &recomputed),
        Err(e) => {
            tracing::warn!(
                error = %e, relationship_id = %rel.id,
                "stored VRC will not canonicalize; skipped for witness-digest matching"
            );
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn vrc() -> JsonValue {
        json!({
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiableCredential", "DTGCredential", "RelationshipCredential"],
            "issuer": "did:webvh:issuer.example",
            "credentialSubject": { "id": "did:webvh:subject.example" }
        })
    }

    /// The property the whole module exists for: the same multihash encoded in
    /// two different bases is the same digest. A string comparison says no
    /// here, and says it to an honest witness.
    #[test]
    fn the_same_digest_in_two_bases_matches() {
        let b58 = digest_multibase(&vrc()).unwrap();
        let (_, bytes) = multibase::decode(&b58).unwrap();
        let b16 = multibase::encode(multibase::Base::Base16Lower, &bytes);

        assert_ne!(b58, b16, "the fixture must actually differ as strings");
        assert!(digests_match(&b58, &b16));
        assert!(digests_match(&b16, &b58), "and it is symmetric");
    }

    #[test]
    fn different_documents_do_not_match() {
        let a = digest_multibase(&vrc()).unwrap();
        let mut other = vrc();
        other["issuer"] = json!("did:webvh:someone-else.example");
        let b = digest_multibase(&other).unwrap();
        assert!(!digests_match(&a, &b));
    }

    /// Member order is not a difference — that is what naming RFC 8785 buys,
    /// and a witness must not be rejected for reserialising the VRC.
    #[test]
    fn member_order_does_not_break_the_binding() {
        let ordered = json!({ "a": 1, "b": { "x": 1, "y": 2 } });
        let shuffled = json!({ "b": { "y": 2, "x": 1 }, "a": 1 });
        assert!(digests_match(
            &digest_multibase(&ordered).unwrap(),
            &digest_multibase(&shuffled).unwrap()
        ));
    }

    /// The digest length and algorithm are fixed by the specification. A
    /// 64-byte digest is not a stronger claim to be accepted generously — it
    /// is a different claim, and admitting it lets the party being checked
    /// choose the hash function.
    #[test]
    fn rejects_a_digest_that_is_not_sha2_256() {
        // sha2-512: multihash code 0x13, length 0x40.
        let mut mh = vec![0x13, 0x40];
        mh.extend_from_slice(&[7u8; 64]);
        let encoded = multibase::encode(multibase::Base::Base58Btc, &mh);
        assert!(decode_sha256_multihash(&encoded).is_none());
        assert!(
            !digests_match(&encoded, &encoded),
            "not even against itself"
        );
    }

    #[test]
    fn rejects_a_bare_hash_with_no_multihash_header() {
        let bare = multibase::encode(multibase::Base::Base58Btc, [9u8; 32]);
        assert!(decode_sha256_multihash(&bare).is_none());
    }

    #[test]
    fn rejects_text_that_is_not_multibase_at_all() {
        assert!(decode_sha256_multihash("not-a-digest").is_none());
        assert!(decode_sha256_multihash("").is_none());
    }

    /// The two claim shapes that reach the ceremony fact: a DI VC keeps the
    /// digest under `credentialSubject`, an SD-JWT-VC has already unwrapped it.
    #[test]
    fn reads_the_digest_from_either_claim_shape() {
        assert_eq!(
            asserted_digest(&json!({ "credentialSubject": { "digest": "zAbc" } })),
            Some("zAbc")
        );
        assert_eq!(asserted_digest(&json!({ "digest": "zAbc" })), Some("zAbc"));
        assert_eq!(asserted_digest(&json!({ "credentialSubject": {} })), None);
        assert_eq!(asserted_digest(&json!({})), None);
    }

    /// `credentialSubject` wins when both are present, because that is the
    /// issuer-signed location — a top-level `digest` beside it is not a second
    /// opinion to be preferred.
    #[test]
    fn the_signed_location_wins() {
        assert_eq!(
            asserted_digest(&json!({
                "credentialSubject": { "digest": "zSigned" },
                "digest": "zElsewhere"
            })),
            Some("zSigned")
        );
    }

    // ── against real storage ──────────────────────────────────────────────

    use crate::relationships::Relationship;
    use crate::relationships::storage::store_relationship;
    use chrono::Utc;
    use uuid::Uuid;
    use vti_common::config::StoreConfig;
    use vti_common::store::Store;

    async fn temp_kss() -> (KeyspaceHandle, KeyspaceHandle, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .unwrap();
        let primary = store.keyspace("relationships").unwrap();
        let index = store.keyspace("relationships_by_did").unwrap();
        (primary, index, dir)
    }

    /// A stored edge whose `vrc_digest_multibase` column is **deliberately
    /// wrong**, mirroring the fixture in `relationships::storage::tests`.
    ///
    /// This is the point of the fixture, not an oversight: the resolver must
    /// find this edge anyway, because it recomputes from `vrc_jsonld` rather
    /// than trusting the column. An implementation that matched on the column
    /// passes every other test here and fails this one.
    fn edge_with_a_stale_digest_column(issuer: &str, subject: &str) -> Relationship {
        let id = Uuid::new_v4();
        Relationship {
            id,
            issuer_did: issuer.into(),
            subject_did: subject.into(),
            vrc_jsonld: json!({
                "@context": ["https://www.w3.org/ns/credentials/v2"],
                "type": ["VerifiableCredential", "DTGCredential", "RelationshipCredential"],
                "issuer": issuer,
                "credentialSubject": { "id": subject }
            }),
            vrc_digest_multibase: format!("{:x}", id.as_u128()),
            created_at: Utc::now(),
            persona: None,
            lifecycle: Default::default(),
        }
    }

    #[tokio::test]
    async fn binds_a_witness_to_the_edge_its_digest_names() {
        let (primary, index, _dir) = temp_kss().await;
        let edge = edge_with_a_stale_digest_column("did:key:zIssuer", "did:key:zSubject");
        let other = edge_with_a_stale_digest_column("did:key:zSomeone", "did:key:zElse");
        store_relationship(&primary, &index, &edge).await.unwrap();
        store_relationship(&primary, &index, &other).await.unwrap();

        let vwc = json!({
            "credentialSubject": { "digest": digest_multibase(&edge.vrc_jsonld).unwrap() }
        });
        assert_eq!(
            resolve_binding(&primary, &vwc).await.unwrap(),
            WitnessBinding::Bound {
                relationship_id: edge.id
            },
            "must name the edge it witnessed, not merely 'some edge'"
        );
    }

    /// The cross-base case again, but through storage: a witness that encoded
    /// its digest in base16 witnesses the same edge as one that used base58btc.
    #[tokio::test]
    async fn a_foreign_base_encoding_still_binds() {
        let (primary, index, _dir) = temp_kss().await;
        let edge = edge_with_a_stale_digest_column("did:key:zIssuer", "did:key:zSubject");
        store_relationship(&primary, &index, &edge).await.unwrap();

        let (_, bytes) = multibase::decode(digest_multibase(&edge.vrc_jsonld).unwrap()).unwrap();
        let vwc = json!({
            "credentialSubject": {
                "digest": multibase::encode(multibase::Base::Base16Lower, &bytes)
            }
        });
        assert_eq!(
            resolve_binding(&primary, &vwc).await.unwrap(),
            WitnessBinding::Bound {
                relationship_id: edge.id
            }
        );
    }

    /// A digest naming an edge held elsewhere is `Unresolved`, not a rejection
    /// — surfaced for the policy to weigh, the way an unresolvable status list
    /// is.
    #[tokio::test]
    async fn an_edge_this_service_does_not_hold_is_unresolved() {
        let (primary, index, _dir) = temp_kss().await;
        store_relationship(
            &primary,
            &index,
            &edge_with_a_stale_digest_column("did:key:zA", "did:key:zB"),
        )
        .await
        .unwrap();

        let elsewhere = json!({ "type": ["VerifiableCredential"], "issuer": "did:key:zNowhere" });
        let vwc = json!({
            "credentialSubject": { "digest": digest_multibase(&elsewhere).unwrap() }
        });
        assert_eq!(
            resolve_binding(&primary, &vwc).await.unwrap(),
            WitnessBinding::Unresolved
        );
    }

    #[tokio::test]
    async fn a_witness_asserting_no_digest_is_absent() {
        let (primary, _index, _dir) = temp_kss().await;
        assert_eq!(
            resolve_binding(&primary, &json!({ "credentialSubject": {} }))
                .await
                .unwrap(),
            WitnessBinding::Absent
        );
    }

    /// Malformed is kept distinct from `Unresolved`: an honest witness can
    /// legitimately name an edge we do not hold, but cannot legitimately emit
    /// a digest that is not a `sha2-256` multihash.
    #[tokio::test]
    async fn an_undecodable_digest_is_malformed() {
        let (primary, _index, _dir) = temp_kss().await;
        for bad in ["not-a-digest", "", "zzzz!!!"] {
            assert_eq!(
                resolve_binding(&primary, &json!({ "credentialSubject": { "digest": bad } }))
                    .await
                    .unwrap(),
                WitnessBinding::Malformed,
                "{bad:?}"
            );
        }
    }

    /// An empty community has no edges, so every witness is unresolved — and
    /// notably not `Bound` by a vacuous scan.
    #[tokio::test]
    async fn an_empty_keyspace_binds_nothing() {
        let (primary, _index, _dir) = temp_kss().await;
        let vwc = json!({
            "credentialSubject": { "digest": digest_multibase(&vrc()).unwrap() }
        });
        assert_eq!(
            resolve_binding(&primary, &vwc).await.unwrap(),
            WitnessBinding::Unresolved
        );
    }
}
