//! Verifying the digest binding on a Verifiable Witness Credential.
//!
//! A VWC asserts that its issuer witnessed *one specific* relationship. The
//! only thing that says *which* is `credentialSubject.digestMultibase`: a
//! digest over the witnessed edge credential, in the form DTG Credentials
//! §Digest Encoding specifies — SHA-256 over the RFC 8785 canonicalization of
//! the credential **with its top-level `proof` removed**, wrapped as a
//! `sha2-256` multihash and multibase-encoded.
//!
//! Until this module existed, nothing recomputed it. The ceremony engine took
//! `WitnessCredential` as a policy fact carrying trusted-issuer, validity and
//! holder-binding predicates, and reasoned to a decision on the *assertion*
//! that a witness credential was present — with no code path that could have
//! established which edge, if any, it witnessed. DTG Credentials Security
//! Considerations 6 (*Digest integrity*) is explicit that without recomputing
//! the digest against the referenced edge credential, a VWC is not evidence of
//! which edge was witnessed.
//!
//! ## One definition of the digest, and it is the library's
//!
//! The recompute and the decode both go through `dtg-credentials`
//! (`digest_multibase_json`, `decode_digest_multibase`), the implementation
//! `DTGCredential::new_vwc_for_session` callers use to produce the value. A
//! first version of this module digested with
//! [`crate::credentials::ingress::digest_multibase`]
//! — the Trust Task framework digest, same encoding, but over the document
//! *proof included* — and read the Working Draft 01 member name `digest`. Both
//! compile, both produce plausible strings, and a VWC built by the library to
//! the specification came back `Absent`: the member was never read, and had it
//! been, the coverage would not have matched a signed VRC. The round-trip test
//! at the bottom of this file pins the two implementations together.
//!
//! ## Recomputed, not compared to a stored digest
//!
//! [`resolve_binding`] recomputes the digest from each stored VRC body rather
//! than comparing against the `vrc_digest_multibase` column. The column is the
//! right thing to *index* on and the wrong thing to *verify* against: it holds
//! the framework digest used to bind a publish authorization, which covers the
//! proof and so is a different value from the one a witness asserts. Trusting
//! it would make this check assert that two stored strings agree, which is not
//! the claim being made.
//!
//! ## Decoded bytes, not encoded strings
//!
//! §Digest Encoding forbids string comparison: a verifier "decodes the
//! Multibase value, decodes the Multihash to recover the algorithm identifier
//! and the raw digest, and compares those". This is not pedantry: multibase is
//! a *family* of encodings, and the same 34-byte multihash is `z...` in
//! base58btc and `f...` in base16. Two conforming implementations can assert
//! the identical digest in strings that are not equal, and a string comparison
//! rejects a valid witness. It fails in the safe direction, which is exactly
//! why it would survive a long time undetected.

use serde_json::Value as JsonValue;
use uuid::Uuid;
use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;

use crate::credentials::ingress::dtg_credential_digest_multibase;
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
///
/// Reaches policy under the snake_case key `witness_binding`, as
/// `{ "state": "bound", "relationship_id": "<uuid>" }` or
/// `{ "state": "unresolved" | "absent" | "malformed" }` — on the ceremony
/// `Credential` fact and on each `WitnessCredential` entry of the personhood
/// projection alike ([`annotate_vp_claims`]).
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
    /// The credential asserts no `credentialSubject.digestMultibase` at all. A
    /// VWC without one witnesses nothing in particular.
    Absent,
    /// A digest is present but is not a decodable multibase multihash, or does
    /// not name `sha2-256`. Distinguished from [`Self::Unresolved`] because
    /// this one cannot be explained by an honest edge held elsewhere — and
    /// §Digest Encoding requires a digest naming an algorithm the verifier does
    /// not accept to be *rejected*, "rather than treating it as a mismatch".
    Malformed,
}

impl WitnessBinding {
    /// Whether this binding establishes which edge was witnessed. The one
    /// predicate a policy needs in the common case.
    pub fn is_bound(&self) -> bool {
        matches!(self, Self::Bound { .. })
    }
}

/// Length of a `sha2-256` digest. `decode_digest_multibase` checks that the
/// multihash's declared length matches the bytes it carries; this checks that
/// the length is the one `sha2-256` produces, so a truncated digest is
/// malformed rather than a well-formed value that merely matches nothing.
const SHA2_256_LEN: usize = 32;

/// Decode a multibase-encoded `sha2-256` multihash to its raw digest bytes.
///
/// Rejects anything that is not the digest DTG Credentials names. A digest of
/// a different length, or one announcing a different hash function, is not a
/// weaker version of this claim — it is a different claim, and accepting it
/// would let the algorithm be chosen by the party being checked.
fn decode_sha256_multihash(encoded: &str) -> Option<Vec<u8>> {
    let (_algorithm, raw) = dtg_credentials::decode_digest_multibase(encoded).ok()?;
    (raw.len() == SHA2_256_LEN).then_some(raw)
}

/// Whether two multibase digests denote the same bytes, regardless of the base
/// each was encoded in.
///
/// The whole point of the function: decode both sides, then compare. `a == b`
/// on the strings answers a different question.
pub fn digests_match(asserted: &str, recomputed: &str) -> bool {
    match (
        decode_sha256_multihash(asserted),
        decode_sha256_multihash(recomputed),
    ) {
        (Some(a), Some(b)) => a == b,
        _ => false,
    }
}

/// Read the asserted digest out of a credential's claims.
///
/// Accepts it under `credentialSubject` (a DI VC, where `claims` is the whole
/// credential) or at the top level (an SD-JWT-VC, where `claims` is already the
/// subject). Both shapes reach the ceremony `Credential` fact through the same
/// field, so both have to be read here rather than at one call site.
///
/// The member is `digestMultibase` (DTG Credentials Working Draft 02). The
/// Working Draft 01 name `digest` is still read, as `dtg-credentials` reads it
/// on deserialization — but only where `digestMultibase` is missing, and a WD01
/// *value* (`sha256:<hex>`) does not decode and resolves to
/// [`WitnessBinding::Malformed`].
fn asserted_digest(claims: &JsonValue) -> Option<&str> {
    fn member(obj: &JsonValue) -> Option<&JsonValue> {
        obj.get("digestMultibase").or_else(|| obj.get("digest"))
    }
    claims
        .get("credentialSubject")
        .and_then(member)
        .or_else(|| member(claims))
        .and_then(JsonValue::as_str)
}

/// Resolve a presented VWC's digest binding against the relationships this
/// service holds.
///
/// Walks the primary keyspace the way `find_by_hash` does, and for the same
/// reason: there is no digest-keyed secondary index yet. The scan cost is the
/// same one idempotent publish already pays, and it buys the property that
/// matters — every candidate is compared by *recomputing* from its stored VRC,
/// so the answer does not depend on a column written for a different purpose.
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

/// Whether a credential's `type` names a `WitnessCredential`.
///
/// Matches on the type rather than on the presence of a digest member: a
/// credential that should carry one and does not is exactly the case worth
/// surfacing as [`WitnessBinding::Absent`], and keying off the member would
/// silently classify it as "not a witness" instead. `type` may be a string or
/// an array, as W3C VCDM allows.
fn names_witness_type(credential: &JsonValue) -> bool {
    match credential.get("type") {
        Some(JsonValue::String(t)) => t == "WitnessCredential",
        Some(JsonValue::Array(types)) => types
            .iter()
            .any(|t| t.as_str() == Some("WitnessCredential")),
        _ => false,
    }
}

/// The key a binding verdict is written under on a projected credential. Shared
/// with the ceremony `Credential` fact, which serializes its field under the
/// same name, so one policy idiom reads both.
pub const WITNESS_BINDING_KEY: &str = "witness_binding";

/// Attach the host's [`WitnessBinding`] verdict to every `WitnessCredential`
/// in a `vp_claims` projection (`crate::policy::extract::extract_vp_claims`).
///
/// The personhood `assert` path hands policy this projection rather than the
/// ceremony facts, and before this existed it carried no binding verdict at
/// all — so the default `personhood.rego` could only check that a
/// `WitnessCredential` had a non-empty issuer, which says nothing about which
/// edge, if any, was witnessed. This puts the same verdict the ceremony path
/// computes onto the projection, and the policy branches on it the same way.
///
/// The key is **host-owned**: it is written on every witness entry and
/// removed from every other one, so nothing a presenter put in the VP can
/// stand in for the verdict. (`extract_vp_claims` does not copy the member
/// either; this does not rely on that.)
///
/// A storage failure resolves to [`WitnessBinding::Unresolved`], the same
/// choice the join path makes: one unreadable keyspace must not decide the
/// assertion, and "could not find the edge" is the honest answer. The policy
/// still sees an unbound witness.
pub async fn annotate_vp_claims(relationships_ks: &KeyspaceHandle, vp_claims: &mut JsonValue) {
    let Some(credentials) = vp_claims
        .get_mut("credentials")
        .and_then(JsonValue::as_array_mut)
    else {
        return;
    };
    for credential in credentials {
        let is_witness = names_witness_type(credential);
        let Some(entry) = credential.as_object_mut() else {
            continue;
        };
        if !is_witness {
            entry.remove(WITNESS_BINDING_KEY);
            continue;
        }
        let snapshot = JsonValue::Object(entry.clone());
        let binding = resolve_binding(relationships_ks, &snapshot)
            .await
            .unwrap_or_else(|e| {
                tracing::warn!(error = %e, "could not resolve witness digest binding");
                WitnessBinding::Unresolved
            });
        entry.insert(
            WITNESS_BINDING_KEY.into(),
            serde_json::to_value(&binding).expect("WitnessBinding serializes"),
        );
    }
}

/// Whether this relationship's stored VRC recomputes to the asserted digest.
///
/// A VRC that will not canonicalize cannot match anything, and is skipped
/// rather than propagated: one unserializable row must not make every witness
/// in the community unverifiable.
fn recomputes_to(rel: &Relationship, asserted: &str) -> bool {
    match dtg_credential_digest_multibase(&rel.vrc_jsonld) {
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
        let b58 = dtg_credential_digest_multibase(&vrc()).unwrap();
        let (_, bytes) = multibase::decode(&b58).unwrap();
        let b16 = multibase::encode(multibase::Base::Base16Lower, &bytes);

        assert_ne!(b58, b16, "the fixture must actually differ as strings");
        assert!(digests_match(&b58, &b16));
        assert!(digests_match(&b16, &b58), "and it is symmetric");
    }

    #[test]
    fn different_documents_do_not_match() {
        let a = dtg_credential_digest_multibase(&vrc()).unwrap();
        let mut other = vrc();
        other["issuer"] = json!("did:webvh:someone-else.example");
        let b = dtg_credential_digest_multibase(&other).unwrap();
        assert!(!digests_match(&a, &b));
    }

    /// Member order is not a difference — that is what naming RFC 8785 buys,
    /// and a witness must not be rejected for reserialising the VRC.
    #[test]
    fn member_order_does_not_break_the_binding() {
        let ordered = json!({ "a": 1, "b": { "x": 1, "y": 2 } });
        let shuffled = json!({ "b": { "y": 2, "x": 1 }, "a": 1 });
        assert!(digests_match(
            &dtg_credential_digest_multibase(&ordered).unwrap(),
            &dtg_credential_digest_multibase(&shuffled).unwrap()
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
            asserted_digest(&json!({ "credentialSubject": { "digestMultibase": "zAbc" } })),
            Some("zAbc")
        );
        assert_eq!(
            asserted_digest(&json!({ "digestMultibase": "zAbc" })),
            Some("zAbc")
        );
        assert_eq!(asserted_digest(&json!({ "credentialSubject": {} })), None);
        assert_eq!(asserted_digest(&json!({})), None);
    }

    /// Working Draft 02 renamed the member to `digestMultibase`. The WD01 name
    /// is still read — `dtg-credentials` accepts it as an alias — but never in
    /// preference to the current one.
    #[test]
    fn reads_the_wd02_member_name_before_the_wd01_one() {
        assert_eq!(
            asserted_digest(&json!({ "credentialSubject": { "digest": "zOld" } })),
            Some("zOld")
        );
        assert_eq!(
            asserted_digest(&json!({
                "credentialSubject": { "digest": "zOld", "digestMultibase": "zNew" }
            })),
            Some("zNew")
        );
    }

    /// `credentialSubject` wins when both are present, because that is the
    /// issuer-signed location — a top-level digest beside it is not a second
    /// opinion to be preferred.
    #[test]
    fn the_signed_location_wins() {
        assert_eq!(
            asserted_digest(&json!({
                "credentialSubject": { "digestMultibase": "zSigned" },
                "digestMultibase": "zElsewhere"
            })),
            Some("zSigned")
        );
    }

    /// A `sha2-256` multihash whose declared length matches its bytes but is
    /// not 32 is a truncated digest. Malformed, not a well-formed value that
    /// merely matches nothing.
    #[test]
    fn rejects_a_truncated_sha2_256_digest() {
        let mut mh = vec![0x12, 0x10];
        mh.extend_from_slice(&[7u8; 16]);
        let encoded = multibase::encode(multibase::Base::Base58Btc, &mh);
        assert!(decode_sha256_multihash(&encoded).is_none());
    }

    /// The WD01 `sha256:<hex>` value form is not a multibase multihash, so it
    /// does not decode — the member name is tolerated, the retired encoding is
    /// not.
    #[test]
    fn a_wd01_hex_digest_value_does_not_decode() {
        assert!(decode_sha256_multihash(&format!("sha256:{}", "ab".repeat(32))).is_none());
    }

    /// DTG Credentials §Digest Encoding step 1: the digest is taken over the
    /// referenced credential **excluding its top-level `proof`**. A signed VRC
    /// and the same claims unsigned are one edge.
    #[test]
    fn the_digest_excludes_the_top_level_proof() {
        let mut signed = vrc();
        signed["proof"] = json!({ "type": "DataIntegrityProof", "proofValue": "zSig" });
        assert!(digests_match(
            &dtg_credential_digest_multibase(&signed).unwrap(),
            &dtg_credential_digest_multibase(&vrc()).unwrap()
        ));
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
    /// fails every test that uses this fixture.
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
            "credentialSubject": { "digestMultibase": dtg_credential_digest_multibase(&edge.vrc_jsonld).unwrap() }
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

        let (_, bytes) =
            multibase::decode(dtg_credential_digest_multibase(&edge.vrc_jsonld).unwrap()).unwrap();
        let vwc = json!({
            "credentialSubject": {
                "digestMultibase": multibase::encode(multibase::Base::Base16Lower, &bytes)
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
            "credentialSubject": { "digestMultibase": dtg_credential_digest_multibase(&elsewhere).unwrap() }
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
                resolve_binding(
                    &primary,
                    &json!({ "credentialSubject": { "digestMultibase": bad } })
                )
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
            "credentialSubject": { "digestMultibase": dtg_credential_digest_multibase(&vrc()).unwrap() }
        });
        assert_eq!(
            resolve_binding(&primary, &vwc).await.unwrap(),
            WitnessBinding::Unresolved
        );
    }

    // ── a VWC built by the catalog, verified by this module ───────────────

    use crate::test_support::dtg_json;
    use dtg_credentials::DTGCredential;

    const WITNESS: &str = "did:webvh:witness.example";
    const ALICE: &str = "did:key:zAlice";
    const BOB: &str = "did:key:zBob";
    /// The `id` of the `witness/session` document that opened the witnessing
    /// session — what a VWC's `taskContext` names (trust task
    /// `witness/session/0.1` §The nesting).
    const SESSION: &str = "urn:uuid:6f1c1c1e-5a8b-4f7e-9d0c-2b7a4e1d9c30";

    /// The `witness/session` document that opened the session, as the witness
    /// received it. `new_vwc_for_session` reads both halves of the citation off
    /// it — `taskContext` from its `id`, `taskDigestMultibase` from its task
    /// digest — so the two cannot disagree, and refuses anything that is not
    /// the opening document (a `submit`, a `#response`, or one whose
    /// `threadId` is not its own `id`).
    fn witness_session() -> JsonValue {
        json!({
            "id": SESSION,
            "type": "https://trusttasks.org/spec/witness/session/0.1",
            "threadId": SESSION,
            "issuer": ALICE,
            "recipient": WITNESS,
            "issuedAt": "2026-09-22T09:59:00Z",
            "payload": { "parties": [ALICE, BOB] }
        })
    }

    /// A VRC as it is stored after publication: the catalog's own credential,
    /// **signed** — the `proof` is what a stored edge carries and what the VWC
    /// digest must not cover.
    fn stored_signed_vrc(issuer: &str, subject: &str) -> (DTGCredential, Relationship) {
        let vrc = DTGCredential::new_vrc(issuer.into(), subject.into(), Utc::now(), None);
        let mut vrc_jsonld = dtg_json(&vrc);
        vrc_jsonld["proof"] = json!({
            "type": "DataIntegrityProof",
            "cryptosuite": "eddsa-jcs-2022",
            "verificationMethod": format!("{issuer}#key-0"),
            "proofPurpose": "assertionMethod",
            "proofValue": "z3FXQjecWufY46yg5abdVZsXqLhxhueuSoZgNSARiKBk"
        });
        let rel = Relationship {
            id: Uuid::new_v4(),
            issuer_did: issuer.into(),
            subject_did: subject.into(),
            // What publication actually writes to the column: the framework
            // digest, proof included — a different value from the one a
            // witness asserts, so matching on the column fails here too.
            vrc_digest_multibase: crate::credentials::ingress::digest_multibase(&vrc_jsonld)
                .unwrap(),
            vrc_jsonld,
            created_at: Utc::now(),
            persona: None,
            lifecycle: Default::default(),
        };
        (vrc, rel)
    }

    /// A VWC for one direction of a witnessed edge, built the only way the
    /// catalog builds one. `credentialSubject.id` is the witnessed VRC's
    /// issuer (DTG Credentials §VWC: "MUST be the DID of the issuer of the edge
    /// credential that the VWC attests"), and `taskContext` is REQUIRED.
    fn vwc_for(witnessed: &DTGCredential) -> DTGCredential {
        DTGCredential::new_vwc_for_session(
            WITNESS.into(),
            witnessed.credential().issuer.clone(),
            Utc::now(),
            None,
            &witness_session(),
            witnessed.digest_multibase().expect("catalog digest"),
            None,
        )
        .expect("the opening witness/session document builds a VWC")
    }

    /// **The round trip #1068 asked for.** A VWC built through
    /// `DTGCredential::new_vwc_for_session`, its digest produced by the
    /// catalog's own `digest_multibase` over the witnessed VRC, binds to that
    /// VRC as this service stores it — signed, with a `proof` the digest
    /// excludes.
    ///
    /// Before this test existed the two sides disagreed twice over, and both
    /// were silent: the verifier read `credentialSubject.digest` where the
    /// catalog writes `digestMultibase` (so this came back `Absent`), and it
    /// digested the stored VRC proof-included (so even the right member would
    /// have come back `Unresolved`).
    #[tokio::test]
    async fn a_catalog_built_vwc_binds_to_the_signed_vrc_it_witnessed() {
        let (primary, index, _dir) = temp_kss().await;
        let (alice_to_bob, edge) = stored_signed_vrc(ALICE, BOB);
        let (_, unrelated) = stored_signed_vrc("did:key:zCarol", "did:key:zDave");
        store_relationship(&primary, &index, &unrelated)
            .await
            .unwrap();
        store_relationship(&primary, &index, &edge).await.unwrap();

        let vwc = dtg_json(&vwc_for(&alice_to_bob));
        assert_eq!(
            vwc["credentialSubject"]["digestMultibase"]
                .as_str()
                .and_then(|d| d.chars().next()),
            Some('z'),
            "§Digest Encoding: issuers MUST use base58btc"
        );

        assert_eq!(
            resolve_binding(&primary, &vwc).await.unwrap(),
            WitnessBinding::Bound {
                relationship_id: edge.id
            }
        );
    }

    /// The same catalog-built VWC clears the receipt half of Trust Task Context
    /// Binding (#1065): `new_vwc_for_session` cannot omit `taskContext`, and
    /// ingress, which refuses a VWC without one, accepts it.
    ///
    /// Since dtg-credentials 0.11 it also carries `taskDigestMultibase`, the
    /// task digest of the same document — the half that *binds* the citation,
    /// where `taskContext` only names it (`witness/session/submit` Conformance
    /// item 1). Both are read off one document, so they cannot disagree.
    #[test]
    fn a_catalog_built_vwc_carries_the_required_task_context() {
        let (alice_to_bob, _) = stored_signed_vrc(ALICE, BOB);
        let built = vwc_for(&alice_to_bob);
        let vwc = dtg_json(&built);
        assert_eq!(vwc["taskContext"], SESSION);
        assert_eq!(
            vwc["taskDigestMultibase"],
            dtg_credentials::task_digest_multibase_json(&witness_session()).unwrap(),
            "the digest is the session document's, not something the issuer chose"
        );
        assert!(
            built.cites_task(&witness_session()).unwrap(),
            "both halves of the citation resolve back to the document they came from"
        );
        assert_eq!(
            crate::credentials::ingress::classify_dtg(&vwc).unwrap(),
            dtg_credentials::DTGCredentialType::Witness
        );
    }

    /// One VWC per direction (DTG Credentials §VWC: the witness "SHOULD issue
    /// one VWC per direction"). Each binds to its own edge and not the other's
    /// — the digest, not the subject id, is what names the edge.
    #[tokio::test]
    async fn each_direction_of_a_witnessed_exchange_binds_its_own_edge() {
        let (primary, index, _dir) = temp_kss().await;
        let (a_to_b, edge_ab) = stored_signed_vrc(ALICE, BOB);
        let (b_to_a, edge_ba) = stored_signed_vrc(BOB, ALICE);
        store_relationship(&primary, &index, &edge_ab)
            .await
            .unwrap();
        store_relationship(&primary, &index, &edge_ba)
            .await
            .unwrap();

        for (vrc, edge) in [(&a_to_b, &edge_ab), (&b_to_a, &edge_ba)] {
            assert_eq!(
                resolve_binding(&primary, &dtg_json(&vwc_for(vrc)))
                    .await
                    .unwrap(),
                WitnessBinding::Bound {
                    relationship_id: edge.id
                }
            );
        }
    }

    // ── the personhood projection ─────────────────────────────────────────

    /// The personhood `assert` path's projection gains the verdict, on witness
    /// entries only, under the same key and shape the ceremony fact uses.
    #[tokio::test]
    async fn annotation_puts_the_verdict_on_witness_entries_only() {
        let (primary, index, _dir) = temp_kss().await;
        let (alice_to_bob, edge) = stored_signed_vrc(ALICE, BOB);
        store_relationship(&primary, &index, &edge).await.unwrap();

        let vp = json!({
            "holder": BOB,
            "verifiableCredential": [
                dtg_json(&vwc_for(&alice_to_bob)),
                { "type": ["VerifiableCredential"], "issuer": "did:key:zOther",
                  "credentialSubject": { "id": BOB } }
            ]
        });
        let mut claims = crate::policy::extract::extract_vp_claims(&vp);
        annotate_vp_claims(&primary, &mut claims).await;

        assert_eq!(
            claims["credentials"][0][WITNESS_BINDING_KEY],
            json!({ "state": "bound", "relationship_id": edge.id })
        );
        assert!(
            claims["credentials"][1].get(WITNESS_BINDING_KEY).is_none(),
            "a non-witness credential has no binding question to answer"
        );
    }

    /// The verdict is the host's, never the presenter's. A VP that tries to
    /// carry its own `witness_binding` — on the witness it forged, or on a
    /// non-witness credential — does not get it into the policy input.
    #[tokio::test]
    async fn a_presenter_cannot_supply_the_verdict() {
        let (primary, _index, _dir) = temp_kss().await;
        let forged_verdict = json!({ "state": "bound", "relationship_id": Uuid::new_v4() });

        let mut claims = json!({
            "holder": BOB,
            "credentials": [
                { "type": ["VerifiableCredential", "WitnessCredential"],
                  "issuer": WITNESS,
                  "credentialSubject": { "id": ALICE },
                  "witness_binding": forged_verdict },
                { "type": ["VerifiableCredential"],
                  "issuer": WITNESS,
                  "witness_binding": forged_verdict }
            ]
        });
        annotate_vp_claims(&primary, &mut claims).await;

        assert_eq!(
            claims["credentials"][0][WITNESS_BINDING_KEY],
            json!({ "state": "absent" }),
            "overwritten with what the credential actually establishes"
        );
        assert!(claims["credentials"][1].get(WITNESS_BINDING_KEY).is_none());
    }

    /// A single-string `type` is legal VCDM, and a witness that uses one is
    /// still a witness.
    #[test]
    fn a_string_type_names_a_witness() {
        assert!(names_witness_type(&json!({ "type": "WitnessCredential" })));
        assert!(!names_witness_type(
            &json!({ "type": "VerifiableCredential" })
        ));
        assert!(!names_witness_type(&json!({})));
    }
}
