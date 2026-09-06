//! The disclosure record: what the holder shared, with whom, and how strongly
//! it was hidden.
//!
//! Append-only, and written **before the artifact is returned**. That ordering
//! is the point of the module: a crash between signing and recording would
//! release data the holder could never afterwards discover they had released.
//! Recording first can only produce a record of a disclosure that did not
//! happen, which is a false positive a holder can investigate — the opposite is
//! a silent release.
//!
//! # It names claim types, never values
//!
//! The history says what *kind* of thing went where. Re-storing the values
//! would double the exposure the record exists to describe, and put a second
//! plaintext copy of the holder's data in a structure whose whole purpose is to
//! be read later.
//!
//! # It answers a debt the scope split incurred
//!
//! Putting the pool above the context boundary bought a correlation check that
//! can see across contexts. The cost is that a holder can no longer tell, by
//! looking at one context, where a fact has gone. Filtering by claim type
//! settles that — *where has my home address reached* — and it is why this is a
//! queryable record rather than an audit log line.

use serde::{Deserialize, Serialize};
use vti_common::error::AppError;

use crate::model::{ProofRung, Ulid};
use crate::storage;
use crate::store::{PersonaStore, now_rfc3339};

/// One claim as it was disclosed — type and rung, never the value.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DisclosedClaim {
    pub r#type: String,
    /// How strongly it was hidden. The same claim type at two rungs is two very
    /// different disclosures, and a holder reviewing what they have done needs
    /// to see which they did.
    pub rung: ProofRung,
}

/// A permanent record of one release.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DisclosureRecord {
    pub disclosure_id: Ulid,
    pub context_id: String,
    pub verifier_did: String,
    pub persona_did: String,
    /// The pairwise identifier the disclosure was made under, so a holder can
    /// tell two disclosures to the same verifier apart.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    pub claims: Vec<DisclosedClaim>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub renderer: Option<String>,
    /// Present when the disclosure minted a durable credential — the one kind
    /// that is still live and still revocable, which is why the history names
    /// it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub durable_credential_id: Option<String>,
    /// Contact revisions this disclosure relied on. Recording them is what
    /// makes contact retention reference-counted rather than a timer: these
    /// revisions are evidence of what the holder was shown before presenting.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cited_contact_revisions: Vec<(Ulid, u64)>,
    pub disclosed_at: String,
}

/// What a holder is asking when they query their own history.
#[derive(Clone, Debug, Default)]
pub struct HistoryQuery<'a> {
    /// Omit to query across every context — which only the holder can do, and
    /// which is the reason this sits above the boundary.
    pub context_id: Option<&'a str>,
    /// "What does this site have of mine."
    pub verifier_did: Option<&'a str>,
    /// "Where has my home address gone." The question the scope split owes an
    /// answer to.
    pub claim_type: Option<&'a str>,
    pub since: Option<&'a str>,
}

impl PersonaStore {
    /// Append a disclosure record and cite the contact revisions it relied on.
    ///
    /// Call this **before** returning the artifact to the caller.
    pub async fn record_disclosure(&self, mut record: DisclosureRecord) -> Result<Ulid, AppError> {
        let _guard = self.write_lock.lock().await;

        let seq = self.next_version().await?;
        if record.disclosure_id.is_empty() {
            record.disclosure_id = ulid::Ulid::new().to_string();
        }
        record.disclosed_at = now_rfc3339();

        let cited = record.cited_contact_revisions.clone();
        let context_id = record.context_id.clone();

        self.ks
            .insert(storage::disclosure_key(&context_id, seq), &record)
            .await?;

        // Citing after the record lands, deliberately: a citation with no
        // record retains a revision nobody needs, which wastes space. A record
        // with no citation would let the evidence behind it be reaped, which
        // loses the thing the record points at.
        drop(_guard);
        for (contact_id, rev) in cited {
            self.cite_contact_revision(&context_id, &contact_id, rev)
                .await?;
        }

        Ok(record.disclosure_id)
    }

    /// Query the holder's own disclosure history.
    ///
    /// Scans every context when `context_id` is omitted — the cross-context
    /// view, which is the holder's alone.
    pub async fn disclosure_history(
        &self,
        query: &HistoryQuery<'_>,
    ) -> Result<Vec<DisclosureRecord>, AppError> {
        let prefix = match query.context_id {
            Some(ctx) => storage::disclosure_prefix(ctx),
            None => "pd:".to_string(),
        };
        let rows = self.ks.prefix_iter_raw(prefix.into_bytes()).await?;

        let mut out: Vec<DisclosureRecord> = rows
            .into_iter()
            .filter_map(|(_k, v)| serde_json::from_slice::<DisclosureRecord>(&v).ok())
            .filter(|r| query.verifier_did.is_none_or(|v| r.verifier_did == v))
            .filter(|r| {
                query
                    .claim_type
                    .is_none_or(|t| r.claims.iter().any(|c| c.r#type == t))
            })
            .filter(|r| query.since.is_none_or(|s| r.disclosed_at.as_str() >= s))
            .collect();

        // Key order is sequence order, which is time order — the counter is
        // monotonic. Sorting again would be redundant, but the scan may have
        // spanned contexts, whose sequences interleave.
        out.sort_by(|a, b| a.disclosed_at.cmp(&b.disclosed_at));
        Ok(out)
    }

    /// Which contexts a claim type has reached.
    ///
    /// The specific question the agent-scoped pool owes the holder: having put
    /// their facts above the context boundary, it must be able to say where
    /// each one has gone.
    pub async fn contexts_reached_by(&self, claim_type: &str) -> Result<Vec<String>, AppError> {
        let mut contexts: Vec<String> = self
            .disclosure_history(&HistoryQuery {
                claim_type: Some(claim_type),
                ..Default::default()
            })
            .await?
            .into_iter()
            .map(|r| r.context_id)
            .collect();
        contexts.sort();
        contexts.dedup();
        Ok(contexts)
    }
}

/// Build a disclosure record with server-assigned identity and timestamp.
#[must_use]
pub fn new_disclosure(
    context_id: impl Into<String>,
    verifier_did: impl Into<String>,
    persona_did: impl Into<String>,
    claims: Vec<DisclosedClaim>,
) -> DisclosureRecord {
    DisclosureRecord {
        disclosure_id: ulid::Ulid::new().to_string(),
        context_id: context_id.into(),
        verifier_did: verifier_did.into(),
        persona_did: persona_did.into(),
        subject: None,
        claims,
        purpose: None,
        renderer: None,
        durable_credential_id: None,
        cited_contact_revisions: Vec::new(),
        disclosed_at: now_rfc3339(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contact::{ContactClaim, ContactDocument};
    use vti_common::config::StoreConfig;
    use vti_common::store::Store;

    async fn fresh() -> (tempfile::TempDir, PersonaStore) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .unwrap();
        let ks = store.keyspace(vta_keyspaces::PERSONA).unwrap();
        (dir, PersonaStore::new(ks, [17u8; 32]))
    }

    fn claims(pairs: &[(&str, ProofRung)]) -> Vec<DisclosedClaim> {
        pairs
            .iter()
            .map(|(t, r)| DisclosedClaim {
                r#type: (*t).into(),
                rung: *r,
            })
            .collect()
    }

    #[tokio::test]
    async fn a_record_names_types_and_rungs_but_never_values() {
        let (_d, s) = fresh().await;
        let rec = new_disclosure(
            "ctx",
            "did:web:bar",
            "did:persona:a",
            claims(&[("person.birthDate", ProofRung::Predicate)]),
        );
        let id = s.record_disclosure(rec).await.unwrap();
        assert!(!id.is_empty());

        let raw = s.ks.prefix_iter_raw(b"pd:".to_vec()).await.unwrap();
        let text = String::from_utf8_lossy(&raw[0].1).to_string();
        assert!(text.contains("person.birthDate"));
        assert!(
            text.contains("predicate"),
            "the rung is recorded: same claim at two rungs is two different disclosures"
        );
    }

    #[tokio::test]
    async fn history_answers_where_a_fact_has_reached() {
        // The debt the scope split incurred: with the pool above the boundary,
        // a holder cannot tell from one context where a fact has gone.
        let (_d, s) = fresh().await;
        s.record_disclosure(new_disclosure(
            "ctx-work",
            "did:web:acme",
            "did:p1",
            claims(&[("address.postal", ProofRung::Whole)]),
        ))
        .await
        .unwrap();
        s.record_disclosure(new_disclosure(
            "ctx-play",
            "did:web:game",
            "did:p2",
            claims(&[("address.postal", ProofRung::Whole)]),
        ))
        .await
        .unwrap();
        s.record_disclosure(new_disclosure(
            "ctx-play",
            "did:web:game",
            "did:p2",
            claims(&[("name.display", ProofRung::Whole)]),
        ))
        .await
        .unwrap();

        let mut reached = s.contexts_reached_by("address.postal").await.unwrap();
        reached.sort();
        assert_eq!(reached, vec!["ctx-play", "ctx-work"]);
        assert_eq!(
            s.contexts_reached_by("name.display").await.unwrap(),
            vec!["ctx-play"]
        );
    }

    #[tokio::test]
    async fn history_narrows_by_verifier_and_by_context() {
        let (_d, s) = fresh().await;
        s.record_disclosure(new_disclosure(
            "ctx-a",
            "did:web:one",
            "did:p",
            claims(&[("email", ProofRung::Whole)]),
        ))
        .await
        .unwrap();
        s.record_disclosure(new_disclosure(
            "ctx-b",
            "did:web:two",
            "did:p",
            claims(&[("email", ProofRung::Whole)]),
        ))
        .await
        .unwrap();

        // Cross-context is the holder's view and returns both.
        assert_eq!(
            s.disclosure_history(&HistoryQuery::default())
                .await
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            s.disclosure_history(&HistoryQuery {
                context_id: Some("ctx-a"),
                ..Default::default()
            })
            .await
            .unwrap()
            .len(),
            1
        );
        assert_eq!(
            s.disclosure_history(&HistoryQuery {
                verifier_did: Some("did:web:two"),
                ..Default::default()
            })
            .await
            .unwrap()
            .len(),
            1
        );
    }

    #[tokio::test]
    async fn recording_a_disclosure_pins_the_contact_revisions_it_relied_on() {
        // This is the caller reference-counted retention was built for: without
        // it the mechanism exists and nothing ever exercises it.
        let (_d, s) = fresh().await;
        let doc = |v: &str| ContactDocument {
            publisher: None,
            card_version: None,
            claims: vec![ContactClaim {
                value_type: crate::ValueType::String,
                r#type: "email".into(),
                value: serde_json::json!(v),
                provenance: None,
            }],
        };
        let f = s
            .file_contact("ctx", "did:bob", "did:me", doc("a"), vec![], None)
            .await
            .unwrap();
        s.file_contact("ctx", "did:bob", "did:me", doc("b"), vec![], None)
            .await
            .unwrap();

        let mut rec = new_disclosure(
            "ctx",
            "did:web:v",
            "did:me",
            claims(&[("email", ProofRung::Whole)]),
        );
        rec.cited_contact_revisions = vec![(f.contact_id.clone(), 1)];
        s.record_disclosure(rec).await.unwrap();

        // The cited revision now survives a retention sweep that would
        // otherwise remove it.
        assert_eq!(
            s.reap_contact_revisions("ctx", &f.contact_id, 0)
                .await
                .unwrap(),
            0
        );
        let (_e, removed, retained) = s.delete_contact("ctx", &f.contact_id).await.unwrap();
        assert_eq!((removed, retained), (0, 1));
    }
}
