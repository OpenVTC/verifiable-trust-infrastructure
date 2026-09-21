//! The correlation index over values a face carries itself.
//!
//! [`crate::correlation`]'s index is keyed on pool attributes, and a face can
//! show a value that is in no pool attribute at all: an `override` replaces a
//! pool value for one face, and an `inline` entry never enters the pool. Before
//! this module neither was indexed, so the analysis could not see them — and
//! they are exactly the two forms a holder reaches for when they want a face to
//! be *different*. The same throwaway address typed into two context-local
//! faces is the linkage the guard exists to report, and it reported nothing.
//!
//! # One edge per value per face
//!
//! [`storage::face_value_key`] holds one row per `(value, face)`. A face
//! showing one value twice is one edge, because the question the index answers
//! is "which faces carry this", not "how many times". The row names the face;
//! it does not name the entry or the claim type, which are re-read from the
//! face when an analysis needs them. A claim type copied into the index would go
//! stale the moment the attribute an override refers to changed its type, and
//! nothing would notice.
//!
//! # Written with the face, under the same lock
//!
//! Every function here that writes expects the caller to hold `write_lock`,
//! for the reason [`crate::PersonaStore::put`] indexes before it writes: an
//! index edge with no face reads as a false warning, and a face with no edge
//! reads as a false all-clear. The writers call [`PersonaStore::reindex_face`]
//! before the face record lands and after it is gone, so a crash can only ever
//! leave the first.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use vti_common::error::AppError;

use crate::correlation;
use crate::model::{Profile, ProfileEntry};
use crate::profile::ProfileSlot;
use crate::storage;
use crate::store::{PersonaStore, Slot};

/// Which face one index edge names.
///
/// `context_id` is present exactly when the face is context-local. A pool face
/// is addressed by its id alone, and a local one needs its context to be found
/// again — the local address space is per context.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct FaceCarrier {
    pub profile_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_id: Option<String>,
}

impl FaceCarrier {
    fn key_suffix(&self) -> String {
        storage::face_carrier(self.context_id.as_deref(), &self.profile_id)
    }
}

/// Every value a face carries itself rather than draws from the pool.
///
/// `ref` and `pinned` entries are absent on purpose: their value *is* the pool
/// attribute's, which the attribute index already holds. Indexing it here as
/// well would count one value twice and report a face as sharing with itself.
pub(crate) fn carried_values(profile: &Profile) -> Vec<&serde_json::Value> {
    profile
        .entries
        .iter()
        .filter_map(|e| match e {
            ProfileEntry::Override { r#override, .. } => Some(&r#override.value),
            ProfileEntry::Inline { inline } => Some(&inline.value),
            ProfileEntry::Ref { .. } | ProfileEntry::Pinned { .. } => None,
        })
        .collect()
}

/// One value a face carries, with what the analysis needs to report it.
pub(crate) struct CarriedClaim {
    pub claim_type: String,
    pub provenance: crate::Provenance,
}

impl PersonaStore {
    fn blinds_of(&self, profile: Option<&Profile>) -> BTreeSet<String> {
        profile
            .map(|p| {
                carried_values(p)
                    .into_iter()
                    .map(|v| correlation::blind(&self.correlation_key, v))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Bring one face's edges from `old` to `new`. **Caller must hold
    /// `write_lock`.**
    ///
    /// Pass `new: None` for a delete and `old: None` for a create. Only the
    /// edges that changed are touched, so re-writing a face without changing
    /// the values it carries writes nothing here.
    pub(crate) async fn reindex_face(
        &self,
        context_id: Option<&str>,
        profile_id: &str,
        old: Option<&Profile>,
        new: Option<&Profile>,
    ) -> Result<(), AppError> {
        let carrier = FaceCarrier {
            profile_id: profile_id.to_string(),
            context_id: context_id.map(str::to_string),
        };
        let suffix = carrier.key_suffix();
        let before = self.blinds_of(old);
        let after = self.blinds_of(new);

        // Added before removed: a crash between the two leaves a stale edge,
        // which over-warns, rather than a missing one, which under-warns.
        for blind in after.difference(&before) {
            self.ks
                .insert(storage::face_value_key(blind, &suffix), &carrier)
                .await?;
        }
        for blind in before.difference(&after) {
            self.ks
                .remove(storage::face_value_key(blind, &suffix))
                .await?;
        }
        Ok(())
    }

    /// Every face carrying the value behind `blind`.
    pub(crate) async fn faces_carrying(&self, blind: &str) -> Result<Vec<FaceCarrier>, AppError> {
        let rows = self
            .ks
            .prefix_iter_raw(storage::face_value_prefix(blind).into_bytes())
            .await?;
        let mut out: Vec<FaceCarrier> = rows
            .into_iter()
            .filter_map(|(_k, v)| serde_json::from_slice(&v).ok())
            .collect();
        out.sort();
        out.dedup();
        Ok(out)
    }

    /// Every blinded value any face carries, each with the faces carrying it.
    pub(crate) async fn all_face_values(
        &self,
    ) -> Result<Vec<(String, Vec<FaceCarrier>)>, AppError> {
        let rows = self
            .ks
            .prefix_iter_raw(storage::FACE_VALUE_PREFIX.as_bytes().to_vec())
            .await?;
        let mut grouped: std::collections::BTreeMap<String, Vec<FaceCarrier>> =
            std::collections::BTreeMap::new();
        for (k, v) in rows {
            let Ok(key) = String::from_utf8(k) else {
                continue;
            };
            // `pxf:{hex}:{carrier}` — the hex holds no `:`, so the first
            // separator after the prefix ends it.
            let Some((blind, _)) = key
                .strip_prefix(storage::FACE_VALUE_PREFIX)
                .and_then(|rest| rest.split_once(':'))
            else {
                continue;
            };
            let Ok(carrier) = serde_json::from_slice::<FaceCarrier>(&v) else {
                continue;
            };
            grouped.entry(blind.to_string()).or_default().push(carrier);
        }
        Ok(grouped.into_iter().collect())
    }

    /// Read the face an edge names, from whichever address space it lives in.
    pub(crate) async fn carrier_face(
        &self,
        carrier: &FaceCarrier,
    ) -> Result<Option<Profile>, AppError> {
        match &carrier.context_id {
            None => self.get_profile(&carrier.profile_id).await,
            Some(ctx) => self.get_local_profile(ctx, &carrier.profile_id).await,
        }
    }

    /// The claims in `face` that carry the value behind `blind` — usually one,
    /// and never a `ref`: those are the attribute index's.
    ///
    /// An override takes the type and provenance of the attribute it replaces,
    /// which is the spec's rule for overrides (value only, provenance
    /// inherited) and the reason a displayed value cannot lower the severity
    /// the credential beneath it earns.
    pub(crate) async fn claims_carrying(
        &self,
        face: &Profile,
        blind: &str,
    ) -> Result<Vec<CarriedClaim>, AppError> {
        let mut out = Vec::new();
        for entry in &face.entries {
            match entry {
                ProfileEntry::Inline { inline }
                    if correlation::blind(&self.correlation_key, &inline.value) == blind =>
                {
                    out.push(CarriedClaim {
                        claim_type: inline.r#type.clone(),
                        provenance: inline.provenance.clone(),
                    });
                }
                ProfileEntry::Override { r#ref, r#override }
                    if correlation::blind(&self.correlation_key, &r#override.value) == blind =>
                {
                    let (claim_type, provenance) = match self.slot(r#ref).await? {
                        Some(Slot::Live(a)) => (a.r#type, a.provenance),
                        // The attribute went away behind the face. The value is
                        // still shown, so it is still reported — as a typed
                        // value, which is the least it can be.
                        _ => (String::new(), crate::Provenance::SelfAsserted),
                    };
                    out.push(CarriedClaim {
                        claim_type,
                        provenance,
                    });
                }
                _ => {}
            }
        }
        Ok(out)
    }

    /// Index every face written before this index existed, once.
    ///
    /// Run from the analysis rather than at boot, because the analysis is the
    /// only reader: a store nobody analyses pays nothing, and one that is
    /// analysed is never read unindexed. Idempotent — [`Self::reindex_face`]
    /// from `None` re-inserts edges that may already exist — so a crash
    /// part-way leaves the marker unset and the next analysis finishes the job.
    pub(crate) async fn ensure_face_value_index(&self) -> Result<(), AppError> {
        if self
            .ks
            .get::<bool>(storage::FACE_VALUE_INDEX_BUILT_KEY)
            .await?
            .is_some()
        {
            return Ok(());
        }
        let _guard = self.write_lock.lock().await;
        // Re-checked under the lock: two analyses racing past the first read
        // would otherwise both rebuild, harmlessly but for nothing.
        if self
            .ks
            .get::<bool>(storage::FACE_VALUE_INDEX_BUILT_KEY)
            .await?
            .is_some()
        {
            return Ok(());
        }

        for profile in self.list_profiles().await? {
            self.reindex_face(None, &profile.profile_id, None, Some(&profile))
                .await?;
        }
        let locals = self.ks.prefix_iter_raw(b"plp:".to_vec()).await?;
        for (k, v) in locals {
            let Ok(ProfileSlot::Live(profile)) = serde_json::from_slice::<ProfileSlot>(&v) else {
                continue;
            };
            // `plp:{context}:{id}`, and the id is a ULID with no `:` — so the
            // context is everything between the prefix and the LAST separator.
            let Some(context_id) = String::from_utf8(k).ok().and_then(|key| {
                key.strip_prefix("plp:")
                    .and_then(|rest| rest.rsplit_once(':'))
                    .map(|(ctx, _)| ctx.to_string())
            }) else {
                continue;
            };
            self.reindex_face(Some(&context_id), &profile.profile_id, None, Some(&profile))
                .await?;
        }

        self.ks
            .insert(storage::FACE_VALUE_INDEX_BUILT_KEY, &true)
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{InlineValue, OverrideValue, Provenance, ValueType};
    use crate::profile::new_profile;
    use crate::store::new_attribute;
    use vti_common::config::StoreConfig;
    use vti_common::store::Store;

    async fn fresh() -> (tempfile::TempDir, PersonaStore) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .unwrap();
        let ks = store.keyspace(vta_keyspaces::PERSONA).unwrap();
        (dir, PersonaStore::new(ks, [5u8; 32]))
    }

    fn inline(t: &str, v: &str) -> ProfileEntry {
        ProfileEntry::Inline {
            inline: InlineValue {
                r#type: t.into(),
                value_type: ValueType::String,
                value: serde_json::json!(v),
                label: None,
                provenance: Provenance::SelfAsserted,
            },
        }
    }

    fn named(findings: &[crate::correlation::Finding]) -> BTreeSet<String> {
        findings
            .iter()
            .flat_map(|f| f.shared_with.iter())
            .filter_map(|s| s.profile_id.clone())
            .collect()
    }

    /// The defect this module closes, stated as the holder would meet it: one
    /// throwaway address typed into two faces in two different contexts, and
    /// no pool attribute anywhere. It used to produce no finding at all.
    #[tokio::test]
    async fn the_same_value_in_two_local_faces_is_a_finding() {
        let (_d, s) = fresh().await;
        let a = new_profile("Market", vec![inline("email.personal", "throw@away.test")]);
        let b = new_profile("Forum", vec![inline("email.personal", "throw@away.test")]);
        s.put_local_profile("ctx-a", a.clone(), None).await.unwrap();
        s.put_local_profile("ctx-b", b.clone(), None).await.unwrap();

        let findings = s.analyze_correlation(None, None).await.unwrap();
        assert_eq!(findings.len(), 1, "one linkage, told once: {findings:?}");
        let f = &findings[0];
        assert!(f.attribute_id.is_none(), "there is no attribute to name");
        assert_eq!(f.severity, "high");
        assert_eq!(
            named(&findings),
            [a.profile_id.clone(), b.profile_id.clone()].into(),
            "both faces must be named, or the holder cannot tell which pair links"
        );
        // A local face names its context even unbound — it is not "nowhere".
        let contexts: BTreeSet<_> = f
            .shared_with
            .iter()
            .filter_map(|w| w.context_id.clone())
            .collect();
        assert_eq!(contexts, ["ctx-a".to_string(), "ctx-b".to_string()].into());
    }

    #[tokio::test]
    async fn an_override_equal_to_another_attribute_is_reported_on_that_attribute() {
        let (_d, s) = fresh().await;
        let mobile = new_attribute(
            "phone.mobile",
            ValueType::String,
            serde_json::json!("+61 400"),
            Provenance::SelfAsserted,
        );
        let work = new_attribute(
            "phone.mobile",
            ValueType::String,
            serde_json::json!("+61 999"),
            Provenance::SelfAsserted,
        );
        s.put(mobile.clone(), None).await.unwrap();
        s.put(work.clone(), None).await.unwrap();
        // A face that shows the personal number in place of the work one.
        let face = new_profile(
            "Work",
            vec![ProfileEntry::Override {
                r#ref: work.attribute_id.clone(),
                r#override: OverrideValue {
                    value: serde_json::json!("+61 400"),
                    label: None,
                },
            }],
        );
        s.put_profile(face.clone(), None).await.unwrap();

        let findings = s
            .analyze_correlation(Some(&mobile.attribute_id), None)
            .await
            .unwrap();
        assert_eq!(findings.len(), 1);
        assert!(named(&findings).contains(&face.profile_id));
        assert!(findings[0].why.contains("face"), "{}", findings[0].why);

        // And not twice over the whole store: the attribute's finding already
        // names the face.
        let all = s.analyze_correlation(None, None).await.unwrap();
        assert_eq!(all.len(), 1, "{all:?}");
    }

    #[tokio::test]
    async fn a_face_does_not_share_with_itself() {
        // One value shown twice by one face is one edge, and a face alone
        // links nothing.
        let (_d, s) = fresh().await;
        let face = new_profile(
            "Solo",
            vec![inline("name.display", "Ada"), inline("x:handle", "Ada")],
        );
        s.put_local_profile("ctx", face, None).await.unwrap();
        assert!(s.analyze_correlation(None, None).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn rewriting_or_deleting_a_face_drops_its_edges() {
        let (_d, s) = fresh().await;
        let a = new_profile("A", vec![inline("name.display", "Ada")]);
        let mut b = new_profile("B", vec![inline("name.display", "Ada")]);
        s.put_local_profile("ctx", a.clone(), None).await.unwrap();
        s.put_profile(b.clone(), None).await.unwrap();
        assert_eq!(s.analyze_correlation(None, None).await.unwrap().len(), 1);

        b.entries = vec![inline("name.display", "Grace")];
        s.put_profile(b.clone(), None).await.unwrap();
        assert!(
            s.analyze_correlation(None, None).await.unwrap().is_empty(),
            "a value the face no longer shows is still linking it"
        );

        b.entries = vec![inline("name.display", "Ada")];
        s.put_profile(b.clone(), None).await.unwrap();
        s.delete_local_profile("ctx", &a.profile_id).await.unwrap();
        assert!(
            s.analyze_correlation(None, None).await.unwrap().is_empty(),
            "a deleted face is still linking"
        );
    }

    /// Faces written before the index existed must be indexed before the first
    /// analysis reads it — otherwise an upgrade is a silent all-clear.
    #[tokio::test]
    async fn faces_written_before_the_index_are_backfilled() {
        let (_d, s) = fresh().await;
        let a = new_profile("A", vec![inline("name.display", "Ada")]);
        let b = new_profile("B", vec![inline("name.display", "Ada")]);
        s.put_profile(a, None).await.unwrap();
        s.put_local_profile("ctx", b, None).await.unwrap();

        // Simulate the pre-upgrade store: no edges, no marker.
        for (k, _) in
            s.ks.prefix_iter_raw(storage::FACE_VALUE_PREFIX.as_bytes().to_vec())
                .await
                .unwrap()
        {
            s.ks.remove(k).await.unwrap();
        }
        s.ks.remove(storage::FACE_VALUE_INDEX_BUILT_KEY)
            .await
            .unwrap();

        assert_eq!(s.analyze_correlation(None, None).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn analysing_a_face_covers_what_it_draws_and_what_it_carries() {
        let (_d, s) = fresh().await;
        let shared = new_attribute(
            "email.personal",
            ValueType::String,
            serde_json::json!("me@home.test"),
            Provenance::SelfAsserted,
        );
        let twin = new_attribute(
            "email.work",
            ValueType::String,
            serde_json::json!("me@home.test"),
            Provenance::SelfAsserted,
        );
        s.put(shared.clone(), None).await.unwrap();
        s.put(twin, None).await.unwrap();

        let face = new_profile(
            "Home",
            vec![
                ProfileEntry::Ref {
                    r#ref: shared.attribute_id.clone(),
                },
                inline("name.display", "Ada"),
            ],
        );
        let other = new_profile("Play", vec![inline("name.display", "Ada")]);
        s.put_profile(face.clone(), None).await.unwrap();
        s.put_local_profile("ctx", other.clone(), None)
            .await
            .unwrap();
        // Unrelated to this face, and must not appear in its analysis.
        s.put_local_profile("x", new_profile("X", vec![inline("x:y", "z")]), None)
            .await
            .unwrap();
        s.put_local_profile("y", new_profile("Y", vec![inline("x:y", "z")]), None)
            .await
            .unwrap();

        let findings = s.analyze_face_correlation(&face.profile_id).await.unwrap();
        assert_eq!(findings.len(), 2, "{findings:?}");
        assert!(
            findings
                .iter()
                .any(|f| f.attribute_id.as_deref() == Some(&*shared.attribute_id))
        );
        assert!(named(&findings).contains(&other.profile_id));

        // A local face is found by id alone.
        let local = s.analyze_face_correlation(&other.profile_id).await.unwrap();
        assert_eq!(local.len(), 1);

        let err = s.analyze_face_correlation("01NOTAFACE").await.unwrap_err();
        assert!(matches!(err, AppError::NotFound(_)), "got {err:?}");
    }
}
