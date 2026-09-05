//! Bindings: assigning a profile to a persona DID, and the push that carries a
//! composition across the context boundary.
//!
//! This is where the one-way rule stops being a key layout and becomes
//! behaviour. The pool and profiles are agent-scoped; a binding is
//! context-scoped. Setting one is the moment a composition crosses, and the
//! crossing has a direction: **the holder pushes a materialised projection
//! down, and a context never pulls.**
//!
//! # The projection carries no back-reference
//!
//! What lands in the context is [`MaterialisedClaim`] — values, flat, with no
//! `attributeId`. That is a distinct type from [`crate::ResolvedClaim`] rather
//! than the same one with a field left empty, because the difference is the
//! security property: a function handed a `MaterialisedClaim` *cannot* obtain a
//! pool identifier, so no future edit can accidentally leak one across the
//! boundary by forgetting to clear it.
//!
//! That is what makes the boundary hold under compromise. An attacker with
//! administrative access to the context sees exactly what was pushed, and
//! nothing there leads anywhere else — the rest of the pool is not merely
//! forbidden to them, it is absent.

use serde::{Deserialize, Serialize};
use vti_common::error::AppError;

use crate::model::{Binding, Provenance, Ulid, Version};
use crate::profile::ProfileSlot;
use crate::storage;
use crate::store::{PersonaStore, check_precondition, now_rfc3339};

/// One claim as it exists *inside a context*, after being pushed down.
///
/// Deliberately has no `attribute_id`. See the module docs: the absence is the
/// control, and making it a separate type means the compiler enforces it rather
/// than a reviewer noticing.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MaterialisedClaim {
    pub r#type: String,
    pub value: Option<serde_json::Value>,
    pub provenance: Provenance,
    /// A stale claim is materialised so the holder can see the projection is
    /// short, and MUST NOT be disclosed.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub stale: bool,
}

/// The binding plus the claims it pushed into the context.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct BindingRecord {
    pub binding: Binding,
    /// Cached label so a context-scoped read can name the composition without
    /// reaching across the boundary to the profile.
    pub profile_name: Option<String>,
    pub claims: Vec<MaterialisedClaim>,
}

/// What a context-scoped caller may learn about a binding.
///
/// Whether a profile is bound, the holder's label for it, and how many claims
/// are available — never their contents. With the disclosure path this exhausts
/// what an application inside a context can obtain: being inside confers no
/// privilege over identity data.
#[derive(Clone, Debug, PartialEq)]
pub struct BindingSummary {
    pub persona_did: String,
    pub bound: bool,
    pub profile_id: Option<Ulid>,
    pub profile_name: Option<String>,
    pub claim_count: usize,
    pub bound_at: Option<String>,
}

/// Outcome of a push.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bound {
    pub version: Version,
    pub materialised_claim_count: usize,
    /// How many *other* personas are bound to this same profile.
    ///
    /// A count, not identifiers: the association between the holder's personas
    /// is exactly what an attacker wants, and a count is enough to warn.
    /// Non-zero means the two personas are the same person by construction, and
    /// no later narrowing undoes that.
    pub also_bound_persona_count: usize,
}

impl PersonaStore {
    /// Assign a profile to a persona in a context, or clear the assignment.
    ///
    /// `profile_id: None` clears. A persona with no profile is a legitimate and
    /// common state — a throwaway identity that presents nothing — so it is a
    /// first-class value rather than an absence to be inferred.
    pub async fn set_binding(
        &self,
        context_id: &str,
        persona_did: &str,
        profile_id: Option<&str>,
        public_entries: Vec<Ulid>,
        expected_version: Option<Version>,
    ) -> Result<Bound, AppError> {
        let _guard = self.write_lock.lock().await;

        let existing = self.binding_record(context_id, persona_did).await?;
        check_precondition(
            expected_version,
            existing.as_ref().map(|r| r.binding.version),
        )?;

        let (profile_name, claims) = match profile_id {
            None => (None, Vec::new()),
            Some(id) => {
                // Refuse rather than write a binding that presents nothing while
                // appearing configured.
                let Some(ProfileSlot::Live(p)) = self.profile_slot(id).await? else {
                    return Err(AppError::NotFound(format!(
                        "profile {id} does not exist; refusing to bind a persona to it"
                    )));
                };
                (Some(p.name.clone()), self.materialise(id).await?)
            }
        };

        let also_bound = match profile_id {
            Some(id) => self
                .personas_bound_to(context_id, id)
                .await?
                .into_iter()
                .filter(|d| d != persona_did)
                .count(),
            None => 0,
        };

        let version = self.next_version().await?;
        let record = BindingRecord {
            binding: Binding {
                persona_did: persona_did.to_string(),
                profile_id: profile_id.map(str::to_string),
                public_entries,
                version,
                bound_at: now_rfc3339(),
            },
            profile_name,
            claims,
        };
        let count = record.claims.len();

        self.ks
            .insert(storage::binding_key(context_id, persona_did), &record)
            .await?;

        Ok(Bound {
            version,
            materialised_claim_count: count,
            also_bound_persona_count: also_bound,
        })
    }

    /// Resolve a profile and strip every pool identifier from the result.
    ///
    /// The strip is the whole point, and it happens by *construction* — the
    /// output type has nowhere to put an identifier.
    async fn materialise(&self, profile_id: &str) -> Result<Vec<MaterialisedClaim>, AppError> {
        Ok(self
            .resolve_profile(profile_id)
            .await?
            .into_iter()
            .map(|c| MaterialisedClaim {
                r#type: c.r#type,
                value: c.value,
                provenance: c.provenance,
                stale: c.stale,
            })
            .collect())
    }

    pub(crate) async fn binding_record(
        &self,
        context_id: &str,
        persona_did: &str,
    ) -> Result<Option<BindingRecord>, AppError> {
        self.ks
            .get::<BindingRecord>(storage::binding_key(context_id, persona_did))
            .await
    }

    /// What a context-scoped caller may learn. Never the claim values.
    pub async fn binding_summary(
        &self,
        context_id: &str,
        persona_did: &str,
    ) -> Result<BindingSummary, AppError> {
        let record = self.binding_record(context_id, persona_did).await?;
        Ok(match record {
            None => BindingSummary {
                persona_did: persona_did.to_string(),
                bound: false,
                profile_id: None,
                profile_name: None,
                claim_count: 0,
                bound_at: None,
            },
            Some(r) => BindingSummary {
                persona_did: persona_did.to_string(),
                // A binding row with a null profile is bound-to-nothing, which
                // is not the same as having no binding at all — but a
                // context-scoped caller is told the same thing either way,
                // because the distinction is the holder's business.
                bound: r.binding.profile_id.is_some(),
                profile_id: r.binding.profile_id.clone(),
                profile_name: r.profile_name.clone(),
                claim_count: r.claims.len(),
                bound_at: Some(r.binding.bound_at.clone()),
            },
        })
    }

    /// The claims pushed into a context for one persona.
    ///
    /// This is what a disclosure draws on. It cannot reach the pool — the return
    /// type has no identifiers — so a disclosure serves what was pushed and
    /// nothing else.
    pub async fn materialised_claims(
        &self,
        context_id: &str,
        persona_did: &str,
    ) -> Result<Vec<MaterialisedClaim>, AppError> {
        Ok(self
            .binding_record(context_id, persona_did)
            .await?
            .map(|r| r.claims)
            .unwrap_or_default())
    }

    /// Every persona in a context bound to a given profile.
    pub async fn personas_bound_to(
        &self,
        context_id: &str,
        profile_id: &str,
    ) -> Result<Vec<String>, AppError> {
        Ok(self
            .list_bindings(context_id)
            .await?
            .into_iter()
            .filter(|r| r.binding.profile_id.as_deref() == Some(profile_id))
            .map(|r| r.binding.persona_did)
            .collect())
    }

    pub(crate) async fn list_bindings(
        &self,
        context_id: &str,
    ) -> Result<Vec<BindingRecord>, AppError> {
        let rows = self
            .ks
            .prefix_iter_raw(storage::binding_prefix(context_id).into_bytes())
            .await?;
        Ok(rows
            .into_iter()
            .filter_map(|(_k, v)| serde_json::from_slice::<BindingRecord>(&v).ok())
            .collect())
    }

    /// Summaries for every persona in a context.
    pub async fn list_binding_summaries(
        &self,
        context_id: &str,
    ) -> Result<Vec<BindingSummary>, AppError> {
        Ok(self
            .list_bindings(context_id)
            .await?
            .into_iter()
            .map(|r| BindingSummary {
                persona_did: r.binding.persona_did,
                bound: r.binding.profile_id.is_some(),
                profile_id: r.binding.profile_id,
                profile_name: r.profile_name,
                claim_count: r.claims.len(),
                bound_at: Some(r.binding.bound_at),
            })
            .collect())
    }

    /// Re-push every projection that draws on a profile.
    ///
    /// "Edit once, everywhere" survives the boundary because this is a **write
    /// initiated above it**, never a read from below. A context that could pull
    /// its projection fresh would be reaching into the pool, which is the thing
    /// the direction rule forbids.
    ///
    /// Returns how many projections were refreshed.
    pub async fn rematerialise(&self, profile_id: &str) -> Result<usize, AppError> {
        let _guard = self.write_lock.lock().await;
        let claims = self.materialise(profile_id).await?;

        let mut refreshed = 0usize;
        let rows = self.ks.prefix_iter_raw(b"pb:".to_vec()).await?;
        for (k, v) in rows {
            let Ok(mut record) = serde_json::from_slice::<BindingRecord>(&v) else {
                continue;
            };
            if record.binding.profile_id.as_deref() != Some(profile_id) {
                continue;
            }
            record.claims = claims.clone();
            self.ks.insert(k, &record).await?;
            refreshed += 1;
        }
        Ok(refreshed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{ProfileEntry, ValueType};
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
        (dir, PersonaStore::new(ks, [11u8; 32]))
    }

    async fn pool_profile(s: &PersonaStore, value: &str) -> (String, String) {
        let a = new_attribute(
            "phone.mobile",
            ValueType::String,
            serde_json::json!(value),
            Provenance::SelfAsserted,
        );
        s.put(a.clone(), None).await.unwrap();
        let p = new_profile(
            "Work",
            vec![ProfileEntry::Ref {
                r#ref: a.attribute_id.clone(),
            }],
        );
        s.put_profile(p.clone(), None).await.unwrap();
        (a.attribute_id, p.profile_id)
    }

    #[tokio::test]
    async fn the_projection_carries_no_pool_identifier() {
        // The security property, asserted on the serialised bytes rather than
        // the type — because what crosses the boundary is what was written.
        let (_d, s) = fresh().await;
        let (attr_id, profile_id) = pool_profile(&s, "+61 4").await;
        s.set_binding("ctx", "did:persona:a", Some(&profile_id), vec![], None)
            .await
            .unwrap();

        let raw =
            s.ks.get_raw(storage::binding_key("ctx", "did:persona:a"))
                .await
                .unwrap()
                .expect("row");
        let text = String::from_utf8_lossy(&raw);
        assert!(
            !text.contains(&attr_id),
            "a materialised projection must carry no back-reference into the pool"
        );
        assert!(
            text.contains("+61 4"),
            "but it does carry the value it pushed"
        );
    }

    #[tokio::test]
    async fn binding_to_a_missing_profile_is_refused() {
        // Writing it would leave a persona that appears configured and presents
        // nothing.
        let (_d, s) = fresh().await;
        let err = s
            .set_binding("ctx", "did:persona:a", Some("01MISSING"), vec![], None)
            .await
            .unwrap_err();
        assert!(matches!(err, AppError::NotFound(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn clearing_is_a_first_class_state_not_an_absence() {
        let (_d, s) = fresh().await;
        let (_a, p) = pool_profile(&s, "x").await;
        s.set_binding("ctx", "did:p", Some(&p), vec![], None)
            .await
            .unwrap();
        assert!(s.binding_summary("ctx", "did:p").await.unwrap().bound);

        s.set_binding("ctx", "did:p", None, vec![], None)
            .await
            .unwrap();
        let sum = s.binding_summary("ctx", "did:p").await.unwrap();
        assert!(!sum.bound);
        assert_eq!(sum.claim_count, 0, "clearing removes the projection");
        assert!(
            s.materialised_claims("ctx", "did:p")
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn a_second_persona_on_one_profile_is_counted_and_warned() {
        // Binding one profile to a second persona makes them the same person by
        // construction, and no later narrowing undoes it.
        let (_d, s) = fresh().await;
        let (_a, p) = pool_profile(&s, "x").await;

        let first = s
            .set_binding("ctx", "did:p1", Some(&p), vec![], None)
            .await
            .unwrap();
        assert_eq!(first.also_bound_persona_count, 0);

        let second = s
            .set_binding("ctx", "did:p2", Some(&p), vec![], None)
            .await
            .unwrap();
        assert_eq!(second.also_bound_persona_count, 1);
    }

    #[tokio::test]
    async fn a_summary_names_the_composition_and_never_its_contents() {
        let (_d, s) = fresh().await;
        let (_a, p) = pool_profile(&s, "+61 4xx secret").await;
        s.set_binding("ctx", "did:p", Some(&p), vec![], None)
            .await
            .unwrap();

        let sum = s.binding_summary("ctx", "did:p").await.unwrap();
        assert_eq!(sum.profile_name.as_deref(), Some("Work"));
        assert_eq!(sum.claim_count, 1);
        // There is nowhere in a summary to put a value, which is the point.
        let rendered = format!("{sum:?}");
        assert!(!rendered.contains("secret"));
    }

    #[tokio::test]
    async fn editing_the_pool_refreshes_pushed_projections() {
        // "Edit once, everywhere" survives the boundary because this is a write
        // from above, not a read from below.
        let (_d, s) = fresh().await;
        let (attr_id, p) = pool_profile(&s, "old").await;
        s.set_binding("ctx", "did:p", Some(&p), vec![], None)
            .await
            .unwrap();
        assert_eq!(
            s.materialised_claims("ctx", "did:p").await.unwrap()[0].value,
            Some(serde_json::json!("old"))
        );

        let mut updated = s.get(&attr_id).await.unwrap().unwrap();
        updated.value = Some(serde_json::json!("new"));
        s.put(updated, None).await.unwrap();

        assert_eq!(s.rematerialise(&p).await.unwrap(), 1);
        assert_eq!(
            s.materialised_claims("ctx", "did:p").await.unwrap()[0].value,
            Some(serde_json::json!("new"))
        );
    }

    #[tokio::test]
    async fn a_context_sees_only_its_own_bindings() {
        let (_d, s) = fresh().await;
        let (_a, p) = pool_profile(&s, "x").await;
        s.set_binding("ctx-a", "did:p", Some(&p), vec![], None)
            .await
            .unwrap();

        assert_eq!(s.list_binding_summaries("ctx-a").await.unwrap().len(), 1);
        assert!(s.list_binding_summaries("ctx-b").await.unwrap().is_empty());
        assert!(!s.binding_summary("ctx-b", "did:p").await.unwrap().bound);
    }
}
