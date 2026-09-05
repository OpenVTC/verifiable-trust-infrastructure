//! Profiles: composition over the pool, and the reverse index that makes a
//! delete able to name what it would break.
//!
//! A profile **references** attributes rather than copying them, which is the
//! property that lets a holder change a fact once. The cost is that the store
//! has to know who refers to what — hence the reverse index, written here and
//! read by [`crate::PersonaStore::referring_profiles`].
//!
//! # Resolution fails whole, never partially
//!
//! A profile whose entries do not all resolve is refused. A partially-resolved
//! composition would disclose less than the holder composed *and tell them
//! nothing about it*, which is the quiet failure this store exists to prevent.

use serde::{Deserialize, Serialize};
use vti_common::error::AppError;

use crate::model::{Profile, ProfileEntry, Ulid, Version};
use crate::storage;
use crate::store::{PersonaStore, Slot, Written, check_precondition, now_rfc3339};

/// A profile as stored, or the tombstone left where one was.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) enum ProfileSlot {
    Live(Profile),
    Tombstone {
        profile_id: Ulid,
        version: Version,
        deleted_at: String,
    },
}

/// One claim a profile would present, after resolution.
///
/// Distinct from [`Attribute`] because a resolved claim may not correspond to a
/// pool record at all — an `inline` entry has no `attributeId` — and because
/// what a profile presents is a *view*, not a record anyone can write back to.
#[derive(Clone, Debug, PartialEq)]
pub struct ResolvedClaim {
    /// `None` for an inline entry, which exists only inside this profile.
    pub attribute_id: Option<Ulid>,
    pub r#type: String,
    pub value: Option<serde_json::Value>,
    pub provenance: crate::Provenance,
    /// Set when a credential-backed value could not be re-derived. Such a claim
    /// MUST NOT be disclosed; it is surfaced so a holder learns their profile
    /// has quietly stopped being fully presentable.
    pub stale: bool,
}

impl PersonaStore {
    /// Create or replace one profile.
    ///
    /// Every `ref` must resolve to a live attribute. A dangling reference
    /// refuses the whole write, naming the offenders.
    pub async fn put_profile(
        &self,
        mut profile: Profile,
        expected_version: Option<Version>,
    ) -> Result<Written, AppError> {
        let _guard = self.write_lock.lock().await;

        // Validate before taking a version, so a refused write consumes nothing.
        let mut dangling = Vec::new();
        for entry in &profile.entries {
            if let Some(id) = entry.referenced()
                && !matches!(self.slot(id).await?, Some(Slot::Live(_)))
            {
                dangling.push(id.to_string());
            }
        }
        if !dangling.is_empty() {
            return Err(AppError::Validation(format!(
                "profile references {} attribute(s) the pool does not hold: {}",
                dangling.len(),
                dangling.join(", ")
            )));
        }

        let existing = self.profile_slot(&profile.profile_id).await?;
        let current_version = match &existing {
            Some(ProfileSlot::Live(p)) => Some(p.version),
            _ => None,
        };
        check_precondition(expected_version, current_version)?;

        let version = self.next_version().await?;
        let created = current_version.is_none();
        profile.version = version;
        profile.updated_at = now_rfc3339();

        // Reverse index: drop the old edges before adding the new, or an
        // attribute dropped from the profile keeps a stale referrer and its
        // delete is refused for a reference that no longer exists.
        if let Some(ProfileSlot::Live(old)) = &existing {
            for entry in &old.entries {
                if let Some(id) = entry.referenced() {
                    self.ks
                        .remove(storage::reverse_index_key(id, &old.profile_id))
                        .await?;
                }
            }
        }
        for entry in &profile.entries {
            if let Some(id) = entry.referenced() {
                self.ks
                    .insert(storage::reverse_index_key(id, &profile.profile_id), &true)
                    .await?;
            }
        }

        self.ks
            .insert(
                storage::profile_key(&profile.profile_id),
                &ProfileSlot::Live(profile),
            )
            .await?;

        Ok(Written { version, created })
    }

    pub async fn get_profile(&self, profile_id: &str) -> Result<Option<Profile>, AppError> {
        Ok(match self.profile_slot(profile_id).await? {
            Some(ProfileSlot::Live(p)) => Some(p),
            _ => None,
        })
    }

    pub(crate) async fn profile_slot(
        &self,
        profile_id: &str,
    ) -> Result<Option<ProfileSlot>, AppError> {
        self.ks
            .get::<ProfileSlot>(storage::profile_key(profile_id))
            .await
    }

    /// Resolve a profile into the claims it would present, in entry order.
    ///
    /// `override` replaces value and label **only** — type and provenance are
    /// inherited from the referenced attribute. Letting an override replace
    /// provenance would let a self-asserted value present as attested, which is
    /// the one thing provenance exists to prevent.
    pub async fn resolve_profile(&self, profile_id: &str) -> Result<Vec<ResolvedClaim>, AppError> {
        let profile = self
            .get_profile(profile_id)
            .await?
            .ok_or_else(|| AppError::NotFound(format!("profile {profile_id}")))?;

        let mut out = Vec::with_capacity(profile.entries.len());
        for entry in &profile.entries {
            out.push(match entry {
                ProfileEntry::Ref { r#ref } => self.claim_from_pool(r#ref, None).await?,
                ProfileEntry::Pinned { r#ref, pin_version } => {
                    self.claim_from_pool(r#ref, Some(*pin_version)).await?
                }
                ProfileEntry::Override { r#ref, r#override } => {
                    let mut c = self.claim_from_pool(r#ref, None).await?;
                    // Value only. Provenance is inherited, deliberately.
                    c.value = Some(r#override.value.clone());
                    c
                }
                ProfileEntry::Inline { inline } => ResolvedClaim {
                    attribute_id: None,
                    r#type: inline.r#type.clone(),
                    value: Some(inline.value.clone()),
                    provenance: inline.provenance.clone(),
                    stale: false,
                },
            });
        }
        Ok(out)
    }

    async fn claim_from_pool(
        &self,
        attribute_id: &str,
        pin: Option<Version>,
    ) -> Result<ResolvedClaim, AppError> {
        let Some(Slot::Live(a)) = self.slot(attribute_id).await? else {
            // Reachable only if an attribute went away behind a profile's back;
            // put_profile refuses dangling references. Surfaced as stale rather
            // than silently omitted, because a shorter disclosure the holder
            // was not told about is the failure mode this store guards.
            return Ok(ResolvedClaim {
                attribute_id: Some(attribute_id.to_string()),
                r#type: String::new(),
                value: None,
                provenance: crate::Provenance::SelfAsserted,
                stale: true,
            });
        };

        // A pin names a version this store no longer holds. Prior versions are
        // not retained yet, so a pin to anything but the current version cannot
        // be honoured — and is reported rather than silently served the current
        // value, which is the whole point of pinning.
        let stale = pin.is_some_and(|p| p != a.version);

        Ok(ResolvedClaim {
            attribute_id: Some(a.attribute_id.clone()),
            r#type: a.r#type.clone(),
            value: if stale { None } else { a.value.clone() },
            provenance: a.provenance.clone(),
            stale: stale || a.stale.unwrap_or(false),
        })
    }

    /// Remove a profile, dropping its reverse-index edges.
    ///
    /// The pool is untouched: a profile references rather than owns, so
    /// deleting a composition destroys no facts. That is the asymmetry with
    /// deleting an attribute, where removal *does* change what compositions
    /// present.
    pub async fn delete_profile(&self, profile_id: &str) -> Result<bool, AppError> {
        let _guard = self.write_lock.lock().await;

        let Some(ProfileSlot::Live(existing)) = self.profile_slot(profile_id).await? else {
            return Ok(false);
        };

        let version = self.next_version().await?;
        for entry in &existing.entries {
            if let Some(id) = entry.referenced() {
                self.ks
                    .remove(storage::reverse_index_key(id, profile_id))
                    .await?;
            }
        }
        self.ks
            .insert(
                storage::profile_key(profile_id),
                &ProfileSlot::Tombstone {
                    profile_id: profile_id.to_string(),
                    version,
                    deleted_at: now_rfc3339(),
                },
            )
            .await?;
        Ok(true)
    }

    /// Every live profile, in key order — which is creation order, because the
    /// identifiers are ULIDs.
    pub async fn list_profiles(&self) -> Result<Vec<Profile>, AppError> {
        let rows = self
            .ks
            .prefix_iter_raw(storage::PROFILE_PREFIX.as_bytes().to_vec())
            .await?;
        let mut out = Vec::new();
        for (_k, v) in rows {
            if let Ok(ProfileSlot::Live(p)) = serde_json::from_slice::<ProfileSlot>(&v) {
                out.push(p);
            }
        }
        Ok(out)
    }
}

/// Build a profile with server-assigned identity and timestamps.
#[must_use]
pub fn new_profile(name: impl Into<String>, entries: Vec<ProfileEntry>) -> Profile {
    let now = now_rfc3339();
    Profile {
        profile_id: ulid::Ulid::new().to_string(),
        name: name.into(),
        entries,
        credential_refs: Vec::new(),
        version: 0,
        created_at: now.clone(),
        updated_at: now,
    }
}

/// Whether every entry is inline — the condition a context-local profile must
/// satisfy.
///
/// A local profile that could reference the pool would be a context-authored
/// object acquiring pool reach, which is the escalation the boundary exists to
/// prevent. Expressed as a function so the dispatcher checks it rather than
/// reimplementing it.
#[must_use]
pub fn is_pool_free(entries: &[ProfileEntry]) -> bool {
    entries.iter().all(|e| e.referenced().is_none())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{InlineValue, OverrideValue, Provenance, ValueType};
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

    fn attr(v: &str) -> crate::Attribute {
        new_attribute(
            "phone.mobile",
            ValueType::String,
            serde_json::json!(v),
            Provenance::SelfAsserted,
        )
    }

    #[tokio::test]
    async fn a_dangling_reference_refuses_the_whole_write() {
        let (_d, s) = fresh().await;
        let p = new_profile(
            "Work",
            vec![ProfileEntry::Ref {
                r#ref: "01MISSING".into(),
            }],
        );
        let err = s.put_profile(p, None).await.unwrap_err();
        assert!(matches!(err, AppError::Validation(_)), "got {err:?}");
        // And consumed no version: a refused write must cost nothing.
        assert!(s.list_profiles().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn the_reverse_index_makes_a_delete_able_to_name_what_it_breaks() {
        let (_d, s) = fresh().await;
        let a = attr("+61 4");
        s.put(a.clone(), None).await.unwrap();
        let p = new_profile(
            "Work",
            vec![ProfileEntry::Ref {
                r#ref: a.attribute_id.clone(),
            }],
        );
        s.put_profile(p.clone(), None).await.unwrap();

        assert_eq!(
            s.referring_profiles(&a.attribute_id).await.unwrap(),
            vec![p.profile_id.clone()]
        );

        // Deleting the attribute is refused while referenced.
        let err = s.delete(&a.attribute_id, false).await.unwrap_err();
        assert!(matches!(err, AppError::Conflict(_)));
        // ...and permitted with cascade.
        let out = s.delete(&a.attribute_id, true).await.unwrap();
        assert_eq!(out.referring_profiles, vec![p.profile_id]);
    }

    #[tokio::test]
    async fn dropping_an_entry_drops_its_index_edge() {
        // Otherwise an attribute removed from a profile keeps a stale referrer,
        // and its delete is refused for a reference that no longer exists.
        let (_d, s) = fresh().await;
        let a = attr("x");
        s.put(a.clone(), None).await.unwrap();
        let mut p = new_profile(
            "Work",
            vec![ProfileEntry::Ref {
                r#ref: a.attribute_id.clone(),
            }],
        );
        s.put_profile(p.clone(), None).await.unwrap();

        p.entries.clear();
        s.put_profile(p, None).await.unwrap();

        assert!(
            s.referring_profiles(&a.attribute_id)
                .await
                .unwrap()
                .is_empty()
        );
        s.delete(&a.attribute_id, false)
            .await
            .expect("no longer referenced");
    }

    #[tokio::test]
    async fn an_override_replaces_the_value_and_never_the_provenance() {
        let (_d, s) = fresh().await;
        let mut a = attr("real");
        a.provenance = Provenance::CredentialBacked {
            credential_id: "vc-1".into(),
            claim_path: "/credentialSubject/tel".into(),
            issuer_did: None,
            proof: None,
        };
        s.put(a.clone(), None).await.unwrap();

        let p = new_profile(
            "Gaming",
            vec![ProfileEntry::Override {
                r#ref: a.attribute_id.clone(),
                r#override: OverrideValue {
                    value: serde_json::json!("masked"),
                    label: None,
                },
            }],
        );
        s.put_profile(p.clone(), None).await.unwrap();

        let claims = s.resolve_profile(&p.profile_id).await.unwrap();
        assert_eq!(claims[0].value, Some(serde_json::json!("masked")));
        // Provenance is inherited. If an override could change it, a
        // self-asserted value could present as attested.
        assert!(matches!(
            claims[0].provenance,
            Provenance::CredentialBacked { .. }
        ));
    }

    #[tokio::test]
    async fn an_unhonourable_pin_is_reported_not_silently_served() {
        let (_d, s) = fresh().await;
        let a = attr("v1");
        let w = s.put(a.clone(), None).await.unwrap();
        let p = new_profile(
            "Work",
            vec![ProfileEntry::Pinned {
                r#ref: a.attribute_id.clone(),
                pin_version: w.version + 99,
            }],
        );
        s.put_profile(p.clone(), None).await.unwrap();

        let claims = s.resolve_profile(&p.profile_id).await.unwrap();
        // Serving the current value would defeat the whole point of pinning.
        assert!(claims[0].stale);
        assert_eq!(claims[0].value, None);
    }

    #[tokio::test]
    async fn inline_entries_resolve_without_the_pool_and_are_pool_free() {
        let (_d, s) = fresh().await;
        let entries = vec![ProfileEntry::Inline {
            inline: InlineValue {
                r#type: "x:guild".into(),
                value_type: ValueType::String,
                value: serde_json::json!("Nightfall"),
                label: None,
                provenance: Provenance::SelfAsserted,
            },
        }];
        assert!(
            is_pool_free(&entries),
            "a local profile must reference nothing"
        );

        let p = new_profile("Gaming", entries);
        s.put_profile(p.clone(), None).await.unwrap();
        let claims = s.resolve_profile(&p.profile_id).await.unwrap();
        assert_eq!(claims[0].attribute_id, None);
        assert_eq!(claims[0].value, Some(serde_json::json!("Nightfall")));
    }

    #[tokio::test]
    async fn deleting_a_profile_leaves_the_pool_alone() {
        // The asymmetry with attribute deletion: a profile references rather
        // than owns, so removing one destroys no facts.
        let (_d, s) = fresh().await;
        let a = attr("keep me");
        s.put(a.clone(), None).await.unwrap();
        let p = new_profile(
            "Work",
            vec![ProfileEntry::Ref {
                r#ref: a.attribute_id.clone(),
            }],
        );
        s.put_profile(p.clone(), None).await.unwrap();

        assert!(s.delete_profile(&p.profile_id).await.unwrap());
        assert!(
            s.get(&a.attribute_id).await.unwrap().is_some(),
            "the fact survives"
        );
        assert!(
            s.referring_profiles(&a.attribute_id)
                .await
                .unwrap()
                .is_empty()
        );
        // A repeat delete converges.
        assert!(!s.delete_profile(&p.profile_id).await.unwrap());
    }
}
