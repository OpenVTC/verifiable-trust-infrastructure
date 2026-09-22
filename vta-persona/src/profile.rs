//! Profiles: composition over the pool, and the reverse index that makes a
//! delete able to name what it would break.
//!
//! A profile **references** attributes rather than copying them, which is the
//! property that lets a holder change an attribute once. The cost is that the store
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
    /// What the value is. An inline entry carries its own; a pool-backed one
    /// takes the attribute's.
    pub value_type: crate::ValueType,
    /// The holder's own words for this claim — the override's where it gives
    /// one, else the pool attribute's, else the inline entry's. Never
    /// disclosed: it is for the holder's own view of what a face shows.
    pub label: Option<String>,
    /// The role the entry this claim came from plays in its face —
    /// `displayName` for what the face calls itself.
    pub slot: Option<String>,
    pub provenance: crate::Provenance,
    /// The pool attribute's version and last-write time — `None` for an inline
    /// entry, which has no pool record behind it and so has neither. The
    /// distinction is the point: a holder reading a resolved profile needs to
    /// know which of its values track something and which are frozen where
    /// they were typed.
    pub version: Option<Version>,
    pub updated_at: Option<String>,
    /// Set when a credential-backed value could not be re-derived. Such a claim
    /// MUST NOT be disclosed; it is surfaced so a holder learns their profile
    /// has quietly stopped being fully presentable.
    pub stale: bool,
    /// The holder's `release` override on the pool attribute behind this claim,
    /// where they set one. `None` for an inline entry — it has no pool record,
    /// so there is nowhere for a decision to have been recorded and the
    /// registry default answers.
    pub release: Option<crate::ReleaseRequirement>,
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
        refuse_duplicate_slot(&profile.entries)?;
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
        // A pin to a version neither current nor kept would present nothing
        // from the moment it is written.
        let unavailable = self.unavailable_pins(&profile.entries).await?;
        if !unavailable.is_empty() {
            return Err(AppError::Validation(format!(
                "profile pins {} version(s) this store does not hold: {}",
                unavailable.len(),
                unavailable
                    .iter()
                    .map(|(a, v)| format!("{a}@{v}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            )));
        }

        let existing = self.profile_slot(&profile.profile_id).await?;
        let current_version = match &existing {
            Some(ProfileSlot::Live(p)) => Some(p.version),
            _ => None,
        };
        check_precondition(expected_version, current_version)?;
        // Narrowing where a face may go must not silently take it off where it
        // is: the holder takes it off there first, deliberately.
        let excluded = self
            .reach_would_exclude(&profile.profile_id, &profile.reach)
            .await?;
        if !excluded.is_empty() {
            return Err(AppError::Validation(format!(
                "the new reach excludes context(s) this face is worn in: {}",
                excluded.join(", ")
            )));
        }

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

        // Values the face carries itself are indexed before the record lands,
        // for the reason the attribute path indexes first: a crash then leaves
        // an edge with no face (a false warning), never a face with no edge (a
        // false all-clear).
        let old_profile = match &existing {
            Some(ProfileSlot::Live(p)) => Some(p),
            _ => None,
        };
        self.reindex_face(None, &profile.profile_id, old_profile, Some(&profile))
            .await?;
        let old_pins: Vec<ProfileEntry> =
            old_profile.map(|p| p.entries.clone()).unwrap_or_default();
        let new_pins: Vec<ProfileEntry> = profile.entries.clone();

        let profile_id = profile.profile_id.clone();
        self.ks
            .insert(
                storage::profile_key(&profile_id),
                &ProfileSlot::Live(profile),
            )
            .await?;

        // Changing what a profile projects changes what every persona bound to
        // it presents. Same reasoning as the attribute path in `store.rs`: the
        // push belongs to the write, because a context cannot pull.
        self.push_profile_locked(&profile_id).await?;

        // A pin this write dropped may have been the last reason to keep an
        // earlier version.
        for attribute_id in pinned_refs(old_pins.iter().chain(new_pins.iter())) {
            self.reap_unpinned(&attribute_id).await?;
        }

        if created {
            self.record_face_event(
                &profile_id,
                crate::FaceEvent::now(crate::FaceEventKind::Composed),
            )
            .await;
        }
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
            let mut claim = match entry {
                ProfileEntry::Ref { r#ref, .. } => self.claim_from_pool(r#ref, None).await?,
                ProfileEntry::Pinned {
                    r#ref, pin_version, ..
                } => self.claim_from_pool(r#ref, Some(*pin_version)).await?,
                ProfileEntry::Override {
                    r#ref, r#override, ..
                } => {
                    let mut c = self.claim_from_pool(r#ref, None).await?;
                    // Value and label. Provenance is inherited, deliberately.
                    c.value = Some(r#override.value.clone());
                    if r#override.label.is_some() {
                        c.label = r#override.label.clone();
                    }
                    c
                }
                ProfileEntry::Inline { inline, .. } => ResolvedClaim {
                    attribute_id: None,
                    r#type: inline.r#type.clone(),
                    value: Some(inline.value.clone()),
                    value_type: inline.value_type,
                    label: inline.label.clone(),
                    slot: None,
                    provenance: inline.provenance.clone(),
                    version: None,
                    updated_at: None,
                    stale: false,
                    release: None,
                },
            };
            // Carried from the entry whatever its form, so a consumer finds
            // "what this face calls itself" by role rather than by guessing
            // from a claim type the face may hold twice.
            claim.slot = entry.slot().map(str::to_string);
            out.push(claim);
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
                value_type: crate::ValueType::String,
                label: None,
                slot: None,
                provenance: crate::Provenance::SelfAsserted,
                version: None,
                updated_at: None,
                stale: true,
                release: None,
            });
        };

        // A pin to an earlier version is served from the copy kept for it
        // (`retention`). A pin to a version the store no longer holds — purged
        // by the holder — is reported stale rather than silently served the
        // current value, which would defeat the whole point of pinning.
        if let Some(p) = pin
            && p != a.version
        {
            let Some(old) = self.retained(attribute_id, p).await? else {
                return Ok(ResolvedClaim {
                    attribute_id: Some(a.attribute_id.clone()),
                    r#type: a.r#type.clone(),
                    value: None,
                    value_type: a.value_type,
                    label: a.label.clone(),
                    slot: None,
                    provenance: a.provenance.clone(),
                    version: Some(p),
                    updated_at: None,
                    stale: true,
                    release: a.release,
                });
            };
            return Ok(ResolvedClaim {
                attribute_id: Some(old.attribute_id.clone()),
                r#type: old.r#type.clone(),
                value: old.value.clone(),
                value_type: old.value_type,
                label: old.label.clone(),
                slot: None,
                provenance: old.provenance.clone(),
                version: Some(old.version),
                updated_at: Some(old.updated_at.clone()),
                stale: old.stale.unwrap_or(false),
                // The holder's decision about letting the attribute leave is
                // about the attribute, not one version of it: the current one
                // answers for the kept copy too.
                release: a.release,
            });
        }
        let stale = false;

        Ok(ResolvedClaim {
            attribute_id: Some(a.attribute_id.clone()),
            r#type: a.r#type.clone(),
            value: if stale { None } else { a.value.clone() },
            value_type: a.value_type,
            label: a.label.clone(),
            slot: None,
            provenance: a.provenance.clone(),
            version: Some(a.version),
            updated_at: Some(a.updated_at.clone()),
            stale: stale || a.stale.unwrap_or(false),
            // Carried down with the value, because nothing below the boundary
            // can read the pool to ask. An `override` entry replaces the value
            // and inherits everything else, this included — the holder's
            // decision is about the attribute, not about one presentation of it.
            release: a.release,
        })
    }

    /// Remove a profile, dropping its reverse-index edges.
    ///
    /// The pool is untouched: a profile references rather than owns, so
    /// deleting a composition destroys no attributes. That is the asymmetry with
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
        // After the tombstone, so a crash between leaves a stale edge.
        self.reindex_face(None, profile_id, Some(&existing), None)
            .await?;
        for attribute_id in pinned_refs(existing.entries.iter()) {
            self.reap_unpinned(&attribute_id).await?;
        }
        self.forget_face_events(profile_id).await?;
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
        profile_id: ulid::Ulid::generate().to_string(),
        name: name.into(),
        entries,
        credential_refs: Vec::new(),
        reach: crate::model::FaceReach::Anywhere,
        status: crate::model::ProfileStatus::Active,
        retired_at: None,
        version: 0,
        created_at: now.clone(),
        updated_at: now,
    }
}

/// The attributes a set of entries pins, each once.
fn pinned_refs<'a>(entries: impl Iterator<Item = &'a ProfileEntry>) -> Vec<String> {
    let set: std::collections::BTreeSet<String> = entries
        .filter_map(|e| match e {
            ProfileEntry::Pinned { r#ref, .. } => Some(r#ref.clone()),
            _ => None,
        })
        .collect();
    set.into_iter().collect()
}

/// Refuse a face in which two entries claim one slot — see
/// [`crate::model::duplicate_slot`]. The dispatcher checks first so it can
/// carry the spec's error code; this is the check no write path can skip.
fn refuse_duplicate_slot(entries: &[ProfileEntry]) -> Result<(), AppError> {
    match crate::model::duplicate_slot(entries) {
        Some(slot) => Err(AppError::Validation(format!(
            "two entries of this face both claim the slot {slot}"
        ))),
        None => Ok(()),
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

    /// The holder's label reaches the resolved view, and an override's wins.
    ///
    /// `OverrideValue.label` was accepted, stored, and then dropped on
    /// resolution while the form's own documentation said it replaced the
    /// label — so a holder who named an override lost the name everywhere
    /// they would look for it.
    #[tokio::test]
    async fn a_resolved_claim_carries_the_holders_label() {
        let (_d, s) = fresh().await;
        let mut a = attr("+61 4");
        a.label = Some("personal mobile".into());
        s.put(a.clone(), None).await.unwrap();
        let p = new_profile(
            "Work",
            vec![
                ProfileEntry::Ref {
                    slot: None,
                    r#ref: a.attribute_id.clone(),
                },
                ProfileEntry::Override {
                    slot: None,
                    r#ref: a.attribute_id.clone(),
                    r#override: OverrideValue {
                        value: serde_json::json!("+61 9"),
                        label: Some("work line".into()),
                    },
                },
                ProfileEntry::Inline {
                    slot: None,
                    inline: InlineValue {
                        r#type: "x:handle".into(),
                        value_type: ValueType::String,
                        value: serde_json::json!("ada"),
                        label: Some("gaming".into()),
                        provenance: Provenance::SelfAsserted,
                    },
                },
            ],
        );
        s.put_profile(p.clone(), None).await.unwrap();
        let labels: Vec<_> = s
            .resolve_profile(&p.profile_id)
            .await
            .unwrap()
            .into_iter()
            .map(|c| c.label)
            .collect();
        assert_eq!(
            labels,
            vec![
                Some("personal mobile".to_string()),
                Some("work line".to_string()),
                Some("gaming".to_string()),
            ]
        );
    }

    #[tokio::test]
    async fn a_dangling_reference_refuses_the_whole_write() {
        let (_d, s) = fresh().await;
        let p = new_profile(
            "Work",
            vec![ProfileEntry::Ref {
                slot: None,
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
                slot: None,
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
                slot: None,
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
                slot: None,
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

    /// A pin to a version the store does not hold is refused when written:
    /// it would present nothing from that moment on.
    #[tokio::test]
    async fn a_pin_to_a_version_that_was_never_held_is_refused() {
        let (_d, s) = fresh().await;
        let a = attr("v1");
        let w = s.put(a.clone(), None).await.unwrap();
        let p = new_profile(
            "Work",
            vec![ProfileEntry::Pinned {
                slot: None,
                r#ref: a.attribute_id.clone(),
                pin_version: w.version + 99,
            }],
        );
        let err = s.put_profile(p.clone(), None).await.unwrap_err();
        assert!(matches!(err, AppError::Validation(_)), "got {err:?}");
        assert!(s.get_profile(&p.profile_id).await.unwrap().is_none());
    }

    async fn renamed(s: &PersonaStore) -> (crate::Attribute, Version, Profile, Profile) {
        // A name, a face that follows it, and a face — the bank — pinned to it.
        let mut a = new_attribute(
            "name.legal",
            ValueType::String,
            serde_json::json!("Ada Lovelace"),
            Provenance::SelfAsserted,
        );
        let v1 = s.put(a.clone(), None).await.unwrap().version;
        let live = new_profile(
            "Friends",
            vec![ProfileEntry::Ref {
                r#ref: a.attribute_id.clone(),
                slot: None,
            }],
        );
        let bank = new_profile(
            "Bank",
            vec![ProfileEntry::Pinned {
                r#ref: a.attribute_id.clone(),
                pin_version: v1,
                slot: None,
            }],
        );
        s.put_profile(live.clone(), None).await.unwrap();
        s.put_profile(bank.clone(), None).await.unwrap();
        a.value = Some(serde_json::json!("Ada King"));
        s.put(a.clone(), None).await.unwrap();
        (a, v1, live, bank)
    }

    /// The case pinning exists for: after a name change, the face that
    /// follows shows the new name and the pinned face keeps the old one.
    #[tokio::test]
    async fn a_pin_keeps_the_value_it_pinned_after_an_edit() {
        let (_d, s) = fresh().await;
        let (a, v1, live, bank) = renamed(&s).await;

        let now = s.resolve_profile(&live.profile_id).await.unwrap();
        assert_eq!(now[0].value, Some(serde_json::json!("Ada King")));
        let kept = s.resolve_profile(&bank.profile_id).await.unwrap();
        assert!(!kept[0].stale, "the pin was not honoured");
        assert_eq!(kept[0].value, Some(serde_json::json!("Ada Lovelace")));
        assert_eq!(kept[0].version, Some(v1));

        // And the holder can see that the old name is kept, and why.
        let listed = s
            .list_attributes(None, crate::ValueVisibility::Metadata)
            .await
            .unwrap()
            .attributes;
        let row = listed
            .iter()
            .find(|x| x.attribute_id == a.attribute_id)
            .unwrap();
        assert_eq!(row.retained_versions.len(), 1);
        assert_eq!(row.retained_versions[0].version, v1);
        assert_eq!(
            row.retained_versions[0].pinned_by,
            vec![bank.profile_id.clone()]
        );
    }

    /// Kept by reference: an edit nothing pins keeps nothing, and dropping the
    /// last pin drops the copy.
    #[tokio::test]
    async fn a_kept_version_lives_exactly_as_long_as_a_pin() {
        let (_d, s) = fresh().await;
        let mut plain = attr("+61 1");
        s.put(plain.clone(), None).await.unwrap();
        plain.value = Some(serde_json::json!("+61 2"));
        s.put(plain.clone(), None).await.unwrap();
        assert!(
            s.retained_versions(&plain.attribute_id)
                .await
                .unwrap()
                .is_empty()
        );

        let (a, _v1, _live, mut bank) = renamed(&s).await;
        assert_eq!(s.retained_versions(&a.attribute_id).await.unwrap().len(), 1);
        bank.entries = vec![ProfileEntry::Ref {
            r#ref: a.attribute_id.clone(),
            slot: None,
        }];
        s.put_profile(bank, None).await.unwrap();
        assert!(
            s.retained_versions(&a.attribute_id)
                .await
                .unwrap()
                .is_empty(),
            "a version no face pins was kept"
        );
    }

    /// The holder's override: purge the old name even though a face pins it.
    /// The face goes stale — it does not quietly start showing the new name to
    /// a counterparty the holder did not choose it for.
    #[tokio::test]
    async fn purging_a_kept_version_leaves_its_pins_stale() {
        let (_d, s) = fresh().await;
        let (a, v1, _live, bank) = renamed(&s).await;

        let current = s.get(&a.attribute_id).await.unwrap().unwrap().version;
        let err = s
            .purge_versions(&a.attribute_id, Some(&[current]))
            .await
            .unwrap_err();
        assert!(
            matches!(err, AppError::Conflict(_)),
            "the live value was purgeable"
        );

        let out = s.purge_versions(&a.attribute_id, None).await.unwrap();
        assert_eq!(out.purged, vec![v1]);
        assert_eq!(out.stale_pins.len(), 1);
        assert_eq!(out.stale_pins[0].profile_id, bank.profile_id);

        let claims = s.resolve_profile(&bank.profile_id).await.unwrap();
        assert!(claims[0].stale);
        assert_eq!(
            claims[0].value, None,
            "a purged pin fell back to another value"
        );
        // Converges.
        assert!(
            s.purge_versions(&a.attribute_id, None)
                .await
                .unwrap()
                .purged
                .is_empty()
        );
    }

    /// Deleting the attribute takes its kept versions with it.
    #[tokio::test]
    async fn deleting_an_attribute_drops_what_was_kept_for_it() {
        let (_d, s) = fresh().await;
        let (a, _v1, _live, _bank) = renamed(&s).await;
        s.delete(&a.attribute_id, true).await.unwrap();
        assert!(
            s.retained_versions(&a.attribute_id)
                .await
                .unwrap()
                .is_empty()
        );
    }

    /// A pinned old value is still a value this face shows, so the correlation
    /// guard must still see it after it stops being current.
    #[tokio::test]
    async fn a_kept_value_is_still_correlated() {
        let (_d, s) = fresh().await;
        let (_a, _v1, _live, bank) = renamed(&s).await;
        // Another face typing the old name.
        let other = new_profile(
            "Club",
            vec![ProfileEntry::Inline {
                slot: None,
                inline: InlineValue {
                    r#type: "name.display".into(),
                    value_type: ValueType::String,
                    value: serde_json::json!("Ada Lovelace"),
                    label: None,
                    provenance: Provenance::SelfAsserted,
                },
            }],
        );
        s.put_local_profile("ctx", other.clone(), None)
            .await
            .unwrap();
        let findings = s.analyze_correlation(None, None).await.unwrap();
        let named: std::collections::BTreeSet<_> = findings
            .iter()
            .flat_map(|f| f.shared_with.iter())
            .filter_map(|w| w.profile_id.clone())
            .collect();
        assert!(named.contains(&bank.profile_id), "{findings:?}");
        assert!(named.contains(&other.profile_id), "{findings:?}");
    }

    #[tokio::test]
    async fn inline_entries_resolve_without_the_pool_and_are_pool_free() {
        let (_d, s) = fresh().await;
        let entries = vec![ProfileEntry::Inline {
            slot: None,
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
        // than owns, so removing one destroys no attributes.
        let (_d, s) = fresh().await;
        let a = attr("keep me");
        s.put(a.clone(), None).await.unwrap();
        let p = new_profile(
            "Work",
            vec![ProfileEntry::Ref {
                slot: None,
                r#ref: a.attribute_id.clone(),
            }],
        );
        s.put_profile(p.clone(), None).await.unwrap();

        assert!(s.delete_profile(&p.profile_id).await.unwrap());
        assert!(
            s.get(&a.attribute_id).await.unwrap().is_some(),
            "the attribute survives"
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

// ─── Context-local profiles ──────────────────────────────────────────────
//
// A separate address space, not a flag on the pool's. A context-scoped
// enumeration therefore scans somewhere a pool profile structurally cannot be,
// rather than scanning everything and filtering — a filter is a line of code
// that can be got wrong, an address space cannot.

impl PersonaStore {
    /// Create or replace a context-local profile.
    ///
    /// Refuses any entry that references the pool. A local profile that could
    /// reference it would be a context-authored object acquiring pool reach,
    /// which is the escalation the boundary exists to prevent.
    pub async fn put_local_profile(
        &self,
        context_id: &str,
        mut profile: Profile,
        expected_version: Option<Version>,
    ) -> Result<Written, AppError> {
        refuse_duplicate_slot(&profile.entries)?;
        if !is_pool_free(&profile.entries) {
            return Err(AppError::Validation(
                "a context-local profile may carry inline entries only; a reference to the \
                 holder's pool is refused"
                    .into(),
            ));
        }

        let _guard = self.write_lock.lock().await;
        let key = storage::local_profile_key(context_id, &profile.profile_id);
        let existing = self.ks.get::<ProfileSlot>(key.clone()).await?;
        let current = match &existing {
            Some(ProfileSlot::Live(p)) => Some(p.version),
            _ => None,
        };
        check_precondition(expected_version, current)?;

        let version = self.next_version().await?;
        let created = current.is_none();
        profile.version = version;
        profile.updated_at = now_rfc3339();

        // Indexed above the boundary although the face lives below it — see
        // `storage::face_value_key`. A per-context index could not see the
        // same value typed into two contexts, and a throwaway identity is
        // exactly where somebody reuses a real one.
        let old_profile = match &existing {
            Some(ProfileSlot::Live(p)) => Some(p),
            _ => None,
        };
        self.reindex_face(
            Some(context_id),
            &profile.profile_id,
            old_profile,
            Some(&profile),
        )
        .await?;

        let profile_id = profile.profile_id.clone();
        self.ks.insert(key, &ProfileSlot::Live(profile)).await?;
        if created {
            let mut event = crate::FaceEvent::now(crate::FaceEventKind::Composed);
            event.context_id = Some(context_id.to_string());
            self.record_face_event(&profile_id, event).await;
        }
        Ok(Written { version, created })
    }

    pub async fn get_local_profile(
        &self,
        context_id: &str,
        profile_id: &str,
    ) -> Result<Option<Profile>, AppError> {
        Ok(
            match self
                .ks
                .get::<ProfileSlot>(storage::local_profile_key(context_id, profile_id))
                .await?
            {
                Some(ProfileSlot::Live(p)) => Some(p),
                _ => None,
            },
        )
    }

    pub async fn list_local_profiles(&self, context_id: &str) -> Result<Vec<Profile>, AppError> {
        let rows = self
            .ks
            .prefix_iter_raw(storage::local_profile_prefix(context_id).into_bytes())
            .await?;
        Ok(rows
            .into_iter()
            .filter_map(|(_k, v)| match serde_json::from_slice::<ProfileSlot>(&v) {
                Ok(ProfileSlot::Live(p)) => Some(p),
                _ => None,
            })
            .collect())
    }

    pub async fn delete_local_profile(
        &self,
        context_id: &str,
        profile_id: &str,
    ) -> Result<bool, AppError> {
        self.remove_local_profile(context_id, profile_id, true)
            .await
    }

    /// Remove a local face, forgetting its history only when `forget`.
    ///
    /// Promotion removes the local face without forgetting: the face lives on
    /// in the pool under the same id, and its history is its own.
    pub(crate) async fn remove_local_profile(
        &self,
        context_id: &str,
        profile_id: &str,
        forget: bool,
    ) -> Result<bool, AppError> {
        let _guard = self.write_lock.lock().await;
        let key = storage::local_profile_key(context_id, profile_id);
        let Some(ProfileSlot::Live(existing)) = self.ks.get::<ProfileSlot>(key.clone()).await?
        else {
            return Ok(false);
        };
        self.ks.remove(key).await?;
        self.reindex_face(Some(context_id), profile_id, Some(&existing), None)
            .await?;
        if forget {
            self.forget_face_events(profile_id).await?;
        }
        Ok(true)
    }

    /// Bind a **context-local** profile to a persona in the same context.
    ///
    /// Refuses a `profile_id` naming a POOL profile. That refusal is the whole
    /// distinction from `set_binding`: resolving the identifier against both
    /// address spaces would let a context-scoped caller bind the holder's
    /// composition and read it back through a disclosure it requests of itself
    /// — precisely the escalation `binding/set` is holder-authorized to prevent,
    /// reintroduced in the task that looks harmless.
    pub async fn set_local_binding(
        &self,
        context_id: &str,
        persona_did: &str,
        profile_id: Option<&str>,
        label: Option<String>,
        until: Option<String>,
    ) -> Result<Version, AppError> {
        if let Some(reason) = crate::binding::until_refusal(until.as_deref(), profile_id.is_some())
        {
            return Err(AppError::Validation(reason));
        }
        if let Some(id) = profile_id {
            match self.get_local_profile(context_id, id).await? {
                None => {
                    return Err(AppError::Validation(format!(
                        "{id} does not name a context-local profile; a pool profile cannot be \
                         bound here"
                    )));
                }
                Some(p) if !p.status.is_active() => {
                    return Err(AppError::Validation(format!(
                        "profile {id} is retired; reinstate it before wearing it"
                    )));
                }
                Some(_) => {}
            }
        }

        // Written as an ordinary binding record, in the ordinary binding
        // keyspace.
        //
        // It used to go to its own `plb:` prefix as a bare
        // `(profile_id, version)` tuple, and the consequences were worse than a
        // second address: `binding_summary` and `materialised_claims` both read
        // through `binding_record`, so a persona bound to a context-local
        // profile reported `bound: false` AND disclosed nothing. The whole
        // local family was unreachable end to end.
        //
        // Separate address spaces are the right guard for *profiles* — a
        // context-scoped scan must not reach a pool composition — but a binding
        // is context-scoped whichever kind it is, so a second space bought
        // nothing and cost both read paths. One space also makes "one binding
        // per (context, persona)" structural rather than something two rows
        // could disagree about.
        //
        // The claims are the profile's inline values themselves. A local entry
        // IS its value, so there is no pool to resolve against — which is also
        // why this cannot leak upward.
        let claims: Vec<crate::MaterialisedClaim> = match profile_id {
            None => Vec::new(),
            Some(id) => self
                .get_local_profile(context_id, id)
                .await?
                .map(|p| {
                    p.entries
                        .iter()
                        .filter_map(|e| match e {
                            ProfileEntry::Inline { inline, .. } => Some(crate::MaterialisedClaim {
                                r#type: inline.r#type.clone(),
                                value: Some(inline.value.clone()),
                                provenance: inline.provenance.clone(),
                                stale: false,
                                // A context-local profile is inline-only, so
                                // there is no pool attribute and no override to
                                // carry — the registry default answers.
                                release: None,
                            }),
                            // Unreachable: `put_local_profile` refuses anything
                            // else, and the schema cannot express it. Skipped
                            // rather than panicked, because a stored row that
                            // somehow held one must not take the process down.
                            _ => None,
                        })
                        .collect()
                })
                .unwrap_or_default(),
        };
        let profile_name = match profile_id {
            None => None,
            Some(id) => self
                .get_local_profile(context_id, id)
                .await?
                .map(|p| p.name.clone()),
        };

        let _guard = self.write_lock.lock().await;
        let before = self
            .binding_record(context_id, persona_did)
            .await?
            .and_then(|r| r.binding.profile_id);
        let version = self.next_version().await?;
        let record = crate::binding::BindingRecord {
            binding: crate::model::Binding {
                persona_did: persona_did.to_string(),
                profile_id: profile_id.map(str::to_string),
                public_entries: Vec::new(),
                version,
                bound_at: crate::store::now_rfc3339(),
                until: profile_id.and(until),
            },
            profile_name,
            label: profile_id.and(label),
            claims,
        };
        self.ks
            .insert(storage::binding_key(context_id, persona_did), &record)
            .await?;
        self.record_wearing(context_id, persona_did, before.as_deref(), profile_id)
            .await;
        Ok(version)
    }
}

#[cfg(test)]
mod local_tests {
    use super::*;
    use crate::model::{InlineValue, Provenance, ValueType};
    use vti_common::config::StoreConfig;
    use vti_common::store::Store;

    async fn fresh() -> (tempfile::TempDir, PersonaStore) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .unwrap();
        (
            dir,
            PersonaStore::new(store.keyspace(vta_keyspaces::PERSONA).unwrap(), [21u8; 32]),
        )
    }

    fn inline(v: &str) -> ProfileEntry {
        ProfileEntry::Inline {
            slot: None,
            inline: InlineValue {
                r#type: "x:handle".into(),
                value_type: ValueType::String,
                value: serde_json::json!(v),
                label: None,
                provenance: Provenance::SelfAsserted,
            },
        }
    }

    #[tokio::test]
    async fn a_reference_to_the_pool_is_refused() {
        let (_d, s) = fresh().await;
        let p = new_profile(
            "Throwaway",
            vec![ProfileEntry::Ref {
                slot: None,
                r#ref: "01ABC".into(),
            }],
        );
        let err = s.put_local_profile("ctx", p, None).await.unwrap_err();
        assert!(matches!(err, AppError::Validation(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn local_and_pool_profiles_do_not_see_each_other() {
        // The isolation is the address space. A context-scoped enumeration must
        // reach somewhere a pool profile cannot be.
        let (_d, s) = fresh().await;
        let pool = new_profile("Work", vec![]);
        s.put_profile(pool.clone(), None).await.unwrap();
        let local = new_profile("Throwaway", vec![inline("g")]);
        s.put_local_profile("ctx", local.clone(), None)
            .await
            .unwrap();

        assert_eq!(s.list_local_profiles("ctx").await.unwrap().len(), 1);
        assert_eq!(s.list_profiles().await.unwrap().len(), 1);
        assert!(
            s.get_local_profile("ctx", &pool.profile_id)
                .await
                .unwrap()
                .is_none()
        );
        assert!(s.get_profile(&local.profile_id).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn a_local_binding_refuses_a_pool_profile() {
        // The one refusal that keeps the local surface from becoming an
        // escalation path.
        let (_d, s) = fresh().await;
        let pool = new_profile("Work", vec![]);
        s.put_profile(pool.clone(), None).await.unwrap();

        let err = s
            .set_local_binding("ctx", "did:p", Some(&pool.profile_id), None, None)
            .await
            .unwrap_err();
        assert!(matches!(err, AppError::Validation(_)), "got {err:?}");

        let local = new_profile("Throwaway", vec![inline("g")]);
        s.put_local_profile("ctx", local.clone(), None)
            .await
            .unwrap();
        s.set_local_binding("ctx", "did:p", Some(&local.profile_id), None, None)
            .await
            .expect("a local profile binds");
    }

    #[tokio::test]
    async fn a_local_profile_is_confined_to_its_context() {
        let (_d, s) = fresh().await;
        let p = new_profile("Throwaway", vec![inline("g")]);
        s.put_local_profile("ctx-a", p.clone(), None).await.unwrap();
        assert!(
            s.get_local_profile("ctx-b", &p.profile_id)
                .await
                .unwrap()
                .is_none()
        );
        assert!(s.list_local_profiles("ctx-b").await.unwrap().is_empty());
    }
}
