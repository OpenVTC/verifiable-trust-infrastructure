//! Earlier versions of an attribute, kept while — and only while — a face pins
//! them.
//!
//! A pin (`{ref, pinVersion}`) exists for the counterparty who verified a value
//! and must keep being shown it: after a name change, the bank that has not been
//! told yet. Honouring one means keeping the value the edit replaced, and the
//! store used not to: a pin to anything but the current version resolved stale,
//! so pinning worked only until the first edit — which is to say never, since an
//! edit is the only reason to pin.
//!
//! # Retained by reference, not by timer
//!
//! A replaced version is kept exactly as long as some face pins it, and reaped
//! the moment none does — the rule `ContactRevision::cited` already follows on
//! the other side of this store. A timer would keep a value nobody asks for, or
//! drop one somebody does; a reference count does neither.
//!
//! # And the holder can remove one anyway
//!
//! [`PersonaStore::purge_versions`] is the override: a deadname kept for the
//! one face that still pins it is kept against the holder's wishes. Purging does
//! not fall back to the current value — a pin exists so a counterparty is *not*
//! shown a value the holder did not choose for them — so the faces that pinned
//! it present that entry as stale, and are named.
//!
//! # The correlation index sees a retained value
//!
//! A face pinning a retained version presents a value no attribute holds any
//! more. [`PersonaStore::face_blinds`] counts it among what the face carries,
//! so the guard does not lose sight of an old name the moment it stops being
//! current.

use std::collections::BTreeSet;

use vti_common::error::AppError;

use crate::binding::HeldByPin;
use crate::correlation;
use crate::model::{Attribute, ProfileEntry, RetainedVersion, Ulid, Version};
use crate::storage;
use crate::store::{PersonaStore, Slot};

/// What a purge removed, and which faces it left presenting nothing.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Purged {
    pub purged: Vec<Version>,
    pub stale_pins: Vec<HeldByPin>,
}

impl PersonaStore {
    /// One retained version, if the store holds it.
    pub(crate) async fn retained(
        &self,
        attribute_id: &str,
        version: Version,
    ) -> Result<Option<Attribute>, AppError> {
        self.ks
            .get::<Attribute>(storage::retained_key(attribute_id, version))
            .await
    }

    /// The value a pin presents when it is **not** the attribute's current
    /// version — `None` when the pin is current (the attribute index holds that
    /// value) or when the version is not held at all (the pin is stale).
    pub(crate) async fn pinned_retained_value(
        &self,
        attribute_id: &str,
        version: Version,
    ) -> Result<Option<serde_json::Value>, AppError> {
        if let Some(Slot::Live(a)) = self.slot(attribute_id).await?
            && a.version == version
        {
            return Ok(None);
        }
        Ok(self
            .retained(attribute_id, version)
            .await?
            .and_then(|a| a.value))
    }

    /// Every (face, version) pinning one attribute.
    pub(crate) async fn pins_of(
        &self,
        attribute_id: &str,
    ) -> Result<Vec<(Ulid, Version)>, AppError> {
        let mut out = Vec::new();
        for profile_id in self.referring_profiles(attribute_id).await? {
            let Some(face) = self.get_profile(&profile_id).await? else {
                continue;
            };
            for entry in &face.entries {
                if let ProfileEntry::Pinned {
                    r#ref, pin_version, ..
                } = entry
                    && r#ref == attribute_id
                {
                    out.push((profile_id.clone(), *pin_version));
                }
            }
        }
        Ok(out)
    }

    /// The retained versions of one attribute and the faces pinning each, in
    /// version order — what `Attribute::retained_versions` reports.
    pub async fn retained_versions(
        &self,
        attribute_id: &str,
    ) -> Result<Vec<RetainedVersion>, AppError> {
        let rows = self
            .ks
            .prefix_iter_raw(storage::retained_prefix(attribute_id).into_bytes())
            .await?;
        if rows.is_empty() {
            return Ok(Vec::new());
        }
        let pins = self.pins_of(attribute_id).await?;
        Ok(rows
            .into_iter()
            .filter_map(|(_k, v)| serde_json::from_slice::<Attribute>(&v).ok())
            .map(|a| RetainedVersion {
                version: a.version,
                updated_at: a.updated_at,
                pinned_by: pins
                    .iter()
                    .filter(|(_, v)| *v == a.version)
                    .map(|(p, _)| p.clone())
                    .collect(),
            })
            .collect())
    }

    /// Keep `old` if a face pins it, because an edit is about to replace it.
    /// **Caller must hold `write_lock`**, and call this before the new record
    /// is written.
    ///
    /// The pinning faces gain a correlation edge for the value here rather than
    /// through a later reindex, so a crash after this and before the new record
    /// lands leaves an edge that over-warns rather than a value the guard
    /// cannot see.
    pub(crate) async fn retain_if_pinned(&self, old: &Attribute) -> Result<(), AppError> {
        let pinning: Vec<Ulid> = self
            .pins_of(&old.attribute_id)
            .await?
            .into_iter()
            .filter(|(_, v)| *v == old.version)
            .map(|(p, _)| p)
            .collect();
        if pinning.is_empty() {
            return Ok(());
        }
        let mut kept = old.clone();
        kept.retained_versions.clear();
        self.ks
            .insert(storage::retained_key(&old.attribute_id, old.version), &kept)
            .await?;
        if let Some(v) = &old.value {
            let added: BTreeSet<String> = [correlation::blind(&self.correlation_key, v)].into();
            for profile_id in pinning {
                self.apply_face_edges(None, &profile_id, &BTreeSet::new(), &added)
                    .await?;
            }
        }
        Ok(())
    }

    /// Drop every retained version of `attribute_id` that no face pins any
    /// more. **Caller must hold `write_lock`.**
    ///
    /// Run after any write that can remove a pin. The faces' correlation edges
    /// for those values were already removed by that write's own reindex — a
    /// face that stopped pinning stopped presenting the value — so there is
    /// nothing left to unindex.
    pub(crate) async fn reap_unpinned(&self, attribute_id: &str) -> Result<(), AppError> {
        let keys = self
            .ks
            .prefix_keys(storage::retained_prefix(attribute_id).into_bytes())
            .await?;
        if keys.is_empty() {
            return Ok(());
        }
        let pinned: BTreeSet<Version> = self
            .pins_of(attribute_id)
            .await?
            .into_iter()
            .map(|(_, v)| v)
            .collect();
        for key in keys {
            let Some(version) = String::from_utf8(key.clone())
                .ok()
                .and_then(|k| k.rsplit(':').next().and_then(|v| v.parse::<Version>().ok()))
            else {
                continue;
            };
            if !pinned.contains(&version) {
                self.ks.remove(key).await?;
            }
        }
        Ok(())
    }

    /// Remove retained versions and move the affected faces' edges, returning
    /// which faces pinned what was removed. **Caller must hold `write_lock`.**
    async fn remove_retained(
        &self,
        attribute_id: &str,
        versions: &BTreeSet<Version>,
    ) -> Result<Vec<HeldByPin>, AppError> {
        let stale: Vec<HeldByPin> = self
            .pins_of(attribute_id)
            .await?
            .into_iter()
            .filter(|(_, v)| versions.contains(v))
            .map(|(profile_id, pin_version)| HeldByPin {
                profile_id,
                pin_version,
            })
            .collect();
        let faces: BTreeSet<Ulid> = stale.iter().map(|h| h.profile_id.clone()).collect();

        let mut before = Vec::with_capacity(faces.len());
        for id in &faces {
            let face = self.get_profile(id).await?;
            before.push((
                id.clone(),
                face.clone(),
                self.face_blinds(face.as_ref()).await?,
            ));
        }
        for v in versions {
            self.ks
                .remove(storage::retained_key(attribute_id, *v))
                .await?;
        }
        for (id, face, was) in before {
            let now = self.face_blinds(face.as_ref()).await?;
            self.apply_face_edges(None, &id, &was, &now).await?;
        }
        Ok(stale)
    }

    /// Every retained version of an attribute being deleted. **Caller must hold
    /// `write_lock`.** A delete that left recoverable copies behind would be a
    /// delete in name only.
    pub(crate) async fn drop_all_retained(&self, attribute_id: &str) -> Result<(), AppError> {
        let held: BTreeSet<Version> = self
            .retained_versions(attribute_id)
            .await?
            .into_iter()
            .map(|r| r.version)
            .collect();
        if !held.is_empty() {
            self.remove_retained(attribute_id, &held).await?;
        }
        Ok(())
    }

    /// The holder's override on retention: remove retained versions of one
    /// attribute — `versions`, or all of them — for good.
    ///
    /// Refuses the current version: that is `delete`, and a purge able to take
    /// the live value would make tidying up old names able to erase the present
    /// one. A version that is not held is nothing to do, so a repeated purge
    /// converges. Every face that pinned a removed version is re-pushed, so the
    /// contexts wearing it stop presenting the value too.
    pub async fn purge_versions(
        &self,
        attribute_id: &str,
        versions: Option<&[Version]>,
    ) -> Result<Purged, AppError> {
        let _guard = self.write_lock.lock().await;
        if let (Some(asked), Some(Slot::Live(a))) = (versions, self.slot(attribute_id).await?)
            && asked.contains(&a.version)
        {
            return Err(AppError::Conflict(format!(
                "version {} is the current value of {attribute_id}; remove it with \
                 persona/attribute/delete",
                a.version
            )));
        }
        let held: BTreeSet<Version> = self
            .retained_versions(attribute_id)
            .await?
            .into_iter()
            .map(|r| r.version)
            .collect();
        let targets: BTreeSet<Version> = match versions {
            Some(asked) => asked.iter().copied().filter(|v| held.contains(v)).collect(),
            None => held,
        };
        if targets.is_empty() {
            return Ok(Purged::default());
        }
        let stale_pins = self.remove_retained(attribute_id, &targets).await?;
        let faces: BTreeSet<&str> = stale_pins.iter().map(|h| h.profile_id.as_str()).collect();
        for face in faces {
            self.push_profile_locked(face).await?;
        }
        Ok(Purged {
            purged: targets.into_iter().collect(),
            stale_pins,
        })
    }

    /// Pins in `entries` naming a version the store neither holds as current
    /// nor retains — `(attribute, version)` pairs. Such a pin presents nothing
    /// from the moment it is written, so a face carrying one is refused.
    pub async fn unavailable_pins(
        &self,
        entries: &[ProfileEntry],
    ) -> Result<Vec<(Ulid, Version)>, AppError> {
        let mut out = Vec::new();
        for entry in entries {
            if let ProfileEntry::Pinned {
                r#ref, pin_version, ..
            } = entry
            {
                let current = matches!(self.slot(r#ref).await?, Some(Slot::Live(a)) if a.version == *pin_version);
                if !current && self.retained(r#ref, *pin_version).await?.is_none() {
                    out.push((r#ref.clone(), *pin_version));
                }
            }
        }
        Ok(out)
    }
}
