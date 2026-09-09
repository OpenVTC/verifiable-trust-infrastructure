//! Facets — the holder's own arrangement of their own identity.
//!
//! A holder who uses this model for a while does not end up with three
//! profiles. They end up with twenty, and a flat list of twenty is a list
//! nobody reads. A facet is the arrangement over them: "Work", "Home", "Play".
//!
//! # An arrangement, not a container
//!
//! Nothing is stored *inside* a facet. It names profiles and attributes that
//! exist perfectly well without it, and deleting one deletes the name and the
//! statement about what belonged to it — nothing else. Every function here is
//! written so that no path can touch a profile or an attribute, and
//! [`PersonaStore::delete_facet`] has no cascading form on purpose: an
//! arrangement that could take its members with it is a folder, and a holder
//! who reads it as a folder is right to be afraid of it.
//!
//! # Why membership lives here and not on the records
//!
//! The obvious alternative is a `facet_id` on [`Attribute`](crate::Attribute).
//! It is the wrong shape for a mechanical reason: `persona/attribute/put`
//! **replaces** the attribute, and a well-behaved consumer does not hold the
//! values it would have to resend — `attribute/list` withholds the plaintext of
//! anything resolving to `sensitivity: high` unless it is asked for by name. So
//! such a consumer would either request every sensitive value the holder owns
//! in order to perform an arrangement that has nothing to do with values, or
//! send a put without one and silently destroy them.
//!
//! Membership on the facet has neither problem: one record is written, no value
//! is read, and the worst outcome of any error is an arrangement to redo.
//!
//! # Agent-scoped, and that is a control
//!
//! A facet states which of the holder's identities are, to them, parts of one
//! life — precisely the join that multiple personas exist to deny a verifier.
//! It is stored under [`storage::FACET_PREFIX`], which
//! [`storage::scope_of`] reports as [`Scope::Agent`](storage::Scope::Agent),
//! and nothing in this module reads or writes a context-scoped key.

use serde::{Deserialize, Serialize};

use crate::model::{Facet, FacetColour, Ulid, Version};
use crate::storage;
use crate::store::{PersonaStore, Written};
use vti_common::error::AppError;

/// A live facet or the grave of one, so a delete is distinguishable from a
/// record that never existed. Same shape as `ProfileSlot`, for the same reason:
/// the version counter is monotonic per store, and a tombstone keeps a deleted
/// id from being confused with an unused one.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) enum FacetSlot {
    Live(Facet),
    Tombstone {
        facet_id: Ulid,
        version: Version,
        deleted_at: String,
    },
}

/// Where a profile already sits, when a write tries to place it somewhere else.
///
/// Carries the facet holding it rather than only the fact of the clash, so a
/// consumer can offer to *move* the profile. Told only that the write failed,
/// the only thing a UI can do is ask the holder to go and find it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PlacedElsewhere {
    pub face_id: Ulid,
    pub facet_id: Ulid,
}

/// The outcome of checking a proposed membership against what is already
/// arranged.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FacetPlacement {
    /// Profiles this write would place that another facet already holds.
    pub placed: Vec<PlacedElsewhere>,
}

/// A new facet with a freshly minted id, at version 0 until it is written.
///
/// Minted here rather than at the dispatcher for the reason `new_profile` and
/// `new_attribute` are: the id format is this store's business — a ULID, so a
/// key-ordered scan is also creation-ordered — and a caller that formatted its
/// own would be free to choose one that scans out of order.
#[must_use]
pub fn new_facet(
    name: impl Into<String>,
    colour: FacetColour,
    icon: Option<String>,
    face_ids: Vec<Ulid>,
    attribute_ids: Vec<Ulid>,
) -> Facet {
    Facet {
        facet_id: ulid::Ulid::generate().to_string(),
        name: name.into(),
        colour,
        icon,
        face_ids,
        attribute_ids,
        version: 0,
        created_at: String::new(),
        updated_at: String::new(),
    }
}

impl PersonaStore {
    /// Create or replace one facet.
    ///
    /// Refuses, without writing, when a listed profile belongs to another facet
    /// or when any listed id names a record the holder does not hold. Both are
    /// checked **before** a version is taken, so a refused write consumes
    /// nothing from the counter.
    pub async fn put_facet(
        &self,
        mut facet: Facet,
        expected_version: Option<Version>,
    ) -> Result<Written, AppError> {
        let _guard = self.write_lock.lock().await;

        // Every id must name something the holder holds. An arrangement
        // referring to a record that never existed is a typo, and accepting it
        // silently makes the typo permanent.
        let mut dangling_faces = Vec::new();
        for id in &facet.face_ids {
            if self.get_profile(id).await?.is_none() {
                dangling_faces.push(id.clone());
            }
        }
        let mut dangling_attributes = Vec::new();
        for id in &facet.attribute_ids {
            if !matches!(self.slot(id).await?, Some(crate::store::Slot::Live(_))) {
                dangling_attributes.push(id.clone());
            }
        }
        if !dangling_faces.is_empty() || !dangling_attributes.is_empty() {
            return Err(AppError::Validation(format!(
                "facet references {} face(s) and {} attribute(s) that do not exist: {}",
                dangling_faces.len(),
                dangling_attributes.len(),
                dangling_faces
                    .iter()
                    .chain(dangling_attributes.iter())
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ")
            )));
        }

        // A profile belongs to at most one facet. Checked against every other
        // facet, excluding this one — a replace that keeps its own faces is not
        // a clash with itself, and treating it as one would make a facet
        // uneditable the moment it held anything.
        let clash = self
            .placement_conflicts(&facet.face_ids, Some(&facet.facet_id))
            .await?;
        if !clash.placed.is_empty() {
            return Err(AppError::Validation(format!(
                "{} face(s) already belong to another facet: {}",
                clash.placed.len(),
                clash
                    .placed
                    .iter()
                    .map(|p| format!("{} in {}", p.face_id, p.facet_id))
                    .collect::<Vec<_>>()
                    .join(", ")
            )));
        }

        let existing = self.facet_slot(&facet.facet_id).await?;
        let current_version = match &existing {
            Some(FacetSlot::Live(f)) => Some(f.version),
            _ => None,
        };
        crate::store::check_precondition(expected_version, current_version)?;

        let version = self.next_version().await?;
        let created = current_version.is_none();
        facet.version = version;
        facet.updated_at = crate::store::now_rfc3339();
        if created {
            facet.created_at = facet.updated_at.clone();
        } else if let Some(FacetSlot::Live(old)) = &existing {
            facet.created_at = old.created_at.clone();
        }

        self.ks
            .insert(storage::facet_key(&facet.facet_id), &FacetSlot::Live(facet))
            .await?;

        Ok(Written { version, created })
    }

    /// Every facet, creation-ordered by the key scan.
    ///
    /// Dangling membership is returned rather than pruned. A member whose
    /// record has since been deleted is how a consumer can offer to tidy;
    /// dropping it here would turn a deletion the holder may not have intended
    /// into one they can never see.
    pub async fn list_facets(&self) -> Result<Vec<Facet>, AppError> {
        let rows = self
            .ks
            .prefix_iter_raw(storage::FACET_PREFIX.as_bytes().to_vec())
            .await?;
        let mut out = Vec::new();
        for (_k, v) in rows {
            if let Ok(FacetSlot::Live(f)) = serde_json::from_slice::<FacetSlot>(&v) {
                out.push(f);
            }
        }
        Ok(out)
    }

    pub async fn get_facet(&self, facet_id: &str) -> Result<Option<Facet>, AppError> {
        Ok(match self.facet_slot(facet_id).await? {
            Some(FacetSlot::Live(f)) => Some(f),
            _ => None,
        })
    }

    /// Delete one facet.
    ///
    /// **Touches no profile and no attribute**, and there is deliberately no
    /// cascading variant. Returns how many profiles now belong to no facet at
    /// all, which is what a consumer needs in order to say what the screen will
    /// look like afterwards.
    pub async fn delete_facet(
        &self,
        facet_id: &str,
        expected_version: Option<Version>,
    ) -> Result<(bool, usize), AppError> {
        let _guard = self.write_lock.lock().await;

        let existing = self.facet_slot(facet_id).await?;
        let live = match &existing {
            Some(FacetSlot::Live(f)) => Some(f.clone()),
            _ => None,
        };
        crate::store::check_precondition(expected_version, live.as_ref().map(|f| f.version))?;

        let Some(facet) = live else {
            // A successful no-op. A producer retrying after a lost response has
            // to be able to reach the state it wanted without having to tell a
            // second delete apart from a first.
            return Ok((false, 0));
        };

        let released = facet.face_ids.len();
        let version = self.next_version().await?;
        self.ks
            .insert(
                storage::facet_key(facet_id),
                &FacetSlot::Tombstone {
                    facet_id: facet_id.to_string(),
                    version,
                    deleted_at: crate::store::now_rfc3339(),
                },
            )
            .await?;

        Ok((true, released))
    }

    /// Which of `face_ids` another facet already holds.
    ///
    /// `excluding` is the facet being written, so a replace does not clash with
    /// its own membership.
    pub async fn placement_conflicts(
        &self,
        face_ids: &[Ulid],
        excluding: Option<&str>,
    ) -> Result<FacetPlacement, AppError> {
        if face_ids.is_empty() {
            return Ok(FacetPlacement::default());
        }
        let mut placed = Vec::new();
        for other in self.list_facets().await? {
            if excluding == Some(other.facet_id.as_str()) {
                continue;
            }
            for id in face_ids {
                if other.face_ids.contains(id) {
                    placed.push(PlacedElsewhere {
                        face_id: id.clone(),
                        facet_id: other.facet_id.clone(),
                    });
                }
            }
        }
        Ok(FacetPlacement { placed })
    }

    pub(crate) async fn facet_slot(&self, facet_id: &str) -> Result<Option<FacetSlot>, AppError> {
        self.ks.get(storage::facet_key(facet_id)).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{FacetColour, Provenance, ValueType};
    use crate::store::new_attribute;
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
            PersonaStore::new(store.keyspace(vta_keyspaces::PERSONA).unwrap(), [9u8; 32]),
        )
    }

    fn facet(name: &str, faces: Vec<Ulid>, attributes: Vec<Ulid>) -> Facet {
        Facet {
            facet_id: format!("01J8XR3QK9V00000000000{:04}", name.len()),
            name: name.to_string(),
            colour: FacetColour::Teal,
            icon: None,
            face_ids: faces,
            attribute_ids: attributes,
            version: 0,
            created_at: String::new(),
            updated_at: String::new(),
        }
    }

    async fn a_profile(s: &PersonaStore, name: &str) -> Ulid {
        let p = crate::profile::new_profile(name, vec![]);
        let id = p.profile_id.clone();
        s.put_profile(p, None).await.unwrap();
        id
    }

    async fn an_attribute(s: &PersonaStore) -> Ulid {
        let a = new_attribute(
            "phone.mobile",
            ValueType::String,
            serde_json::json!("+61 400 000 000"),
            Provenance::SelfAsserted,
        );
        let id = a.attribute_id.clone();
        s.put(a, None).await.unwrap();
        id
    }

    #[tokio::test]
    async fn a_facet_round_trips_with_its_membership() {
        let (_d, s) = fresh().await;
        let face = a_profile(&s, "Acme").await;
        let attr = an_attribute(&s).await;

        let written = s
            .put_facet(
                facet("Work", vec![face.clone()], vec![attr.clone()]),
                Some(0),
            )
            .await
            .unwrap();
        assert!(written.created);

        let listed = s.list_facets().await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].name, "Work");
        assert_eq!(listed[0].face_ids, vec![face]);
        assert_eq!(listed[0].attribute_ids, vec![attr]);
    }

    /// The property the whole design turns on: a facet is an arrangement, not a
    /// container. Deleting one must leave every record it named untouched.
    #[tokio::test]
    async fn deleting_a_facet_deletes_nothing_it_named() {
        let (_d, s) = fresh().await;
        let face = a_profile(&s, "Acme").await;
        let attr = an_attribute(&s).await;
        let f = facet("Work", vec![face.clone()], vec![attr.clone()]);
        let facet_id = f.facet_id.clone();
        s.put_facet(f, Some(0)).await.unwrap();

        let (existed, released) = s.delete_facet(&facet_id, None).await.unwrap();
        assert!(existed);
        assert_eq!(
            released, 1,
            "the released-face count is what the screen reads"
        );

        assert!(
            s.get_profile(&face).await.unwrap().is_some(),
            "deleting a facet deleted a profile it merely named"
        );
        assert!(
            s.get(&attr).await.unwrap().is_some(),
            "deleting a facet deleted an attribute it merely named"
        );
        assert!(s.list_facets().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn deleting_what_is_not_there_is_a_successful_no_op() {
        // A producer retrying after a lost response must reach the state it
        // wanted without having to tell a second delete apart from a first.
        let (_d, s) = fresh().await;
        let (existed, released) = s
            .delete_facet("01J8XR3QK9V0000000000000ZZ", None)
            .await
            .unwrap();
        assert!(!existed);
        assert_eq!(released, 0);
    }

    #[tokio::test]
    async fn a_face_belongs_to_at_most_one_facet() {
        let (_d, s) = fresh().await;
        let face = a_profile(&s, "Acme").await;
        s.put_facet(facet("Work", vec![face.clone()], vec![]), Some(0))
            .await
            .unwrap();

        let err = s
            .put_facet(facet("Home!", vec![face.clone()], vec![]), Some(0))
            .await
            .expect_err("a face was placed in two facets");
        assert!(format!("{err}").contains("already belong"), "{err}");

        // And the refusal names where it already is, so a consumer can offer to
        // move it rather than sending the holder to look for it.
        let clash = s.placement_conflicts(&[face], None).await.unwrap();
        assert_eq!(clash.placed.len(), 1);
        assert_eq!(
            clash.placed[0].facet_id,
            facet("Work", vec![], vec![]).facet_id
        );
    }

    #[tokio::test]
    async fn an_attribute_may_belong_to_several() {
        // A mobile number is genuinely part of both a working life and a home
        // one; a model that made the holder choose would be asking a question
        // about their phone that has no answer.
        let (_d, s) = fresh().await;
        let attr = an_attribute(&s).await;
        s.put_facet(facet("Work", vec![], vec![attr.clone()]), Some(0))
            .await
            .unwrap();
        s.put_facet(facet("Home!", vec![], vec![attr]), Some(0))
            .await
            .expect("an attribute was refused a second facet");
    }

    #[tokio::test]
    async fn a_replace_does_not_clash_with_its_own_faces() {
        // Excluding the facet being written is what keeps it editable: without
        // it, a facet becomes uneditable the moment it holds anything.
        let (_d, s) = fresh().await;
        let face = a_profile(&s, "Acme").await;
        let first = facet("Work", vec![face.clone()], vec![]);
        let id = first.facet_id.clone();
        let v = s.put_facet(first, Some(0)).await.unwrap().version;

        let mut again = facet("Work", vec![face], vec![]);
        again.facet_id = id;
        again.name = "Work life".into();
        let written = s
            .put_facet(again, Some(v))
            .await
            .expect("a replace clashed with itself");
        assert!(!written.created);
    }

    #[tokio::test]
    async fn a_dangling_reference_refuses_the_write() {
        let (_d, s) = fresh().await;
        let err = s
            .put_facet(
                facet("Work", vec!["01J8XR3QK9V0000000000000AA".into()], vec![]),
                Some(0),
            )
            .await
            .expect_err("a facet named a profile that does not exist");
        assert!(format!("{err}").contains("do not exist"), "{err}");
        assert!(
            s.list_facets().await.unwrap().is_empty(),
            "a refused write left a facet behind"
        );
    }

    #[tokio::test]
    async fn a_refused_write_consumes_no_version() {
        // Validation runs before a version is taken, so a rejected document
        // does not advance the store's change-feed watermark.
        let (_d, s) = fresh().await;
        let before = s.next_version().await.unwrap();
        let _ = s
            .put_facet(
                facet("Work", vec!["01J8XR3QK9V0000000000000AA".into()], vec![]),
                Some(0),
            )
            .await;
        let after = s.next_version().await.unwrap();
        assert_eq!(after, before + 1, "a refused write consumed a version");
    }

    #[tokio::test]
    async fn membership_naming_a_deleted_record_is_returned_not_pruned() {
        // A dangling member is how a consumer offers to tidy. Dropping it here
        // turns a deletion the holder may not have intended into one they can
        // never see.
        let (_d, s) = fresh().await;
        let face = a_profile(&s, "Acme").await;
        s.put_facet(facet("Work", vec![face.clone()], vec![]), Some(0))
            .await
            .unwrap();
        s.delete_profile(&face).await.unwrap();

        let listed = s.list_facets().await.unwrap();
        assert_eq!(
            listed[0].face_ids,
            vec![face],
            "a dangling member was silently pruned"
        );
    }

    #[tokio::test]
    async fn a_facet_is_agent_scoped() {
        // The security property, asserted on the key rather than the type.
        assert_eq!(
            storage::scope_of(&storage::facet_key("01J8")),
            Some(storage::Scope::Agent)
        );
    }
}
