//! Worlds — the holder's own arrangement of their own identity.
//!
//! A holder who uses this model for a while does not end up with three
//! profiles. They end up with twenty, and a flat list of twenty is a list
//! nobody reads. A world is the arrangement over them: "Work", "Home", "Play".
//!
//! # An arrangement, not a container
//!
//! Nothing is stored *inside* a world. It names profiles and attributes that
//! exist perfectly well without it, and deleting one deletes the name and the
//! statement about what belonged to it — nothing else. Every function here is
//! written so that no path can touch a profile or an attribute, and
//! [`PersonaStore::delete_world`] has no cascading form on purpose: an
//! arrangement that could take its members with it is a folder, and a holder
//! who reads it as a folder is right to be afraid of it.
//!
//! # Why membership lives here and not on the records
//!
//! The obvious alternative is a `world_id` on [`Attribute`](crate::Attribute).
//! It is the wrong shape for a mechanical reason: `persona/attribute/put`
//! **replaces** the attribute, and a well-behaved consumer does not hold the
//! values it would have to resend — `attribute/list` withholds the plaintext of
//! anything resolving to `sensitivity: high` unless it is asked for by name. So
//! such a consumer would either request every sensitive value the holder owns
//! in order to perform an arrangement that has nothing to do with values, or
//! send a put without one and silently destroy them.
//!
//! Membership on the world has neither problem: one record is written, no value
//! is read, and the worst outcome of any error is an arrangement to redo.
//!
//! # Agent-scoped, and that is a control
//!
//! A world states which of the holder's identities are, to them, parts of one
//! life — precisely the join that multiple personas exist to deny a verifier.
//! It is stored under [`storage::WORLD_PREFIX`], which
//! [`storage::scope_of`] reports as [`Scope::Agent`](storage::Scope::Agent),
//! and nothing in this module reads or writes a context-scoped key.

use serde::{Deserialize, Serialize};

use crate::model::{Ulid, Version, World, WorldColour};
use crate::storage;
use crate::store::{PersonaStore, Written};
use vti_common::error::AppError;

/// A live world or the grave of one, so a delete is distinguishable from a
/// record that never existed. Same shape as `ProfileSlot`, for the same reason:
/// the version counter is monotonic per store, and a tombstone keeps a deleted
/// id from being confused with an unused one.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) enum WorldSlot {
    Live(World),
    Tombstone {
        world_id: Ulid,
        version: Version,
        deleted_at: String,
    },
}

/// Where a profile already sits, when a write tries to place it somewhere else.
///
/// Carries the world holding it rather than only the fact of the clash, so a
/// consumer can offer to *move* the profile. Told only that the write failed,
/// the only thing a UI can do is ask the holder to go and find it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PlacedElsewhere {
    pub face_id: Ulid,
    pub world_id: Ulid,
}

/// The outcome of checking a proposed membership against what is already
/// arranged.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WorldPlacement {
    /// Profiles this write would place that another world already holds.
    pub placed: Vec<PlacedElsewhere>,
}

/// A new world with a freshly minted id, at version 0 until it is written.
///
/// Minted here rather than at the dispatcher for the reason `new_profile` and
/// `new_attribute` are: the id format is this store's business — a ULID, so a
/// key-ordered scan is also creation-ordered — and a caller that formatted its
/// own would be free to choose one that scans out of order.
#[must_use]
pub fn new_world(
    name: impl Into<String>,
    colour: WorldColour,
    icon: Option<String>,
    face_ids: Vec<Ulid>,
    attribute_ids: Vec<Ulid>,
) -> World {
    World {
        world_id: ulid::Ulid::generate().to_string(),
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
    /// Create or replace one world.
    ///
    /// Refuses, without writing, when a listed profile belongs to another world
    /// or when any listed id names a record the holder does not hold. Both are
    /// checked **before** a version is taken, so a refused write consumes
    /// nothing from the counter.
    pub async fn put_world(
        &self,
        mut world: World,
        expected_version: Option<Version>,
    ) -> Result<Written, AppError> {
        let _guard = self.write_lock.lock().await;

        // Every id must name something the holder holds. An arrangement
        // referring to a record that never existed is a typo, and accepting it
        // silently makes the typo permanent.
        let mut dangling_faces = Vec::new();
        for id in &world.face_ids {
            if self.get_profile(id).await?.is_none() {
                dangling_faces.push(id.clone());
            }
        }
        let mut dangling_attributes = Vec::new();
        for id in &world.attribute_ids {
            if !matches!(self.slot(id).await?, Some(crate::store::Slot::Live(_))) {
                dangling_attributes.push(id.clone());
            }
        }
        if !dangling_faces.is_empty() || !dangling_attributes.is_empty() {
            return Err(AppError::Validation(format!(
                "world references {} face(s) and {} attribute(s) that do not exist: {}",
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

        // A profile belongs to at most one world. Checked against every other
        // world, excluding this one — a replace that keeps its own faces is not
        // a clash with itself, and treating it as one would make a world
        // uneditable the moment it held anything.
        let clash = self
            .placement_conflicts(&world.face_ids, Some(&world.world_id))
            .await?;
        if !clash.placed.is_empty() {
            return Err(AppError::Validation(format!(
                "{} face(s) already belong to another world: {}",
                clash.placed.len(),
                clash
                    .placed
                    .iter()
                    .map(|p| format!("{} in {}", p.face_id, p.world_id))
                    .collect::<Vec<_>>()
                    .join(", ")
            )));
        }

        let existing = self.world_slot(&world.world_id).await?;
        let current_version = match &existing {
            Some(WorldSlot::Live(f)) => Some(f.version),
            _ => None,
        };
        crate::store::check_precondition(expected_version, current_version)?;

        let version = self.next_version().await?;
        let created = current_version.is_none();
        world.version = version;
        world.updated_at = crate::store::now_rfc3339();
        if created {
            world.created_at = world.updated_at.clone();
        } else if let Some(WorldSlot::Live(old)) = &existing {
            world.created_at = old.created_at.clone();
        }

        self.ks
            .insert(storage::world_key(&world.world_id), &WorldSlot::Live(world))
            .await?;

        Ok(Written { version, created })
    }

    /// Every world, creation-ordered by the key scan.
    ///
    /// Dangling membership is returned rather than pruned. A member whose
    /// record has since been deleted is how a consumer can offer to tidy;
    /// dropping it here would turn a deletion the holder may not have intended
    /// into one they can never see.
    pub async fn list_worlds(&self) -> Result<Vec<World>, AppError> {
        let rows = self
            .ks
            .prefix_iter_raw(storage::WORLD_PREFIX.as_bytes().to_vec())
            .await?;
        let mut out = Vec::new();
        for (_k, v) in rows {
            if let Ok(WorldSlot::Live(f)) = serde_json::from_slice::<WorldSlot>(&v) {
                out.push(f);
            }
        }
        Ok(out)
    }

    pub async fn get_world(&self, world_id: &str) -> Result<Option<World>, AppError> {
        Ok(match self.world_slot(world_id).await? {
            Some(WorldSlot::Live(f)) => Some(f),
            _ => None,
        })
    }

    /// Delete one world.
    ///
    /// **Touches no profile and no attribute**, and there is deliberately no
    /// cascading variant. Returns how many profiles now belong to no world at
    /// all, which is what a consumer needs in order to say what the screen will
    /// look like afterwards.
    pub async fn delete_world(
        &self,
        world_id: &str,
        expected_version: Option<Version>,
    ) -> Result<(bool, usize), AppError> {
        let _guard = self.write_lock.lock().await;

        let existing = self.world_slot(world_id).await?;
        let live = match &existing {
            Some(WorldSlot::Live(f)) => Some(f.clone()),
            _ => None,
        };
        crate::store::check_precondition(expected_version, live.as_ref().map(|f| f.version))?;

        let Some(world) = live else {
            // A successful no-op. A producer retrying after a lost response has
            // to be able to reach the state it wanted without having to tell a
            // second delete apart from a first.
            return Ok((false, 0));
        };

        let released = world.face_ids.len();
        let version = self.next_version().await?;
        self.ks
            .insert(
                storage::world_key(world_id),
                &WorldSlot::Tombstone {
                    world_id: world_id.to_string(),
                    version,
                    deleted_at: crate::store::now_rfc3339(),
                },
            )
            .await?;

        Ok((true, released))
    }

    /// Which of `face_ids` another world already holds.
    ///
    /// `excluding` is the world being written, so a replace does not clash with
    /// its own membership.
    pub async fn placement_conflicts(
        &self,
        face_ids: &[Ulid],
        excluding: Option<&str>,
    ) -> Result<WorldPlacement, AppError> {
        if face_ids.is_empty() {
            return Ok(WorldPlacement::default());
        }
        let mut placed = Vec::new();
        for other in self.list_worlds().await? {
            if excluding == Some(other.world_id.as_str()) {
                continue;
            }
            for id in face_ids {
                if other.face_ids.contains(id) {
                    placed.push(PlacedElsewhere {
                        face_id: id.clone(),
                        world_id: other.world_id.clone(),
                    });
                }
            }
        }
        Ok(WorldPlacement { placed })
    }

    pub(crate) async fn world_slot(&self, world_id: &str) -> Result<Option<WorldSlot>, AppError> {
        self.ks.get(storage::world_key(world_id)).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Provenance, ValueType, WorldColour};
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

    fn world(name: &str, faces: Vec<Ulid>, attributes: Vec<Ulid>) -> World {
        World {
            world_id: format!("01J8XR3QK9V00000000000{:04}", name.len()),
            name: name.to_string(),
            colour: WorldColour::Teal,
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
    async fn a_world_round_trips_with_its_membership() {
        let (_d, s) = fresh().await;
        let face = a_profile(&s, "Acme").await;
        let attr = an_attribute(&s).await;

        let written = s
            .put_world(
                world("Work", vec![face.clone()], vec![attr.clone()]),
                Some(0),
            )
            .await
            .unwrap();
        assert!(written.created);

        let listed = s.list_worlds().await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].name, "Work");
        assert_eq!(listed[0].face_ids, vec![face]);
        assert_eq!(listed[0].attribute_ids, vec![attr]);
    }

    /// The property the whole design turns on: a world is an arrangement, not a
    /// container. Deleting one must leave every record it named untouched.
    #[tokio::test]
    async fn deleting_a_world_deletes_nothing_it_named() {
        let (_d, s) = fresh().await;
        let face = a_profile(&s, "Acme").await;
        let attr = an_attribute(&s).await;
        let f = world("Work", vec![face.clone()], vec![attr.clone()]);
        let world_id = f.world_id.clone();
        s.put_world(f, Some(0)).await.unwrap();

        let (existed, released) = s.delete_world(&world_id, None).await.unwrap();
        assert!(existed);
        assert_eq!(
            released, 1,
            "the released-face count is what the screen reads"
        );

        assert!(
            s.get_profile(&face).await.unwrap().is_some(),
            "deleting a world deleted a profile it merely named"
        );
        assert!(
            s.get(&attr).await.unwrap().is_some(),
            "deleting a world deleted an attribute it merely named"
        );
        assert!(s.list_worlds().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn deleting_what_is_not_there_is_a_successful_no_op() {
        // A producer retrying after a lost response must reach the state it
        // wanted without having to tell a second delete apart from a first.
        let (_d, s) = fresh().await;
        let (existed, released) = s
            .delete_world("01J8XR3QK9V0000000000000ZZ", None)
            .await
            .unwrap();
        assert!(!existed);
        assert_eq!(released, 0);
    }

    #[tokio::test]
    async fn a_face_belongs_to_at_most_one_world() {
        let (_d, s) = fresh().await;
        let face = a_profile(&s, "Acme").await;
        s.put_world(world("Work", vec![face.clone()], vec![]), Some(0))
            .await
            .unwrap();

        let err = s
            .put_world(world("Home!", vec![face.clone()], vec![]), Some(0))
            .await
            .expect_err("a face was placed in two worlds");
        assert!(format!("{err}").contains("already belong"), "{err}");

        // And the refusal names where it already is, so a consumer can offer to
        // move it rather than sending the holder to look for it.
        let clash = s.placement_conflicts(&[face], None).await.unwrap();
        assert_eq!(clash.placed.len(), 1);
        assert_eq!(
            clash.placed[0].world_id,
            world("Work", vec![], vec![]).world_id
        );
    }

    #[tokio::test]
    async fn an_attribute_may_belong_to_several() {
        // A mobile number is genuinely part of both a working life and a home
        // one; a model that made the holder choose would be asking a question
        // about their phone that has no answer.
        let (_d, s) = fresh().await;
        let attr = an_attribute(&s).await;
        s.put_world(world("Work", vec![], vec![attr.clone()]), Some(0))
            .await
            .unwrap();
        s.put_world(world("Home!", vec![], vec![attr]), Some(0))
            .await
            .expect("an attribute was refused a second world");
    }

    #[tokio::test]
    async fn a_replace_does_not_clash_with_its_own_faces() {
        // Excluding the world being written is what keeps it editable: without
        // it, a world becomes uneditable the moment it holds anything.
        let (_d, s) = fresh().await;
        let face = a_profile(&s, "Acme").await;
        let first = world("Work", vec![face.clone()], vec![]);
        let id = first.world_id.clone();
        let v = s.put_world(first, Some(0)).await.unwrap().version;

        let mut again = world("Work", vec![face], vec![]);
        again.world_id = id;
        again.name = "Work life".into();
        let written = s
            .put_world(again, Some(v))
            .await
            .expect("a replace clashed with itself");
        assert!(!written.created);
    }

    #[tokio::test]
    async fn a_dangling_reference_refuses_the_write() {
        let (_d, s) = fresh().await;
        let err = s
            .put_world(
                world("Work", vec!["01J8XR3QK9V0000000000000AA".into()], vec![]),
                Some(0),
            )
            .await
            .expect_err("a world named a profile that does not exist");
        assert!(format!("{err}").contains("do not exist"), "{err}");
        assert!(
            s.list_worlds().await.unwrap().is_empty(),
            "a refused write left a world behind"
        );
    }

    #[tokio::test]
    async fn a_refused_write_consumes_no_version() {
        // Validation runs before a version is taken, so a rejected document
        // does not advance the store's change-feed watermark.
        let (_d, s) = fresh().await;
        let before = s.next_version().await.unwrap();
        let _ = s
            .put_world(
                world("Work", vec!["01J8XR3QK9V0000000000000AA".into()], vec![]),
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
        s.put_world(world("Work", vec![face.clone()], vec![]), Some(0))
            .await
            .unwrap();
        s.delete_profile(&face).await.unwrap();

        let listed = s.list_worlds().await.unwrap();
        assert_eq!(
            listed[0].face_ids,
            vec![face],
            "a dangling member was silently pruned"
        );
    }

    #[tokio::test]
    async fn a_world_is_agent_scoped() {
        // The security property, asserted on the key rather than the type.
        assert_eq!(
            storage::scope_of(&storage::world_key("01J8")),
            Some(storage::Scope::Agent)
        );
    }
}
