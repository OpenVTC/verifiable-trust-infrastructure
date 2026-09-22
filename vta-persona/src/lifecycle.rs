//! Retiring a face, bringing it back, and bindings that end on their own.
//!
//! `persona/profile/retire`, `persona/profile/reinstate` and binding `until` —
//! design note `docs/05-design-notes/persona-context-first.md` §9.4, §9.5.
//!
//! # Three ways to remove a face
//!
//! "Not here" is a cleared binding; "gone" is a delete; retire is the middle:
//! worn nowhere, out of pickers, refused by a binding, and **kept** — every
//! value and every disclosure it made. Reinstating makes it wearable and wears
//! it nowhere, because wearing a face in a context is decided in that context.
//!
//! # Expiry retires, never deletes
//!
//! A binding with an `until` reads as cleared from the moment it passes (see
//! `BindingRecord::into_read`); [`PersonaStore::expire_bindings`] makes that
//! durable and then retires each face the expiry left worn nowhere. A face
//! still worn in another context stays active: the `until` was about one
//! context, and retiring would take the face off contexts the holder said
//! nothing about.
//!
//! # Ordered for a crash
//!
//! Retire marks the face before it clears the bindings, so an interruption
//! leaves a face that cannot be newly worn, and a repeat retire — which always
//! clears what is still bound — finishes the job.

use std::collections::BTreeSet;

use vti_common::error::AppError;

use crate::binding::BindingRecord;
use crate::model::{Profile, ProfileStatus, Ulid, Version};
use crate::profile::ProfileSlot;
use crate::storage;
use crate::store::{PersonaStore, check_precondition, now_rfc3339};

/// What a retire did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Retired {
    pub version: Version,
    pub retired_at: String,
    /// `(context_id, persona_did)` for each binding cleared.
    pub unbound: Vec<(String, String)>,
}

/// One binding an expiry sweep cleared.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Lapsed {
    pub context_id: String,
    pub persona_did: String,
    pub profile_id: Ulid,
    /// Whether the face was then worn nowhere, and so retired.
    pub retired: bool,
}

/// How far a face has spoken — `persona/profile/get` `disclosedTo`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DisclosedTo {
    pub party_count: usize,
    pub context_count: usize,
}

/// Where a face lives: the pool, or one context's local space.
enum Home {
    Pool,
    Local(String),
}

impl PersonaStore {
    /// Stop wearing a face anywhere, and keep it.
    ///
    /// `context_id` names the context of a context-local face; `None` is a pool
    /// face. A face already retired is a success that takes no new version —
    /// but anything still bound to it is cleared, so a retire interrupted
    /// between its two steps is finished by the next.
    pub async fn retire_profile(
        &self,
        profile_id: &str,
        context_id: Option<&str>,
        expected_version: Option<Version>,
    ) -> Result<Retired, AppError> {
        let (face, home) = self.face_at(profile_id, context_id).await?;
        check_precondition(expected_version, Some(face.version))?;
        let face_was_active = face.status.is_active();

        let (version, retired_at) = if face_was_active {
            let _guard = self.write_lock.lock().await;
            let version = self.next_version().await?;
            let retired_at = now_rfc3339();
            let face = Profile {
                status: ProfileStatus::Retired,
                retired_at: Some(retired_at.clone()),
                version,
                updated_at: retired_at.clone(),
                ..face
            };
            self.write_face(&home, face).await?;
            (version, retired_at)
        } else {
            (
                face.version,
                face.retired_at.clone().unwrap_or_else(now_rfc3339),
            )
        };

        let unbound = self.unbind_face(profile_id, &home).await?;
        if face_was_active {
            self.record_face_event(
                profile_id,
                crate::FaceEvent::now(crate::FaceEventKind::Retired),
            )
            .await;
        }
        Ok(Retired {
            version,
            retired_at,
            unbound,
        })
    }

    /// Make a retired face wearable again. Binds nothing. Returns the face's
    /// version, unchanged for a face already active.
    pub async fn reinstate_profile(
        &self,
        profile_id: &str,
        context_id: Option<&str>,
        expected_version: Option<Version>,
    ) -> Result<Version, AppError> {
        let (face, home) = self.face_at(profile_id, context_id).await?;
        check_precondition(expected_version, Some(face.version))?;
        if face.status.is_active() {
            return Ok(face.version);
        }
        let _guard = self.write_lock.lock().await;
        let version = self.next_version().await?;
        let face = Profile {
            status: ProfileStatus::Active,
            retired_at: None,
            version,
            updated_at: now_rfc3339(),
            ..face
        };
        self.write_face(&home, face).await?;
        drop(_guard);
        self.record_face_event(
            profile_id,
            crate::FaceEvent::now(crate::FaceEventKind::Reinstated),
        )
        .await;
        Ok(version)
    }

    /// Make every binding past its `until` durably cleared, and retire each
    /// face that leaves worn nowhere. The sweeper's entry point.
    ///
    /// Reads already treat a lapsed binding as cleared; this is what stops the
    /// row claiming otherwise and what retires the face.
    pub async fn expire_bindings(
        &self,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<Lapsed>, AppError> {
        let mut lapsed = Vec::new();
        {
            let _guard = self.write_lock.lock().await;
            let rows = self.ks.prefix_iter_raw(b"pb:".to_vec()).await?;
            for (k, v) in rows {
                let Ok(record) = serde_json::from_slice::<BindingRecord>(&v) else {
                    continue;
                };
                if !record.lapsed_at(now) {
                    continue;
                }
                let Some(profile_id) = record.binding.profile_id.clone() else {
                    continue;
                };
                let Some(context_id) = String::from_utf8(k.clone()).ok().and_then(|key| {
                    key.strip_prefix("pb:")
                        .and_then(|rest| rest.split_once(':'))
                        .map(|(ctx, _)| ctx.to_string())
                }) else {
                    continue;
                };
                let mut cleared = record.into_read(now);
                cleared.binding.version = self.next_version().await?;
                cleared.binding.bound_at = now_rfc3339();
                let persona_did = cleared.binding.persona_did.clone();
                self.ks.insert(k, &cleared).await?;
                self.record_face_event(
                    &profile_id,
                    crate::FaceEvent::now(crate::FaceEventKind::Expired)
                        .worn_by(&context_id, &persona_did),
                )
                .await;
                lapsed.push(Lapsed {
                    context_id,
                    persona_did,
                    profile_id,
                    retired: false,
                });
            }
        }

        let mut decided: BTreeSet<String> = BTreeSet::new();
        for i in 0..lapsed.len() {
            let profile_id = lapsed[i].profile_id.clone();
            if !decided.insert(profile_id.clone()) {
                continue;
            }
            let context = lapsed[i].context_id.clone();
            let home = match self.get_profile(&profile_id).await? {
                Some(_) => None,
                None => Some(context.as_str()),
            };
            let worn_anywhere = match home {
                None => !self.bindings_to_anywhere(&profile_id).await?.is_empty(),
                Some(ctx) => !self.personas_bound_to(ctx, &profile_id).await?.is_empty(),
            };
            if worn_anywhere {
                continue;
            }
            match self.retire_profile(&profile_id, home, None).await {
                Ok(_) => {
                    for l in lapsed.iter_mut().filter(|l| l.profile_id == profile_id) {
                        l.retired = true;
                    }
                }
                // Deleted since it was worn: there is nothing left to retire.
                Err(AppError::NotFound(_)) => {}
                Err(e) => return Err(e),
            }
        }
        Ok(lapsed)
    }

    /// How many parties, across how many contexts, a face has disclosed to.
    ///
    /// A record names the face it was made through. One written before it did
    /// is attributed through the binding it was made under, where that binding
    /// still wears this face — the best answer the older record allows, and
    /// one that can only undercount.
    pub async fn disclosed_to(&self, profile_id: &str) -> Result<DisclosedTo, AppError> {
        let mut parties = BTreeSet::new();
        let mut contexts = BTreeSet::new();
        for record in self.disclosures_through(profile_id).await? {
            parties.insert(record.verifier_did);
            contexts.insert(record.context_id);
        }
        Ok(DisclosedTo {
            party_count: parties.len(),
            context_count: contexts.len(),
        })
    }

    /// The face and where it lives. `NotFound` when it is not there.
    async fn face_at(
        &self,
        profile_id: &str,
        context_id: Option<&str>,
    ) -> Result<(Profile, Home), AppError> {
        let found = match context_id {
            None => self.get_profile(profile_id).await?.map(|p| (p, Home::Pool)),
            Some(ctx) => self
                .get_local_profile(ctx, profile_id)
                .await?
                .map(|p| (p, Home::Local(ctx.to_string()))),
        };
        found.ok_or_else(|| {
            AppError::NotFound(match context_id {
                None => format!("profile {profile_id}"),
                Some(ctx) => format!("context-local profile {profile_id} in {ctx}"),
            })
        })
    }

    /// Write a face whose entries are unchanged. **Caller holds
    /// `write_lock`.** Status is not a value, so nothing is re-indexed or
    /// re-pushed.
    async fn write_face(&self, home: &Home, face: Profile) -> Result<(), AppError> {
        let key = match home {
            Home::Pool => storage::profile_key(&face.profile_id),
            Home::Local(ctx) => storage::local_profile_key(ctx, &face.profile_id),
        };
        self.ks.insert(key, &ProfileSlot::Live(face)).await
    }

    /// Clear every binding wearing this face, and say where.
    async fn unbind_face(
        &self,
        profile_id: &str,
        home: &Home,
    ) -> Result<Vec<(String, String)>, AppError> {
        match home {
            Home::Pool => {
                let bound = self.bindings_to_anywhere(profile_id).await?;
                if !bound.is_empty() {
                    self.unbind_everywhere(profile_id).await?;
                }
                Ok(bound)
            }
            Home::Local(ctx) => {
                let mut out = Vec::new();
                for persona in self.personas_bound_to(ctx, profile_id).await? {
                    self.set_local_binding(ctx, &persona, None, None, None)
                        .await?;
                    out.push((ctx.clone(), persona));
                }
                Ok(out)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compose::{ComposeClaim, ComposeRequest, Share};
    use crate::model::ValueType;
    use serde_json::json;
    use vti_common::config::StoreConfig;
    use vti_common::store::Store;

    async fn fresh() -> (tempfile::TempDir, PersonaStore) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .unwrap();
        let ks = store.keyspace(vta_keyspaces::PERSONA).unwrap();
        (dir, PersonaStore::new(ks, [13u8; 32]))
    }

    /// A pool face (one shared claim), worn by `persona` in `ctx`.
    async fn worn_pool_face(s: &PersonaStore, ctx: &str, persona: &str) -> String {
        let c = s
            .compose(ComposeRequest {
                context_id: ctx.into(),
                name: "Conference".into(),
                claims: vec![ComposeClaim::New {
                    r#type: "name.display".into(),
                    value_type: ValueType::String,
                    value: json!("Ada"),
                    label: None,
                    slot: None,
                    share: Share::Pool,
                }],
                persona_did: Some(persona.into()),
                wear: false,
                label: None,
                until: None,
            })
            .await
            .unwrap();
        c.profile_id
    }

    fn soon() -> String {
        (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339()
    }

    #[tokio::test]
    async fn retire_takes_a_face_off_everywhere_keeps_it_and_refuses_it_until_reinstated() {
        let (_d, s) = fresh().await;
        let face = worn_pool_face(&s, "conf", "did:key:z6MkA").await;
        s.set_binding(
            "expo",
            "did:key:z6MkB",
            Some(&face),
            vec![],
            None,
            None,
            None,
        )
        .await
        .unwrap();

        let r = s.retire_profile(&face, None, None).await.unwrap();
        let mut unbound = r.unbound.clone();
        unbound.sort();
        assert_eq!(
            unbound,
            vec![
                ("conf".to_string(), "did:key:z6MkA".to_string()),
                ("expo".to_string(), "did:key:z6MkB".to_string()),
            ]
        );
        let kept = s.get_profile(&face).await.unwrap().expect("kept");
        assert_eq!(kept.status, ProfileStatus::Retired);
        assert_eq!(kept.retired_at.as_deref(), Some(r.retired_at.as_str()));
        assert!(
            s.set_binding(
                "conf",
                "did:key:z6MkA",
                Some(&face),
                vec![],
                None,
                None,
                None
            )
            .await
            .is_err(),
            "a retired face cannot be worn"
        );

        let again = s.retire_profile(&face, None, None).await.unwrap();
        assert_eq!(again.version, r.version, "a repeat retire takes no version");

        s.reinstate_profile(&face, None, None).await.unwrap();
        assert!(
            s.bindings_to_anywhere(&face).await.unwrap().is_empty(),
            "reinstating wears the face nowhere"
        );
        s.set_binding(
            "conf",
            "did:key:z6MkA",
            Some(&face),
            vec![],
            None,
            None,
            None,
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn a_lapsed_binding_reads_as_cleared_before_the_sweep_and_retires_its_face_after() {
        let (_d, s) = fresh().await;
        let face = worn_pool_face(&s, "conf", "did:key:z6MkA").await;
        s.set_binding(
            "conf",
            "did:key:z6MkA",
            Some(&face),
            vec![],
            None,
            Some(soon()),
            None,
        )
        .await
        .unwrap();
        let summary = s.binding_summary("conf", "did:key:z6MkA").await.unwrap();
        assert!(summary.bound && summary.until.is_some(), "{summary:?}");

        // Past `until`, as seen from later: the sweep clears it and retires
        // the face, which is worn nowhere else.
        let later = chrono::Utc::now() + chrono::Duration::hours(2);
        let lapsed = s.expire_bindings(later).await.unwrap();
        assert_eq!(lapsed.len(), 1);
        assert!(lapsed[0].retired);
        assert!(
            !s.binding_summary("conf", "did:key:z6MkA")
                .await
                .unwrap()
                .bound
        );
        let kept = s
            .get_profile(&face)
            .await
            .unwrap()
            .expect("retired, never deleted");
        assert_eq!(kept.status, ProfileStatus::Retired);
    }

    #[tokio::test]
    async fn nothing_is_disclosed_through_a_lapsed_binding_even_before_the_sweep() {
        let (_d, s) = fresh().await;
        let face = worn_pool_face(&s, "conf", "did:key:z6MkA").await;
        s.set_binding(
            "conf",
            "did:key:z6MkA",
            Some(&face),
            vec![],
            None,
            Some(soon()),
            None,
        )
        .await
        .unwrap();
        // Time passes; the sweeper has not run.
        let key = storage::binding_key("conf", "did:key:z6MkA");
        let mut row =
            s.ks.get::<BindingRecord>(key.clone())
                .await
                .unwrap()
                .unwrap();
        row.binding.until = Some((chrono::Utc::now() - chrono::Duration::minutes(1)).to_rfc3339());
        s.ks.insert(key, &row).await.unwrap();

        assert!(
            s.materialised_claims("conf", "did:key:z6MkA")
                .await
                .unwrap()
                .is_empty()
        );
        assert!(
            !s.binding_summary("conf", "did:key:z6MkA")
                .await
                .unwrap()
                .bound
        );
        assert!(s.bindings_to_anywhere(&face).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn an_expiry_does_not_retire_a_face_still_worn_elsewhere() {
        let (_d, s) = fresh().await;
        let face = worn_pool_face(&s, "work", "did:key:z6MkA").await;
        s.set_binding(
            "conf",
            "did:key:z6MkB",
            Some(&face),
            vec![],
            None,
            Some(soon()),
            None,
        )
        .await
        .unwrap();
        let lapsed = s
            .expire_bindings(chrono::Utc::now() + chrono::Duration::hours(2))
            .await
            .unwrap();
        assert_eq!(lapsed.len(), 1);
        assert!(!lapsed[0].retired);
        assert!(
            s.get_profile(&face)
                .await
                .unwrap()
                .unwrap()
                .status
                .is_active()
        );
        assert!(
            s.binding_summary("work", "did:key:z6MkA")
                .await
                .unwrap()
                .bound
        );
    }

    #[tokio::test]
    async fn a_binding_refuses_an_until_in_the_past_or_without_a_face() {
        let (_d, s) = fresh().await;
        let face = worn_pool_face(&s, "conf", "did:key:z6MkA").await;
        let past = (chrono::Utc::now() - chrono::Duration::hours(1)).to_rfc3339();
        assert!(
            s.set_binding(
                "conf",
                "did:key:z6MkA",
                Some(&face),
                vec![],
                None,
                Some(past),
                None
            )
            .await
            .is_err()
        );
        assert!(
            s.set_binding(
                "conf",
                "did:key:z6MkA",
                None,
                vec![],
                None,
                Some(soon()),
                None
            )
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn a_face_is_told_how_far_it_has_spoken() {
        let (_d, s) = fresh().await;
        let face = worn_pool_face(&s, "conf", "did:key:z6MkA").await;
        for (verifier, ctx) in [
            ("did:web:a", "conf"),
            ("did:web:b", "conf"),
            ("did:web:a", "conf"),
        ] {
            let mut r = crate::new_disclosure(ctx, verifier, "did:key:z6MkA", vec![]);
            r.profile_id = Some(face.clone());
            s.record_disclosure(r).await.unwrap();
        }
        // A record from before faces were recorded, attributed through the
        // binding it was made under.
        s.record_disclosure(crate::new_disclosure(
            "conf",
            "did:web:c",
            "did:key:z6MkA",
            vec![],
        ))
        .await
        .unwrap();
        assert_eq!(
            s.disclosed_to(&face).await.unwrap(),
            DisclosedTo {
                party_count: 3,
                context_count: 1
            }
        );
    }
}
