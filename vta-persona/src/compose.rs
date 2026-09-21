//! Composing a face where it is asked for, and widening a local value later.
//!
//! `persona/profile/compose` and `persona/attribute/promote` — design note
//! `docs/05-design-notes/persona-context-first.md` §2.1 and §5.3.
//!
//! # Local by default, and scope follows from the claims
//!
//! A value typed at compose stays in the face: it is carried inline and enters
//! no pool, so no other face can come to present it. A claim marked
//! [`Share::Pool`] references a pool attribute instead. Where the face lives is
//! decided by what it carries — every entry inline makes a context-local face,
//! anything referencing the pool makes a pool face — so there is no scope
//! argument a caller could set independently of the claims, and so wrongly.
//!
//! # Reuse, never edit
//!
//! A pooled value is matched against the pool before anything is created: a
//! **self-asserted** attribute of the same type holding exactly the same value
//! is referenced rather than duplicated, and reported as reused. It is never
//! edited, and an attribute of any other provenance is never reused — a
//! credential-backed one presents an issuer's attestation and goes stale with
//! its credential, and a typed value is neither.
//!
//! # Several writes, ordered for a crash
//!
//! Neither operation is one store write, and the store has no transaction. Each
//! is ordered so that the process dying between two lines leaves something a
//! retry completes or a reader tolerates:
//!
//! - compose validates everything before writing anything, and on a failed
//!   later step removes the attributes it created, so a refused compose leaves
//!   no pool value that nothing references;
//! - promote writes the pool face and moves the bindings **before** removing
//!   the local face, so an interruption leaves the local face in place and
//!   worn, and a retry — which reuses the attributes it already made — finishes
//!   the move.

use vti_common::error::AppError;

use crate::correlation;
use crate::model::{InlineValue, Profile, ProfileEntry, Provenance, Ulid, ValueType, Version};
use crate::profile::{is_pool_free, new_profile};
use crate::store::{PersonaStore, Slot, new_attribute};

/// Whether a value typed at compose may be reused by other faces.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Share {
    /// Carried inline in this face alone. The default.
    #[default]
    Local,
    /// Referenced from the pool, where other faces can present it too.
    Pool,
}

/// One claim of a face being composed.
#[derive(Clone, Debug, PartialEq)]
pub enum ComposeClaim {
    /// A value typed now. Self-asserted by construction.
    New {
        r#type: String,
        value_type: ValueType,
        value: serde_json::Value,
        label: Option<String>,
        slot: Option<String>,
        share: Share,
    },
    /// An attribute already in the pool, presented live.
    Held {
        attribute_id: Ulid,
        slot: Option<String>,
    },
}

/// Where a composed face lives.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FaceScope {
    /// In one context's local address space.
    Local,
    /// Above contexts.
    Pool,
}

/// A pool attribute a claim now references, and whether this call made it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pooled {
    pub attribute_id: Ulid,
    pub created: bool,
}

/// The binding a compose made, when it was asked to wear the face.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ComposedBinding {
    pub persona_did: String,
    pub version: Version,
    pub also_bound_persona_count: usize,
}

/// What a compose made.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Composed {
    pub profile_id: Ulid,
    pub scope: FaceScope,
    pub version: Version,
    /// One per [`Share::Pool`] claim, in request order.
    pub pooled: Vec<Pooled>,
    pub binding: Option<ComposedBinding>,
    /// How many of the face's claims present a value something else the
    /// holder keeps also presents. A count, as on `profile/put`.
    pub shared_count: usize,
}

/// Why a compose was refused before anything was written.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ComposeRefusal {
    /// Held claims naming attributes the pool does not hold.
    UnresolvedReference(Vec<Ulid>),
    /// Two claims carry this slot.
    DuplicateSlot(String),
    /// A label was given with no persona to wear the face.
    LabelWithoutPersona,
    /// A new claim's value does not agree with its declared type.
    ValueDisagreesWithType(String),
}

impl ComposeRefusal {
    fn into_app_error(self) -> AppError {
        AppError::Validation(match self {
            Self::UnresolvedReference(ids) => format!(
                "the face draws on {} attribute(s) the pool does not hold: {}",
                ids.len(),
                ids.join(", ")
            ),
            Self::DuplicateSlot(slot) => {
                format!("two claims of this face both claim the slot {slot}")
            }
            Self::LabelWithoutPersona => {
                "a label names the face to the context it is worn in; give a personaDid to \
                 wear it, or leave the label off"
                    .into()
            }
            Self::ValueDisagreesWithType(t) => {
                format!("a {t} claim's value does not agree with its declared valueType")
            }
        })
    }
}

/// A compose request, as the store takes it.
#[derive(Clone, Debug, PartialEq)]
pub struct ComposeRequest {
    pub context_id: String,
    pub name: String,
    pub claims: Vec<ComposeClaim>,
    pub persona_did: Option<String>,
    pub label: Option<String>,
}

/// One entry a promote moved to the pool.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PromotedEntry {
    pub entry: usize,
    pub attribute_id: Ulid,
    pub created: bool,
}

/// What a promote did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Promoted {
    pub profile_id: Ulid,
    /// The face's version in the pool.
    pub version: Version,
    pub promoted: Vec<PromotedEntry>,
    pub rebound_persona_dids: Vec<String>,
}

impl PersonaStore {
    /// Why `request` would be refused, checked before anything is written.
    ///
    /// Public so a dispatcher can carry the specification's code for each
    /// case; [`Self::compose`] runs the same check, so no caller can skip it.
    pub async fn compose_refusal(
        &self,
        request: &ComposeRequest,
    ) -> Result<Option<ComposeRefusal>, AppError> {
        if request.label.is_some() && request.persona_did.is_none() {
            return Ok(Some(ComposeRefusal::LabelWithoutPersona));
        }
        let mut seen = std::collections::BTreeSet::new();
        for claim in &request.claims {
            let slot = match claim {
                ComposeClaim::New { slot, .. } | ComposeClaim::Held { slot, .. } => slot,
            };
            if let Some(s) = slot
                && !seen.insert(s.as_str())
            {
                return Ok(Some(ComposeRefusal::DuplicateSlot(s.clone())));
            }
        }
        for claim in &request.claims {
            if let ComposeClaim::New {
                r#type,
                value_type,
                value,
                ..
            } = claim
                && !value_type.accepts(value)
            {
                return Ok(Some(ComposeRefusal::ValueDisagreesWithType(r#type.clone())));
            }
        }
        let mut dangling = Vec::new();
        for claim in &request.claims {
            if let ComposeClaim::Held { attribute_id, .. } = claim
                && !matches!(self.slot(attribute_id).await?, Some(Slot::Live(_)))
            {
                dangling.push(attribute_id.clone());
            }
        }
        if !dangling.is_empty() {
            return Ok(Some(ComposeRefusal::UnresolvedReference(dangling)));
        }
        Ok(None)
    }

    /// Compose a face for `request.context_id`, and wear it there when a
    /// persona is named.
    pub async fn compose(&self, request: ComposeRequest) -> Result<Composed, AppError> {
        if let Some(refusal) = self.compose_refusal(&request).await? {
            return Err(refusal.into_app_error());
        }

        let mut pooled = Vec::new();
        let mut entries = Vec::with_capacity(request.claims.len());
        for claim in &request.claims {
            let entry = match claim {
                ComposeClaim::Held { attribute_id, slot } => ProfileEntry::Ref {
                    r#ref: attribute_id.clone(),
                    slot: slot.clone(),
                },
                ComposeClaim::New {
                    r#type,
                    value_type,
                    value,
                    label,
                    slot,
                    share: Share::Local,
                } => ProfileEntry::Inline {
                    inline: InlineValue {
                        r#type: r#type.clone(),
                        value_type: *value_type,
                        value: value.clone(),
                        label: label.clone(),
                        provenance: Provenance::SelfAsserted,
                    },
                    slot: slot.clone(),
                },
                ComposeClaim::New {
                    r#type,
                    value_type,
                    value,
                    label,
                    slot,
                    share: Share::Pool,
                } => {
                    let found = match self
                        .pool_value(r#type, *value_type, value, label.clone())
                        .await
                    {
                        Ok(p) => p,
                        Err(e) => {
                            self.forget_created(&pooled).await;
                            return Err(e);
                        }
                    };
                    let entry = ProfileEntry::Ref {
                        r#ref: found.attribute_id.clone(),
                        slot: slot.clone(),
                    };
                    pooled.push(found);
                    entry
                }
            };
            entries.push(entry);
        }

        let profile = new_profile(request.name.clone(), entries);
        let profile_id = profile.profile_id.clone();
        let scope = if is_pool_free(&profile.entries) {
            FaceScope::Local
        } else {
            FaceScope::Pool
        };
        let blinds = self.face_blinds_of(&profile).await?;

        let written = match scope {
            FaceScope::Local => {
                self.put_local_profile(&request.context_id, profile, Some(0))
                    .await
            }
            FaceScope::Pool => self.put_profile(profile, Some(0)).await,
        };
        let written = match written {
            Ok(w) => w,
            Err(e) => {
                self.forget_created(&pooled).await;
                return Err(e);
            }
        };

        let binding = match &request.persona_did {
            None => None,
            Some(did) => {
                let bound = match scope {
                    FaceScope::Local => self
                        .set_local_binding(
                            &request.context_id,
                            did,
                            Some(&profile_id),
                            request.label.clone(),
                            None,
                        )
                        .await
                        .map(|version| (version, 0)),
                    FaceScope::Pool => self
                        .set_binding(
                            &request.context_id,
                            did,
                            Some(&profile_id),
                            Vec::new(),
                            request.label.clone(),
                            None,
                            None,
                        )
                        .await
                        .map(|b| (b.version, b.also_bound_persona_count)),
                };
                match bound {
                    Ok((version, also)) => Some(ComposedBinding {
                        persona_did: did.clone(),
                        version,
                        also_bound_persona_count: also,
                    }),
                    Err(e) => {
                        // A face composed to be worn and then not worn is not
                        // what was asked for; take it back with what it made.
                        let _ = match scope {
                            FaceScope::Local => {
                                self.delete_local_profile(&request.context_id, &profile_id)
                                    .await
                            }
                            FaceScope::Pool => self.delete_profile(&profile_id).await,
                        };
                        self.forget_created(&pooled).await;
                        return Err(e);
                    }
                }
            }
        };

        let shared_count = self
            .shared_elsewhere(&blinds, &profile_id, &request.context_id, scope)
            .await?;

        Ok(Composed {
            profile_id,
            scope,
            version: written.version,
            pooled,
            binding,
            shared_count,
        })
    }

    /// Move entries of a context-local face into the pool, and the face with
    /// them.
    pub async fn promote(
        &self,
        context_id: &str,
        profile_id: &str,
        positions: &[usize],
        expected_version: Version,
    ) -> Result<Promoted, AppError> {
        let Some(local) = self.get_local_profile(context_id, profile_id).await? else {
            return Err(AppError::NotFound(format!(
                "{profile_id} is not a context-local face in {context_id}"
            )));
        };
        if local.version != expected_version {
            return Err(AppError::Conflict(format!(
                "expectedVersion {expected_version} does not match current version {}",
                local.version
            )));
        }
        if let Some(&beyond) = positions.iter().find(|&&p| p >= local.entries.len()) {
            return Err(AppError::Validation(format!(
                "entry {beyond} is beyond the face's {} entries",
                local.entries.len()
            )));
        }

        let mut promoted = Vec::with_capacity(positions.len());
        let mut entries = local.entries.clone();
        for &position in positions {
            let ProfileEntry::Inline { inline, slot } = &local.entries[position] else {
                // Unreachable for a stored local face — it is inline-only by
                // construction — and refused rather than guessed at.
                return Err(AppError::Validation(format!(
                    "entry {position} is not a value this face carries itself"
                )));
            };
            let found = self
                .pool_value(
                    &inline.r#type,
                    inline.value_type,
                    &inline.value,
                    inline.label.clone(),
                )
                .await?;
            entries[position] = ProfileEntry::Ref {
                r#ref: found.attribute_id.clone(),
                slot: slot.clone(),
            };
            promoted.push(PromotedEntry {
                entry: position,
                attribute_id: found.attribute_id,
                created: found.created,
            });
        }

        // Same id, name, order, slots and labels; only the promoted entries
        // change form. Last-writer-wins rather than create-only, so a retry
        // after an interrupted promote overwrites its own earlier write.
        let face = Profile {
            entries,
            ..local.clone()
        };
        let written = self.put_profile(face, None).await?;

        let mut rebound = Vec::new();
        for record in self.list_bindings(context_id).await? {
            if record.binding.profile_id.as_deref() != Some(profile_id) {
                continue;
            }
            self.set_binding(
                context_id,
                &record.binding.persona_did,
                Some(profile_id),
                Vec::new(),
                record.label.clone(),
                // Promotion changes where the face lives, not how long it is
                // worn here.
                record.binding.until.clone(),
                None,
            )
            .await?;
            rebound.push(record.binding.persona_did);
        }

        self.delete_local_profile(context_id, profile_id).await?;

        Ok(Promoted {
            profile_id: profile_id.to_string(),
            version: written.version,
            promoted,
            rebound_persona_dids: rebound,
        })
    }

    /// The self-asserted pool attribute holding exactly `value` as `type`,
    /// created when there is none.
    async fn pool_value(
        &self,
        r#type: &str,
        value_type: ValueType,
        value: &serde_json::Value,
        label: Option<String>,
    ) -> Result<Pooled, AppError> {
        let blind = correlation::blind(&self.correlation_key, value);
        for id in self.indexed_ids(&blind).await? {
            if let Some(a) = self.get(&id).await?
                && a.r#type == r#type
                && a.provenance == Provenance::SelfAsserted
                && a.value.as_ref() == Some(value)
            {
                return Ok(Pooled {
                    attribute_id: a.attribute_id,
                    created: false,
                });
            }
        }
        let mut attribute =
            new_attribute(r#type, value_type, value.clone(), Provenance::SelfAsserted);
        attribute.label = label;
        let attribute_id = attribute.attribute_id.clone();
        self.put(attribute, Some(0)).await?;
        Ok(Pooled {
            attribute_id,
            created: true,
        })
    }

    /// Remove attributes this call created, after a later step failed.
    ///
    /// Best effort: the failure being reported is the one the caller needs,
    /// and a second one here would only hide it. What is left behind is an
    /// unreferenced self-asserted value the holder can see and delete.
    async fn forget_created(&self, pooled: &[Pooled]) {
        for p in pooled.iter().filter(|p| p.created) {
            if let Err(e) = self.delete(&p.attribute_id, false).await {
                tracing::warn!(
                    error = %e, attribute_id = %p.attribute_id,
                    "could not remove an attribute a failed compose created"
                );
            }
        }
    }

    /// The blinded values a face presents, each once.
    async fn face_blinds_of(&self, face: &Profile) -> Result<Vec<String>, AppError> {
        let mut out = std::collections::BTreeSet::new();
        for entry in &face.entries {
            let value = match entry {
                ProfileEntry::Inline { inline, .. } => Some(inline.value.clone()),
                ProfileEntry::Override { r#override, .. } => Some(r#override.value.clone()),
                ProfileEntry::Ref { r#ref, .. } | ProfileEntry::Pinned { r#ref, .. } => {
                    self.get(r#ref).await?.and_then(|a| a.value)
                }
            };
            if let Some(v) = value {
                out.insert(correlation::blind(&self.correlation_key, &v));
            }
        }
        Ok(out.into_iter().collect())
    }

    /// How many of `blinds` something other than this face also presents: a
    /// pool attribute this face does not draw on, or another face.
    async fn shared_elsewhere(
        &self,
        blinds: &[String],
        profile_id: &str,
        context_id: &str,
        scope: FaceScope,
    ) -> Result<usize, AppError> {
        let face = match scope {
            FaceScope::Local => self.get_local_profile(context_id, profile_id).await?,
            FaceScope::Pool => self.get_profile(profile_id).await?,
        };
        let drawn: Vec<String> = face
            .map(|f| {
                f.entries
                    .iter()
                    .filter_map(|e| e.referenced().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        let mut shared = 0;
        for blind in blinds {
            let other_attribute = self
                .indexed_ids(blind)
                .await?
                .iter()
                .any(|id| !drawn.contains(id));
            let other_face = self
                .faces_carrying(blind)
                .await?
                .iter()
                .any(|c| c.profile_id != profile_id);
            let other_referrer = self.other_referrers(blind, &drawn, profile_id).await?;
            if other_attribute || other_face || other_referrer {
                shared += 1;
            }
        }
        Ok(shared)
    }

    /// Whether another face draws on a pool attribute holding this value.
    async fn other_referrers(
        &self,
        blind: &str,
        drawn: &[String],
        profile_id: &str,
    ) -> Result<bool, AppError> {
        for id in self.indexed_ids(blind).await? {
            if !drawn.contains(&id) {
                continue;
            }
            if self
                .referring_profiles(&id)
                .await?
                .iter()
                .any(|p| p != profile_id)
            {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
        (dir, PersonaStore::new(ks, [9u8; 32]))
    }

    fn typed(t: &str, v: &str, share: Share) -> ComposeClaim {
        ComposeClaim::New {
            r#type: t.into(),
            value_type: ValueType::String,
            value: json!(v),
            label: None,
            slot: None,
            share,
        }
    }

    fn request(claims: Vec<ComposeClaim>) -> ComposeRequest {
        ComposeRequest {
            context_id: "coop".into(),
            name: "Co-op".into(),
            claims,
            persona_did: None,
            label: None,
        }
    }

    #[tokio::test]
    async fn a_face_of_typed_values_stays_in_its_context_and_enters_no_pool() {
        let (_d, s) = fresh().await;
        let c = s
            .compose(request(vec![typed("name.display", "Ada", Share::Local)]))
            .await
            .unwrap();
        assert_eq!(c.scope, FaceScope::Local);
        assert!(c.pooled.is_empty());
        assert!(
            s.get_local_profile("coop", &c.profile_id)
                .await
                .unwrap()
                .is_some()
        );
        assert!(s.get_profile(&c.profile_id).await.unwrap().is_none());
        assert!(
            s.list_attributes(None, crate::ValueVisibility::All)
                .await
                .unwrap()
                .attributes
                .is_empty(),
            "nothing typed locally reached the pool"
        );
    }

    #[tokio::test]
    async fn a_shared_value_makes_a_pool_face_and_reuses_what_is_already_held() {
        let (_d, s) = fresh().await;
        let first = s
            .compose(request(vec![
                typed("name.display", "Ada", Share::Local),
                typed("email.personal", "ada@example.org", Share::Pool),
            ]))
            .await
            .unwrap();
        assert_eq!(first.scope, FaceScope::Pool);
        assert_eq!(first.pooled.len(), 1);
        assert!(first.pooled[0].created);
        let face = s.get_profile(&first.profile_id).await.unwrap().unwrap();
        assert!(matches!(face.entries[0], ProfileEntry::Inline { .. }));
        assert!(matches!(face.entries[1], ProfileEntry::Ref { .. }));

        let second = s
            .compose(request(vec![typed(
                "email.personal",
                "ada@example.org",
                Share::Pool,
            )]))
            .await
            .unwrap();
        assert_eq!(
            second.pooled,
            vec![Pooled {
                attribute_id: first.pooled[0].attribute_id.clone(),
                created: false
            }],
            "the value already kept is referenced, not duplicated"
        );
        assert_eq!(second.shared_count, 1, "and the face is told it shares it");
    }

    #[tokio::test]
    async fn a_credential_backed_value_is_not_reused_for_a_typed_one() {
        let (_d, s) = fresh().await;
        let attested = new_attribute(
            "name.legal",
            ValueType::String,
            json!("Ada Lovelace"),
            Provenance::CredentialBacked {
                credential_id: "cred-1".into(),
                claim_path: "$.credentialSubject.name".into(),
                issuer_did: None,
                proof: None,
            },
        );
        s.put(attested.clone(), None).await.unwrap();
        let c = s
            .compose(request(vec![typed(
                "name.legal",
                "Ada Lovelace",
                Share::Pool,
            )]))
            .await
            .unwrap();
        assert!(c.pooled[0].created);
        assert_ne!(c.pooled[0].attribute_id, attested.attribute_id);
    }

    #[tokio::test]
    async fn a_refused_compose_writes_nothing() {
        let (_d, s) = fresh().await;
        let mut r = request(vec![
            typed("email.personal", "ada@example.org", Share::Pool),
            ComposeClaim::Held {
                attribute_id: "01J000000000000000000NOPE0".into(),
                slot: None,
            },
        ]);
        assert!(matches!(
            s.compose_refusal(&r).await.unwrap(),
            Some(ComposeRefusal::UnresolvedReference(_))
        ));
        assert!(s.compose(r.clone()).await.is_err());
        assert!(
            s.list_attributes(None, crate::ValueVisibility::All)
                .await
                .unwrap()
                .attributes
                .is_empty(),
            "the pooled claim before the bad reference created nothing"
        );

        r.claims.truncate(1);
        r.label = Some("the co-op one".into());
        assert_eq!(
            s.compose_refusal(&r).await.unwrap(),
            Some(ComposeRefusal::LabelWithoutPersona)
        );
    }

    #[tokio::test]
    async fn compose_can_wear_the_face_it_makes() {
        let (_d, s) = fresh().await;
        let mut r = request(vec![typed("name.display", "Ada", Share::Local)]);
        r.persona_did = Some("did:key:z6MkPersona".into());
        r.label = Some("Ada at the co-op".into());
        let c = s.compose(r).await.unwrap();
        let b = c.binding.expect("worn");
        assert_eq!(b.persona_did, "did:key:z6MkPersona");
        let claims = s
            .materialised_claims("coop", "did:key:z6MkPersona")
            .await
            .unwrap();
        assert_eq!(claims.len(), 1);
        assert_eq!(claims[0].value, Some(json!("Ada")));
    }

    #[tokio::test]
    async fn promote_moves_the_face_up_keeping_its_id_and_its_wearers() {
        let (_d, s) = fresh().await;
        let mut r = request(vec![
            typed("name.display", "Ada", Share::Local),
            typed("email.personal", "ada@example.org", Share::Local),
        ]);
        r.persona_did = Some("did:key:z6MkPersona".into());
        r.label = Some("Ada at the co-op".into());
        let c = s.compose(r).await.unwrap();
        let local = s
            .get_local_profile("coop", &c.profile_id)
            .await
            .unwrap()
            .unwrap();

        let p = s
            .promote("coop", &c.profile_id, &[1], local.version)
            .await
            .unwrap();
        assert_eq!(p.profile_id, c.profile_id);
        assert_eq!(p.rebound_persona_dids, vec!["did:key:z6MkPersona"]);
        assert!(p.promoted[0].created);

        assert!(
            s.get_local_profile("coop", &c.profile_id)
                .await
                .unwrap()
                .is_none()
        );
        let face = s.get_profile(&c.profile_id).await.unwrap().unwrap();
        assert_eq!(face.name, "Co-op");
        assert!(matches!(face.entries[0], ProfileEntry::Inline { .. }));
        assert!(
            matches!(&face.entries[1], ProfileEntry::Ref { r#ref, .. } if *r#ref == p.promoted[0].attribute_id)
        );

        let claims = s
            .materialised_claims("coop", "did:key:z6MkPersona")
            .await
            .unwrap();
        let values: Vec<_> = claims.iter().map(|c| c.value.clone()).collect();
        assert_eq!(
            values,
            vec![Some(json!("Ada")), Some(json!("ada@example.org"))],
            "the wearer presents exactly what it did"
        );
        let summary = s
            .list_binding_summaries("coop")
            .await
            .unwrap()
            .into_iter()
            .find(|b| b.persona_did == "did:key:z6MkPersona")
            .unwrap();
        assert_eq!(summary.label.as_deref(), Some("Ada at the co-op"));
    }

    #[tokio::test]
    async fn promote_refuses_a_stale_read_and_a_position_past_the_end() {
        let (_d, s) = fresh().await;
        let c = s
            .compose(request(vec![typed("name.display", "Ada", Share::Local)]))
            .await
            .unwrap();
        let v = s
            .get_local_profile("coop", &c.profile_id)
            .await
            .unwrap()
            .unwrap()
            .version;
        assert!(matches!(
            s.promote("coop", &c.profile_id, &[0], v + 1).await,
            Err(AppError::Conflict(_))
        ));
        assert!(matches!(
            s.promote("coop", &c.profile_id, &[1], v).await,
            Err(AppError::Validation(_))
        ));
        assert!(matches!(
            s.promote("elsewhere", &c.profile_id, &[0], v).await,
            Err(AppError::NotFound(_))
        ));
    }

    #[tokio::test]
    async fn an_interrupted_promote_is_finished_by_a_retry() {
        let (_d, s) = fresh().await;
        let mut r = request(vec![typed(
            "email.personal",
            "ada@example.org",
            Share::Local,
        )]);
        r.persona_did = Some("did:key:z6MkPersona".into());
        let c = s.compose(r).await.unwrap();
        let local = s
            .get_local_profile("coop", &c.profile_id)
            .await
            .unwrap()
            .unwrap();

        // The process died after the pool face was written: the local face is
        // still there and still worn.
        let attribute = s
            .pool_value(
                "email.personal",
                ValueType::String,
                &json!("ada@example.org"),
                None,
            )
            .await
            .unwrap();
        s.put_profile(
            Profile {
                entries: vec![ProfileEntry::Ref {
                    r#ref: attribute.attribute_id.clone(),
                    slot: None,
                }],
                ..local.clone()
            },
            None,
        )
        .await
        .unwrap();

        let p = s
            .promote("coop", &c.profile_id, &[0], local.version)
            .await
            .unwrap();
        assert_eq!(
            p.promoted[0],
            PromotedEntry {
                entry: 0,
                attribute_id: attribute.attribute_id,
                created: false
            },
            "the retry reuses what the first attempt made"
        );
        assert!(
            s.get_local_profile("coop", &c.profile_id)
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(p.rebound_persona_dids, vec!["did:key:z6MkPersona"]);
    }
}
