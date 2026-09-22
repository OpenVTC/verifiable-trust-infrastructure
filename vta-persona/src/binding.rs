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
    /// The holder's `release` override, copied down with the value.
    ///
    /// **This is the whole mechanism for honouring an override below the
    /// boundary.** A context cannot read the pool to ask what the holder
    /// decided, so the decision travels with the projection or it does not
    /// travel at all — copies go down, nothing reads up. Re-materialisation on
    /// an attribute edit refreshes it, so changing the override changes what
    /// every bound context enforces without any of them reading anything.
    ///
    /// `None` on a binding written before this field existed, which resolves to
    /// the registry default — the behaviour those bindings already had.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub release: Option<crate::ReleaseRequirement>,
}

/// The binding plus the claims it pushed into the context.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct BindingRecord {
    pub binding: Binding,
    /// Cached label so a context-scoped read can name the composition without
    /// reaching across the boundary to the profile.
    pub profile_name: Option<String>,
    /// What the holder said this context may call the face — the only name a
    /// context-scoped caller is given. `profile_name` is the holder's own and
    /// stays holder-only; see `persona/binding/set` `label`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    pub claims: Vec<MaterialisedClaim>,
}

impl BindingRecord {
    /// Whether this binding's `until` has passed at `now`.
    pub(crate) fn lapsed_at(&self, now: chrono::DateTime<chrono::Utc>) -> bool {
        self.binding.profile_id.is_some()
            && self
                .binding
                .until
                .as_deref()
                .and_then(|u| chrono::DateTime::parse_from_rfc3339(u).ok())
                .is_some_and(|u| u <= now)
    }

    /// The binding as every reader must see it.
    ///
    /// A binding past its `until` reads as cleared **whether or not the sweeper
    /// has reached it yet** — `persona/binding/set` says a face is never
    /// disclosed through a binding whose `until` has passed, and a sweeper runs
    /// on an interval. Making the lapse a property of the read rather than of
    /// the sweep means no reader can forget it: they all decode through here.
    /// The version is kept, so a conditional write still sees the row it read.
    pub(crate) fn into_read(mut self, now: chrono::DateTime<chrono::Utc>) -> Self {
        if self.lapsed_at(now) {
            self.binding.profile_id = None;
            self.binding.until = None;
            self.profile_name = None;
            self.label = None;
            self.claims.clear();
        }
        self
    }

    /// Decode a stored row as a reader must see it.
    pub(crate) fn decode(bytes: &[u8]) -> Option<Self> {
        serde_json::from_slice::<Self>(bytes)
            .ok()
            .map(|r| r.into_read(chrono::Utc::now()))
    }
}

/// Check a binding's `until` before it is written: in the future, and only on
/// a binding that wears a face. `None` when it is acceptable.
pub(crate) fn until_refusal(until: Option<&str>, wears_a_face: bool) -> Option<String> {
    let until = until?;
    if !wears_a_face {
        return Some("an `until` ends a face being worn; a cleared binding has none".into());
    }
    match chrono::DateTime::parse_from_rfc3339(until) {
        Ok(t) if t > chrono::Utc::now() => None,
        Ok(_) => Some(format!("until {until} is not in the future")),
        Err(e) => Some(format!("until {until} is not an RFC 3339 date-time: {e}")),
    }
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
    /// The holder's own name for the face. **Holder-only**: a dispatcher MUST
    /// NOT hand it to a context-scoped caller, which reads [`Self::label`].
    pub profile_name: Option<String>,
    /// The name the holder chose for this context to call the face.
    pub label: Option<String>,
    pub claim_count: usize,
    pub bound_at: Option<String>,
    /// When the binding ends on its own.
    pub until: Option<String>,
}

/// Where an attribute edit landed — see [`PersonaStore::attribute_reach`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct AttributeReach {
    pub refreshed: Vec<RefreshedBinding>,
    pub held_by_pin: Vec<HeldByPin>,
}

/// One binding whose projection an attribute edit re-pushed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RefreshedBinding {
    pub profile_id: Ulid,
    pub context_id: String,
    pub persona_did: String,
}

/// One face that pins an attribute and so did not follow an edit to it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeldByPin {
    pub profile_id: Ulid,
    pub pin_version: Version,
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
    // One argument per member of `persona/binding/set`; a struct here would
    // only be the payload again under another name.
    #[allow(clippy::too_many_arguments)]
    pub async fn set_binding(
        &self,
        context_id: &str,
        persona_did: &str,
        profile_id: Option<&str>,
        public_entries: Vec<Ulid>,
        label: Option<String>,
        until: Option<String>,
        expected_version: Option<Version>,
    ) -> Result<Bound, AppError> {
        if let Some(reason) = until_refusal(until.as_deref(), profile_id.is_some()) {
            return Err(AppError::Validation(reason));
        }
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
                // A retired face is one the holder has stopped being; binding it
                // back by accident would undo that. Reinstate first.
                if !p.status.is_active() {
                    return Err(AppError::Validation(format!(
                        "profile {id} is retired; reinstate it before wearing it"
                    )));
                }
                // The holder said where this face may go; anywhere else is
                // refused rather than trusted to the caller.
                if !p.reach.admits(context_id) {
                    return Err(AppError::Validation(format!(
                        "profile {id} may not be worn in {context_id}; its reach does not \
                         include it"
                    )));
                }
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
                until: profile_id.and(until),
            },
            profile_name,
            // A cleared binding wears no face, so it has nothing to name.
            label: profile_id.and(label),
            claims,
        };
        let count = record.claims.len();

        self.ks
            .insert(storage::binding_key(context_id, persona_did), &record)
            .await?;
        let before = existing.and_then(|r| r.binding.profile_id);
        self.record_wearing(context_id, persona_did, before.as_deref(), profile_id)
            .await;

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
                release: c.release,
            })
            .collect())
    }

    pub(crate) async fn binding_record(
        &self,
        context_id: &str,
        persona_did: &str,
    ) -> Result<Option<BindingRecord>, AppError> {
        Ok(self
            .ks
            .get::<BindingRecord>(storage::binding_key(context_id, persona_did))
            .await?
            .map(|r| r.into_read(chrono::Utc::now())))
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
                label: None,
                claim_count: 0,
                bound_at: None,
                until: None,
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
                label: r.label.clone(),
                claim_count: r.claims.len(),
                bound_at: Some(r.binding.bound_at.clone()),
                until: r.binding.until.clone(),
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
            .filter_map(|(_k, v)| BindingRecord::decode(&v))
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
                label: r.label,
                claim_count: r.claims.len(),
                bound_at: Some(r.binding.bound_at),
                until: r.binding.until,
            })
            .collect())
    }

    /// Every persona bound to a profile, across **every** context.
    ///
    /// Holder-only by consequence: it spans contexts, which is exactly the view
    /// a context-scoped caller must not have. Used by profile deletion to name
    /// what a removal would leave presenting nothing.
    pub async fn personas_bound_to_anywhere(
        &self,
        profile_id: &str,
    ) -> Result<Vec<String>, AppError> {
        let rows = self.ks.prefix_iter_raw(b"pb:".to_vec()).await?;
        Ok(rows
            .into_iter()
            .filter_map(|(_k, v)| BindingRecord::decode(&v))
            .filter(|r| r.binding.profile_id.as_deref() == Some(profile_id))
            .map(|r| r.binding.persona_did)
            .collect())
    }

    /// Every persona bound to a profile **and the context each is bound in**,
    /// across every context.
    ///
    /// The sibling above answers "who would stop presenting if this profile
    /// went away", which is a question about personas alone — so it discards
    /// the key and loses the context. `correlation/analyze` asks a different
    /// question: *where has this value actually gone*, and a persona DID with
    /// no context attached does not answer it. A holder shown
    /// `did:peer:0z6Mk…` and nothing else cannot act; shown that DID in
    /// `ctx-employer` they can.
    ///
    /// Holder-only for the same reason as its sibling — it spans contexts,
    /// which is precisely the view a context-scoped caller must not have.
    ///
    /// # Parsing the context out of the key
    ///
    /// The key is `pb:{context_id}:{persona_did}` and **a persona DID contains
    /// colons** — `did:peer:2.Ez6…` has two before the method-specific id even
    /// begins. So the key cannot be split on `':'` and indexed: `split(':')`
    /// over that key yields `["pb", ctx, "did", "peer", …]`, and any call site
    /// that takes a fixed element is reading a DID fragment as a context id.
    /// Strip the `pb:` prefix, then `split_once(':')` — it consumes exactly the
    /// **first** separator and hands back the whole remainder untouched, so the
    /// colons inside the DID cannot be mistaken for structure. The persona DID
    /// itself is read from the deserialised record rather than from that
    /// remainder, so nothing is ever reassembled and there is nothing to
    /// mangle.
    pub async fn bindings_to_anywhere(
        &self,
        profile_id: &str,
    ) -> Result<Vec<(String, String)>, AppError> {
        let rows = self.ks.prefix_iter_raw(b"pb:".to_vec()).await?;
        Ok(rows
            .into_iter()
            .filter_map(|(k, v)| {
                let record = BindingRecord::decode(&v)?;
                if record.binding.profile_id.as_deref() != Some(profile_id) {
                    return None;
                }
                let key = String::from_utf8(k).ok()?;
                let (context_id, _persona) = key.strip_prefix("pb:")?.split_once(':')?;
                Some((context_id.to_string(), record.binding.persona_did))
            })
            .collect())
    }

    /// Clear every binding to a profile, across every context.
    ///
    /// The deliberate half of profile deletion: it leaves those personas
    /// presenting nothing, which is a legal state and one the holder is told
    /// about rather than discovering.
    pub async fn unbind_everywhere(&self, profile_id: &str) -> Result<usize, AppError> {
        let _guard = self.write_lock.lock().await;
        let rows = self.ks.prefix_iter_raw(b"pb:".to_vec()).await?;
        let mut cleared = 0usize;
        for (k, v) in rows {
            let Some(mut record) = BindingRecord::decode(&v) else {
                continue;
            };
            if record.binding.profile_id.as_deref() != Some(profile_id) {
                continue;
            }
            record.binding.profile_id = None;
            record.profile_name = None;
            record.label = None;
            record.claims.clear();
            self.ks.insert(k.clone(), &record).await?;
            cleared += 1;
            if let Some(ctx) = String::from_utf8(k).ok().and_then(|key| {
                key.strip_prefix("pb:")
                    .and_then(|rest| rest.split_once(':'))
                    .map(|(c, _)| c.to_string())
            }) {
                self.record_face_event(
                    profile_id,
                    crate::FaceEvent::now(crate::FaceEventKind::Unworn)
                        .worn_by(&ctx, &record.binding.persona_did),
                )
                .await;
            }
        }
        Ok(cleared)
    }

    /// Re-push every projection that draws on a profile.
    ///
    /// "Edit once, everywhere" survives the boundary because this is a **write
    /// initiated above it**, never a read from below. A context that could pull
    /// its projection fresh would be reaching into the pool, which is the thing
    /// the direction rule forbids.
    ///
    /// Returns how many projections were refreshed.
    ///
    /// **This is the maintenance entry point, not the mechanism.** Every write
    /// that changes what a profile projects pushes for itself, from inside its
    /// own lock — see [`Self::push_profile_locked`]. Calling this afterwards is
    /// a no-op that costs a scan.
    pub async fn rematerialise(&self, profile_id: &str) -> Result<usize, AppError> {
        let _guard = self.write_lock.lock().await;
        self.push_profile_locked(profile_id).await
    }

    /// The push itself. **Caller must hold `write_lock`.**
    ///
    /// Split out because the writes that need it already hold the lock, and
    /// `tokio::sync::Mutex` is not reentrant — `put` calling `rematerialise`
    /// would deadlock rather than fail, which is the worst way to find out.
    ///
    /// Holding the lock across both is not merely convenient, it is the
    /// property that matters: the write and the push land together. A crash
    /// between them would leave every bound context holding a projection of a
    /// pool state that no longer exists, with nothing to notice or repair it —
    /// and the holder would have no way to tell, because the console reads the
    /// pool while the verifier is shown the copy.
    pub(crate) async fn push_profile_locked(&self, profile_id: &str) -> Result<usize, AppError> {
        let claims = self.materialise(profile_id).await?;

        let mut refreshed = 0usize;
        let rows = self.ks.prefix_iter_raw(b"pb:".to_vec()).await?;
        for (k, v) in rows {
            let Some(mut record) = BindingRecord::decode(&v) else {
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

    /// Where an edit to one attribute lands: the bindings that present it
    /// live, and the faces that pin it and so do not follow.
    ///
    /// The answer `persona/attribute/put` returns as `refreshed` and
    /// `heldByPin`. An edit propagating is the point of a pool and also the
    /// surprise — a holder told only that the write succeeded cannot tell
    /// whether it changed what one counterparty sees or nine.
    ///
    /// An `override` entry is in neither list: the face shows its own value,
    /// so the edit changes nothing it presents.
    pub async fn attribute_reach(&self, attribute_id: &str) -> Result<AttributeReach, AppError> {
        let mut reach = AttributeReach::default();
        for profile_id in self.referring_profiles(attribute_id).await? {
            let Some(face) = self.get_profile(&profile_id).await? else {
                continue;
            };
            let mut live = false;
            for entry in &face.entries {
                match entry {
                    crate::ProfileEntry::Ref { r#ref, .. } if r#ref == attribute_id => live = true,
                    crate::ProfileEntry::Pinned {
                        r#ref, pin_version, ..
                    } if r#ref == attribute_id => {
                        reach.held_by_pin.push(HeldByPin {
                            profile_id: profile_id.clone(),
                            pin_version: *pin_version,
                        });
                    }
                    _ => {}
                }
            }
            if live {
                for (context_id, persona_did) in self.bindings_to_anywhere(&profile_id).await? {
                    reach.refreshed.push(RefreshedBinding {
                        profile_id: profile_id.clone(),
                        context_id,
                        persona_did,
                    });
                }
            }
        }
        Ok(reach)
    }

    /// Push every profile that references one attribute.
    ///
    /// The attribute-side entry point: a pool edit changes what every profile
    /// referencing it projects, and the reverse index is what makes that
    /// answerable without scanning every profile. **Caller must hold
    /// `write_lock`.**
    pub(crate) async fn push_attribute_locked(
        &self,
        attribute_id: &str,
    ) -> Result<usize, AppError> {
        let mut refreshed = 0usize;
        for profile_id in self.referring_profiles(attribute_id).await? {
            refreshed += self.push_profile_locked(&profile_id).await?;
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
                slot: None,
                r#ref: a.attribute_id.clone(),
            }],
        );
        s.put_profile(p.clone(), None).await.unwrap();
        (a.attribute_id, p.profile_id)
    }

    /// A binding is reported with the context it lives in — and the context id
    /// survives a persona DID full of colons.
    ///
    /// `personas_bound_to_anywhere` discards the storage key, so the context is
    /// simply not available to it. `bindings_to_anywhere` recovers it from the
    /// key, and the key is `pb:{context_id}:{persona_did}` — where the persona
    /// DID has colons of its own. The `did:peer:2.…` below is the shape that
    /// breaks a naive `split(':')`: an implementation taking a fixed element
    /// returns `"did"` as the context id, which is not obviously wrong when
    /// read and is completely wrong when acted on.
    /// A record with a fingerprint and one type, for the currency tests.
    fn disclosed(s: &PersonaStore, value: Option<&str>) -> crate::DisclosureRecord {
        crate::new_disclosure(
            "ctx",
            "did:v",
            "did:p",
            vec![crate::DisclosedClaim {
                r#type: "phone.mobile".into(),
                rung: crate::ProofRung::Whole,
                value_blind: value
                    .map(|v| crate::correlation::blind(&s.correlation_key, &serde_json::json!(v))),
            }],
        )
    }

    #[tokio::test]
    async fn currency_says_whether_the_verifier_still_holds_what_is_presented() {
        use crate::ClaimCurrency as C;
        let (_d, s) = fresh().await;
        let (attr, profile) = pool_profile(&s, "+61 400").await;
        s.set_binding("ctx", "did:p", Some(&profile), vec![], None, None, None)
            .await
            .unwrap();

        let rec = disclosed(&s, Some("+61 400"));
        assert_eq!(s.claim_currency(&rec).await.unwrap(), vec![C::Current]);

        // The value changes and the push re-materialises the binding.
        let mut a = s.get(&attr).await.unwrap().unwrap();
        a.value = Some(serde_json::json!("+61 999"));
        s.put(a, None).await.unwrap();
        assert_eq!(s.claim_currency(&rec).await.unwrap(), vec![C::Changed]);

        // The persona stops presenting it; the verifier keeps what it got.
        s.set_binding("ctx", "did:p", None, vec![], None, None, None)
            .await
            .unwrap();
        assert_eq!(s.claim_currency(&rec).await.unwrap(), vec![C::Removed]);

        // No fingerprint — a predicate, or a record from before them — is
        // never reported as current.
        let old = disclosed(&s, None);
        assert_eq!(s.claim_currency(&old).await.unwrap(), vec![C::Unknown]);
    }

    #[tokio::test]
    async fn a_cleared_binding_keeps_no_label() {
        // A persona wearing no face has nothing to name, and a stale label
        // would name a face it no longer wears.
        let (_d, s) = fresh().await;
        let (_attr, profile) = pool_profile(&s, "+61 400").await;
        s.set_binding(
            "ctx",
            "did:p",
            Some(&profile),
            vec![],
            Some("Co-op".into()),
            None,
            None,
        )
        .await
        .unwrap();
        assert_eq!(
            s.binding_summary("ctx", "did:p")
                .await
                .unwrap()
                .label
                .as_deref(),
            Some("Co-op")
        );
        s.set_binding(
            "ctx",
            "did:p",
            None,
            vec![],
            Some("Co-op".into()),
            None,
            None,
        )
        .await
        .unwrap();
        assert_eq!(s.binding_summary("ctx", "did:p").await.unwrap().label, None);
    }

    #[tokio::test]
    async fn a_binding_is_reported_with_the_context_it_lives_in() {
        let (_d, s) = fresh().await;
        let (_a, profile) = pool_profile(&s, "+61 400 000 000").await;
        let persona = "did:peer:2.Ez6LSbXq3.Vz6MkfR9c";

        s.set_binding(
            "ctx-employer",
            persona,
            Some(&profile),
            vec![],
            None,
            None,
            None,
        )
        .await
        .unwrap();

        let found = s.bindings_to_anywhere(&profile).await.unwrap();
        assert_eq!(
            found,
            vec![("ctx-employer".to_string(), persona.to_string())],
            "the context id was lost or mangled parsing a key whose persona DID \
             contains colons"
        );

        // And a profile nothing is bound to reports nothing, rather than every
        // binding in the store.
        assert!(
            s.bindings_to_anywhere("01J0000000000000000000000A")
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn the_projection_carries_no_pool_identifier() {
        // The security property, asserted on the serialised bytes rather than
        // the type — because what crosses the boundary is what was written.
        let (_d, s) = fresh().await;
        let (attr_id, profile_id) = pool_profile(&s, "+61 4").await;
        s.set_binding(
            "ctx",
            "did:persona:a",
            Some(&profile_id),
            vec![],
            None,
            None,
            None,
        )
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
            .set_binding(
                "ctx",
                "did:persona:a",
                Some("01MISSING"),
                vec![],
                None,
                None,
                None,
            )
            .await
            .unwrap_err();
        assert!(matches!(err, AppError::NotFound(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn clearing_is_a_first_class_state_not_an_absence() {
        let (_d, s) = fresh().await;
        let (_a, p) = pool_profile(&s, "x").await;
        s.set_binding("ctx", "did:p", Some(&p), vec![], None, None, None)
            .await
            .unwrap();
        assert!(s.binding_summary("ctx", "did:p").await.unwrap().bound);

        s.set_binding("ctx", "did:p", None, vec![], None, None, None)
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
            .set_binding("ctx", "did:p1", Some(&p), vec![], None, None, None)
            .await
            .unwrap();
        assert_eq!(first.also_bound_persona_count, 0);

        let second = s
            .set_binding("ctx", "did:p2", Some(&p), vec![], None, None, None)
            .await
            .unwrap();
        assert_eq!(second.also_bound_persona_count, 1);
    }

    #[tokio::test]
    async fn a_summary_names_the_composition_and_never_its_contents() {
        let (_d, s) = fresh().await;
        let (_a, p) = pool_profile(&s, "+61 4xx secret").await;
        s.set_binding("ctx", "did:p", Some(&p), vec![], None, None, None)
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
        s.set_binding("ctx", "did:p", Some(&p), vec![], None, None, None)
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
        s.set_binding("ctx-a", "did:p", Some(&p), vec![], None, None, None)
            .await
            .unwrap();

        assert_eq!(s.list_binding_summaries("ctx-a").await.unwrap().len(), 1);
        assert!(s.list_binding_summaries("ctx-b").await.unwrap().is_empty());
        assert!(!s.binding_summary("ctx-b", "did:p").await.unwrap().bound);
    }
}
