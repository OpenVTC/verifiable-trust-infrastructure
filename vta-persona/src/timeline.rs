//! Where a face is worn now, and what it has done.
//!
//! `persona/profile/usage` and `persona/profile/timeline` — design note
//! `docs/05-design-notes/persona-context-first.md` §5.4, §9.6.
//!
//! # What is recorded, and what is joined
//!
//! Most of a face's history is already kept somewhere: disclosure records name
//! the face they were made through, a face knows when it was made and retired.
//! One thing is not — a binding taken off leaves no trace in the binding that
//! replaces it — so every change to what a face is worn by, and every change
//! to its lifecycle, is appended to the face's own event log (`pft:`) as it
//! happens. The timeline is that log joined with the disclosure records.
//!
//! # Never a value, never a private label
//!
//! A [`FaceEvent`] has nowhere to put either. It names contexts, personas,
//! parties, claim types and versions. A history that carried values would be a
//! second copy of every value the face ever showed, with a lifetime the
//! holder's edits and purges do not reach — the same lifetime argument
//! `audit_persona` makes for the audit trail.
//!
//! # Recording never fails a write
//!
//! The event is recorded after the change it describes, and a failure to
//! record it is logged rather than returned: a binding the holder asked for
//! must not be refused because its history row could not be written. The
//! timeline is a view, not the source of truth for any decision.

use serde::{Deserialize, Serialize};
use vti_common::error::AppError;

use crate::model::{FaceReach, Version};
use crate::storage;
use crate::store::{PersonaStore, now_rfc3339};

/// What happened to a face.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum FaceEventKind {
    Composed,
    Worn,
    Unworn,
    Expired,
    Disclosed,
    ValueChanged,
    Promoted,
    Retired,
    Reinstated,
}

/// One event in a face's history.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FaceEvent {
    pub at: String,
    pub kind: FaceEventKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub persona_did: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verifier_did: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub claim_types: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<Version>,
}

impl FaceEvent {
    /// An event of `kind`, now, carrying nothing else.
    #[must_use]
    pub fn now(kind: FaceEventKind) -> Self {
        Self {
            at: now_rfc3339(),
            kind,
            context_id: None,
            persona_did: None,
            verifier_did: None,
            claim_types: Vec::new(),
            version: None,
        }
    }

    /// The same event, in a context and for a persona.
    #[must_use]
    pub fn worn_by(mut self, context_id: &str, persona_did: &str) -> Self {
        self.context_id = Some(context_id.to_string());
        self.persona_did = Some(persona_did.to_string());
        self
    }
}

/// One place a face is worn now.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Usage {
    pub context_id: String,
    pub persona_did: String,
    pub bound_at: String,
    pub until: Option<String>,
}

/// A page of a face's timeline.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TimelinePage {
    pub events: Vec<FaceEvent>,
    /// An opaque continuation; `None` at the end.
    pub next_cursor: Option<String>,
}

impl PersonaStore {
    /// Append an event to a face's history. See the module docs for why this
    /// logs rather than fails.
    pub(crate) async fn record_face_event(&self, profile_id: &str, event: FaceEvent) {
        let key = storage::face_event_key(profile_id, &ulid::Ulid::generate().to_string());
        if let Err(e) = self.ks.insert(key, &event).await {
            tracing::warn!(
                error = %e, profile_id, kind = ?event.kind,
                "could not record a face timeline event"
            );
        }
    }

    /// Record what a binding write changed: the face taken off (if any) and
    /// the face put on (if any). Rebinding the same face records nothing —
    /// nothing about what the face is worn by changed.
    pub(crate) async fn record_wearing(
        &self,
        context_id: &str,
        persona_did: &str,
        before: Option<&str>,
        after: Option<&str>,
    ) {
        if before == after {
            return;
        }
        if let Some(old) = before {
            self.record_face_event(
                old,
                FaceEvent::now(FaceEventKind::Unworn).worn_by(context_id, persona_did),
            )
            .await;
        }
        if let Some(new) = after {
            self.record_face_event(
                new,
                FaceEvent::now(FaceEventKind::Worn).worn_by(context_id, persona_did),
            )
            .await;
        }
    }

    /// Where a new `reach` would exclude a context the face is worn in now —
    /// the contexts `persona/profile/put` names in `boundOutsideReach`.
    pub async fn reach_would_exclude(
        &self,
        profile_id: &str,
        reach: &FaceReach,
    ) -> Result<Vec<String>, AppError> {
        let mut out: Vec<String> = self
            .bindings_to_anywhere(profile_id)
            .await?
            .into_iter()
            .map(|(ctx, _)| ctx)
            .filter(|ctx| !reach.admits(ctx))
            .collect();
        out.sort();
        out.dedup();
        Ok(out)
    }

    /// Remove a face's history with the face. The disclosure records it was
    /// joined with keep their own retention.
    pub(crate) async fn forget_face_events(&self, profile_id: &str) -> Result<(), AppError> {
        let keys = self
            .ks
            .prefix_keys(storage::face_event_prefix(profile_id).into_bytes())
            .await?;
        for k in keys {
            self.ks.remove(k).await?;
        }
        Ok(())
    }

    /// Where a face is worn now. `context_id` is the context of a
    /// context-local face; `None` a pool face. `NotFound` when there is no
    /// such face. Returns the face's reach beside the answer — `None` for a
    /// context-local face, which has none.
    pub async fn face_usage(
        &self,
        profile_id: &str,
        context_id: Option<&str>,
    ) -> Result<(Option<FaceReach>, Vec<Usage>), AppError> {
        let reach = match context_id {
            None => match self.get_profile(profile_id).await? {
                Some(p) => Some(p.reach),
                None => return Err(AppError::NotFound(format!("profile {profile_id}"))),
            },
            Some(ctx) => {
                if self.get_local_profile(ctx, profile_id).await?.is_none() {
                    return Err(AppError::NotFound(format!(
                        "context-local profile {profile_id} in {ctx}"
                    )));
                }
                None
            }
        };
        let rows = match context_id {
            None => self.ks.prefix_iter_raw(b"pb:".to_vec()).await?,
            Some(ctx) => {
                self.ks
                    .prefix_iter_raw(storage::binding_prefix(ctx).into_bytes())
                    .await?
            }
        };
        let mut out = Vec::new();
        for (k, v) in rows {
            let Some(record) = crate::binding::BindingRecord::decode(&v) else {
                continue;
            };
            if record.binding.profile_id.as_deref() != Some(profile_id) {
                continue;
            }
            // The context is the key's first segment; a persona DID has colons
            // of its own, so split once — see `bindings_to_anywhere`.
            let Some(ctx) = String::from_utf8(k).ok().and_then(|key| {
                key.strip_prefix("pb:")
                    .and_then(|rest| rest.split_once(':'))
                    .map(|(c, _)| c.to_string())
            }) else {
                continue;
            };
            out.push(Usage {
                context_id: ctx,
                persona_did: record.binding.persona_did,
                bound_at: record.binding.bound_at,
                until: record.binding.until,
            });
        }
        Ok((reach, out))
    }

    /// One face's history, oldest first: its own event log joined with the
    /// disclosures made through it. `NotFound` when there is no such face.
    ///
    /// A face composed before the log existed has no `composed` event; one is
    /// synthesised from the face's creation time, since the spec asks that a
    /// face's composition always be reported.
    pub async fn face_timeline(
        &self,
        profile_id: &str,
        context_id: Option<&str>,
        since: Option<&str>,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<TimelinePage, AppError> {
        let face = match context_id {
            None => self.get_profile(profile_id).await?,
            Some(ctx) => self.get_local_profile(ctx, profile_id).await?,
        }
        .ok_or_else(|| AppError::NotFound(format!("profile {profile_id}")))?;

        let mut events: Vec<(String, FaceEvent)> = self
            .ks
            .prefix_iter_raw(storage::face_event_prefix(profile_id).into_bytes())
            .await?
            .into_iter()
            .filter_map(|(k, v)| {
                let e = serde_json::from_slice::<FaceEvent>(&v).ok()?;
                Some((String::from_utf8(k).ok()?, e))
            })
            .collect();

        if !events
            .iter()
            .any(|(_, e)| e.kind == FaceEventKind::Composed)
        {
            events.push((
                String::new(),
                FaceEvent {
                    at: face.created_at.clone(),
                    ..FaceEvent::now(FaceEventKind::Composed)
                },
            ));
        }

        for record in self.disclosures_through(profile_id).await? {
            events.push((
                format!("pd:{}", record.disclosure_id),
                FaceEvent {
                    at: record.disclosed_at.clone(),
                    kind: FaceEventKind::Disclosed,
                    context_id: Some(record.context_id.clone()),
                    persona_did: Some(record.persona_did.clone()),
                    verifier_did: Some(record.verifier_did.clone()),
                    claim_types: record.claims.iter().map(|c| c.r#type.clone()).collect(),
                    version: None,
                },
            ));
        }

        // Time, then the recording key — stable across pages, and it keeps two
        // events recorded in one instant in the order they were written.
        events.sort_by(|a, b| {
            timestamp(&a.1.at)
                .cmp(&timestamp(&b.1.at))
                .then_with(|| a.0.cmp(&b.0))
        });
        if let Some(s) = since {
            let from = timestamp(s);
            events.retain(|(_, e)| timestamp(&e.at) >= from);
        }

        let start = match cursor {
            None => 0,
            Some(c) => c
                .strip_prefix("t:")
                .and_then(|n| n.parse::<usize>().ok())
                .ok_or_else(|| AppError::Validation("unrecognised cursor".into()))?,
        };
        let end = (start + limit).min(events.len());
        let page: Vec<FaceEvent> = events
            .get(start..end)
            .unwrap_or_default()
            .iter()
            .map(|(_, e)| e.clone())
            .collect();
        Ok(TimelinePage {
            events: page,
            next_cursor: (end < events.len()).then(|| format!("t:{end}")),
        })
    }

    /// Every disclosure made through a face — the same attribution
    /// [`Self::disclosed_to`] counts.
    pub(crate) async fn disclosures_through(
        &self,
        profile_id: &str,
    ) -> Result<Vec<crate::DisclosureRecord>, AppError> {
        let rows = self.ks.prefix_iter_raw(b"pd:".to_vec()).await?;
        let mut out = Vec::new();
        for (_k, v) in rows {
            let Ok(record) = serde_json::from_slice::<crate::DisclosureRecord>(&v) else {
                continue;
            };
            let through = match &record.profile_id {
                Some(p) => p == profile_id,
                None => self
                    .ks
                    .get::<crate::binding::BindingRecord>(storage::binding_key(
                        &record.context_id,
                        &record.persona_did,
                    ))
                    .await?
                    .is_some_and(|b| b.binding.profile_id.as_deref() == Some(profile_id)),
            };
            if through {
                out.push(record);
            }
        }
        Ok(out)
    }
}

/// An RFC 3339 time as a comparable instant. Unparseable sorts first, so a
/// malformed row cannot hide the rest of the timeline behind it.
fn timestamp(at: &str) -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::parse_from_rfc3339(at)
        .map(|t| t.with_timezone(&chrono::Utc))
        .unwrap_or(chrono::DateTime::<chrono::Utc>::MIN_UTC)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compose::{ComposeClaim, ComposeRequest, Share};
    use crate::model::{ProfileEntry, Provenance, ValueType};
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
        (dir, PersonaStore::new(ks, [17u8; 32]))
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

    async fn compose(
        s: &PersonaStore,
        ctx: &str,
        claims: Vec<ComposeClaim>,
        persona: Option<&str>,
    ) -> crate::Composed {
        s.compose(ComposeRequest {
            context_id: ctx.into(),
            name: "Secret filing name".into(),
            claims,
            persona_did: persona.map(str::to_string),
            label: persona.map(|_| "a private label".to_string()),
            until: None,
        })
        .await
        .unwrap()
    }

    fn kinds(page: &TimelinePage) -> Vec<FaceEventKind> {
        page.events.iter().map(|e| e.kind).collect()
    }

    #[tokio::test]
    async fn a_face_is_worn_only_where_its_reach_allows_and_reach_cannot_strand_a_wearer() {
        let (_d, s) = fresh().await;
        let c = compose(
            &s,
            "work",
            vec![typed("email.work", "a@w.test", Share::Pool)],
            Some("did:key:z6MkA"),
        )
        .await;
        let mut face = s.get_profile(&c.profile_id).await.unwrap().unwrap();

        // Narrowing past a context it is worn in is refused, naming it.
        face.reach = FaceReach::Only {
            context_ids: vec!["club".into()],
        };
        assert_eq!(
            s.reach_would_exclude(&c.profile_id, &face.reach)
                .await
                .unwrap(),
            vec!["work".to_string()]
        );
        assert!(s.put_profile(face.clone(), None).await.is_err());

        // A reach that keeps it keeps working, and anywhere else is refused.
        face.reach = FaceReach::Only {
            context_ids: vec!["work".into()],
        };
        s.put_profile(face, None).await.unwrap();
        assert!(
            s.set_binding(
                "club",
                "did:key:z6MkB",
                Some(&c.profile_id),
                vec![],
                None,
                None,
                None
            )
            .await
            .is_err()
        );
        let (reach, usage) = s.face_usage(&c.profile_id, None).await.unwrap();
        assert_eq!(
            reach,
            Some(FaceReach::Only {
                context_ids: vec!["work".into()]
            })
        );
        assert_eq!(usage.len(), 1);
        assert_eq!(usage[0].context_id, "work");
        assert_eq!(usage[0].persona_did, "did:key:z6MkA");
    }

    #[tokio::test]
    async fn the_timeline_joins_a_faces_history_and_carries_no_value_or_label() {
        let (_d, s) = fresh().await;
        let c = compose(
            &s,
            "conf",
            vec![typed("name.display", "Ada", Share::Pool)],
            Some("did:key:z6MkA"),
        )
        .await;
        let attribute = c.pooled[0].attribute_id.clone();

        // A value it shows changes.
        let mut a = s.get(&attribute).await.unwrap().unwrap();
        a.value = Some(json!("Ada King"));
        s.put(a, None).await.unwrap();

        // It tells someone something.
        let mut r = crate::new_disclosure(
            "conf",
            "did:web:verifier.test",
            "did:key:z6MkA",
            vec![crate::DisclosedClaim {
                r#type: "name.display".into(),
                rung: crate::ProofRung::Whole,
                value_blind: None,
            }],
        );
        r.profile_id = Some(c.profile_id.clone());
        s.record_disclosure(r).await.unwrap();

        s.retire_profile(&c.profile_id, None, None).await.unwrap();
        s.reinstate_profile(&c.profile_id, None, None)
            .await
            .unwrap();

        let page = s
            .face_timeline(&c.profile_id, None, None, None, 100)
            .await
            .unwrap();
        assert_eq!(
            kinds(&page),
            vec![
                FaceEventKind::Composed,
                FaceEventKind::Worn,
                FaceEventKind::ValueChanged,
                FaceEventKind::Disclosed,
                FaceEventKind::Unworn,
                FaceEventKind::Retired,
                FaceEventKind::Reinstated,
            ]
        );
        let changed = &page.events[2];
        assert_eq!(changed.claim_types, vec!["name.display".to_string()]);
        let disclosed = &page.events[3];
        assert_eq!(
            disclosed.verifier_did.as_deref(),
            Some("did:web:verifier.test")
        );

        // Never a value, never a private label — anywhere in it.
        let wire = serde_json::to_string(&page.events).unwrap();
        for secret in ["Ada", "Secret filing name", "a private label"] {
            assert!(!wire.contains(secret), "{secret} leaked into {wire}");
        }

        // Pages, stably.
        let first = s
            .face_timeline(&c.profile_id, None, None, None, 3)
            .await
            .unwrap();
        let rest = s
            .face_timeline(&c.profile_id, None, None, first.next_cursor.as_deref(), 100)
            .await
            .unwrap();
        assert!(rest.next_cursor.is_none());
        assert_eq!([kinds(&first), kinds(&rest)].concat(), kinds(&page));
    }

    #[tokio::test]
    async fn a_promoted_face_keeps_its_history_and_a_deleted_one_loses_it() {
        let (_d, s) = fresh().await;
        let c = compose(
            &s,
            "coop",
            vec![typed("email.personal", "a@p.test", Share::Local)],
            Some("did:key:z6MkA"),
        )
        .await;
        let v = s
            .get_local_profile("coop", &c.profile_id)
            .await
            .unwrap()
            .unwrap()
            .version;
        s.promote("coop", &c.profile_id, &[0], v).await.unwrap();
        let page = s
            .face_timeline(&c.profile_id, None, None, None, 100)
            .await
            .unwrap();
        let k = kinds(&page);
        assert_eq!(k.first(), Some(&FaceEventKind::Composed));
        assert!(k.contains(&FaceEventKind::Worn));
        assert_eq!(k.last(), Some(&FaceEventKind::Promoted));

        s.unbind_everywhere(&c.profile_id).await.unwrap();
        s.delete_profile(&c.profile_id).await.unwrap();
        assert!(
            s.ks.prefix_keys(storage::face_event_prefix(&c.profile_id).into_bytes())
                .await
                .unwrap()
                .is_empty(),
            "the history goes with the face"
        );
    }

    #[tokio::test]
    async fn a_face_from_before_the_log_still_reports_its_composition() {
        let (_d, s) = fresh().await;
        let a = crate::new_attribute(
            "phone.mobile",
            ValueType::String,
            json!("1"),
            Provenance::SelfAsserted,
        );
        s.put(a.clone(), None).await.unwrap();
        let face = crate::new_profile(
            "old",
            vec![ProfileEntry::Ref {
                r#ref: a.attribute_id.clone(),
                slot: None,
            }],
        );
        let id = face.profile_id.clone();
        s.put_profile(face, None).await.unwrap();
        s.forget_face_events(&id).await.unwrap();
        let page = s.face_timeline(&id, None, None, None, 10).await.unwrap();
        assert_eq!(kinds(&page), vec![FaceEventKind::Composed]);
    }

    #[tokio::test]
    async fn compose_can_set_until_and_refuses_one_in_the_past() {
        let (_d, s) = fresh().await;
        let mut r = ComposeRequest {
            context_id: "conf".into(),
            name: "Weekend".into(),
            claims: vec![typed("name.display", "Ada", Share::Local)],
            persona_did: Some("did:key:z6MkA".into()),
            label: None,
            until: Some((chrono::Utc::now() - chrono::Duration::hours(1)).to_rfc3339()),
        };
        assert_eq!(
            s.compose_refusal(&r).await.unwrap(),
            Some(crate::ComposeRefusal::UntilNotFuture)
        );
        r.until = Some((chrono::Utc::now() + chrono::Duration::days(2)).to_rfc3339());
        let c = s.compose(r).await.unwrap();
        let (_, usage) = s.face_usage(&c.profile_id, Some("conf")).await.unwrap();
        assert!(usage[0].until.is_some());
    }
}
