//! The holder's **annotations** on a contact — a star, a petname, the holder's
//! own lists, a directory link — and the lists themselves
//! (`persona/contact/put/1.2`, `persona/contact/lists/*`).
//!
//! What the holder keeps *about* a contact, as distinct from what the contact
//! disclosed, and so kept apart from it: annotations are **contact-level, not
//! revision-level**. Changing one appends no revision and moves no `rev`, and
//! no revision records one (put 1.1 item 7). They are stored beside the contact
//! (`pca:<context>:<contactId>`), not inside it, and go with it when it is
//! deleted (item 12).
//!
//! # They never leave the agent
//!
//! A community never stores who its members star or list — its operator would
//! hold the graph of who watches whom — so the holder's own agent keeps them,
//! and nothing here sends them anywhere: not to the contact, not to the
//! community a [`DirectoryRef`] names, not into any document the agent signs
//! (item 10). Nothing here logs a petname, a note or a list name (item 11).
//!
//! # Lists
//!
//! A list (`pcl:<context>:<listId>`) is context-scoped like the contacts it
//! holds: it may hold contacts known by any persona in its context and from any
//! number of communities, never a contact of another context. Deleting one
//! takes it off every contact in the same write (lists/delete item 2).

use serde::{Deserialize, Serialize};
use vti_common::error::AppError;

use crate::store::{PersonaStore, now_rfc3339};

/// The most lists one context holds (`lists/put` `tooManyLists`).
pub const MAX_LISTS: usize = 256;

/// A contact's link to the entry in a community's member directory it
/// corresponds to. Confers nothing: it names an entry, it is not evidence the
/// contact is a member there.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DirectoryRef {
    pub vtc_did: String,
    pub entry_id: String,
}

/// A contact's annotations (the note stays on [`crate::Contact`], where 1.0
/// kept it).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContactAnnotations {
    #[serde(default)]
    pub starred: bool,
    /// The holder's private name for the contact, as written: never folded or
    /// normalised (item 9).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub petname: Option<String>,
    /// A set; empty means on no list.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub lists: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub directory_ref: Option<DirectoryRef>,
}

/// One annotation's change: left as it is, replaced, or removed.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum Change<T> {
    #[default]
    Keep,
    Set(T),
    Remove,
}

impl<T: PartialEq + Clone> Change<T> {
    /// `current` after this change.
    fn apply(&self, current: Option<&T>) -> Option<T> {
        match self {
            Change::Keep => current.cloned(),
            Change::Set(v) => Some(v.clone()),
            Change::Remove => None,
        }
    }
}

/// What one request changes (item 6): each annotation given replaces the
/// stored one, each `Remove` removes one, each `Keep` leaves it, and `lists`
/// replaces the whole set.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AnnotationChange {
    pub starred: Option<bool>,
    pub petname: Change<String>,
    pub lists: Change<Vec<String>>,
    pub directory_ref: Change<DirectoryRef>,
    pub notes: Change<String>,
}

impl AnnotationChange {
    /// Whether it names any change at all.
    pub fn is_empty(&self) -> bool {
        self.starred.is_none()
            && self.petname == Change::Keep
            && self.lists == Change::Keep
            && self.directory_ref == Change::Keep
            && self.notes == Change::Keep
    }
}

/// Why an annotation change was refused.
#[derive(Debug)]
#[non_exhaustive]
pub enum AnnotateError {
    /// No such contact in this context.
    NotFound,
    /// `lists` names a list this context does not hold; nothing changed.
    ListUnknown(Vec<String>),
    Store(AppError),
}

impl From<AppError> for AnnotateError {
    fn from(e: AppError) -> Self {
        AnnotateError::Store(e)
    }
}

/// One of the holder's lists.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContactList {
    pub list_id: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub colour: Option<String>,
    pub order: u32,
    pub created_at: String,
    pub updated_at: String,
}

/// A list as a read answers it: with how many contacts are on it now.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListView {
    pub list: ContactList,
    pub contact_count: usize,
}

/// What a `lists/put` changes. `None` leaves a detail as it is.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ListChange {
    pub name: Option<String>,
    pub colour: Change<String>,
    pub order: Option<u32>,
}

/// Why a list write was refused.
#[derive(Debug)]
#[non_exhaustive]
pub enum ListError {
    NotFound,
    NameTaken,
    TooManyLists(usize),
    Store(AppError),
}

impl From<AppError> for ListError {
    fn from(e: AppError) -> Self {
        ListError::Store(e)
    }
}

fn annotations_key(context_id: &str, contact_id: &str) -> String {
    format!("pca:{context_id}:{contact_id}")
}

fn list_key(context_id: &str, list_id: &str) -> String {
    format!("pcl:{context_id}:{list_id}")
}

fn list_prefix(context_id: &str) -> String {
    format!("pcl:{context_id}:")
}

fn annotations_prefix(context_id: &str) -> String {
    format!("pca:{context_id}:")
}

impl PersonaStore {
    /// A contact's annotations: the default (nothing) for one never annotated.
    pub async fn contact_annotations(
        &self,
        context_id: &str,
        contact_id: &str,
    ) -> Result<ContactAnnotations, AppError> {
        Ok(self
            .ks
            .get::<ContactAnnotations>(annotations_key(context_id, contact_id))
            .await?
            .unwrap_or_default())
    }

    /// Every annotated contact in a context, by contact id.
    pub async fn context_annotations(
        &self,
        context_id: &str,
    ) -> Result<std::collections::HashMap<String, ContactAnnotations>, AppError> {
        let prefix = annotations_prefix(context_id);
        Ok(self
            .ks
            .prefix_iter_raw(prefix.clone().into_bytes())
            .await?
            .into_iter()
            .filter_map(|(k, v)| {
                let id = String::from_utf8_lossy(&k[prefix.len()..]).into_owned();
                serde_json::from_slice::<ContactAnnotations>(&v)
                    .ok()
                    .map(|a| (id, a))
            })
            .collect())
    }

    /// The list ids `lists` names that this context does not hold.
    async fn unknown_lists(
        &self,
        context_id: &str,
        lists: &[String],
    ) -> Result<Vec<String>, AppError> {
        let mut unknown = Vec::new();
        for id in lists {
            if self.ks.get_raw(list_key(context_id, id)).await?.is_none() {
                unknown.push(id.clone());
            }
        }
        Ok(unknown)
    }

    /// Refuse `change` before anything is written when it names a list this
    /// context does not hold (item 6).
    pub(crate) async fn check_annotation_change(
        &self,
        context_id: &str,
        change: &AnnotationChange,
    ) -> Result<(), AnnotateError> {
        if let Change::Set(lists) = &change.lists {
            let unknown = self.unknown_lists(context_id, lists).await?;
            if !unknown.is_empty() {
                return Err(AnnotateError::ListUnknown(unknown));
            }
        }
        Ok(())
    }

    /// Apply `change` to a contact, the write lock held by the caller. Returns
    /// whether anything changed: `false`, and nothing written, when every
    /// annotation given already matches and every one named for removal is
    /// already absent (item 8).
    pub(crate) async fn apply_annotations_locked(
        &self,
        context_id: &str,
        contact_id: &str,
        change: &AnnotationChange,
    ) -> Result<bool, AnnotateError> {
        let Some(mut contact) = self.get_contact(context_id, contact_id).await? else {
            return Err(AnnotateError::NotFound);
        };
        self.check_annotation_change(context_id, change).await?;
        let before = self.contact_annotations(context_id, contact_id).await?;
        let mut after = before.clone();
        if let Some(s) = change.starred {
            after.starred = s;
        }
        after.petname = change.petname.apply(before.petname.as_ref());
        after.directory_ref = change.directory_ref.apply(before.directory_ref.as_ref());
        after.lists = match &change.lists {
            Change::Keep => before.lists.clone(),
            Change::Set(l) => {
                let mut l = l.clone();
                l.sort();
                l.dedup();
                l
            }
            Change::Remove => Vec::new(),
        };
        let mut sorted_before = before.lists.clone();
        sorted_before.sort();
        let lists_same = sorted_before == after.lists;
        let notes = change.notes.apply(contact.notes.as_ref());
        let notes_changed = notes != contact.notes;
        let annotations_changed = after.starred != before.starred
            || after.petname != before.petname
            || after.directory_ref != before.directory_ref
            || !lists_same;
        if annotations_changed {
            if after == ContactAnnotations::default() {
                self.ks
                    .remove(annotations_key(context_id, contact_id))
                    .await?;
            } else {
                self.ks
                    .insert(annotations_key(context_id, contact_id), &after)
                    .await?;
            }
        }
        if notes_changed {
            contact.notes = notes;
            self.ks
                .insert(
                    crate::storage::contact_key(context_id, contact_id),
                    &contact,
                )
                .await?;
        }
        Ok(annotations_changed || notes_changed)
    }

    /// Change a contact's annotations without filing anything (the annotating
    /// form): no revision is appended and `rev` does not move (item 7).
    pub async fn annotate_contact(
        &self,
        context_id: &str,
        contact_id: &str,
        change: &AnnotationChange,
    ) -> Result<bool, AnnotateError> {
        let _guard = self.write_lock.lock().await;
        self.apply_annotations_locked(context_id, contact_id, change)
            .await
    }

    /// The linking form (put 1.1 item 4): the contact this context keeps for
    /// the directory entry `directory_ref` and the persona `known_by_persona`,
    /// made on the first request for that key — `rev` 1, an empty document, no
    /// subject DID — with `change` applied, appending no revision. Never the
    /// contact a filing made, whatever its directory link: the two are not
    /// merged. Returns `(contact id, rev, created, annotations changed)`.
    pub async fn link_contact(
        &self,
        context_id: &str,
        directory_ref: &DirectoryRef,
        known_by_persona: &str,
        change: &AnnotationChange,
    ) -> Result<(String, u64, bool, bool), AnnotateError> {
        let _guard = self.write_lock.lock().await;
        self.check_annotation_change(context_id, change).await?;
        let annotations = self.context_annotations(context_id).await?;
        let found = self
            .list_contacts(context_id, Some(known_by_persona))
            .await?
            .into_iter()
            .find(|c| {
                c.subject_did.is_empty()
                    && annotations
                        .get(&c.contact_id)
                        .and_then(|a| a.directory_ref.as_ref())
                        == Some(directory_ref)
            });
        let mut change = change.clone();
        change.directory_ref = Change::Set(directory_ref.clone());
        if let Some(c) = found {
            let changed = self
                .apply_annotations_locked(context_id, &c.contact_id, &change)
                .await?;
            return Ok((c.contact_id, c.rev, false, changed));
        }
        let contact = crate::Contact {
            contact_id: ulid::Ulid::generate().to_string(),
            // A linked contact has no DID: the holder was not shown one.
            subject_did: String::new(),
            known_by_persona: known_by_persona.to_string(),
            rev: 1,
            document: crate::ContactDocument {
                publisher: None,
                card_version: None,
                claims: Vec::new(),
            },
            credential_refs: Vec::new(),
            notes: None,
            has_unreviewed_change: false,
            received_at: Some(now_rfc3339()),
        };
        self.ks
            .insert(
                crate::storage::contact_key(context_id, &contact.contact_id),
                &contact,
            )
            .await?;
        self.apply_annotations_locked(context_id, &contact.contact_id, &change)
            .await?;
        Ok((contact.contact_id, 1, true, true))
    }

    /// Forget a deleted contact's annotations (item 12).
    pub(crate) async fn forget_annotations(
        &self,
        context_id: &str,
        contact_id: &str,
    ) -> Result<(), AppError> {
        self.ks
            .remove(annotations_key(context_id, contact_id))
            .await
    }

    // ─── lists ────────────────────────────────────────────────────────────

    /// One list, with its contact count now.
    pub async fn contact_list(
        &self,
        context_id: &str,
        list_id: &str,
    ) -> Result<Option<ListView>, AppError> {
        let Some(list) = self
            .ks
            .get::<ContactList>(list_key(context_id, list_id))
            .await?
        else {
            return Ok(None);
        };
        let count = self
            .context_annotations(context_id)
            .await?
            .values()
            .filter(|a| a.lists.iter().any(|l| l == list_id))
            .count();
        Ok(Some(ListView {
            list,
            contact_count: count,
        }))
    }

    /// A context's lists, ordered by `order` then `name`, each with its count.
    pub async fn contact_lists(&self, context_id: &str) -> Result<Vec<ListView>, AppError> {
        let annotations = self.context_annotations(context_id).await?;
        let mut out: Vec<ListView> = self
            .ks
            .prefix_iter_raw(list_prefix(context_id).into_bytes())
            .await?
            .into_iter()
            .filter_map(|(_, v)| serde_json::from_slice::<ContactList>(&v).ok())
            .map(|list| {
                let contact_count = annotations
                    .values()
                    .filter(|a| a.lists.contains(&list.list_id))
                    .count();
                ListView {
                    list,
                    contact_count,
                }
            })
            .collect();
        out.sort_by(|a, b| {
            a.list
                .order
                .cmp(&b.list.order)
                .then_with(|| a.list.name.cmp(&b.list.name))
                .then_with(|| a.list.list_id.cmp(&b.list.list_id))
        });
        Ok(out)
    }

    /// Create a list (`list_id: None`) or change one. Returns the list, whether
    /// it was created, and whether anything changed (lists/put items 2 – 5).
    pub async fn put_contact_list(
        &self,
        context_id: &str,
        list_id: Option<&str>,
        change: ListChange,
    ) -> Result<(ListView, bool, bool), ListError> {
        let _guard = self.write_lock.lock().await;
        let existing = self.contact_lists(context_id).await?;
        let taken = |name: &str, except: Option<&str>| {
            existing
                .iter()
                .any(|v| v.list.name == name && Some(v.list.list_id.as_str()) != except)
        };
        let now = now_rfc3339();
        match list_id {
            None => {
                let Some(name) = change.name else {
                    return Err(ListError::Store(AppError::Validation(
                        "a new list has a name".into(),
                    )));
                };
                if taken(&name, None) {
                    return Err(ListError::NameTaken);
                }
                if existing.len() >= MAX_LISTS {
                    return Err(ListError::TooManyLists(MAX_LISTS));
                }
                // After every existing list, unless placed (item 2).
                let order = change.order.unwrap_or_else(|| {
                    existing
                        .iter()
                        .map(|v| v.list.order)
                        .max()
                        .map_or(0, |m| m.saturating_add(10).min(1_000_000))
                });
                let list = ContactList {
                    list_id: ulid::Ulid::generate().to_string(),
                    name,
                    colour: match change.colour {
                        Change::Set(c) => Some(c),
                        _ => None,
                    },
                    order,
                    created_at: now.clone(),
                    updated_at: now,
                };
                self.ks
                    .insert(list_key(context_id, &list.list_id), &list)
                    .await?;
                Ok((
                    ListView {
                        list,
                        contact_count: 0,
                    },
                    true,
                    true,
                ))
            }
            Some(id) => {
                let Some(current) = existing.iter().find(|v| v.list.list_id == id).cloned() else {
                    return Err(ListError::NotFound);
                };
                let mut next = current.list.clone();
                if let Some(name) = change.name {
                    if name != next.name && taken(&name, Some(id)) {
                        return Err(ListError::NameTaken);
                    }
                    next.name = name;
                }
                next.colour = change.colour.apply(next.colour.as_ref());
                if let Some(order) = change.order {
                    next.order = order;
                }
                if next == current.list {
                    return Ok((current, false, false));
                }
                next.updated_at = now;
                self.ks.insert(list_key(context_id, id), &next).await?;
                Ok((
                    ListView {
                        list: next,
                        contact_count: current.contact_count,
                    },
                    false,
                    true,
                ))
            }
        }
    }

    /// Delete a list and take it off every contact, together. Returns
    /// `(existed, contacts updated)`; no contact is deleted or revised.
    pub async fn delete_contact_list(
        &self,
        context_id: &str,
        list_id: &str,
    ) -> Result<(bool, usize), AppError> {
        let _guard = self.write_lock.lock().await;
        if self
            .ks
            .get_raw(list_key(context_id, list_id))
            .await?
            .is_none()
        {
            return Ok((false, 0));
        }
        let mut batch = vti_common::store::Batch::new();
        let mut updated = 0;
        for (contact_id, mut a) in self.context_annotations(context_id).await? {
            if !a.lists.iter().any(|l| l == list_id) {
                continue;
            }
            a.lists.retain(|l| l != list_id);
            updated += 1;
            let key = annotations_key(context_id, &contact_id);
            if a == ContactAnnotations::default() {
                batch.remove(key);
            } else {
                batch.insert(key, &a)?;
            }
        }
        batch.remove(list_key(context_id, list_id));
        self.ks.apply_batch(batch).await?;
        Ok((true, updated))
    }
}
