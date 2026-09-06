//! Contacts: what a peer disclosed, filed by revision.
//!
//! Two properties are not negotiable, and both exist because an address book
//! that quietly changes is worse than one that does not exist.
//!
//! **Revisioned, never overwritten.** When a peer re-discloses, the previous
//! document is kept and the new one becomes current. An address book that
//! silently replaces a payment address is a phishing surface; one that reports
//! *"this changed four minutes ago, here is what it was"* is a defence. A
//! revision history nobody is shown is an archive, not a defence — which is
//! what [`ContactSummary::has_unreviewed_change`] and [`Filed::changed_claims`]
//! are for.
//!
//! **A contact belongs to a relationship, not to the holder at large.** The
//! same peer met through two personas is two contacts. Collapsing them would
//! correlate the holder's own personas *inside their own address book* — the
//! one place nobody would think to look for that linkage.
//!
//! # Retention is reference-counted, not a timer
//!
//! A superseded revision is reaped after a retention window **unless something
//! still points at it**. A revision behind a disclosure record is evidence of
//! what the holder was shown before they presented, and a flat TTL would delete
//! it precisely when it mattered. See [`PersonaStore::reap_contact_revisions`].

use serde::{Deserialize, Serialize};
use vti_common::error::AppError;

use crate::model::Ulid;
use crate::storage;
use crate::store::{PersonaStore, now_rfc3339};

/// A claim as a peer disclosed it.
///
/// Structurally the claim set a holder composes — a profile and a contact card
/// are one schema seen from two sides — which is why one validator serves both.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContactClaim {
    pub r#type: String,
    pub value: serde_json::Value,
    /// What the value is.
    ///
    /// Required by the published document schema on both the way in and the way
    /// out. It was missing from this struct entirely, so `contact/put` silently
    /// dropped whatever the peer sent and `contact/get` could not emit it —
    /// the response failed schema validation with `"valueType" is a required
    /// property`. Nothing noticed, because the contact family had no test.
    pub value_type: crate::ValueType,
    /// As **asserted by the publisher**. A recipient must not treat a claimed
    /// credential-backed provenance as verified: it states what the publisher
    /// says backs the claim, and verification is a separate act against the
    /// credential itself.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance: Option<crate::Provenance>,
}

/// What a peer published, as received.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContactDocument {
    /// The DID that published it. Normally pairwise, so it names the
    /// relationship rather than the person across all of theirs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub publisher: Option<String>,
    /// The publisher's own counter, if supplied. **Advisory**: it orders the
    /// publisher's revisions relative to each other and must never be used to
    /// order them against anything else — a recipient counts what it received,
    /// which is the only sequence it can vouch for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub card_version: Option<u64>,
    pub claims: Vec<ContactClaim>,
}

/// One received version of a contact's document.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContactRevision {
    /// Assigned by the recipient, monotonic per contact.
    pub rev: u64,
    pub received_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub superseded_at: Option<String>,
    pub document: ContactDocument,
    /// Set when a disclosure record cites this revision. A cited revision is
    /// evidence the holder can still be asked to account for, so retention
    /// counts references rather than days.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub cited: bool,
}

/// A contact's current state.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Contact {
    pub contact_id: Ulid,
    pub subject_did: String,
    /// Which of the holder's personas knows this contact. Part of the identity
    /// of the record, not a tag on it.
    pub known_by_persona: String,
    pub rev: u64,
    pub document: ContactDocument,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub credential_refs: Vec<String>,
    /// The holder's private note. Never disclosed to anyone, including the
    /// contact it is about — which makes it the most sensitive member here,
    /// because its subject cannot see it and never consented to it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    pub has_unreviewed_change: bool,
}

/// Outcome of filing a disclosure.
#[derive(Clone, Debug, PartialEq)]
pub struct Filed {
    pub contact_id: Ulid,
    pub rev: u64,
    pub created: bool,
    /// Claim **types** whose value differs from the previous revision.
    ///
    /// Types, not values: this is what turns a history into a defence, and a
    /// producer that needs the old value reads the prior revision, which is an
    /// explicit act.
    pub changed_claims: Vec<String>,
}

/// What a listing shows. No claim values — finding one contact does not require
/// disclosing the details of every contact.
#[derive(Clone, Debug, PartialEq)]
pub struct ContactSummary {
    pub contact_id: Ulid,
    pub subject_did: String,
    pub known_by_persona: String,
    pub rev: u64,
    pub claim_count: usize,
    pub received_at: String,
    pub has_unreviewed_change: bool,
}

impl PersonaStore {
    /// File what a peer disclosed, appending a revision.
    ///
    /// Keyed on `(context, subject, known_by_persona)`: the same peer met
    /// through two personas is two contacts, deliberately.
    pub async fn file_contact(
        &self,
        context_id: &str,
        subject_did: &str,
        known_by_persona: &str,
        document: ContactDocument,
        credential_refs: Vec<String>,
        notes: Option<String>,
    ) -> Result<Filed, AppError> {
        let _guard = self.write_lock.lock().await;

        let existing = self
            .find_contact(context_id, subject_did, known_by_persona)
            .await?;

        // A supplied note replaces; an omitted one PRESERVES what is there.
        //
        // The wire member is optional, and a peer re-disclosing their card must
        // not wipe the holder's private annotation about them — the note is the
        // holder's, and nothing the subject sends should be able to clear it.
        // Before this parameter existed the note could not be set at all:
        // `contact/put` accepted `notes` on the wire and dropped it on the
        // floor, so a member documented as "the holder's private annotation"
        // was never stored.
        let (contact_id, rev, created, changed, prior_notes) = match existing {
            None => (ulid::Ulid::new().to_string(), 1u64, true, Vec::new(), None),
            Some(prev) => {
                let changed = diff_claims(&prev.document, &document);
                // Archive the outgoing revision before the new one lands, so a
                // crash leaves a duplicate rather than a gap. A gap in a history
                // that exists to prove what changed is worse than a repeat.
                self.ks
                    .insert(
                        storage::contact_revision_key(context_id, &prev.contact_id, prev.rev),
                        &ContactRevision {
                            rev: prev.rev,
                            received_at: now_rfc3339(),
                            superseded_at: Some(now_rfc3339()),
                            document: prev.document.clone(),
                            cited: false,
                        },
                    )
                    .await?;
                (prev.contact_id, prev.rev + 1, false, changed, prev.notes)
            }
        };

        let contact = Contact {
            contact_id: contact_id.clone(),
            subject_did: subject_did.to_string(),
            known_by_persona: known_by_persona.to_string(),
            rev,
            document,
            credential_refs,
            notes: notes.or(prior_notes),
            // A change nobody has looked at yet is the whole reason to keep
            // revisions; a producer clears it when the holder has seen the diff.
            has_unreviewed_change: !created && !changed.is_empty(),
        };
        self.ks
            .insert(storage::contact_key(context_id, &contact_id), &contact)
            .await?;

        Ok(Filed {
            contact_id,
            rev,
            created,
            changed_claims: changed,
        })
    }

    pub async fn get_contact(
        &self,
        context_id: &str,
        contact_id: &str,
    ) -> Result<Option<Contact>, AppError> {
        self.ks
            .get::<Contact>(storage::contact_key(context_id, contact_id))
            .await
    }

    /// A specific revision.
    ///
    /// `Gone` — not `NotFound` — for a revision that existed and was reaped. A
    /// caller comparing a current value against history must tell *never
    /// existed* from *no longer kept*: the first means their premise was wrong,
    /// the second means their comparison is unsound. Collapsing the two lets a
    /// producer conclude "nothing changed" from an absence that means the
    /// opposite.
    pub async fn get_contact_revision(
        &self,
        context_id: &str,
        contact_id: &str,
        rev: u64,
    ) -> Result<ContactRevision, AppError> {
        if let Some(r) = self
            .ks
            .get::<ContactRevision>(storage::contact_revision_key(context_id, contact_id, rev))
            .await?
        {
            return Ok(r);
        }
        let current = self.get_contact(context_id, contact_id).await?;
        match current {
            Some(c) if c.rev == rev => Ok(ContactRevision {
                rev: c.rev,
                received_at: now_rfc3339(),
                superseded_at: None,
                document: c.document,
                cited: false,
            }),
            Some(c) if rev < c.rev => Err(AppError::Gone(format!(
                "revision {rev} of contact {contact_id} has been reaped"
            ))),
            _ => Err(AppError::NotFound(format!(
                "contact {contact_id} has no revision {rev}"
            ))),
        }
    }

    /// Revision metadata without documents — a timeline is cheap and the
    /// documents behind it are not.
    pub async fn contact_history(
        &self,
        context_id: &str,
        contact_id: &str,
    ) -> Result<Vec<(u64, String, bool)>, AppError> {
        let rows = self
            .ks
            .prefix_iter_raw(storage::contact_revision_prefix(context_id, contact_id).into_bytes())
            .await?;
        Ok(rows
            .into_iter()
            .filter_map(|(_k, v)| serde_json::from_slice::<ContactRevision>(&v).ok())
            .map(|r| (r.rev, r.received_at, r.cited))
            .collect())
    }

    async fn find_contact(
        &self,
        context_id: &str,
        subject_did: &str,
        known_by_persona: &str,
    ) -> Result<Option<Contact>, AppError> {
        Ok(self
            .list_contacts(context_id, None)
            .await?
            .into_iter()
            .find(|c| c.subject_did == subject_did && c.known_by_persona == known_by_persona))
    }

    /// Contacts in a context, optionally narrowed to one persona.
    ///
    /// The unfiltered view puts the holder's personas side by side, which is a
    /// map of their compartmentalisation — a producer should offer it
    /// deliberately rather than by default.
    pub async fn list_contacts(
        &self,
        context_id: &str,
        known_by_persona: Option<&str>,
    ) -> Result<Vec<Contact>, AppError> {
        let rows = self
            .ks
            .prefix_iter_raw(storage::contact_prefix(context_id).into_bytes())
            .await?;
        Ok(rows
            .into_iter()
            .filter_map(|(_k, v)| serde_json::from_slice::<Contact>(&v).ok())
            .filter(|c| known_by_persona.is_none_or(|p| c.known_by_persona == p))
            .collect())
    }

    pub async fn list_contact_summaries(
        &self,
        context_id: &str,
        known_by_persona: Option<&str>,
    ) -> Result<Vec<ContactSummary>, AppError> {
        Ok(self
            .list_contacts(context_id, known_by_persona)
            .await?
            .into_iter()
            .map(|c| ContactSummary {
                contact_id: c.contact_id,
                subject_did: c.subject_did,
                known_by_persona: c.known_by_persona,
                rev: c.rev,
                claim_count: c.document.claims.len(),
                received_at: now_rfc3339(),
                has_unreviewed_change: c.has_unreviewed_change,
            })
            .collect())
    }

    /// Mark a revision as cited by a disclosure record, exempting it from
    /// reaping.
    pub async fn cite_contact_revision(
        &self,
        context_id: &str,
        contact_id: &str,
        rev: u64,
    ) -> Result<(), AppError> {
        let key = storage::contact_revision_key(context_id, contact_id, rev);
        if let Some(mut r) = self.ks.get::<ContactRevision>(key.clone()).await? {
            r.cited = true;
            self.ks.insert(key, &r).await?;
        }
        Ok(())
    }

    /// Remove a contact and every revision **not cited by a disclosure record**.
    ///
    /// Returns `(existed, removed, retained)`. A maintainer must report the
    /// retained count rather than let the holder believe the deletion was
    /// total: an incomplete erasure the holder thinks is complete is worse than
    /// one they know about, because they will make the next decision on a false
    /// premise.
    pub async fn delete_contact(
        &self,
        context_id: &str,
        contact_id: &str,
    ) -> Result<(bool, usize, usize), AppError> {
        let _guard = self.write_lock.lock().await;

        let existed = self.get_contact(context_id, contact_id).await?.is_some();
        if existed {
            self.ks
                .remove(storage::contact_key(context_id, contact_id))
                .await?;
        }

        let rows = self
            .ks
            .prefix_iter_raw(storage::contact_revision_prefix(context_id, contact_id).into_bytes())
            .await?;
        let (mut removed, mut retained) = (0usize, 0usize);
        for (k, v) in rows {
            match serde_json::from_slice::<ContactRevision>(&v) {
                Ok(r) if r.cited => retained += 1,
                _ => {
                    self.ks.remove(k).await?;
                    removed += 1;
                }
            }
        }
        Ok((existed, removed, retained))
    }

    /// Reap superseded revisions older than `retain_days`, **except** those a
    /// disclosure record cites.
    ///
    /// Reference-counted rather than a flat timer, because a flat timer deletes
    /// the evidence behind a disclosure precisely when it matters. Returns how
    /// many were removed.
    pub async fn reap_contact_revisions(
        &self,
        context_id: &str,
        contact_id: &str,
        retain_days: i64,
    ) -> Result<usize, AppError> {
        let _guard = self.write_lock.lock().await;
        let cutoff = chrono::Utc::now() - chrono::Duration::days(retain_days);

        let rows = self
            .ks
            .prefix_iter_raw(storage::contact_revision_prefix(context_id, contact_id).into_bytes())
            .await?;
        let mut removed = 0usize;
        for (k, v) in rows {
            let Ok(r) = serde_json::from_slice::<ContactRevision>(&v) else {
                continue;
            };
            if r.cited {
                continue;
            }
            let superseded = r
                .superseded_at
                .as_deref()
                .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok());
            if superseded.is_some_and(|t| t < cutoff) {
                self.ks.remove(k).await?;
                removed += 1;
            }
        }
        Ok(removed)
    }
}

/// Claim types whose value differs between two documents.
///
/// A type appearing in one and not the other counts as changed: a claim that
/// vanished is exactly as much of an event as one that moved, and a diff that
/// reported only mutations would stay quiet when a peer stopped disclosing
/// their payment address.
fn diff_claims(previous: &ContactDocument, next: &ContactDocument) -> Vec<String> {
    let mut changed = Vec::new();
    for c in &next.claims {
        match previous.claims.iter().find(|p| p.r#type == c.r#type) {
            Some(p) if p.value == c.value => {}
            _ => changed.push(c.r#type.clone()),
        }
    }
    for p in &previous.claims {
        if !next.claims.iter().any(|c| c.r#type == p.r#type) {
            changed.push(p.r#type.clone());
        }
    }
    changed.sort();
    changed.dedup();
    changed
}

#[cfg(test)]
mod tests {
    use super::*;
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

    fn doc(pairs: &[(&str, &str)]) -> ContactDocument {
        ContactDocument {
            publisher: Some("did:peer:2.Ez6".into()),
            card_version: None,
            claims: pairs
                .iter()
                .map(|(t, v)| ContactClaim {
                    value_type: crate::ValueType::String,
                    r#type: (*t).into(),
                    value: serde_json::json!(v),
                    provenance: None,
                })
                .collect(),
        }
    }

    #[tokio::test]
    async fn re_disclosure_appends_and_reports_what_changed() {
        // The whole reason to keep revisions: a silently replaced payment
        // address is a phishing surface, and naming the change is the defence.
        let (_d, s) = fresh().await;
        let first = s
            .file_contact(
                "ctx",
                "did:bob",
                "did:me",
                doc(&[("payment.address", "acct-1")]),
                vec![],
                None,
            )
            .await
            .unwrap();
        assert!(first.created && first.rev == 1 && first.changed_claims.is_empty());

        let second = s
            .file_contact(
                "ctx",
                "did:bob",
                "did:me",
                doc(&[("payment.address", "acct-2")]),
                vec![],
                None,
            )
            .await
            .unwrap();
        assert!(!second.created);
        assert_eq!(second.rev, 2);
        assert_eq!(second.changed_claims, vec!["payment.address"]);
        assert_eq!(
            second.contact_id, first.contact_id,
            "same relationship, same contact"
        );

        let c = s
            .get_contact("ctx", &first.contact_id)
            .await
            .unwrap()
            .unwrap();
        assert!(
            c.has_unreviewed_change,
            "a change nobody has seen must be badgeable"
        );
        // And the prior document survives.
        let prev = s
            .get_contact_revision("ctx", &first.contact_id, 1)
            .await
            .unwrap();
        assert_eq!(prev.document.claims[0].value, serde_json::json!("acct-1"));
    }

    #[tokio::test]
    async fn a_claim_that_vanishes_counts_as_a_change() {
        // A diff reporting only mutations stays quiet when a peer STOPS
        // disclosing something, which is exactly when it should speak up.
        let (_d, s) = fresh().await;
        s.file_contact(
            "ctx",
            "did:bob",
            "did:me",
            doc(&[("email", "a"), ("phone", "b")]),
            vec![],
            None,
        )
        .await
        .unwrap();
        let f = s
            .file_contact(
                "ctx",
                "did:bob",
                "did:me",
                doc(&[("email", "a")]),
                vec![],
                None,
            )
            .await
            .unwrap();
        assert_eq!(f.changed_claims, vec!["phone"]);
    }

    #[tokio::test]
    async fn the_same_peer_through_two_personas_is_two_contacts() {
        // Collapsing them would correlate the holder's own personas inside
        // their own address book — the one place nobody would look.
        let (_d, s) = fresh().await;
        let a = s
            .file_contact(
                "ctx",
                "did:bob",
                "did:work",
                doc(&[("email", "x")]),
                vec![],
                None,
            )
            .await
            .unwrap();
        let b = s
            .file_contact(
                "ctx",
                "did:bob",
                "did:play",
                doc(&[("email", "x")]),
                vec![],
                None,
            )
            .await
            .unwrap();
        assert_ne!(a.contact_id, b.contact_id);
        assert!(b.created, "the second persona starts its own history");

        assert_eq!(
            s.list_contacts("ctx", Some("did:work"))
                .await
                .unwrap()
                .len(),
            1
        );
        assert_eq!(s.list_contacts("ctx", None).await.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn a_reaped_revision_is_gone_not_missing() {
        // A caller comparing against history must tell "never existed" from
        // "no longer kept": only the second means their comparison is unsound.
        let (_d, s) = fresh().await;
        let f = s
            .file_contact(
                "ctx",
                "did:bob",
                "did:me",
                doc(&[("email", "a")]),
                vec![],
                None,
            )
            .await
            .unwrap();
        s.file_contact(
            "ctx",
            "did:bob",
            "did:me",
            doc(&[("email", "b")]),
            vec![],
            None,
        )
        .await
        .unwrap();

        assert_eq!(
            s.reap_contact_revisions("ctx", &f.contact_id, 0)
                .await
                .unwrap(),
            1
        );

        let err = s
            .get_contact_revision("ctx", &f.contact_id, 1)
            .await
            .unwrap_err();
        assert!(matches!(err, AppError::Gone(_)), "reaped, got {err:?}");

        let never = s
            .get_contact_revision("ctx", &f.contact_id, 99)
            .await
            .unwrap_err();
        assert!(
            matches!(never, AppError::NotFound(_)),
            "never existed, got {never:?}"
        );
    }

    #[tokio::test]
    async fn a_cited_revision_survives_reaping_and_deletion() {
        // Retention counts references, not days: a revision behind a disclosure
        // record is evidence the holder can still be asked to account for.
        let (_d, s) = fresh().await;
        let f = s
            .file_contact(
                "ctx",
                "did:bob",
                "did:me",
                doc(&[("email", "a")]),
                vec![],
                None,
            )
            .await
            .unwrap();
        s.file_contact(
            "ctx",
            "did:bob",
            "did:me",
            doc(&[("email", "b")]),
            vec![],
            None,
        )
        .await
        .unwrap();
        s.cite_contact_revision("ctx", &f.contact_id, 1)
            .await
            .unwrap();

        assert_eq!(
            s.reap_contact_revisions("ctx", &f.contact_id, 0)
                .await
                .unwrap(),
            0,
            "a cited revision is exempt from the retention window"
        );

        let (existed, removed, retained) = s.delete_contact("ctx", &f.contact_id).await.unwrap();
        assert!(existed);
        assert_eq!(removed, 0);
        assert_eq!(retained, 1, "and the deletion must report what it kept");
    }

    #[tokio::test]
    async fn a_summary_carries_no_claim_values() {
        let (_d, s) = fresh().await;
        s.file_contact(
            "ctx",
            "did:bob",
            "did:me",
            doc(&[("email", "secret-address")]),
            vec![],
            None,
        )
        .await
        .unwrap();
        let sums = s.list_contact_summaries("ctx", None).await.unwrap();
        assert_eq!(sums[0].claim_count, 1);
        assert!(!format!("{sums:?}").contains("secret-address"));
    }
}
