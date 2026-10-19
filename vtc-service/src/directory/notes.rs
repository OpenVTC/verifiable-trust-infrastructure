//! Administrators' notes about members (`vtc/directory/notes/*`,
//! VTI-DIR-030 – 033).
//!
//! **Apart from the card.** A note is never a field, never in a projection,
//! and no read of the directory reaches one, whatever a policy returns
//! (VTI-DIR-030): a field "only administrators can see" is one ceiling or one
//! policy away from members, and a note that is not on the card is not. Only
//! holders of `vtc.directory.notes` read or write them.
//!
//! **Append-only.** A note is never altered. A correction or withdrawal is a
//! later note that `redacts` it (VTI-DIR-031); the redacted note's text is then
//! withheld from every read but `notes/export`, which answers the member's own
//! request for the data held about them.
//!
//! Notes are keyed by the entry, never the member's DID, so a rotation moves
//! nothing (VTI-DIR-122). At departure they follow the disposition: a purge
//! erases them, and a tombstone or historical record keeps them for the
//! directory's retention period, after which the directory pass erases them.
//!
//! Rows in the `directory` keyspace: `note:<entryId>:<seq>` ([`Note`], `seq`
//! zero-padded so the rows sort oldest first) and `notes-departed:<entryId>`
//! (when the kept notes of a departed member are erased).

use base64::Engine as _;
use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use vti_common::error::AppError;
use vti_common::store::{Batch, KeyspaceHandle};

/// A note as stored. [`Note::wire`] is the `AdminNote` a reader receives.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Note {
    pub note_id: String,
    pub entry_id: String,
    pub author: String,
    pub created_at: DateTime<Utc>,
    /// Absent on a redaction that says nothing of its own.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub follow_up: Option<NaiveDate>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redacts: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redacted_by: Option<String>,
}

impl Note {
    /// The `AdminNote` for `notes/list`: a redacted note without its text.
    pub fn wire(&self) -> Value {
        self.wire_with(self.redacted_by.is_none())
    }

    /// The `AdminNote` for `notes/export`: every note as written.
    pub fn wire_whole(&self) -> Value {
        self.wire_with(true)
    }

    fn wire_with(&self, with_text: bool) -> Value {
        let mut out = json!({
            "noteId": self.note_id,
            "entryId": self.entry_id,
            "author": self.author,
            "createdAt": self.created_at,
        });
        if let (true, Some(t)) = (with_text, &self.text) {
            out["text"] = Value::String(t.clone());
        }
        if let Some(d) = self.follow_up {
            out["followUp"] = Value::String(d.format("%Y-%m-%d").to_string());
        }
        if let Some(r) = &self.redacts {
            out["redacts"] = Value::String(r.clone());
        }
        if let Some(r) = &self.redacted_by {
            out["redactedBy"] = Value::String(r.clone());
        }
        out
    }
}

fn prefix(entry_id: &str) -> Vec<u8> {
    format!("note:{entry_id}:").into_bytes()
}

fn note_key(entry_id: &str, seq: u64) -> Vec<u8> {
    format!("note:{entry_id}:{seq:020}").into_bytes()
}

fn departed_key(entry_id: &str) -> Vec<u8> {
    format!("notes-departed:{entry_id}").into_bytes()
}

/// A fresh note identifier: `note_` and 22 base64url characters of
/// randomness.
pub fn new_note_id() -> String {
    let mut bytes = [0u8; 16];
    rand::fill(&mut bytes);
    format!(
        "note_{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    )
}

/// Every note about `entry_id`, oldest first, each with its row key.
pub async fn all_for(
    ks: &KeyspaceHandle,
    entry_id: &str,
) -> Result<Vec<(Vec<u8>, Note)>, AppError> {
    ks.prefix_iter_raw(prefix(entry_id))
        .await?
        .into_iter()
        .map(|(k, raw)| {
            serde_json::from_slice::<Note>(&raw)
                .map(|n| (k, n))
                .map_err(|e| AppError::Internal(format!("stored note is unreadable: {e}")))
        })
        .collect()
}

/// Why an append was refused — one variant per declared code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AppendError {
    NoteNotFound,
    AlreadyRedacted,
    /// Neither text nor a redaction: nothing to append.
    Empty,
}

/// What one append asks for: text, or a redaction of an earlier note (the
/// payload is one or the other).
#[derive(Debug, Clone, Default)]
pub struct NewNote {
    pub text: Option<String>,
    pub follow_up: Option<NaiveDate>,
    pub redacts: Option<String>,
}

/// Whether `new` could be appended about `entry_id` now — the refusals
/// [`append`] makes, checked before anything is audited.
pub async fn check(
    ks: &KeyspaceHandle,
    entry_id: &str,
    new: &NewNote,
) -> Result<Result<(), AppendError>, AppError> {
    if new.text.is_none() && new.redacts.is_none() {
        return Ok(Err(AppendError::Empty));
    }
    let Some(target) = &new.redacts else {
        return Ok(Ok(()));
    };
    Ok(
        match all_for(ks, entry_id)
            .await?
            .iter()
            .find(|(_, n)| &n.note_id == target)
        {
            None => Err(AppendError::NoteNotFound),
            Some((_, n)) if n.redacted_by.is_some() => Err(AppendError::AlreadyRedacted),
            Some(_) => Ok(()),
        },
    )
}

/// Append note `note_id` about `entry_id` by `author` (`notes/append` items 2
/// and 3). A redaction marks the note it redacts in the same write.
pub async fn append(
    ks: &KeyspaceHandle,
    entry_id: &str,
    author: &str,
    new: NewNote,
    note_id: String,
    now: DateTime<Utc>,
) -> Result<Result<Note, AppendError>, AppError> {
    if new.text.is_none() && new.redacts.is_none() {
        return Ok(Err(AppendError::Empty));
    }
    let _guard = super::WRITE_LOCK.lock().await;
    let existing = all_for(ks, entry_id).await?;
    let mut batch = Batch::new();
    if let Some(target) = &new.redacts {
        let Some((key, earlier)) = existing.iter().find(|(_, n)| &n.note_id == target) else {
            return Ok(Err(AppendError::NoteNotFound));
        };
        if earlier.redacted_by.is_some() {
            return Ok(Err(AppendError::AlreadyRedacted));
        }
        let mut marked = earlier.clone();
        marked.redacted_by = Some(note_id.clone());
        batch.insert(key.clone(), &marked)?;
        let note = Note {
            note_id,
            entry_id: entry_id.to_string(),
            author: author.to_string(),
            created_at: now,
            text: new.text,
            follow_up: new.follow_up,
            redacts: Some(target.clone()),
            redacted_by: None,
        };
        batch.insert(note_key(entry_id, existing.len() as u64), &note)?;
        ks.apply_batch(batch).await?;
        return Ok(Ok(note));
    }
    let note = Note {
        note_id,
        entry_id: entry_id.to_string(),
        author: author.to_string(),
        created_at: now,
        text: new.text,
        follow_up: new.follow_up,
        redacts: None,
        redacted_by: None,
    };
    batch.insert(note_key(entry_id, existing.len() as u64), &note)?;
    ks.apply_batch(batch).await?;
    Ok(Ok(note))
}

/// At a member's departure (VTI-DIR-121): a purge erases their notes; any
/// other disposition keeps them until `retention_days` from now, when
/// [`sweep_departed`] erases them.
pub async fn on_departure(
    ks: &KeyspaceHandle,
    entry_id: &str,
    purge: bool,
    retention_days: u32,
    now: DateTime<Utc>,
) -> Result<(), AppError> {
    let _guard = super::WRITE_LOCK.lock().await;
    let notes = all_for(ks, entry_id).await?;
    if notes.is_empty() {
        return Ok(());
    }
    let mut batch = Batch::new();
    if purge {
        for (k, _) in notes {
            batch.remove(k);
        }
    } else {
        let until = now + chrono::Duration::days(i64::from(retention_days));
        batch.insert_raw(departed_key(entry_id), until.to_rfc3339().into_bytes());
    }
    ks.apply_batch(batch).await?;
    Ok(())
}

/// Erase the kept notes of every departed member whose retention has passed.
/// Returns the entries whose notes were erased.
pub async fn sweep_departed(ks: &KeyspaceHandle, now: DateTime<Utc>) -> Result<usize, AppError> {
    let _guard = super::WRITE_LOCK.lock().await;
    let mut erased = 0;
    for (key, raw) in ks.prefix_iter_raw(b"notes-departed:".to_vec()).await? {
        let due = String::from_utf8(raw)
            .ok()
            .and_then(|s| DateTime::parse_from_rfc3339(&s).ok())
            .is_none_or(|t| t.with_timezone(&Utc) <= now);
        if !due {
            continue;
        }
        let entry_id = String::from_utf8_lossy(&key["notes-departed:".len()..]).to_string();
        let mut batch = Batch::new();
        for (k, _) in all_for(ks, &entry_id).await? {
            batch.remove(k);
        }
        batch.remove(key);
        ks.apply_batch(batch).await?;
        erased += 1;
    }
    Ok(erased)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ENTRY: &str = "dir_Q2xhcmFRMmxoY21GUk1t";

    fn text(t: &str) -> NewNote {
        NewNote {
            text: Some(t.into()),
            ..NewNote::default()
        }
    }

    #[tokio::test]
    async fn vti_dir_031_a_note_is_never_altered_only_redacted() {
        let ks = super::super::tests::scratch().await;
        let now = Utc::now();
        let first = append(
            &ks,
            ENTRY,
            "did:example:admin",
            text("Spoke at the meetup"),
            new_note_id(),
            now,
        )
        .await
        .unwrap()
        .unwrap();
        let redaction = append(
            &ks,
            ENTRY,
            "did:example:admin",
            NewNote {
                text: Some("That was someone else".into()),
                redacts: Some(first.note_id.clone()),
                ..NewNote::default()
            },
            new_note_id(),
            now,
        )
        .await
        .unwrap()
        .unwrap();
        let notes = all_for(&ks, ENTRY).await.unwrap();
        assert_eq!(notes.len(), 2);
        let (_, stored) = &notes[0];
        assert_eq!(
            stored.text.as_deref(),
            Some("Spoke at the meetup"),
            "kept as written"
        );
        assert_eq!(stored.redacted_by.as_ref(), Some(&redaction.note_id));
        // Withheld from a read, whole in an export.
        assert!(stored.wire().get("text").is_none());
        assert_eq!(stored.wire_whole()["text"], "Spoke at the meetup");

        assert_eq!(
            append(
                &ks,
                ENTRY,
                "did:example:admin",
                NewNote {
                    redacts: Some(first.note_id.clone()),
                    ..NewNote::default()
                },
                new_note_id(),
                now
            )
            .await
            .unwrap(),
            Err(AppendError::AlreadyRedacted)
        );
        assert_eq!(
            append(
                &ks,
                ENTRY,
                "did:example:admin",
                NewNote {
                    redacts: Some("note_nosuchnote0000000000".into()),
                    ..NewNote::default()
                },
                new_note_id(),
                now
            )
            .await
            .unwrap(),
            Err(AppendError::NoteNotFound)
        );
    }

    #[tokio::test]
    async fn notes_follow_the_departure_disposition() {
        let ks = super::super::tests::scratch().await;
        let now = Utc::now();
        append(
            &ks,
            "dir_purgedpurgedpurged",
            "did:example:a",
            text("x"),
            new_note_id(),
            now,
        )
        .await
        .unwrap()
        .unwrap();
        append(
            &ks,
            "dir_keptkeptkeptkeptkept",
            "did:example:a",
            text("y"),
            new_note_id(),
            now,
        )
        .await
        .unwrap()
        .unwrap();
        on_departure(&ks, "dir_purgedpurgedpurged", true, 30, now)
            .await
            .unwrap();
        on_departure(&ks, "dir_keptkeptkeptkeptkept", false, 30, now)
            .await
            .unwrap();
        assert!(
            all_for(&ks, "dir_purgedpurgedpurged")
                .await
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            all_for(&ks, "dir_keptkeptkeptkeptkept")
                .await
                .unwrap()
                .len(),
            1
        );

        assert_eq!(
            sweep_departed(&ks, now).await.unwrap(),
            0,
            "kept for the retention period"
        );
        let later = now + chrono::Duration::days(31);
        assert_eq!(sweep_departed(&ks, later).await.unwrap(), 1);
        assert!(
            all_for(&ks, "dir_keptkeptkeptkeptkept")
                .await
                .unwrap()
                .is_empty()
        );
    }
}
