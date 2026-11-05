//! A member's name in a room — a record of kind `memberProfile` whose `title` is the name
//! (`rooms/_shared/0.3/member-profile.schema.json`: `MemberName`, `MemberProfileRecord`,
//! `MemberProfileCleartext`; trust-tasks-tf #1035).
//!
//! # What this is
//!
//! An ordinary record: a `SealedRecordBody` on the sealed tiers, an open room's `cleartext`
//! of `rooms/records/put/0.5`. No task, host or key holder changes for it — a key holder
//! seals it as it seals any body, a host stores it as it stores any record. What is here is
//! the **writer's** and the **reader's** rules:
//!
//! - a writer writes one only where the room's profile lists both `kind` and
//!   `memberProfile` in `recordMembers` ([`crate::record_members::used`] names
//!   `memberProfile` for such a body, so the writer's rule covers it);
//! - its shape: `kind: memberProfile`, the name in `title` ([`check_name`]), none of the
//!   other content members, no `body` on the sealed tiers and an empty one on an open room
//!   ([`check`]);
//! - a reader takes a name only from a record that passes [`check`], and none from one
//!   whose name is empty or only white space — a withdrawal ([`name_of`]).
//!
//! A name is a claim by the member about themselves: plain text, never markup, never
//! instructions, never shown as verified, and never a reason to fetch anything.

use serde_json::{Map, Value};

/// The record kind that carries a member's name, and the `recordMembers` value that permits
/// writing one.
pub const KIND: &str = "memberProfile";

/// The most code points a name may hold, after Unicode Normalization Form C.
pub const MAX_NAME_CODE_POINTS: usize = 64;

/// The `SealedRecordBody` content members a `memberProfile` record never carries
/// (`MemberProfileRecord`): `body` is separate, since an open room's cleartext requires it.
const FORBIDDEN: [&str; 10] = [
    "description",
    "tags",
    "file",
    "inReplyTo",
    "roomProfile",
    "basis",
    "confidence",
    "evidence",
    "validFor",
    "validUntil",
];

/// The members an open room's `MemberProfileCleartext` may carry (`additionalProperties:
/// false`).
const CLEARTEXT_MEMBERS: [&str; 5] = ["kind", "title", "body", "writtenAt", "editedAt"];

/// Whether `c` is a character a `MemberName` may not hold: C0 and C1 controls, DEL, and the
/// line and paragraph separators — one line, no control characters.
fn forbidden_char(c: char) -> bool {
    matches!(c, '\u{0000}'..='\u{001F}' | '\u{007F}'..='\u{009F}' | '\u{2028}' | '\u{2029}')
}

/// Check `name` against `MemberName`: no control character and no line break, and at most
/// [`MAX_NAME_CODE_POINTS`] code points both as written and after NFC. Empty is allowed: it
/// is a withdrawal.
pub fn check_name(name: &str) -> Result<(), String> {
    if let Some(c) = name.chars().find(|c| forbidden_char(*c)) {
        return Err(format!(
            "a name is one line of plain text; it may not hold U+{:04X}",
            c as u32
        ));
    }
    use unicode_normalization::UnicodeNormalization as _;
    let written = name.chars().count();
    let normalised = name.nfc().count();
    if written.max(normalised) > MAX_NAME_CODE_POINTS {
        return Err(format!(
            "a name is at most {MAX_NAME_CODE_POINTS} characters; this one is {}",
            written.max(normalised)
        ));
    }
    Ok(())
}

/// Whether `name` withdraws the member's name: empty, or only `White_Space` characters.
pub fn is_withdrawal(name: &str) -> bool {
    name.chars().all(char::is_whitespace)
}

/// Whether `object` (a `SealedRecordBody` or an open room's `cleartext`) says it is a
/// member's name — `kind: memberProfile` — whatever else it carries.
pub fn is_member_profile(object: &Map<String, Value>) -> bool {
    object.get("kind").and_then(Value::as_str) == Some(KIND)
}

/// Check `object` against `MemberProfileRecord` (`open` false: a `SealedRecordBody`) or
/// `MemberProfileCleartext` (`open` true: an open room's `cleartext`). `Err` says why, for a
/// writer refusing before it writes and a reader refusing a name.
pub fn check(object: &Map<String, Value>, open: bool) -> Result<(), String> {
    if !is_member_profile(object) {
        return Err(format!("a member's name is a record of kind `{KIND}`"));
    }
    let Some(title) = object.get("title") else {
        return Err("a member's name record carries the name in `title`".into());
    };
    let title = title
        .as_str()
        .ok_or("a member's name (`title`) is a string")?;
    check_name(title)?;
    if let Some(m) = FORBIDDEN.iter().find(|m| object.contains_key(**m)) {
        return Err(format!("a member's name record carries no `{m}`"));
    }
    if open {
        if let Some(m) = object
            .keys()
            .find(|k| !CLEARTEXT_MEMBERS.contains(&k.as_str()))
        {
            return Err(format!("a member's name on an open room carries no `{m}`"));
        }
        if object.get("body").and_then(Value::as_str) != Some("") {
            return Err("a member's name on an open room has an empty `body`".into());
        }
    } else if object.contains_key("body") {
        return Err("a member's sealed name record carries no `body`".into());
    }
    Ok(())
}

/// The name `object` gives its author, as a reader takes it: `Some` only for a record that
/// passes [`check`] and whose name is not a withdrawal. The caller applies it only to the
/// record's author, only in this room, and only from the current version of the author's
/// own record (`MemberProfileRecord`, *Reading one*).
pub fn name_of(object: &Map<String, Value>, open: bool) -> Option<&str> {
    check(object, open).ok()?;
    let name = object.get("title")?.as_str()?;
    (!is_withdrawal(name)).then_some(name)
}

/// The members a writer gives a sealed `memberProfile` body beyond the record's location
/// and author: `kind` and the name.
pub fn sealed_members(name: &str) -> Result<Map<String, Value>, String> {
    check_name(name)?;
    let mut m = Map::new();
    m.insert("kind".into(), Value::String(KIND.into()));
    m.insert("title".into(), Value::String(name.into()));
    Ok(m)
}

/// An open room's `cleartext` for a member's name (`MemberProfileCleartext`).
pub fn cleartext(name: &str) -> Result<Map<String, Value>, String> {
    let mut m = sealed_members(name)?;
    m.insert("body".into(), Value::String(String::new()));
    Ok(m)
}

/// The names a reader has learned in one room, from the `memberProfile` records it read
/// (`MemberProfileRecord`, *Reading one*): per author, the name of the version the host
/// stored most recently — by `bodyStoredAt`, else `updatedAt` — and none where that version
/// withdraws it or is not a name at all.
///
/// Only for one room: a reader never applies a name to the same DID in another room.
#[derive(Debug, Clone, Default)]
pub struct Names {
    by_author:
        std::collections::HashMap<String, (Option<chrono::DateTime<chrono::Utc>>, Option<String>)>,
}

impl Names {
    /// Offer one record a reader read: `author` as verified (the body's signer on a sealed
    /// tier, the author the host recorded on an open room), `created_by` the record's
    /// `createdBy` where the host gave one, `object` the body or cleartext, `stored_at` its
    /// `bodyStoredAt` (else `updatedAt`). A record that is not `kind: memberProfile` is
    /// ignored; one whose author is not its original author names nobody (rule 3).
    pub fn offer(
        &mut self,
        author: &str,
        created_by: Option<&str>,
        object: &Map<String, Value>,
        stored_at: Option<&str>,
        open: bool,
    ) {
        if !is_member_profile(object) || created_by.is_some_and(|c| c != author) {
            return;
        }
        let at = stored_at
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
            .map(|d| d.with_timezone(&chrono::Utc));
        let name = name_of(object, open).map(str::to_string);
        match self.by_author.get(author) {
            // A version stored earlier than the one already taken does not replace it.
            Some((held, _)) if held.is_some() && (at.is_none() || at < *held) => {}
            _ => {
                self.by_author.insert(author.to_string(), (at, name));
            }
        }
    }

    /// The name `author` gave themselves in this room, if any.
    pub fn name(&self, author: &str) -> Option<&str> {
        self.by_author.get(author)?.1.as_deref()
    }

    /// Every author with a name, and the name.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.by_author
            .iter()
            .filter_map(|(a, (_, n))| Some((a.as_str(), n.as_deref()?)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn obj(v: Value) -> Map<String, Value> {
        v.as_object().unwrap().clone()
    }

    #[test]
    fn a_name_is_one_short_line_of_plain_text() {
        for good in ["Alice", "", "  ", "Zoë 🌿", &"a".repeat(64), "名前"] {
            check_name(good).unwrap_or_else(|e| panic!("{good:?}: {e}"));
        }
        for bad in [
            "two\nlines",
            "tab\there",
            "nul\u{0}",
            "del\u{7f}",
            "c1\u{85}",
            "sep\u{2028}",
            "para\u{2029}",
            &"a".repeat(65),
        ] {
            assert!(check_name(bad).is_err(), "{bad:?}");
        }
        // 64 decomposed characters that compose to 64 still pass; 65 written do not.
        let decomposed = "e\u{301}".repeat(32);
        check_name(&decomposed).unwrap();
    }

    #[test]
    fn an_empty_or_blank_name_withdraws() {
        assert!(is_withdrawal(""));
        assert!(is_withdrawal(" \u{3000}\t"));
        assert!(!is_withdrawal(" a "));
    }

    #[test]
    fn a_sealed_name_record_carries_kind_and_title_and_nothing_else() {
        let ok = obj(json!({
            "roomId": "did:example:r", "key": "k", "version": 2, "author": "did:example:a",
            "kind": "memberProfile", "title": "Alice", "writtenAt": "2026-01-01T00:00:00Z",
        }));
        check(&ok, false).unwrap();
        assert_eq!(name_of(&ok, false), Some("Alice"));

        for (member, value) in [
            ("body", json!("")),
            ("description", json!("d")),
            ("tags", json!(["t"])),
            ("file", json!({})),
            ("inReplyTo", json!({ "key": "k" })),
            ("roomProfile", json!({})),
            ("basis", json!("declared")),
            ("confidence", json!(1)),
            ("evidence", json!([])),
            ("validFor", json!({})),
            ("validUntil", json!("2027-01-01T00:00:00Z")),
        ] {
            let mut bad = ok.clone();
            bad.insert(member.into(), value);
            assert!(check(&bad, false).is_err(), "{member}");
            assert_eq!(name_of(&bad, false), None, "{member}");
        }
        let mut other_kind = ok.clone();
        other_kind.insert("kind".into(), json!("note"));
        assert!(check(&other_kind, false).is_err());
        let mut untitled = ok.clone();
        untitled.remove("title");
        assert!(check(&untitled, false).is_err());
        let mut withdrawn = ok;
        withdrawn.insert("title".into(), json!(""));
        check(&withdrawn, false).unwrap();
        assert_eq!(name_of(&withdrawn, false), None);
    }

    #[test]
    fn an_open_rooms_name_has_an_empty_body_and_no_other_member() {
        let ok = obj(json!({ "kind": "memberProfile", "title": "Alice", "body": "" }));
        check(&ok, true).unwrap();
        assert_eq!(
            Value::Object(cleartext("Alice").unwrap()),
            Value::Object(ok.clone())
        );
        for bad in [
            json!({ "kind": "memberProfile", "title": "Alice" }),
            json!({ "kind": "memberProfile", "title": "Alice", "body": "hi" }),
            json!({ "kind": "memberProfile", "title": "Alice", "body": "", "author": "x" }),
        ] {
            assert!(check(&obj(bad.clone()), true).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_reader_takes_the_latest_stored_name_of_the_original_author() {
        let named = |n: &str| obj(json!({ "kind": "memberProfile", "title": n, "author": "a" }));
        let mut names = Names::default();
        names.offer(
            "did:a",
            Some("did:a"),
            &named("Old"),
            Some("2026-01-01T00:00:00Z"),
            false,
        );
        names.offer(
            "did:a",
            Some("did:a"),
            &named("New"),
            Some("2026-01-02T00:00:00Z"),
            false,
        );
        names.offer(
            "did:a",
            None,
            &named("Stale"),
            Some("2025-12-31T00:00:00Z"),
            false,
        );
        assert_eq!(names.name("did:a"), Some("New"));

        // A rewrite by another member names nobody.
        names.offer("did:b", Some("did:a"), &named("Impostor"), None, false);
        assert_eq!(names.name("did:b"), None);
        // A note is not a name.
        names.offer(
            "did:c",
            None,
            &obj(json!({ "kind": "note", "title": "C" })),
            None,
            false,
        );
        assert_eq!(names.name("did:c"), None);
        // A later withdrawal leaves no name.
        names.offer(
            "did:a",
            Some("did:a"),
            &named(""),
            Some("2026-01-03T00:00:00Z"),
            false,
        );
        assert_eq!(names.name("did:a"), None);
        assert_eq!(names.iter().count(), 0);
    }

    #[test]
    fn writers_build_what_readers_accept() {
        let mut body = sealed_members("Bob").unwrap();
        body.insert("author".into(), json!("did:example:b"));
        assert_eq!(name_of(&body, false), Some("Bob"));
        assert!(sealed_members("a\nb").is_err());
    }
}
