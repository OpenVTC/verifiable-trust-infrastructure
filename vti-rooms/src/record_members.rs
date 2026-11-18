//! A record's kind, what it answers, when it was written and edited, and an image's size and
//! preview — the optional `SealedRecordBody` members a room's profile governs
//! (`rooms/_shared` `SealedRecordBody`, *When a writer may use these members*;
//! `RoomProfile.recordMembers`; trust-tasks-tf #1027).
//!
//! # Who checks what
//!
//! - **The shape** of each member is the specification's, checked here ([`check`]) against
//!   the one payload that publishes them all, `rooms/records/put/0.5`'s open-room
//!   `cleartext`. `kind` is an open set: any lowerCamelCase value of at most 64 characters
//!   is a kind, and nobody refuses a record for one it does not know.
//! - **Whether a writer may use them** is the writer's rule: a writer **MUST NOT** write any
//!   of them unless the room's current profile lists it in `recordMembers`, and no profile,
//!   one without `recordMembers` or one the writer cannot resolve means none ([`permitted`]).
//!   A key holder sealing or completing a write for a member (`rooms/keys/seal/0.3`,
//!   `rooms/keys/act/0.11`) does **not** apply it — both specifications say so — and no
//!   host can on the sealed tiers, where it never sees them.
//!
//! Like provenance, they are description, **never authority**: nothing here grants, widens or
//! evidences a permission. The values are kept as received and only checked, never rewritten.

use serde_json::{Map, Value};
use vti_specs_rooms::rooms::records::put::v0_5 as spec;

/// The body members `recordMembers` governs, as the wire spells them.
pub const BODY_MEMBERS: [&str; 4] = ["kind", "inReplyTo", "writtenAt", "editedAt"];

/// The `FileManifest` members `recordMembers` governs, inside a record's `file`.
pub const FILE_MEMBERS: [&str; 3] = ["width", "height", "preview"];

/// The most bytes a `preview` may decode to (`FileManifest.preview`).
pub const MAX_PREVIEW_BYTES: usize = 8192;

/// The `recordMembers` values that permit a record **kind** rather than a member: a record
/// of that kind may be written only where the profile lists the value, as well as `kind`.
/// `memberProfile`, a member's name in the room (`rooms/_shared/0.3` `MemberProfileRecord`,
/// *When a writer may write one*; [`crate::member_profile`]).
pub const KIND_VALUES: [&str; 1] = [crate::member_profile::KIND];

/// Every governed member `object` (a `SealedRecordBody`, or an open room's `cleartext`)
/// carries, by the name `recordMembers` lists it under, in a fixed order — and, last, the
/// value its `kind` needs listed where that kind is one of [`KIND_VALUES`].
pub fn used(object: &Map<String, Value>) -> Vec<&'static str> {
    let file = object.get("file").and_then(Value::as_object);
    let kind = object.get("kind").and_then(Value::as_str);
    BODY_MEMBERS
        .iter()
        .filter(|m| object.contains_key(**m))
        .chain(
            FILE_MEMBERS
                .iter()
                .filter(|m| file.is_some_and(|f| f.contains_key(**m))),
        )
        .chain(KIND_VALUES.iter().filter(|v| kind == Some(**v)))
        .copied()
        .collect()
}

/// Check every governed member `object` carries against the specification: `kind` a
/// lowerCamelCase string of 1–64 characters, `inReplyTo` a `{key, version?}` reference,
/// `writtenAt` and `editedAt` RFC 3339 instants in UTC (`Z`), and in `file` a `width` and
/// `height` of 1–1048576 pixels and a `preview` of at most [`MAX_PREVIEW_BYTES`] in JPEG,
/// PNG or WebP. Members other than these are not looked at.
///
/// `Err` names the member and why, for a writer's or a key holder's refusal.
pub fn check(object: &Map<String, Value>) -> Result<(), String> {
    fn probe(cleartext: Value, member: &str) -> Result<(), String> {
        let probe = serde_json::json!({
            "roomId": "did:example:room",
            "key": "k",
            "presentation": { "membership": "m", "authority": ["a"] },
            "cleartext": cleartext,
        });
        <spec::Payload as trust_tasks_rs::validate::ValidatedPayload>::validate_value(&probe)
            .map_err(|e| {
                format!(
                    "`{member}` is not what the specification allows: {}",
                    e.messages().join("; ")
                )
            })?;
        serde_json::from_value::<spec::Payload>(probe)
            .map(|_| ())
            .map_err(|e| format!("`{member}` is not what the specification allows: {e}"))
    }
    // One member per probe, so a refusal names the member it is about.
    for member in BODY_MEMBERS {
        if let Some(v) = object.get(member) {
            probe(serde_json::json!({ "body": "", member: v }), member)?;
        }
    }
    let Some(file) = object.get("file").and_then(Value::as_object) else {
        return Ok(());
    };
    for member in FILE_MEMBERS {
        let Some(v) = file.get(member) else {
            continue;
        };
        // The member inside a manifest that is otherwise the least valid one, so that only
        // the member is judged here.
        let mut manifest = serde_json::json!({
            "fileId": "A".repeat(43),
            "name": "f",
            "size": 0,
            "digest": "uEiA47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU",
            "epoch": 1,
            "segmentSize": 16368,
            "blobRef": "uEiA47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU",
            "fileKey": "A".repeat(43),
        });
        manifest[member] = v.clone();
        probe(
            serde_json::json!({ "body": "", "file": manifest }),
            &format!("file.{member}"),
        )?;
    }
    // The schema bounds the encoding's length; the bound is on the bytes.
    if let Some(data) = file
        .get("preview")
        .and_then(|p| p.get("data"))
        .and_then(Value::as_str)
    {
        use base64::Engine as _;
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(data)
            .map_err(|e| format!("`file.preview.data` is not base64url: {e}"))?;
        if bytes.len() > MAX_PREVIEW_BYTES {
            return Err(format!(
                "`file.preview` is {} bytes; at most {MAX_PREVIEW_BYTES}",
                bytes.len()
            ));
        }
    }
    Ok(())
}

/// The writer's rule: `Ok` when every governed member `object` carries is listed in
/// `record_members` — the room's current profile's `recordMembers` — and `Err` naming the
/// first that is not. `None` is no profile, a profile without `recordMembers` or one the
/// writer could not resolve, and permits none (the most restrictive reading).
pub fn permitted(
    object: &Map<String, Value>,
    record_members: Option<&[String]>,
) -> Result<(), String> {
    let listed = record_members.unwrap_or_default();
    match used(object)
        .into_iter()
        .find(|m| !listed.iter().any(|l| l == m))
    {
        None => Ok(()),
        Some(m) => Err(format!(
            "`{m}` may not be written to this room: its profile does not list it in \
             `recordMembers`"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn obj(v: Value) -> Map<String, Value> {
        v.as_object().unwrap().clone()
    }

    fn file_with(member: &str, v: Value) -> Map<String, Value> {
        let mut f = json!({ "fileId": "x" });
        f[member] = v;
        obj(json!({ "file": f }))
    }

    #[test]
    fn a_kind_is_an_open_lower_camel_case_set() {
        for k in [
            "note",
            "message",
            "reaction",
            "pollVote",
            "x",
            &"a".repeat(64),
        ] {
            check(&obj(json!({ "kind": k }))).unwrap_or_else(|e| panic!("{k}: {e}"));
        }
        for bad in [
            json!(""),
            json!("Message"),
            json!("poll-vote"),
            json!("1st"),
            json!("a".repeat(65)),
            json!(3),
        ] {
            assert!(check(&obj(json!({ "kind": bad }))).is_err(), "{bad}");
        }
    }

    #[test]
    fn in_reply_to_is_a_key_and_an_optional_version() {
        for good in [json!({ "key": "k" }), json!({ "key": "k", "version": 3 })] {
            check(&obj(json!({ "inReplyTo": good }))).unwrap_or_else(|e| panic!("{e}"));
        }
        for bad in [
            json!("k"),
            json!({}),
            json!({ "key": "" }),
            json!({ "key": "a".repeat(513) }),
            json!({ "key": "k", "version": 0 }),
            json!({ "key": "k", "version": "1" }),
            json!({ "key": "k", "room": "did:example:other" }),
        ] {
            assert!(check(&obj(json!({ "inReplyTo": bad }))).is_err(), "{bad}");
        }
    }

    #[test]
    fn written_at_and_edited_at_are_utc_instants() {
        for m in ["writtenAt", "editedAt"] {
            for good in ["2026-01-01T00:00:00Z", "2026-01-01T00:00:00.123456789Z"] {
                check(&obj(json!({ m: good }))).unwrap_or_else(|e| panic!("{m} {good}: {e}"));
            }
            for bad in [
                json!("2026-01-01T00:00:00+01:00"),
                json!("2026-01-01T00:00:00"),
                json!("2026-01-01"),
                json!("yesterday"),
                json!(1767225600),
            ] {
                assert!(check(&obj(json!({ m: bad }))).is_err(), "{m} {bad}");
            }
        }
    }

    #[test]
    fn an_images_size_is_whole_pixels() {
        for m in ["width", "height"] {
            for good in [1, 640, 1_048_576] {
                check(&file_with(m, json!(good))).unwrap_or_else(|e| panic!("{m} {good}: {e}"));
            }
            for bad in [
                json!(0),
                json!(-1),
                json!(1_048_577),
                json!(1.5),
                json!("640"),
            ] {
                assert!(check(&file_with(m, bad.clone())).is_err(), "{m} {bad}");
            }
        }
    }

    #[test]
    fn a_preview_is_a_small_raster_image() {
        use base64::Engine as _;
        let enc = |n: usize| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(vec![7u8; n]);
        for media in ["image/jpeg", "image/png", "image/webp"] {
            check(&file_with(
                "preview",
                json!({ "mediaType": media, "data": enc(MAX_PREVIEW_BYTES) }),
            ))
            .unwrap_or_else(|e| panic!("{media}: {e}"));
        }
        for bad in [
            json!({ "mediaType": "image/svg+xml", "data": enc(10) }),
            json!({ "mediaType": "image/gif", "data": enc(10) }),
            json!({ "mediaType": "image/png", "data": enc(MAX_PREVIEW_BYTES + 1) }),
            json!({ "mediaType": "image/png", "data": "" }),
            json!({ "mediaType": "image/png", "data": "not+base64/url=" }),
            json!({ "mediaType": "image/png" }),
            json!({ "data": enc(10) }),
            json!({ "mediaType": "image/png", "data": enc(10), "url": "https://x" }),
        ] {
            assert!(check(&file_with("preview", bad.clone())).is_err(), "{bad}");
        }
    }

    #[test]
    fn members_this_does_not_govern_are_not_looked_at() {
        check(&obj(
            json!({ "title": 7, "basis": "nonsense", "file": { "name": 1 } }),
        ))
        .unwrap();
    }

    #[test]
    fn a_writer_uses_only_what_the_profile_lists() {
        let body = obj(json!({
            "kind": "message",
            "writtenAt": "2026-01-01T00:00:00Z",
            "file": { "width": 1, "height": 1 },
        }));
        assert_eq!(used(&body), ["kind", "writtenAt", "width", "height"]);

        // No profile, or none listing them: nothing governed may be written.
        assert!(permitted(&body, None).is_err());
        assert!(permitted(&body, Some(&[])).is_err());
        let some: Vec<String> = ["kind", "writtenAt", "width"].map(String::from).to_vec();
        let err = permitted(&body, Some(&some)).unwrap_err();
        assert!(err.contains("`height`"), "{err}");
        let all: Vec<String> = ["kind", "writtenAt", "width", "height", "unknownToUs"]
            .map(String::from)
            .to_vec();
        permitted(&body, Some(&all)).unwrap();

        // A body using none of them is always permitted.
        permitted(&obj(json!({ "title": "t", "body": "b" })), None).unwrap();
    }

    /// A member's name (`kind: memberProfile`, trust-tasks-tf #1035) needs `memberProfile`
    /// listed as well as `kind`: a reader that predates it would show every name as a note.
    #[test]
    fn a_members_name_needs_member_profile_listed_beside_kind() {
        let name = obj(json!({ "kind": "memberProfile", "title": "Alice" }));
        assert_eq!(used(&name), ["kind", "memberProfile"]);
        let kind_only: Vec<String> = vec!["kind".into()];
        let err = permitted(&name, Some(&kind_only)).unwrap_err();
        assert!(err.contains("`memberProfile`"), "{err}");
        let both: Vec<String> = vec!["kind".into(), "memberProfile".into()];
        permitted(&name, Some(&both)).unwrap();
        // Listing `memberProfile` permits nothing else: a message still needs only `kind`.
        assert_eq!(used(&obj(json!({ "kind": "message" }))), ["kind"]);
    }
}
