//! Integration coverage for administrators' notes (`vtc/directory/notes/*`,
//! VTI-DIR-030 – 033) and the directory's export (`vtc/directory/export`).
//!
//! Each declared error code is driven here and asserted on (#1600), which is
//! what the error-code census reads.

use axum::http::StatusCode;
use serde_json::{Value, json};
use vti_rooms_dtg::test_support::Party;

use crate::common::second_party::{GatedAdmin, step_up_request};
use crate::common::signed::{call, seed_role};
use vtc_service::acl::VtcRole;
use vtc_service::members::{Member, store_member};
use vtc_service::policy::default::install_defaults;
use vtc_service::test_support::TestVtc;

const SPEC: &str = "https://trusttasks.org/spec/vtc/directory";

fn task(name: &str) -> String {
    format!("{SPEC}/{name}/0.1")
}

use trust_tasks_rs::specs::vtc::directory as d;

const NOTES_APPEND_ERR_NOT_FOUND: &str = d::notes::append::v0_1::error_codes::NOT_FOUND.code;
const NOTES_APPEND_ERR_NOTE_NOT_FOUND: &str =
    d::notes::append::v0_1::error_codes::NOTE_NOT_FOUND.code;
const NOTES_APPEND_ERR_ALREADY_REDACTED: &str =
    d::notes::append::v0_1::error_codes::ALREADY_REDACTED.code;
const NOTES_LIST_ERR_NOT_FOUND: &str = d::notes::list::v0_1::error_codes::NOT_FOUND.code;
const NOTES_LIST_ERR_CURSOR_INVALID: &str = d::notes::list::v0_1::error_codes::CURSOR_INVALID.code;
const NOTES_EXPORT_ERR_NOT_FOUND: &str = d::notes::export::v0_1::error_codes::NOT_FOUND.code;
const EXPORT_ERR_CURSOR_INVALID: &str = d::export::v0_1::error_codes::CURSOR_INVALID.code;

fn tt_error_code(body: &Value) -> &str {
    body["code"].as_str().unwrap_or_default()
}

const UNKNOWN_ENTRY: &str = "dir_UnknownUnknownUnknown";

struct Fixture {
    vtc: TestVtc,
    admin: GatedAdmin,
    member: Party,
    entry: String,
}

async fn fixture() -> Fixture {
    let vtc = TestVtc::builder()
        .with_audit(true)
        .with_public_url("https://vtc.example.com")
        .build()
        .await;
    install_defaults(&vtc.state.policies_ks, &vtc.state.active_policies_ks)
        .await
        .unwrap();
    let admin = GatedAdmin::new(&vtc).await;
    let member = Party::new();
    seed_role(&vtc, &member.did, VtcRole::Member, &[]).await;
    store_member(&vtc.state.members_ks, &Member::fresh(&member.did))
        .await
        .unwrap();
    let (_, up) = call(
        &vtc,
        &member,
        &task("card/update"),
        json!({ "values": { "displayName": "Carol Example" } }),
    )
    .await;
    let entry = up["payload"]["card"]["entryId"]
        .as_str()
        .unwrap()
        .to_string();
    Fixture {
        vtc,
        admin,
        member,
        entry,
    }
}

impl Fixture {
    async fn as_admin(&self, name: &str, payload: Value) -> (StatusCode, Value) {
        let (status, doc) = self.admin.call(&self.vtc, &task(name), payload).await;
        (status, doc["payload"].clone())
    }

    async fn note(&self, text: &str) -> Value {
        let (status, body) = self
            .as_admin(
                "notes/append",
                json!({ "entryId": self.entry, "text": text }),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body["note"].clone()
    }
}

/// VTI-DIR-031: a note is never altered; a redaction is a later note, and the
/// redacted text is withheld from every read but the export.
#[tokio::test]
async fn notes_append_refuses_what_its_specification_declares() {
    let f = fixture().await;
    let (_, unknown) = f
        .as_admin(
            "notes/append",
            json!({ "entryId": UNKNOWN_ENTRY, "text": "x" }),
        )
        .await;
    assert_eq!(
        tt_error_code(&unknown),
        NOTES_APPEND_ERR_NOT_FOUND,
        "{unknown}"
    );

    let first = f.note("Spoke at the June meetup.").await;
    let (_, missing) = f
        .as_admin(
            "notes/append",
            json!({ "entryId": f.entry, "redacts": "note_NoSuchNoteNoSuchNote" }),
        )
        .await;
    assert_eq!(
        tt_error_code(&missing),
        NOTES_APPEND_ERR_NOTE_NOT_FOUND,
        "{missing}"
    );

    let (status, redaction) = f
        .as_admin(
            "notes/append",
            json!({ "entryId": f.entry, "redacts": first["noteId"] }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{redaction}");
    assert_eq!(redaction["note"]["redacts"], first["noteId"]);
    let (_, twice) = f
        .as_admin(
            "notes/append",
            json!({ "entryId": f.entry, "redacts": first["noteId"] }),
        )
        .await;
    assert_eq!(
        tt_error_code(&twice),
        NOTES_APPEND_ERR_ALREADY_REDACTED,
        "{twice}"
    );
}

#[tokio::test]
async fn notes_list_refuses_what_its_specification_declares() {
    let f = fixture().await;
    let first = f.note("First.").await;
    f.note("Second.").await;
    f.as_admin(
        "notes/append",
        json!({ "entryId": f.entry, "redacts": first["noteId"] }),
    )
    .await;

    let (status, page) = f
        .as_admin("notes/list", json!({ "entryId": f.entry, "limit": 2 }))
        .await;
    assert_eq!(status, StatusCode::OK, "{page}");
    let items = page["items"].as_array().unwrap();
    assert_eq!(items.len(), 2, "newest first, two to a page");
    assert!(items[0].get("redacts").is_some(), "the redaction is newest");
    let rest = f
        .as_admin(
            "notes/list",
            json!({ "entryId": f.entry, "limit": 2, "cursor": page["nextCursor"] }),
        )
        .await
        .1;
    let oldest = &rest["items"][0];
    assert_eq!(oldest["noteId"], first["noteId"]);
    assert!(
        oldest.get("text").is_none(),
        "a redacted note's text is withheld: {oldest}"
    );

    let (_, unknown) = f
        .as_admin("notes/list", json!({ "entryId": UNKNOWN_ENTRY }))
        .await;
    assert_eq!(
        tt_error_code(&unknown),
        NOTES_LIST_ERR_NOT_FOUND,
        "{unknown}"
    );
    let (_, bad) = f
        .as_admin(
            "notes/list",
            json!({ "entryId": f.entry, "cursor": "not-a-cursor" }),
        )
        .await;
    assert_eq!(tt_error_code(&bad), NOTES_LIST_ERR_CURSOR_INVALID, "{bad}");
}

/// VTI-DIR-030 / 031: only holders of `vtc.directory.notes` read or write
/// notes, and no directory read carries one.
#[tokio::test]
async fn a_member_reads_no_note_anywhere() {
    let f = fixture().await;
    f.note("Private to administrators.").await;
    for (name, payload) in [
        ("notes/list", json!({ "entryId": f.entry })),
        ("notes/append", json!({ "entryId": f.entry, "text": "x" })),
        ("notes/export", json!({ "entryId": f.entry, "reason": "x" })),
    ] {
        let (_, doc) = call(&f.vtc, &f.member, &task(name), payload).await;
        assert_eq!(doc["payload"]["code"], "permissionDenied", "{name}: {doc}");
    }
    let (_, own) = call(&f.vtc, &f.member, &task("card/show"), json!({})).await;
    assert!(!own.to_string().contains("Private to administrators"));
}

/// VTI-DIR-033: releasing a member's notes takes the exporter's gesture bound
/// to the document, and returns every note as written.
#[tokio::test]
async fn notes_export_refuses_what_its_specification_declares() {
    let f = fixture().await;
    let first = f.note("Kept as written.").await;
    f.as_admin(
        "notes/append",
        json!({ "entryId": f.entry, "redacts": first["noteId"] }),
    )
    .await;

    // Without the gesture, nothing is released.
    let (_, ungestured) = call(
        &f.vtc,
        &f.admin.requester,
        &task("notes/export"),
        json!({ "entryId": f.entry, "reason": "The member asked." }),
    )
    .await;
    assert!(step_up_request(&ungestured).is_some(), "{ungestured}");

    let (status, export) = f
        .as_admin(
            "notes/export",
            json!({ "entryId": f.entry, "reason": "The member asked." }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{export}");
    let notes = export["notes"].as_array().unwrap();
    assert_eq!(notes.len(), 2, "oldest first, the redaction included");
    assert_eq!(
        notes[0]["text"], "Kept as written.",
        "redacted text included"
    );

    let (_, unknown) = f
        .as_admin(
            "notes/export",
            json!({ "entryId": UNKNOWN_ENTRY, "reason": "x" }),
        )
        .await;
    assert_eq!(
        tt_error_code(&unknown),
        NOTES_EXPORT_ERR_NOT_FOUND,
        "{unknown}"
    );
}

#[tokio::test]
async fn export_refuses_what_its_specification_declares() {
    let f = fixture().await;
    f.note("Never exported with the cards.").await;
    let (status, page) = f
        .as_admin(
            "export",
            json!({ "format": "jscontact", "reason": "Annual archive.", "limit": 1 }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{page}");
    let all = page.to_string();
    assert!(!all.contains("Never exported"), "no note in an export");
    let mut cards = page["items"].as_array().unwrap().clone();
    let mut cursor = page["nextCursor"].clone();
    while cursor.is_string() {
        let (_, next) = f
            .as_admin(
                "export",
                json!({ "format": "jscontact", "reason": "Annual archive.", "limit": 1, "cursor": cursor }),
            )
            .await;
        cards.extend(next["items"].as_array().unwrap().iter().cloned());
        cursor = next["nextCursor"].clone();
    }
    let carol = cards
        .iter()
        .find(|c| c["uid"] == format!("urn:vtc-directory:{}", f.entry))
        .expect("the member's card is exported");
    assert_eq!(carol["@type"], "Card");
    assert_eq!(carol["name"]["full"], "Carol Example");
    assert_eq!(carol["role"], "member");

    let (_, bad) = f
        .as_admin(
            "export",
            json!({ "format": "jscontact", "reason": "x", "cursor": "not-a-cursor" }),
        )
        .await;
    assert_eq!(tt_error_code(&bad), EXPORT_ERR_CURSOR_INVALID, "{bad}");

    let (_, member) = call(
        &f.vtc,
        &f.member,
        &task("export"),
        json!({ "format": "jscontact", "reason": "x" }),
    )
    .await;
    assert_eq!(member["payload"]["code"], "permissionDenied", "{member}");
}
