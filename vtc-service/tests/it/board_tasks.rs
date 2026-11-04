//! Community boards over the signed-document door (`vtc/boards/*`, VTI-BRD-001 – 080).
//!
//! Each accepted idea's election is registered with the real ballot box
//! (`vti_voting::service::BallotBox`) behind the channel the community reaches ballot boxes
//! through, so an acceptance is checked by the rules a deployed voting service applies, and a
//! selection reads a result the community verifies from a real board.

#![cfg(feature = "voting")]

use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::{Arc, Mutex};

use axum::http::StatusCode;
use chrono::{DateTime, Duration, Utc};
use serde_json::{Value, json};
use vtc_service::acl::{
    AdminAuthority, AdminRole, Capability, CapabilityGrant, CapabilityScope, ResourceQualifier,
    VtcRole, store_acl_entry,
};
use vtc_service::elections::link::{BallotBoxChannel, BoxAnswer, LinkError};
use vtc_service::elections::{TrustedBallotBox, VotingConfig};
use vtc_service::test_support::TestVtc;
use vti_rooms_dtg::test_support::Party;
use vti_voting::service::{BallotBox, Caller, ElectionVersion};

use crate::common::second_party::{GatedAdmin, step_up_request};
use crate::common::signed::{admin, call, party_with_role, payload};

use vti_specs::vtc::boards as b;

const CREATE_ERR_TEMPLATE_INVALID: &str = b::create::v0_1::error_codes::TEMPLATE_INVALID.code;
const CREATE_ERR_BALLOT_BOX_NOT_TRUSTED: &str =
    b::create::v0_1::error_codes::BALLOT_BOX_NOT_TRUSTED.code;
const CREATE_ERR_GROUP_NOT_FOUND: &str = b::create::v0_1::error_codes::GROUP_NOT_FOUND.code;
const CREATE_ERR_SCHEDULE_INVALID: &str = b::create::v0_1::error_codes::SCHEDULE_INVALID.code;
const CREATE_ERR_TIMETABLE_INVALID: &str = b::create::v0_1::error_codes::TIMETABLE_INVALID.code;
const UPDATE_ERR_NOT_FOUND: &str = b::update::v0_1::error_codes::NOT_FOUND.code;
const UPDATE_ERR_FIXED_AFTER_VOTING_OPENS: &str =
    b::update::v0_1::error_codes::FIXED_AFTER_VOTING_OPENS.code;
const UPDATE_ERR_STATUS_INVALID: &str = b::update::v0_1::error_codes::STATUS_INVALID.code;
const UPDATE_ERR_ARCHIVED: &str = b::update::v0_1::error_codes::ARCHIVED.code;
const UPDATE_ERR_TEMPLATE_INVALID: &str = b::update::v0_1::error_codes::TEMPLATE_INVALID.code;
const UPDATE_ERR_BALLOT_BOX_NOT_TRUSTED: &str =
    b::update::v0_1::error_codes::BALLOT_BOX_NOT_TRUSTED.code;
const UPDATE_ERR_SCHEDULE_INVALID: &str = b::update::v0_1::error_codes::SCHEDULE_INVALID.code;
const UPDATE_ERR_TIMETABLE_INVALID: &str = b::update::v0_1::error_codes::TIMETABLE_INVALID.code;
const LIST_ERR_CURSOR_INVALID: &str = b::list::v0_1::error_codes::CURSOR_INVALID.code;
const SHOW_ERR_NOT_FOUND: &str = b::show::v0_1::error_codes::NOT_FOUND.code;
const SHOW_ERR_CURSOR_INVALID: &str = b::show::v0_1::error_codes::CURSOR_INVALID.code;
const PROPOSE_ERR_NOT_FOUND: &str = b::ideas::propose::v0_1::error_codes::NOT_FOUND.code;
const PROPOSE_ERR_PROPOSALS_CLOSED: &str =
    b::ideas::propose::v0_1::error_codes::PROPOSALS_CLOSED.code;
const PROPOSE_ERR_LIMIT_REACHED: &str = b::ideas::propose::v0_1::error_codes::LIMIT_REACHED.code;
const PROPOSE_ERR_TOPIC_UNKNOWN: &str = b::ideas::propose::v0_1::error_codes::TOPIC_UNKNOWN.code;
const PROPOSE_ERR_FORMAT_UNKNOWN: &str = b::ideas::propose::v0_1::error_codes::FORMAT_UNKNOWN.code;
const IDEA_UPDATE_ERR_NOT_FOUND: &str = b::ideas::update::v0_1::error_codes::NOT_FOUND.code;
const IDEA_UPDATE_ERR_IDEA_NOT_FOUND: &str =
    b::ideas::update::v0_1::error_codes::IDEA_NOT_FOUND.code;
const IDEA_UPDATE_ERR_NOT_PROPOSER: &str = b::ideas::update::v0_1::error_codes::NOT_PROPOSER.code;
const IDEA_UPDATE_ERR_NOT_PROPOSED: &str = b::ideas::update::v0_1::error_codes::NOT_PROPOSED.code;
const IDEA_UPDATE_ERR_TOPIC_UNKNOWN: &str = b::ideas::update::v0_1::error_codes::TOPIC_UNKNOWN.code;
const IDEA_UPDATE_ERR_FORMAT_UNKNOWN: &str =
    b::ideas::update::v0_1::error_codes::FORMAT_UNKNOWN.code;
const WITHDRAW_ERR_NOT_FOUND: &str = b::ideas::withdraw::v0_1::error_codes::NOT_FOUND.code;
const WITHDRAW_ERR_IDEA_NOT_FOUND: &str =
    b::ideas::withdraw::v0_1::error_codes::IDEA_NOT_FOUND.code;
const WITHDRAW_ERR_NOT_PROPOSER: &str = b::ideas::withdraw::v0_1::error_codes::NOT_PROPOSER.code;
const WITHDRAW_ERR_NOT_PROPOSED: &str = b::ideas::withdraw::v0_1::error_codes::NOT_PROPOSED.code;
const DECIDE_ERR_NOT_FOUND: &str = b::ideas::decide::v0_1::error_codes::NOT_FOUND.code;
const DECIDE_ERR_IDEA_NOT_FOUND: &str = b::ideas::decide::v0_1::error_codes::IDEA_NOT_FOUND.code;
const DECIDE_ERR_STATE_INVALID: &str = b::ideas::decide::v0_1::error_codes::STATE_INVALID.code;
const DECIDE_ERR_OWN_IDEA: &str = b::ideas::decide::v0_1::error_codes::OWN_IDEA.code;
const DECIDE_ERR_MERGE_TARGET_INVALID: &str =
    b::ideas::decide::v0_1::error_codes::MERGE_TARGET_INVALID.code;
const DECIDE_ERR_REASON_REQUIRED: &str = b::ideas::decide::v0_1::error_codes::REASON_REQUIRED.code;
const DECIDE_ERR_VOTING_CLOSED: &str = b::ideas::decide::v0_1::error_codes::VOTING_CLOSED.code;
const DECIDE_ERR_ELECTION_REFUSED: &str =
    b::ideas::decide::v0_1::error_codes::ELECTION_REFUSED.code;
const SELECT_ERR_NOT_FOUND: &str = b::ideas::select::v0_1::error_codes::NOT_FOUND.code;
const SELECT_ERR_IDEA_NOT_FOUND: &str = b::ideas::select::v0_1::error_codes::IDEA_NOT_FOUND.code;
const SELECT_ERR_NOT_TALLIED: &str = b::ideas::select::v0_1::error_codes::NOT_TALLIED.code;
const SELECT_ERR_STATE_INVALID: &str = b::ideas::select::v0_1::error_codes::STATE_INVALID.code;
const SELECT_ERR_SLOT_UNKNOWN: &str = b::ideas::select::v0_1::error_codes::SLOT_UNKNOWN.code;
const SELECT_ERR_SLOT_TAKEN: &str = b::ideas::select::v0_1::error_codes::SLOT_TAKEN.code;
const SELECT_ERR_REASON_REQUIRED: &str = b::ideas::select::v0_1::error_codes::REASON_REQUIRED.code;
const NOTES_ADD_ERR_NOT_FOUND: &str = b::notes::add::v0_1::error_codes::NOT_FOUND.code;
const NOTES_ADD_ERR_IDEA_NOT_FOUND: &str = b::notes::add::v0_1::error_codes::IDEA_NOT_FOUND.code;
const NOTES_ADD_ERR_BOARD_CLOSED: &str = b::notes::add::v0_1::error_codes::BOARD_CLOSED.code;
const NOTES_ADD_ERR_IDEA_WITHDRAWN: &str = b::notes::add::v0_1::error_codes::IDEA_WITHDRAWN.code;
const NOTES_ADD_ERR_RATE_LIMITED: &str = b::notes::add::v0_1::error_codes::RATE_LIMITED.code;
const NOTES_LIST_ERR_NOT_FOUND: &str = b::notes::list::v0_1::error_codes::NOT_FOUND.code;
const NOTES_LIST_ERR_IDEA_NOT_FOUND: &str = b::notes::list::v0_1::error_codes::IDEA_NOT_FOUND.code;
const NOTES_LIST_ERR_CURSOR_INVALID: &str = b::notes::list::v0_1::error_codes::CURSOR_INVALID.code;
const NOTE_WITHDRAW_ERR_NOTE_NOT_FOUND: &str =
    b::notes::withdraw::v0_1::error_codes::NOTE_NOT_FOUND.code;
const NOTE_WITHDRAW_ERR_NOT_AUTHOR: &str = b::notes::withdraw::v0_1::error_codes::NOT_AUTHOR.code;
const NOTE_WITHDRAW_ERR_ALREADY_WITHDRAWN: &str =
    b::notes::withdraw::v0_1::error_codes::ALREADY_WITHDRAWN.code;
const HIDE_ERR_NOTE_NOT_FOUND: &str = b::notes::hide::v0_1::error_codes::NOTE_NOT_FOUND.code;
const HIDE_ERR_STATE_INVALID: &str = b::notes::hide::v0_1::error_codes::STATE_INVALID.code;
const HIDE_ERR_REASON_REQUIRED: &str = b::notes::hide::v0_1::error_codes::REASON_REQUIRED.code;

const BOX: &str = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";
const OTHER_BOX: &str = "did:key:z6MkjchhfUsD6mmvni8mCdXHw216Xrm9bQe2mBH1P5RDjVJG";
const SPEC: &str = "https://trusttasks.org/spec/";
const UNKNOWN_BOARD: &str = "brd_AAAAAAAAAAAAAAAAAAAAAA";
const UNKNOWN_IDEA: &str = "ida_AAAAAAAAAAAAAAAAAAAAAA";
const UNKNOWN_NOTE: &str = "bnt_AAAAAAAAAAAAAAAAAAAAAA";

fn uri(task: &str) -> String {
    format!("{SPEC}vtc/boards/{task}/0.1")
}

fn tt_error_code(doc: &Value) -> &str {
    doc.pointer("/payload/code")
        .and_then(Value::as_str)
        .unwrap_or_default()
}

fn stamp(t: DateTime<Utc>) -> String {
    t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

// ─── the ballot box ──────────────────────────────────────────────────────

/// The real ballot box, in process: it can refuse, and run its clock ahead to tally.
struct InProcessBox {
    bb: Mutex<BallotBox>,
    refuse: AtomicBool,
    /// Answers nothing: the community's link reports it unavailable, so the sweeper retries.
    silent: AtomicBool,
    ahead: AtomicI64,
}

impl InProcessBox {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            bb: Mutex::new(BallotBox::new(BOX)),
            refuse: AtomicBool::new(false),
            silent: AtomicBool::new(false),
            ahead: AtomicI64::new(0),
        })
    }
}

#[async_trait::async_trait]
impl BallotBoxChannel for InProcessBox {
    async fn exchange(
        &self,
        _ballot_box: &str,
        type_uri: &str,
        payload: &Value,
    ) -> Result<BoxAnswer, LinkError> {
        let (slug, _) = type_uri
            .strip_prefix(SPEC)
            .and_then(|t| t.rsplit_once('/'))
            .expect("a voting task");
        if self.silent.load(Ordering::SeqCst) {
            return Err(LinkError::Unavailable("silent for the test".into()));
        }
        if self.refuse.load(Ordering::SeqCst) {
            return Ok(BoxAnswer::Refused {
                code: format!("{slug}:refused"),
                message: "refused for the test".into(),
            });
        }
        let signer = payload["community"].as_str().unwrap_or_default();
        let now = Utc::now() + Duration::seconds(self.ahead.load(Ordering::SeqCst));
        let mut bb = self.bb.lock().unwrap();
        let out = match slug {
            "voting/election/register" => {
                bb.register_at(ElectionVersion::V0_4, signer, payload, now)
            }
            "voting/election/close" => bb.close(signer, payload, now),
            "voting/election/cancel" => bb.cancel(signer, payload, now),
            "voting/board/head" => bb.board_head(Caller::Did(signer), payload, now),
            "voting/board/read" => bb.board_read(Caller::Did(signer), payload, now),
            "voting/result/show" => bb.result(Caller::Did(signer), payload, now),
            other => panic!("the community sent {other}"),
        };
        Ok(match out {
            Ok(p) => BoxAnswer::Success {
                document: json!({ "type": format!("{type_uri}#response"), "payload": p }),
                payload: p,
            },
            Err(f) => BoxAnswer::Refused {
                code: if f.standard {
                    f.local.to_string()
                } else {
                    format!("{slug}:{}", f.local)
                },
                message: f.reason,
            },
        })
    }
}

async fn community(bx: Arc<InProcessBox>) -> TestVtc {
    TestVtc::builder()
        .with_signers(true)
        .with_audit(true)
        // The bound step-up a deletion takes is a WebAuthn gesture.
        .with_public_url("https://vtc.example")
        .with_elections(
            VotingConfig {
                trusted_ballot_boxes: vec![TrustedBallotBox {
                    did: BOX.into(),
                    operator: "Independent Ballots Ltd".into(),
                    same_operator: false,
                }],
            },
            bx,
        )
        .build()
        .await
}

// ─── fixtures ────────────────────────────────────────────────────────────

async fn member(tv: &TestVtc) -> Party {
    let m = party_with_role(tv, VtcRole::Member, &[]).await;
    vtc_service::members::store_member(
        &tv.state.members_ks,
        &vtc_service::members::Member::fresh(m.did.clone()),
    )
    .await
    .unwrap();
    m
}

/// An active member who facilitates `board_id` alone (`vtc.boards.manage` at
/// `board:<boardId>`), and holds nothing else.
async fn facilitator_of(tv: &TestVtc, board_id: &str) -> Party {
    let p = member(tv).await;
    let mut entry = vtc_service::acl::get_acl_entry(&tv.state.acl_ks, &p.did)
        .await
        .unwrap()
        .unwrap();
    entry.admin = AdminAuthority {
        capabilities: CapabilityScope::listed(vec![CapabilityGrant {
            capability: Capability::BoardsManage,
            resource: Some(ResourceQualifier::Board(board_id.to_string())),
            additive: false,
        }])
        .unwrap(),
        ..AdminAuthority::for_role(AdminRole::CommunityAdmin)
    };
    store_acl_entry(&tv.state.acl_ks, &entry).await.unwrap();
    p
}

fn template() -> Value {
    json!({
        "questions": [{
            "key": "attend", "type": "choice", "text": "Would you attend this session?",
            "options": [{ "key": "yes", "label": "Yes" }, { "key": "no", "label": "Not for me" }],
            "minSelections": 1, "maxSelections": 1, "optional": false
        }],
        "secrecy": "open",
        "revote": "replace",
        "board": { "visibility": "public", "auditors": [] },
        "ballotBox": BOX,
        "allowEarlyClose": true,
        "resultsBeforeClose": false,
        "textReleaseThreshold": 10
    })
}

/// A board taking proposals now, with voting open from half an hour ago for two hours.
fn board_body() -> Value {
    let now = Utc::now();
    json!({
        "title": "Trust Week Unconference",
        "audience": { "kind": "members" },
        "proposals": { "opensAt": stamp(now - Duration::hours(1)), "closesAt": stamp(now + Duration::hours(1)) },
        "voting": { "opensAt": stamp(now - Duration::minutes(30)), "closesAt": stamp(now + Duration::hours(2)) },
        "topics": ["Identity", "Governance"],
        "formats": ["Talk", "Discussion"],
        "selectionRule": "The sessions the most members would attend.",
        "timetable": [
            { "slotId": "a-0900", "label": "Room A", "startsAt": stamp(now + Duration::days(1)), "endsAt": stamp(now + Duration::days(1) + Duration::hours(1)) },
            { "slotId": "b-0900", "label": "Room B", "startsAt": stamp(now + Duration::days(1)), "endsAt": stamp(now + Duration::days(1) + Duration::hours(1)) }
        ],
        "template": template()
    })
}

async fn create_board(tv: &TestVtc, chair: &Party, body: Value) -> String {
    let (status, doc) = call(tv, chair, &uri("create"), body).await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    payload(&doc)["board"]["boardId"]
        .as_str()
        .unwrap()
        .to_string()
}

async fn propose(tv: &TestVtc, who: &Party, board: &str, title: &str) -> String {
    let (status, doc) = call(
        tv,
        who,
        &uri("ideas/propose"),
        json!({ "boardId": board, "title": title, "description": "What it covers.", "format": "Talk", "topic": "Identity" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    payload(&doc)["idea"]["ideaId"]
        .as_str()
        .unwrap()
        .to_string()
}

async fn decide(tv: &TestVtc, who: &Party, idea: &str, body: Value) -> (StatusCode, Value) {
    let mut p = body;
    p["ideaId"] = json!(idea);
    call(tv, who, &uri("ideas/decide"), p).await
}

// ─── create, update ──────────────────────────────────────────────────────

/// VTI-BRD-001, VTI-BRD-002, VTI-BRD-030.
#[tokio::test]
async fn vti_brd_002_create_refuses_what_its_specification_declares() {
    let tv = community(InProcessBox::new()).await;
    let chair = admin(&tv).await;
    let alice = member(&tv).await;

    // Both capabilities, unqualified: a member has neither.
    let (_, doc) = call(&tv, &alice, &uri("create"), board_body()).await;
    assert_eq!(tt_error_code(&doc), "permissionDenied", "{doc}");

    let mut bad = board_body();
    bad["voting"]["closesAt"] = bad["proposals"]["opensAt"].clone();
    let (_, doc) = call(&tv, &chair, &uri("create"), bad).await;
    assert_eq!(tt_error_code(&doc), CREATE_ERR_SCHEDULE_INVALID, "{doc}");

    let mut bad = board_body();
    bad["timetable"][1]["slotId"] = json!("a-0900");
    let (_, doc) = call(&tv, &chair, &uri("create"), bad).await;
    assert_eq!(tt_error_code(&doc), CREATE_ERR_TIMETABLE_INVALID, "{doc}");

    let mut bad = board_body();
    bad["audience"] = json!({ "kind": "group", "groupId": "grp_AAAAAAAAAAAAAAAAAAAAAA" });
    let (_, doc) = call(&tv, &chair, &uri("create"), bad).await;
    assert_eq!(tt_error_code(&doc), CREATE_ERR_GROUP_NOT_FOUND, "{doc}");

    let mut bad = board_body();
    bad["template"]["questions"][0]["maxSelections"] = json!(5);
    let (_, doc) = call(&tv, &chair, &uri("create"), bad).await;
    assert_eq!(tt_error_code(&doc), CREATE_ERR_TEMPLATE_INVALID, "{doc}");

    let mut bad = board_body();
    bad["template"]["ballotBox"] = json!(OTHER_BOX);
    let (_, doc) = call(&tv, &chair, &uri("create"), bad).await;
    assert_eq!(
        tt_error_code(&doc),
        CREATE_ERR_BALLOT_BOX_NOT_TRUSTED,
        "{doc}"
    );

    let (status, doc) = call(&tv, &chair, &uri("create"), board_body()).await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    assert_eq!(payload(&doc)["board"]["status"], "open");
    assert_eq!(payload(&doc)["board"]["facilitator"], true);

    // A facilitator of one board cannot create another: creating takes both capabilities.
    let board = payload(&doc)["board"]["boardId"]
        .as_str()
        .unwrap()
        .to_string();
    let fac = facilitator_of(&tv, &board).await;
    let (_, doc) = call(&tv, &fac, &uri("create"), board_body()).await;
    assert_eq!(tt_error_code(&doc), "permissionDenied", "{doc}");
}

/// VTI-BRD-002, VTI-BRD-004, VTI-BRD-005.
#[tokio::test]
async fn vti_brd_004_update_refuses_what_its_specification_declares() {
    let tv = community(InProcessBox::new()).await;
    let chair = admin(&tv).await;
    let board = create_board(&tv, &chair, board_body()).await;
    let up = |extra: Value| {
        let mut p = extra;
        p["boardId"] = json!(board);
        p
    };

    let (_, doc) = call(
        &tv,
        &chair,
        &uri("update"),
        json!({ "boardId": UNKNOWN_BOARD, "title": "x" }),
    )
    .await;
    assert_eq!(tt_error_code(&doc), UPDATE_ERR_NOT_FOUND, "{doc}");

    // Voting has opened: its window and the audience are fixed.
    let now = Utc::now();
    let (_, doc) = call(
        &tv,
        &chair,
        &uri("update"),
        up(json!({ "voting": { "opensAt": stamp(now - Duration::minutes(30)), "closesAt": stamp(now + Duration::hours(5)) } })),
    )
    .await;
    assert_eq!(
        tt_error_code(&doc),
        UPDATE_ERR_FIXED_AFTER_VOTING_OPENS,
        "{doc}"
    );

    let (_, doc) = call(
        &tv,
        &chair,
        &uri("update"),
        up(json!({ "proposals": { "opensAt": stamp(now - Duration::hours(1)), "closesAt": stamp(now + Duration::hours(9)) } })),
    )
    .await;
    assert_eq!(tt_error_code(&doc), UPDATE_ERR_SCHEDULE_INVALID, "{doc}");

    let mut slots = board_body()["timetable"].clone();
    slots[0]["endsAt"] = slots[0]["startsAt"].clone();
    let (_, doc) = call(
        &tv,
        &chair,
        &uri("update"),
        up(json!({ "timetable": slots })),
    )
    .await;
    assert_eq!(tt_error_code(&doc), UPDATE_ERR_TIMETABLE_INVALID, "{doc}");

    let mut t = template();
    t["questions"][0]["maxSelections"] = json!(5);
    let (_, doc) = call(&tv, &chair, &uri("update"), up(json!({ "template": t }))).await;
    assert_eq!(tt_error_code(&doc), UPDATE_ERR_TEMPLATE_INVALID, "{doc}");

    let mut t = template();
    t["ballotBox"] = json!(OTHER_BOX);
    let (_, doc) = call(&tv, &chair, &uri("update"), up(json!({ "template": t }))).await;
    assert_eq!(
        tt_error_code(&doc),
        UPDATE_ERR_BALLOT_BOX_NOT_TRUSTED,
        "{doc}"
    );

    let (status, doc) = call(
        &tv,
        &chair,
        &uri("update"),
        up(json!({ "status": "closed", "title": "Renamed" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    assert_eq!(payload(&doc)["board"]["status"], "closed");
    assert_eq!(payload(&doc)["board"]["title"], "Renamed");
    let (_, doc) = call(
        &tv,
        &chair,
        &uri("update"),
        up(json!({ "status": "closed" })),
    )
    .await;
    assert_eq!(tt_error_code(&doc), UPDATE_ERR_STATUS_INVALID, "{doc}");

    let (status, _) = call(
        &tv,
        &chair,
        &uri("update"),
        up(json!({ "status": "archived" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (_, doc) = call(&tv, &chair, &uri("update"), up(json!({ "title": "Again" }))).await;
    assert_eq!(tt_error_code(&doc), UPDATE_ERR_ARCHIVED, "{doc}");
}

// ─── reads ───────────────────────────────────────────────────────────────

/// VTI-BRD-003: a board the caller may not see is `notFound`; cursors are bound.
#[tokio::test]
async fn vti_brd_003_reads_refuse_unseen_boards_and_foreign_cursors() {
    let tv = community(InProcessBox::new()).await;
    let chair = admin(&tv).await;
    let alice = member(&tv).await;
    let board = create_board(&tv, &chair, board_body()).await;

    let (_, doc) = call(&tv, &alice, &uri("list"), json!({ "cursor": "1.deadbeef" })).await;
    assert_eq!(tt_error_code(&doc), LIST_ERR_CURSOR_INVALID, "{doc}");
    let (status, doc) = call(&tv, &alice, &uri("list"), json!({})).await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    assert_eq!(payload(&doc)["boards"][0]["boardId"], board.as_str());
    assert_eq!(payload(&doc)["boards"][0]["facilitator"], false);

    let (_, doc) = call(
        &tv,
        &alice,
        &uri("show"),
        json!({ "boardId": UNKNOWN_BOARD }),
    )
    .await;
    assert_eq!(tt_error_code(&doc), SHOW_ERR_NOT_FOUND, "{doc}");
    let (_, doc) = call(
        &tv,
        &alice,
        &uri("show"),
        json!({ "boardId": board, "cursor": "1.deadbeef" }),
    )
    .await;
    assert_eq!(tt_error_code(&doc), SHOW_ERR_CURSOR_INVALID, "{doc}");

    let (_, doc) = call(
        &tv,
        &alice,
        &uri("notes/list"),
        json!({ "boardId": UNKNOWN_BOARD }),
    )
    .await;
    assert_eq!(tt_error_code(&doc), NOTES_LIST_ERR_NOT_FOUND, "{doc}");
    let (_, doc) = call(
        &tv,
        &alice,
        &uri("notes/list"),
        json!({ "boardId": board, "ideaId": UNKNOWN_IDEA }),
    )
    .await;
    assert_eq!(tt_error_code(&doc), NOTES_LIST_ERR_IDEA_NOT_FOUND, "{doc}");
    let (_, doc) = call(
        &tv,
        &alice,
        &uri("notes/list"),
        json!({ "boardId": board, "cursor": "1.deadbeef" }),
    )
    .await;
    assert_eq!(tt_error_code(&doc), NOTES_LIST_ERR_CURSOR_INVALID, "{doc}");
}

// ─── ideas ───────────────────────────────────────────────────────────────

/// VTI-BRD-010.
#[tokio::test]
async fn vti_brd_010_propose_refuses_what_its_specification_declares() {
    let tv = community(InProcessBox::new()).await;
    let chair = admin(&tv).await;
    let alice = member(&tv).await;
    let mut body = board_body();
    body["maxIdeasPerMember"] = json!(1);
    let board = create_board(&tv, &chair, body).await;
    let later = {
        let now = Utc::now();
        let mut b = board_body();
        b["proposals"] = json!({ "opensAt": stamp(now + Duration::hours(1)), "closesAt": stamp(now + Duration::hours(2)) });
        b["voting"] = json!({ "opensAt": stamp(now + Duration::hours(1)), "closesAt": stamp(now + Duration::hours(3)) });
        create_board(&tv, &chair, b).await
    };
    let idea = |board: &str, topic: &str, format: &str| json!({ "boardId": board, "title": "A session", "description": "What it covers.", "topic": topic, "format": format });

    let (_, doc) = call(
        &tv,
        &alice,
        &uri("ideas/propose"),
        idea(UNKNOWN_BOARD, "Identity", "Talk"),
    )
    .await;
    assert_eq!(tt_error_code(&doc), PROPOSE_ERR_NOT_FOUND, "{doc}");
    let (_, doc) = call(
        &tv,
        &alice,
        &uri("ideas/propose"),
        idea(&later, "Identity", "Talk"),
    )
    .await;
    assert_eq!(tt_error_code(&doc), PROPOSE_ERR_PROPOSALS_CLOSED, "{doc}");
    let (_, doc) = call(
        &tv,
        &alice,
        &uri("ideas/propose"),
        idea(&board, "Cooking", "Talk"),
    )
    .await;
    assert_eq!(tt_error_code(&doc), PROPOSE_ERR_TOPIC_UNKNOWN, "{doc}");
    let (_, doc) = call(
        &tv,
        &alice,
        &uri("ideas/propose"),
        idea(&board, "Identity", "Dance"),
    )
    .await;
    assert_eq!(tt_error_code(&doc), PROPOSE_ERR_FORMAT_UNKNOWN, "{doc}");

    let (status, doc) = call(
        &tv,
        &alice,
        &uri("ideas/propose"),
        idea(&board, "Identity", "Talk"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    let shown = &payload(&doc)["idea"];
    assert_eq!(shown["state"], "proposed");
    assert_eq!(shown["proposer"]["you"], true, "{doc}");
    let (_, doc) = call(
        &tv,
        &alice,
        &uri("ideas/propose"),
        idea(&board, "Identity", "Talk"),
    )
    .await;
    assert_eq!(tt_error_code(&doc), PROPOSE_ERR_LIMIT_REACHED, "{doc}");
}

/// VTI-BRD-012: only the proposer changes or withdraws an idea, and only while it is proposed.
#[tokio::test]
async fn vti_brd_012_a_proposer_alone_changes_a_proposed_idea() {
    let tv = community(InProcessBox::new()).await;
    let chair = admin(&tv).await;
    let (alice, bob) = (member(&tv).await, member(&tv).await);
    let board = create_board(&tv, &chair, board_body()).await;
    let mine = propose(&tv, &alice, &board, "Mine").await;
    let gone = propose(&tv, &alice, &board, "Gone").await;
    let accepted = propose(&tv, &alice, &board, "Accepted").await;

    let (_, doc) = call(
        &tv,
        &alice,
        &uri("ideas/update"),
        json!({ "ideaId": UNKNOWN_IDEA, "title": "x" }),
    )
    .await;
    assert_eq!(tt_error_code(&doc), IDEA_UPDATE_ERR_NOT_FOUND, "{doc}");
    let (_, doc) = call(
        &tv,
        &bob,
        &uri("ideas/update"),
        json!({ "ideaId": mine, "title": "x" }),
    )
    .await;
    assert_eq!(tt_error_code(&doc), IDEA_UPDATE_ERR_NOT_PROPOSER, "{doc}");
    let (_, doc) = call(
        &tv,
        &alice,
        &uri("ideas/update"),
        json!({ "ideaId": mine, "topic": "Cooking" }),
    )
    .await;
    assert_eq!(tt_error_code(&doc), IDEA_UPDATE_ERR_TOPIC_UNKNOWN, "{doc}");
    let (_, doc) = call(
        &tv,
        &alice,
        &uri("ideas/update"),
        json!({ "ideaId": mine, "format": "Dance" }),
    )
    .await;
    assert_eq!(tt_error_code(&doc), IDEA_UPDATE_ERR_FORMAT_UNKNOWN, "{doc}");
    let (status, doc) = call(
        &tv,
        &alice,
        &uri("ideas/update"),
        json!({ "ideaId": mine, "title": "Retitled" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    assert_eq!(payload(&doc)["idea"]["title"], "Retitled");

    let (_, doc) = call(
        &tv,
        &alice,
        &uri("ideas/withdraw"),
        json!({ "ideaId": UNKNOWN_IDEA }),
    )
    .await;
    assert_eq!(tt_error_code(&doc), WITHDRAW_ERR_NOT_FOUND, "{doc}");
    let (_, doc) = call(&tv, &bob, &uri("ideas/withdraw"), json!({ "ideaId": mine })).await;
    assert_eq!(tt_error_code(&doc), WITHDRAW_ERR_NOT_PROPOSER, "{doc}");
    let (status, doc) = call(
        &tv,
        &alice,
        &uri("ideas/withdraw"),
        json!({ "ideaId": gone }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    assert_eq!(payload(&doc)["idea"]["state"], "withdrawn");

    // A withdrawn idea is shown only to its proposer and the facilitators.
    let (_, doc) = call(
        &tv,
        &bob,
        &uri("ideas/update"),
        json!({ "ideaId": gone, "title": "x" }),
    )
    .await;
    assert_eq!(tt_error_code(&doc), IDEA_UPDATE_ERR_IDEA_NOT_FOUND, "{doc}");
    let (_, doc) = call(&tv, &bob, &uri("ideas/withdraw"), json!({ "ideaId": gone })).await;
    assert_eq!(tt_error_code(&doc), WITHDRAW_ERR_IDEA_NOT_FOUND, "{doc}");
    let (_, doc) = call(
        &tv,
        &alice,
        &uri("ideas/withdraw"),
        json!({ "ideaId": gone }),
    )
    .await;
    assert_eq!(tt_error_code(&doc), WITHDRAW_ERR_NOT_PROPOSED, "{doc}");

    // Once its election is opened, the idea's text is its manifest's.
    let (status, doc) = decide(&tv, &chair, &accepted, json!({ "decision": "accept" })).await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    let (_, doc) = call(
        &tv,
        &alice,
        &uri("ideas/update"),
        json!({ "ideaId": accepted, "title": "x" }),
    )
    .await;
    assert_eq!(tt_error_code(&doc), IDEA_UPDATE_ERR_NOT_PROPOSED, "{doc}");
}

/// VTI-BRD-013, VTI-BRD-031, VTI-BRD-033: accepting opens one election, and a board never
/// carries anything about tickets or ballots.
#[tokio::test]
async fn vti_brd_031_accepting_an_idea_opens_its_election() {
    let bx = InProcessBox::new();
    let tv = community(bx.clone()).await;
    let chair = admin(&tv).await;
    let co_chair = admin(&tv).await;
    // The chair is also a member: only the board's audience proposes (VTI-BRD-010).
    vtc_service::members::store_member(
        &tv.state.members_ks,
        &vtc_service::members::Member::fresh(chair.did.clone()),
    )
    .await
    .unwrap();
    let (alice, bob) = (member(&tv).await, member(&tv).await);
    let board = create_board(&tv, &chair, board_body()).await;
    let idea = propose(&tv, &alice, &board, "Accessible sign-in").await;
    let other = propose(&tv, &alice, &board, "Wallet recovery").await;
    let gone = propose(&tv, &alice, &board, "Gone").await;
    call(
        &tv,
        &alice,
        &uri("ideas/withdraw"),
        json!({ "ideaId": gone }),
    )
    .await;
    let own = propose(&tv, &chair, &board, "The chair's own").await;

    let (_, doc) = decide(&tv, &chair, UNKNOWN_IDEA, json!({ "decision": "accept" })).await;
    assert_eq!(tt_error_code(&doc), DECIDE_ERR_NOT_FOUND, "{doc}");
    // Bob neither facilitates nor proposed it: a withdrawn idea is not his to see.
    let (_, doc) = decide(&tv, &bob, &gone, json!({ "decision": "accept" })).await;
    assert_eq!(tt_error_code(&doc), DECIDE_ERR_IDEA_NOT_FOUND, "{doc}");
    let (_, doc) = decide(&tv, &bob, &idea, json!({ "decision": "accept" })).await;
    assert_eq!(tt_error_code(&doc), "permissionDenied", "{doc}");
    // Another facilitator exists, so the chair does not decide their own idea.
    let (_, doc) = decide(
        &tv,
        &chair,
        &own,
        json!({ "decision": "decline", "reason": "mine" }),
    )
    .await;
    assert_eq!(tt_error_code(&doc), DECIDE_ERR_OWN_IDEA, "{doc}");
    let (status, _) = decide(
        &tv,
        &co_chair,
        &own,
        json!({ "decision": "decline", "reason": "A duplicate." }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (_, doc) = decide(&tv, &chair, &other, json!({ "decision": "decline" })).await;
    assert_eq!(tt_error_code(&doc), DECIDE_ERR_REASON_REQUIRED, "{doc}");
    let (_, doc) = decide(
        &tv,
        &chair,
        &other,
        json!({ "decision": "merge", "mergeInto": other }),
    )
    .await;
    assert_eq!(
        tt_error_code(&doc),
        DECIDE_ERR_MERGE_TARGET_INVALID,
        "{doc}"
    );

    // The ballot box refuses: the idea stays proposed, and the facilitator sees why.
    bx.refuse.store(true, Ordering::SeqCst);
    let (_, doc) = decide(&tv, &chair, &idea, json!({ "decision": "accept" })).await;
    assert_eq!(tt_error_code(&doc), DECIDE_ERR_ELECTION_REFUSED, "{doc}");
    let (_, shown) = call(&tv, &chair, &uri("show"), json!({ "boardId": board })).await;
    let refused = payload(&shown)["ideas"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["ideaId"] == idea.as_str())
        .unwrap()
        .clone();
    assert_eq!(refused["state"], "proposed", "{shown}");
    assert!(refused["opening"]["refusal"]["code"].is_string(), "{shown}");
    bx.refuse.store(false, Ordering::SeqCst);

    let (status, doc) = decide(&tv, &chair, &idea, json!({ "decision": "accept" })).await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    let accepted = &payload(&doc)["idea"];
    assert_eq!(accepted["state"], "open", "{doc}");
    let election = accepted["election"]["electionId"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(election, format!("board.{board}.{idea}"));
    let (_, doc) = decide(
        &tv,
        &chair,
        &idea,
        json!({ "decision": "decline", "reason": "late" }),
    )
    .await;
    assert_eq!(tt_error_code(&doc), DECIDE_ERR_STATE_INVALID, "{doc}");

    // The election is an ordinary one: members see it among the community's elections.
    let (status, doc) = call(
        &tv,
        &alice,
        &format!("{SPEC}vtc/elections/show/0.6"),
        json!({ "electionId": election }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    assert_eq!(payload(&doc)["manifest"]["title"], "Accessible sign-in");
    assert_eq!(payload(&doc)["manifest"]["binding"], false);

    // VTI-BRD-033: nothing on the board says who took a ticket or voted.
    let (_, shown) = call(&tv, &alice, &uri("show"), json!({ "boardId": board })).await;
    let text = shown.to_string();
    assert!(
        !text.contains("ticket") && !text.contains("Ticket"),
        "{shown}"
    );
    for i in payload(&shown)["ideas"].as_array().unwrap() {
        assert!(i.get("opening").is_none(), "facilitators only: {i}");
    }

    // A board whose voting has closed opens no election.
    let now = Utc::now();
    let mut past = board_body();
    past["proposals"] = json!({ "opensAt": stamp(now - Duration::hours(3)), "closesAt": stamp(now - Duration::hours(2)) });
    past["voting"] = json!({ "opensAt": stamp(now - Duration::hours(2)), "closesAt": stamp(now - Duration::hours(1)) });
    let closed = create_board(&tv, &chair, past).await;
    let late = vtc_service::boards::Idea {
        idea_id: vtc_service::boards::new_idea_id(),
        board_id: closed,
        state: vtc_service::boards::StoredIdeaState::Proposed,
        title: Some("Late".into()),
        description: Some("Too late.".into()),
        format: None,
        topic: None,
        proposer: "dir_AAAAAAAAAAAAAAAAAAAAAA".into(),
        proposed_at: now - Duration::hours(2),
        election_id: None,
        accepted_at: None,
        refusal: None,
        decision: None,
    };
    vtc_service::boards::put_idea(&tv.state.boards_ks, &late)
        .await
        .unwrap();
    let (_, doc) = decide(&tv, &chair, &late.idea_id, json!({ "decision": "accept" })).await;
    assert_eq!(tt_error_code(&doc), DECIDE_ERR_VOTING_CLOSED, "{doc}");
}

/// VTI-BRD-040, VTI-BRD-041: a selection records the result it was made with.
#[tokio::test]
async fn vti_brd_040_select_records_the_result_it_was_made_with() {
    let bx = InProcessBox::new();
    let tv = community(bx.clone()).await;
    let chair = admin(&tv).await;
    let (alice, bob) = (member(&tv).await, member(&tv).await);
    let board = create_board(&tv, &chair, board_body()).await;
    let first = propose(&tv, &alice, &board, "First").await;
    let second = propose(&tv, &alice, &board, "Second").await;
    let waiting = propose(&tv, &alice, &board, "Waiting").await;
    let gone = propose(&tv, &alice, &board, "Gone").await;
    call(
        &tv,
        &alice,
        &uri("ideas/withdraw"),
        json!({ "ideaId": gone }),
    )
    .await;
    for i in [&first, &second] {
        let (status, doc) = decide(&tv, &chair, i, json!({ "decision": "accept" })).await;
        assert_eq!(status, StatusCode::OK, "{doc}");
    }
    let select = |idea: &str, extra: Value| {
        let mut p = extra;
        p["ideaId"] = json!(idea);
        p
    };

    let (_, doc) = call(
        &tv,
        &chair,
        &uri("ideas/select"),
        select(UNKNOWN_IDEA, json!({ "decision": "selected" })),
    )
    .await;
    assert_eq!(tt_error_code(&doc), SELECT_ERR_NOT_FOUND, "{doc}");
    let (_, doc) = call(
        &tv,
        &bob,
        &uri("ideas/select"),
        select(&gone, json!({ "decision": "selected" })),
    )
    .await;
    assert_eq!(tt_error_code(&doc), SELECT_ERR_IDEA_NOT_FOUND, "{doc}");
    let (_, doc) = call(
        &tv,
        &chair,
        &uri("ideas/select"),
        select(&waiting, json!({ "decision": "selected" })),
    )
    .await;
    assert_eq!(tt_error_code(&doc), SELECT_ERR_STATE_INVALID, "{doc}");
    // Voting is still open: nothing is tallied.
    let (_, doc) = call(
        &tv,
        &chair,
        &uri("ideas/select"),
        select(&first, json!({ "decision": "selected" })),
    )
    .await;
    assert_eq!(tt_error_code(&doc), SELECT_ERR_NOT_TALLIED, "{doc}");

    // Past the close, the ballot box tallies.
    bx.ahead.store(3 * 3600, Ordering::SeqCst);
    let (_, doc) = call(
        &tv,
        &chair,
        &uri("ideas/select"),
        select(
            &first,
            json!({ "decision": "selected", "slotId": "z-9999" }),
        ),
    )
    .await;
    assert_eq!(tt_error_code(&doc), SELECT_ERR_SLOT_UNKNOWN, "{doc}");
    let (_, doc) = call(
        &tv,
        &chair,
        &uri("ideas/select"),
        select(
            &first,
            json!({ "decision": "selected", "departsFromRule": true }),
        ),
    )
    .await;
    assert_eq!(tt_error_code(&doc), SELECT_ERR_REASON_REQUIRED, "{doc}");
    let (status, doc) = call(
        &tv,
        &chair,
        &uri("ideas/select"),
        select(
            &first,
            json!({ "decision": "selected", "slotId": "a-0900" }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    let selected = &payload(&doc)["idea"];
    assert_eq!(selected["state"], "selected");
    assert_eq!(selected["decision"]["slotId"], "a-0900");
    assert_eq!(selected["election"]["state"], "tallied");
    assert_eq!(selected["election"]["certified"], false, "{doc}");
    assert_eq!(selected["election"]["result"]["ballotsCounted"], 0);

    let (_, doc) = call(
        &tv,
        &chair,
        &uri("ideas/select"),
        select(
            &second,
            json!({ "decision": "selected", "slotId": "a-0900" }),
        ),
    )
    .await;
    assert_eq!(tt_error_code(&doc), SELECT_ERR_SLOT_TAKEN, "{doc}");
    let (status, doc) = call(
        &tv,
        &chair,
        &uri("ideas/select"),
        select(&second, json!({ "decision": "notSelected", "departsFromRule": true, "reason": "The room is too small." })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    assert_eq!(payload(&doc)["idea"]["state"], "notSelected");
}

// ─── notes ───────────────────────────────────────────────────────────────

/// VTI-BRD-020, VTI-BRD-021: notes, their withdrawal and their hiding.
#[tokio::test]
async fn vti_brd_021_notes_are_added_withdrawn_and_hidden() {
    let tv = community(InProcessBox::new()).await;
    let chair = admin(&tv).await;
    let (alice, bob) = (member(&tv).await, member(&tv).await);
    let board = create_board(&tv, &chair, board_body()).await;
    let idea = propose(&tv, &alice, &board, "An idea").await;
    let gone = propose(&tv, &alice, &board, "Gone").await;
    call(
        &tv,
        &alice,
        &uri("ideas/withdraw"),
        json!({ "ideaId": gone }),
    )
    .await;
    let add = |board: &str, idea: Option<&str>, text: &str| {
        let mut p = json!({ "boardId": board, "text": text });
        if let Some(i) = idea {
            p["ideaId"] = json!(i);
        }
        p
    };

    let (_, doc) = call(&tv, &bob, &uri("notes/add"), add(UNKNOWN_BOARD, None, "x")).await;
    assert_eq!(tt_error_code(&doc), NOTES_ADD_ERR_NOT_FOUND, "{doc}");
    let (_, doc) = call(
        &tv,
        &bob,
        &uri("notes/add"),
        add(&board, Some(UNKNOWN_IDEA), "x"),
    )
    .await;
    assert_eq!(tt_error_code(&doc), NOTES_ADD_ERR_IDEA_NOT_FOUND, "{doc}");
    let (_, doc) = call(
        &tv,
        &alice,
        &uri("notes/add"),
        add(&board, Some(&gone), "x"),
    )
    .await;
    assert_eq!(tt_error_code(&doc), NOTES_ADD_ERR_IDEA_WITHDRAWN, "{doc}");

    let (status, doc) = call(
        &tv,
        &bob,
        &uri("notes/add"),
        add(&board, Some(&idea), "Happy to co-host."),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    let bobs = payload(&doc)["note"]["noteId"]
        .as_str()
        .unwrap()
        .to_string();
    let (status, doc) = call(
        &tv,
        &alice,
        &uri("notes/add"),
        add(&board, None, "Lunch is at noon."),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    let alices = payload(&doc)["note"]["noteId"]
        .as_str()
        .unwrap()
        .to_string();

    let (_, doc) = call(
        &tv,
        &bob,
        &uri("notes/withdraw"),
        json!({ "noteId": UNKNOWN_NOTE }),
    )
    .await;
    assert_eq!(
        tt_error_code(&doc),
        NOTE_WITHDRAW_ERR_NOTE_NOT_FOUND,
        "{doc}"
    );
    let (_, doc) = call(
        &tv,
        &bob,
        &uri("notes/withdraw"),
        json!({ "noteId": alices }),
    )
    .await;
    assert_eq!(tt_error_code(&doc), NOTE_WITHDRAW_ERR_NOT_AUTHOR, "{doc}");
    let (status, _) = call(
        &tv,
        &alice,
        &uri("notes/withdraw"),
        json!({ "noteId": alices }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (_, doc) = call(
        &tv,
        &alice,
        &uri("notes/withdraw"),
        json!({ "noteId": alices }),
    )
    .await;
    assert_eq!(
        tt_error_code(&doc),
        NOTE_WITHDRAW_ERR_ALREADY_WITHDRAWN,
        "{doc}"
    );
    // Bob sees that a note was withdrawn, not what it said; Alice still reads her own.
    let (_, doc) = call(&tv, &bob, &uri("notes/list"), json!({ "boardId": board })).await;
    let n = &payload(&doc)["notes"][0];
    assert_eq!(n["state"], "withdrawn", "{doc}");
    assert!(n.get("text").is_none(), "{doc}");
    let (_, doc) = call(&tv, &alice, &uri("notes/list"), json!({ "boardId": board })).await;
    assert_eq!(payload(&doc)["notes"][0]["text"], "Lunch is at noon.");

    let (_, doc) = call(
        &tv,
        &chair,
        &uri("notes/hide"),
        json!({ "noteId": UNKNOWN_NOTE, "action": "hide", "reason": "x" }),
    )
    .await;
    assert_eq!(tt_error_code(&doc), HIDE_ERR_NOTE_NOT_FOUND, "{doc}");
    let (_, doc) = call(
        &tv,
        &chair,
        &uri("notes/hide"),
        json!({ "noteId": bobs, "action": "hide" }),
    )
    .await;
    assert_eq!(tt_error_code(&doc), HIDE_ERR_REASON_REQUIRED, "{doc}");
    let (_, doc) = call(
        &tv,
        &chair,
        &uri("notes/hide"),
        json!({ "noteId": bobs, "action": "unhide" }),
    )
    .await;
    assert_eq!(tt_error_code(&doc), HIDE_ERR_STATE_INVALID, "{doc}");
    let (_, doc) = call(
        &tv,
        &bob,
        &uri("notes/hide"),
        json!({ "noteId": bobs, "action": "hide", "reason": "x" }),
    )
    .await;
    assert_eq!(tt_error_code(&doc), "permissionDenied", "{doc}");
    let (status, doc) = call(
        &tv,
        &chair,
        &uri("notes/hide"),
        json!({ "noteId": bobs, "action": "hide", "reason": "Off topic." }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    let (_, doc) = call(
        &tv,
        &alice,
        &uri("notes/list"),
        json!({ "boardId": board, "ideaId": idea }),
    )
    .await;
    let n = &payload(&doc)["notes"][0];
    assert_eq!(n["state"], "hidden");
    assert_eq!(n["hiddenReason"], "Off topic.");
    assert!(n.get("text").is_none(), "{doc}");
    let (_, doc) = call(
        &tv,
        &bob,
        &uri("notes/list"),
        json!({ "boardId": board, "ideaId": idea }),
    )
    .await;
    assert_eq!(payload(&doc)["notes"][0]["text"], "Happy to co-host.");

    // The rate a member adds notes at is bounded.
    let mut limited = false;
    for i in 0..12 {
        let (_, doc) = call(
            &tv,
            &bob,
            &uri("notes/add"),
            add(&board, None, &format!("note {i}")),
        )
        .await;
        if tt_error_code(&doc) == NOTES_ADD_ERR_RATE_LIMITED {
            limited = true;
            break;
        }
    }
    assert!(limited, "twelve notes in a minute are not all taken");

    // A closed board takes no notes.
    call(
        &tv,
        &chair,
        &uri("update"),
        json!({ "boardId": board, "status": "closed" }),
    )
    .await;
    let (_, doc) = call(&tv, &alice, &uri("notes/add"), add(&board, None, "late")).await;
    assert_eq!(tt_error_code(&doc), NOTES_ADD_ERR_BOARD_CLOSED, "{doc}");
}

// ─── who may act ─────────────────────────────────────────────────────────

/// VTI-BRD-002: `vtc.boards.manage` qualified by a board facilitates that board alone.
#[tokio::test]
async fn vti_brd_002_a_qualified_facilitator_runs_one_board_only() {
    let tv = community(InProcessBox::new()).await;
    let chair = admin(&tv).await;
    let alice = member(&tv).await;
    let one = create_board(&tv, &chair, board_body()).await;
    let two = create_board(&tv, &chair, board_body()).await;
    let fac = facilitator_of(&tv, &one).await;
    let on_one = propose(&tv, &alice, &one, "On one").await;
    let on_two = propose(&tv, &alice, &two, "On two").await;

    let (status, doc) = decide(
        &tv,
        &fac,
        &on_one,
        json!({ "decision": "decline", "reason": "A duplicate." }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    let (_, doc) = decide(
        &tv,
        &fac,
        &on_two,
        json!({ "decision": "decline", "reason": "x" }),
    )
    .await;
    assert_eq!(tt_error_code(&doc), "permissionDenied", "{doc}");
    let (_, doc) = call(&tv, &fac, &uri("show"), json!({ "boardId": one })).await;
    assert_eq!(payload(&doc)["board"]["facilitator"], true, "{doc}");
    let (_, doc) = call(&tv, &fac, &uri("show"), json!({ "boardId": two })).await;
    assert_eq!(payload(&doc)["board"]["facilitator"], false, "{doc}");
}

/// VTI-BRD-050, VTI-BRD-051: the portal's key signs a member's proposals, never a
/// facilitator's decision — even for a member who facilitates.
#[tokio::test]
async fn vti_brd_051_the_portal_key_proposes_but_never_decides() {
    let tv = community(InProcessBox::new()).await;
    let chair = admin(&tv).await;
    let alice = member(&tv).await;
    let board = create_board(&tv, &chair, board_body()).await;
    let fac = facilitator_of(&tv, &board).await;
    let idea = propose(&tv, &alice, &board, "An idea").await;

    // Arm the portal's sign-in key `K_b` for the facilitator's live session.
    let k_b = Party::new();
    let now = vti_common::auth::session::now_epoch();
    let session: vti_common::auth::session::Session = serde_json::from_value(json!({
        "session_id": "sess-boards-portal",
        "did": fac.did,
        "challenge": "c",
        "state": "Authenticated",
        "created_at": now,
        "refresh_token": null,
        "refresh_expires_at": now + 3600,
        "not_after": now + 3600,
        "session_pubkey_b58btc": k_b.did.strip_prefix("did:key:").unwrap(),
    }))
    .unwrap();
    vti_common::auth::session::store_session(&tv.state.member_sessions_ks, &session)
        .await
        .unwrap();
    vtc_service::member_portal::delegation::record(
        &tv.state.member_sessions_ks,
        &k_b.did,
        &vtc_service::member_portal::delegation::Delegation {
            member_did: fac.did.clone(),
            session_id: "sess-boards-portal".into(),
            scope: vec!["vtc/boards".into()],
            not_after: now + 3600,
            grant_id: Some("urn:uuid:boards-portal-grant".into()),
        },
    )
    .await
    .unwrap();

    let (status, doc) = call(
        &tv,
        &k_b,
        &uri("ideas/propose"),
        json!({ "boardId": board, "title": "From the portal", "description": "Signed by K_b.", "topic": "Identity", "format": "Talk" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    assert_eq!(payload(&doc)["idea"]["proposer"]["you"], true, "{doc}");

    let (status, doc) = decide(
        &tv,
        &k_b,
        &idea,
        json!({ "decision": "decline", "reason": "x" }),
    )
    .await;
    assert_ne!(status, StatusCode::OK, "{doc}");
    let (status, doc) = decide(
        &tv,
        &fac,
        &idea,
        json!({ "decision": "decline", "reason": "Out of scope." }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
}

/// VTI-BRD-060: a departing member's proposed ideas are withdrawn; an accepted one stays.
#[tokio::test]
async fn vti_brd_060_departure_withdraws_proposed_ideas() {
    let tv = community(InProcessBox::new()).await;
    let chair = admin(&tv).await;
    let alice = member(&tv).await;
    let board = create_board(&tv, &chair, board_body()).await;
    let proposed = propose(&tv, &alice, &board, "Proposed").await;
    let accepted = propose(&tv, &alice, &board, "Accepted").await;
    decide(&tv, &chair, &accepted, json!({ "decision": "accept" })).await;

    let entry = vtc_service::directory::cards::entry_of(tv.state.directory.ks(), &alice.did)
        .await
        .unwrap()
        .unwrap();
    let withdrawn = vtc_service::boards::on_departure(&tv.state, &entry, true)
        .await
        .unwrap();
    assert_eq!(withdrawn, 1);
    let p = vtc_service::boards::get_idea(&tv.state.boards_ks, &proposed)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(p.state, vtc_service::boards::StoredIdeaState::Withdrawn);
    assert!(p.title.is_none(), "erased");
    let a = vtc_service::boards::get_idea(&tv.state.boards_ks, &accepted)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        a.title.as_deref(),
        Some("Accepted"),
        "its manifest carries it"
    );
}

/// VTI-BRD-031: two facilitators accepting one idea at once — the board lock is not held while
/// the ballot box is asked (R1.3), so the two can overlap. However they interleave, neither is
/// answered as refused, the idea ends open, and it has one election.
#[tokio::test]
async fn vti_brd_031_concurrent_accepts_open_one_election_and_refuse_neither() {
    let bx = InProcessBox::new();
    let tv = community(bx.clone()).await;
    let chair = admin(&tv).await;
    let co_chair = admin(&tv).await;
    let alice = member(&tv).await;
    let board = create_board(&tv, &chair, board_body()).await;
    let idea = propose(&tv, &alice, &board, "Accessible sign-in").await;

    let ((s1, d1), (s2, d2)) = tokio::join!(
        decide(&tv, &chair, &idea, json!({ "decision": "accept" })),
        decide(&tv, &co_chair, &idea, json!({ "decision": "accept" })),
    );
    for (status, doc) in [(s1, &d1), (s2, &d2)] {
        if status != StatusCode::OK {
            // The later one may only find the idea already accepted.
            assert_eq!(tt_error_code(doc), DECIDE_ERR_STATE_INVALID, "{doc}");
        }
    }
    assert!(
        s1 == StatusCode::OK || s2 == StatusCode::OK,
        "one accept succeeds: {d1} / {d2}"
    );

    let (_, shown) = call(&tv, &chair, &uri("show"), json!({ "boardId": board })).await;
    let listed = payload(&shown)["ideas"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["ideaId"] == idea.as_str())
        .unwrap()
        .clone();
    assert_eq!(listed["state"], "open", "{shown}");
    assert!(
        listed
            .get("opening")
            .is_none_or(|o| o.get("refusal").is_none()),
        "{shown}"
    );
    let ours: Vec<_> = vtc_service::elections::store::all(tv.state.elections.ks())
        .await
        .unwrap()
        .into_iter()
        .filter(|r| r.election_id.ends_with(idea.as_str()))
        .collect();
    assert_eq!(ours.len(), 1);
}

// ─── closing and deleting ────────────────────────────────────────────────

const DELETE_ERR_NOT_FOUND: &str = b::delete::v0_1::error_codes::NOT_FOUND.code;
const DELETE_ERR_NOT_CLOSED: &str = b::delete::v0_1::error_codes::NOT_CLOSED.code;
const DELETE_ERR_ELECTIONS_RUNNING: &str = b::delete::v0_1::error_codes::ELECTIONS_RUNNING.code;

async fn election_state(tv: &TestVtc, election_id: &str) -> String {
    vtc_service::elections::store::get(tv.state.elections.ks(), election_id)
        .await
        .unwrap()
        .map_or_else(|| "gone".into(), |r| r.state(Utc::now()).to_string())
}

/// Wait for the background ask after a close to land, as the sweeper would otherwise.
async fn settled(tv: &TestVtc, election_id: &str) -> String {
    for _ in 0..50 {
        let s = election_state(tv, election_id).await;
        if matches!(s.as_str(), "closed" | "tallied" | "cancelled") {
            return s;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    election_state(tv, election_id).await
}

async fn accepted(tv: &TestVtc, chair: &Party, idea: &str) -> String {
    let (status, doc) = decide(tv, chair, idea, json!({ "decision": "accept" })).await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    payload(&doc)["idea"]["election"]["electionId"]
        .as_str()
        .unwrap()
        .to_string()
}

/// VTI-BRD-006: closing a board ends its voting — an election open for voting is closed early,
/// one not yet open is cancelled and its idea not selected, one that cannot close early runs on —
/// and a closed board opens no election (VTI-BRD-005).
#[tokio::test]
async fn vti_brd_006_closing_a_board_ends_its_voting() {
    let bx = InProcessBox::new();
    let tv = community(bx.clone()).await;
    let chair = admin(&tv).await;
    let alice = member(&tv).await;

    // Voting open now: one idea closes early, one is made to look like an older election that
    // does not allow it.
    let board = create_board(&tv, &chair, board_body()).await;
    let early = propose(&tv, &alice, &board, "Closes early").await;
    let older = propose(&tv, &alice, &board, "Runs on").await;
    let waiting = propose(&tv, &alice, &board, "Never accepted").await;
    let early_e = accepted(&tv, &chair, &early).await;
    let older_e = accepted(&tv, &chair, &older).await;
    let ks = tv.state.elections.ks();
    let mut rec = vtc_service::elections::store::get(ks, &older_e)
        .await
        .unwrap()
        .unwrap();
    rec.manifest["allowEarlyClose"] = json!(false);
    vtc_service::elections::store::put(ks, &rec).await.unwrap();

    let (status, doc) = call(
        &tv,
        &chair,
        &uri("update"),
        json!({ "boardId": board, "status": "closed" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    let closing = &payload(&doc)["closing"];
    assert_eq!(closing["closedEarly"], 1, "{doc}");
    assert_eq!(closing["cancelled"], 0, "{doc}");
    assert_eq!(closing["runningToClose"], json!([older]), "{doc}");
    assert_eq!(settled(&tv, &early_e).await, "closed");
    assert_eq!(election_state(&tv, &older_e).await, "voting");

    // Closed: no idea on it is put to a vote.
    let (_, doc) = decide(&tv, &chair, &waiting, json!({ "decision": "accept" })).await;
    assert_eq!(tt_error_code(&doc), DECIDE_ERR_VOTING_CLOSED, "{doc}");

    // Voting not yet open: the election is cancelled, and its idea not selected.
    let mut body = board_body();
    let now = Utc::now();
    body["voting"] = json!({ "opensAt": stamp(now + Duration::minutes(50)), "closesAt": stamp(now + Duration::hours(3)) });
    let later = create_board(&tv, &chair, body).await;
    let idea = propose(&tv, &alice, &later, "Not voting yet").await;
    let e = accepted(&tv, &chair, &idea).await;
    let (_, doc) = call(
        &tv,
        &chair,
        &uri("update"),
        json!({ "boardId": later, "status": "archived" }),
    )
    .await;
    assert_eq!(payload(&doc)["closing"]["cancelled"], 1, "{doc}");
    assert_eq!(settled(&tv, &e).await, "cancelled");
    let (_, shown) = call(
        &tv,
        &chair,
        &uri("show"),
        json!({ "boardId": later, "includeArchived": true }),
    )
    .await;
    let ideas = payload(&shown)["ideas"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let i = ideas.iter().find(|i| i["ideaId"] == idea);
    if let Some(i) = i {
        assert_eq!(i["state"], "notSelected", "{shown}");
    }
}

/// VTI-BRD-006: a close the ballot box does not answer is recorded first and asked again by the
/// elections sweeper, its one retry owner, until it is.
#[tokio::test]
async fn vti_brd_006_an_unanswered_close_is_retried_by_the_sweeper() {
    let bx = InProcessBox::new();
    let tv = community(bx.clone()).await;
    let chair = admin(&tv).await;
    let alice = member(&tv).await;
    let board = create_board(&tv, &chair, board_body()).await;
    let idea = propose(&tv, &alice, &board, "Retried").await;
    let e = accepted(&tv, &chair, &idea).await;

    bx.silent.store(true, Ordering::SeqCst);
    let (status, doc) = call(
        &tv,
        &chair,
        &uri("update"),
        json!({ "boardId": board, "status": "closed" }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the close does not wait for the ballot box: {doc}"
    );
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let rec = vtc_service::elections::store::get(tv.state.elections.ks(), &e)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(rec.state(Utc::now()), "voting");
    let pending = rec
        .pending_end
        .expect("recorded before the ballot box was asked");
    assert!(pending.attempts >= 1, "{pending:?}");

    bx.silent.store(false, Ordering::SeqCst);
    // Past its backoff.
    vtc_service::elections::sweeper::pass(&tv.state, Utc::now() + Duration::hours(1))
        .await
        .unwrap();
    assert_eq!(election_state(&tv, &e).await, "closed");
    let rec = vtc_service::elections::store::get(tv.state.elections.ks(), &e)
        .await
        .unwrap()
        .unwrap();
    assert!(rec.pending_end.is_none());
}

/// VTI-BRD-030: a board's template must allow closing early.
#[tokio::test]
async fn vti_brd_030_a_template_that_cannot_close_early_is_refused() {
    let tv = community(InProcessBox::new()).await;
    let chair = admin(&tv).await;
    let mut body = board_body();
    body["template"]["allowEarlyClose"] = json!(false);
    let (_, doc) = call(&tv, &chair, &uri("create"), body).await;
    assert_eq!(tt_error_code(&doc), CREATE_ERR_TEMPLATE_INVALID, "{doc}");
}

/// VTI-BRD-007, VTI-BRD-008: deleting takes vtc.boards.manage unqualified and a bound step-up,
/// only once the board is closed and its voting over; it removes the board, ideas, notes and
/// each election's content, and keeps a tombstone for the retention.
#[tokio::test]
async fn vti_brd_007_deleting_a_closed_board_keeps_only_tombstones() {
    let bx = InProcessBox::new();
    let tv = community(bx.clone()).await;
    let chair = GatedAdmin::new(&tv).await;
    let alice = member(&tv).await;
    let board = create_board(&tv, &chair.requester, board_body()).await;
    let idea = propose(&tv, &alice, &board, "Delete me").await;
    let e = accepted(&tv, &chair.requester, &idea).await;
    call(
        &tv,
        &alice,
        &uri("notes/add"),
        json!({ "boardId": board, "ideaId": idea, "text": "A note." }),
    )
    .await;
    let del = |id: &str| json!({ "boardId": id, "reason": "The event is over." });

    let (_, doc) = chair.call(&tv, &uri("delete"), del(UNKNOWN_BOARD)).await;
    assert_eq!(tt_error_code(&doc), DELETE_ERR_NOT_FOUND, "{doc}");
    let (_, doc) = chair.call(&tv, &uri("delete"), del(&board)).await;
    assert_eq!(tt_error_code(&doc), DELETE_ERR_NOT_CLOSED, "{doc}");

    // Closed, but one election cannot close early and is still running.
    let ks = tv.state.elections.ks();
    let mut rec = vtc_service::elections::store::get(ks, &e)
        .await
        .unwrap()
        .unwrap();
    rec.manifest["allowEarlyClose"] = json!(false);
    vtc_service::elections::store::put(ks, &rec).await.unwrap();
    let (status, doc) = call(
        &tv,
        &chair.requester,
        &uri("update"),
        json!({ "boardId": board, "status": "closed" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    let (_, doc) = chair.call(&tv, &uri("delete"), del(&board)).await;
    assert_eq!(tt_error_code(&doc), DELETE_ERR_ELECTIONS_RUNNING, "{doc}");

    // Its election ends.
    vtc_service::elections::ops::cancel(&tv.state, &e, "ended for the test", Utc::now())
        .await
        .unwrap();

    // A facilitator of this one board closes it, but never deletes it.
    let qualified = facilitator_of(&tv, &board).await;
    let (_, doc) = call(&tv, &qualified, &uri("delete"), del(&board)).await;
    assert_eq!(tt_error_code(&doc), "permissionDenied", "{doc}");
    // Without a gesture bound to the deletion, nothing goes.
    let (_, doc) = call(&tv, &chair.requester, &uri("delete"), del(&board)).await;
    assert!(step_up_request(&doc).is_some(), "{doc}");

    let (status, doc) = chair.call(&tv, &uri("delete"), del(&board)).await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    let out = payload(&doc);
    assert_eq!(out["ideasRemoved"], 1, "{doc}");
    assert_eq!(out["notesRemoved"], 1, "{doc}");
    assert_eq!(out["electionsRemoved"], 1, "{doc}");
    assert_eq!(out["tombstones"]["kept"], 1, "{doc}");
    let remove_at: DateTime<Utc> = out["tombstones"]["removeAt"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    assert!(
        (remove_at - Utc::now() - Duration::days(365))
            .num_minutes()
            .abs()
            < 5
    );

    let (_, doc) = call(
        &tv,
        &chair.requester,
        &uri("show"),
        json!({ "boardId": board }),
    )
    .await;
    assert_eq!(tt_error_code(&doc), SHOW_ERR_NOT_FOUND, "{doc}");
    assert!(
        vtc_service::elections::store::get(ks, &e)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        vtc_service::elections::store::tickets(ks, &e)
            .await
            .unwrap()
            .is_empty()
    );
    let t = vtc_service::elections::store::tombstone(ks, &e)
        .await
        .unwrap()
        .expect("kept");
    assert_eq!(t.manifest_digest, rec.manifest_digest);
    let kept = serde_json::to_string(&t).unwrap();
    assert!(
        !kept.contains("Delete me"),
        "a tombstone carries no text: {kept}"
    );

    // Once its retention has passed, the sweeper removes it.
    vtc_service::elections::sweeper::pass(&tv.state, Utc::now() + Duration::days(366))
        .await
        .unwrap();
    assert!(
        vtc_service::elections::store::tombstone(ks, &e)
            .await
            .unwrap()
            .is_none()
    );
}

/// VTI-BRD-008: a retention of zero keeps no tombstone at all.
#[tokio::test]
async fn vti_brd_008_a_zero_retention_keeps_nothing() {
    let bx = InProcessBox::new();
    let tv = community(bx.clone()).await;
    tv.state.config.write().await.boards.tombstone_retention =
        vtc_service::boards::TombstoneRetention::Days(0);
    let chair = GatedAdmin::new(&tv).await;
    let alice = member(&tv).await;
    let board = create_board(&tv, &chair.requester, board_body()).await;
    let idea = propose(&tv, &alice, &board, "Gone entirely").await;
    let e = accepted(&tv, &chair.requester, &idea).await;
    call(
        &tv,
        &chair.requester,
        &uri("update"),
        json!({ "boardId": board, "status": "closed" }),
    )
    .await;
    assert_eq!(settled(&tv, &e).await, "closed");
    let (status, doc) = chair
        .call(
            &tv,
            &uri("delete"),
            json!({ "boardId": board, "reason": "Test board." }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    assert_eq!(payload(&doc)["tombstones"], json!({ "kept": 0 }), "{doc}");
    let ks = tv.state.elections.ks();
    assert!(
        vtc_service::elections::store::tombstone(ks, &e)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        vtc_service::elections::store::get(ks, &e)
            .await
            .unwrap()
            .is_none()
    );
}
