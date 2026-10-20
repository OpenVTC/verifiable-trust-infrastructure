//! Community elections over the signed-document door (`vtc/elections/*`, VTI-VOT-001 – 100).
//!
//! The ballot box is the real one — `vti_voting::service::BallotBox` — behind the channel the
//! community reaches ballot boxes through, so a registration the community sends is checked by
//! the same rules a deployed voting service applies, and a board it certifies is a real board.
//! The voter is the real one too: the ticket the community issues blind is unblinded and cast
//! with `vti_voting::voter::Voter`, which is what a member's VTA runs.
//!
//! The in-process ballot box can be made unreachable, made to refuse, run on a later clock, and
//! made to serve a tampered board or result — each the failure a certification must catch.

#![cfg(feature = "voting")]

use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::{Arc, Mutex};

use axum::http::StatusCode;
use chrono::{DateTime, Duration, Utc};
use serde_json::{Value, json};
use vtc_service::acl::VtcRole;
use vtc_service::elections::link::{BallotBoxChannel, BoxAnswer, LinkError};
use vtc_service::elections::{TrustedBallotBox, VotingConfig};
use vtc_service::test_support::{TEST_VTC_DID, TestVtc};
use vti_rooms_dtg::test_support::Party;
use vti_voting::{
    board::Board,
    election::{Election, ElectionId},
    rules::{digest_from_multibase, digest_multibase},
    scheme::VotingParams,
    service::{BallotBox, Caller},
    voter::{Ticket, Voter},
};

use crate::common::signed::{admin, call, party_with_role, payload, post, signed_to};

// The declared codes, read from the generated bindings.
use trust_tasks_rs::specs::vtc::elections as el;
const CREATE_ERR_ELECTION_EXISTS: &str = el::create::v0_1::error_codes::ELECTION_EXISTS.code;
const CREATE_ERR_INVALID_MANIFEST: &str = el::create::v0_1::error_codes::INVALID_MANIFEST.code;
const CREATE_ERR_UNSUPPORTED_SECRECY: &str =
    el::create::v0_1::error_codes::UNSUPPORTED_SECRECY.code;
const CREATE_ERR_COMMUNITY_MISMATCH: &str = el::create::v0_1::error_codes::COMMUNITY_MISMATCH.code;
const CREATE_ERR_BALLOT_BOX_NOT_TRUSTED: &str =
    el::create::v0_1::error_codes::BALLOT_BOX_NOT_TRUSTED.code;
const CREATE_ERR_BALLOT_BOX_REFUSED: &str = el::create::v0_1::error_codes::BALLOT_BOX_REFUSED.code;
const CLOSE_ERR_ELECTION_UNKNOWN: &str = el::close::v0_1::error_codes::ELECTION_UNKNOWN.code;
const CLOSE_ERR_NOT_OPEN: &str = el::close::v0_1::error_codes::NOT_OPEN.code;
const CLOSE_ERR_EARLY_CLOSE_NOT_ALLOWED: &str =
    el::close::v0_1::error_codes::EARLY_CLOSE_NOT_ALLOWED.code;
const CLOSE_ERR_BALLOT_BOX_UNAVAILABLE: &str =
    el::close::v0_1::error_codes::BALLOT_BOX_UNAVAILABLE.code;
const CLOSE_ERR_BALLOT_BOX_REFUSED: &str = el::close::v0_1::error_codes::BALLOT_BOX_REFUSED.code;
const CANCEL_ERR_ELECTION_UNKNOWN: &str = el::cancel::v0_1::error_codes::ELECTION_UNKNOWN.code;
const CANCEL_ERR_NOT_OPEN: &str = el::cancel::v0_1::error_codes::NOT_OPEN.code;
const CANCEL_ERR_BALLOT_BOX_UNAVAILABLE: &str =
    el::cancel::v0_1::error_codes::BALLOT_BOX_UNAVAILABLE.code;
const CANCEL_ERR_BALLOT_BOX_REFUSED: &str = el::cancel::v0_1::error_codes::BALLOT_BOX_REFUSED.code;
const SHOW_ERR_ELECTION_UNKNOWN: &str = el::show::v0_1::error_codes::ELECTION_UNKNOWN.code;
const ISSUE_ERR_ELECTION_UNKNOWN: &str =
    el::tickets::issue::v0_1::error_codes::ELECTION_UNKNOWN.code;
const ISSUE_ERR_NOT_OPEN: &str = el::tickets::issue::v0_1::error_codes::NOT_OPEN.code;
const ISSUE_ERR_MANIFEST_MISMATCH: &str =
    el::tickets::issue::v0_1::error_codes::MANIFEST_MISMATCH.code;
const ISSUE_ERR_NOT_ELIGIBLE: &str = el::tickets::issue::v0_1::error_codes::NOT_ELIGIBLE.code;
const ISSUE_ERR_ALREADY_ISSUED: &str = el::tickets::issue::v0_1::error_codes::ALREADY_ISSUED.code;
const ISSUE_ERR_REQUEST_INVALID: &str = el::tickets::issue::v0_1::error_codes::REQUEST_INVALID.code;
const CERTIFY_ERR_ALREADY_CERTIFIED: &str = el::certify::v0_1::error_codes::ALREADY_CERTIFIED.code;
const CERTIFY_ERR_AUDIT_ATTESTATION_INVALID: &str =
    el::certify::v0_1::error_codes::AUDIT_ATTESTATION_INVALID.code;
const CERTIFY_ERR_BALLOT_BOX_UNAVAILABLE: &str =
    el::certify::v0_1::error_codes::BALLOT_BOX_UNAVAILABLE.code;
const CERTIFY_ERR_BOARD_INCONSISTENT: &str =
    el::certify::v0_1::error_codes::BOARD_INCONSISTENT.code;
const CERTIFY_ERR_CAST_INVALID: &str = el::certify::v0_1::error_codes::CAST_INVALID.code;
const CERTIFY_ERR_COUNT_EXCEEDS_TICKETS: &str =
    el::certify::v0_1::error_codes::COUNT_EXCEEDS_TICKETS.code;
const CERTIFY_ERR_ELECTION_UNKNOWN: &str = el::certify::v0_1::error_codes::ELECTION_UNKNOWN.code;
const CERTIFY_ERR_NOT_TALLIED: &str = el::certify::v0_1::error_codes::NOT_TALLIED.code;
const CERTIFY_ERR_RESULT_MISMATCH: &str = el::certify::v0_1::error_codes::RESULT_MISMATCH.code;

const BOX: &str = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";
const AUDITOR: &str = "did:key:z6MkjchhfUsD6mmvni8mCdXHw216Xrm9bQe2mBH1P5RDjVJG";
const SPEC: &str = "https://trusttasks.org/spec/";

fn uri(task: &str) -> String {
    format!("{SPEC}vtc/elections/{task}/0.1")
}

/// The code a refusal carries, from the framework's error document.
fn tt_error_code(doc: &Value) -> &str {
    doc.pointer("/payload/code")
        .and_then(Value::as_str)
        .unwrap_or_default()
}

/// What the in-process ballot box serves wrongly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tamper {
    None,
    /// A cast entry rewritten, the head left as it was.
    RewriteEntry,
    /// A cast's ballot changed and the head recomputed over it: the board hashes, the cast does
    /// not verify.
    ForgeCast,
    /// The published totals changed.
    Result,
}

/// The real ballot box, in process.
struct InProcessBox {
    bb: Mutex<BallotBox>,
    up: AtomicBool,
    refuse: AtomicBool,
    /// Seconds the box's clock runs ahead of the test's.
    ahead: AtomicI64,
    tamper: Mutex<Tamper>,
}

impl InProcessBox {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            bb: Mutex::new(BallotBox::new(BOX)),
            up: AtomicBool::new(true),
            refuse: AtomicBool::new(false),
            ahead: AtomicI64::new(0),
            tamper: Mutex::new(Tamper::None),
        })
    }

    fn now(&self) -> DateTime<Utc> {
        Utc::now() + Duration::seconds(self.ahead.load(Ordering::SeqCst))
    }

    fn set_tamper(&self, t: Tamper) {
        *self.tamper.lock().unwrap() = t;
    }

    /// A voter's cast, straight to the ballot box as a member's agent sends it.
    fn cast(&self, cast: Value, election: &str) {
        let now = self.now();
        self.bb
            .lock()
            .unwrap()
            .cast(
                &json!({ "community": TEST_VTC_DID, "electionId": election, "cast": cast }),
                now,
            )
            .expect("the ballot box admits the cast");
    }

    /// Every entry, tampered as set, and the root over them.
    fn entries(&self, bb: &mut BallotBox, sel: &Value, now: DateTime<Utc>) -> Vec<Value> {
        let mut read = sel.clone();
        read["from"] = json!(0);
        read["limit"] = json!(1000);
        let all = bb
            .board_read(Caller::Did(TEST_VTC_DID), &read, now)
            .unwrap();
        let mut entries: Vec<Value> = all["entries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["entry"].clone())
            .collect();
        if matches!(
            *self.tamper.lock().unwrap(),
            Tamper::RewriteEntry | Tamper::ForgeCast
        ) && let Some(cast) = entries.iter_mut().find(|e| e["kind"] == "cast")
        {
            let choice = &mut cast["cast"]["ballot"]["answers"][0]["choice"][0];
            *choice = json!(if choice == "alice" { "bob" } else { "alice" });
        }
        entries
    }
}

fn root_of(entries: &[Value]) -> String {
    let mut board = Board::new();
    for e in entries {
        board.append(&serde_json_canonicalizer::to_vec(e).unwrap());
    }
    digest_multibase(&board.root(board.len()).unwrap())
}

#[async_trait::async_trait]
impl BallotBoxChannel for InProcessBox {
    async fn exchange(
        &self,
        ballot_box: &str,
        type_uri: &str,
        payload: &Value,
    ) -> Result<BoxAnswer, LinkError> {
        assert_eq!(
            ballot_box, BOX,
            "the community sends to the manifest's ballot box"
        );
        if !self.up.load(Ordering::SeqCst) {
            return Err(LinkError::Unavailable("down".into()));
        }
        let slug = type_uri
            .strip_prefix(SPEC)
            .and_then(|t| t.strip_suffix("/0.1"))
            .expect("a voting task");
        if self.refuse.load(Ordering::SeqCst) {
            return Ok(BoxAnswer::Refused {
                code: format!("{slug}:refused"),
                message: "refused for the test".into(),
            });
        }
        // The community signs as itself; the ballot box authorizes on that alone.
        let signer = payload["community"].as_str().unwrap_or_default();
        let now = self.now();
        let tamper = *self.tamper.lock().unwrap();
        let mut bb = self.bb.lock().unwrap();
        let out = match slug {
            "voting/election/register" => bb.register(signer, payload, now),
            "voting/election/close" => bb.close(signer, payload, now),
            "voting/election/cancel" => bb.cancel(signer, payload, now),
            "voting/board/head" => bb
                .board_head(Caller::Did(signer), payload, now)
                .map(|mut h| {
                    if tamper == Tamper::ForgeCast {
                        h["head"]["rootHash"] =
                            json!(root_of(&self.entries(&mut bb, payload, now)));
                    }
                    h
                }),
            "voting/board/read" => bb
                .board_read(Caller::Did(signer), payload, now)
                .map(|mut r| {
                    let entries = self.entries(&mut bb, payload, now);
                    for page_entry in r["entries"].as_array_mut().unwrap() {
                        let i = page_entry["index"].as_u64().unwrap() as usize;
                        page_entry["entry"] = entries[i].clone();
                    }
                    r
                }),
            "voting/result/show" => bb.result(Caller::Did(signer), payload, now).map(|mut r| {
                if tamper == Tamper::Result {
                    r["result"]["questions"][0]["choice"]["alice"] = json!(99);
                }
                r
            }),
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

fn stamp(t: DateTime<Utc>) -> String {
    t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// A manifest whose ticket issuance is open now and voting open for an hour.
fn manifest(id: &str, binding: bool) -> Value {
    let now = Utc::now();
    json!({
        "electionId": id,
        "community": TEST_VTC_DID,
        "title": "Annual meeting",
        "questions": [{
            "key": "chair", "type": "choice", "text": "Who should chair?",
            "options": [{ "key": "alice" }, { "key": "bob" }],
            "minSelections": 1, "maxSelections": 1, "optional": true
        }],
        "secrecy": "open",
        "roll": { "rule": "members" },
        "registrationOpens": stamp(now - Duration::hours(1)),
        "votingOpens": stamp(now - Duration::minutes(1)),
        "votingCloses": stamp(now + Duration::hours(1)),
        "revote": "replace",
        "board": { "visibility": "public", "auditors": [AUDITOR] },
        "ballotBox": BOX,
        "binding": binding,
        "allowEarlyClose": true,
        "resultsBeforeClose": false,
        "textReleaseThreshold": 10
    })
}

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

async fn create(tv: &TestVtc, chair: &Party, m: Value) -> (StatusCode, Value) {
    call(tv, chair, &uri("create"), json!({ "manifest": m })).await
}

/// A voter's agent: its parameters and the election, read from `show` as a member reads them.
struct Ballot {
    params: VotingParams,
    election: Election,
    digest: String,
}

async fn read_election(tv: &TestVtc, reader: &Party, id: &str) -> Ballot {
    let (status, shown) = call(tv, reader, &uri("show"), json!({ "electionId": id })).await;
    assert_eq!(status, StatusCode::OK, "{shown}");
    let shown = payload(&shown);
    let hvk =
        vti_vetting_pcs::scheme::dec(shown["parameters"]["votingKey"].as_str().unwrap()).unwrap();
    let digest = shown["manifestDigest"].as_str().unwrap().to_string();
    Ballot {
        params: VotingParams::new(TEST_VTC_DID, hvk).unwrap(),
        election: Election::new(
            TEST_VTC_DID,
            ElectionId::new(id).unwrap(),
            digest_from_multibase(&digest).unwrap(),
        )
        .unwrap(),
        digest,
    }
}

/// A ticket request, as a member's VTA builds it.
fn ask(b: &Ballot, voter: &Voter, label: &str) -> (Value, vti_voting::voter::TicketState) {
    let (request, blinding) = voter
        .ticket_request(&b.params, &b.election, &mut vti_voting::rand::rngs::OsRng)
        .unwrap();
    (
        json!({
            "electionId": b.election.id().as_str(),
            "manifestDigest": b.digest,
            "request": {
                "label": label,
                "id": vti_voting::scheme::point_text(voter.id()).unwrap(),
                "request": serde_json::to_value(&request).unwrap(),
            }
        }),
        blinding,
    )
}

/// `party` takes its ticket through the community.
async fn take_ticket(tv: &TestVtc, party: &Party, b: &Ballot) -> (Voter, Ticket) {
    let voter = Voter::generate(&b.params, &mut vti_voting::rand::rngs::OsRng).unwrap();
    let label = format!("voter/{}", b.election.id().as_str());
    let (body, blinding) = ask(b, &voter, &label);
    let (status, issued) = call(tv, party, &uri("tickets/issue"), body).await;
    assert_eq!(status, StatusCode::OK, "{issued}");
    let pre =
        vti_vetting_pcs::scheme::dec(payload(&issued)["preCredential"].as_str().unwrap()).unwrap();
    let ticket = voter
        .accept_ticket(&b.params, &b.election, &pre, &blinding)
        .expect("the pre-credential unblinds into a ticket");
    (voter, ticket)
}

fn cast_for(b: &Ballot, voter: &Voter, ticket: &Ticket, choice: &str) -> Value {
    voter
        .cast_wire(
            &b.params,
            ticket,
            &json!({
                "electionId": b.election.id().as_str(),
                "manifestDigest": b.digest,
                "answers": [{ "question": "chair", "choice": [choice] }],
            }),
            &mut vti_voting::rand::rngs::OsRng,
        )
        .unwrap()
}

#[tokio::test]
async fn an_election_is_created_registered_shown_and_a_member_takes_a_ticket_blind() {
    let bx = InProcessBox::new();
    let tv = community(bx.clone()).await;
    let chair = admin(&tv).await;

    // Create: checked, recorded and registered with the ballot box (VTI-VOT-005).
    let (status, doc) = create(&tv, &chair, manifest("agm", false)).await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    assert_eq!(payload(&doc)["state"], "registered");

    // The identifier is the community's to use once.
    let (_, doc) = create(&tv, &chair, manifest("agm", false)).await;
    assert_eq!(tt_error_code(&doc), CREATE_ERR_ELECTION_EXISTS, "{doc}");

    // A member sees it, with the parameters and disclosure it must read before a ticket, and
    // not the count of tickets issued (show items 3 – 4).
    let alice = member(&tv).await;
    let (status, list) = call(&tv, &alice, &uri("list"), json!({})).await;
    assert_eq!(status, StatusCode::OK, "{list}");
    assert_eq!(payload(&list)["elections"][0]["electionId"], "agm");
    assert_eq!(payload(&list)["elections"][0]["ticketHeld"], false);
    let (_, shown) = call(&tv, &alice, &uri("show"), json!({ "electionId": "agm" })).await;
    let shown = payload(&shown).clone();
    assert_eq!(shown["disclosure"]["sameOperator"], false);
    assert_eq!(
        shown["disclosure"]["ballotBoxOperator"],
        "Independent Ballots Ltd"
    );
    assert_eq!(shown["disclosure"]["coercionResistance"], false);
    assert!(
        shown.get("ticketsIssued").is_none(),
        "a member is not told the count"
    );

    // The ticket, as a member's VTA asks for it, unblinds under the published key.
    let b = read_election(&tv, &alice, "agm").await;
    let voter = Voter::generate(&b.params, &mut vti_voting::rand::rngs::OsRng).unwrap();
    let (body, blinding) = ask(&b, &voter, "voter/agm");
    let issue_doc = signed_to(&alice, TEST_VTC_DID, &uri("tickets/issue"), body.clone()).await;
    let (status, issued) = post(&tv, &issue_doc).await;
    assert_eq!(status, StatusCode::OK, "{issued}");
    let pre = payload(&issued)["preCredential"]
        .as_str()
        .unwrap()
        .to_string();
    voter
        .accept_ticket(
            &b.params,
            &b.election,
            &vti_vetting_pcs::scheme::dec(&pre).unwrap(),
            &blinding,
        )
        .expect("the pre-credential unblinds into a ticket");

    // A resend of the same document is answered with its first answer, signing nothing again.
    let (_, again) = post(&tv, &issue_doc).await;
    assert_eq!(payload(&again)["preCredential"], pre.as_str());
    // A new request is refused: one ticket per party per election (VTI-VOT-022).
    let (_, second) = call(&tv, &alice, &uri("tickets/issue"), body.clone()).await;
    assert_eq!(tt_error_code(&second), ISSUE_ERR_ALREADY_ISSUED, "{second}");

    let (_, list) = call(&tv, &alice, &uri("list"), json!({})).await;
    assert_eq!(payload(&list)["elections"][0]["ticketHeld"], true);
    let (_, shown) = call(&tv, &chair, &uri("show"), json!({ "electionId": "agm" })).await;
    assert_eq!(
        payload(&shown)["ticketsIssued"],
        1,
        "a manager is told the count"
    );

    // A stranger learns nothing: not the election, not that it exists.
    let stranger = Party::new();
    let (_, unseen) = call(&tv, &stranger, &uri("show"), json!({ "electionId": "agm" })).await;
    assert_eq!(
        tt_error_code(&unseen),
        SHOW_ERR_ELECTION_UNKNOWN,
        "{unseen}"
    );
    let (_, unseen) = call(&tv, &stranger, &uri("tickets/issue"), body.clone()).await;
    assert_eq!(
        tt_error_code(&unseen),
        ISSUE_ERR_ELECTION_UNKNOWN,
        "{unseen}"
    );

    // A member cannot close it (VTI-VOT-080).
    let (_, denied) = call(&tv, &alice, &uri("close"), json!({ "electionId": "agm" })).await;
    assert_eq!(tt_error_code(&denied), "permissionDenied", "{denied}");

    // Close early: the ballot box closes it, then the community records it and keeps the head.
    let (status, closed) = call(
        &tv,
        &chair,
        &uri("close"),
        json!({ "electionId": "agm", "reason": "quorum" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{closed}");
    let (_, shown) = call(&tv, &chair, &uri("show"), json!({ "electionId": "agm" })).await;
    assert_eq!(payload(&shown)["state"], "closed");
    assert_eq!(payload(&shown)["checkpoints"].as_array().unwrap().len(), 1);
    // And no ticket after it.
    let bob = member(&tv).await;
    let (body, _) = ask(&b, &voter, "voter/agm");
    let (_, late) = call(&tv, &bob, &uri("tickets/issue"), body).await;
    assert_eq!(tt_error_code(&late), ISSUE_ERR_NOT_OPEN, "{late}");
}

/// SPEC §4.4.1: a request's `#request` fragment is optional, so a document typed with it routes
/// exactly as the bare form does.
#[tokio::test]
async fn a_request_typed_with_its_fragment_is_served() {
    let tv = community(InProcessBox::new()).await;
    let chair = admin(&tv).await;
    create(&tv, &chair, manifest("agm", false)).await;
    let doc = signed_to(
        &chair,
        TEST_VTC_DID,
        &format!("{}#request", uri("show")),
        json!({ "electionId": "agm" }),
    )
    .await;
    let (status, shown) = post(&tv, &doc).await;
    assert_eq!(status, StatusCode::OK, "{shown}");
    assert_eq!(payload(&shown)["manifest"]["electionId"], "agm");
}

#[tokio::test]
async fn a_creation_is_refused_for_each_rule_it_breaks() {
    let bx = InProcessBox::new();
    let tv = community(bx.clone()).await;
    let chair = admin(&tv).await;

    let mut sealed = manifest("sealed", false);
    sealed["secrecy"] = json!("sealed");
    sealed["trustees"] =
        json!({ "dids": ["did:key:z6MkTrusteeA", "did:key:z6MkTrusteeB"], "threshold": 2 });
    let (_, doc) = create(&tv, &chair, sealed).await;
    assert_eq!(tt_error_code(&doc), CREATE_ERR_UNSUPPORTED_SECRECY, "{doc}");

    let mut other = manifest("other", false);
    other["community"] = json!("did:key:z6MkAnotherCommunity");
    let (_, doc) = create(&tv, &chair, other).await;
    assert_eq!(tt_error_code(&doc), CREATE_ERR_COMMUNITY_MISMATCH, "{doc}");

    let mut untrusted = manifest("untrusted", false);
    untrusted["ballotBox"] = json!("did:key:z6MkUntrustedBox");
    let (_, doc) = create(&tv, &chair, untrusted).await;
    assert_eq!(
        tt_error_code(&doc),
        CREATE_ERR_BALLOT_BOX_NOT_TRUSTED,
        "{doc}"
    );

    let mut past = manifest("past", false);
    past["votingCloses"] = json!(stamp(Utc::now() - Duration::seconds(1)));
    past["votingOpens"] = json!(stamp(Utc::now() - Duration::seconds(2)));
    let (_, doc) = create(&tv, &chair, past).await;
    assert_eq!(tt_error_code(&doc), CREATE_ERR_INVALID_MANIFEST, "{doc}");
    assert!(payload(&doc)["details"]["reason"].is_string(), "{doc}");

    // The ballot box refuses: its code and message are carried, and nothing is kept.
    bx.refuse.store(true, Ordering::SeqCst);
    let (_, doc) = create(&tv, &chair, manifest("refused", false)).await;
    assert_eq!(tt_error_code(&doc), CREATE_ERR_BALLOT_BOX_REFUSED, "{doc}");
    assert_eq!(
        payload(&doc)["details"]["code"],
        "voting/election/register:refused"
    );

    assert!(
        vtc_service::elections::store::all(tv.state.elections.ks())
            .await
            .unwrap()
            .is_empty(),
        "nothing was recorded for any of them"
    );
}

#[tokio::test]
async fn a_ticket_is_refused_for_each_rule_it_breaks() {
    let tv = community(InProcessBox::new()).await;
    let chair = admin(&tv).await;
    let alice = member(&tv).await;
    // A roll of one listed party, so the chair — who sees every election — is not on it.
    let mut m = manifest("listed", false);
    m["roll"] = json!({ "rule": "listed", "listed": [alice.did] });
    let (status, doc) = create(&tv, &chair, m).await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    let b = read_election(&tv, &alice, "listed").await;
    let voter = Voter::generate(&b.params, &mut vti_voting::rand::rngs::OsRng).unwrap();

    let (mut body, _) = ask(&b, &voter, "voter/listed");
    body["manifestDigest"] = json!(digest_multibase(&[9u8; 32]));
    let (_, doc) = call(&tv, &alice, &uri("tickets/issue"), body).await;
    assert_eq!(tt_error_code(&doc), ISSUE_ERR_MANIFEST_MISMATCH, "{doc}");

    let (body, _) = ask(&b, &voter, "voter/another");
    let (_, doc) = call(&tv, &alice, &uri("tickets/issue"), body).await;
    assert_eq!(tt_error_code(&doc), ISSUE_ERR_REQUEST_INVALID, "{doc}");

    // A manager sees the election, so learns that the roll does not admit them.
    let (body, _) = ask(&b, &voter, "voter/listed");
    let (_, doc) = call(&tv, &chair, &uri("tickets/issue"), body).await;
    assert_eq!(tt_error_code(&doc), ISSUE_ERR_NOT_ELIGIBLE, "{doc}");
}

#[tokio::test]
async fn close_and_cancel_are_refused_for_each_rule_they_break() {
    let bx = InProcessBox::new();
    let tv = community(bx.clone()).await;
    let chair = admin(&tv).await;
    let close = |id: &str| json!({ "electionId": id, "reason": "test" });

    let (_, doc) = call(&tv, &chair, &uri("close"), close("nope")).await;
    assert_eq!(tt_error_code(&doc), CLOSE_ERR_ELECTION_UNKNOWN, "{doc}");
    let (_, doc) = call(&tv, &chair, &uri("cancel"), close("nope")).await;
    assert_eq!(tt_error_code(&doc), CANCEL_ERR_ELECTION_UNKNOWN, "{doc}");

    let mut fixed = manifest("fixed", false);
    fixed["allowEarlyClose"] = json!(false);
    create(&tv, &chair, fixed).await;
    let (_, doc) = call(&tv, &chair, &uri("close"), close("fixed")).await;
    assert_eq!(
        tt_error_code(&doc),
        CLOSE_ERR_EARLY_CLOSE_NOT_ALLOWED,
        "{doc}"
    );

    // Not yet voting.
    let mut later = manifest("later", false);
    later["votingOpens"] = json!(stamp(Utc::now() + Duration::minutes(30)));
    create(&tv, &chair, later).await;
    let (_, doc) = call(&tv, &chair, &uri("close"), close("later")).await;
    assert_eq!(tt_error_code(&doc), CLOSE_ERR_NOT_OPEN, "{doc}");

    create(&tv, &chair, manifest("agm", false)).await;
    bx.up.store(false, Ordering::SeqCst);
    let (_, doc) = call(&tv, &chair, &uri("close"), close("agm")).await;
    assert_eq!(
        tt_error_code(&doc),
        CLOSE_ERR_BALLOT_BOX_UNAVAILABLE,
        "{doc}"
    );
    let (_, doc) = call(&tv, &chair, &uri("cancel"), close("agm")).await;
    assert_eq!(
        tt_error_code(&doc),
        CANCEL_ERR_BALLOT_BOX_UNAVAILABLE,
        "{doc}"
    );
    bx.up.store(true, Ordering::SeqCst);
    bx.refuse.store(true, Ordering::SeqCst);
    let (_, doc) = call(&tv, &chair, &uri("close"), close("agm")).await;
    assert_eq!(tt_error_code(&doc), CLOSE_ERR_BALLOT_BOX_REFUSED, "{doc}");
    let (_, doc) = call(&tv, &chair, &uri("cancel"), close("agm")).await;
    assert_eq!(tt_error_code(&doc), CANCEL_ERR_BALLOT_BOX_REFUSED, "{doc}");
    bx.refuse.store(false, Ordering::SeqCst);

    // Cancelled once; a second is refused.
    let (status, doc) = call(&tv, &chair, &uri("cancel"), close("agm")).await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    let (_, doc) = call(&tv, &chair, &uri("cancel"), close("agm")).await;
    assert_eq!(tt_error_code(&doc), CANCEL_ERR_NOT_OPEN, "{doc}");
}

#[tokio::test]
async fn a_binding_election_is_not_created_on_the_requesters_word_alone() {
    let tv = community(InProcessBox::new()).await;
    let chair = admin(&tv).await;
    let (_, doc) = create(&tv, &chair, manifest("board", true)).await;
    // The requester's bound gesture comes first, and then another holder's consent
    // (VTI-VOT-081): either way, nothing is recorded or registered yet.
    assert_ne!(doc["type"], format!("{}#response", uri("create")), "{doc}");
    assert!(
        vtc_service::elections::store::get(tv.state.elections.ks(), "board")
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn an_unanswered_registration_is_delivered_again_until_the_ballot_box_answers() {
    let bx = InProcessBox::new();
    bx.up.store(false, Ordering::SeqCst);
    let tv = community(bx.clone()).await;
    let chair = admin(&tv).await;
    let (status, doc) = create(&tv, &chair, manifest("later", false)).await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    assert_eq!(payload(&doc)["state"], "pendingRegistration");

    // No ticket before registration (VTI-VOT-024), and a member does not see it yet.
    let alice = member(&tv).await;
    let (_, list) = call(&tv, &alice, &uri("list"), json!({})).await;
    assert_eq!(payload(&list)["elections"].as_array().unwrap().len(), 0);

    // The sweeper is the one retry owner; once the ballot box answers, it is registered.
    bx.up.store(true, Ordering::SeqCst);
    vtc_service::elections::sweeper::pass(&tv.state, Utc::now() + Duration::hours(2))
        .await
        .unwrap();
    let (_, shown) = call(&tv, &chair, &uri("show"), json!({ "electionId": "later" })).await;
    assert_eq!(payload(&shown)["state"], "voting", "{shown}");
}

#[tokio::test]
async fn a_result_is_certified_only_from_a_board_that_holds_together() {
    let bx = InProcessBox::new();
    let tv = community(bx.clone()).await;
    let chair = admin(&tv).await;
    let certify =
        |attestations: Value| json!({ "electionId": "agm", "auditAttestations": attestations });

    let (_, doc) = call(&tv, &chair, &uri("certify"), certify(json!([]))).await;
    assert_eq!(tt_error_code(&doc), CERTIFY_ERR_ELECTION_UNKNOWN, "{doc}");

    create(&tv, &chair, manifest("agm", false)).await;
    let (alice, bob) = (member(&tv).await, member(&tv).await);
    let b = read_election(&tv, &alice, "agm").await;
    for (party, choice) in [(&alice, "alice"), (&bob, "bob")] {
        let (voter, ticket) = take_ticket(&tv, party, &b).await;
        bx.cast(cast_for(&b, &voter, &ticket, choice), "agm");
    }

    // Voting is still open: there is no result to certify.
    let (_, doc) = call(&tv, &chair, &uri("certify"), certify(json!([]))).await;
    assert_eq!(tt_error_code(&doc), CERTIFY_ERR_NOT_TALLIED, "{doc}");

    // Past the close, the ballot box tallies.
    bx.ahead.store(2 * 3600, Ordering::SeqCst);

    bx.up.store(false, Ordering::SeqCst);
    let (_, doc) = call(&tv, &chair, &uri("certify"), certify(json!([]))).await;
    assert_eq!(
        tt_error_code(&doc),
        CERTIFY_ERR_BALLOT_BOX_UNAVAILABLE,
        "{doc}"
    );
    bx.up.store(true, Ordering::SeqCst);

    // Every tampering is caught, and nothing is recorded for any of them.
    bx.set_tamper(Tamper::RewriteEntry);
    let (_, doc) = call(&tv, &chair, &uri("certify"), certify(json!([]))).await;
    assert_eq!(tt_error_code(&doc), CERTIFY_ERR_BOARD_INCONSISTENT, "{doc}");
    assert_eq!(payload(&doc)["details"]["fault"], "rootMismatch");
    bx.set_tamper(Tamper::ForgeCast);
    let (_, doc) = call(&tv, &chair, &uri("certify"), certify(json!([]))).await;
    assert_eq!(tt_error_code(&doc), CERTIFY_ERR_CAST_INVALID, "{doc}");
    bx.set_tamper(Tamper::Result);
    let (_, doc) = call(&tv, &chair, &uri("certify"), certify(json!([]))).await;
    assert_eq!(tt_error_code(&doc), CERTIFY_ERR_RESULT_MISMATCH, "{doc}");
    bx.set_tamper(Tamper::None);

    // An attestation from a party the manifest does not name as an auditor.
    let stranger = json!({
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "type": ["VerifiableCredential"],
        "issuer": "did:key:z6MkNotAnAuditor",
        "credentialSubject": { "electionId": "agm", "community": TEST_VTC_DID },
    });
    let (_, doc) = call(&tv, &chair, &uri("certify"), certify(json!([stranger]))).await;
    assert_eq!(
        tt_error_code(&doc),
        CERTIFY_ERR_AUDIT_ATTESTATION_INVALID,
        "{doc}"
    );
    assert_eq!(payload(&doc)["details"]["index"], 0);

    // The community's own verification, from its own key: certified, once.
    let (status, doc) = call(&tv, &chair, &uri("certify"), certify(json!([]))).await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    assert_eq!(payload(&doc)["result"]["ballotsCounted"], 2);
    assert_eq!(
        payload(&doc)["result"]["questions"][0]["choice"],
        json!({ "alice": 1, "bob": 1 })
    );
    let (_, shown) = call(&tv, &alice, &uri("show"), json!({ "electionId": "agm" })).await;
    assert_eq!(payload(&shown)["state"], "tallied");
    assert!(payload(&shown)["certified"].is_object(), "{shown}");
    let (_, doc) = call(&tv, &chair, &uri("certify"), certify(json!([]))).await;
    assert_eq!(tt_error_code(&doc), CERTIFY_ERR_ALREADY_CERTIFIED, "{doc}");
}

#[tokio::test]
async fn a_board_with_more_ballots_than_tickets_is_not_certified() {
    let bx = InProcessBox::new();
    let tv = community(bx.clone()).await;
    let chair = admin(&tv).await;
    create(&tv, &chair, manifest("agm", false)).await;
    let alice = member(&tv).await;
    let b = read_election(&tv, &alice, "agm").await;
    let (voter, ticket) = take_ticket(&tv, &alice, &b).await;
    bx.cast(cast_for(&b, &voter, &ticket, "alice"), "agm");

    // A ticket signed under the community's key that the community has no record of issuing:
    // what a leaked key, or a registrar bypassing its own records, would produce (VTI-VOT-072).
    let reg = vtc_service::elections::ops::registrar(&tv.state)
        .await
        .unwrap();
    let ghost = Voter::generate(&b.params, &mut vti_voting::rand::rngs::OsRng).unwrap();
    let (req, st) = ghost
        .ticket_request(&b.params, &b.election, &mut vti_voting::rand::rngs::OsRng)
        .unwrap();
    let pre = reg
        .issue_ticket(
            &b.election,
            ghost.id(),
            &req,
            &mut vti_voting::rand::rngs::OsRng,
        )
        .unwrap();
    let ghost_ticket = ghost
        .accept_ticket(&b.params, &b.election, &pre, &st)
        .unwrap();
    bx.cast(cast_for(&b, &ghost, &ghost_ticket, "bob"), "agm");

    bx.ahead.store(2 * 3600, Ordering::SeqCst);
    let (_, doc) = call(
        &tv,
        &chair,
        &uri("certify"),
        json!({ "electionId": "agm", "auditAttestations": [] }),
    )
    .await;
    assert_eq!(
        tt_error_code(&doc),
        CERTIFY_ERR_COUNT_EXCEEDS_TICKETS,
        "{doc}"
    );
    assert_eq!(
        payload(&doc)["details"],
        json!({ "ballotsCounted": 2, "ticketsIssued": 1 })
    );
}
