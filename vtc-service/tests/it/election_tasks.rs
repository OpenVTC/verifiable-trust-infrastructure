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
    /// The trustees' dealings served without their proofs — as a dealing the ballot box made in
    /// a trustee's name would have to be, since it cannot sign as one.
    UnsignedStep,
}

/// The real ballot box, in process.
struct InProcessBox {
    bb: Mutex<BallotBox>,
    up: AtomicBool,
    refuse: AtomicBool,
    /// Seconds the box's clock runs ahead of the test's.
    ahead: AtomicI64,
    tamper: Mutex<Tamper>,
    /// The community's signing key, where a test runs its community as a resolvable DID: a
    /// decryption authorization is kept on the board as the community signed it (CONVENTIONS
    /// §9.7), which the in-process channel otherwise never sees.
    signer: Mutex<Option<Arc<vtc_service::credentials::LocalSigner>>>,
}

impl InProcessBox {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            bb: Mutex::new(BallotBox::new(BOX)),
            up: AtomicBool::new(true),
            refuse: AtomicBool::new(false),
            ahead: AtomicI64::new(0),
            tamper: Mutex::new(Tamper::None),
            signer: Mutex::new(None),
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
            .board_read(
                Caller::Did(sel["community"].as_str().unwrap_or_default()),
                &read,
                now,
            )
            .unwrap();
        let mut entries: Vec<Value> = all["entries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["entry"].clone())
            .collect();
        let tamper = *self.tamper.lock().unwrap();
        if matches!(tamper, Tamper::RewriteEntry | Tamper::ForgeCast)
            && let Some(cast) = entries.iter_mut().find(|e| e["kind"] == "cast")
        {
            let choice = &mut cast["cast"]["ballot"]["answers"][0]["choice"][0];
            *choice = json!(if choice == "alice" { "bob" } else { "alice" });
        }
        if tamper == Tamper::UnsignedStep {
            for e in entries.iter_mut().filter(|e| {
                e["request"]["type"]
                    .as_str()
                    .is_some_and(|t| t.contains("/trustees/deal/"))
            }) {
                e["request"].as_object_mut().unwrap().remove("proof");
            }
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
        // An authorization goes on the board as the community signed it.
        let authorization = if slug == "voting/trustees/authorize" {
            let key = self
                .signer
                .lock()
                .unwrap()
                .clone()
                .expect("a test authorizing a decryption sets the community's signer");
            let mut doc = json!({
                "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
                "type": type_uri,
                "issuer": signer,
                "recipient": BOX,
                "issuedAt": stamp(Utc::now()),
                "payload": payload,
            });
            key.sign_operational_doc(&mut doc).await.unwrap();
            Some(doc)
        } else {
            None
        };
        let now = self.now();
        let tamper = *self.tamper.lock().unwrap();
        let mut bb = self.bb.lock().unwrap();
        let out = match slug {
            "voting/election/register" => bb.register(signer, payload, now),
            "voting/trustees/authorize" => {
                bb.trustees_authorize(signer, authorization.as_ref().unwrap(), now)
            }
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

/// A community whose DID is a `did:key` it signs with, so that what it signs — a decryption
/// authorization on the board — verifies anywhere, certification included.
async fn keyed_community(bx: Arc<InProcessBox>) -> (TestVtc, String) {
    let p = Party::new();
    let signer = Arc::new(vtc_service::credentials::LocalSigner::new(
        p.did.clone(),
        p.secret.clone(),
    ));
    *bx.signer.lock().unwrap() = Some(signer.clone());
    let tv = TestVtc::builder()
        .vtc_did(p.did.clone())
        .with_signers(true)
        .with_credential_signer(signer)
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
        .await;
    (tv, p.did)
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
    read_election_of(tv, reader, id, TEST_VTC_DID).await
}

/// [`read_election`], for a community whose DID is `community`.
async fn read_election_of(tv: &TestVtc, reader: &Party, id: &str, community: &str) -> Ballot {
    let (status, shown) = call(tv, reader, &uri("show"), json!({ "electionId": id })).await;
    assert_eq!(status, StatusCode::OK, "{shown}");
    let shown = payload(&shown);
    let hvk =
        vti_vetting_pcs::scheme::dec(shown["parameters"]["votingKey"].as_str().unwrap()).unwrap();
    let digest = shown["manifestDigest"].as_str().unwrap().to_string();
    Ballot {
        params: VotingParams::new(community, hvk).unwrap(),
        election: Election::new(
            community,
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

    // A sealed election names its trustees.
    let mut sealed = manifest("sealed", false);
    sealed["secrecy"] = json!("sealed");
    let (_, doc) = create(&tv, &chair, sealed).await;
    assert_eq!(tt_error_code(&doc), CREATE_ERR_INVALID_MANIFEST, "{doc}");

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

/// VTI-VOT-022 across a restore: a ticket issued after the backup is not in it, so its holder
/// would be issued a second. A restored election that could have issued in that gap issues no
/// more; one whose registration has not opened issued nothing and is left as it was.
#[tokio::test]
async fn a_restore_closes_ticket_issuance_on_an_election_that_was_issuing() {
    use vtc_service::backup::{export_backup, import_backup};
    use vtc_service::keys::seed_store::PlaintextSecretStore;
    const PW: &str = "election-restore-password";

    let tv = community(InProcessBox::new()).await;
    tv.state.config.write().await.config_path = tv.data_dir().join("config.toml");
    let secrets = PlaintextSecretStore::new(tv.data_dir());
    let chair = admin(&tv).await;
    let (alice, bob) = (member(&tv).await, member(&tv).await);
    let (status, doc) = create(&tv, &chair, manifest("agm", false)).await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    let mut later = manifest("later", false);
    let now = Utc::now();
    later["registrationOpens"] = json!(stamp(now + Duration::days(1)));
    later["votingOpens"] = json!(stamp(now + Duration::days(2)));
    later["votingCloses"] = json!(stamp(now + Duration::days(3)));
    let (status, doc) = create(&tv, &chair, later).await;
    assert_eq!(status, StatusCode::OK, "{doc}");

    let b = read_election(&tv, &alice, "agm").await;
    take_ticket(&tv, &alice, &b).await;
    let backup = export_backup(&tv.state, &secrets, PW, false).await.unwrap();
    // Issued after the backup: the restore forgets it.
    take_ticket(&tv, &bob, &b).await;

    let result = import_backup(&tv.state, &secrets, &backup, PW, true)
        .await
        .unwrap();
    assert_eq!(result.status, "imported");

    // Bob would otherwise get a second ticket; nobody gets one now.
    let voter = Voter::generate(&b.params, &mut vti_voting::rand::rngs::OsRng).unwrap();
    for who in [&bob, &alice] {
        let (body, _) = ask(&b, &voter, "voter/agm");
        let (_, doc) = call(&tv, who, &uri("tickets/issue"), body).await;
        assert_eq!(tt_error_code(&doc), ISSUE_ERR_NOT_OPEN, "{doc}");
    }

    let ks = tv.state.elections.ks();
    let agm = vtc_service::elections::store::get(ks, "agm")
        .await
        .unwrap()
        .unwrap();
    assert!(agm.issuance_closed_by_restore.is_some());
    let later = vtc_service::elections::store::get(ks, "later")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(later.issuance_closed_by_restore, None);
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

/// Trustees for a sealed election, run against the in-process box directly — the community never
/// carries their documents (CONVENTIONS §9.6). Each signs its own requests, as its VTA would, so
/// the community can verify every step on the board as that trustee's.
struct Trustees {
    parties: Vec<Party>,
    keys: Vec<vti_voting::trustees::TrusteeKey>,
}

impl Trustees {
    fn dids(&self) -> Vec<String> {
        self.parties.iter().map(|p| p.did.clone()).collect()
    }
}

/// `from`'s `voting/trustees/<task>` request, signed and addressed to the ballot box.
async fn trustee_request(from: &Party, task: &str, payload: Value) -> Value {
    signed_to(
        from,
        BOX,
        &format!("{SPEC}voting/trustees/{task}/0.1"),
        payload,
    )
    .await
}

/// The key ceremony on `bx`'s board, at the box's own clock.
async fn run_ceremony(
    bx: &InProcessBox,
    community: &str,
    parties: Vec<Party>,
    ctx: &[u8],
    id: &str,
) -> Trustees {
    use vti_voting::trustees::{
        Dealing, Threshold, TransportSecret, TrusteeKey, deal, open_share, seal_share, verify_share,
    };
    let mut rng = vti_voting::rand::rngs::OsRng;
    let sel = json!({ "community": community, "electionId": id });
    let with = |extra: Value| {
        let mut v = sel.clone();
        v.as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        v
    };
    let now = bx.now();
    let status = |did: &str| {
        bx.bb
            .lock()
            .unwrap()
            .trustees_status(Caller::Did(did), &sel, now)
            .unwrap()
    };
    let secrets: Vec<TransportSecret> = (1..=3)
        .map(|j| TransportSecret::generate(j, &mut rng))
        .collect();
    for (s, p) in secrets.iter().zip(&parties) {
        let tk = s.publish(ctx, &mut rng);
        let doc = trustee_request(
            p,
            "enrol",
            with(json!({ "transportKey": vti_voting::wire::transport_key_value(&tk) })),
        )
        .await;
        bx.bb
            .lock()
            .unwrap()
            .trustees_enrol(&p.did, &doc, now)
            .unwrap();
    }
    let th = Threshold::new(2, 3).unwrap();
    let tks: Vec<_> = status(&parties[0].did)["transportKeys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| vti_voting::wire::transport_key(v).unwrap())
        .collect();
    let mut shares: Vec<Vec<vti_voting::trustees::Share>> = vec![Vec::new(); 3];
    for i in 1..=3u32 {
        let (dealing, dealt) = deal(i, th, ctx, &mut rng).unwrap();
        let sealed = dealt
            .iter()
            .map(|s| {
                (
                    s.recipient,
                    seal_share(s, &tks[s.recipient as usize - 1], ctx, &mut rng).unwrap(),
                )
            })
            .collect();
        let sd = vti_voting::ceremony::SealedDealing {
            dealing,
            shares: sealed,
        };
        let p = &parties[i as usize - 1];
        let doc = trustee_request(
            p,
            "deal",
            with(json!({ "dealing": vti_voting::wire::dealing_value(&sd) })),
        )
        .await;
        bx.bb
            .lock()
            .unwrap()
            .trustees_deal(&p.did, &doc, now)
            .unwrap();
    }
    let dealings: Vec<_> = status(&parties[0].did)["dealings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| vti_voting::wire::dealing(v).unwrap())
        .collect();
    for (j, p) in parties.iter().enumerate() {
        for sd in &dealings {
            let s = open_share(
                &secrets[j],
                sd.dealing.dealer,
                &sd.shares[&(j as u32 + 1)],
                ctx,
            )
            .unwrap();
            verify_share(&sd.dealing, &s).unwrap();
            shares[j].push(s);
        }
        let doc = trustee_request(
            p,
            "confirm",
            with(json!({ "trustee": j + 1, "complaints": [] })),
        )
        .await;
        bx.bb
            .lock()
            .unwrap()
            .trustees_confirm(&p.did, &doc, now)
            .unwrap();
    }
    let ek = vti_voting::wire::election_key(&status(&parties[0].did)["electionKey"], th).unwrap();
    let plain: Vec<Dealing> = dealings.iter().map(|d| d.dealing.clone()).collect();
    Trustees {
        parties,
        keys: (0..3)
            .map(|j| TrusteeKey::from_shares(j as u32 + 1, &shares[j], &plain, &ek).unwrap())
            .collect(),
    }
}

/// A sealed election end to end through the community, on a **private** board: created and
/// registered, the trustees' key formed on the box's board (each trustee reading its ceremony
/// as itself), members take tickets, read the election key from `show` — they cannot read the
/// board — and cast sealed ballots, two trustees decrypt after close, and the community
/// certifies the board — the ceremony, every encrypted cast and every partial re-verified from
/// its own voting key (VTI-VOT-060 – 073; show item 6). The key the community shows is the one
/// the trustees' own signed steps form; a board whose dealings carry no trustee's proof shows
/// none (CONVENTIONS §9.6).
#[tokio::test]
async fn a_sealed_election_is_created_decrypted_by_its_trustees_and_certified() {
    let bx = InProcessBox::new();
    let (tv, cdid) = keyed_community(bx.clone()).await;
    let chair = admin(&tv).await;

    let parties: Vec<Party> = (0..3).map(|_| Party::new()).collect();
    let trustee_dids: Vec<String> = parties.iter().map(|p| p.did.clone()).collect();

    // The trustee rules are the community's to check too.
    let mut broken = manifest("sealed", false);
    broken["community"] = json!(cdid);
    broken["secrecy"] = json!("sealed");
    broken["trustees"] = json!({ "dids": trustee_dids, "threshold": 4 });
    let (_, doc) = create(&tv, &chair, broken).await;
    assert_eq!(tt_error_code(&doc), CREATE_ERR_INVALID_MANIFEST, "{doc}");

    // Voting opens a minute ago for the community; the box runs two hours behind, so the
    // trustees generate the key before its votingOpens.
    bx.ahead.store(-2 * 3600, Ordering::SeqCst);
    let mut m = manifest("sealed", false);
    m["community"] = json!(cdid);
    m["secrecy"] = json!("sealed");
    m["trustees"] = json!({ "dids": trustee_dids, "threshold": 2 });
    m["board"]["visibility"] = json!("private");
    let (status, doc) = create(&tv, &chair, m.clone()).await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    let (alice, bob) = (member(&tv).await, member(&tv).await);
    let b = read_election_of(&tv, &alice, "sealed", &cdid).await;
    let ctx = b.election.trustee_context();
    let trustees = run_ceremony(&bx, &cdid, parties, &ctx, "sealed").await;
    assert_eq!(trustees.dids(), trustee_dids);

    // Voting: each member's agent seals the ballot to the election key and casts it.
    bx.ahead.store(0, Ordering::SeqCst);
    let sel = json!({ "community": cdid, "electionId": "sealed" });
    // A voter cannot read the private board; the community reads the key and shows it.
    assert!(
        bx.bb
            .lock()
            .unwrap()
            .trustees_status(Caller::Did(&alice.did), &sel, bx.now())
            .is_err()
    );
    let (_, shown) = call(&tv, &alice, &uri("show"), json!({ "electionId": "sealed" })).await;
    assert!(payload(&shown).get("electionKey").is_none(), "not read yet");
    // A key formed from dealings no trustee signed is never shown.
    bx.set_tamper(Tamper::UnsignedStep);
    vtc_service::elections::sweeper::pass(&tv.state, Utc::now())
        .await
        .unwrap();
    let (_, shown) = call(&tv, &alice, &uri("show"), json!({ "electionId": "sealed" })).await;
    assert!(payload(&shown).get("electionKey").is_none(), "{shown}");
    bx.set_tamper(Tamper::None);
    vtc_service::elections::sweeper::pass(&tv.state, Utc::now())
        .await
        .unwrap();
    let (_, shown) = call(&tv, &alice, &uri("show"), json!({ "electionId": "sealed" })).await;
    let ek = vti_voting::wire::election_key(
        &payload(&shown)["electionKey"],
        vti_voting::trustees::Threshold::new(2, 3).unwrap(),
    )
    .expect("show carries the election key once formed");
    let typed: trust_tasks_rs::specs::voting::election::register::v0_1::Manifest =
        serde_json::from_value(m).unwrap();
    for (party, choice) in [(&alice, "alice"), (&bob, "alice")] {
        let (voter, ticket) = take_ticket(&tv, party, &b).await;
        let ballot = json!({
            "electionId": "sealed", "manifestDigest": b.digest,
            "answers": [{ "question": "chair", "choice": [choice] }],
        });
        let tag = voter
            .tag_for(&b.params, &ticket, &mut vti_voting::rand::rngs::OsRng)
            .unwrap();
        let form = vti_voting::voter::encrypted_form(
            &typed,
            &b.election,
            &ek,
            &ballot,
            &tag,
            &mut vti_voting::rand::rngs::OsRng,
        )
        .unwrap();
        let cast = voter
            .cast_encrypted_wire(
                &b.params,
                &ticket,
                &form,
                &mut vti_voting::rand::rngs::OsRng,
            )
            .unwrap();
        let now = bx.now();
        bx.bb
            .lock()
            .unwrap()
            .cast_encrypted(
                &json!({ "community": cdid, "electionId": "sealed", "cast": cast }),
                now,
            )
            .expect("the ballot box admits the sealed cast");
    }

    // Past the close nothing is tallied until the trustees decrypt.
    bx.ahead.store(2 * 3600, Ordering::SeqCst);
    let certify = json!({ "electionId": "sealed", "auditAttestations": [] });
    let (_, doc) = call(&tv, &chair, &uri("certify"), certify.clone()).await;
    assert_eq!(tt_error_code(&doc), CERTIFY_ERR_NOT_TALLIED, "{doc}");
    // No partial is taken until the community authorizes the decryption it computed itself
    // from the closed board (CONVENTIONS §9.7) — which its sweeper does.
    assert!(
        bx.bb
            .lock()
            .unwrap()
            .trustees_status(Caller::Did(&trustees.parties[0].did), &sel, bx.now())
            .unwrap()
            .get("authorization")
            .is_none()
    );
    vtc_service::elections::sweeper::pass(&tv.state, Utc::now() + Duration::hours(2))
        .await
        .unwrap();
    assert!(
        bx.bb
            .lock()
            .unwrap()
            .trustees_status(Caller::Did(&trustees.parties[0].did), &sel, bx.now())
            .unwrap()
            .get("authorization")
            .is_some(),
        "the community authorized the decryption"
    );
    for j in [0usize, 2] {
        let now = bx.now();
        let did = trustees.parties[j].did.clone();
        let status = bx
            .bb
            .lock()
            .unwrap()
            .trustees_status(Caller::Did(&did), &sel, now)
            .unwrap();
        let partials: Vec<Value> = status["targets"]
            .as_array()
            .unwrap()
            .iter()
            .map(|tv| {
                let (target, ct) = vti_voting::wire::target(tv).unwrap();
                let p = vti_voting::trustees::partial_decrypt(
                    &trustees.keys[j],
                    &ct,
                    &ctx,
                    &mut vti_voting::rand::rngs::OsRng,
                );
                vti_voting::wire::partial_value(&target, &ct, &p)
            })
            .collect();
        let mut p = sel.clone();
        p["trustee"] = json!(j + 1);
        p["partials"] = json!(partials);
        let doc = trustee_request(&trustees.parties[j], "decrypt", p).await;
        bx.bb
            .lock()
            .unwrap()
            .trustees_decrypt(&did, &doc, now)
            .unwrap();
    }

    let (status, doc) = call(&tv, &chair, &uri("certify"), certify).await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    assert_eq!(payload(&doc)["result"]["ballotsCounted"], 2);
    assert_eq!(
        payload(&doc)["result"]["questions"][0]["choice"],
        json!({ "alice": 2, "bob": 0 })
    );
}

/// An open election end to end over a real mediator: the community's production link to a
/// ballot box (TSP, then DIDComm, signed as the community — VTI-VOT-005), and a real voting
/// service — the host session and dispatcher a deployed `vti-voting-service` runs — on the same
/// mediator. Created and registered, a member takes a ticket and casts over the ballot box's
/// HTTPS door, the community closes early, and certifies the board it reads back over the
/// mediator. Nothing here is in-process between the community and the ballot box.
#[tokio::test]
async fn an_open_election_runs_against_a_real_ballot_box_over_a_mediator() {
    use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};
    use affinidi_tdk::dids::{
        DID, KeyType, OneOrMany, PeerKeyRole, PeerService, PeerServiceEndpoint,
        PeerServiceEndpointLong,
    };
    use http_body_util::BodyExt as _;
    use tower::ServiceExt as _;
    use vtc_service::test_support::MockVtcTransport;
    use vti_voting_service::{
        AppState as BoxState,
        identity::Identity,
        messaging::{BallotBoxResponder, IdentitySession, Shared, supervise},
    };

    let h = MockVtcTransport::start_with_elections(VotingConfig::default()).await;
    let community = h.vtc_did().to_string();

    // The ballot box: a did:peer at the shared mediator, served by the voting service's own
    // host session and dispatcher.
    let (box_did, box_secrets) = DID::generate_did_peer_with_services(
        vec![
            (PeerKeyRole::Verification, KeyType::Ed25519),
            (PeerKeyRole::Encryption, KeyType::X25519),
        ],
        Some(vec![PeerService {
            type_: "DIDCommMessaging".into(),
            endpoint: PeerServiceEndpoint::Long(OneOrMany::One(PeerServiceEndpointLong {
                uri: h.mediator_did().to_string(),
                accept: vec![],
                routing_keys: vec![],
            })),
            id: None,
        }]),
    )
    .expect("mint the ballot box's did:peer");
    h.register_local_did(&box_did).await;
    let did_resolver = DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
        .await
        .expect("a DID resolver");
    let key = vta_sdk::trust_task_sign::HolderKey::new(
        box_secrets[0].id.clone(),
        box_secrets[0].get_private_keymultibase().unwrap(),
    )
    .unwrap();
    let box_state = Arc::new(BoxState::new(
        BallotBox::new(&box_did),
        Identity {
            did: box_did.clone(),
            key,
        },
        vti_common::auth::TrustTaskVmResolver::new(did_resolver.clone()),
        vti_voting_service::config::CommunitiesConfig {
            allowed: vec![community.clone()],
            ..Default::default()
        },
    ));
    let (stop, stopped) = tokio::sync::watch::channel(false);
    let session = tokio::spawn(supervise(
        IdentitySession::new(
            BallotBoxResponder::new(box_state.clone()),
            h.mediator_did().to_string(),
            box_secrets,
        ),
        Arc::new(Shared {
            did_resolver,
            resolver_url: None,
        }),
        stopped,
    ));

    // The community trusts it.
    h.vtc.state.config.write().await.voting = VotingConfig {
        trusted_ballot_boxes: vec![TrustedBallotBox {
            did: box_did.clone(),
            operator: "E2E Ballots".into(),
            same_operator: false,
        }],
    };
    let tv = &h.vtc;
    let chair = admin(tv).await;
    let mut m = manifest("e2e", false);
    m["community"] = json!(community);
    m["ballotBox"] = json!(box_did);
    m["board"]["auditors"] = json!([]);
    m["votingOpens"] = json!(stamp(Utc::now() + Duration::seconds(4)));

    // Registered over the mediator: until the ballot box's session is up, the create stays
    // pending and the sweeper redelivers it.
    let (status, doc) = create(tv, &chair, m).await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(60);
    loop {
        let (_, shown) = call(tv, &chair, &uri("show"), json!({ "electionId": "e2e" })).await;
        if payload(&shown)["state"] != "pendingRegistration" {
            assert_ne!(payload(&shown)["state"], "failed", "{shown}");
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "never registered: {shown}"
        );
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        vtc_service::elections::sweeper::pass(&tv.state, Utc::now())
            .await
            .unwrap();
    }

    // A member takes a ticket from the community and casts at the ballot box's HTTPS door,
    // from a key made for the cast.
    let alice = member(tv).await;
    let b = read_election_of(tv, &alice, "e2e", &community).await;
    let (voter, ticket) = take_ticket(tv, &alice, &b).await;
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    let cast = cast_for(&b, &voter, &ticket, "alice");
    let one_time = Identity::from_seed(&[7; 32]).unwrap();
    let mut cast_doc: trust_tasks_rs::TrustTask<Value> = serde_json::from_value(json!({
        "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        "type": "https://trusttasks.org/spec/voting/ballot/cast/0.1",
        "issuer": one_time.did,
        "recipient": box_did,
        "issuedAt": stamp(Utc::now()),
        "payload": { "community": community, "electionId": "e2e", "cast": cast },
    }))
    .unwrap();
    vta_sdk::trust_task_sign::sign_in_place_with(&mut cast_doc, &one_time.key)
        .await
        .unwrap();
    let res = vti_voting_service::router(box_state.clone())
        .oneshot(
            axum::http::Request::post("/trust-tasks")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    serde_json::to_vec(&cast_doc).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = res.status();
    let receipt: Value =
        serde_json::from_slice(&res.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(status, StatusCode::OK, "{receipt}");
    assert_eq!(receipt["payload"]["outcome"], "counted");

    // Closed early by the community, over the mediator, and certified from the board it reads
    // back the same way.
    let (status, doc) = call(tv, &chair, &uri("close"), json!({ "electionId": "e2e" })).await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    let (status, doc) = call(
        tv,
        &chair,
        &uri("certify"),
        json!({ "electionId": "e2e", "auditAttestations": [] }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    assert_eq!(payload(&doc)["result"]["ballotsCounted"], 1);
    assert_eq!(
        payload(&doc)["result"]["questions"][0]["choice"],
        json!({ "alice": 1, "bob": 0 })
    );

    let _ = stop.send(true);
    let _ = tokio::time::timeout(std::time::Duration::from_secs(15), session).await;
    h.shutdown().await;
}
