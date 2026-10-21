//! Community elections on the signed-document spine — `vtc/elections/{create,list,show,close,
//! cancel,certify}/0.1` and `vtc/elections/tickets/issue/0.1` ([`crate::elections`], VTI-VOT-001 – 100).
//!
//! | task | signed by | authority (read now) |
//! |---|---|---|
//! | `create`, `close`, `cancel`, `certify` | an administrator | `vtc.elections.manage` (VTI-VOT-080); a binding `create` also another holder's consent (VTI-VOT-081) |
//! | `list`, `show` | anyone the community knows | a holder of `vtc.elections.manage` sees every election; anyone else a registered one whose roll admits them now |
//! | `tickets/issue` | a party the roll admits | the roll, as the records stand now (VTI-VOT-021), once per election (VTI-VOT-022) |
//!
//! # Unknown and unseen are one answer
//!
//! An election the caller may not see is `electionUnknown` exactly as one that does not exist,
//! in code and message, so a member learns nothing of an election that is not theirs — not even
//! that it exists. For the same reason `tickets/issue` answers an ineligible caller who holds no
//! `vtc.elections.manage` with `electionUnknown`, never `notEligible`.
//!
//! # The community never sees a ballot
//!
//! No task here carries one, and the audit never records a ticket request's identifier, its
//! blinded commitment or the pre-credential (tickets/issue item 11).
//!
//! # Certification is the community's own verification
//!
//! `certify` reads the result, the head and every entry from the ballot box itself, never from
//! the requester, and re-verifies the whole board from the community's own voting key
//! (`vti_voting::audit`). Auditors' attestations are evidence beside that, never instead of it.
//! A certified result authorizes nothing by itself (item 12).

use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use trust_tasks_rs::specs::vtc::elections::{
    cancel::v0_1 as cancel, certify::v0_1 as certify, close::v0_1 as close, create::v0_1 as create,
    list::v0_1 as list, show::v0_1 as show, tickets::issue::v0_1 as issue,
};
use trust_tasks_rs::{Payload, RejectReason, TrustTask};
use vti_common::audit::{AuditEvent, ElectionChangedData, ElectionTicketIssuedData};

use super::helpers::{
    TrustTaskOutcome, app_error_to_reject, extended_code, reject_with, reject_with_code,
    success_response,
};
use super::{JoinAuthCtx, admin_signer, capable_signer, parse_spec_payload};
use crate::acl::{Capability, get_acl_entry};
use crate::elections::ops::{self, CertifyError, CreateError, EndError, IssueError, TicketAsk};
use crate::elections::store::{self, ElectionRecord};
use crate::error::AppError;
use crate::server::AppState;

pub(crate) const CREATE_TYPE: &str = <create::Payload as Payload>::TYPE_URI;
pub(crate) const LIST_TYPE: &str = <list::Payload as Payload>::TYPE_URI;
pub(crate) const SHOW_TYPE: &str = <show::Payload as Payload>::TYPE_URI;
pub(crate) const CLOSE_TYPE: &str = <close::Payload as Payload>::TYPE_URI;
pub(crate) const CANCEL_TYPE: &str = <cancel::Payload as Payload>::TYPE_URI;
pub(crate) const ISSUE_TYPE: &str = <issue::Payload as Payload>::TYPE_URI;
pub(crate) const CERTIFY_TYPE: &str = <certify::Payload as Payload>::TYPE_URI;

// The declared codes, read from the generated bindings: the handlers emit these, and the
// error-code census names each as the constant its witness asserts.
pub(crate) const CREATE_ERR_ELECTION_EXISTS: &str = create::error_codes::ELECTION_EXISTS.code;
pub(crate) const CREATE_ERR_INVALID_MANIFEST: &str = create::error_codes::INVALID_MANIFEST.code;
pub(crate) const CREATE_ERR_UNSUPPORTED_SECRECY: &str =
    create::error_codes::UNSUPPORTED_SECRECY.code;
pub(crate) const CREATE_ERR_COMMUNITY_MISMATCH: &str = create::error_codes::COMMUNITY_MISMATCH.code;
pub(crate) const CREATE_ERR_BALLOT_BOX_NOT_TRUSTED: &str =
    create::error_codes::BALLOT_BOX_NOT_TRUSTED.code;
pub(crate) const CREATE_ERR_BALLOT_BOX_REFUSED: &str = create::error_codes::BALLOT_BOX_REFUSED.code;
pub(crate) const CLOSE_ERR_ELECTION_UNKNOWN: &str = close::error_codes::ELECTION_UNKNOWN.code;
pub(crate) const CLOSE_ERR_NOT_OPEN: &str = close::error_codes::NOT_OPEN.code;
pub(crate) const CLOSE_ERR_EARLY_CLOSE_NOT_ALLOWED: &str =
    close::error_codes::EARLY_CLOSE_NOT_ALLOWED.code;
pub(crate) const CLOSE_ERR_BALLOT_BOX_UNAVAILABLE: &str =
    close::error_codes::BALLOT_BOX_UNAVAILABLE.code;
pub(crate) const CLOSE_ERR_BALLOT_BOX_REFUSED: &str = close::error_codes::BALLOT_BOX_REFUSED.code;
pub(crate) const CANCEL_ERR_ELECTION_UNKNOWN: &str = cancel::error_codes::ELECTION_UNKNOWN.code;
pub(crate) const CANCEL_ERR_NOT_OPEN: &str = cancel::error_codes::NOT_OPEN.code;
pub(crate) const CANCEL_ERR_BALLOT_BOX_UNAVAILABLE: &str =
    cancel::error_codes::BALLOT_BOX_UNAVAILABLE.code;
pub(crate) const CANCEL_ERR_BALLOT_BOX_REFUSED: &str = cancel::error_codes::BALLOT_BOX_REFUSED.code;
pub(crate) const SHOW_ERR_ELECTION_UNKNOWN: &str = show::error_codes::ELECTION_UNKNOWN.code;
pub(crate) const ISSUE_ERR_ELECTION_UNKNOWN: &str = issue::error_codes::ELECTION_UNKNOWN.code;
pub(crate) const ISSUE_ERR_NOT_OPEN: &str = issue::error_codes::NOT_OPEN.code;
pub(crate) const ISSUE_ERR_MANIFEST_MISMATCH: &str = issue::error_codes::MANIFEST_MISMATCH.code;
pub(crate) const ISSUE_ERR_NOT_ELIGIBLE: &str = issue::error_codes::NOT_ELIGIBLE.code;
pub(crate) const ISSUE_ERR_ALREADY_ISSUED: &str = issue::error_codes::ALREADY_ISSUED.code;
pub(crate) const ISSUE_ERR_REQUEST_INVALID: &str = issue::error_codes::REQUEST_INVALID.code;
pub(crate) const CERTIFY_ERR_ALREADY_CERTIFIED: &str = certify::error_codes::ALREADY_CERTIFIED.code;
pub(crate) const CERTIFY_ERR_AUDIT_ATTESTATION_INVALID: &str =
    certify::error_codes::AUDIT_ATTESTATION_INVALID.code;
pub(crate) const CERTIFY_ERR_BALLOT_BOX_UNAVAILABLE: &str =
    certify::error_codes::BALLOT_BOX_UNAVAILABLE.code;
pub(crate) const CERTIFY_ERR_BOARD_INCONSISTENT: &str =
    certify::error_codes::BOARD_INCONSISTENT.code;
pub(crate) const CERTIFY_ERR_CAST_INVALID: &str = certify::error_codes::CAST_INVALID.code;
pub(crate) const CERTIFY_ERR_COUNT_EXCEEDS_TICKETS: &str =
    certify::error_codes::COUNT_EXCEEDS_TICKETS.code;
pub(crate) const CERTIFY_ERR_ELECTION_UNKNOWN: &str = certify::error_codes::ELECTION_UNKNOWN.code;
pub(crate) const CERTIFY_ERR_NOT_TALLIED: &str = certify::error_codes::NOT_TALLIED.code;
pub(crate) const CERTIFY_ERR_RESULT_MISMATCH: &str = certify::error_codes::RESULT_MISMATCH.code;

/// Every URI [`dispatch`] routes.
pub(crate) const URIS: &[&str] = &[
    CREATE_TYPE,
    LIST_TYPE,
    SHOW_TYPE,
    CLOSE_TYPE,
    CANCEL_TYPE,
    ISSUE_TYPE,
    CERTIFY_TYPE,
];

/// Route one of [`URIS`]; `None` for any other URI.
pub(super) async fn dispatch(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
    type_uri: &str,
) -> Option<TrustTaskOutcome> {
    Some(match type_uri {
        CREATE_TYPE => handle_create(state, ctx, doc).await,
        LIST_TYPE => handle_list(state, ctx, doc).await,
        SHOW_TYPE => handle_show(state, ctx, doc).await,
        CLOSE_TYPE => handle_close(state, ctx, doc).await,
        CANCEL_TYPE => handle_cancel(state, ctx, doc).await,
        ISSUE_TYPE => handle_issue(state, ctx, doc).await,
        CERTIFY_TYPE => handle_certify(state, ctx, doc).await,
        _ => return None,
    })
}

// ─── who is asking ───────────────────────────────────────────────────────

/// The proven caller, and whether they hold `vtc.elections.manage` now. A console key answers
/// for the administrator it acts for; a party with no entry at all (a DID a roll lists) is a
/// caller without the capability.
async fn caller(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: &TrustTask<Value>,
) -> Result<(String, bool), TrustTaskOutcome> {
    let signer = ctx
        .verified_signer
        .clone()
        .ok_or_else(|| reject_with(doc, RejectReason::ProofRequired))?;
    match get_acl_entry(&state.acl_ks, &signer).await {
        Ok(Some(entry)) => {
            let manager = entry.can(Capability::ElectionsManage, None);
            Ok((signer, manager))
        }
        Ok(None) => match admin_signer(state, ctx, doc).await {
            Ok(claims) => {
                let manager = crate::acl::require_capability(
                    &state.acl_ks,
                    &claims.did,
                    Capability::ElectionsManage,
                    None,
                )
                .await
                .is_ok();
                Ok((claims.did, manager))
            }
            Err(_) => Ok((signer, false)),
        },
        Err(e) => Err(app_error_to_reject(doc, &e)),
    }
}

fn unknown(doc: &TrustTask<Value>, code: &str) -> TrustTaskOutcome {
    reject_with_code(
        doc,
        extended_code(code),
        "no such election is known to this community",
        None,
    )
}

async fn audit(state: &AppState, actor: &str, subject: Option<&str>, event: AuditEvent) {
    let Some(writer) = state.audit_writer.as_ref() else {
        return;
    };
    if let Err(e) = writer.write(actor, subject, event).await {
        tracing::warn!(error = %e, "could not audit an election change");
    }
}

fn changed(election_id: &str, change: &str) -> ElectionChangedData {
    ElectionChangedData {
        election_id: election_id.to_string(),
        change: change.to_string(),
        manifest_digest: None,
        binding: None,
        action_id: None,
        ballot_box_answer: None,
        reason: None,
        head_tree_size: None,
        head_root_hash: None,
        result_digest: None,
        attestation_issuers: Vec::new(),
    }
}

// ─── create ──────────────────────────────────────────────────────────────

/// `vtc/elections/create/0.1` (items 1 – 10).
async fn handle_create(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    // Item 1.
    let actor = match capable_signer(state, ctx, &doc, Capability::ElectionsManage, None).await {
        Ok(a) => a,
        Err(reject) => return reject,
    };
    if let Err(reject) = parse_spec_payload::<create::Payload>(&doc) {
        return reject;
    }
    // The manifest as received: its digest is taken over these bytes, never a re-serialisation.
    let manifest = doc.payload["manifest"].clone();
    let now = Utc::now();
    let refuse = |e: CreateError| -> TrustTaskOutcome {
        match e {
            CreateError::InvalidManifest(reason) => reject_with_code(
                &doc,
                extended_code(CREATE_ERR_INVALID_MANIFEST),
                format!("the manifest is not valid: {reason}"),
                Some(json!({ "reason": reason })),
            ),
            CreateError::UnsupportedSecrecy => reject_with_code(
                &doc,
                extended_code(CREATE_ERR_UNSUPPORTED_SECRECY),
                "this community runs open elections only (voting CONVENTIONS §7)",
                None,
            ),
            CreateError::CommunityMismatch => reject_with_code(
                &doc,
                extended_code(CREATE_ERR_COMMUNITY_MISMATCH),
                "the manifest names another community",
                None,
            ),
            CreateError::BallotBoxNotTrusted => reject_with_code(
                &doc,
                extended_code(CREATE_ERR_BALLOT_BOX_NOT_TRUSTED),
                "the ballot box is not one of this community's trusted voting services \
                 (VTI-VOT-082); an operator adds one under [voting] trusted_ballot_boxes",
                None,
            ),
            CreateError::ElectionExists => reject_with_code(
                &doc,
                extended_code(CREATE_ERR_ELECTION_EXISTS),
                "this community already holds an election, or a parked creation, under that \
                 electionId",
                None,
            ),
            CreateError::BallotBoxRefused { code, message } => reject_with_code(
                &doc,
                extended_code(CREATE_ERR_BALLOT_BOX_REFUSED),
                format!("the ballot box refused the registration: {message}"),
                Some(json!({ "code": code, "message": message })),
            ),
            CreateError::App(e) => app_error_to_reject(&doc, &e),
        }
    };
    // Items 2 – 6.
    let checked = match ops::check_create(state, &manifest, now).await {
        Ok(c) => c,
        Err(e) => return refuse(e),
    };
    let election_id = checked.manifest.election_id.as_str().to_string();
    let binding = checked.manifest.binding;

    // Item 7: a binding election takes another holder's consent; on execution the checks
    // above ran again against the community as it is then. The action list records the
    // parking; item 10's row is written when the creation executes, naming the action.
    if binding
        && let Err(outcome) = super::acl_tasks::settle_consent_gate(
            state,
            &actor,
            &doc,
            crate::acl::admin_consent::Act::CreateBindingElection,
            &election_id,
            &format!("Create the binding election {election_id}"),
            &format!(
                "Create {election_id}, an election whose result this community treats as \
                 deciding something in its name"
            ),
        )
        .await
    {
        return outcome;
    }
    let action_id = crate::admin_actions::executing().map(|e| e.action_id);

    // Items 8 – 9.
    let rec = match ops::create(
        state,
        &actor.did,
        &manifest,
        checked,
        action_id.clone(),
        now,
    )
    .await
    {
        Ok(rec) => rec,
        Err(e) => {
            if let CreateError::BallotBoxRefused { code, .. } = &e {
                audit(
                    state,
                    &actor.did,
                    None,
                    AuditEvent::ElectionChanged(ElectionChangedData {
                        binding: Some(binding),
                        action_id: action_id.clone(),
                        ballot_box_answer: Some(code.clone()),
                        ..changed(&election_id, "registrationRefused")
                    }),
                )
                .await;
            }
            return refuse(e);
        }
    };
    let state_text = if rec.is_registered() {
        "registered"
    } else {
        "pendingRegistration"
    };
    // Item 10.
    audit(
        state,
        &actor.did,
        None,
        AuditEvent::ElectionChanged(ElectionChangedData {
            manifest_digest: Some(rec.manifest_digest.clone()),
            binding: Some(binding),
            action_id: action_id.clone(),
            ballot_box_answer: Some(
                if rec.is_registered() {
                    "success"
                } else {
                    "pending"
                }
                .into(),
            ),
            ..changed(&election_id, "created")
        }),
    )
    .await;
    let mut body = json!({
        "electionId": rec.election_id,
        "manifestDigest": rec.manifest_digest,
        "state": state_text,
    });
    if let Some(id) = action_id {
        body["actionId"] = json!(id);
    }
    success_response(&doc, body)
}

// ─── list ────────────────────────────────────────────────────────────────

/// The default and largest page.
const DEFAULT_LIMIT: usize = 20;

/// A cursor names an offset, bound to the caller and the filter (list item 4).
fn cursor_for(caller: &str, filter: Option<&str>, offset: usize) -> String {
    format!("{offset}.{}", cursor_mac(caller, filter, offset))
}

fn cursor_mac(caller: &str, filter: Option<&str>, offset: usize) -> String {
    let mut h = Sha256::new();
    h.update(b"vtc/elections/list/cursor/v1\0");
    for part in [caller, filter.unwrap_or(""), &offset.to_string()] {
        h.update((part.len() as u64).to_be_bytes());
        h.update(part.as_bytes());
    }
    hex::encode(&h.finalize()[..12])
}

fn offset_of(cursor: &str, caller: &str, filter: Option<&str>) -> Option<usize> {
    let (n, mac) = cursor.split_once('.')?;
    let offset: usize = n.parse().ok()?;
    (cursor_mac(caller, filter, offset) == mac).then_some(offset)
}

/// `vtc/elections/list/0.1` (items 1 – 5).
async fn handle_list(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let (who, manager) = match caller(state, ctx, &doc).await {
        Ok(c) => c,
        Err(reject) => return reject,
    };
    if let Err(reject) = parse_spec_payload::<list::Payload>(&doc) {
        return reject;
    }
    let filter = doc.payload["state"].as_str();
    let limit = doc.payload["limit"].as_u64().map_or(DEFAULT_LIMIT, |l| {
        usize::try_from(l).unwrap_or(DEFAULT_LIMIT)
    });
    let offset = match doc.payload["cursor"].as_str() {
        None => 0,
        Some(c) => match offset_of(c, &who, filter) {
            Some(o) => o,
            None => {
                return reject_with(
                    &doc,
                    RejectReason::MalformedRequest {
                        reason: "the cursor was issued to another caller or filter".into(),
                    },
                );
            }
        },
    };
    let now = Utc::now();
    let all = match store::all(state.elections.ks()).await {
        Ok(a) => a,
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    let mut seen: Vec<ElectionRecord> = Vec::new();
    for rec in all {
        match ops::may_see(state, &rec, &who, manager).await {
            Ok(true) => {}
            Ok(false) => continue,
            Err(e) => return app_error_to_reject(&doc, &e),
        }
        if filter.is_some_and(|f| f != rec.state(now)) {
            continue;
        }
        seen.push(rec);
    }
    // The reference order: votingOpens, most recent first.
    seen.sort_by(|a, b| {
        b.voting_opens
            .cmp(&a.voting_opens)
            .then_with(|| a.election_id.cmp(&b.election_id))
    });
    let mut items = Vec::new();
    for rec in seen.iter().skip(offset).take(limit) {
        let held = match store::ticket(state.elections.ks(), &rec.election_id, &who).await {
            Ok(t) => t.is_some(),
            Err(e) => return app_error_to_reject(&doc, &e),
        };
        let mut item = json!({
            "electionId": rec.election_id,
            "state": rec.state(now),
            "votingOpens": rfc3339(rec.voting_opens),
            "votingCloses": rfc3339(rec.voting_closes),
            "binding": rec.binding,
            "ticketHeld": held,
        });
        if let Some(t) = rec.manifest.get("title") {
            item["title"] = t.clone();
        }
        items.push(item);
    }
    let mut body = json!({ "elections": items });
    if offset + limit < seen.len() {
        body["next"] = json!(cursor_for(&who, filter, offset + limit));
    }
    success_response(&doc, body)
}

fn rfc3339(t: DateTime<Utc>) -> String {
    t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

// ─── show ────────────────────────────────────────────────────────────────

/// `vtc/elections/show/0.1` (items 1 – 6).
async fn handle_show(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let (who, manager) = match caller(state, ctx, &doc).await {
        Ok(c) => c,
        Err(reject) => return reject,
    };
    if let Err(reject) = parse_spec_payload::<show::Payload>(&doc) {
        return reject;
    }
    let election_id = doc.payload["electionId"].as_str().unwrap_or_default();
    let rec = match visible(state, &who, manager, election_id).await {
        Ok(Some(r)) => r,
        Ok(None) => return unknown(&doc, SHOW_ERR_ELECTION_UNKNOWN),
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    let parameters = match ops::parameters(state).await {
        Ok(p) => p,
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    let mut body = json!({
        "manifest": rec.manifest,
        "manifestDigest": rec.manifest_digest,
        "state": rec.state(Utc::now()),
        "parameters": parameters,
        "disclosure": ops::disclosure(state, &rec).await,
        "checkpoints": rec.checkpoints,
    });
    // Item 4.
    if manager {
        body["ticketsIssued"] = json!(rec.tickets_issued);
    }
    // Item 6.
    if let Some(k) = &rec.election_key {
        body["electionKey"] = k.clone();
    }
    // Item 7.
    if let Some(c) = &rec.certified {
        body["certified"] = c.clone();
    }
    success_response(&doc, body)
}

/// The election, when `who` may see it.
async fn visible(
    state: &AppState,
    who: &str,
    manager: bool,
    election_id: &str,
) -> Result<Option<ElectionRecord>, AppError> {
    let Some(rec) = store::get(state.elections.ks(), election_id).await? else {
        return Ok(None);
    };
    Ok(ops::may_see(state, &rec, who, manager)
        .await?
        .then_some(rec))
}

// ─── close and cancel ────────────────────────────────────────────────────

fn end_refusal(
    doc: &TrustTask<Value>,
    e: EndError,
    unknown_code: &str,
    not_open: &str,
    unavailable: &str,
    refused: &str,
    early: Option<&str>,
) -> TrustTaskOutcome {
    match e {
        EndError::ElectionUnknown => unknown(doc, unknown_code),
        EndError::NotOpen => reject_with_code(
            doc,
            extended_code(not_open),
            "the election is not open",
            None,
        ),
        EndError::EarlyCloseNotAllowed => reject_with_code(
            doc,
            extended_code(early.unwrap_or(not_open)),
            "the manifest does not allow an early close; members took their tickets on its word",
            None,
        ),
        EndError::BallotBoxUnavailable(why) => reject_with_code(
            doc,
            extended_code(unavailable),
            format!("the ballot box did not answer ({why}); send the request again"),
            None,
        ),
        EndError::BallotBoxRefused { code, message } => reject_with_code(
            doc,
            extended_code(refused),
            format!("the ballot box refused: {message}"),
            Some(json!({ "code": code, "message": message })),
        ),
        EndError::App(e) => app_error_to_reject(doc, &e),
    }
}

/// `vtc/elections/close/0.1` (items 1 – 6).
async fn handle_close(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let actor = match capable_signer(state, ctx, &doc, Capability::ElectionsManage, None).await {
        Ok(a) => a,
        Err(reject) => return reject,
    };
    if let Err(reject) = parse_spec_payload::<close::Payload>(&doc) {
        return reject;
    }
    let election_id = doc.payload["electionId"].as_str().unwrap_or_default();
    let reason = doc.payload["reason"].as_str();
    let out = ops::close(state, election_id, reason, Utc::now()).await;
    let answer = match &out {
        Ok(_) => "success".to_string(),
        Err(EndError::BallotBoxRefused { code, .. }) => code.clone(),
        Err(EndError::BallotBoxUnavailable(_)) => "unavailable".to_string(),
        Err(_) => String::new(),
    };
    if !answer.is_empty() {
        audit(
            state,
            &actor.did,
            None,
            AuditEvent::ElectionChanged(ElectionChangedData {
                ballot_box_answer: Some(answer),
                reason: reason.map(str::to_string),
                ..changed(election_id, "closed")
            }),
        )
        .await;
    }
    match out {
        Ok(st) => success_response(&doc, json!({ "electionId": election_id, "state": st })),
        Err(e) => end_refusal(
            &doc,
            e,
            CLOSE_ERR_ELECTION_UNKNOWN,
            CLOSE_ERR_NOT_OPEN,
            CLOSE_ERR_BALLOT_BOX_UNAVAILABLE,
            CLOSE_ERR_BALLOT_BOX_REFUSED,
            Some(CLOSE_ERR_EARLY_CLOSE_NOT_ALLOWED),
        ),
    }
}

/// `vtc/elections/cancel/0.1` (items 1 – 6).
async fn handle_cancel(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let actor = match capable_signer(state, ctx, &doc, Capability::ElectionsManage, None).await {
        Ok(a) => a,
        Err(reject) => return reject,
    };
    if let Err(reject) = parse_spec_payload::<cancel::Payload>(&doc) {
        return reject;
    }
    let election_id = doc.payload["electionId"].as_str().unwrap_or_default();
    let reason = doc.payload["reason"].as_str().unwrap_or_default();
    let out = ops::cancel(state, election_id, reason, Utc::now()).await;
    let answer = match &out {
        Ok(_) => "success".to_string(),
        Err(EndError::BallotBoxRefused { code, .. }) => code.clone(),
        Err(EndError::BallotBoxUnavailable(_)) => "unavailable".to_string(),
        Err(_) => String::new(),
    };
    if !answer.is_empty() {
        audit(
            state,
            &actor.did,
            None,
            AuditEvent::ElectionChanged(ElectionChangedData {
                ballot_box_answer: Some(answer),
                reason: Some(reason.to_string()),
                ..changed(election_id, "cancelled")
            }),
        )
        .await;
    }
    match out {
        Ok(st) => success_response(&doc, json!({ "electionId": election_id, "state": st })),
        Err(e) => end_refusal(
            &doc,
            e,
            CANCEL_ERR_ELECTION_UNKNOWN,
            CANCEL_ERR_NOT_OPEN,
            CANCEL_ERR_BALLOT_BOX_UNAVAILABLE,
            CANCEL_ERR_BALLOT_BOX_REFUSED,
            None,
        ),
    }
}

// ─── tickets ─────────────────────────────────────────────────────────────

/// `vtc/elections/tickets/issue/0.1` (items 1 – 11).
async fn handle_issue(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let (who, manager) = match caller(state, ctx, &doc).await {
        Ok(c) => c,
        Err(reject) => return reject,
    };
    if let Err(reject) = parse_spec_payload::<issue::Payload>(&doc) {
        return reject;
    }
    let election_id = doc.payload["electionId"].as_str().unwrap_or_default();
    let doc_digest = match serde_json::to_vec(&doc) {
        Ok(bytes) => hex::encode(Sha256::digest(bytes)),
        Err(e) => return app_error_to_reject(&doc, &AppError::Internal(e.to_string())),
    };
    let ask = TicketAsk {
        signer: &who,
        manager,
        election_id,
        manifest_digest: doc.payload["manifestDigest"].as_str().unwrap_or_default(),
        request: &doc.payload["request"],
        doc_id: &doc.id,
        doc_digest: &doc_digest,
    };
    let declared = |code: &str, message: &str| {
        reject_with_code(&doc, extended_code(code), message.to_string(), None)
    };
    match ops::issue_ticket(state, ask, Utc::now()).await {
        Ok((pre, resend)) => {
            // Item 11: the signer, the election, the time — nothing derived from the request.
            if !resend {
                audit(
                    state,
                    &ops::community_did(state).await,
                    Some(&who),
                    AuditEvent::ElectionTicketIssued(ElectionTicketIssuedData {
                        election_id: election_id.to_string(),
                    }),
                )
                .await;
            }
            success_response(
                &doc,
                json!({
                    "electionId": election_id,
                    "label": format!("voter/{election_id}"),
                    "preCredential": pre,
                }),
            )
        }
        Err(IssueError::ElectionUnknown) => unknown(&doc, ISSUE_ERR_ELECTION_UNKNOWN),
        // Item 2: a caller without the capability learns nothing of an election not theirs.
        Err(IssueError::NotEligible) if !manager => unknown(&doc, ISSUE_ERR_ELECTION_UNKNOWN),
        Err(IssueError::NotEligible) => declared(
            ISSUE_ERR_NOT_ELIGIBLE,
            "the election's roll does not admit this signer",
        ),
        Err(IssueError::NotOpen) => declared(
            ISSUE_ERR_NOT_OPEN,
            "tickets for this election are not being issued now",
        ),
        Err(IssueError::ManifestMismatch) => declared(
            ISSUE_ERR_MANIFEST_MISMATCH,
            "the manifest digest is not the registered manifest's; read the election again",
        ),
        Err(IssueError::AlreadyIssued) => declared(
            ISSUE_ERR_ALREADY_ISSUED,
            "this signer has already taken its ticket for this election",
        ),
        Err(IssueError::RequestInvalid(why)) => declared(
            ISSUE_ERR_REQUEST_INVALID,
            &format!("the ticket request is not valid for this election: {why}"),
        ),
        Err(IssueError::App(e)) => app_error_to_reject(&doc, &e),
    }
}

// ─── certify ─────────────────────────────────────────────────────────────

/// `vtc/elections/certify/0.1` (items 1 – 12).
async fn handle_certify(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    // Item 1.
    let actor = match capable_signer(state, ctx, &doc, Capability::ElectionsManage, None).await {
        Ok(a) => a,
        Err(reject) => return reject,
    };
    if let Err(reject) = parse_spec_payload::<certify::Payload>(&doc) {
        return reject;
    }
    let election_id = doc.payload["electionId"].as_str().unwrap_or_default();
    // Kept exactly as received.
    let attestations = doc.payload["auditAttestations"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let declared = |code: &str, message: String, details: Option<Value>| {
        reject_with_code(&doc, extended_code(code), message, details)
    };
    match ops::certify(state, election_id, &attestations, Utc::now()).await {
        Ok(c) => {
            let head_size = c.head["treeSize"].as_u64();
            let head_root = c.head["rootHash"].as_str().map(str::to_string);
            let result_digest = vti_voting::audit::result_digest(&c.result).ok();
            audit(
                state,
                &actor.did,
                None,
                AuditEvent::ElectionChanged(ElectionChangedData {
                    head_tree_size: head_size,
                    head_root_hash: head_root,
                    result_digest,
                    attestation_issuers: c.attestation_issuers,
                    ..changed(election_id, "certified")
                }),
            )
            .await;
            success_response(
                &doc,
                json!({
                    "electionId": election_id,
                    "result": c.result,
                    "head": c.head,
                    "certifiedAt": rfc3339(c.certified_at),
                    "auditAttestations": c.attestations,
                }),
            )
        }
        Err(CertifyError::ElectionUnknown) => unknown(&doc, CERTIFY_ERR_ELECTION_UNKNOWN),
        Err(CertifyError::NotTallied) => declared(
            CERTIFY_ERR_NOT_TALLIED,
            "the ballot box has not published a final result for this election".into(),
            None,
        ),
        Err(CertifyError::AlreadyCertified) => declared(
            CERTIFY_ERR_ALREADY_CERTIFIED,
            "the election is already certified".into(),
            None,
        ),
        Err(CertifyError::BallotBoxUnavailable(why)) => declared(
            CERTIFY_ERR_BALLOT_BOX_UNAVAILABLE,
            format!(
                "the ballot box did not answer a read the verification needs ({why}); nothing was recorded"
            ),
            None,
        ),
        Err(CertifyError::BoardInconsistent(details)) => declared(
            CERTIFY_ERR_BOARD_INCONSISTENT,
            "the board does not hold together".into(),
            Some(details),
        ),
        Err(CertifyError::CastInvalid(index)) => declared(
            CERTIFY_ERR_CAST_INVALID,
            format!("the cast at board index {index} would not have been admitted"),
            Some(json!({ "index": index })),
        ),
        Err(CertifyError::ResultMismatch(why)) => declared(
            CERTIFY_ERR_RESULT_MISMATCH,
            format!("the published result is not the board's: {why}"),
            None,
        ),
        Err(CertifyError::CountExceedsTickets { counted, issued }) => declared(
            CERTIFY_ERR_COUNT_EXCEEDS_TICKETS,
            format!("the board counts {counted} ballots, but {issued} tickets were issued"),
            Some(json!({ "ballotsCounted": counted, "ticketsIssued": issued })),
        ),
        Err(CertifyError::AuditAttestationInvalid { index, reason }) => declared(
            CERTIFY_ERR_AUDIT_ATTESTATION_INVALID,
            format!("the attestation at position {index} is not valid: {reason}"),
            Some(json!({ "index": index })),
        ),
        Err(CertifyError::App(e)) => app_error_to_reject(&doc, &e),
    }
}
