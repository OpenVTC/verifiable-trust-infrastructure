//! Community elections on the signed-document spine — `vtc/elections/create/0.5` (and 0.4,
//! 0.3), `list/0.5` (and 0.3), `show/0.6` (and 0.3, 0.2), `{close,cancel,certify}/0.1`,
//! `vtc/elections/tickets/issue/0.3` (and 0.1) and
//! `vtc/elections/ballot-boxes/list/0.1` ([`crate::elections`], VTI-VOT-001 – 100).
//!
//! | task | signed by | authority (read now) |
//! |---|---|---|
//! | `ballot-boxes/list` | an administrator | `vtc.elections.manage` (VTI-VOT-080) |
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
//! # A credential roll's presentation is checked first
//!
//! Under a credential roll (VTI-VOT-025) a claim — and the read of an election put to a member
//! party's members (VTI-VOT-015 item 3) — carries a presentation of a membership credential.
//! It is checked before the election is looked up and without reference to it
//! ([`crate::elections::presentation`], VTI-VOT-018), so an outage of a status list or a DID
//! document is the framework's `indeterminate` whatever `electionId` names. Every check after
//! the lookup reads the community's own records alone. An election whose roll names a member
//! party is shown, and its ticket claimed, by anyone but a manager or the party itself only on
//! a presentation that passes; every other outcome is `electionUnknown` (VTI-VOT-017). A list
//! never carries one, and never shows such an election to anyone else.
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
use trust_tasks_rs::{Payload, RejectReason, TrustTask};
use vti_common::audit::{AuditEvent, ElectionChangedData, ElectionTicketIssuedData};
use vti_specs::vtc::elections::{
    ballot_boxes::list::v0_1 as ballot_boxes_list, cancel::v0_1 as cancel,
    certify::v0_1 as certify, close::v0_1 as close, create::v0_5 as create, list::v0_5 as list,
    show::v0_6 as show, tickets::issue::v0_3 as issue, tombstones::show::v0_1 as tombstone_show,
};
// Still served: a client composing a manifest under voting/_shared/0.2 or 0.3 sends these. The
// 0.2 schema holds `textReleaseThreshold` to 10 or more (VTI-VOT-065), and neither carries a
// credential roll (VTI-VOT-025).
#[allow(deprecated)]
use vti_specs::vtc::elections::{
    create::v0_3 as create_0_3, create::v0_4 as create_0_4, list::v0_3 as list_0_3,
    show::v0_2 as show_0_2, show::v0_3 as show_0_3, tickets::issue::v0_1 as issue_0_1,
};

use super::helpers::{
    TrustTaskOutcome, app_error_to_reject, extended_code, reject_with, reject_with_code,
    success_response,
};
use super::{JoinAuthCtx, admin_signer, capable_signer, parse_spec_payload};
use crate::acl::{Capability, get_acl_entry};
use crate::elections::ops::{self, CertifyError, CreateError, EndError, IssueError, TicketAsk};
use crate::elections::presentation::{self, Outcome};
use crate::elections::store::{self, ElectionRecord};
use crate::error::AppError;
use crate::server::AppState;

pub(crate) const CREATE_TYPE: &str = <create::Payload as Payload>::TYPE_URI;
#[allow(deprecated)] // superseded by create/0.5, and still served
pub(crate) const CREATE_0_4_TYPE: &str = <create_0_4::Payload as Payload>::TYPE_URI;
#[allow(deprecated)] // superseded by create/0.5, and still served
pub(crate) const CREATE_0_3_TYPE: &str = <create_0_3::Payload as Payload>::TYPE_URI;
pub(crate) const LIST_TYPE: &str = <list::Payload as Payload>::TYPE_URI;
#[allow(deprecated)] // superseded by list/0.5, and still served
pub(crate) const LIST_0_3_TYPE: &str = <list_0_3::Payload as Payload>::TYPE_URI;
pub(crate) const SHOW_TYPE: &str = <show::Payload as Payload>::TYPE_URI;
#[allow(deprecated)] // superseded by show/0.6, and still served
pub(crate) const SHOW_0_3_TYPE: &str = <show_0_3::Payload as Payload>::TYPE_URI;
#[allow(deprecated)] // superseded by show/0.6, and still served
pub(crate) const SHOW_0_2_TYPE: &str = <show_0_2::Payload as Payload>::TYPE_URI;
pub(crate) const CLOSE_TYPE: &str = <close::Payload as Payload>::TYPE_URI;
pub(crate) const CANCEL_TYPE: &str = <cancel::Payload as Payload>::TYPE_URI;
pub(crate) const ISSUE_TYPE: &str = <issue::Payload as Payload>::TYPE_URI;
#[allow(deprecated)] // superseded by tickets/issue/0.3, and still served
pub(crate) const ISSUE_0_1_TYPE: &str = <issue_0_1::Payload as Payload>::TYPE_URI;
pub(crate) const CERTIFY_TYPE: &str = <certify::Payload as Payload>::TYPE_URI;
pub(crate) const BALLOT_BOXES_LIST_TYPE: &str = <ballot_boxes_list::Payload as Payload>::TYPE_URI;
pub(crate) const TOMBSTONE_SHOW_TYPE: &str = <tombstone_show::Payload as Payload>::TYPE_URI;
pub(crate) const TOMBSTONE_ERR_ELECTION_UNKNOWN: &str =
    tombstone_show::error_codes::ELECTION_UNKNOWN.code;

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
pub(crate) const CREATE_ERR_ROLL_UNTRUSTED: &str = create::error_codes::ROLL_UNTRUSTED.code;
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
pub(crate) const ISSUE_ERR_PRESENTATION_REQUIRED: &str =
    issue::error_codes::PRESENTATION_REQUIRED.code;
pub(crate) const ISSUE_ERR_MEMBERSHIP_NOT_PROVEN: &str =
    issue::error_codes::MEMBERSHIP_NOT_PROVEN.code;
pub(crate) const ISSUE_ERR_MEMBERSHIP_REVOKED: &str = issue::error_codes::MEMBERSHIP_REVOKED.code;
pub(crate) const ISSUE_ERR_ROLL_UNTRUSTED: &str = issue::error_codes::ROLL_UNTRUSTED.code;
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
    CREATE_0_4_TYPE,
    CREATE_0_3_TYPE,
    LIST_TYPE,
    LIST_0_3_TYPE,
    SHOW_TYPE,
    SHOW_0_3_TYPE,
    SHOW_0_2_TYPE,
    CLOSE_TYPE,
    CANCEL_TYPE,
    ISSUE_TYPE,
    ISSUE_0_1_TYPE,
    CERTIFY_TYPE,
    BALLOT_BOXES_LIST_TYPE,
    TOMBSTONE_SHOW_TYPE,
];

/// Route one of [`URIS`]; `None` for any other URI.
pub(super) async fn dispatch(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
    type_uri: &str,
) -> Option<TrustTaskOutcome> {
    Some(match type_uri {
        CREATE_TYPE => handle_create(state, ctx, doc, Shared::V0_4).await,
        CREATE_0_4_TYPE => handle_create(state, ctx, doc, Shared::V0_3).await,
        CREATE_0_3_TYPE => handle_create(state, ctx, doc, Shared::V0_2).await,
        LIST_TYPE => handle_list(state, ctx, doc, false).await,
        LIST_0_3_TYPE => handle_list(state, ctx, doc, true).await,
        SHOW_TYPE => handle_show(state, ctx, doc, Shared::V0_4).await,
        SHOW_0_3_TYPE => handle_show(state, ctx, doc, Shared::V0_3).await,
        SHOW_0_2_TYPE => handle_show(state, ctx, doc, Shared::V0_2).await,
        CLOSE_TYPE => handle_close(state, ctx, doc).await,
        CANCEL_TYPE => handle_cancel(state, ctx, doc).await,
        ISSUE_TYPE => handle_issue(state, ctx, doc, true).await,
        ISSUE_0_1_TYPE => handle_issue(state, ctx, doc, false).await,
        CERTIFY_TYPE => handle_certify(state, ctx, doc).await,
        BALLOT_BOXES_LIST_TYPE => handle_ballot_boxes_list(state, ctx, doc).await,
        TOMBSTONE_SHOW_TYPE => handle_tombstone_show(state, ctx, doc).await,
        _ => return None,
    })
}

/// Which voting/_shared manifest a `create` or `show` request's version carries: 0.2 (create
/// 0.3, show 0.2), whose `textReleaseThreshold` is 10 or more; 0.3 (create 0.4, show 0.3),
/// whose threshold may be as low as 1 (VTI-VOT-065); or 0.4 (create 0.5, show 0.6), which adds
/// the credential roll (VTI-VOT-025). The manifest is otherwise the same, so one election
/// serves every version that can carry it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Shared {
    V0_2,
    V0_3,
    V0_4,
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

/// The proven signer itself, and whether it manages elections — never an administrator a
/// console key acts for. A ticket is the signer's one ticket (VTI-VOT-022; CONVENTIONS §4: the
/// proven signer is eligible), so a console session cannot spend its administrator's.
async fn own_signer(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: &TrustTask<Value>,
) -> Result<(String, bool), TrustTaskOutcome> {
    let signer = ctx
        .verified_signer
        .clone()
        .ok_or_else(|| reject_with(doc, RejectReason::ProofRequired))?;
    match get_acl_entry(&state.acl_ks, &signer).await {
        Ok(entry) => {
            let manager = entry.is_some_and(|e| e.can(Capability::ElectionsManage, None));
            Ok((signer, manager))
        }
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
        roll_member_of: None,
        reason: None,
        head_tree_size: None,
        head_root_hash: None,
        result_digest: None,
        attestation_issuers: Vec::new(),
    }
}

// ─── trusted ballot boxes ────────────────────────────────────────────────

/// `vtc/elections/ballot-boxes/list/0.1`: the trusted ballot boxes (VTI-VOT-082), read from the
/// live configuration — the same list `create` checks `ballotBox` against (item 2) — each with
/// what an election naming it discloses (item 3, as [`ops::disclosure`] does).
async fn handle_ballot_boxes_list(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    // Item 1.
    if let Err(reject) = capable_signer(state, ctx, &doc, Capability::ElectionsManage, None).await {
        return reject;
    }
    if let Err(reject) = parse_spec_payload::<ballot_boxes_list::Payload>(&doc) {
        return reject;
    }
    success_response(&doc, ballot_boxes_answer(&state.config.read().await.voting))
}

/// The answer to `ballot-boxes/list`: every trusted ballot box, in configuration order, and an
/// empty list when there are none (items 2 – 4).
fn ballot_boxes_answer(voting: &crate::elections::VotingConfig) -> Value {
    let boxes: Vec<Value> = voting
        .trusted_ballot_boxes
        .iter()
        .map(|b| {
            json!({
                "did": b.did,
                "operator": b.operator,
                "sameOperator": b.same_operator,
            })
        })
        .collect();
    json!({ "ballotBoxes": boxes })
}

// ─── create ──────────────────────────────────────────────────────────────

/// `vtc/elections/create/0.4` (items 1 – 10), and 0.3: the same task over a manifest whose
/// `textReleaseThreshold` its schema holds to 10 or more. Each request is held to its own
/// version's schema; nothing else differs.
async fn handle_create(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
    shared: Shared,
) -> TrustTaskOutcome {
    // Item 1.
    let actor = match capable_signer(state, ctx, &doc, Capability::ElectionsManage, None).await {
        Ok(a) => a,
        Err(reject) => return reject,
    };
    let parsed = match shared {
        Shared::V0_4 => parse_spec_payload::<create::Payload>(&doc).map(drop),
        #[allow(deprecated)]
        Shared::V0_3 => parse_spec_payload::<create_0_4::Payload>(&doc).map(drop),
        #[allow(deprecated)]
        Shared::V0_2 => parse_spec_payload::<create_0_3::Payload>(&doc).map(drop),
    };
    if let Err(reject) = parsed {
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
            CreateError::RollUntrusted => reject_with_code(
                &doc,
                extended_code(CREATE_ERR_ROLL_UNTRUSTED),
                "the roll's memberOf is not this community, one of its groups, or a party that \
                 is itself an active member of this community holding its membership credential \
                 (VTI-VOT-026); recognition through a trust registry is not membership",
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
    let roll_member_of = checked
        .manifest
        .roll
        .member_of
        .as_ref()
        .map(|d| d.as_str().to_string());

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
                        roll_member_of: roll_member_of.clone(),
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
            roll_member_of,
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

/// `vtc/elections/list/0.5` (items 1 – 6), and 0.3, whose payload is the same. Both list an
/// election only to a caller who may see it without a presentation: an election put to a member
/// party's members is listed to managers and the party itself alone, never as a stub
/// (VTI-VOT-015). A list carries no presentation; its schema has no member for one (item 5).
async fn handle_list(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
    v0_3: bool,
) -> TrustTaskOutcome {
    let (who, manager) = match caller(state, ctx, &doc).await {
        Ok(c) => c,
        Err(reject) => return reject,
    };
    let parsed = if v0_3 {
        #[allow(deprecated)]
        parse_spec_payload::<list_0_3::Payload>(&doc).map(drop)
    } else {
        parse_spec_payload::<list::Payload>(&doc).map(drop)
    };
    if let Err(reject) = parsed {
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
    // The reference order: votingOpensAt, most recent first.
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
            "votingOpensAt": rfc3339(rec.voting_opens),
            "votingClosesAt": rfc3339(rec.voting_closes),
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
        body["nextCursor"] = json!(cursor_for(&who, filter, offset + limit));
    }
    success_response(&doc, body)
}

fn rfc3339(t: DateTime<Utc>) -> String {
    t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

// ─── show ────────────────────────────────────────────────────────────────

/// How long a read's presentation is accepted after the read's `issuedAt`, and how far ahead of
/// this clock an `issuedAt` may be (show/0.6 Conformance item 8.1).
const PRESENTATION_WINDOW: chrono::Duration = chrono::Duration::minutes(10);
const PRESENTATION_SKEW: chrono::Duration = chrono::Duration::minutes(1);

/// The framework's `indeterminate` (SPEC §8.3, retryable): a presentation's check needed a
/// reference that could not be obtained. Its `details` name only that reference's kind, never
/// anything of an election (VTI-VOT-018).
fn indeterminate(doc: &TrustTask<Value>, reference: &str) -> TrustTaskOutcome {
    reject_with_code(
        doc,
        "indeterminate"
            .parse()
            .expect("indeterminate is a standard code"),
        "the presented credential could not be checked now; send the same document again later",
        Some(json!({ "reference": reference })),
    )
}

/// `vtc/elections/show/0.6` (items 1 – 8), and 0.3 and 0.2, which carry no presentation and
/// whose manifests cannot carry what later ones can: an election under a credential roll is
/// refused `unsupportedVersion` under 0.3 and 0.2, naming 0.6, and one releasing text below 10
/// under 0.2, naming 0.3 — never answered in a shape the version forbids, and only to a caller
/// who may see it.
/// `tombstones/show/0.1` (items 1 – 4, VTI-BRD-009): what the community keeps of an election on a
/// deleted board, to an active member or an elections manager. No tombstone and an unreadable
/// one are the same `electionUnknown`.
async fn handle_tombstone_show(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let (who, manager) = match caller(state, ctx, &doc).await {
        Ok(c) => c,
        Err(reject) => return reject,
    };
    if let Err(reject) = parse_spec_payload::<tombstone_show::Payload>(&doc) {
        return reject;
    }
    // Item 1: a manager, or an active member.
    let reader = manager
        || match crate::member_portal::active::active_member(state, &who).await {
            Ok(m) => m.is_some(),
            Err(e) => return app_error_to_reject(&doc, &e),
        };
    let election_id = doc.payload["electionId"].as_str().unwrap_or_default();
    // Item 2: looked up only for a reader, so no one else learns whether it exists.
    let kept = if reader {
        match store::tombstone(state.elections.ks(), election_id).await {
            Ok(t) => t,
            Err(e) => return app_error_to_reject(&doc, &e),
        }
    } else {
        None
    };
    let Some(t) = kept else {
        return unknown(&doc, TOMBSTONE_ERR_ELECTION_UNKNOWN);
    };
    // Items 3 – 4: as kept; a tombstone holds nothing else.
    let stamp = |at: DateTime<Utc>| at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let mut body = json!({
        "electionId": t.election_id,
        "manifestDigest": t.manifest_digest,
        "ballotBox": t.ballot_box,
        "checkpoints": t.checkpoints,
        "deletedAt": stamp(t.deleted_at),
    });
    if let Some(at) = t.remove_at {
        body["removeAt"] = json!(stamp(at));
    }
    success_response(&doc, body)
}

async fn handle_show(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
    shared: Shared,
) -> TrustTaskOutcome {
    let (who, manager) = match caller(state, ctx, &doc).await {
        Ok(c) => c,
        Err(reject) => return reject,
    };
    let parsed = match shared {
        Shared::V0_4 => parse_spec_payload::<show::Payload>(&doc).map(drop),
        #[allow(deprecated)]
        Shared::V0_3 => parse_spec_payload::<show_0_3::Payload>(&doc).map(drop),
        #[allow(deprecated)]
        Shared::V0_2 => parse_spec_payload::<show_0_2::Payload>(&doc).map(drop),
    };
    if let Err(reject) = parsed {
        return reject;
    }
    let election_id = doc.payload["electionId"].as_str().unwrap_or_default();
    let now = Utc::now();
    let community = ops::community_did(state).await;

    // Item 8.1 – 8.2: a presentation in a signed, fresh document not already accepted is
    // checked before the election is looked up, on nothing but what it carries.
    let outcome = match doc.payload.get("presentation") {
        Some(p) if shared == Shared::V0_4 => {
            let fresh = doc
                .issued_at
                .is_some_and(|t| t <= now + PRESENTATION_SKEW && now - t <= PRESENTATION_WINDOW);
            let reused =
                match store::presentation_accepted(state.elections.ks(), &doc.id, now).await {
                    Ok(r) => r,
                    Err(e) => return app_error_to_reject(&doc, &e),
                };
            if fresh && !reused {
                let o = presentation::check(state, p, &doc.id, &community, &who, now).await;
                if let Outcome::Indeterminate { reference } = o {
                    return indeterminate(&doc, reference);
                }
                Some(o)
            } else {
                None
            }
        }
        _ => None,
    };

    let Some(rec) = (match store::get(state.elections.ks(), election_id).await {
        Ok(r) => r,
        Err(e) => return app_error_to_reject(&doc, &e),
    }) else {
        return unknown(&doc, SHOW_ERR_ELECTION_UNKNOWN);
    };
    // Item 1, and 8.3 – 8.5: one answer for every failure.
    let seen = match ops::may_see(state, &rec, &who, manager).await {
        Ok(true) => true,
        Ok(false) => match ops::presentation_admits(state, &rec, outcome.as_ref()).await {
            Ok(true) => {
                // Item 8.6: only the document's `id`, for the window.
                match store::accept_presentation(
                    state.elections.ks(),
                    &doc.id,
                    now + PRESENTATION_WINDOW,
                    now,
                )
                .await
                {
                    Ok(accepted) => accepted,
                    Err(e) => return app_error_to_reject(&doc, &e),
                }
            }
            Ok(false) => false,
            Err(e) => return app_error_to_reject(&doc, &e),
        },
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    if !seen {
        return unknown(&doc, SHOW_ERR_ELECTION_UNKNOWN);
    }
    // An election registered under voting/election/register/0.1 holds a manifest 0.2
    // cannot carry, and its digest binds the old member names: refused by name.
    if let Err(e) = vti_voting::rules::require_current_manifest(&rec.manifest) {
        return app_error_to_reject(&doc, &AppError::Conflict(e.to_string()));
    }
    // Only after the election is found and visible, so the refusal says nothing of one the
    // caller may not see.
    let unsupported = |message: &str| {
        reject_with_code(
            &doc,
            "unsupportedVersion"
                .parse()
                .expect("unsupportedVersion is a standard code"),
            message.to_string(),
            None,
        )
    };
    if shared != Shared::V0_4 && rec.roll_member_of().is_some() {
        return unsupported(
            "this election's roll is the holders of a membership credential, which this version \
             of vtc/elections/show cannot carry; read it with vtc/elections/show/0.6",
        );
    }
    if shared == Shared::V0_2
        && rec.manifest["textReleaseThreshold"]
            .as_u64()
            .is_some_and(|t| t < 10)
    {
        return unsupported(
            "this election releases written answers after fewer than 10 ballots, which \
             vtc/elections/show/0.2 cannot carry; read it with vtc/elections/show/0.3",
        );
    }
    let parameters = match ops::parameters(state).await {
        Ok(p) => p,
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    let mut body = json!({
        "manifest": rec.manifest,
        "manifestDigest": rec.manifest_digest,
        "state": rec.state(now),
        "parameters": parameters,
        "disclosure": ops::disclosure(state, &rec, manager).await,
        "checkpoints": rec.checkpoints,
    });
    // Item 4.
    if manager {
        body["ticketsIssued"] = json!(rec.tickets_issued);
    }
    // Item 6.
    if let Some(k) = &rec.election_key {
        body["electionKey"] = k.clone();
        if let Some(c) = &rec.ceremony {
            body["ceremony"] = c.clone();
        }
    }
    // Item 7.
    if let Some(c) = &rec.certified {
        body["certified"] = c.clone();
    }
    success_response(&doc, body)
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

/// `vtc/elections/tickets/issue/0.3` (items 1 – 12), and 0.1, which carries no presentation:
/// an election under a credential roll claimed at 0.1 is refused `unsupportedVersion` naming
/// 0.3, once the claimant may see it.
async fn handle_issue(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
    v0_3: bool,
) -> TrustTaskOutcome {
    let (who, manager) = match own_signer(state, ctx, &doc).await {
        Ok(c) => c,
        Err(reject) => return reject,
    };
    let parsed = if v0_3 {
        parse_spec_payload::<issue::Payload>(&doc).map(drop)
    } else {
        #[allow(deprecated)]
        parse_spec_payload::<issue_0_1::Payload>(&doc).map(drop)
    };
    if let Err(reject) = parsed {
        return reject;
    }
    let election_id = doc.payload["electionId"].as_str().unwrap_or_default();
    let doc_digest = match serde_json::to_vec(&doc) {
        Ok(bytes) => hex::encode(Sha256::digest(bytes)),
        Err(e) => return app_error_to_reject(&doc, &AppError::Internal(e.to_string())),
    };
    let now = Utc::now();
    let answered = |pre: String| {
        success_response(
            &doc,
            json!({
                "electionId": election_id,
                "label": format!("voter/{election_id}"),
                "preCredential": pre,
            }),
        )
    };
    // Item 1, before anything is fetched: a resend is answered with its first answer, whatever
    // a status list says now. It finds a record only for a signer who took this election's
    // ticket, so it tells nobody else anything.
    match store::ticket(state.elections.ks(), election_id, &who).await {
        Ok(Some(t)) if t.doc_id == doc.id && t.doc_digest == doc_digest => {
            if let Some(pre) = t.pre_credential {
                return answered(pre);
            }
        }
        Ok(_) => {}
        Err(e) => return app_error_to_reject(&doc, &e),
    }
    // Item 2 (VTI-VOT-018): the presentation, before the election is looked up and without
    // reference to it. An outage is `indeterminate`, identically whatever `electionId` names,
    // and nothing is recorded.
    let outcome = match doc.payload.get("presentation") {
        Some(p) => {
            let community = ops::community_did(state).await;
            let o = presentation::check(state, p, &doc.id, &community, &who, now).await;
            if let Outcome::Indeterminate { reference } = o {
                return indeterminate(&doc, reference);
            }
            Some(o)
        }
        None => None,
    };
    let ask = TicketAsk {
        signer: &who,
        manager,
        election_id,
        manifest_digest: doc.payload["manifestDigest"].as_str().unwrap_or_default(),
        request: &doc.payload["request"],
        doc_id: &doc.id,
        doc_digest: &doc_digest,
        presentation: outcome.as_ref(),
        carries_presentation: v0_3,
    };
    let declared = |code: &str, message: &str, details: Option<Value>| {
        reject_with_code(&doc, extended_code(code), message.to_string(), details)
    };
    // `presentation` is discarded with `outcome` when this returns (item 11, VTI-CRD-042).
    match ops::issue_ticket(state, ask, now).await {
        Ok(issued) => {
            // Item 12: the signer, the election, the time and, under a credential roll, the
            // credential's issuer — nothing derived from the request or the presentation.
            if !issued.resend {
                audit(
                    state,
                    &ops::community_did(state).await,
                    Some(&who),
                    AuditEvent::ElectionTicketIssued(ElectionTicketIssuedData {
                        election_id: election_id.to_string(),
                        credential_issuer: issued.credential_issuer,
                    }),
                )
                .await;
            }
            answered(issued.pre_credential)
        }
        Err(IssueError::ElectionUnknown) => unknown(&doc, ISSUE_ERR_ELECTION_UNKNOWN),
        // Item 3: a caller without the capability learns nothing of an election not theirs.
        Err(IssueError::NotEligible) if !manager => unknown(&doc, ISSUE_ERR_ELECTION_UNKNOWN),
        Err(IssueError::NotEligible | IssueError::NotEligibleSeen) => declared(
            ISSUE_ERR_NOT_ELIGIBLE,
            "the election's roll does not admit this signer",
            None,
        ),
        Err(IssueError::NotOpen) => declared(
            ISSUE_ERR_NOT_OPEN,
            "tickets for this election are not being issued now",
            None,
        ),
        Err(IssueError::ManifestMismatch) => declared(
            ISSUE_ERR_MANIFEST_MISMATCH,
            "the manifest digest is not the registered manifest's; read the election again",
            None,
        ),
        Err(IssueError::AlreadyIssued) => declared(
            ISSUE_ERR_ALREADY_ISSUED,
            "this signer has already taken its ticket for this election",
            None,
        ),
        Err(IssueError::RequestInvalid(why)) => declared(
            ISSUE_ERR_REQUEST_INVALID,
            &format!("the ticket request is not valid for this election: {why}"),
            None,
        ),
        Err(IssueError::PresentationUnexpected) => reject_with(
            &doc,
            RejectReason::MalformedRequest {
                reason: "this election's roll takes no presentation".into(),
            },
        ),
        Err(IssueError::PresentationRequired) => declared(
            ISSUE_ERR_PRESENTATION_REQUIRED,
            "this election's roll is the holders of a membership credential; present it with \
             the request",
            None,
        ),
        Err(IssueError::RollUntrusted) => declared(
            ISSUE_ERR_ROLL_UNTRUSTED,
            "the party this election's roll names is no longer one this community trusts for it",
            None,
        ),
        Err(IssueError::MembershipNotProven(reason)) => declared(
            ISSUE_ERR_MEMBERSHIP_NOT_PROVEN,
            "the presentation does not prove a membership credential for the party the roll \
             names, held by the signer, valid now",
            Some(json!({ "reason": reason })),
        ),
        Err(IssueError::MembershipRevoked) => declared(
            ISSUE_ERR_MEMBERSHIP_REVOKED,
            "the presented membership credential is revoked or suspended",
            None,
        ),
        Err(IssueError::UnsupportedVersion) => reject_with_code(
            &doc,
            "unsupportedVersion"
                .parse()
                .expect("unsupportedVersion is a standard code"),
            "this election's roll is the holders of a membership credential, presented with the \
             claim; claim with vtc/elections/tickets/issue/0.3",
            None,
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
