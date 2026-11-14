//! Opening an idea's election (VTI-BRD-031) and reading its result for a selection
//! (VTI-BRD-040), through the election module's own paths — never a second registrar.

use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use vtc_audit::{AuditEvent, ElectionChangedData};
use vti_common::error::AppError;

use super::{Board, BoardAudience, Idea, election_id_for};
use crate::elections::ops::{self as eops, CreateError};
use crate::server::AppState;

fn stamp(t: DateTime<Utc>) -> String {
    t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// Why an idea's election could not be opened.
#[derive(Debug)]
pub enum OpenError {
    /// The community or the ballot box refused it: the code to show the facilitator.
    Refused {
        code: String,
        message: String,
    },
    /// Another accept of the same idea created its election first: answered with the idea as it
    /// stands, never as a refusal of an election that exists.
    AlreadyOpening,
    App(AppError),
}

impl From<AppError> for OpenError {
    fn from(e: AppError) -> Self {
        Self::App(e)
    }
}

/// The manifest an idea's election registers (`ElectionTemplate`): the board's template,
/// completed with the members the community fills in per idea.
///
/// # Errors
/// The audience's group cannot be read, or no longer exists.
pub async fn manifest_for(
    state: &AppState,
    board: &Board,
    idea: &Idea,
    now: DateTime<Utc>,
) -> Result<Value, OpenError> {
    let mut m = board.template.clone();
    let Some(obj) = m.as_object_mut() else {
        return Err(OpenError::Refused {
            code: "templateInvalid".into(),
            message: "the board's election template is not an object".into(),
        });
    };
    let roll = match &board.audience {
        BoardAudience::Members => json!({ "rule": "members" }),
        BoardAudience::Group { group_id } => {
            let group = crate::groups::get(state.directory.ks(), group_id)
                .await?
                .ok_or_else(|| OpenError::Refused {
                    code: "groupNotFound".into(),
                    message: "the board's audience names a group that no longer exists".into(),
                })?;
            json!({ "rule": "credential", "memberOf": group.group_did })
        }
    };
    let opens = board.voting.opens_at.max(now);
    // Tickets can be taken from the moment the idea is accepted, ahead of voting: taking a
    // ticket well before casting is what VTI-VOT-033 asks of a voter's agent.
    let registration = now.min(opens);
    obj.insert(
        "electionId".into(),
        json!(election_id_for(&board.board_id, &idea.idea_id)),
    );
    obj.insert("community".into(), json!(eops::community_did(state).await));
    obj.insert(
        "title".into(),
        json!(idea.title.clone().unwrap_or_default()),
    );
    if let Some(d) = &idea.description {
        obj.insert("description".into(), json!(d));
    }
    obj.insert("roll".into(), roll);
    obj.insert("registrationOpensAt".into(), json!(stamp(registration)));
    obj.insert("votingOpensAt".into(), json!(stamp(opens)));
    obj.insert(
        "votingClosesAt".into(),
        json!(stamp(board.voting.closes_at)),
    );
    // A board's elections are never binding, and always allow closing early, so closing the
    // board can end them — whatever a template stored before that rule stated (VTI-BRD-030,
    // VTI-BRD-006).
    obj.insert("binding".into(), json!(false));
    obj.insert("allowEarlyClose".into(), json!(true));
    Ok(m)
}

/// Whether `template` would make an election the community accepts, as it would be completed
/// for an idea accepted now: create item 3, the board checks VTI-BRD-030 holds.
///
/// # Errors
/// The refusal, as an `(code, message)` pair: `ballotBoxNotTrusted` or `templateInvalid`.
pub async fn check_template(
    state: &AppState,
    board: &Board,
    now: DateTime<Utc>,
) -> Result<(), (&'static str, String)> {
    // Closing the board ends its elections early (VTI-BRD-006), so a template must allow it.
    if board.template["allowEarlyClose"] == json!(false) {
        return Err((
            "templateInvalid",
            "a board's election template must allow closing early (allowEarlyClose: true), so \
             closing the board can end its elections (VTI-BRD-030)"
                .into(),
        ));
    }
    let probe = Idea {
        idea_id: "ida_template_check_000000".into(),
        board_id: board.board_id.clone(),
        state: super::StoredIdeaState::Proposed,
        title: Some("Template check".into()),
        description: None,
        format: None,
        topic: None,
        proposer: String::new(),
        proposed_at: now,
        election_id: None,
        accepted_at: None,
        refusal: None,
        decision: None,
    };
    let manifest = match manifest_for(state, board, &probe, now).await {
        Ok(m) => m,
        Err(OpenError::Refused { message, .. }) => return Err(("templateInvalid", message)),
        Err(OpenError::App(e)) => return Err(("templateInvalid", e.to_string())),
        // Forming a manifest creates no election, so nothing can have opened one.
        Err(OpenError::AlreadyOpening) => {
            return Err(("templateInvalid", "the template formed no manifest".into()));
        }
    };
    // The voting window may already have closed when a board is changed after the fact; the
    // template is still checked as for a window open now.
    let mut manifest = manifest;
    if board.voting.closes_at <= now {
        manifest["votingClosesAt"] = json!(stamp(now + chrono::Duration::hours(1)));
    }
    match eops::check_create(state, &manifest, now).await {
        Ok(_) | Err(CreateError::ElectionExists) => Ok(()),
        Err(CreateError::BallotBoxNotTrusted) => Err((
            "ballotBoxNotTrusted",
            "the template's ballot box is not one this community registers elections with".into(),
        )),
        Err(CreateError::InvalidManifest(why)) => Err(("templateInvalid", why)),
        Err(CreateError::UnsupportedSecrecy) => Err((
            "templateInvalid",
            "the template's secrecy level is not one this community runs".into(),
        )),
        Err(CreateError::RollUntrusted) => Err((
            "templateInvalid",
            "the board's audience cannot be put as a credential roll".into(),
        )),
        Err(CreateError::CommunityMismatch) => Err((
            "templateInvalid",
            "the template names another community".into(),
        )),
        Err(CreateError::BallotBoxRefused { message, .. }) => Err(("templateInvalid", message)),
        Err(CreateError::App(e)) => Err(("templateInvalid", e.to_string())),
    }
}

/// Open `idea`'s election from `board`'s template, as `requester` (VTI-BRD-031): checked and
/// created exactly as `vtc/elections/create` would, never parked (it is never binding). The
/// answer is the election's record as it then stands — registered, or pending with the
/// election sweeper owning its delivery.
///
/// # Errors
/// [`OpenError::Refused`] when the community or the ballot box refused it; the caller leaves
/// the idea `proposed`.
pub async fn open_election(
    state: &AppState,
    board: &Board,
    idea: &Idea,
    requester: &str,
    now: DateTime<Utc>,
) -> Result<crate::elections::store::ElectionRecord, OpenError> {
    let manifest = manifest_for(state, board, idea, now).await?;
    let refused = |code: &str, message: String| OpenError::Refused {
        code: code.to_string(),
        message,
    };
    let checked = match eops::check_create(state, &manifest, now).await {
        Ok(c) => c,
        Err(CreateError::App(e)) => return Err(OpenError::App(e)),
        Err(CreateError::InvalidManifest(why)) => return Err(refused("invalidManifest", why)),
        Err(CreateError::UnsupportedSecrecy) => {
            return Err(refused(
                "unsupportedSecrecy",
                "the template's secrecy level is not one this community runs".into(),
            ));
        }
        Err(CreateError::CommunityMismatch) => {
            return Err(refused(
                "communityMismatch",
                "the manifest names another community".into(),
            ));
        }
        Err(CreateError::BallotBoxNotTrusted) => {
            return Err(refused(
                "ballotBoxNotTrusted",
                "the template's ballot box is no longer one this community trusts".into(),
            ));
        }
        Err(CreateError::RollUntrusted) => {
            return Err(refused(
                "rollUntrusted",
                "the board's audience group cannot be put as a credential roll".into(),
            ));
        }
        Err(CreateError::ElectionExists) => return Err(OpenError::AlreadyOpening),
        Err(CreateError::BallotBoxRefused { code, message }) => {
            return Err(refused(&code, message));
        }
    };
    let roll_member_of = manifest["roll"]["memberOf"].as_str().map(str::to_string);
    let rec = match eops::create(state, requester, &manifest, checked, None, now).await {
        Ok(r) => r,
        Err(CreateError::App(e)) => return Err(OpenError::App(e)),
        Err(CreateError::BallotBoxRefused { code, message }) => {
            return Err(refused(&code, message));
        }
        Err(CreateError::ElectionExists) => return Err(OpenError::AlreadyOpening),
        Err(e) => return Err(refused("invalidManifest", format!("{e:?}"))),
    };
    // The election's own audit row (VTI-VOT-100), as `vtc/elections/create` writes it.
    if let Some(writer) = state.audit_writer.as_ref() {
        let event = AuditEvent::ElectionChanged(ElectionChangedData {
            election_id: rec.election_id.clone(),
            change: "created".into(),
            manifest_digest: Some(rec.manifest_digest.clone()),
            binding: Some(false),
            action_id: None,
            ballot_box_answer: Some(
                if rec.is_registered() {
                    "success"
                } else {
                    "pending"
                }
                .into(),
            ),
            roll_member_of,
            reason: None,
            head_tree_size: None,
            head_root_hash: None,
            result_digest: None,
            attestation_issuers: Vec::new(),
        });
        writer.write(requester, None, event).await?;
    }
    Ok(rec)
}

/// The result a selection is made with (VTI-BRD-040): the certified one, or one the community
/// verified from the board and keeps uncertified. `(result, certified)`.
///
/// # Errors
/// `Ok(None)` when no result has been published yet; an error when the board does not verify
/// or the ballot box cannot be reached.
pub async fn result_for(
    state: &AppState,
    election_id: &str,
    now: DateTime<Utc>,
) -> Result<Option<(Value, bool)>, String> {
    let rec = crate::elections::store::get(state.elections.ks(), election_id)
        .await
        .map_err(|e| e.to_string())?;
    let Some(rec) = rec else {
        return Ok(None);
    };
    if let Some(c) = &rec.certified {
        return Ok(Some((c["result"].clone(), true)));
    }
    match eops::verify_and_keep(state, election_id, now).await {
        Ok(result) => Ok(Some((result, false))),
        Err(eops::CertifyError::NotTallied | eops::CertifyError::ElectionUnknown) => Ok(None),
        Err(e) => Err(format!("{e:?}")),
    }
}

/// How closing a board ended its voting (VTI-BRD-006): the update's `closing` answer.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Closing {
    /// Elections open for voting asked to close early.
    pub closed_early: u32,
    /// Elections not yet open for voting asked to be cancelled.
    pub cancelled: u32,
    /// Ideas whose election cannot close early and closes when its manifest says.
    pub running_to_close: Vec<String>,
}

impl Closing {
    /// The `closing` member of `vtc/boards/update/0.1`'s response.
    #[must_use]
    pub fn wire(&self) -> Value {
        json!({
            "closedEarly": self.closed_early,
            "cancelled": self.cancelled,
            "runningToClose": self.running_to_close,
        })
    }
}

/// End the voting on a board that has just been recorded closed (VTI-BRD-006): each idea's
/// election open for voting that allows it is closed early, so its count is final; each not yet
/// open for voting, or not yet registered, is cancelled; each that cannot close early is left to
/// close when its manifest says. Every request is recorded on its election before the ballot box
/// is asked, and the elections sweeper asks again until it answers; this never waits for that.
/// Call it after the board is stored and without the board lock held (R1.3).
///
/// # Errors
/// A store failure.
pub async fn end_voting(
    state: &AppState,
    board: &Board,
    now: DateTime<Utc>,
) -> Result<Closing, AppError> {
    use crate::elections::store::{self as estore, EndKind};
    let mut out = Closing::default();
    let mut asked = Vec::new();
    let reason = format!("board {} closed", board.board_id);
    for idea in super::ideas_of(&state.boards_ks, &board.board_id).await? {
        let Some(id) = idea.election_id.as_deref() else {
            continue;
        };
        let Some(rec) = estore::get(state.elections.ks(), id).await? else {
            continue;
        };
        let kind = match rec.state(now) {
            "closed" | "tallied" | "cancelled" => continue,
            "voting" if rec.manifest["allowEarlyClose"].as_bool().unwrap_or(false) => {
                EndKind::Close
            }
            "voting" => {
                out.running_to_close.push(idea.idea_id.clone());
                continue;
            }
            // Registration open, registered ahead of voting, or not yet registered.
            _ => EndKind::Cancel,
        };
        if eops::record_end(state, id, kind, &reason, now).await? {
            match kind {
                EndKind::Close => out.closed_early += 1,
                EndKind::Cancel => out.cancelled += 1,
            }
            asked.push((id.to_string(), kind));
        }
    }
    // Ask now rather than at the sweeper's next pass, but never make the facilitator's request
    // wait on the ballot box: each end is recorded, and the sweeper asks again if this does not
    // get an answer.
    if !asked.is_empty() {
        let state = state.clone();
        tokio::spawn(async move {
            for (id, kind) in asked {
                if let Err(e) = eops::request_end(&state, &id, kind, &reason, Utc::now()).await {
                    tracing::warn!(election = %id, error = %e, "could not ask the ballot box to end a closed board's election; the sweeper will");
                }
            }
        });
    }
    Ok(out)
}
