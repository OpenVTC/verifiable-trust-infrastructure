//! Opening an idea's election (VTI-BRD-031) and reading its result for a selection
//! (VTI-BRD-040), through the election module's own paths — never a second registrar.

use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use vti_common::audit::{AuditEvent, ElectionChangedData};
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
    // A board's elections are never binding (VTI-BRD-030).
    obj.insert("binding".into(), json!(false));
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
        Err(CreateError::ElectionExists) => {
            return Err(refused(
                "electionExists",
                "an election already holds this idea's identifier".into(),
            ));
        }
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
        Err(CreateError::ElectionExists) => {
            return Err(refused(
                "electionExists",
                "an election already holds this idea's identifier".into(),
            ));
        }
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
