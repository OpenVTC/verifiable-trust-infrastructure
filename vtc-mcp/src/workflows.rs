//! The workflow tools and the action-list tools.
//!
//! A workflow tool is a **thin orchestrator**: it sends the tasks of one of
//! the workflows the prompts describe, in order, each through the same
//! guard and recorder as a `vtc_call` and under its own Trust Task URI — so
//! `--read-only`, `--deny` and `--confirm` apply to every step exactly as
//! they would to the assistant sending it by hand — and it **stops at the
//! first step that does not complete**: a refusal, a parked write, or a step
//! the local policy refused or the operator declined. What it returns is how
//! far it got, step by step, with each step's answer, so the assistant can
//! carry on from there with `vtc_call` or `vtc_actions_show`.
//!
//! Nothing here builds a payload the specification does not describe: a
//! workflow takes the create payload as the task's own JSON and derives only
//! the identifiers later steps need (`groupId`, `boardId`, `roomId`,
//! `electionId`, `badgeId`, a picture's digest) from the answers it received.
//!
//! The action-list tools follow and decide a parked operation. Deciding is
//! this identity **vouching** for someone else's authority, so
//! `vtc_actions_decide` always puts the verified summary and the match code
//! in front of the human through the host, whatever `--confirm` says, and
//! refuses when it cannot.

use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::CallToolResult;
use rmcp::service::Peer;
use rmcp::{ErrorData as McpError, RoleServer, tool, tool_router};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::server::{VtcMcp, outcome};

/// The Trust Task URIs the workflows send. Every one is held to the pinned
/// index by `every_workflow_uri_is_pinned`.
pub(crate) mod wire {
    pub const GROUPS_CREATE: &str = "https://trusttasks.org/spec/vtc/groups/create/0.1";
    pub const GROUPS_MANAGERS_ADD: &str = "https://trusttasks.org/spec/vtc/groups/managers/add/0.1";
    pub const GROUPS_MEMBERS_ADD: &str = "https://trusttasks.org/spec/vtc/groups/members/add/0.1";
    pub const GROUPS_BINDINGS_ADD: &str = "https://trusttasks.org/spec/vtc/groups/bindings/add/0.1";
    pub const GROUPS_SHOW: &str = "https://trusttasks.org/spec/vtc/groups/show/0.1";
    pub const BALLOT_BOXES_LIST: &str =
        "https://trusttasks.org/spec/vtc/elections/ballot-boxes/list/0.1";
    pub const BOARDS_CREATE: &str = "https://trusttasks.org/spec/vtc/boards/create/0.1";
    pub const BOARDS_FACILITATORS_ADD: &str =
        "https://trusttasks.org/spec/vtc/boards/facilitators/add/0.1";
    pub const ELECTIONS_CREATE: &str = "https://trusttasks.org/spec/vtc/elections/create/0.5";
    pub const ELECTIONS_SHOW: &str = "https://trusttasks.org/spec/vtc/elections/show/0.6";
    pub const ROOMS_CREATE: &str = "https://trusttasks.org/spec/vtc/rooms/community/create/0.4";
    pub const ROOMS_MEMBERS_ADD: &str =
        "https://trusttasks.org/spec/vtc/rooms/community/members/add/0.2";
    pub const ROOMS_MEMBERS_LIST: &str =
        "https://trusttasks.org/spec/vtc/rooms/community/members/list/0.2";
    pub const MEMBERS_ADMIT: &str = "https://trusttasks.org/spec/vtc/members/admit/0.1";
    pub const MEMBERS_CREDENTIALS: &str = "https://trusttasks.org/spec/vtc/members/credentials/0.1";
    pub const BADGES_IMAGES_UPLOAD: &str =
        "https://trusttasks.org/spec/vtc/badges/images/upload/0.1";
    pub const BADGES_CREATE: &str = "https://trusttasks.org/spec/vtc/badges/create/0.1";
    pub const BADGES_AWARDS_OFFER: &str = "https://trusttasks.org/spec/vtc/badges/awards/offer/0.1";
    pub const BADGES_CLAIMS_CREATE: &str =
        "https://trusttasks.org/spec/vtc/badges/claims/create/0.1";
    pub const BADGES_SHOW: &str = "https://trusttasks.org/spec/vtc/badges/show/0.1";
    pub const ACL_SHOW: &str = "https://trusttasks.org/spec/acl/show/0.2";
    pub const ACL_GRANT: &str = "https://trusttasks.org/spec/acl/grant/0.2";
    pub const ACTIONS_LIST: &str = "https://trusttasks.org/spec/vtc/admin/actions/list/0.3";
    pub const ACTIONS_SHOW: &str = "https://trusttasks.org/spec/vtc/admin/actions/show/0.3";
    pub const ACTIONS_CANCEL: &str = "https://trusttasks.org/spec/vtc/admin/actions/cancel/0.3";
    pub const CONSENT_DECISION: &str = "https://trusttasks.org/spec/task-consent/decision/0.2";

    /// Every URI above, for the census.
    #[cfg(test)]
    pub const ALL: &[&str] = &[
        GROUPS_CREATE,
        GROUPS_MANAGERS_ADD,
        GROUPS_MEMBERS_ADD,
        GROUPS_BINDINGS_ADD,
        GROUPS_SHOW,
        BALLOT_BOXES_LIST,
        BOARDS_CREATE,
        BOARDS_FACILITATORS_ADD,
        ELECTIONS_CREATE,
        ELECTIONS_SHOW,
        ROOMS_CREATE,
        ROOMS_MEMBERS_ADD,
        ROOMS_MEMBERS_LIST,
        MEMBERS_ADMIT,
        MEMBERS_CREDENTIALS,
        BADGES_IMAGES_UPLOAD,
        BADGES_CREATE,
        BADGES_AWARDS_OFFER,
        BADGES_CLAIMS_CREATE,
        BADGES_SHOW,
        ACL_SHOW,
        ACL_GRANT,
        ACTIONS_LIST,
        ACTIONS_SHOW,
        ACTIONS_CANCEL,
        CONSENT_DECISION,
    ];
}

/// How one step ended.
enum StepEnd {
    /// The community answered; the answer.
    Done(Value),
    /// The community parked it; the parked result.
    Parked(Value),
    /// Refused — by the community, by the local policy, or by the operator.
    Stopped,
}

/// A workflow's progress: each step as it ended, then the outcome.
pub(crate) struct Progress {
    steps: Vec<Value>,
}

impl Progress {
    fn new() -> Self {
        Self { steps: Vec::new() }
    }

    fn record(&mut self, task: &str, status: &str, detail: Value) {
        self.steps.push(json!({
            "task": task,
            "status": status,
            "detail": detail,
        }));
    }

    /// The report: every step and how the whole workflow ended.
    fn finish(self, outcome: &str, extra: Value) -> Value {
        let mut report = json!({
            "outcome": outcome,
            "steps": self.steps,
        });
        if let Value::Object(map) = extra {
            for (k, v) in map {
                report[k] = v;
            }
        }
        report
    }
}

impl VtcMcp {
    /// Send one workflow step through the guard and recorder, under its own
    /// URI, and record how it ended.
    async fn step(
        &self,
        tool: &'static str,
        uri: &str,
        payload: Value,
        peer: Option<&Peer<RoleServer>>,
        progress: &mut Progress,
    ) -> StepEnd {
        let slug = vti_mcp_common::guard::slug_of(uri).unwrap_or(uri);
        let call = match self
            .begin(
                tool,
                Some(uri),
                json!({ "operation": uri, "payload": payload }),
                peer,
            )
            .await
        {
            Ok(call) => call,
            Err(refused) => {
                let (status, message) = match *refused {
                    Err(e) => ("refused-locally", e.message.to_string()),
                    Ok(_) => ("refused-locally", "refused".to_string()),
                };
                progress.record(slug, status, json!({ "error": message }));
                return StepEnd::Stopped;
            }
        };
        let result = self.call_operation(uri, payload).await;
        let end = match &result {
            Ok(value) if value["status"] == "parked" => {
                progress.record(slug, "parked", value.clone());
                StepEnd::Parked(value.clone())
            }
            // The person's own step-up is owed; the link is in the record, and
            // the workflow stops here like any other step that did not run.
            Ok(value) if value["status"] == "stepUpRequired" => {
                progress.record(slug, "stepUpRequired", value.clone());
                StepEnd::Stopped
            }
            Ok(value) => {
                progress.record(slug, "ok", value.clone());
                StepEnd::Done(value.clone())
            }
            Err(e) => {
                progress.record(slug, "refused", json!({ "error": e.message.to_string() }));
                StepEnd::Stopped
            }
        };
        // The step is recorded whatever it returned; the tool's own result is
        // the progress report, not this step's.
        let _ = call.finish(result);
        end
    }

    /// Run the whole workflow as one guarded tool call around its steps.
    async fn workflow<F, Fut>(
        &self,
        tool: &'static str,
        args: Value,
        peer: Peer<RoleServer>,
        run: F,
    ) -> Result<CallToolResult, McpError>
    where
        F: FnOnce(Peer<RoleServer>) -> Fut,
        Fut: std::future::Future<Output = Value>,
    {
        let call = match self.begin(tool, None, args, Some(&peer)).await {
            Ok(call) => call,
            Err(refused) => return *refused,
        };
        let report = run(peer).await;
        call.finish(Ok(report))
    }

    /// The group workflow: create, appoint managers, add bindings, add
    /// members, read back.
    pub(crate) async fn run_group_setup(
        &self,
        p: GroupSetupParams,
        peer: Option<&Peer<RoleServer>>,
    ) -> Value {
        const TOOL: &str = "group_setup";
        let mut progress = Progress::new();
        let reason = p
            .reason
            .clone()
            .or_else(|| p.create["reason"].as_str().map(str::to_string));
        let group = match self
            .step(TOOL, wire::GROUPS_CREATE, p.create, peer, &mut progress)
            .await
        {
            StepEnd::Done(v) => v,
            StepEnd::Parked(_) => return progress.finish("parked", json!({})),
            StepEnd::Stopped => return progress.finish("stopped", json!({})),
        };
        let Some(group_id) = group["group"]["groupId"].as_str().map(str::to_string) else {
            progress.record(
                "vtc/groups/create",
                "refused",
                json!({ "error": "the answer carries no group.groupId" }),
            );
            return progress.finish("stopped", json!({}));
        };
        let with_reason = |mut payload: Value| {
            if let Some(r) = &reason {
                payload["reason"] = json!(r);
            }
            payload
        };
        for entry_id in &p.managers {
            let payload = with_reason(json!({ "groupId": group_id, "entryId": entry_id }));
            match self
                .step(
                    TOOL,
                    wire::GROUPS_MANAGERS_ADD,
                    payload,
                    peer,
                    &mut progress,
                )
                .await
            {
                StepEnd::Done(_) => {}
                StepEnd::Parked(_) => {
                    return progress.finish("parked", json!({ "groupId": group_id }));
                }
                StepEnd::Stopped => {
                    return progress.finish("stopped", json!({ "groupId": group_id }));
                }
            }
        }
        for binding in &p.bindings {
            let payload = with_reason(json!({ "groupId": group_id, "binding": binding }));
            match self
                .step(
                    TOOL,
                    wire::GROUPS_BINDINGS_ADD,
                    payload,
                    peer,
                    &mut progress,
                )
                .await
            {
                StepEnd::Done(_) => {}
                StepEnd::Parked(_) => {
                    return progress.finish("parked", json!({ "groupId": group_id }));
                }
                StepEnd::Stopped => {
                    return progress.finish("stopped", json!({ "groupId": group_id }));
                }
            }
        }
        for entry_id in &p.members {
            let payload = with_reason(json!({ "groupId": group_id, "entryId": entry_id }));
            match self
                .step(TOOL, wire::GROUPS_MEMBERS_ADD, payload, peer, &mut progress)
                .await
            {
                StepEnd::Done(_) => {}
                StepEnd::Parked(_) => {
                    return progress.finish("parked", json!({ "groupId": group_id }));
                }
                StepEnd::Stopped => {
                    return progress.finish("stopped", json!({ "groupId": group_id }));
                }
            }
        }
        let outcome = match self
            .step(
                TOOL,
                wire::GROUPS_SHOW,
                json!({ "groupId": group_id }),
                peer,
                &mut progress,
            )
            .await
        {
            StepEnd::Done(_) => "completed",
            StepEnd::Parked(_) => "parked",
            StepEnd::Stopped => "stopped",
        };
        progress.finish(outcome, json!({ "groupId": group_id }))
    }

    /// Whether `ballot_box` is one the community trusts, read from the
    /// community itself; a refusal to list is recorded and stops the flow.
    async fn ballot_box_is_trusted(
        &self,
        tool: &'static str,
        ballot_box: Option<&str>,
        peer: Option<&Peer<RoleServer>>,
        progress: &mut Progress,
    ) -> Option<bool> {
        let listed = match self
            .step(tool, wire::BALLOT_BOXES_LIST, json!({}), peer, progress)
            .await
        {
            StepEnd::Done(v) => v,
            _ => return None,
        };
        let trusted = listed["ballotBoxes"]
            .as_array()
            .map(|boxes| {
                boxes
                    .iter()
                    .any(|b| b["did"].as_str().is_some() && b["did"].as_str() == ballot_box)
            })
            .unwrap_or(false);
        Some(trusted)
    }

    /// The board workflow: check the ballot box, create, appoint facilitators.
    pub(crate) async fn run_board_create(
        &self,
        p: BoardCreateParams,
        peer: Option<&Peer<RoleServer>>,
    ) -> Value {
        const TOOL: &str = "board_create";
        let mut progress = Progress::new();
        let ballot_box = p.create["template"]["ballotBox"]
            .as_str()
            .map(str::to_string);
        match self
            .ballot_box_is_trusted(TOOL, ballot_box.as_deref(), peer, &mut progress)
            .await
        {
            Some(true) => {}
            Some(false) => {
                progress.record(
                    "vtc/boards/create",
                    "refused-locally",
                    json!({
                        "error": format!(
                            "template.ballotBox {} is not one the community trusts; pick one \
                             from the ballot-boxes step",
                            ballot_box.as_deref().unwrap_or("(absent)")
                        )
                    }),
                );
                return progress.finish("stopped", json!({}));
            }
            None => return progress.finish("stopped", json!({})),
        }
        let board = match self
            .step(TOOL, wire::BOARDS_CREATE, p.create, peer, &mut progress)
            .await
        {
            StepEnd::Done(v) => v,
            StepEnd::Parked(_) => return progress.finish("parked", json!({})),
            StepEnd::Stopped => return progress.finish("stopped", json!({})),
        };
        let Some(board_id) = board["board"]["boardId"].as_str().map(str::to_string) else {
            progress.record(
                "vtc/boards/create",
                "refused",
                json!({ "error": "the answer carries no board.boardId" }),
            );
            return progress.finish("stopped", json!({}));
        };
        for entry_id in &p.facilitators {
            let mut payload = json!({ "boardId": board_id, "entryId": entry_id });
            if let Some(r) = &p.reason {
                payload["reason"] = json!(r);
            }
            match self
                .step(
                    TOOL,
                    wire::BOARDS_FACILITATORS_ADD,
                    payload,
                    peer,
                    &mut progress,
                )
                .await
            {
                StepEnd::Done(_) => {}
                StepEnd::Parked(_) => {
                    return progress.finish("parked", json!({ "boardId": board_id }));
                }
                StepEnd::Stopped => {
                    return progress.finish("stopped", json!({ "boardId": board_id }));
                }
            }
        }
        progress.finish("completed", json!({ "boardId": board_id }))
    }

    /// The election workflow: check the ballot box, create from the manifest,
    /// read the registrar's state back.
    pub(crate) async fn run_election_create(
        &self,
        p: ElectionCreateParams,
        peer: Option<&Peer<RoleServer>>,
    ) -> Value {
        const TOOL: &str = "election_create";
        let mut progress = Progress::new();
        let ballot_box = p.manifest["ballotBox"].as_str().map(str::to_string);
        match self
            .ballot_box_is_trusted(TOOL, ballot_box.as_deref(), peer, &mut progress)
            .await
        {
            Some(true) => {}
            Some(false) => {
                progress.record(
                    "vtc/elections/create",
                    "refused-locally",
                    json!({
                        "error": format!(
                            "manifest.ballotBox {} is not one the community trusts; pick one \
                             from the ballot-boxes step",
                            ballot_box.as_deref().unwrap_or("(absent)")
                        )
                    }),
                );
                return progress.finish("stopped", json!({}));
            }
            None => return progress.finish("stopped", json!({})),
        }
        let created = match self
            .step(
                TOOL,
                wire::ELECTIONS_CREATE,
                json!({ "manifest": p.manifest }),
                peer,
                &mut progress,
            )
            .await
        {
            StepEnd::Done(v) => v,
            // A binding election parks for another elections manager.
            StepEnd::Parked(_) => return progress.finish("parked", json!({})),
            StepEnd::Stopped => return progress.finish("stopped", json!({})),
        };
        let Some(election_id) = created["electionId"].as_str().map(str::to_string) else {
            progress.record(
                "vtc/elections/create",
                "refused",
                json!({ "error": "the answer carries no electionId" }),
            );
            return progress.finish("stopped", json!({}));
        };
        let outcome = match self
            .step(
                TOOL,
                wire::ELECTIONS_SHOW,
                json!({ "electionId": election_id }),
                peer,
                &mut progress,
            )
            .await
        {
            StepEnd::Done(_) => "completed",
            StepEnd::Parked(_) => "parked",
            StepEnd::Stopped => "stopped",
        };
        progress.finish(outcome, json!({ "electionId": election_id }))
    }

    /// The room workflow: create, offer each member admission, list members.
    pub(crate) async fn run_room_open(
        &self,
        p: RoomOpenParams,
        peer: Option<&Peer<RoleServer>>,
    ) -> Value {
        const TOOL: &str = "room_open";
        let mut progress = Progress::new();
        let created = match self
            .step(TOOL, wire::ROOMS_CREATE, p.create, peer, &mut progress)
            .await
        {
            StepEnd::Done(v) => v,
            StepEnd::Parked(_) => return progress.finish("parked", json!({})),
            StepEnd::Stopped => return progress.finish("stopped", json!({})),
        };
        let Some(room_id) = created["room"]["room"]["roomId"]
            .as_str()
            .map(str::to_string)
        else {
            progress.record(
                "vtc/rooms/community/create",
                "refused",
                json!({ "error": "the answer carries no room.room.roomId" }),
            );
            return progress.finish("stopped", json!({}));
        };
        for member in &p.members {
            let mut payload = member.clone();
            payload["roomId"] = json!(room_id);
            match self
                .step(TOOL, wire::ROOMS_MEMBERS_ADD, payload, peer, &mut progress)
                .await
            {
                StepEnd::Done(_) => {}
                StepEnd::Parked(_) => {
                    return progress.finish("parked", json!({ "roomId": room_id }));
                }
                StepEnd::Stopped => {
                    return progress.finish("stopped", json!({ "roomId": room_id }));
                }
            }
        }
        let outcome = match self
            .step(
                TOOL,
                wire::ROOMS_MEMBERS_LIST,
                json!({ "roomId": room_id }),
                peer,
                &mut progress,
            )
            .await
        {
            StepEnd::Done(_) => "completed",
            StepEnd::Parked(_) => "parked",
            StepEnd::Stopped => "stopped",
        };
        progress.finish(outcome, json!({ "roomId": room_id }))
    }

    /// The admission workflow: admit directly, then read what the member holds.
    pub(crate) async fn run_member_admit(
        &self,
        p: MemberAdmitParams,
        peer: Option<&Peer<RoleServer>>,
    ) -> Value {
        const TOOL: &str = "member_admit";
        let mut progress = Progress::new();
        let mut payload = json!({
            "subject": p.subject,
            "role": p.role.unwrap_or_else(|| "member".to_string()),
        });
        if let Some(label) = &p.label {
            payload["label"] = json!(label);
        }
        if let Some(reason) = &p.reason {
            payload["reason"] = json!(reason);
        }
        match self
            .step(TOOL, wire::MEMBERS_ADMIT, payload, peer, &mut progress)
            .await
        {
            StepEnd::Done(_) => {}
            // The community's admission policy referred it to a second
            // administrator.
            StepEnd::Parked(_) => return progress.finish("parked", json!({})),
            StepEnd::Stopped => return progress.finish("stopped", json!({})),
        }
        let outcome = match self
            .step(
                TOOL,
                wire::MEMBERS_CREDENTIALS,
                json!({ "did": p.subject }),
                peer,
                &mut progress,
            )
            .await
        {
            StepEnd::Done(_) => "completed",
            StepEnd::Parked(_) => "parked",
            StepEnd::Stopped => "stopped",
        };
        progress.finish(outcome, json!({ "subject": p.subject }))
    }

    /// The badge workflow: upload the picture, create the badge, offer it,
    /// issue a claim code, read it back. Only `create` is required; each
    /// later step runs when it was asked for.
    pub(crate) async fn run_badge_create(
        &self,
        p: BadgeCreateParams,
        peer: Option<&Peer<RoleServer>>,
    ) -> Value {
        const TOOL: &str = "badge_create";
        let mut progress = Progress::new();
        let mut create = p.create;
        if let Some(image) = p.image {
            let uploaded = match self
                .step(TOOL, wire::BADGES_IMAGES_UPLOAD, image, peer, &mut progress)
                .await
            {
                StepEnd::Done(v) => v,
                StepEnd::Parked(_) => return progress.finish("parked", json!({})),
                StepEnd::Stopped => return progress.finish("stopped", json!({})),
            };
            // The create names the picture by the digest the upload answered
            // to this signer: the community's own re-encoding (VTI-BDG-050).
            let Some(sha256) = uploaded["image"]["sha256"].as_str() else {
                progress.record(
                    "vtc/badges/images/upload",
                    "refused",
                    json!({ "error": "the answer carries no image.sha256" }),
                );
                return progress.finish("stopped", json!({}));
            };
            create["image"] = json!({ "sha256": sha256 });
        }
        let badge = match self
            .step(TOOL, wire::BADGES_CREATE, create, peer, &mut progress)
            .await
        {
            StepEnd::Done(v) => v,
            StepEnd::Parked(_) => return progress.finish("parked", json!({})),
            StepEnd::Stopped => return progress.finish("stopped", json!({})),
        };
        let Some(badge_id) = badge["badge"]["badgeId"].as_str().map(str::to_string) else {
            progress.record(
                "vtc/badges/create",
                "refused",
                json!({ "error": "the answer carries no badge.badgeId" }),
            );
            return progress.finish("stopped", json!({}));
        };
        let ids = || json!({ "badgeId": badge_id });
        if let Some(mut offer) = p.offer {
            offer["badgeId"] = json!(badge_id);
            match self
                .step(TOOL, wire::BADGES_AWARDS_OFFER, offer, peer, &mut progress)
                .await
            {
                StepEnd::Done(_) => {}
                StepEnd::Parked(_) => return progress.finish("parked", ids()),
                StepEnd::Stopped => return progress.finish("stopped", ids()),
            }
        }
        if let Some(mut claim) = p.claim_code {
            claim["badgeId"] = json!(badge_id);
            match self
                .step(TOOL, wire::BADGES_CLAIMS_CREATE, claim, peer, &mut progress)
                .await
            {
                StepEnd::Done(_) => {}
                StepEnd::Parked(_) => return progress.finish("parked", ids()),
                StepEnd::Stopped => return progress.finish("stopped", ids()),
            }
        }
        let outcome = match self
            .step(TOOL, wire::BADGES_SHOW, ids(), peer, &mut progress)
            .await
        {
            StepEnd::Done(_) => "completed",
            StepEnd::Parked(_) => "parked",
            StepEnd::Stopped => "stopped",
        };
        progress.finish(outcome, ids())
    }

    /// The grant workflow: read the subject's entry, grant, and when the grant
    /// parks, read the action it is waiting as.
    pub(crate) async fn run_admin_grant(
        &self,
        p: AdminGrantParams,
        peer: Option<&Peer<RoleServer>>,
    ) -> Value {
        const TOOL: &str = "admin_grant";
        let mut progress = Progress::new();
        let Some(subject) = p.entry["subject"].as_str().map(str::to_string) else {
            progress.record(
                "acl/grant",
                "refused-locally",
                json!({ "error": "entry.subject (the DID to grant to) is required" }),
            );
            return progress.finish("stopped", json!({}));
        };
        let shown = match self
            .step(
                TOOL,
                wire::ACL_SHOW,
                json!({ "subject": subject }),
                peer,
                &mut progress,
            )
            .await
        {
            StepEnd::Done(v) => v,
            _ => return progress.finish("stopped", json!({ "subject": subject })),
        };
        if !shown["entry"].is_null() {
            progress.record(
                "acl/grant",
                "refused-locally",
                json!({
                    "error": format!(
                        "{subject} already has an entry (role {}); change it with \
                         vtc/members/role/set, acl/update or acl/change-role rather than \
                         granting a second one",
                        shown["entry"]["role"].as_str().unwrap_or("?")
                    ),
                    "entry": shown["entry"],
                }),
            );
            return progress.finish("stopped", json!({ "subject": subject }));
        }
        let mut payload = json!({ "entry": p.entry });
        if let Some(reason) = &p.reason {
            payload["reason"] = json!(reason);
        }
        let parked = match self
            .step(TOOL, wire::ACL_GRANT, payload, peer, &mut progress)
            .await
        {
            StepEnd::Done(_) => {
                return progress.finish("completed", json!({ "subject": subject }));
            }
            StepEnd::Parked(v) => v,
            StepEnd::Stopped => return progress.finish("stopped", json!({ "subject": subject })),
        };
        // The grant is waiting for another administrator: read the action so
        // the report says who, and how many approvals remain.
        let action_id = parked["actionId"].as_str().map(str::to_string);
        if let Some(action_id) = &action_id {
            let _ = self
                .step(
                    TOOL,
                    wire::ACTIONS_SHOW,
                    json!({ "actionId": action_id }),
                    peer,
                    &mut progress,
                )
                .await;
        }
        progress.finish(
            "parked",
            json!({ "subject": subject, "actionId": action_id }),
        )
    }

    /// Decide a parked action as this identity, with the human's confirmation.
    pub(crate) async fn decide_action(
        &self,
        p: &ActionDecideParams,
        peer: Option<&Peer<RoleServer>>,
    ) -> Result<Value, McpError> {
        let client = self.client()?;
        // `show_action` answers the action itself, unwrapped.
        let action = outcome(client.show_action(&p.action_id).await)?;
        let verified = vtc_client::actions::verify_action(&action).map_err(|e| {
            McpError::internal_error(
                format!(
                    "refusing to decide {}: {e}. What the action says is not what would run; \
                     do not approve it.",
                    p.action_id
                ),
                None,
            )
        })?;
        let Some(decision) =
            vtc_client::actions::decision_for(&verified.action, p.approve, p.reason.as_deref())
                .map_err(|e| McpError::internal_error(e, None))?
        else {
            return Err(McpError::internal_error(
                format!(
                    "this identity cannot decide {} now: the action is not open, it is not \
                     waiting for this identity, or this identity has already decided it \
                     (it carries no challenge for this caller)",
                    p.action_id
                ),
                None,
            ));
        };
        let match_code = verified.action["payloadDigest"]
            .as_str()
            .and_then(|d| vta_sdk::task_consent::match_code(d).ok())
            .unwrap_or_else(|| "(none)".to_string());
        let fields: Vec<String> = verified
            .fields
            .iter()
            .map(|(name, value)| format!("{name}: {value}"))
            .collect();
        let prompt = format!(
            "{} {} parked action {}: \"{}\"{}. {} Requested by {}. Match code {}: approve only \
             if it is the code the requester shows you.",
            if p.approve { "Approve" } else { "Deny" },
            "the",
            p.action_id,
            verified.title,
            verified
                .effect
                .as_ref()
                .map(|e| format!(" — {e}"))
                .unwrap_or_default(),
            if fields.is_empty() {
                String::new()
            } else {
                format!("{}.", fields.join("; "))
            },
            verified.action["requester"].as_str().unwrap_or("?"),
            match_code,
        );
        // Always: this is the identity vouching for someone else's authority,
        // and the host's per-tool approval is not consent to that.
        let answer = match peer {
            Some(peer) => self.confirm(peer, &prompt).await,
            None => Err("no MCP host to ask".to_string()),
        };
        match answer {
            Ok(true) => {}
            Ok(false) => {
                return Err(McpError::invalid_request(
                    format!("{prompt} — declined by the operator; nothing was decided."),
                    None,
                ));
            }
            Err(reason) => {
                return Err(McpError::invalid_request(
                    format!(
                        "{prompt} — could not obtain the operator's confirmation ({reason}), so \
                         nothing was decided: a decision is never sent unconfirmed."
                    ),
                    None,
                ));
            }
        }
        let response = outcome(
            client
                .decide_action(&decision)
                .await
                .and_then(|r| serde_json::to_value(r).map_err(|e| VtcErrorShim::from(e).0)),
        )?;
        Ok(json!({
            "actionId": p.action_id,
            "decision": if p.approve { "approve" } else { "deny" },
            "verified": {
                "title": verified.title,
                "effect": verified.effect,
                "matchCode": match_code,
            },
            "response": response,
        }))
    }
}

/// A serialisation failure as the client's own error, so one `outcome`
/// mapping serves the typed answer too.
struct VtcErrorShim(vtc_client::VtcError);

impl From<serde_json::Error> for VtcErrorShim {
    fn from(e: serde_json::Error) -> Self {
        Self(vtc_client::VtcError::InvalidPayload(e.to_string()))
    }
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GroupSetupParams {
    /// The `vtc/groups/create` payload: `name`, `kind`, `visibility`,
    /// `showMembers`, `reason`, and optionally `joinPolicy`, `description`,
    /// `issuesCredentials`, `rule`. Read its schema with `vtc_list_operations`
    /// (detail `full`).
    pub create: Value,
    /// Directory entry ids of the members to appoint as managers.
    #[serde(default)]
    pub managers: Vec<String>,
    /// Directory entry ids of the first members to add (a `closed` group).
    #[serde(default)]
    pub members: Vec<String>,
    /// Bindings to add, each a `vtc/groups/bindings/add` `binding` object
    /// (`kind: room | grants | role`). A grants or role binding parks.
    #[serde(default)]
    pub bindings: Vec<Value>,
    /// The reason recorded on each appointment, binding and addition; the
    /// create payload's own `reason` when omitted.
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct BoardCreateParams {
    /// The `vtc/boards/create` payload: `title`, `audience`, `proposals` and
    /// `voting` windows, the election `template` (whose `ballotBox` must be
    /// one the community trusts), and the optional members. Read its schema
    /// with `vtc_list_operations` (detail `full`).
    pub create: Value,
    /// Directory entry ids of the members to appoint as facilitators.
    #[serde(default)]
    pub facilitators: Vec<String>,
    /// The reason recorded on each appointment.
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ElectionCreateParams {
    /// The election manifest (`vtc/elections/create`'s `manifest`): identifier,
    /// title, questions, `roll`, schedule, `secrecy`, `revote`, `ballotBox`,
    /// `binding`, … Read its schema with `vtc_list_operations` (detail `full`).
    /// `binding: true` parks for another elections manager.
    pub manifest: Value,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct RoomOpenParams {
    /// The `vtc/rooms/community/create` payload: `label`, `visibility`
    /// (`attributed` or `open`), `reason`, and optionally `description`,
    /// `tags`, `retentionPolicy`, `retentionDays`, `storageConfig`.
    pub create: Value,
    /// Members to offer admission, each a `vtc/rooms/community/members/add`
    /// payload without `roomId`: `member` (DID), `actions`, `validUntil`,
    /// `reason`.
    #[serde(default)]
    pub members: Vec<Value>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct MemberAdmitParams {
    /// The DID to admit.
    pub subject: String,
    /// The role to seat (default `member`). `admin` is never seated this way.
    #[serde(default)]
    pub role: Option<String>,
    /// A label for the entry.
    #[serde(default)]
    pub label: Option<String>,
    /// Why, recorded in the audit.
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct BadgeCreateParams {
    /// The `vtc/badges/create` payload: `kind` (`community` or `kudos`),
    /// `name`, `description`, `image`, `reason`, and optionally `criteria`,
    /// `owners`, `requestable`, `repeatable`, `automatic` (a rule),
    /// `shareableOutside`, `listed`, `holdersVisibleTo`. Read its schema with
    /// `vtc_list_operations` (detail `full`). When `image` below is given, the
    /// payload's own `image` is replaced by the uploaded picture's digest.
    pub create: Value,
    /// The picture to upload first, as a `vtc/badges/images/upload` payload:
    /// `mediaType` and base64 `data`.
    #[serde(default)]
    pub image: Option<Value>,
    /// Offer the new badge, as a `vtc/badges/awards/offer` payload without
    /// `badgeId`: `to` (directory entry ids) or `group`, and an optional
    /// `note`. Nothing is issued until each member accepts.
    #[serde(default)]
    pub offer: Option<Value>,
    /// Issue a claim code for an event, as a `vtc/badges/claims/create`
    /// payload without `badgeId`: `label`, `validUntil` (at most 90 days
    /// ahead) and `limit`. The code is in that step's answer, once.
    #[serde(default)]
    pub claim_code: Option<Value>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct AdminGrantParams {
    /// The `acl/grant` `entry`: `subject`, `role`, `act`, `capabilities`,
    /// `keys`, and optionally `approve`, `approveCapabilities`, `expiresAt`,
    /// `label`. Read its schema with `vtc_list_operations` (detail `full`).
    pub entry: Value,
    /// Why, shown to the approvers and recorded.
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ActionsListParams {
    /// `waitingForMe` (default), `requestedByMe`, `history` or `all`.
    #[serde(default)]
    pub view: Option<String>,
    /// The previous page's `nextCursor`.
    #[serde(default)]
    pub cursor: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ActionShowParams {
    /// The action id a parked result or the list named.
    pub action_id: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ActionDecideParams {
    /// The action id.
    pub action_id: String,
    /// `true` to approve, `false` to deny. One denial closes the action.
    pub approve: bool,
    /// A note recorded with the decision.
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ActionCancelParams {
    /// The action id; only its requester may cancel it.
    pub action_id: String,
    #[serde(default)]
    pub reason: Option<String>,
}

#[tool_router(router = workflow_router, vis = "pub(crate)")]
impl VtcMcp {
    #[tool(
        description = "Set up a community group end to end: create it from a \
                       `vtc/groups/create` payload, appoint managers, add bindings (a room, or \
                       grants / a role, which park), add the first members, and read it back. \
                       Each step goes through this bridge's policy under its own operation; \
                       the flow stops at the first step that is refused or parked and reports \
                       how far it got.",
        annotations(
            title = "Set up a group",
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = false,
            open_world_hint = false
        )
    )]
    async fn group_setup(
        &self,
        Parameters(p): Parameters<GroupSetupParams>,
        peer: Peer<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let args = json!({ "managers": p.managers.len(), "members": p.members.len(), "bindings": p.bindings.len() });
        self.workflow("group_setup", args, peer, |peer| async move {
            self.run_group_setup(p, Some(&peer)).await
        })
        .await
    }

    #[tool(
        description = "Create a community board end to end: check the template's ballot box \
                       is one the community trusts, create the board from a \
                       `vtc/boards/create` payload, and appoint its facilitators. Stops at the \
                       first refused step and reports how far it got.",
        annotations(
            title = "Create a board",
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = false,
            open_world_hint = false
        )
    )]
    async fn board_create(
        &self,
        Parameters(p): Parameters<BoardCreateParams>,
        peer: Peer<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let args = json!({ "facilitators": p.facilitators.len() });
        self.workflow("board_create", args, peer, |peer| async move {
            self.run_board_create(p, Some(&peer)).await
        })
        .await
    }

    #[tool(
        description = "Create an election, poll or survey: check the manifest's ballot box is \
                       one the community trusts, create it, and read the registrar's state \
                       back. A binding manifest parks for another elections manager; the \
                       report says so and names the action.",
        annotations(
            title = "Create an election",
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = false,
            open_world_hint = false
        )
    )]
    async fn election_create(
        &self,
        Parameters(p): Parameters<ElectionCreateParams>,
        peer: Peer<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let args =
            json!({ "electionId": p.manifest["electionId"], "binding": p.manifest["binding"] });
        self.workflow("election_create", args, peer, |peer| async move {
            self.run_election_create(p, Some(&peer)).await
        })
        .await
    }

    #[tool(
        description = "Open a community-owned data room end to end: create it from a \
                       `vtc/rooms/community/create` payload, offer each named member \
                       admission, and list who is offered. Stops at the first refused step and \
                       reports how far it got.",
        annotations(
            title = "Open a data room",
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = false,
            open_world_hint = false
        )
    )]
    async fn room_open(
        &self,
        Parameters(p): Parameters<RoomOpenParams>,
        peer: Peer<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let args = json!({ "members": p.members.len() });
        self.workflow("room_open", args, peer, |peer| async move {
            self.run_room_open(p, Some(&peer)).await
        })
        .await
    }

    #[tool(
        description = "Admit a member directly (`vtc/members/admit`) and read the credentials \
                       they now hold. The community's admission policy may refer it to a \
                       second administrator, in which case the report is parked and names the \
                       action.",
        annotations(
            title = "Admit a member",
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = false,
            open_world_hint = false
        )
    )]
    async fn member_admit(
        &self,
        Parameters(p): Parameters<MemberAdmitParams>,
        peer: Peer<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let args = json!({ "subject": p.subject, "role": p.role });
        self.workflow("member_admit", args, peer, |peer| async move {
            self.run_member_admit(p, Some(&peer)).await
        })
        .await
    }

    #[tool(
        description = "Create a member badge end to end: upload its picture \
                       (`vtc/badges/images/upload`), create it from a `vtc/badges/create` \
                       payload naming the uploaded digest, optionally offer it to members or \
                       a group and issue a claim code for an event (answered once, in that \
                       step), and read it back. Each step goes through this bridge's policy \
                       under its own operation; the flow stops at the first step that is \
                       refused and reports how far it got.",
        annotations(
            title = "Create a badge",
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = false,
            open_world_hint = false
        )
    )]
    async fn badge_create(
        &self,
        Parameters(p): Parameters<BadgeCreateParams>,
        peer: Peer<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let args = json!({
            "kind": p.create["kind"],
            "image": p.image.is_some(),
            "offer": p.offer.is_some(),
            "claimCode": p.claim_code.is_some(),
        });
        self.workflow("badge_create", args, peer, |peer| async move {
            self.run_badge_create(p, Some(&peer)).await
        })
        .await
    }

    #[tool(
        description = "Grant an entry administration: read the subject's current entry (and \
                       stop if one exists — change it instead), send `acl/grant`, and when the \
                       grant parks for other administrators, read the action it waits as so \
                       the report says who approves and how many approvals remain.",
        annotations(
            title = "Grant administration",
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = false,
            open_world_hint = false
        )
    )]
    async fn admin_grant(
        &self,
        Parameters(p): Parameters<AdminGrantParams>,
        peer: Peer<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let args = json!({ "subject": p.entry["subject"], "role": p.entry["role"] });
        self.workflow("admin_grant", args, peer, |peer| async move {
            self.run_admin_grant(p, Some(&peer)).await
        })
        .await
    }

    #[tool(
        description = "List the community's action list as this identity sees it: what is \
                       waiting for it to approve, what it requested, history, or everything.",
        annotations(
            title = "List actions",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn vtc_actions_list(
        &self,
        Parameters(p): Parameters<ActionsListParams>,
        peer: Peer<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let view = p.view.unwrap_or_else(|| "waitingForMe".to_string());
        let call = match self
            .begin(
                "vtc_actions_list",
                Some(wire::ACTIONS_LIST),
                json!({ "view": view, "cursor": p.cursor }),
                Some(&peer),
            )
            .await
        {
            Ok(call) => call,
            Err(refused) => return *refused,
        };
        let result = match self.client() {
            Ok(client) => outcome(client.list_actions(&view, p.cursor.as_deref()).await),
            Err(e) => Err(e),
        };
        call.finish(result)
    }

    #[tool(
        description = "Read one parked action: what it would do, re-derived from the payload \
                       that would run and verified against its summary, who requested it, \
                       who has approved, how many approvals remain, and whether this identity \
                       may decide it.",
        annotations(
            title = "Show an action",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn vtc_actions_show(
        &self,
        Parameters(p): Parameters<ActionShowParams>,
        peer: Peer<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let call = match self
            .begin(
                "vtc_actions_show",
                Some(wire::ACTIONS_SHOW),
                json!({ "actionId": p.action_id }),
                Some(&peer),
            )
            .await
        {
            Ok(call) => call,
            Err(refused) => return *refused,
        };
        let result = match self.client() {
            Ok(client) => outcome(client.show_action(&p.action_id).await).map(|action| {
                let action = &action;
                let verified = vtc_client::actions::verify_action(action);
                json!({
                    "action": action,
                    "verified": match &verified {
                        Ok(v) => json!({
                            "title": v.title,
                            "effect": v.effect,
                            "fields": v.fields.iter().map(|(n, val)| json!({ "name": n, "value": val })).collect::<Vec<_>>(),
                            "matchCode": action["payloadDigest"].as_str().and_then(|d| vta_sdk::task_consent::match_code(d).ok()),
                        }),
                        Err(e) => json!({ "error": e }),
                    },
                    "thisIdentityMayDecide": action["challenge"].is_string(),
                })
            }),
            Err(e) => Err(e),
        };
        call.finish(result)
    }

    #[tool(
        description = "Approve or deny a parked action as this identity, as a \
                       `task-consent/decision` signed with its own key. The action's summary \
                       is re-derived from the payload that would run and refused on any \
                       mismatch; the operator is ALWAYS asked to confirm, shown the summary \
                       and the match code to compare with the requester's, whatever the \
                       bridge's confirm level — a host that cannot ask gets a refusal, never \
                       an unconfirmed decision.",
        annotations(
            title = "Decide an action",
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = false,
            open_world_hint = false
        )
    )]
    async fn vtc_actions_decide(
        &self,
        Parameters(p): Parameters<ActionDecideParams>,
        peer: Peer<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let call = match self
            .begin(
                "vtc_actions_decide",
                Some(wire::CONSENT_DECISION),
                json!({ "actionId": p.action_id, "approve": p.approve }),
                Some(&peer),
            )
            .await
        {
            Ok(call) => call,
            Err(refused) => return *refused,
        };
        let result = self.decide_action(&p, Some(&peer)).await;
        call.finish(result)
    }

    #[tool(
        description = "Cancel a parked action this identity requested.",
        annotations(
            title = "Cancel an action",
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn vtc_actions_cancel(
        &self,
        Parameters(p): Parameters<ActionCancelParams>,
        peer: Peer<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let call = match self
            .begin(
                "vtc_actions_cancel",
                Some(wire::ACTIONS_CANCEL),
                json!({ "actionId": p.action_id }),
                Some(&peer),
            )
            .await
        {
            Ok(call) => call,
            Err(refused) => return *refused,
        };
        let result = match self.client() {
            Ok(client) => outcome(
                client
                    .cancel_action(&p.action_id, p.reason.as_deref())
                    .await,
            ),
            Err(e) => Err(e),
        };
        call.finish(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::BridgeIdentity;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use vtc_client::{HolderKey, VtcClient};
    use vti_mcp_common::guard::{ConfirmLevel, Guard};
    use vti_mcp_common::observability::Recorder;

    const VTC_DID: &str = "did:web:vtc.example.com";

    /// Every URI a workflow sends is pinned, so none can be refused unsent.
    #[test]
    fn every_workflow_uri_is_pinned() {
        for uri in wire::ALL {
            assert!(
                vti_specs::schema_index::is_pinned(uri),
                "{uri} is not a pinned Trust Task version"
            );
        }
    }

    fn holder() -> HolderKey {
        let signing = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let did = format!(
            "did:key:{}",
            vta_sdk::did_key::ed25519_multibase_pubkey(&signing.verifying_key().to_bytes())
        );
        let private = multibase::encode(multibase::Base::Base58Btc, signing.to_bytes());
        HolderKey::from_did_key(&did, private).unwrap()
    }

    fn reply_doc(type_uri: &str, payload: Value) -> String {
        json!({
            "id": "urn:uuid:4d2c3f4e-1b2a-4c3d-8e9f-0a1b2c3d4e5f",
            "type": type_uri,
            "issuer": VTC_DID,
            "issuedAt": "2026-11-06T00:00:00Z",
            "payload": payload,
        })
        .to_string()
    }

    /// A community over loopback HTTP that answers a scripted sequence of
    /// requests, each with a status and a body, and hands back the documents
    /// it received in order.
    async fn scripted_vtc(
        replies: Vec<(&'static str, String)>,
    ) -> (String, tokio::task::JoinHandle<Vec<Value>>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let served = tokio::spawn(async move {
            let mut received = Vec::new();
            for (status, body) in replies {
                let (mut sock, _) = listener.accept().await.unwrap();
                let mut buf = Vec::new();
                let head_end = loop {
                    let mut chunk = [0u8; 4096];
                    let n = sock.read(&mut chunk).await.unwrap();
                    assert!(n > 0);
                    buf.extend_from_slice(&chunk[..n]);
                    if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        break i + 4;
                    }
                };
                let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
                let length: usize = head
                    .lines()
                    .find_map(|l| {
                        l.to_ascii_lowercase()
                            .strip_prefix("content-length:")
                            .map(str::to_owned)
                    })
                    .map(|v| v.trim().parse().unwrap())
                    .unwrap_or(0);
                let mut request = buf[head_end..].to_vec();
                while request.len() < length {
                    let mut chunk = [0u8; 4096];
                    let n = sock.read(&mut chunk).await.unwrap();
                    assert!(n > 0);
                    request.extend_from_slice(&chunk[..n]);
                }
                request.truncate(length);
                received.push(serde_json::from_slice::<Value>(&request).unwrap());
                sock.write_all(
                    format!(
                        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
                sock.shutdown().await.ok();
            }
            received
        });
        (format!("http://127.0.0.1:{port}/v1"), served)
    }

    fn bridge_at(base: &str, guard: Guard) -> VtcMcp {
        VtcMcp::new(
            Arc::new(VtcClient::with_key(base, VTC_DID, holder())),
            BridgeIdentity {
                mode: "did:key".into(),
                agent_did: Some("did:key:zAgent".into()),
                vtc_did: Some(VTC_DID.into()),
                transport_choice: "rest".into(),
                reuse_warning: None,
            },
            guard,
            Arc::new(Recorder::default()),
        )
    }

    fn group_create() -> Value {
        json!({
            "name": "Gardeners",
            "kind": "static",
            "visibility": "members",
            "showMembers": "members",
            "joinPolicy": "closed",
            "reason": "the allotment working group",
        })
    }

    #[tokio::test]
    async fn a_group_is_set_up_step_by_step_and_the_report_says_so() {
        let (base, served) = scripted_vtc(vec![
            (
                "200 OK",
                reply_doc(
                    &format!("{}#response", wire::GROUPS_CREATE),
                    json!({ "group": { "groupId": "grp_0123456789abcdef", "name": "Gardeners",
                        "kind": "static", "visibility": "members", "showMembers": "members",
                        "issuesCredentials": false, "carriesAuthority": false,
                        "createdAt": "2026-11-06T00:00:00Z", "groupDid": "did:webvh:x:g" } }),
                ),
            ),
            (
                "200 OK",
                reply_doc(
                    &format!("{}#response", wire::GROUPS_MANAGERS_ADD),
                    json!({ "groupId": "grp_0123456789abcdef", "managers": ["dir_aaaaaaaaaaaaaaaa"] }),
                ),
            ),
            (
                "200 OK",
                reply_doc(
                    &format!("{}#response", wire::GROUPS_MEMBERS_ADD),
                    json!({ "credentialId": null, "member": { "entryId": "dir_bbbbbbbbbbbbbbbb",
                        "since": "2026-11-06T00:00:00Z", "source": "added", "state": "active" } }),
                ),
            ),
            (
                "200 OK",
                reply_doc(
                    &format!("{}#response", wire::GROUPS_SHOW),
                    json!({ "group": { "groupId": "grp_0123456789abcdef", "name": "Gardeners",
                        "kind": "static", "visibility": "members", "showMembers": "members",
                        "issuesCredentials": false, "carriesAuthority": false,
                        "createdAt": "2026-11-06T00:00:00Z", "groupDid": "did:webvh:x:g" } }),
                ),
            ),
        ])
        .await;
        let bridge = bridge_at(
            &base,
            Guard {
                confirm: ConfirmLevel::Never,
                ..Guard::default()
            },
        );
        let report = bridge
            .run_group_setup(
                GroupSetupParams {
                    create: group_create(),
                    managers: vec!["dir_aaaaaaaaaaaaaaaa".into()],
                    members: vec!["dir_bbbbbbbbbbbbbbbb".into()],
                    bindings: vec![],
                    reason: None,
                },
                None,
            )
            .await;
        assert_eq!(report["outcome"], "completed", "{report}");
        assert_eq!(report["groupId"], "grp_0123456789abcdef");
        let steps = report["steps"].as_array().unwrap();
        let tasks: Vec<&str> = steps.iter().map(|s| s["task"].as_str().unwrap()).collect();
        assert_eq!(
            tasks,
            vec![
                "vtc/groups/create",
                "vtc/groups/managers/add",
                "vtc/groups/members/add",
                "vtc/groups/show"
            ]
        );
        assert!(steps.iter().all(|s| s["status"] == "ok"));
        let sent = served.await.unwrap();
        assert_eq!(sent[1]["payload"]["entryId"], "dir_aaaaaaaaaaaaaaaa");
        assert_eq!(sent[1]["payload"]["reason"], "the allotment working group");
        assert_eq!(sent[2]["payload"]["groupId"], "grp_0123456789abcdef");
        assert!(sent.iter().all(|d| d["proof"].is_object()));
    }

    #[tokio::test]
    async fn a_badge_is_created_from_its_uploaded_picture_offered_and_given_a_claim_code() {
        const BADGE: &str = "bdg_0123456789abcdefgh";
        let sha = "ab".repeat(32);
        let badge = json!({ "badgeId": BADGE, "kind": "community", "name": "Host" });
        let (base, served) = scripted_vtc(vec![
            (
                "200 OK",
                reply_doc(
                    &format!("{}#response", wire::BADGES_IMAGES_UPLOAD),
                    json!({ "image": { "sha256": sha, "mediaType": "image/png" },
                        "expiresAt": "2026-11-07T00:00:00Z" }),
                ),
            ),
            (
                "200 OK",
                reply_doc(
                    &format!("{}#response", wire::BADGES_CREATE),
                    json!({ "badge": badge }),
                ),
            ),
            (
                "200 OK",
                reply_doc(
                    &format!("{}#response", wire::BADGES_AWARDS_OFFER),
                    json!({ "offered": ["dir_aaaaaaaaaaaaaaaa"] }),
                ),
            ),
            (
                "200 OK",
                reply_doc(
                    &format!("{}#response", wire::BADGES_CLAIMS_CREATE),
                    json!({ "claim": { "badgeId": BADGE, "claimId": "bcl_0123456789abcdef" },
                        "code": "the-code" }),
                ),
            ),
            (
                "200 OK",
                reply_doc(
                    &format!("{}#response", wire::BADGES_SHOW),
                    json!({ "badge": badge }),
                ),
            ),
        ])
        .await;
        let bridge = bridge_at(
            &base,
            Guard {
                confirm: ConfirmLevel::Never,
                ..Guard::default()
            },
        );
        let report = bridge
            .run_badge_create(
                BadgeCreateParams {
                    create: json!({
                        "kind": "community",
                        "name": "Host",
                        "description": "Hosted a workshop",
                        "image": { "sha256": "00".repeat(32) },
                        "reason": "workshops",
                    }),
                    image: Some(json!({ "mediaType": "image/png", "data": "iVBORw0KGgo" })),
                    offer: Some(json!({ "to": ["dir_aaaaaaaaaaaaaaaa"] })),
                    claim_code: Some(json!({
                        "label": "Spring meetup",
                        "validUntil": "2026-11-20T00:00:00Z",
                        "limit": 40,
                    })),
                },
                None,
            )
            .await;
        assert_eq!(report["outcome"], "completed", "{report}");
        assert_eq!(report["badgeId"], BADGE);
        let tasks: Vec<&str> = report["steps"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s["task"].as_str().unwrap())
            .collect();
        assert_eq!(
            tasks,
            vec![
                "vtc/badges/images/upload",
                "vtc/badges/create",
                "vtc/badges/awards/offer",
                "vtc/badges/claims/create",
                "vtc/badges/show"
            ]
        );
        // The code is answered once, in the claim step's own answer.
        assert_eq!(report["steps"][3]["detail"]["code"], "the-code");
        let sent = served.await.unwrap();
        // The create names the picture by the digest the upload answered,
        // whatever the payload carried.
        assert_eq!(sent[1]["payload"]["image"], json!({ "sha256": sha }));
        assert_eq!(sent[2]["payload"]["badgeId"], BADGE);
        assert_eq!(sent[2]["payload"]["to"], json!(["dir_aaaaaaaaaaaaaaaa"]));
        assert_eq!(sent[3]["payload"]["badgeId"], BADGE);
        assert_eq!(sent[3]["payload"]["limit"], 40);
        assert_eq!(sent[4]["payload"], json!({ "badgeId": BADGE }));
    }

    #[tokio::test]
    async fn a_refused_create_stops_the_flow_and_sends_nothing_more() {
        let (base, served) = scripted_vtc(vec![(
            "403 Forbidden",
            reply_doc(
                "https://trusttasks.org/spec/trust-task-error/0.3",
                json!({ "code": "vtc/groups/create:noKeyHolder", "message": "add [groups]" }),
            ),
        )])
        .await;
        let bridge = bridge_at(
            &base,
            Guard {
                confirm: ConfirmLevel::Never,
                ..Guard::default()
            },
        );
        let report = bridge
            .run_group_setup(
                GroupSetupParams {
                    create: group_create(),
                    managers: vec!["dir_aaaaaaaaaaaaaaaa".into()],
                    members: vec![],
                    bindings: vec![],
                    reason: None,
                },
                None,
            )
            .await;
        assert_eq!(report["outcome"], "stopped");
        let steps = report["steps"].as_array().unwrap();
        assert_eq!(steps.len(), 1);
        assert_eq!(steps[0]["status"], "refused");
        assert!(
            steps[0]["detail"]["error"]
                .as_str()
                .unwrap()
                .contains("noKeyHolder")
        );
        assert_eq!(served.await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn the_local_policy_refuses_a_step_before_it_is_sent() {
        // A read-only bridge never sends the create: the first step is refused
        // locally and no request reaches the (absent) community.
        let bridge = bridge_at(
            "http://192.0.2.1:9/v1",
            Guard {
                read_only: true,
                confirm: ConfirmLevel::Never,
                ..Guard::default()
            },
        );
        let report = bridge
            .run_group_setup(
                GroupSetupParams {
                    create: group_create(),
                    managers: vec![],
                    members: vec![],
                    bindings: vec![],
                    reason: None,
                },
                None,
            )
            .await;
        assert_eq!(report["outcome"], "stopped");
        let steps = report["steps"].as_array().unwrap();
        assert_eq!(steps[0]["status"], "refused-locally");
        assert!(
            steps[0]["detail"]["error"]
                .as_str()
                .unwrap()
                .contains("--read-only")
        );

        // And a step that needs confirming, with no host to ask, is refused
        // rather than run unconfirmed.
        let confirming = bridge_at("http://192.0.2.1:9/v1", Guard::default());
        let report = confirming
            .run_admin_grant(
                AdminGrantParams {
                    entry: json!({ "subject": "did:key:zAlice" }),
                    reason: None,
                },
                None,
            )
            .await;
        // acl/show is a read and runs (and fails to connect); the report stops
        // there without a grant ever being built.
        assert_eq!(report["outcome"], "stopped");
        assert_eq!(report["steps"][0]["task"], "acl/show");
    }

    #[tokio::test]
    async fn an_untrusted_ballot_box_stops_a_board_before_create() {
        let (base, served) = scripted_vtc(vec![(
            "200 OK",
            reply_doc(
                &format!("{}#response", wire::BALLOT_BOXES_LIST),
                json!({ "ballotBoxes": [{ "did": "did:web:box.example.com", "operator": "did:web:op", "sameOperator": false }] }),
            ),
        )])
        .await;
        let bridge = bridge_at(
            &base,
            Guard {
                confirm: ConfirmLevel::Never,
                ..Guard::default()
            },
        );
        let report = bridge
            .run_board_create(
                BoardCreateParams {
                    create: json!({ "title": "Ideas", "template": { "ballotBox": "did:web:rogue" } }),
                    facilitators: vec![],
                    reason: None,
                },
                None,
            )
            .await;
        assert_eq!(report["outcome"], "stopped");
        let steps = report["steps"].as_array().unwrap();
        assert_eq!(steps.len(), 2);
        assert_eq!(steps[0]["task"], "vtc/elections/ballot-boxes/list");
        assert_eq!(steps[1]["status"], "refused-locally");
        assert!(
            steps[1]["detail"]["error"]
                .as_str()
                .unwrap()
                .contains("did:web:rogue")
        );
        assert_eq!(served.await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn a_grant_to_an_existing_entry_is_stopped_locally() {
        let (base, served) = scripted_vtc(vec![(
            "200 OK",
            reply_doc(
                &format!("{}#response", wire::ACL_SHOW),
                json!({ "entry": { "subject": "did:key:zAlice", "role": "moderator",
                    "act": { "scope": "all" }, "capabilities": { "scope": "ceiling" },
                    "keys": { "scope": "all" } } }),
            ),
        )])
        .await;
        let bridge = bridge_at(
            &base,
            Guard {
                confirm: ConfirmLevel::Never,
                ..Guard::default()
            },
        );
        let report = bridge
            .run_admin_grant(
                AdminGrantParams {
                    entry: json!({ "subject": "did:key:zAlice", "role": "community-admin" }),
                    reason: Some("promotion".into()),
                },
                None,
            )
            .await;
        assert_eq!(report["outcome"], "stopped");
        let steps = report["steps"].as_array().unwrap();
        assert_eq!(steps[1]["task"], "acl/grant");
        assert!(
            steps[1]["detail"]["error"]
                .as_str()
                .unwrap()
                .contains("role/set")
        );
        assert_eq!(served.await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn deciding_is_never_sent_without_the_operator() {
        let action = json!({
            "actionId": "act_1",
            "typeUri": "https://trusttasks.org/spec/acl/grant/0.2",
            "requester": "did:key:zBob",
            "challenge": "c".repeat(32),
            "payload": { "entry": { "subject": "did:key:zAlice", "role": "moderator" } },
            "summary": { "title": "Grant {role} to {subject}", "templateDigest": "z", "fields": {
                "role": { "format": "text", "pointer": "/entry/role", "value": "moderator" },
                "subject": { "format": "did", "pointer": "/entry/subject", "value": "did:key:zAlice" }
            } },
        });
        let mut action = action;
        action["payloadDigest"] =
            json!(vtc_client::actions::payload_digest(&action["payload"]).unwrap());
        let (base, served) = scripted_vtc(vec![(
            "200 OK",
            reply_doc(
                &format!("{}#response", wire::ACTIONS_SHOW),
                json!({ "action": action }),
            ),
        )])
        .await;
        let bridge = bridge_at(
            &base,
            Guard {
                confirm: ConfirmLevel::Never,
                ..Guard::default()
            },
        );
        let err = bridge
            .decide_action(
                &ActionDecideParams {
                    action_id: "act_1".into(),
                    approve: true,
                    reason: None,
                },
                None,
            )
            .await
            .unwrap_err();
        assert!(
            err.message.contains("nothing was decided"),
            "{}",
            err.message
        );
        assert!(
            err.message.contains("Grant moderator to did:key:zAlice"),
            "{}",
            err.message
        );
        assert!(err.message.contains("Match code"), "{}", err.message);
        // Only the show was sent: no decision document reached the community.
        assert_eq!(served.await.unwrap().len(), 1);
    }
}
