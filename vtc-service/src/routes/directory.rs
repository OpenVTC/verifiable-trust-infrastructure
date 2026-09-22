//! `GET /v1/directory/{did}` — the directory ceremony.
//!
//! The first community ceremony wired end-to-end through the decision
//! pipeline ([`crate::ceremony`]). Directory is the read-only
//! instance: an authenticated viewer asks to see a subject's member
//! record, and the active `directory` policy decides which fields the
//! viewer may see. There is no thread and no state mutation — the
//! whole ceremony is a single synchronous request → projection.
//!
//! Flow (pipeline §2, realized here):
//! 1. **Trigger / Gather** — the route: an authenticated viewer
//!    ([`AuthClaims`]) names a `subject` DID.
//! 2. **Verify / Facts** — [`assemble_directory_facts`] reads the
//!    viewer's community role and the subject's member row from
//!    storage into a [`Facts`]. The viewer is already authenticated
//!    (the extractor verified the JWT + session), so the facts gate
//!    ([`VerifiedFacts::assemble`]) passes trivially — directory
//!    carries no presented evidence to verify.
//! 3. **Evaluate / Verdict** — [`crate::ceremony::decide`] runs the
//!    active `directory` policy and applies the host invariants.
//! 4. **Effect** — [`crate::ceremony::plan`] turns an `allow` into a
//!    field projection, intersected with the PII-boundary whitelist
//!    ([`DIRECTORY_FIELD_WHITELIST`]).
//!
//! ## Role source
//!
//! `actor.role` in the facts is the viewer's **community** role
//! (`VtcRole`, read from the ACL keyspace), not the JWT/VTA `Role` the
//! [`AuthClaims`] extractor carries — the directory policy branches on
//! community standing (`admin` vs `member`), which lives in the ACL.

use axum::Json;
use axum::extract::{Path, Query, State};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value as JsonValue, json};

use vti_common::error::AppError;

use crate::error::TaskError;

use crate::acl::get_acl_entry;
use crate::auth::AuthClaims;
use crate::ceremony::{
    self, Evidence, Facts, Purpose, Verdict, VerifiedFacts, effects::EffectPlan,
};
use crate::ceremony::{FactsInputs, assemble_facts, load_actor_role, member_state};
use crate::members::get_member;
use crate::policy::load_active_compiled;
use crate::policy::model::PolicyPurpose;
use crate::server::AppState;

/// The PII boundary for the directory ceremony: the maximum set of
/// member fields any directory policy may ever project, member-to-
/// member. A policy can narrow this (the default shows `did` + `role`
/// to members), but cannot widen past it — [`crate::ceremony::plan`]
/// intersects the policy's chosen fields with this list. Per-community
/// configuration of the whitelist is a follow-up; this constant is the
/// safe default ceiling.
pub const DIRECTORY_FIELD_WHITELIST: [&str; 4] = ["did", "role", "joined_at", "status"];

/// Optional `?fields=a,b,c` hint — the fields the caller is interested
/// in. Advisory: the policy decides what it returns, and the PII
/// boundary caps it. Recorded into the facts so a policy *may* honour
/// it, but the default directory policy projects by viewer role.
#[derive(Debug, Default, Deserialize, utoipa::ToSchema, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub struct DirectoryQuery {
    #[serde(default)]
    pub fields: Option<String>,
}

/// The projected subject record.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
#[derive(utoipa::ToSchema)]
pub struct DirectoryResponse {
    pub subject: String,
    pub fields: Map<String, JsonValue>,
}

/// `vtc/directory/query:notFound` — no member with that DID, or none whose
/// projection is visible to this caller.
pub const QUERY_ERR_NOT_FOUND: &str =
    trust_tasks_rs::specs::vtc::directory::query::v0_1::error_codes::NOT_FOUND.code;

/// The one answer for every "nothing to show" outcome. `vtc/directory/query`
/// makes "no such member" and "nothing visible to you" indistinguishable, so
/// they share a status, a code and a message — anything else is a membership
/// oracle.
fn not_visible() -> TaskError {
    TaskError::declared(
        QUERY_ERR_NOT_FOUND,
        AppError::NotFound("no directory entry for that DID is visible to this caller".into()),
    )
}

/// `GET /v1/directory/{did}`.
#[utoipa::path(
    get, path = "/directory/{did}", tag = "directory",
    security(("bearer_jwt" = [])),
    params(
        ("did" = String, Path, description = "Subject DID"),
        DirectoryQuery,
    ),
    responses(
        (status = 200, description = "Projected subject record", body = DirectoryResponse),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 404, description = "No member with that DID, or nothing about them visible to this caller"),
    ),
)]
pub async fn query(
    viewer: AuthClaims,
    State(state): State<AppState>,
    Path(subject_did): Path<String>,
    Query(q): Query<DirectoryQuery>,
) -> Result<Json<DirectoryResponse>, TaskError> {
    vti_common::identifier::validate_did("did", &subject_did)?;
    let facts = assemble_directory_facts(&state, &viewer, &subject_did, q.fields).await?;
    // Read before the policy runs, answered after it: the policy's verdict
    // decides for a missing subject exactly as for a present one, so the order
    // of the checks cannot tell the two apart either.
    let subject_is_member = facts.state.subject_member.is_some();
    let verified = VerifiedFacts::assemble(facts).map_err(AppError::from)?;

    let policy = load_active_compiled(
        &state.active_policies_ks,
        &state.policies_ks,
        PolicyPurpose::Directory,
    )
    .await?;
    let verdict = ceremony::decide(&verified, &policy)?;

    match &verdict {
        Verdict::Allow(_) => {
            let whitelist: Vec<String> = DIRECTORY_FIELD_WHITELIST
                .iter()
                .map(|s| s.to_string())
                .collect();
            match ceremony::plan(&verified, &verdict, &whitelist)? {
                // `notFound` for a DID that is not a member, and for an empty
                // projection — "exists, but you may see nothing" is not an
                // answer this task gives.
                EffectPlan::Project { .. } if !subject_is_member => Err(not_visible()),
                EffectPlan::Project { fields } if fields.is_empty() => Err(not_visible()),
                EffectPlan::Project { fields } => Ok(Json(DirectoryResponse {
                    subject: subject_did,
                    fields,
                })),
                // Allow on a directory must plan a projection; any other
                // plan means the active policy isn't a directory policy.
                other => Err(AppError::Internal(format!(
                    "directory allow produced a non-projection effect: {other:?}"
                ))
                .into()),
            }
        }
        // A deny is "nothing visible to this caller", which the task answers
        // as `notFound` — the same answer a missing subject gets, so a denied
        // viewer cannot probe membership by telling the two apart. The deny's
        // own code stays in the server log, not on the wire.
        Verdict::Deny(d) => {
            tracing::debug!(
                viewer = %viewer.did,
                code = %d.code,
                reason = d.reason.as_deref().unwrap_or_default(),
                "directory query denied by policy"
            );
            Err(not_visible())
        }
        // Directory is synchronous and unthreaded — a policy that
        // refers or requests-more is misconfigured for this purpose.
        Verdict::Refer(_) | Verdict::RequestMore(_) => Err(AppError::Internal(
            "directory policy returned a non-terminal verdict; directory is synchronous".into(),
        )
        .into()),
    }
}

/// Read the viewer's community role + the subject's member row from
/// storage into the purpose-agnostic [`Facts`] the policy evaluates
/// over.
async fn assemble_directory_facts(
    state: &AppState,
    viewer: &AuthClaims,
    subject_did: &str,
    fields_hint: Option<String>,
) -> Result<Facts, AppError> {
    // Subject's member facts: role from the ACL, status + joined_at from the
    // member row (directory sources the subject's role from the ACL rather than
    // a caller-supplied current role, so it builds the MemberState explicitly).
    let subject_member = match get_member(&state.members_ks, subject_did).await? {
        Some(m) => {
            let role = get_acl_entry(&state.acl_ks, subject_did)
                .await?
                .map(|e| e.role.to_string())
                .unwrap_or_else(|| "member".to_string());
            Some(member_state(role, Some(&m)))
        }
        None => None,
    };

    let request = fields_hint.map(|raw| {
        let fields: Vec<String> = raw
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        json!({ "fields_requested": fields })
    });

    assemble_facts(
        state,
        FactsInputs {
            purpose: Purpose::Directory,
            actor_did: viewer.did.clone(),
            actor_role: load_actor_role(state, &viewer.did).await?,
            subject_did: subject_did.to_string(),
            subject_member,
            evidence: Evidence {
                vetting: None,
                invitation: None,
                presentation: None,
                request,
            },
            // A directory read is synchronous and unthreaded, and presents no
            // credentials to bind.
            thread_id: None,
        },
    )
    .await
}
