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
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value as JsonValue, json};

use vti_common::error::AppError;

use crate::acl::get_acl_entry;
use crate::auth::AuthClaims;
use crate::ceremony::{
    self, Actor, Context, Evidence, Facts, MemberState, Purpose, State as FactsState, Subject,
    Verdict, VerifiedFacts, effects::EffectPlan,
};
use crate::community::load_profile;
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
        (status = 403, description = "Directory access denied"),
    ),
)]
pub async fn query(
    viewer: AuthClaims,
    State(state): State<AppState>,
    Path(subject_did): Path<String>,
    Query(q): Query<DirectoryQuery>,
) -> Result<Json<DirectoryResponse>, AppError> {
    let facts = assemble_directory_facts(&state, &viewer, &subject_did, q.fields).await?;
    let verified = VerifiedFacts::assemble(facts)?;

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
                EffectPlan::Project { fields } => Ok(Json(DirectoryResponse {
                    subject: subject_did,
                    fields,
                })),
                // Allow on a directory must plan a projection; any other
                // plan means the active policy isn't a directory policy.
                other => Err(AppError::Internal(format!(
                    "directory allow produced a non-projection effect: {other:?}"
                ))),
            }
        }
        Verdict::Deny(d) => Err(AppError::Forbidden(format!(
            "directory access denied ({}){}",
            d.code,
            d.reason
                .as_deref()
                .map(|r| format!(": {r}"))
                .unwrap_or_default(),
        ))),
        // Directory is synchronous and unthreaded — a policy that
        // refers or requests-more is misconfigured for this purpose.
        Verdict::Refer(_) | Verdict::RequestMore(_) => Err(AppError::Internal(
            "directory policy returned a non-terminal verdict; directory is synchronous".into(),
        )),
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
    // Actor's community role comes from the ACL, not the JWT.
    let actor_role = get_acl_entry(&state.acl_ks, &viewer.did)
        .await?
        .map(|e| e.role.to_string());

    // Subject's member facts: role from the ACL, status from the
    // member row's tombstone, joined_at from the member row.
    let subject_member = match get_member(&state.members_ks, subject_did).await? {
        Some(m) => {
            let role = get_acl_entry(&state.acl_ks, subject_did)
                .await?
                .map(|e| e.role.to_string())
                .unwrap_or_else(|| "member".to_string());
            let status = if m.removed_at.is_some() {
                "removed"
            } else {
                "active"
            };
            Some(MemberState {
                role,
                status: status.to_string(),
                joined_at: m.joined_at,
                personhood: None,
            })
        }
        None => None,
    };

    // community_did is informational for directory (the policy doesn't
    // branch on it); empty when no profile is set yet.
    let community_did = load_profile(&state.community_ks)
        .await?
        .map(|p| p.community_did)
        .unwrap_or_default();

    let member_count = state.member_count();

    let request = fields_hint.map(|raw| {
        let fields: Vec<String> = raw
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        json!({ "fields_requested": fields })
    });

    Ok(Facts {
        purpose: Purpose::Directory,
        now: Utc::now(),
        actor: Actor {
            did: viewer.did.clone(),
            role: actor_role,
            authenticated: true,
        },
        subject: Subject {
            did: subject_did.to_string(),
        },
        context: Context {
            community_did,
            channel: "rest".to_string(),
            member_count,
        },
        evidence: Evidence {
            invitation: None,
            presentation: None,
            request,
        },
        state: FactsState { subject_member },
    })
}
