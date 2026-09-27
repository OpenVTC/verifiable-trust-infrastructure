//! Members' step-up passkeys — the console's listing. See
//! [`crate::step_up_passkey`].
//!
//! Issuing an invite, redeeming it and revoking a credential are Trust Tasks
//! (`auth/passkey/enroll/invite/0.2`, `auth/passkey/enroll/redeem/{start,finish}/0.1`,
//! `auth/passkey/revoke/{start,finish}/0.2`) served only by the spine
//! (`crate::trust_tasks::step_up_passkey_tasks`), so they reach the same code
//! over TSP, DIDComm and HTTPS. No REST route serves them.
//!
//! - `GET /v1/admin/step-up-passkeys` — every member's step-up passkeys, or
//!   one member's (`?subject=`). A community administrator. The published
//!   `auth/passkey/list` lists only the signer's own credentials and forbids a
//!   subject in the payload, so no task covers an administrator reading
//!   another member's; this route carries no Trust-Task binding, like the
//!   console-key listing.

use axum::Json;
use axum::extract::{Query, State};
use serde::{Deserialize, Serialize};
use vti_common::auth::AdminAuth;
use vti_common::error::AppError;

use crate::server::AppState;
use crate::step_up_passkey::{self, CredentialMeta};

#[derive(Debug, Deserialize, utoipa::IntoParams)]
pub struct ListQuery {
    /// Only this member's step-up passkeys.
    pub subject: Option<String>,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
#[schema(as = StepUpPasskeyList)]
pub struct StepUpPasskeyList {
    pub credentials: Vec<CredentialMeta>,
}

#[utoipa::path(
    get, path = "/admin/step-up-passkeys", tag = "admin",
    operation_id = "stepUpPasskeyList",
    security(("bearer_jwt" = [])),
    params(ListQuery),
    responses(
        (status = 200, description = "Members' step-up passkeys, newest first per member", body = StepUpPasskeyList),
        (status = 403, description = "Not a community administrator"),
    ),
)]
pub async fn list(
    admin: AdminAuth,
    State(state): State<AppState>,
    Query(q): Query<ListQuery>,
) -> Result<Json<StepUpPasskeyList>, AppError> {
    if !crate::git_ns::ops::standing(&state, &admin.0.did)
        .await?
        .community_admin
    {
        return Err(AppError::Forbidden(
            "only a community administrator lists members' step-up passkeys".into(),
        ));
    }
    Ok(Json(StepUpPasskeyList {
        credentials: step_up_passkey::list(&state.step_up_passkeys_ks, q.subject.as_deref())
            .await?,
    }))
}
