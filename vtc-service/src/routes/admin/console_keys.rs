//! `/v1/admin/console-keys/*` — enrol, list and revoke the admin console's
//! signing keys (#1684, design note `docs/05-design-notes/vtc-console-signing.md`).
//!
//! The console cannot author a signed Trust Task document, which is what keeps
//! every bearer route #1641 would retire mounted. This is the server half of
//! the fix: the browser generates a **non-extractable** WebCrypto Ed25519 key,
//! derives `did:key:z6Mk…` from its public half, and enrols it here as a
//! *delegation* of the operator's existing admin DID. See
//! [`crate::acl::console_key`] for what a delegation is and, more importantly,
//! for what it is not.
//!
//! ## Why there is no Trust Task URI on these three routes
//!
//! Every other route in this module carries one. These do not, and the reason
//! is the workspace rule rather than an oversight: **no published task family
//! covers enrolling a signing-key delegation.**
//!
//! - `device/register/0.1` is the nearest miss and it is the wrong shape. It
//!   registers a *device* as a consumer in its own right — `consumerKind`, an
//!   HPKE recipient key, an optional attestation, and a `Capability` set the
//!   maintainer grants it. That is an identity with its own row and its own
//!   authority, which is exactly §5F of the design note and exactly what
//!   VTI-OPS-050 refuses here.
//! - `auth/passkey/{enroll,revoke,list}` is WebAuthn end to end: credential
//!   creation options, an attestation object, a UV assertion. None of it
//!   describes a `did:key` a browser minted for itself.
//!
//! So per `new-task-family-needs-upstream-spec-first`, this is served on the
//! existing REST surface and the specification moves first. Binding an
//! invented `trusttasks.org/spec/…` URI would assert the registry serves it,
//! which `tests/trust_task_manifest.rs::
//! every_bound_canonical_task_exists_in_the_registry` checks and would fail —
//! and raising that test's exception count is explicitly the wrong fix. Same
//! exemption `relationships::{suspend,restore}` and the `schemas` routes carry.
//!
//! **What the upstream task should be**, when it is authored in
//! dtgwg-trust-tasks-tf: an `auth/signing-key/{enroll,list,revoke}` family,
//! sibling to `auth/passkey/*`, because the thing being managed is the same
//! thing — a credential of an identity, enrolled by its holder behind a
//! second factor, listed, and individually revocable. `enroll` takes
//! `{ signingKeyDid, deviceLabel?, expiresAt? }` and no subject: the subject
//! is the proven caller, and a subject field would be a field an attacker can
//! set. `revoke` takes `{ signingKeyDid }`. `list` takes nothing and returns
//! the caller's own. The bodies below are those payloads already.
//!
//! ## The gates
//!
//! | verb | gate |
//! |---|---|
//! | `POST` | `AdminAuth` **plus a live step-up** — [`crate::acl::elevation::verified`] |
//! | `GET` | `AdminAuth`. A read of your own keys is safe and needs no gesture, the same call `auth/passkey/list/0.1` makes. |
//! | `DELETE` | `AdminAuth`, self or a super-admin. De-escalation, so no step-up. |

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use tracing::info;
use vti_common::audit::{AdminConsoleKeyData, AuditEvent};
use vti_common::auth::AdminAuth;
use vti_common::error::AppError;

use crate::acl::console_key::{
    ConsoleKeyDelegation, enrol_delegation, get_delegation, list_delegations_for_admin,
    revoke_delegation,
};
use crate::server::AppState;

/// Serialises enrolment so the "already delegated" read and the write that
/// follows it are one critical section. Without it two concurrent enrolments
/// of the same console DID — one per admin — can both pass the check and the
/// later write wins, silently re-pointing a key at a different operator.
///
/// The same reasoning, and the same shape, as `ADMIN_PASSKEY_LOCK`.
static CONSOLE_KEY_LOCK: Mutex<()> = Mutex::const_new(());

// ---------------------------------------------------------------------------
// Wire shapes — camelCase, `deny_unknown_fields` on the request bodies (R3.2)
// ---------------------------------------------------------------------------

/// The enrolment request.
///
/// **There is no `adminDid` member, and that is the design.** The delegation is
/// always written against the authenticated caller, so "enrol a key that acts
/// as somebody else" is not a request this surface can express. See
/// [`enrol`]'s own comment for why self-targeting is the only valid case here
/// and why that is the *opposite* of the `acl/grant` rule.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EnrolRequest {
    /// The console key's `did:key` — Ed25519 multikey, as the browser derives
    /// it from the public half of its non-extractable keypair.
    pub console_did: String,
    /// Operator-supplied, e.g. `"Work laptop — Chrome"`. Optional; an empty
    /// string is treated as absent.
    #[serde(default)]
    pub label: Option<String>,
    /// Optional finite lifetime. Omit — the expected case — and the delegation
    /// lasts until it is revoked or the browser profile is cleared.
    #[serde(default)]
    pub expires_at: Option<DateTime<Utc>>,
}

/// One delegation as the console sees it.
///
/// Separate from the stored [`ConsoleKeyDelegation`] for the same reason
/// `RegisteredCredential` is separate from `RegisteredPasskey`: that type is a
/// storage row whose member names are the on-disk format. This one can change
/// without orphaning anything.
#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ConsoleKey {
    pub console_did: String,
    /// The admin DID this key acts as — always the listing caller, included so
    /// a console need not infer it from the session.
    pub admin_did: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<DateTime<Utc>>,
    /// Live right now: not revoked, not expired. Computed server-side so the
    /// console does not re-implement the predicate the verifier uses — the two
    /// disagreeing is how a page shows a key as working after it stopped.
    pub active: bool,
}

impl From<&ConsoleKeyDelegation> for ConsoleKey {
    fn from(d: &ConsoleKeyDelegation) -> Self {
        Self {
            console_did: d.console_did.clone(),
            admin_did: d.admin_did.clone(),
            label: d.label.clone(),
            created_at: d.created_at,
            expires_at: d.expires_at,
            last_used_at: d.last_used_at,
            revoked_at: d.revoked_at,
            active: d.is_active_at(Utc::now()),
        }
    }
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ListResponse {
    /// The caller's own console keys, newest first, revoked ones included so
    /// an operator can see that a browser was disowned rather than never
    /// enrolled.
    pub console_keys: Vec<ConsoleKey>,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RevokeResponse {
    pub console_did: String,
    pub revoked_at: DateTime<Utc>,
    /// How many of the owning admin's console keys are still active. Zero is a
    /// legitimate state — unlike a passkey, whose last one is protected,
    /// because losing every console key costs an operator the *signed* door
    /// and not the door: the bearer routes and the passkey login are untouched.
    pub remaining_active: usize,
}

// ---------------------------------------------------------------------------
// POST — enrol
// ---------------------------------------------------------------------------

#[utoipa::path(
    post, path = "/admin/console-keys",
    operation_id = "adminConsoleKeyEnrol", tag = "admin",
    security(("bearer_jwt" = [])),
    request_body = EnrolRequest,
    responses(
        (status = 201, description = "The console key may now act as the caller's admin DID", body = ConsoleKey),
        (status = 400, description = "consoleDid is not a did:key, or is the caller's own DID"),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not an admin, or has no live step-up"),
        (status = 409, description = "That DID already holds an ACL row, or is already enrolled"),
    ),
)]
pub async fn enrol(
    admin: AdminAuth,
    State(state): State<AppState>,
    Json(req): Json<EnrolRequest>,
) -> Result<(StatusCode, Json<ConsoleKey>), AppError> {
    // **A fresh step-up, and the reason is not the one `acl/grant` has.**
    //
    // Enrolling a console key confers no role, so VTI-OPS-051 is not what is
    // being satisfied here. What is: the credential this writes can author
    // signed documents in the caller's name *with no gesture at use time*, for
    // as long as it lives. A stolen session is enough to ride the cookie while
    // it lasts; it must not be enough to leave something behind that outlives
    // it. So enrolment costs a live passkey user-verification — the one thing
    // script in the origin cannot forge — and the console already runs exactly
    // this ceremony (`stepUpSession()`, #1658) before its admin-conferring
    // operations.
    //
    // `elevation::verified` reads the **session row**, not the token: a JWT
    // minted before the elevation, or long after it lapsed, says nothing about
    // it. Failing closed is the only safe reading.
    if !crate::acl::elevation::verified(&admin.0, &state.sessions_ks).await {
        return Err(crate::acl::elevation::required(
            "enrolling a console signing key",
        ));
    }

    // **Self-targeted is the only valid case, which inverts the `acl/grant`
    // rule on purpose.** `create_acl` refuses a *self*-targeted admin grant,
    // because conferring a role on yourself is self-promotion however well
    // authenticated (VTI-OPS-050, #1658). Here the opposite holds: a
    // delegation confers nothing, so there is nothing to promote — and it is a
    // credential of *your* identity, so enrolling one for somebody else would
    // be handing them a key that acts as you, or planting one on them. Neither
    // is a thing an operator should be able to ask for, so the admin DID is
    // taken from the proven caller and the request body cannot name it.
    let admin_did = admin.0.did.clone();

    let _guard = CONSOLE_KEY_LOCK.lock().await;
    let delegation = enrol_delegation(
        &state.console_keys_ks,
        &state.acl_ks,
        &req.console_did,
        &admin_did,
        req.label,
        req.expires_at,
    )
    .await?;

    if let Some(writer) = state.audit_writer.as_ref() {
        writer
            .write(
                &admin_did,
                Some(&delegation.console_did),
                AuditEvent::AdminConsoleKeyEnrolled(AdminConsoleKeyData {
                    console_did: delegation.console_did.clone(),
                    label: delegation.label.clone(),
                }),
            )
            .await?;
    }

    info!(
        admin_did = %admin_did,
        console_did = %delegation.console_did,
        "console signing key enrolled"
    );
    Ok((StatusCode::CREATED, Json(ConsoleKey::from(&delegation))))
}

// ---------------------------------------------------------------------------
// GET — list
// ---------------------------------------------------------------------------

#[utoipa::path(
    get, path = "/admin/console-keys",
    operation_id = "adminConsoleKeyList", tag = "admin",
    security(("bearer_jwt" = [])),
    responses(
        (status = 200, description = "The caller's console keys; empty when none are enrolled", body = ListResponse),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not an admin"),
    ),
)]
pub async fn list(
    admin: AdminAuth,
    State(state): State<AppState>,
) -> Result<Json<ListResponse>, AppError> {
    // Empty is a collection, not a missing one — 200 with `[]`, for the reason
    // `auth/passkey/list/0.1` learned: an operator who has never enrolled one
    // is the *first* state this page renders, and a 404 there makes the console
    // contradict its own empty state.
    let mine = list_delegations_for_admin(&state.console_keys_ks, &admin.0.did).await?;
    Ok(Json(ListResponse {
        console_keys: mine.iter().map(ConsoleKey::from).collect(),
    }))
}

// ---------------------------------------------------------------------------
// DELETE — revoke
// ---------------------------------------------------------------------------

#[utoipa::path(
    delete, path = "/admin/console-keys/{console_did}",
    operation_id = "adminConsoleKeyRevoke", tag = "admin",
    security(("bearer_jwt" = [])),
    params(("console_did" = String, Path, description = "The console key's did:key")),
    responses(
        (status = 200, description = "Revoked; the next document signed by this key is refused", body = RevokeResponse),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is neither the owning admin nor a super-admin"),
        (status = 404, description = "No such console key"),
    ),
)]
pub async fn revoke(
    admin: AdminAuth,
    State(state): State<AppState>,
    Path(console_did): Path<String>,
) -> Result<Json<RevokeResponse>, AppError> {
    let _guard = CONSOLE_KEY_LOCK.lock().await;

    let existing = get_delegation(&state.console_keys_ks, &console_did)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("no console key enrolled for {console_did}")))?;

    // Self, or a super-admin doing incident response. Revocation only ever
    // *removes* authority, so a broad power here cannot escalate — but it can
    // deny service, which is why a context-scoped admin cannot disarm a peer's
    // console. Decided through `is_super_admin` (which reads `ActScope`),
    // never `allowed_contexts.is_empty()` — for a non-admin row that emptiness
    // means the opposite.
    if existing.admin_did != admin.0.did && !admin.0.is_super_admin() {
        return Err(AppError::Forbidden(
            "a console key may be revoked by the admin it acts for, or by a super-admin".into(),
        ));
    }

    // **No step-up.** Requiring a fresh gesture to *withdraw* a credential is
    // a gate that protects the attacker: an operator who suspects a browser is
    // compromised should not have to reach for their authenticator before they
    // can disown it.
    let revoked = revoke_delegation(&state.console_keys_ks, &console_did, &admin.0.did)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("no console key enrolled for {console_did}")))?;

    let now = Utc::now();
    let remaining_active = list_delegations_for_admin(&state.console_keys_ks, &revoked.admin_did)
        .await?
        .iter()
        .filter(|d| d.is_active_at(now))
        .count();

    if let Some(writer) = state.audit_writer.as_ref() {
        writer
            .write(
                &admin.0.did,
                Some(&revoked.console_did),
                AuditEvent::AdminConsoleKeyRevoked(AdminConsoleKeyData {
                    console_did: revoked.console_did.clone(),
                    label: revoked.label.clone(),
                }),
            )
            .await?;
    }

    info!(
        revoked_by = %admin.0.did,
        console_did = %revoked.console_did,
        "console signing key revoked"
    );
    Ok(Json(RevokeResponse {
        console_did: revoked.console_did,
        revoked_at: revoked.revoked_at.unwrap_or(now),
        remaining_active,
    }))
}
