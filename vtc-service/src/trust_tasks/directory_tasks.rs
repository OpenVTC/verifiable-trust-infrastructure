//! The member directory on the signed-document spine (`vtc/directory/*`;
//! [`crate::directory`]).
//!
//! | task | authority (read now) |
//! |---|---|
//! | `fields/list/0.1` | an active member or an administrator; retired fields to `vtc.directory.admin` only |
//! | `fields/{define,update,retire}/0.1` | `vtc.directory.admin` (a console key acts for its administrator); a widening update parks for the other holders (VTI-DIR-024) |
//! | `card/{show,update}/0.1` | being the member: the signer's own active membership, never a console key |
//! | `card/assert/0.1` | `vtc.directory.admin` |
//! | `entries/{list,show}/0.1` | an active member or an administrator, each entry projected for them |
//! | `query/0.1` | as `entries/show`, answered through the same projection (`community_tasks`) |
//! | `disclosure/0.1` | anyone the join manifest answers: the statement is what an applicant reads before applying (VTI-DIR-130) |
//!
//! None has a REST route. Each arrives the same way over TSP, DIDComm or
//! HTTPS.
//!
//! # The member portal's key
//!
//! The member tasks (`fields/list`, `card/*` but `assert`, `entries/*`) also
//! accept a document signed by a member-portal sign-in key the member
//! delegated `vtc/directory` to (`auth/oob/grant/0.2`,
//! [`crate::member_portal::delegation`]), read as the member's. Such a key can
//! never make a value `public` or publish the card beyond the community
//! ([`Writer::Delegated`]).

use std::collections::BTreeMap;

use chrono::Utc;
use serde_json::{Value, json};
use trust_tasks_rs::specs::vtc::directory::{
    card::{assert::v0_1 as card_assert, show::v0_1 as card_show, update::v0_1 as card_update},
    disclosure::v0_1 as disclosure,
    entries::{list::v0_1 as entries_list, show::v0_1 as entries_show},
    fields::{
        define::v0_1 as fields_define, list::v0_1 as fields_list, retire::v0_1 as fields_retire,
        update::v0_1 as fields_update,
    },
};
use trust_tasks_rs::{Payload, RejectReason, TrustTask};
use vti_common::audit::{AuditEvent, DirectoryCardChangedData, DirectoryFieldChangedData};
use vti_common::auth::extractor::AuthClaims;
use vti_common::error::AppError;

use super::admin_tasks::member_signer;
use super::helpers::{
    TrustTaskOutcome, app_error_to_reject, extended_code, reject_with, reject_with_code,
    success_response,
};
use super::{JoinAuthCtx, capable_signer, parse_spec_payload};
use crate::acl::Capability;
use crate::directory::cards::{self, CardError, MemberUpdate, Writer};
use crate::directory::fields::{self, FieldError};
use crate::directory::model::FieldState;
use crate::directory::project::Viewer;
use crate::directory::read::{self, ListError, ListQuery, ShowBy, ShowError};
use crate::directory::write_policy::{self, WriteFacts};
use crate::policy::model::PolicyPurpose;
use crate::server::AppState;

pub(crate) const FIELDS_LIST_TYPE: &str = <fields_list::Payload as Payload>::TYPE_URI;
pub(crate) const FIELDS_DEFINE_TYPE: &str = <fields_define::Payload as Payload>::TYPE_URI;
pub(crate) const FIELDS_UPDATE_TYPE: &str = <fields_update::Payload as Payload>::TYPE_URI;
pub(crate) const FIELDS_RETIRE_TYPE: &str = <fields_retire::Payload as Payload>::TYPE_URI;
pub(crate) const CARD_SHOW_TYPE: &str = <card_show::Payload as Payload>::TYPE_URI;
pub(crate) const CARD_UPDATE_TYPE: &str = <card_update::Payload as Payload>::TYPE_URI;
pub(crate) const CARD_ASSERT_TYPE: &str = <card_assert::Payload as Payload>::TYPE_URI;
pub(crate) const ENTRIES_LIST_TYPE: &str = <entries_list::Payload as Payload>::TYPE_URI;
pub(crate) const ENTRIES_SHOW_TYPE: &str = <entries_show::Payload as Payload>::TYPE_URI;
pub(crate) const DISCLOSURE_TYPE: &str = <disclosure::Payload as Payload>::TYPE_URI;

/// Exactly what [`dispatch`] routes.
pub(crate) const URIS: &[&str] = &[
    FIELDS_LIST_TYPE,
    FIELDS_DEFINE_TYPE,
    FIELDS_UPDATE_TYPE,
    FIELDS_RETIRE_TYPE,
    CARD_SHOW_TYPE,
    CARD_UPDATE_TYPE,
    CARD_ASSERT_TYPE,
    ENTRIES_LIST_TYPE,
    ENTRIES_SHOW_TYPE,
    DISCLOSURE_TYPE,
];

// ─── the codes these tasks declare, as the error-code census witnesses them ─

macro_rules! codes {
    ($($name:ident = $module:ident :: $code:ident;)*) => {
        $(pub(crate) const $name: &str = $module::error_codes::$code.code;)*
    };
}

codes! {
    DEFINE_ERR_FIELD_EXISTS = fields_define::FIELD_EXISTS;
    DEFINE_ERR_RESERVED_KEY = fields_define::RESERVED_KEY;
    DEFINE_ERR_ABOVE_CEILING = fields_define::ABOVE_CEILING;
    DEFINE_ERR_VALUE_INVALID = fields_define::VALUE_INVALID;
    DEFINE_ERR_TOO_MANY_FIELDS = fields_define::TOO_MANY_FIELDS;
    UPDATE_ERR_FIELD_UNKNOWN = fields_update::FIELD_UNKNOWN;
    UPDATE_ERR_FIELD_RETIRED = fields_update::FIELD_RETIRED;
    UPDATE_ERR_ABOVE_CEILING = fields_update::ABOVE_CEILING;
    UPDATE_ERR_VALUE_INVALID = fields_update::VALUE_INVALID;
    RETIRE_ERR_FIELD_UNKNOWN = fields_retire::FIELD_UNKNOWN;
    RETIRE_ERR_FIELD_RETIRED = fields_retire::FIELD_RETIRED;
    RETIRE_ERR_BASE_FIELD = fields_retire::BASE_FIELD;
    CARD_SHOW_ERR_NOT_MEMBER = card_show::NOT_MEMBER;
    CARD_UPDATE_ERR_NOT_MEMBER = card_update::NOT_MEMBER;
    CARD_UPDATE_ERR_SUPERSEDED = card_update::SUPERSEDED;
    CARD_UPDATE_ERR_FIELD_UNKNOWN = card_update::FIELD_UNKNOWN;
    CARD_UPDATE_ERR_FIELD_RETIRED = card_update::FIELD_RETIRED;
    CARD_UPDATE_ERR_FIELD_NOT_WRITABLE = card_update::FIELD_NOT_WRITABLE;
    CARD_UPDATE_ERR_VALUE_INVALID = card_update::VALUE_INVALID;
    CARD_UPDATE_ERR_VALUE_REFUSED = card_update::VALUE_REFUSED;
    CARD_UPDATE_ERR_ABOVE_CEILING = card_update::ABOVE_CEILING;
    CARD_UPDATE_ERR_NOT_AVAILABLE = card_update::NOT_AVAILABLE;
    ASSERT_ERR_NOT_FOUND = card_assert::NOT_FOUND;
    ASSERT_ERR_FIELD_UNKNOWN = card_assert::FIELD_UNKNOWN;
    ASSERT_ERR_FIELD_RETIRED = card_assert::FIELD_RETIRED;
    ASSERT_ERR_FIELD_NOT_WRITABLE = card_assert::FIELD_NOT_WRITABLE;
    ASSERT_ERR_VALUE_INVALID = card_assert::VALUE_INVALID;
    ASSERT_ERR_VALUE_REFUSED = card_assert::VALUE_REFUSED;
    LIST_ERR_QUERY_TOO_SHORT = entries_list::QUERY_TOO_SHORT;
    LIST_ERR_CURSOR_INVALID = entries_list::CURSOR_INVALID;
    LIST_ERR_NOT_FOUND = entries_list::NOT_FOUND;
    LIST_ERR_RATE_LIMITED = entries_list::RATE_LIMITED;
    SHOW_ERR_NOT_FOUND = entries_show::NOT_FOUND;
}

pub(super) async fn dispatch(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
    type_uri: &str,
) -> Option<TrustTaskOutcome> {
    Some(match type_uri {
        FIELDS_LIST_TYPE => handle_fields_list(state, ctx, doc).await,
        FIELDS_DEFINE_TYPE => handle_fields_define(state, ctx, doc).await,
        FIELDS_UPDATE_TYPE => handle_fields_update(state, ctx, doc).await,
        FIELDS_RETIRE_TYPE => handle_fields_retire(state, ctx, doc).await,
        CARD_SHOW_TYPE => handle_card_show(state, ctx, doc).await,
        CARD_UPDATE_TYPE => handle_card_update(state, ctx, doc).await,
        CARD_ASSERT_TYPE => handle_card_assert(state, ctx, doc).await,
        ENTRIES_LIST_TYPE => handle_entries_list(state, ctx, doc).await,
        ENTRIES_SHOW_TYPE => handle_entries_show(state, ctx, doc).await,
        DISCLOSURE_TYPE => handle_disclosure(state, ctx, doc).await,
        _ => return None,
    })
}

// ─── shared ───────────────────────────────────────────────────────────────

fn declared(doc: &TrustTask<Value>, code: &str, message: impl Into<String>) -> TrustTaskOutcome {
    reject_with_code(doc, extended_code(code), message, None)
}

fn declared_with(
    doc: &TrustTask<Value>,
    code: &str,
    message: impl Into<String>,
    details: Value,
) -> TrustTaskOutcome {
    reject_with_code(doc, extended_code(code), message, Some(details))
}

fn denied(doc: &TrustTask<Value>, why: &str) -> TrustTaskOutcome {
    reject_with(
        doc,
        RejectReason::PermissionDenied {
            reason: why.to_string(),
        },
    )
}

/// The signer as a directory viewer: a console key reads as the administrator
/// it acts for, anyone else as themselves.
async fn reader<P>(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: &TrustTask<Value>,
) -> Result<(Viewer, P), TrustTaskOutcome>
where
    P: trust_tasks_rs::validate::ValidatedPayload + serde::de::DeserializeOwned,
{
    let did = match delegated(state, ctx, doc).await? {
        Some(member) => member,
        None => member_signer(state, ctx, doc).await?.did,
    };
    let payload = parse_spec_payload::<P>(doc)?;
    let viewer = read::viewer(state, &did)
        .await
        .map_err(|e| app_error_to_reject(doc, &e))?;
    if !viewer.may_read() {
        return Err(denied(
            doc,
            "the directory is read by this community's active members and administrators",
        ));
    }
    Ok((viewer, payload))
}

/// The member a portal sign-in key signs as, when the signer is one whose
/// delegation covers this task and whose session is live. `None` for every
/// other signer, who is then authorized as themselves.
async fn delegated(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: &TrustTask<Value>,
) -> Result<Option<String>, TrustTaskOutcome> {
    let Some(signer) = ctx.verified_signer.as_deref() else {
        return Ok(None);
    };
    crate::member_portal::delegation::member_for(
        &state.member_sessions_ks,
        signer,
        &doc.type_uri.to_string(),
    )
    .await
    .map_err(|e| app_error_to_reject(doc, &e))
}

/// The proven signer, who must be an active member — the card tasks' whole
/// entitlement — and how they signed: as themselves, or through the portal
/// key they delegated. A console key is not the member: it acts for an
/// administrator, and a card is never written for its member by anyone else.
async fn as_card_member(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: &TrustTask<Value>,
    not_member: &str,
) -> Result<(crate::member_portal::active::ActiveMember, Writer), TrustTaskOutcome> {
    let Some(signer) = ctx.verified_signer.clone() else {
        return Err(reject_with(doc, RejectReason::ProofRequired));
    };
    let (did, writer) = match delegated(state, ctx, doc).await? {
        Some(member) => (member, Writer::Delegated),
        None => (signer, Writer::Member),
    };
    match crate::member_portal::active::active_member(state, &did).await {
        Ok(Some(m)) => Ok((m, writer)),
        Ok(None) => Err(declared(
            doc,
            not_member,
            "the signer is not an active member of this community",
        )),
        Err(e) => Err(app_error_to_reject(doc, &e)),
    }
}

/// The audit writer, or a refusal: a directory write is never unaudited.
fn writer(state: &AppState) -> Result<&vti_common::audit::AuditWriter, AppError> {
    state
        .audit_writer
        .as_ref()
        .ok_or_else(|| AppError::ServiceError {
            status: axum::http::StatusCode::SERVICE_UNAVAILABLE,
            message: "audit writer not configured: directory changes are refused rather than \
                      made unaudited"
                .into(),
        })
}

async fn audit_field(
    state: &AppState,
    actor: &AuthClaims,
    key: &str,
    change: &str,
    widens: bool,
    reason: Option<&str>,
) -> Result<(), AppError> {
    writer(state)?
        .write(
            &actor.did,
            None,
            AuditEvent::DirectoryFieldChanged(DirectoryFieldChangedData {
                key: key.to_string(),
                change: change.to_string(),
                widens,
                reason: reason.map(str::to_string),
            }),
        )
        .await
        .map(drop)
}

async fn audit_card(
    state: &AppState,
    actor: &AuthClaims,
    entry_id: &str,
    by: &str,
    fields: &[String],
    revision: u64,
) -> Result<(), AppError> {
    writer(state)?
        .write(
            &actor.did,
            None,
            AuditEvent::DirectoryCardChanged(DirectoryCardChangedData {
                entry_id: entry_id.to_string(),
                by: by.to_string(),
                fields: fields.to_vec(),
                revision,
            }),
        )
        .await
        .map(drop)
}

fn reason_of(doc: &TrustTask<Value>) -> Option<String> {
    doc.payload
        .get("reason")
        .and_then(Value::as_str)
        .map(str::to_string)
}

// ─── fields ───────────────────────────────────────────────────────────────

/// `fields/list/0.1`: the schema as the caller may see it (items 2 – 4).
async fn handle_fields_list(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let (viewer, payload) = match reader::<fields_list::Payload>(state, ctx, &doc).await {
        Ok(v) => v,
        Err(reject) => return reject,
    };
    let include_retired = viewer.directory_admin && payload.include_retired == Some(true);
    let schema = match fields::schema(state.directory.ks()).await {
        Ok(s) => s,
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    let shown: Vec<_> = schema
        .into_iter()
        .filter(|f| include_retired || f.state != FieldState::Retired)
        .collect();
    success_response(
        &doc,
        json!({
            "fields": shown,
            "listingDefaults": {
                "defaultListing": state.directory.settings().default_listing.as_str(),
            },
        }),
    )
}

/// `vtc/directory/disclosure/0.1`: the statement of what the directory
/// discloses, and to whom, generated now
/// ([`crate::directory::disclosure::statement`]).
///
/// Answered to every reader the join manifest is answered to, and refused on
/// exactly the same terms ([`super::discovery_refusal`]): an applicant who can
/// read the criteria can read the statement.
async fn handle_disclosure(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    if let Err(reject) = parse_spec_payload::<disclosure::Payload>(&doc) {
        return reject;
    }
    if let Some(refusal) = super::discovery_refusal(state, ctx, &doc).await {
        return refusal;
    }
    let community_did = state
        .config
        .read()
        .await
        .vtc_did
        .clone()
        .filter(|d| !d.is_empty());
    let Some(community_did) = community_did else {
        return app_error_to_reject(&doc, &AppError::Internal("VTC DID not configured".into()));
    };
    match crate::directory::disclosure::statement(&state.directory).await {
        Ok(statement) => success_response(
            &doc,
            json!({ "communityDid": community_did, "disclosure": statement }),
        ),
        Err(e) => app_error_to_reject(&doc, &e),
    }
}

fn field_error(doc: &TrustTask<Value>, task: &str, e: FieldError) -> TrustTaskOutcome {
    use FieldError as E;
    // The code each task declares for each refusal. A refusal a task cannot
    // produce has none, and is a fault here, never a borrowed code.
    let code: Option<&'static str> = match (task, &e) {
        ("define", E::FieldExists) => Some(DEFINE_ERR_FIELD_EXISTS),
        ("define", E::ReservedKey) => Some(DEFINE_ERR_RESERVED_KEY),
        ("define", E::TooManyFields) => Some(DEFINE_ERR_TOO_MANY_FIELDS),
        ("define", E::AboveCeiling) => Some(DEFINE_ERR_ABOVE_CEILING),
        ("define", E::ValueInvalid { .. }) => Some(DEFINE_ERR_VALUE_INVALID),
        ("update", E::AboveCeiling) => Some(UPDATE_ERR_ABOVE_CEILING),
        ("update", E::ValueInvalid { .. }) => Some(UPDATE_ERR_VALUE_INVALID),
        ("update", E::FieldUnknown) => Some(UPDATE_ERR_FIELD_UNKNOWN),
        ("update", E::FieldRetired) => Some(UPDATE_ERR_FIELD_RETIRED),
        ("retire", E::FieldUnknown) => Some(RETIRE_ERR_FIELD_UNKNOWN),
        ("retire", E::FieldRetired) => Some(RETIRE_ERR_FIELD_RETIRED),
        ("retire", E::BaseField) => Some(RETIRE_ERR_BASE_FIELD),
        _ => None,
    };
    let Some(code) = code else {
        return app_error_to_reject(
            doc,
            &AppError::Internal(format!(
                "fields/{task} refused with {e:?}, which it never declares"
            )),
        );
    };
    match e {
        E::FieldExists => declared(
            doc,
            code,
            "a field with this key exists or existed; a key is never reused",
        ),
        E::ReservedKey => declared(
            doc,
            code,
            "keys without a dot are reserved to the base fields",
        ),
        E::TooManyFields => declared(
            doc,
            code,
            "this community already has 64 active community fields",
        ),
        E::AboveCeiling => declared(
            doc,
            code,
            "the default visibility is wider than the ceiling",
        ),
        E::ValueInvalid { field, reason } => declared_with(
            doc,
            code,
            format!("{field}: {reason}"),
            json!({ "field": field, "reason": reason }),
        ),
        E::FieldUnknown => declared(doc, code, "no field has this key"),
        E::FieldRetired => declared(doc, code, "the field is retired"),
        E::BaseField => declared(
            doc,
            code,
            "a base field is disabled with fields/update, never retired",
        ),
    }
}

/// `fields/define/0.1` (items 1 – 5).
async fn handle_fields_define(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let actor = match capable_signer(state, ctx, &doc, Capability::DirectoryAdmin, None).await {
        Ok(a) => a,
        Err(reject) => return reject,
    };
    if let Err(reject) = parse_spec_payload::<fields_define::Payload>(&doc) {
        return reject;
    }
    let input = doc.payload.get("field").cloned().unwrap_or(Value::Null);
    let key = input
        .get("key")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    // Audited before the write, so a field never exists without its record.
    // A refusal below leaves an audit row for an attempt that did not land,
    // which is the safe side of the two.
    if let Err(e) = audit_field(
        state,
        &actor,
        &key,
        "define",
        false,
        reason_of(&doc).as_deref(),
    )
    .await
    {
        return app_error_to_reject(&doc, &e);
    }
    match fields::define(state.directory.ks(), &input, Utc::now()).await {
        Ok(field) => success_response(&doc, json!({ "field": field })),
        Err(e) => field_error(&doc, "define", e),
    }
}

/// `fields/update/0.1` (items 1 – 6). A widening is held for the other
/// holders of `vtc.directory.admin`, re-run on the last approval against the
/// field as it is then (VTI-DIR-024, VTI-APV-017).
async fn handle_fields_update(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let actor = match capable_signer(state, ctx, &doc, Capability::DirectoryAdmin, None).await {
        Ok(a) => a,
        Err(reject) => return reject,
    };
    if let Err(reject) = parse_spec_payload::<fields_update::Payload>(&doc) {
        return reject;
    }
    let change = match fields::plan_update(state.directory.ks(), &doc.payload, Utc::now()).await {
        Ok(c) => c,
        Err(e) => return field_error(&doc, "update", e),
    };
    if change.changes_nothing() {
        return success_response(&doc, json!({ "field": change.before }));
    }
    let widens = change.widens();
    if widens {
        let key = &change.after.key;
        if let Err(outcome) = super::acl_tasks::settle_consent_gate(
            state,
            &actor,
            &doc,
            crate::acl::admin_consent::Act::ChangeDirectoryPrivacy,
            key,
            &format!("Widen the directory field {key}"),
            &format!(
                "Widen what members' values in the directory field {key} may reach: it is \
                 shown, searched or counted more widely than members were promised when they \
                 filled it in"
            ),
        )
        .await
        {
            return outcome;
        }
    }
    if let Err(e) = audit_field(
        state,
        &actor,
        &change.after.key,
        "update",
        widens,
        reason_of(&doc).as_deref(),
    )
    .await
    {
        return app_error_to_reject(&doc, &e);
    }
    match fields::store_update(state.directory.ks(), &change).await {
        Ok(true) => success_response(&doc, json!({ "field": change.after })),
        Ok(false) => app_error_to_reject(
            &doc,
            &AppError::Conflict(
                "the field changed while this update was decided; read it and send the update \
                 again"
                    .into(),
            ),
        ),
        Err(e) => app_error_to_reject(&doc, &e),
    }
}

/// `fields/retire/0.1` (items 1 – 5). The purge itself is the sweeper's
/// ([`crate::directory::read`] never shows a retired field meanwhile).
async fn handle_fields_retire(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let actor = match capable_signer(state, ctx, &doc, Capability::DirectoryAdmin, None).await {
        Ok(a) => a,
        Err(reject) => return reject,
    };
    let payload = match parse_spec_payload::<fields_retire::Payload>(&doc) {
        Ok(p) => p,
        Err(reject) => return reject,
    };
    let key = payload.key.to_string();
    // The refusals first, so the audit row records only a retirement that
    // will land.
    match fields::get(state.directory.ks(), &key).await {
        Ok(None) => return field_error(&doc, "retire", FieldError::FieldUnknown),
        Ok(Some(f)) if f.base => return field_error(&doc, "retire", FieldError::BaseField),
        Ok(Some(f)) if f.state == FieldState::Retired => {
            return field_error(&doc, "retire", FieldError::FieldRetired);
        }
        Ok(Some(_)) => {}
        Err(e) => return app_error_to_reject(&doc, &e),
    }
    if let Err(e) = audit_field(
        state,
        &actor,
        &key,
        "retire",
        false,
        reason_of(&doc).as_deref(),
    )
    .await
    {
        return app_error_to_reject(&doc, &e);
    }
    match fields::retire(
        state.directory.ks(),
        &key,
        state.directory.settings().retention_days,
        Utc::now(),
    )
    .await
    {
        Ok(field) => success_response(&doc, json!({ "field": field })),
        Err(e) => field_error(&doc, "retire", e),
    }
}

// ─── cards ────────────────────────────────────────────────────────────────

/// `card/show/0.1` (items 1 – 3).
async fn handle_card_show(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let (member, _) = match as_card_member(state, ctx, &doc, CARD_SHOW_ERR_NOT_MEMBER).await {
        Ok(m) => m,
        Err(reject) => return reject,
    };
    if let Err(reject) = parse_spec_payload::<card_show::Payload>(&doc) {
        return reject;
    }
    let own = member
        .entry
        .label_set_by_subject
        .then(|| member.entry.label.clone())
        .flatten();
    let card = match cards::ensure(
        state.directory.ks(),
        &member.member.did,
        &state.directory.settings(),
        own.as_deref(),
    )
    .await
    {
        Ok(c) => c,
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    let schema = match fields::schema(state.directory.ks()).await {
        Ok(s) => s,
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    success_response(
        &doc,
        json!({
            "card": card.wire(),
            "missingRequired": cards::missing_required(&card, &schema),
        }),
    )
}

fn card_error(doc: &TrustTask<Value>, e: CardError) -> TrustTaskOutcome {
    match e {
        CardError::Superseded { revision } => declared_with(
            doc,
            CARD_UPDATE_ERR_SUPERSEDED,
            "a change to this card issued after this document is already applied, or \
             expectedRevision does not match",
            json!({ "revision": revision }),
        ),
        CardError::FieldUnknown(field) => declared_with(
            doc,
            CARD_UPDATE_ERR_FIELD_UNKNOWN,
            format!("the directory has no field {field}"),
            json!({ "field": field }),
        ),
        CardError::FieldRetired(field) => declared_with(
            doc,
            CARD_UPDATE_ERR_FIELD_RETIRED,
            format!("the field {field} is retired or disabled"),
            json!({ "field": field }),
        ),
        CardError::FieldNotWritable(field) => declared_with(
            doc,
            CARD_UPDATE_ERR_FIELD_NOT_WRITABLE,
            format!("{field} is not written by the member"),
            json!({ "field": field }),
        ),
        CardError::ValueInvalid { field, reason } => declared_with(
            doc,
            CARD_UPDATE_ERR_VALUE_INVALID,
            format!("{field}: {reason}"),
            json!({ "field": field, "reason": reason }),
        ),
        CardError::AboveCeiling { field, ceiling } => declared_with(
            doc,
            CARD_UPDATE_ERR_ABOVE_CEILING,
            format!(
                "{field} can be shown to {} at most in this community",
                ceiling.as_str()
            ),
            json!({ "field": field, "ceiling": ceiling.as_str() }),
        ),
        CardError::NotAvailable => declared(
            doc,
            CARD_UPDATE_ERR_NOT_AVAILABLE,
            "this community cannot publish external cards yet; nothing was changed",
        ),
        CardError::NeedsMembershipDid => denied(
            doc,
            "making a value public must be signed by the membership DID itself, not a \
             delegated key",
        ),
    }
}

/// Other members' nicknames, for a `directoryWrite` policy that makes them
/// unique.
async fn other_nicknames(state: &AppState, entry_id: &str) -> Result<Vec<String>, AppError> {
    Ok(cards::all(state.directory.ks())
        .await?
        .into_iter()
        .filter(|c| c.entry_id != entry_id)
        .filter_map(|c| {
            c.values
                .get("nickname")
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .collect())
}

/// `card/update/0.1` (items 1 – 9).
async fn handle_card_update(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let (member, writer) = match as_card_member(state, ctx, &doc, CARD_UPDATE_ERR_NOT_MEMBER).await
    {
        Ok(m) => m,
        Err(reject) => return reject,
    };
    if let Err(reject) = parse_spec_payload::<card_update::Payload>(&doc) {
        return reject;
    }
    let update = match MemberUpdate::from_payload(&doc.payload) {
        Ok(u) => u,
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    // The spine refuses a document without one (`issuedAtRequirement`).
    let Some(issued_at) = doc.issued_at else {
        return app_error_to_reject(
            &doc,
            &AppError::Validation("card/update needs issuedAt".into()),
        );
    };
    let did = member.member.did.clone();
    let actor = AuthClaims {
        did: did.clone(),
        ..Default::default()
    };
    let dir = &state.directory;
    let own = member
        .entry
        .label_set_by_subject
        .then(|| member.entry.label.clone())
        .flatten();

    // A concurrent write to the same card is applied after, not lost: read,
    // apply and commit again.
    for _ in 0..3 {
        let card = match cards::ensure(dir.ks(), &did, &dir.settings(), own.as_deref()).await {
            Ok(c) => c,
            Err(e) => return app_error_to_reject(&doc, &e),
        };
        let schema = match fields::schema(dir.ks()).await {
            Ok(s) => s,
            Err(e) => return app_error_to_reject(&doc, &e),
        };
        let applied = match cards::apply_member_update(
            &card,
            &schema,
            &update,
            writer,
            &doc.id,
            issued_at,
            Utc::now(),
        ) {
            Ok(a) => a,
            Err(e) => return card_error(&doc, e),
        };
        // External publication needs recognition consent too (item 7); this
        // build refuses it outright above, so nothing reaches here asking.
        if applied.widens {
            match judge(state, &doc, &actor, &member.entry, &applied, "update").await {
                Ok(None) => {}
                Ok(Some(refusal)) => {
                    return declared_with(
                        &doc,
                        CARD_UPDATE_ERR_VALUE_REFUSED,
                        refusal.message.clone(),
                        json!({
                            "field": refusal.field.clone().unwrap_or_else(|| applied.changed.first().cloned().unwrap_or_default()),
                            "message": refusal.message,
                        }),
                    );
                }
                Err(e) => return app_error_to_reject(&doc, &e),
            }
        }
        if let Err(e) = audit_card(
            state,
            &actor,
            &applied.card.entry_id,
            "member",
            &applied.changed,
            applied.card.revision,
        )
        .await
        {
            return app_error_to_reject(&doc, &e);
        }
        match cards::commit(dir.ks(), &card, &applied).await {
            Ok(true) => {
                return success_response(
                    &doc,
                    json!({
                        "card": applied.card.wire(),
                        "missingRequired": cards::missing_required(&applied.card, &schema),
                    }),
                );
            }
            Ok(false) => continue,
            Err(e) => return app_error_to_reject(&doc, &e),
        }
    }
    app_error_to_reject(
        &doc,
        &AppError::Conflict(
            "the card kept changing while this update was applied; send it again".into(),
        ),
    )
}

async fn judge(
    state: &AppState,
    _doc: &TrustTask<Value>,
    actor: &AuthClaims,
    entry: &crate::acl::VtcAclEntry,
    applied: &cards::Applied,
    operation: &'static str,
) -> Result<Option<write_policy::Refusal>, AppError> {
    let policy = crate::policy::load_active_compiled(
        &state.active_policies_ks,
        &state.policies_ks,
        PolicyPurpose::DirectoryWrite,
    )
    .await?;
    let role = entry.role.to_string();
    let facts = WriteFacts {
        operation,
        now: Utc::now(),
        actor_did: &actor.did,
        actor_role: Some(&role),
        actor_directory_admin: entry.can(Capability::DirectoryAdmin, None),
        card: &applied.card,
        changed: &applied.changed,
        other_nicknames: other_nicknames(state, &applied.card.entry_id).await?,
    };
    write_policy::judge(&policy, &facts)
}

/// `card/assert/0.1` (items 1 – 6).
async fn handle_card_assert(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let actor = match capable_signer(state, ctx, &doc, Capability::DirectoryAdmin, None).await {
        Ok(a) => a,
        Err(reject) => return reject,
    };
    let payload = match parse_spec_payload::<card_assert::Payload>(&doc) {
        Ok(p) => p,
        Err(reject) => return reject,
    };
    let entry_id = payload.entry_id.to_string();
    let values: BTreeMap<String, Option<Value>> = doc
        .payload
        .get("values")
        .and_then(Value::as_object)
        .map(|m| {
            m.iter()
                .map(|(k, v)| (k.clone(), (!v.is_null()).then(|| v.clone())))
                .collect()
        })
        .unwrap_or_default();
    let not_found = |doc: &TrustTask<Value>| {
        declared(doc, ASSERT_ERR_NOT_FOUND, "no active member has this entry")
    };
    let actor_entry = match crate::acl::get_acl_entry(&state.acl_ks, &actor.did).await {
        Ok(Some(e)) => e,
        Ok(None) => return denied(&doc, "the signer holds no entry in this community"),
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    let dir = &state.directory;
    for _ in 0..3 {
        let card = match cards::get(dir.ks(), &entry_id).await {
            Ok(Some(c)) => c,
            Ok(None) => return not_found(&doc),
            Err(e) => return app_error_to_reject(&doc, &e),
        };
        match crate::member_portal::active::active_member(state, &card.did).await {
            Ok(Some(_)) => {}
            Ok(None) => return not_found(&doc),
            Err(e) => return app_error_to_reject(&doc, &e),
        }
        let schema = match fields::schema(dir.ks()).await {
            Ok(s) => s,
            Err(e) => return app_error_to_reject(&doc, &e),
        };
        let applied = match cards::apply_assertion(&card, &schema, &values, Utc::now()) {
            Ok(a) => a,
            Err(e) => return assert_error(&doc, e),
        };
        match judge(state, &doc, &actor, &actor_entry, &applied, "assert").await {
            Ok(None) => {}
            Ok(Some(refusal)) => {
                let mut details = json!({ "message": refusal.message });
                if let Some(f) = refusal.field {
                    details["field"] = json!(f);
                }
                return declared_with(&doc, ASSERT_ERR_VALUE_REFUSED, refusal.message, details);
            }
            Err(e) => return app_error_to_reject(&doc, &e),
        }
        if let Err(e) = audit_card(
            state,
            &actor,
            &entry_id,
            "admin",
            &applied.changed,
            applied.card.revision,
        )
        .await
        {
            return app_error_to_reject(&doc, &e);
        }
        match cards::commit(dir.ks(), &card, &applied).await {
            // Item 6: only which fields were written, never the card.
            Ok(true) => {
                return success_response(
                    &doc,
                    json!({
                        "entryId": entry_id,
                        "written": applied.changed,
                        "revision": applied.card.revision,
                    }),
                );
            }
            Ok(false) => continue,
            Err(e) => return app_error_to_reject(&doc, &e),
        }
    }
    app_error_to_reject(
        &doc,
        &AppError::Conflict("the card kept changing while this assertion was applied".into()),
    )
}

fn assert_error(doc: &TrustTask<Value>, e: CardError) -> TrustTaskOutcome {
    match e {
        CardError::FieldUnknown(field) => declared_with(
            doc,
            ASSERT_ERR_FIELD_UNKNOWN,
            format!("the directory has no field {field}"),
            json!({ "field": field }),
        ),
        CardError::FieldRetired(field) => declared_with(
            doc,
            ASSERT_ERR_FIELD_RETIRED,
            format!("the field {field} is retired or disabled"),
            json!({ "field": field }),
        ),
        CardError::FieldNotWritable(field) => declared_with(
            doc,
            ASSERT_ERR_FIELD_NOT_WRITABLE,
            format!("{field} is not administrator-asserted"),
            json!({ "field": field }),
        ),
        CardError::ValueInvalid { field, reason } => declared_with(
            doc,
            ASSERT_ERR_VALUE_INVALID,
            format!("{field}: {reason}"),
            json!({ "field": field, "reason": reason }),
        ),
        // An assertion names no visibility, discoverability or revision.
        other => app_error_to_reject(doc, &AppError::Internal(format!("assertion: {other:?}"))),
    }
}

// ─── entries ──────────────────────────────────────────────────────────────

/// `entries/list/0.1` (items 1 – 9).
async fn handle_entries_list(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let (viewer, _payload) = match reader::<entries_list::Payload>(state, ctx, &doc).await {
        Ok(v) => v,
        Err(reject) => return reject,
    };
    let query = ListQuery::from_payload(&doc.payload);
    match read::list(state, &viewer, &query).await {
        Ok(body) => success_response(&doc, body),
        Err(ListError::PermissionDenied) => denied(
            &doc,
            "the directory is read by this community's active members and administrators",
        ),
        Err(ListError::QueryTooShort) => declared(
            &doc,
            LIST_ERR_QUERY_TOO_SHORT,
            "a search needs at least three characters, or a whole nickname",
        ),
        Err(ListError::CursorInvalid) => declared(
            &doc,
            LIST_ERR_CURSOR_INVALID,
            "this cursor was not issued for this caller and this question",
        ),
        Err(ListError::NotFound) => declared(&doc, LIST_ERR_NOT_FOUND, "no such group"),
        Err(ListError::RateLimited) => reject_with_code(
            &doc,
            extended_code(LIST_ERR_RATE_LIMITED),
            "too many directory reads; try again in a minute",
            None,
        ),
        Err(ListError::Internal(e)) => app_error_to_reject(&doc, &e),
    }
}

/// `entries/show/0.1` (items 1 – 4).
async fn handle_entries_show(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let (viewer, _payload) = match reader::<entries_show::Payload>(state, ctx, &doc).await {
        Ok(v) => v,
        Err(reject) => return reject,
    };
    let by = match (
        doc.payload.get("entryId").and_then(Value::as_str),
        doc.payload.get("did").and_then(Value::as_str),
    ) {
        (Some(id), None) => ShowBy::Entry(id.to_string()),
        (None, Some(did)) => ShowBy::Did(did.to_string()),
        _ => {
            return reject_with(
                &doc,
                RejectReason::MalformedRequest {
                    reason: "name exactly one of entryId and did".into(),
                },
            );
        }
    };
    match read::show(state, &viewer, &by).await {
        Ok(body) => success_response(&doc, body),
        Err(ShowError::PermissionDenied) => denied(
            &doc,
            "an entry is addressed by DID only by those who administer membership",
        ),
        // One code, one message, whatever the cause (item 3).
        Err(ShowError::NotFound) => declared(&doc, SHOW_ERR_NOT_FOUND, "No such entry."),
        Err(ShowError::Internal(e)) => app_error_to_reject(&doc, &e),
    }
}
