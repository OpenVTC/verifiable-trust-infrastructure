//! `GET /v1/members/{did}/credentials` — the membership pair's **bodies** for
//! one member (`vtc/members/credentials/0.1`, #1215).
//!
//! `members/show/0.1` answers "who is a member" with identifiers; its response
//! is `additionalProperties: false` and says outright that the credential body
//! is not echoed there. This is the read that answers "what did we issue this
//! member, and what did they acknowledge": the community-issued grant, the
//! role VEC, and the member-issued acknowledgement, plus whether that
//! acknowledgement's digest was verified against the grant.
//!
//! Reads the four fields #1213 already keeps on the member row
//! (`current_vmc`, `current_role_vec`, `member_vmc`, `member_vmc_bound`). No
//! new storage and no new verification: `memberVmcBound` is the answer
//! recorded at receipt, deliberately not recomputed (see
//! [`crate::members::Member::member_vmc_bound`]).
//!
//! The response type is the generated `specs::vtc::members::credentials::v0_1`
//! one, documented through its `vta_sdk::openapi` wrapper — never a local
//! mirror of it.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::{Map, Value as JsonValue};
use trust_tasks_rs::specs::vtc::members::credentials::v0_1 as wire;
use vta_sdk::openapi::MemberCredentials01Response;
use vti_common::audit::{AuditEvent, MemberCredentialsReadData};

use crate::acl::get_acl_entry;
use crate::auth::AdminAuth;
use crate::error::AppError;
use crate::members::{Member, get_member};
use crate::server::AppState;

/// The one error code `vtc/members/credentials/0.1` declares: no member with
/// the supplied `did` exists in this community. Distinct, per the
/// specification, from a member who exists and holds no credentials — that is
/// a successful answer with every document absent.
pub const MEMBER_CREDENTIALS_ERR_NOT_FOUND: &str =
    trust_tasks_rs::specs::vtc::members::credentials::v0_1::error_codes::NOT_FOUND.code;

/// Why a lookup produced no answer. Kept apart from [`AppError`] so the
/// not-found case can carry the specification's declared code.
pub enum CredentialsError {
    /// No presentable member with this DID — the declared `notFound`.
    NotFound(String),
    /// Anything else, rendered as the service renders every other error.
    Other(AppError),
}

impl From<AppError> for CredentialsError {
    fn from(e: AppError) -> Self {
        Self::Other(e)
    }
}

impl IntoResponse for CredentialsError {
    fn into_response(self) -> Response {
        match self {
            // Same status and `error` member every other VTC 404 carries, so a
            // client reading the status (`VtaError::from_http`) or the message
            // is unaffected; `code` adds the specification's declared error
            // code for a client that branches on it.
            Self::NotFound(message) => (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({
                    "error": format!("not found: {message}"),
                    "code": MEMBER_CREDENTIALS_ERR_NOT_FOUND,
                })),
            )
                .into_response(),
            Self::Other(e) => e.into_response(),
        }
    }
}

/// Project a stored member row onto the `vtc/members/credentials/0.1`
/// response.
///
/// The single place the row becomes the wire shape — the handler and the
/// conformance witness both go through it, so the witness asserts on what this
/// service actually sends rather than on a transcription of it.
///
/// Bodies are carried as stored. They are opaque to the schema and each
/// carries a proof over its own content, so nothing here rewrites them.
pub(crate) fn credentials_response(member: &Member) -> Result<wire::Response, AppError> {
    let mut builder = wire::Response::builder()
        .did(member.did.as_str())
        .member_vmc_bound(member.member_vmc_bound);

    if let Some(grant) = document(member.current_vmc.as_ref(), "current_vmc", &member.did) {
        builder = builder.membership_credential(grant);
    }
    if let Some(role) = document(
        member.current_role_vec.as_ref(),
        "current_role_vec",
        &member.did,
    ) {
        builder = builder.role_credential(role);
    }

    // `memberVmcReceivedAt` is paired with `memberVmc`: the specification says
    // a maintainer MUST NOT send one without the other. A row written before
    // the body was kept has an id and a receipt time but no body, and the
    // receipt time alone would describe a document this answer cannot
    // produce.
    let acknowledgement = document(member.member_vmc.as_ref(), "member_vmc", &member.did);
    match (acknowledgement, member.member_vmc_received_at) {
        (Some(ack), Some(received_at)) => {
            builder = builder
                .member_vmc(ack)
                .member_vmc_received_at(Some(received_at));
        }
        (Some(_), None) => {
            // `record_member_vmc` stamps both together, so this is a row
            // something else wrote. Sending the body without its pair would
            // break the specification's rule; sending neither is honest about
            // what this row can support, and the log says why.
            tracing::warn!(
                member = %member.did,
                "member VMC body stored without a receipt time; omitted from \
                 members/credentials (the two are paired on the wire)"
            );
        }
        (None, _) => {}
    }

    wire::Response::try_from(builder)
        .map_err(|e| AppError::Internal(format!("members/credentials response: {e}")))
}

/// A stored credential as the response's opaque-object member, or `None` when
/// there is no document to send.
///
/// The schema requires `minProperties: 1`, and the generated type omits an
/// empty map on serialisation — so an empty object and a non-object are both
/// "no document". Neither is a shape any issuance path writes; one reaching
/// here is logged rather than sent as something the schema refuses.
fn document(
    stored: Option<&JsonValue>,
    field: &'static str,
    did: &str,
) -> Option<Map<String, JsonValue>> {
    match stored? {
        JsonValue::Object(map) if !map.is_empty() => Some(map.clone()),
        other => {
            tracing::warn!(
                member = %did,
                field,
                kind = json_kind(other),
                "stored credential is not a non-empty JSON object; omitted from members/credentials"
            );
            None
        }
    }
}

fn json_kind(v: &JsonValue) -> &'static str {
    match v {
        JsonValue::Null => "null",
        JsonValue::Bool(_) => "boolean",
        JsonValue::Number(_) => "number",
        JsonValue::String(_) => "string",
        JsonValue::Array(_) => "array",
        JsonValue::Object(_) => "empty object",
    }
}

/// The wire names of the documents a response carries — what the audit row
/// records instead of the bodies.
fn disclosed(response: &wire::Response) -> Vec<String> {
    let mut out = Vec::new();
    if !response.membership_credential.is_empty() {
        out.push("membershipCredential".to_string());
    }
    if !response.role_credential.is_empty() {
        out.push("roleCredential".to_string());
    }
    if !response.member_vmc.is_empty() {
        out.push("memberVmc".to_string());
    }
    out
}

/// Read one member's credential bodies on behalf of `actor_did`, auditing the
/// disclosure — the whole of the operation, with no transport in it.
///
/// Both doors call this: the bearer REST route below, and the signed-document
/// arm in [`crate::trust_tasks`] (#1641 phase 2). Keeping the body here is what
/// stops the two answering differently — the "is a member" rule, the audit row
/// and the declared not-found are decided once.
///
/// Unknown member → [`CredentialsError::NotFound`], which carries
/// `vtc/members/credentials:notFound` on both surfaces. A member who holds no
/// credentials is **not** that: it is a success with every document absent and
/// `memberVmcBound: false`, which is the case the task exists to make visible.
///
/// "Unknown" is judged exactly as `members/show` judges it — a member row
/// **and** its ACL row. A departed (tombstoned) member keeps a row but not an
/// ACL entry, and tombstoning clears every credential body anyway; answering
/// for one here while `show` says not-found would be two definitions of "is a
/// member" one route apart.
///
/// Every successful read is audited (`MemberCredentialsRead`): the
/// specification says a maintainer SHOULD record it, and a disclosure of
/// credential bodies that leaves no trace cannot be reviewed afterwards. The
/// audit write happens before the bodies are returned — a read that could not
/// be recorded is refused rather than disclosed silently.
pub(crate) async fn read_member_credentials(
    state: &AppState,
    actor_did: &str,
    did: &str,
) -> Result<wire::Response, CredentialsError> {
    vti_common::identifier::validate_did("did", did)?;

    let member = get_member(&state.members_ks, did)
        .await?
        .ok_or_else(|| CredentialsError::NotFound(format!("member not found: {did}")))?;
    if get_acl_entry(&state.acl_ks, did).await?.is_none() {
        return Err(CredentialsError::NotFound(format!(
            "member not found (no ACL row): {did}"
        )));
    }

    let response = credentials_response(&member)?;

    let audit_writer = state
        .audit_writer
        .as_ref()
        .ok_or_else(|| AppError::Internal("audit_writer not initialised".into()))?;
    audit_writer
        .write(
            actor_did,
            Some(did),
            AuditEvent::MemberCredentialsRead(MemberCredentialsReadData {
                disclosed: disclosed(&response),
            }),
        )
        .await?;

    Ok(response)
}

/// GET /members/{did}/credentials — the membership pair's bodies. Auth: Admin.
///
/// Unknown member → 404 carrying `vtc/members/credentials:notFound`. A member
/// who holds no credentials is **not** that: it is a 200 with every document
/// absent and `memberVmcBound: false`, which is the case the task exists to
/// make visible.
///
/// "Unknown" is judged exactly as `members/show` judges it — a member row
/// **and** its ACL row. A departed (tombstoned) member keeps a row but not an
/// ACL entry, and tombstoning clears every credential body anyway; answering
/// for one here while `show` says not-found would be two definitions of "is a
/// member" one route apart.
///
/// Every successful read is audited (`MemberCredentialsRead`): the
/// specification says a maintainer SHOULD record it, and a disclosure of
/// credential bodies that leaves no trace cannot be reviewed afterwards. The
/// audit write happens before the bodies are returned — a read that could not
/// be recorded is refused rather than disclosed silently.
///
/// **Transitional bearer-token path (#1641).** `vtc/members/credentials/0.1`
/// declares `proof` REQUIRED, and the authoritative binding is the signed
/// Trust Task document at `POST /v1/trust-tasks`, where the proof authenticates
/// the administrator and their authority is read from their ACL entry. This
/// route authenticates by bearer JWT and verifies no document proof; it is kept
/// only until the admin console can sign a Trust Task document, and is removed
/// in the same change that gives it that.
#[utoipa::path(
    get, path = "/members/{did}/credentials",
    operation_id = "memberCredentials", tag = "members",
    security(("bearer_jwt" = [])),
    params(("did" = String, Path, description = "Member DID")),
    responses(
        (status = 200, description = "The credential documents the community holds for this member", body = MemberCredentials01Response),
        (status = 400, description = "`did` is not a DID"),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not an admin"),
        (status = 404, description = "No such member (`vtc/members/credentials:notFound`)"),
    ),
)]
pub async fn credentials(
    auth: AdminAuth,
    State(state): State<AppState>,
    Path(did): Path<String>,
) -> Result<Json<MemberCredentials01Response>, CredentialsError> {
    let response = read_member_credentials(&state, &auth.0.did, &did).await?;
    Ok(Json(response.into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const DID: &str = "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH";

    fn vc(id: &str) -> JsonValue {
        json!({ "id": id, "type": ["VerifiableCredential"], "proof": { "proofValue": "z1" } })
    }

    /// A member with no documents is a real answer: every body absent and
    /// `memberVmcBound` stated, not inferred from silence.
    #[test]
    fn a_member_holding_nothing_answers_with_bound_false_and_no_documents() {
        let v = serde_json::to_value(credentials_response(&Member::fresh(DID)).unwrap()).unwrap();
        assert_eq!(v, json!({ "did": DID, "memberVmcBound": false }));
    }

    /// The bodies go out exactly as stored.
    #[test]
    fn bodies_are_carried_as_stored() {
        let mut m = Member::fresh(DID);
        m.record_issued_credentials(vc("urn:uuid:grant"), vc("urn:uuid:role"));
        m.record_member_vmc("urn:uuid:ack", vc("urn:uuid:ack"), true);
        let v = serde_json::to_value(credentials_response(&m).unwrap()).unwrap();
        assert_eq!(v["membershipCredential"], vc("urn:uuid:grant"));
        assert_eq!(v["roleCredential"], vc("urn:uuid:role"));
        assert_eq!(v["memberVmc"], vc("urn:uuid:ack"));
        assert!(v["memberVmcReceivedAt"].is_string());
        assert_eq!(v["memberVmcBound"], true);
    }

    /// `memberVmcReceivedAt` never goes out without `memberVmc` — the
    /// specification's pairing rule. A pre-#1213 row has the id and the
    /// receipt time but no body.
    #[test]
    fn a_receipt_time_without_its_body_is_not_sent() {
        let mut m = Member::fresh(DID);
        m.member_vmc_id = Some("urn:uuid:ack".into());
        m.member_vmc_received_at = Some(chrono::Utc::now());
        let v = serde_json::to_value(credentials_response(&m).unwrap()).unwrap();
        assert!(v.get("memberVmc").is_none());
        assert!(v.get("memberVmcReceivedAt").is_none(), "{v}");
    }

    /// Nor the body without its receipt time.
    #[test]
    fn a_body_without_its_receipt_time_is_not_sent() {
        let mut m = Member::fresh(DID);
        m.member_vmc = Some(vc("urn:uuid:ack"));
        let v = serde_json::to_value(credentials_response(&m).unwrap()).unwrap();
        assert!(v.get("memberVmc").is_none(), "{v}");
        assert!(v.get("memberVmcReceivedAt").is_none());
    }

    #[test]
    fn disclosed_names_only_the_documents_present() {
        let mut m = Member::fresh(DID);
        m.record_issued_credentials(vc("urn:uuid:grant"), vc("urn:uuid:role"));
        let r = credentials_response(&m).unwrap();
        assert_eq!(
            disclosed(&r),
            vec!["membershipCredential", "roleCredential"]
        );
    }
}
