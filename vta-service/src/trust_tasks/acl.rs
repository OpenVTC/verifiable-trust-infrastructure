//! ACL slice trust-task handlers: `acl/{grant,show,update,change-role,
//! revoke}/0.2`, `acl/list/0.4` and `acl/swap-key/0.1`.
//!
//! AclEntry 0.2 states every authority axis explicitly; how the VTA's stored
//! entry maps onto it, and which 0.2 values it refuses because it cannot hold
//! them, is [`operations::acl_v0_3`]. These handlers parse the payload, call
//! it, and answer each refusal with the code the task being answered declares
//! (`acl/_shared/0.3` CONVENTIONS §3: never another slug's).
//!
//! Auth: Admin or Initiator for list/grant/show/revoke; Admin-only for update
//! and change-role (enforced in the operations).

use super::helpers::TrustTaskOutcome;
use serde_json::{Value, json};
use trust_tasks_rs::{DeclaredErrorCode, RejectReason, TrustTask, TrustTaskCode};
use vta_sdk::acl::PurposeScope;
use vta_sdk::protocols::acl_management::change_role::ChangeRoleBody;
use vta_sdk::protocols::acl_management::swap::SwapKeyBody;
use vta_sdk::protocols::acl_management::v0_2::{AclEntry as WireEntry, Revocation};
use vti_specs::acl::{
    change_role::v0_3 as change_role_spec, grant::v0_3 as grant_spec, list::v0_4 as list_spec,
    revoke::v0_3 as revoke_spec, show::v0_3 as show_spec, update::v0_3 as update_spec,
};

use crate::auth::AuthClaims;
use crate::error::AppError;
use crate::operations;
use crate::operations::acl_v0_3::{KNOWN_ROLES, ListQuery, UpdateBody, V03Error};
use crate::server::AppState;

use super::helpers::{
    TRANSPORT_TRUST_TASK, app_error_to_reject, parse_payload, reject_with, reject_with_code,
    success_response,
};

/// The codes the 0.2 task being answered declares, each `None` where it
/// declares no such code — that refusal then answers with a framework code.
#[derive(Clone, Copy, Default)]
struct Codes {
    role_not_recognized: Option<DeclaredErrorCode>,
    invalid_act_scope: Option<DeclaredErrorCode>,
    unknown_capability: Option<DeclaredErrorCode>,
    capability_outside_ceiling: Option<DeclaredErrorCode>,
    additive_within_ceiling: Option<DeclaredErrorCode>,
    not_found: Option<DeclaredErrorCode>,
    narrowing_not_permitted: Option<DeclaredErrorCode>,
    not_narrowing: Option<DeclaredErrorCode>,
    state_mismatch: Option<DeclaredErrorCode>,
    cursor_mismatch: Option<DeclaredErrorCode>,
    purpose_outside_delegator: Option<DeclaredErrorCode>,
}

fn grant_codes() -> Codes {
    use grant_spec::error_codes as c;
    Codes {
        role_not_recognized: Some(c::ROLE_NOT_RECOGNIZED),
        invalid_act_scope: Some(c::INVALID_ACT_SCOPE),
        unknown_capability: Some(c::UNKNOWN_CAPABILITY),
        capability_outside_ceiling: Some(c::CAPABILITY_OUTSIDE_CEILING),
        additive_within_ceiling: Some(c::ADDITIVE_WITHIN_CEILING),
        purpose_outside_delegator: Some(c::PURPOSE_OUTSIDE_DELEGATOR),
        ..Codes::default()
    }
}

fn update_codes() -> Codes {
    use update_spec::error_codes as c;
    Codes {
        invalid_act_scope: Some(c::INVALID_ACT_SCOPE),
        unknown_capability: Some(c::UNKNOWN_CAPABILITY),
        capability_outside_ceiling: Some(c::CAPABILITY_OUTSIDE_CEILING),
        additive_within_ceiling: Some(c::ADDITIVE_WITHIN_CEILING),
        not_found: Some(c::NOT_FOUND),
        narrowing_not_permitted: Some(c::NARROWING_NOT_PERMITTED),
        purpose_outside_delegator: Some(c::PURPOSE_OUTSIDE_DELEGATOR),
        ..Codes::default()
    }
}

fn change_role_codes() -> Codes {
    use change_role_spec::error_codes as c;
    Codes {
        role_not_recognized: Some(c::ROLE_NOT_RECOGNIZED),
        capability_outside_ceiling: Some(c::CAPABILITY_OUTSIDE_CEILING),
        additive_within_ceiling: Some(c::ADDITIVE_WITHIN_CEILING),
        state_mismatch: Some(c::STATE_MISMATCH),
        ..Codes::default()
    }
}

fn revoke_codes() -> Codes {
    use revoke_spec::error_codes as c;
    Codes {
        invalid_act_scope: Some(c::INVALID_ACT_SCOPE),
        not_found: Some(c::SUBJECT_NOT_PRESENT),
        not_narrowing: Some(c::NOT_NARROWING),
        ..Codes::default()
    }
}

fn list_codes() -> Codes {
    Codes {
        cursor_mismatch: Some(list_spec::error_codes::CURSOR_MISMATCH),
        ..Codes::default()
    }
}

fn extended(code: DeclaredErrorCode) -> TrustTaskCode {
    TrustTaskCode::Extended {
        slug: code.namespace().to_string(),
        local: code.local().to_string(),
    }
}

/// Answer `e` with `code` where the task declares one, else as `fallback`.
fn coded(
    doc: &TrustTask<Value>,
    code: Option<DeclaredErrorCode>,
    message: String,
    details: Option<Value>,
    fallback: AppError,
) -> TrustTaskOutcome {
    match code {
        Some(c) => reject_with_code(doc, extended(c), message, details),
        None => app_error_to_reject(doc, fallback),
    }
}

fn refuse(doc: &TrustTask<Value>, e: V03Error, codes: Codes) -> TrustTaskOutcome {
    match e {
        V03Error::RoleNotRecognized(r) => coded(
            doc,
            codes.role_not_recognized,
            format!("'{r}' is not a role this VTA recognises"),
            Some(json!({ "offendingRole": r, "knownRoles": KNOWN_ROLES })),
            AppError::Validation(format!("role not recognized: {r}")),
        ),
        V03Error::InvalidActScope { member, reason } => coded(
            doc,
            codes.invalid_act_scope,
            reason.clone(),
            Some(json!({ "member": member })),
            AppError::Validation(reason),
        ),
        V03Error::UnknownCapability(caps) => {
            let m = format!(
                "{} {} not in this VTA's capability registry",
                caps.join(", "),
                if caps.len() == 1 { "is" } else { "are" }
            );
            coded(
                doc,
                codes.unknown_capability,
                m.clone(),
                Some(json!({ "capabilities": caps })),
                AppError::Validation(m),
            )
        }
        V03Error::CapabilityOutsideCeiling { role, caps } => {
            let m = format!(
                "role {role} does not carry {}; an entry's capabilities narrow its role, and \
                 an additive capability is marked `additive: true`",
                caps.join(", ")
            );
            coded(
                doc,
                codes.capability_outside_ceiling,
                m.clone(),
                Some(json!({ "role": role, "capabilities": caps })),
                AppError::Validation(m),
            )
        }
        V03Error::AdditiveWithinCeiling(caps) => {
            let m = format!(
                "{} {} already in the role's ceiling and cannot be marked additive",
                caps.join(", "),
                if caps.len() == 1 { "is" } else { "are" }
            );
            coded(
                doc,
                codes.additive_within_ceiling,
                m.clone(),
                Some(json!({ "capabilities": caps })),
                AppError::Validation(m),
            )
        }
        V03Error::Unsupported(m) => app_error_to_reject(doc, AppError::Validation(m)),
        V03Error::NarrowingNotPermitted => coded(
            doc,
            codes.narrowing_not_permitted,
            "acl/update never narrows act; narrow it with acl/revoke/0.3 {kind: act}".into(),
            None,
            AppError::Validation("narrowing act is acl/revoke/0.3's".into()),
        ),
        V03Error::NotNarrowing => coded(
            doc,
            codes.not_narrowing,
            "the stated act scope is not strictly narrower than the stored one".into(),
            None,
            AppError::Validation("not narrowing".into()),
        ),
        V03Error::NotFound(s) => coded(
            doc,
            codes.not_found,
            format!("no ACL entry for {s}"),
            None,
            AppError::NotFound(format!("ACL entry not found for DID: {s}")),
        ),
        V03Error::StateMismatch(m) => coded(doc, codes.state_mismatch, m.clone(), None, {
            AppError::Conflict(m)
        }),
        V03Error::CursorMismatch => coded(
            doc,
            codes.cursor_mismatch,
            "the cursor was minted under other filters, or not by this VTA".into(),
            None,
            AppError::InvalidCursor,
        ),
        V03Error::PurposeOutsideDelegator(purposes) => {
            let m = format!(
                "{} {} wider than your own purposes; an entry you write may state only purposes \
                 your entry grants, and `any` never grants modelTraining (VTI-ACL-107)",
                purposes.join(", "),
                if purposes.len() == 1 { "is" } else { "are" }
            );
            coded(
                doc,
                codes.purpose_outside_delegator,
                m.clone(),
                Some(json!({ "purposes": purposes })),
                AppError::Forbidden(m),
            )
        }
        V03Error::App(e) => app_error_to_reject(doc, e),
    }
}

/// Answer with `body` held to the task's generated response type, so a
/// rendering that drifted from the published schema is an internal error here
/// rather than a malformed answer on the wire.
fn typed_response<R: serde::de::DeserializeOwned + serde::Serialize>(
    doc: &TrustTask<Value>,
    body: Result<Value, V03Error>,
    codes: Codes,
) -> TrustTaskOutcome {
    match body {
        Ok(v) => match serde_json::from_value::<R>(v) {
            Ok(r) => success_response(doc, r),
            Err(e) => reject_with(
                doc,
                RejectReason::InternalError {
                    reason: format!("ACL response does not match its schema: {e}"),
                },
            ),
        },
        Err(e) => refuse(doc, e, codes),
    }
}

/// A payload member read with the shared component type.
fn member<T: serde::de::DeserializeOwned>(
    doc: &TrustTask<Value>,
    key: &str,
) -> Result<T, TrustTaskOutcome> {
    let v = doc.payload.get(key).cloned().unwrap_or(Value::Null);
    serde_json::from_value(v).map_err(|e| {
        reject_with(
            doc,
            RejectReason::MalformedRequest {
                reason: format!("`{key}`: {e}"),
            },
        )
    })
}

/// A grant's `entry`, split into its 0.2 members and its `purposes`
/// (`acl/_shared/0.3` CONVENTIONS §8a). The dispatcher has already held the
/// payload to the published schema, so `purposes` is present and well formed;
/// it is checked again where it is written.
fn split_entry(doc: &TrustTask<Value>) -> Result<(WireEntry, PurposeScope), TrustTaskOutcome> {
    let malformed = |reason: String| reject_with(doc, RejectReason::MalformedRequest { reason });
    let mut raw = doc.payload.get("entry").cloned().unwrap_or(Value::Null);
    let purposes = raw
        .as_object_mut()
        .and_then(|m| m.remove("purposes"))
        .ok_or_else(|| malformed("`entry.purposes` is required".into()))?;
    let purposes: PurposeScope = serde_json::from_value(purposes)
        .map_err(|e| malformed(format!("`entry.purposes`: {e}")))?;
    let entry: WireEntry =
        serde_json::from_value(raw).map_err(|e| malformed(format!("`entry`: {e}")))?;
    Ok((entry, purposes))
}

/// Handler for `acl/list/0.4`.
pub(super) async fn handle_list(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    if let Err(resp) = parse_payload::<list_spec::Payload>(&doc) {
        return resp;
    }
    let q = match ListQuery::from_payload(&doc.payload) {
        Ok(q) => q,
        Err(e) => return refuse(&doc, e, list_codes()),
    };
    let body = operations::acl_v0_3::list(&state.acl_ks, auth, &q, TRANSPORT_TRUST_TASK).await;
    typed_response::<list_spec::Response>(&doc, body, list_codes())
}

/// Handler for `acl/grant/0.3`.
pub(super) async fn handle_create(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    if let Err(e) = auth.require_manage() {
        return app_error_to_reject(&doc, e);
    }
    // Step-up / approval for `acl/grant` is enforced centrally by the PDP gate.
    if let Err(resp) = parse_payload::<grant_spec::Payload>(&doc) {
        return resp;
    }
    // AclEntry 0.3 is 0.2's members plus `purposes` (CONVENTIONS §8a): take
    // `purposes` off, and read the rest as the 0.2 entry.
    let (entry, purposes) = match split_entry(&doc) {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    // A hand-off rollover rides `acl/grant` (VTI-CLT-017: the long-term entry
    // "written by the bootstrap identifier itself"), asked for explicitly so a
    // marked caller's ordinary grant is never turned into one (VTI-ACL-058).
    let rollover = match vta_sdk::protocols::acl_management::create::handoff_rollover_from_ext(
        doc.payload.get("ext"),
    ) {
        Ok(r) => r,
        Err(reason) => return app_error_to_reject(&doc, AppError::Validation(reason)),
    };
    let successor = entry.subject.clone();
    let result = if rollover {
        operations::acl_v0_3::rollover(
            &state.acl_ks,
            &state.audit_sink,
            &state.contexts_ks,
            auth,
            entry,
            purposes,
            TRANSPORT_TRUST_TASK,
        )
        .await
    } else {
        operations::acl_v0_3::grant(
            &state.acl_ks,
            &state.audit_sink,
            &state.contexts_ks,
            auth,
            entry,
            purposes,
            TRANSPORT_TRUST_TASK,
        )
        .await
    };
    // A rollover carries the predecessor's collection claims to its successor
    // (VTI-NTF-084).
    if rollover
        && result.is_ok()
        && let Err(e) =
            crate::operations::collection::carry_claims(&state.collection_ks, &auth.did, &successor)
                .await
    {
        tracing::warn!(error = %e, "could not carry collection claims across a rollover");
    }
    typed_response::<grant_spec::Response>(&doc, result, grant_codes())
}

/// Handler for `acl/show/0.3`.
pub(super) async fn handle_get(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let req = match parse_payload::<show_spec::Payload>(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let body = operations::acl_v0_3::show(
        &state.acl_ks,
        auth,
        req.subject.as_str(),
        TRANSPORT_TRUST_TASK,
    )
    .await;
    typed_response::<show_spec::Response>(&doc, body, Codes::default())
}

/// Handler for `acl/update/0.3`. Admin-only.
pub(super) async fn handle_update(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    if let Err(e) = auth.require_admin() {
        return app_error_to_reject(&doc, e);
    }
    // Named before the payload parse, which would otherwise answer "unknown
    // field" for the one mistake this task declares a code for (item 2).
    if doc.payload.get("role").is_some() {
        return reject_with_code(
            &doc,
            extended(update_spec::error_codes::ROLE_CHANGE_NOT_PERMITTED),
            "acl/update does not change a role — use acl/change-role/0.3, which takes the \
             current role as a compare-and-swap",
            None,
        );
    }
    if let Err(resp) = parse_payload::<update_spec::Payload>(&doc) {
        return resp;
    }
    let req = match UpdateBody::from_payload(&doc.payload) {
        Ok(r) => r,
        Err(e) => return refuse(&doc, e, update_codes()),
    };
    let body = operations::acl_v0_3::update(
        &state.acl_ks,
        &state.audit_sink,
        &state.contexts_ks,
        auth,
        req,
        TRANSPORT_TRUST_TASK,
    )
    .await;
    typed_response::<update_spec::Response>(&doc, body, update_codes())
}

/// Handler for `acl/change-role/0.3`. Admin-only.
///
/// Separate task from `acl/update` because the transition is
/// compare-and-swapped against `fromRole`.
pub(super) async fn handle_change_role(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    if let Err(e) = auth.require_admin() {
        return app_error_to_reject(&doc, e);
    }
    if let Err(resp) = parse_payload::<change_role_spec::Payload>(&doc) {
        return resp;
    }
    let req: ChangeRoleBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let body = operations::acl_v0_3::change_role(
        &state.acl_ks,
        &state.audit_sink,
        auth,
        &req.subject,
        &req.from_role,
        &req.to_role,
        req.reason.as_deref(),
        TRANSPORT_TRUST_TASK,
    )
    .await;
    typed_response::<change_role_spec::Response>(&doc, body, change_role_codes())
}

/// Handler for `acl/revoke/0.3`.
pub(super) async fn handle_delete(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    if let Err(e) = auth.require_manage() {
        return app_error_to_reject(&doc, e);
    }
    // Step-up / approval for `acl/revoke` is enforced centrally by the PDP gate.
    let req = match parse_payload::<revoke_spec::Payload>(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let revocation: Revocation = match member(&doc, "revocation") {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let body = operations::acl_v0_3::revoke(
        &state.acl_ks,
        &state.audit_sink,
        &state.contexts_ks,
        auth,
        req.subject.as_str(),
        revocation,
        req.reason.as_ref().map(|r| r.to_string()),
        TRANSPORT_TRUST_TASK,
    )
    .await;
    typed_response::<revoke_spec::Response>(&doc, body, revoke_codes())
}

/// Handler for the canonical `acl/swap-key/0.1` Trust Task — self-service
/// rotation of the caller's own ACL entry onto a new subject DID. Consolidates
/// the bespoke REST `/acl/swap` handler and the DIDComm `handle_swap_acl` onto
/// the shared dispatcher (so it works over REST, DIDComm, and TSP identically).
///
/// No `require_manage()`: the caller only moves their own grant. The
/// authenticated caller (REST bearer, TSP VID, or over DIDComm the document
/// proof bound to the sender) and the document `issuer` are both bound to
/// `currentSubject`; the `link_proof` VP-JWT proves control of
/// `newSubject`.
pub(super) async fn handle_swap_key(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let req: SwapKeyBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    // `linkProof` is optional at the framework level and required by this
    // deployment. Refused by name rather than as a parse failure: the document
    // is well-formed, and telling a producer its shape is wrong sends it to
    // re-read the schema, which will agree with the producer.
    let Some(link_proof) = req.link_proof.clone() else {
        return reject_with(
            &doc,
            RejectReason::TaskFailed {
                reason: "acl:link_proof_required — this maintainer requires a `linkProof` \
                         proving the new subject consents to the takeover"
                    .to_string(),
                details: None,
            },
        );
    };

    // The authenticated caller must equal the declared currentSubject — stops a
    // sender from claiming to rotate someone else's entry.
    if req.current_subject != auth.did {
        return reject_with(
            &doc,
            RejectReason::MalformedRequest {
                reason: format!(
                    "acl/swap-key: currentSubject {} does not equal authenticated caller {}",
                    req.current_subject, auth.did
                ),
            },
        );
    }

    // `acl/swap-key/0.1` §6: the document's `issuer` MUST equal
    // `currentSubject` (and its REQUIRED proof, verified by the spine, is bound
    // to that issuer). Held here as well as by the spine's issuer == caller
    // rule, because it is this task's own requirement.
    if doc.issuer.as_deref() != Some(req.current_subject.as_str()) {
        return reject_with(
            &doc,
            RejectReason::IdentityMismatch(trust_tasks_rs::ConsistencyError::IssuerMismatch {
                in_band: doc.issuer.clone().unwrap_or_default(),
                transport: req.current_subject.clone(),
            }),
        );
    }

    // No inline step-up check. This handler used to resolve the `acl/swap-key`
    // config floor itself, passing the non-escalation carve-out — swap-key
    // being self-service rotation of the caller's own entry — so that a floor
    // with `allow_aal1_if_non_escalating` still admitted an AAL1
    // sender-authenticated transport.
    //
    // The floors are retired, and with them the carve-out: it existed to let a
    // blunt, op-class-keyed floor make an exception a rule can simply not
    // make in the first place. An operator who wants rotation gated writes a
    // rule naming `acl/swap-key/0.1`, and [`super::policy_gate`] enforces it
    // before this handler is reached — on every transport.
    let did_resolver = match state.did_resolver.as_ref() {
        Some(r) => r,
        None => {
            return app_error_to_reject(
                &doc,
                AppError::Internal("DID resolver not available".into()),
            );
        }
    };
    let vta_did = match state.config.read().await.vta_did.clone() {
        Some(v) => v,
        None => {
            return app_error_to_reject(&doc, AppError::Internal("VTA DID not configured".into()));
        }
    };

    match operations::acl::swap_acl(
        &state.acl_ks,
        &state.audit_sink,
        auth,
        &link_proof,
        did_resolver,
        &vta_did,
        TRANSPORT_TRUST_TASK,
    )
    .await
    {
        Ok(result) => {
            // Cross-check the declared newSubject matches the VP holder the
            // operation actually verified (defence-in-depth over the proof).
            if req.new_subject != result.did {
                return reject_with(
                    &doc,
                    RejectReason::MalformedRequest {
                        reason: format!(
                            "acl/swap-key: newSubject {} does not match verified VP holder {}",
                            req.new_subject, result.did
                        ),
                    },
                );
            }
            // A key rotation carries the subject's collection claims
            // (VTI-NTF-084, VTI-CLT-025).
            if let Err(e) = crate::operations::collection::carry_claims(
                &state.collection_ks,
                &auth.did,
                &result.did,
            )
            .await
            {
                tracing::warn!(error = %e, "could not carry collection claims across a key swap");
            }
            // Canonical `acl/swap-key/0.1` responds with the realized entry
            // plus the swapped-out `previousSubject` (#857).
            success_response(
                &doc,
                vta_sdk::protocols::acl_management::swap::SwapKeyResultBody {
                    entry: vta_sdk::protocols::acl_management::entry::AclEntry::from_result(
                        &result,
                    ),
                    previous_subject: req.current_subject.clone(),
                },
            )
        }
        Err(e) => app_error_to_reject(&doc, e),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use vta_sdk::protocols::acl_management::change_role::ChangeRoleBody;
    use vta_sdk::protocols::acl_management::v0_2::{
        AuthorityScope, CapabilityGrant, CapabilityScope, KeyScope,
    };

    use vti_specs::acl::change_role::v0_3 as canonical_change_role;
    use vti_specs::acl::update::v0_3 as canonical_update;

    /// Our wire shapes must be the canonical ones, not merely bound to the
    /// canonical URIs: the generated types carry `deny_unknown_fields` and the
    /// spec's required set.
    #[test]
    fn change_role_conforms() {
        let change = ChangeRoleBody {
            subject: "did:key:z6MkSubject".into(),
            from_role: "reader".into(),
            to_role: "application".into(),
            reason: Some("promoted".into()),
        };
        let json = serde_json::to_value(&change).expect("serialize");
        serde_json::from_value::<canonical_change_role::Payload>(json.clone())
            .unwrap_or_else(|e| panic!("not canonical `acl/change-role/0.3`: {e}\n{json:#}"));
    }

    /// An amendment spelled with the shared components is canonical, reads
    /// back through [`super::UpdateBody::from_payload`], and keeps an explicit
    /// `null` apart from absence.
    #[test]
    fn update_payload_is_canonical_and_reads_back() {
        let payload = json!({
            "subject": "did:key:z6MkSubject",
            "act": AuthorityScope::Contexts { contexts: vec!["ctx-a".into(), "ctx-b".into()] },
            "approve": AuthorityScope::None,
            "capabilities": CapabilityScope::Listed {
                grants: vec![CapabilityGrant::new("memory-read", false)],
            },
            "keys": KeyScope::Listed { keys: vec!["tenant-key-a".into()] },
            "label": null,
            "expiresAt": "2027-01-15T08:00:00Z",
            "reason": "quarterly access review",
        });
        serde_json::from_value::<canonical_update::Payload>(payload.clone())
            .unwrap_or_else(|e| panic!("not canonical `acl/update/0.3`: {e}\n{payload:#}"));

        let mut drifted = payload.clone();
        drifted
            .as_object_mut()
            .expect("object")
            .insert("scopes".into(), json!(["ctx-a"]));
        assert!(
            serde_json::from_value::<canonical_update::Payload>(drifted).is_err(),
            "the 0.1 `scopes` member must be rejected by the 0.3 schema"
        );

        let body = super::UpdateBody::from_payload(&payload).expect("reads back");
        assert_eq!(body.label, Some(None), "null clears");
        assert!(body.expires_at.is_some_and(|e| e.is_some()));
        assert!(body.step_up.is_none(), "absent leaves unchanged");
        assert!(
            body.purposes.is_none(),
            "absent leaves the purposes unchanged"
        );

        let mut narrowing = payload.clone();
        narrowing["purposes"] = json!({"scope": "listed", "purposes": ["personalisation"]});
        serde_json::from_value::<canonical_update::Payload>(narrowing.clone())
            .unwrap_or_else(|e| panic!("a purposes replacement is canonical: {e}"));
        let body = super::UpdateBody::from_payload(&narrowing).expect("reads back");
        assert_eq!(
            body.purposes,
            Some(vta_sdk::acl::PurposeScope::listed(["personalisation"]).unwrap())
        );
    }
}
