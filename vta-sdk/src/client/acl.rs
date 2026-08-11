//! ACL methods on [`VtaClient`].

use super::types::AclEntryEnvelope;
use super::{
    AclEntryResponse, AclListResponse, ChangeAclRoleRequest, CreateAclRequest, SwapAclRequest,
    UpdateAclRequest, VtaClient, encode_path_segment,
};
use crate::acl::ContextDirection;
use crate::error::VtaError;
use crate::protocols::acl_management::change_role::ChangeRoleBody;

#[cfg(feature = "client")]
use crate::protocols::acl_management;

#[cfg(feature = "client")]
impl VtaClient {
    /// List ACL entries, optionally filtered to the entries that may act **in**
    /// `context`.
    ///
    /// For the other direction — what is granted *beneath* a context, which is
    /// what a revocation sweep or a delegation audit needs — call
    /// [`list_acl_in_direction`](Self::list_acl_in_direction). This method is
    /// exactly `ContextDirection::ActingIn` and stays that way.
    pub async fn list_acl(&self, context: Option<&str>) -> Result<AclListResponse, VtaError> {
        self.list_acl_in_direction(context, ContextDirection::ActingIn)
            .await
    }

    /// List ACL entries, filtering `context` in an explicit
    /// [`ContextDirection`].
    ///
    /// A context id names a subtree, so `?context=X` is two questions:
    /// [`ActingIn`](ContextDirection::ActingIn) (who holds authority over X)
    /// and [`Subtree`](ContextDirection::Subtree) (what is granted inside X).
    /// Sweeping a subtree with the first returns precisely the entries the
    /// sweep is *not* revoking, so a caller cutting a branch must ask for the
    /// second (#822). [`Any`](ContextDirection::Any) is the auditor's union.
    ///
    /// The direction is inert without a context and the VTA refuses that
    /// combination rather than silently listing everything.
    pub async fn list_acl_in_direction(
        &self,
        context: Option<&str>,
        direction: ContextDirection,
    ) -> Result<AclListResponse, VtaError> {
        // Omitted when it is the default, so an old VTA — which would reject
        // the unknown field — keeps serving the calls that mean what it
        // already does.
        let direction_field = (direction != ContextDirection::default())
            .then(|| serde_json::Value::String(direction.to_string()));
        let mut payload = serde_json::Map::new();
        if let Some(ctx) = context {
            payload.insert("scope".into(), serde_json::Value::String(ctx.to_string()));
        }
        if let Some(d) = direction_field {
            payload.insert("direction".into(), d);
        }
        self.rpc_tt(
            crate::trust_tasks::TASK_ACL_LIST_0_1,
            serde_json::Value::Object(payload),
            30,
            |c, url| {
                // Both parameters are appended independently — a direction
                // without a context is a caller error, and the VTA says so;
                // dropping it here would make REST answer a question DIDComm
                // refuses.
                let mut u = format!("{url}/acl");
                let mut sep = '?';
                if let Some(ctx) = context {
                    u.push_str(&format!("{sep}context={ctx}"));
                    sep = '&';
                }
                if direction != ContextDirection::default() {
                    u.push_str(&format!("{sep}direction={direction}"));
                }
                c.get(u)
            },
        )
        .await
    }

    pub async fn get_acl(&self, did: &str) -> Result<AclEntryResponse, VtaError> {
        // Canonical `acl/show/0.1` wraps the entry (alongside `redactedFields`);
        // unwrap so callers keep working with the entry itself.
        let wrapped: AclEntryEnvelope = self
            .rpc_tt(
                crate::trust_tasks::TASK_ACL_SHOW_0_1,
                serde_json::json!({ "subject": did }),
                30,
                |c, url| c.get(format!("{url}/acl/{}", encode_path_segment(did))),
            )
            .await?;
        Ok(wrapped.entry)
    }

    pub async fn create_acl(&self, req: CreateAclRequest) -> Result<AclEntryResponse, VtaError> {
        // Canonical `acl/grant/0.1` returns the realized entry under `entry`.
        // `CreateAclRequest` serializes to the canonical `{ entry, … }`
        // request, so the same body serves the REST route and the trust-task
        // dispatcher (which schema-validates it against the published spec).
        let wrapped: AclEntryEnvelope = self
            .rpc_tt(
                crate::trust_tasks::TASK_ACL_GRANT_0_1,
                serde_json::to_value(&req)?,
                30,
                |c, url| c.post(format!("{url}/acl")).json(&req),
            )
            .await?;
        Ok(wrapped.entry)
    }

    pub async fn update_acl(
        &self,
        did: &str,
        req: UpdateAclRequest,
    ) -> Result<AclEntryResponse, VtaError> {
        // Canonical `acl/update/0.1` returns the realized entry under `entry`,
        // like grant and show.
        //
        // The task payload is the full canonical body. Hand-rolling three of
        // its members here — as this did before #884 — silently dropped the
        // step-up, approve-authority, expiry, `allowedKeys` and `reason` the
        // caller asked for the moment the client was on DIDComm rather than
        // REST: a narrowing the operator believed they had applied.
        let body = acl_management::update::UpdateAclBody {
            did: did.to_string(),
            label: req.label.clone(),
            allowed_contexts: req.allowed_contexts.clone(),
            expires_at: None,
            reason: None,
            step_up: (req.step_up_approver.is_some() || req.step_up_require.is_some()).then(|| {
                acl_management::entry::StepUp {
                    approver: req.step_up_approver.clone(),
                    require: req.step_up_require.clone(),
                }
            }),
            approve: req
                .approve_scope
                .as_ref()
                .map(acl_management::entry::Approve::from_scope),
            allowed_keys: req.allowed_keys.clone(),
        };
        let wrapped: AclEntryEnvelope = self
            .rpc_tt(
                crate::trust_tasks::TASK_ACL_UPDATE_0_1,
                serde_json::to_value(&body)?,
                30,
                |c, url| {
                    c.patch(format!("{url}/acl/{}", encode_path_segment(did)))
                        .json(&req)
                },
            )
            .await?;
        Ok(wrapped.entry)
    }

    /// Transition a subject's role, compare-and-swapped against the role
    /// they currently hold.
    ///
    /// Separate from [`Self::update_acl`] because role is the one ACL
    /// attribute where a lost update is a privilege change. If another
    /// admin has moved the subject since you read them, this fails
    /// rather than overwriting their change — re-read and retry.
    pub async fn change_acl_role(
        &self,
        did: &str,
        req: ChangeAclRoleRequest,
    ) -> Result<AclEntryResponse, VtaError> {
        let wrapped: AclEntryEnvelope = self
            .rpc_tt(
                crate::trust_tasks::TASK_ACL_CHANGE_ROLE_0_1,
                // Built from the canonical body, not a hand-rolled map. The
                // map interpolated `req.reason` — an `Option` — directly, so a
                // change with no rationale sent `"reason": null` and
                // `acl/change-role/0.1` types it `"string"`. `ChangeRoleBody`
                // already carried the right `skip_serializing_if`; this call
                // simply did not use it. Same defect as #919's `keys/create`
                // and #921's `derive_and_sign_document`.
                serde_json::to_value(ChangeRoleBody {
                    subject: did.to_string(),
                    from_role: req.from_role.clone(),
                    to_role: req.to_role.clone(),
                    reason: req.reason.clone(),
                })?,
                30,
                |c, url| {
                    c.post(format!(
                        "{url}/acl/{}/change-role",
                        encode_path_segment(did)
                    ))
                    .json(&req)
                },
            )
            .await?;
        Ok(wrapped.entry)
    }

    pub async fn delete_acl(&self, did: &str) -> Result<(), VtaError> {
        self.rpc_tt_void(
            crate::trust_tasks::TASK_ACL_REVOKE_0_1,
            serde_json::json!({ "subject": did }),
            30,
            |c, url| c.delete(format!("{url}/acl/{}", encode_path_segment(did))),
        )
        .await
    }

    /// Atomic self-service key rotation: move the caller's own ACL entry onto
    /// the DID proven by `req.presentation` (a VP-JWT). Returns the new entry.
    ///
    /// Sends canonical `acl/swap-key/0.1` on **every** transport — over REST
    /// through the trust-task endpoint rather than the legacy `POST /acl/swap`
    /// route, which is the one surface that still answers with the maintainer's
    /// flat stored row. That mismatch is what left this method returning
    /// `missing field 'subject'` for every caller on every transport after the
    /// canonical fold (#842); the legacy route stays mounted, untouched, for
    /// the non-Rust consumers that read it.
    ///
    /// `newSubject` is read from the presentation's `iss`, and `currentSubject`
    /// from the DID this client sends as. Both are declarations the maintainer
    /// cross-checks against the proof and the authenticated caller — a wrong
    /// one is refused, never applied.
    ///
    /// **A REST client has a bearer token, not a DID**, so there is nothing to
    /// infer the swapped-out VID from; use [`swap_acl_for`](Self::swap_acl_for)
    /// there.
    pub async fn swap_acl(&self, req: SwapAclRequest) -> Result<AclEntryResponse, VtaError> {
        let current_subject = self.caller_did().map(str::to_string).ok_or_else(|| {
            VtaError::Validation(
                "acl/swap-key declares the VID being swapped out, and a REST client has no DID \
                 to infer it from — call `swap_acl_for(<did>, req)` instead"
                    .into(),
            )
        })?;
        self.swap_acl_for(&current_subject, req).await
    }

    /// [`swap_acl`](Self::swap_acl) with the swapped-out VID stated outright —
    /// the REST-transport form, since a bearer token does not name a DID.
    ///
    /// The maintainer refuses a `currentSubject` that is not the authenticated
    /// caller, so naming someone else's VID here rotates nothing.
    pub async fn swap_acl_for(
        &self,
        current_subject: &str,
        req: SwapAclRequest,
    ) -> Result<AclEntryResponse, VtaError> {
        let new_subject = acl_management::swap::peek_presentation_holder(&req.presentation)
            .map_err(|e| VtaError::Validation(format!("swap presentation is unreadable: {e}")))?;

        // `AclEntryEnvelope` ignores the response's `previousSubject`; the
        // caller asked for the entry, and the VID that lost the grant is the
        // one they just sent.
        let payload = serde_json::json!({
            "currentSubject": current_subject,
            "newSubject": new_subject,
            "linkProof": &req.presentation,
        });
        let response = self
            .dispatch_trust_task(crate::trust_tasks::TASK_ACL_SWAP_KEY_0_1, payload, 30)
            .await?;
        let wrapped: AclEntryEnvelope = serde_json::from_value(response)
            .map_err(|e| VtaError::Protocol(format!("acl/swap-key response decode: {e}")))?;
        Ok(wrapped.entry)
    }
}
