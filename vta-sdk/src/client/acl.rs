//! ACL methods on [`VtaClient`].

use super::types::AclEntryEnvelope;
use super::{
    AclEntryResponse, AclListResponse, ChangeAclRoleRequest, CreateAclRequest, SwapAclRequest,
    UpdateAclRequest, VtaClient, encode_path_segment,
};
use crate::acl::ContextDirection;
use crate::error::VtaError;

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
        self.rpc(
            acl_management::LIST_ACL,
            serde_json::json!({ "context": context, "direction": direction_field }),
            acl_management::LIST_ACL_RESULT,
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
            .rpc(
                acl_management::GET_ACL,
                serde_json::json!({ "subject": did }),
                acl_management::GET_ACL_RESULT,
                30,
                |c, url| c.get(format!("{url}/acl/{}", encode_path_segment(did))),
            )
            .await?;
        Ok(wrapped.entry)
    }

    pub async fn create_acl(&self, req: CreateAclRequest) -> Result<AclEntryResponse, VtaError> {
        // Canonical `acl/grant/0.1` returns the realized entry under `entry`.
        let wrapped: AclEntryEnvelope = self
            .rpc(
                acl_management::CREATE_ACL,
                serde_json::to_value(&req)?,
                acl_management::CREATE_ACL_RESULT,
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
        let wrapped: AclEntryEnvelope = self
            .rpc(
                acl_management::UPDATE_ACL,
                serde_json::json!({
                    "subject": did,
                    "label": &req.label,
                    "allowed_contexts": &req.allowed_contexts,
                }),
                acl_management::UPDATE_ACL_RESULT,
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
            .rpc(
                acl_management::CHANGE_ROLE,
                serde_json::json!({
                    "subject": did,
                    "fromRole": &req.from_role,
                    "toRole": &req.to_role,
                    "reason": &req.reason,
                }),
                acl_management::CHANGE_ROLE_RESULT,
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
        self.rpc_void(
            acl_management::DELETE_ACL,
            serde_json::json!({ "subject": did }),
            acl_management::DELETE_ACL_RESULT,
            30,
            |c, url| c.delete(format!("{url}/acl/{}", encode_path_segment(did))),
        )
        .await
    }

    /// Atomic self-service key rotation: move the caller's own ACL entry onto
    /// the DID proven by `req.presentation` (a VP-JWT). Returns the new entry.
    pub async fn swap_acl(&self, req: SwapAclRequest) -> Result<AclEntryResponse, VtaError> {
        self.rpc(
            acl_management::SWAP_ACL,
            serde_json::to_value(&req)?,
            acl_management::SWAP_ACL_RESULT,
            30,
            |c, url| c.post(format!("{url}/acl/swap")).json(&req),
        )
        .await
    }
}
