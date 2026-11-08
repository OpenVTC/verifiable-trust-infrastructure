//! ACL methods on [`VtaClient`].

use super::types::{AclEntryEnvelope, AclListPage, AclShowResponse, act_for, capability_scope_for};
use super::{
    AclEntryResponse, AclListResponse, ChangeAclRoleRequest, CreateAclRequest, SwapAclRequest,
    UpdateAclRequest, VtaClient,
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

    /// List ACL entries (`acl/list/0.3`), filtering `context` in an explicit
    /// [`ContextDirection`], following `nextCursor` to the last page.
    ///
    /// A context id names a subtree, so a context filter is two questions:
    /// [`ActingIn`](ContextDirection::ActingIn) (who holds authority over X)
    /// and [`Subtree`](ContextDirection::Subtree) (what is granted inside X).
    /// Sweeping a subtree with the first returns precisely the entries the
    /// sweep is *not* revoking, so a caller cutting a branch must ask for the
    /// second (#822). [`Any`](ContextDirection::Any) is the auditor's union.
    ///
    /// 0.3 requires the direction whenever a context is given and refuses one
    /// without, so it is sent exactly then.
    pub async fn list_acl_in_direction(
        &self,
        context: Option<&str>,
        direction: ContextDirection,
    ) -> Result<AclListResponse, VtaError> {
        let mut entries = Vec::new();
        let mut cursor: Option<String> = None;
        // A bound on the walk, so a maintainer that kept answering with a
        // cursor cannot hold the client forever; an ACL longer than this is
        // an error rather than a partial list that reads as complete.
        for _ in 0..1000 {
            let payload = acl_management::v0_2::list_payload(
                context.map(|c| (c, direction.into())),
                cursor.take().as_deref(),
                Some(500),
            );
            let page: AclListPage = self
                .rpc_tt(crate::trust_tasks::TASK_ACL_LIST_0_3, payload, 30)
                .await?;
            entries.extend(page.entries);
            match page.next_cursor {
                None => return Ok(AclListResponse { entries }),
                Some(next) => cursor = Some(next),
            }
        }
        Err(VtaError::Protocol(
            "acl/list kept returning a nextCursor after 1000 pages".into(),
        ))
    }

    /// The entry for `did` (`acl/show/0.2`). An absent entry — or one this
    /// caller may not see, which the VTA answers the same way — is
    /// [`VtaError::NotFound`].
    pub async fn get_acl(&self, did: &str) -> Result<AclEntryResponse, VtaError> {
        let shown: AclShowResponse = self
            .rpc_tt(
                crate::trust_tasks::TASK_ACL_SHOW_0_2,
                acl_management::v0_2::show_payload(did),
                30,
            )
            .await?;
        shown
            .entry
            .ok_or_else(|| VtaError::NotFound(format!("ACL entry not found for DID: {did}")))
    }

    /// Grant an entry (`acl/grant/0.2`). The request is sent with every axis
    /// explicit — see [`CreateAclRequest::to_entry_v0_2`].
    pub async fn create_acl(&self, req: CreateAclRequest) -> Result<AclEntryResponse, VtaError> {
        let wrapped: AclEntryEnvelope = self
            .rpc_tt(
                crate::trust_tasks::TASK_ACL_GRANT_0_2,
                serde_json::to_value(&req)?,
                30,
            )
            .await?;
        Ok(wrapped.entry)
    }

    /// Exercise the caller's hand-off marker (VTI-ACL-054 – VTI-ACL-057): write
    /// `successor_did` as the caller's one successor and remove the caller's
    /// own entry, atomically. `acl/grant/0.2` with
    /// [`HANDOFF_ROLLOVER_EXT_MEMBER`](acl_management::create::HANDOFF_ROLLOVER_EXT_MEMBER).
    ///
    /// The successor's expiry is the one the granter recorded with the marker,
    /// not the caller's — the point of a hand-off — and `role` / `scopes` may
    /// not exceed the caller's. The caller must already hold the successor's
    /// private key: unlike `provision/integration`'s admin rollover, nothing is
    /// minted for it (VTI-CLT-002).
    pub async fn roll_over_handoff(
        &self,
        successor_did: &str,
        role: &str,
        scopes: Vec<String>,
        label: Option<String>,
    ) -> Result<AclEntryResponse, VtaError> {
        let mut entry = acl_management::v0_2::AclEntry::new(
            successor_did,
            role,
            act_for(role, &scopes),
            acl_management::v0_2::KeyScope::All,
            acl_management::v0_2::CapabilityScope::Ceiling,
        );
        entry.label = label;
        let wrapped: AclEntryEnvelope = self
            .rpc_tt(
                crate::trust_tasks::TASK_ACL_GRANT_0_2,
                acl_management::v0_2::grant_payload(&entry, None, true),
                30,
            )
            .await?;
        Ok(wrapped.entry)
    }

    /// Amend an entry (`acl/update/0.2`, and `acl/revoke/0.2` for a narrowing
    /// of where it may act).
    ///
    /// 0.2 puts every narrowing of `act` in `acl/revoke`, so a context change
    /// is read against the stored entry first: a pure widening is an update; a
    /// pure narrowing is a revoke `{kind: act}`; a lateral move (some contexts
    /// added, some removed) widens to the union and then narrows to the
    /// target, so at no point does the subject hold a context it neither had
    /// nor was meant to get. Every other member travels in the one update.
    pub async fn update_acl(
        &self,
        did: &str,
        req: UpdateAclRequest,
    ) -> Result<AclEntryResponse, VtaError> {
        use acl_management::v0_2::{
            ApproveCapabilityScope, AuthorityScope, KeyScope, Revocation, StepUpReplacement,
            revoke_payload,
        };

        // The payload, member by member: each present member replaces the
        // stored one, each absent one leaves it unchanged.
        let mut body = serde_json::Map::new();
        body.insert("subject".into(), serde_json::Value::String(did.to_string()));
        let put =
            |b: &mut serde_json::Map<String, serde_json::Value>, k: &str, v: serde_json::Value| {
                b.insert(k.to_string(), v);
            };
        let mut narrow_to: Option<AuthorityScope> = None;
        // Read the stored entry whenever the change depends on it: the act
        // comparison, and the role a capability narrowing is spelled against.
        let current = if req.allowed_contexts.is_some() || req.capabilities.is_some() {
            Some(self.get_acl(did).await?)
        } else {
            None
        };
        if let (Some(contexts), Some(cur)) = (&req.allowed_contexts, &current) {
            let held = AuthorityScope::from_act_scope(cur.act());
            let target = act_for(&cur.role, contexts);
            if target != held {
                if target.includes(&held) {
                    put(&mut body, "act", serde_json::to_value(&target)?);
                } else if held.includes(&target) {
                    narrow_to = Some(target);
                } else {
                    // Lateral: widen to the union, then narrow.
                    let mut union: Vec<String> = held.contexts().to_vec();
                    for c in target.contexts() {
                        if !union.contains(c) {
                            union.push(c.clone());
                        }
                    }
                    put(
                        &mut body,
                        "act",
                        serde_json::to_value(AuthorityScope::Contexts { contexts: union })?,
                    );
                    narrow_to = Some(target);
                }
            }
        }
        if let Some(label) = &req.label {
            put(&mut body, "label", serde_json::Value::String(label.clone()));
        }
        if let (Some(names), Some(cur)) = (&req.capabilities, &current) {
            put(
                &mut body,
                "capabilities",
                serde_json::to_value(capability_scope_for(&cur.role, names))?,
            );
        }
        if let Some(scope) = &req.approve_scope {
            let approve = match scope {
                crate::acl::ApproveScope::None => AuthorityScope::None,
                crate::acl::ApproveScope::All => AuthorityScope::All,
                crate::acl::ApproveScope::Contexts(cs) => AuthorityScope::Contexts {
                    contexts: cs.clone(),
                },
            };
            let caps = if approve == AuthorityScope::None {
                ApproveCapabilityScope::None
            } else {
                ApproveCapabilityScope::Ceiling
            };
            put(
                &mut body,
                "approveCapabilities",
                serde_json::to_value(caps)?,
            );
            put(&mut body, "approve", serde_json::to_value(approve)?);
        }
        if let Some(keys) = &req.allowed_keys {
            put(
                &mut body,
                "keys",
                serde_json::to_value(KeyScope::from_allowed_keys(keys.as_deref()))?,
            );
        }
        if req.step_up_approver.is_some() || req.step_up_require.is_some() {
            // An empty string clears, as the builder documents.
            let clear_or =
                |v: &Option<String>| v.as_ref().map(|s| (!s.is_empty()).then(|| s.clone()));
            put(
                &mut body,
                "stepUp",
                serde_json::to_value(StepUpReplacement {
                    approver: clear_or(&req.step_up_approver),
                    require: clear_or(&req.step_up_require),
                })?,
            );
        }

        let changes_beyond_narrowing = body.len() > 1;
        let mut result: Option<AclEntryResponse> = None;
        if changes_beyond_narrowing || narrow_to.is_none() {
            let wrapped: AclEntryEnvelope = self
                .rpc_tt(
                    crate::trust_tasks::TASK_ACL_UPDATE_0_2,
                    serde_json::Value::Object(body),
                    30,
                )
                .await?;
            result = Some(wrapped.entry);
        }
        if let Some(act) = narrow_to {
            let revoked: AclShowResponse = self
                .rpc_tt(
                    crate::trust_tasks::TASK_ACL_REVOKE_0_2,
                    revoke_payload(did, &Revocation::Act { act }, None),
                    30,
                )
                .await?;
            result = revoked.entry;
        }
        result.ok_or_else(|| {
            VtaError::Protocol("acl/revoke narrowed the entry but returned none".into())
        })
    }

    /// Transition a subject's role (`acl/change-role/0.2`), compare-and-swapped
    /// against the role they currently hold.
    ///
    /// Separate from [`Self::update_acl`] because role is the one ACL
    /// attribute where a lost update is a privilege change. If another
    /// admin has moved the subject since you read them, this fails
    /// rather than overwriting their change — re-read and retry.
    ///
    /// The act scope is carried across unchanged, so a move the VTA cannot
    /// hold with the same act scope — `reader` acting nowhere to `admin`, which
    /// under the old reading would have made it unrestricted — is refused.
    pub async fn change_acl_role(
        &self,
        did: &str,
        req: ChangeAclRoleRequest,
    ) -> Result<AclEntryResponse, VtaError> {
        let wrapped: AclEntryEnvelope = self
            .rpc_tt(
                crate::trust_tasks::TASK_ACL_CHANGE_ROLE_0_2,
                serde_json::to_value(ChangeRoleBody {
                    subject: did.to_string(),
                    from_role: req.from_role.clone(),
                    to_role: req.to_role.clone(),
                    reason: req.reason.clone(),
                })?,
                30,
            )
            .await?;
        Ok(wrapped.entry)
    }

    /// Remove an entry (`acl/revoke/0.2` `{kind: entry}`).
    pub async fn delete_acl(&self, did: &str) -> Result<(), VtaError> {
        self.rpc_tt_void(
            crate::trust_tasks::TASK_ACL_REVOKE_0_2,
            acl_management::v0_2::revoke_payload(
                did,
                &acl_management::v0_2::Revocation::Entry,
                None,
            ),
            30,
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
