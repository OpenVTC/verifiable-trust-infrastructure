//! [`AdminActor`] — the administrator a signed administrative document is
//! authorized as.
//!
//! Before #2580 the admin verbs carried a synthetic
//! `vti_common::auth::extractor::AuthClaims { role: Admin, allowed_contexts: [] }`.
//! The VTC has no contexts, so every such value read as **unscoped** to the
//! shared `vti_common` helpers: an `is_super_admin()` or
//! `require_super_admin()` on it compiled, and passed for every administrator —
//! an `auditor` included. "No gate in this service may be a claims check" was
//! held by a doc comment.
//!
//! This type holds it by construction. It carries the actor's DID, the live ACL
//! entry it was authorized from (read at execution time, VTI-ACL-030), and the
//! console key it acted through, if any (#1684) — and exposes
//! [`AdminActor::can`], the one authorization question
//! (`docs/05-design-notes/vtc-admin-roles.md`), and nothing role-shaped. There
//! is no role to read, no context list to misread, and no session whose
//! step-up a signed document could borrow.

use vti_common::error::AppError;

use super::{Capability, ResourceQualifier, VtcAclEntry};

/// A signer this community holds a live entry for — a member or an
/// administrator — authorized **as a member**: its DID, and nothing
/// role-shaped (#2580). What a member verb decides beyond membership it reads
/// from the community's records for this DID, never from this value.
#[derive(Debug, Clone)]
pub struct MemberSigner {
    /// The signer's DID.
    pub did: String,
}

/// The administrator a signed administrative document is authorized as: its
/// DID, the live entry that authorized it, and the console key it signed
/// through.
///
/// Constructed only by resolving an administrator's live entry
/// ([`AdminActor::resolve`]), so holding one means that entry was read and was
/// an administrator's when the document was executed.
#[derive(Debug, Clone)]
pub struct AdminActor {
    /// The administrator's DID — the delegating administrator's for a
    /// console-key signature, never the console key's.
    pub did: String,
    entry: VtcAclEntry,
    /// The DID of the console key it signed through (#1684) — a public
    /// `did:key`, not key material.
    console_did: Option<String>,
}

impl AdminActor {
    /// Read `did`'s live entry and admit it as an administrator, with the
    /// refusals the admin verbs have always given: absent or expired is
    /// `Forbidden`, as is an entry that is not an administrator's
    /// ([`super::auth_role_for`]).
    pub async fn resolve(
        acl_ks: &vti_common::store::KeyspaceHandle,
        did: &str,
    ) -> Result<Self, AppError> {
        let entry = super::get_acl_entry(acl_ks, did)
            .await?
            .ok_or_else(|| AppError::Forbidden(format!("DID not in ACL: {did}")))?;
        if entry.is_expired(crate::auth::session::now_epoch()) {
            return Err(AppError::Forbidden(format!("ACL entry expired: {did}")));
        }
        super::auth_role_for(&entry)?;
        Ok(Self {
            did: did.to_string(),
            entry,
            console_did: None,
        })
    }

    /// The same actor, recorded as acting through console key `console_did`.
    #[must_use]
    pub fn through_console_key(mut self, console_did: impl Into<String>) -> Self {
        self.console_did = Some(console_did.into());
        self
    }

    /// The administrator's DID.
    pub fn did(&self) -> &str {
        &self.did
    }

    /// The console key this actor signed through, if it did.
    pub fn via_console_key(&self) -> Option<&str> {
        self.console_did.as_deref()
    }

    /// Whether the actor's entry, as read when it was authorized, holds `cap`
    /// at `resource` (`None` = community-wide) — [`VtcAclEntry::can`].
    pub fn can(&self, cap: Capability, resource: Option<&ResourceQualifier>) -> bool {
        self.entry.can(cap, resource)
    }

    /// [`Self::can`] as a refusal, worded exactly as
    /// [`super::require_capability`] words it: a suspended entry names its
    /// suspension, anything else the capability that is missing.
    pub fn require(
        &self,
        cap: Capability,
        resource: Option<&ResourceQualifier>,
    ) -> Result<(), AppError> {
        if self.entry.can(cap, resource) {
            return Ok(());
        }
        match &self.entry.suspension {
            Some(s) => Err(s.refusal(&self.did)),
            None => Err(super::storage::capability_refusal(&self.did, cap, resource)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acl::VtcRole;
    use crate::test_support::TestVtc;
    use crate::trust_tasks::test_fixtures::seed_acl;

    const ADMIN: &str = "did:key:zActorAdmin";
    const SCOPED: &str = "did:key:zActorScoped";
    const MEMBER: &str = "did:key:zActorMember";

    async fn vtc() -> TestVtc {
        let vtc = TestVtc::builder().build().await;
        seed_acl(&vtc, ADMIN, VtcRole::Admin, vec![]).await;
        seed_acl(&vtc, SCOPED, VtcRole::Admin, vec!["ctx-a".to_string()]).await;
        seed_acl(&vtc, MEMBER, VtcRole::Member, vec![]).await;
        vtc
    }

    /// The refusals the admin verbs gave when they built claims from
    /// `resolve_auth_role`: no entry, or an entry that is not an
    /// administrator's, is `Forbidden`.
    #[tokio::test]
    async fn resolve_admits_administrators_only() {
        let vtc = vtc().await;
        let ks = &vtc.state.acl_ks;
        assert_eq!(
            AdminActor::resolve(ks, ADMIN).await.expect("admin").did(),
            ADMIN
        );
        for did in [MEMBER, "did:key:zNobody"] {
            assert!(
                matches!(
                    AdminActor::resolve(ks, did).await,
                    Err(AppError::Forbidden(_))
                ),
                "{did} is no administrator"
            );
        }
    }

    /// `can` / `require` on the entry read once answer exactly what
    /// [`crate::acl::require_capability`] answers on a fresh read — every
    /// capability, both administrators, the refusal worded alike (#2580).
    #[tokio::test]
    async fn require_answers_as_require_capability_does() {
        let vtc = vtc().await;
        let ks = &vtc.state.acl_ks;
        for did in [ADMIN, SCOPED] {
            let actor = AdminActor::resolve(ks, did).await.expect("administrator");
            for cap in Capability::ALL {
                let fresh = crate::acl::require_capability(ks, did, cap, None).await;
                let held = actor.require(cap, None);
                assert_eq!(fresh.is_ok(), held.is_ok(), "{did} {cap:?}");
                assert_eq!(actor.can(cap, None), held.is_ok());
                if let (Err(a), Err(b)) = (fresh, held) {
                    assert_eq!(a.to_string(), b.to_string());
                }
            }
        }
    }
}
