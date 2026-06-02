//! The pre-verification typestate — [`VerifiedFacts`]
//! (ceremony-pipeline design §2 "Verify", §9).
//!
//! The pipeline's load-bearing invariant: **crypto lives entirely in
//! the Verify stage, so the policy reasons only over a verified
//! view.** This module is where that becomes a *type*, not a
//! convention. The evaluate stage takes a [`VerifiedFacts`], which can
//! only be produced by running raw [`Facts`] through
//! [`VerifiedFacts::assemble`]. A call site that tries to evaluate
//! un-verified facts doesn't compile — it has a [`Facts`], not a
//! [`VerifiedFacts`].
//!
//! This generalizes the MVP's `VerifiedJoinRequest` (`vtc-mvp.md`
//! §10.1) from one ceremony to all of them, per the build-vs-reuse
//! map (pipeline §10: "generalize `VerifiedJoinRequest` →
//! `VerifiedFacts`").
//!
//! ## What "verified" means here
//!
//! The per-evidence cryptography — VP proof checking, holder-binding,
//! invitation-signature verification, status-list resolution,
//! issuer-trust via TRQP — is performed by the host *upstream* and
//! recorded into the `verified` / `issuer_trusted` / `status` fields
//! of [`Facts`]. [`VerifiedFacts::assemble`] is the **gate** that
//! refuses to let facts reach the policy unless every evidence slot
//! the actor presented actually carries a passing `verified` verdict.
//! An authenticity failure aborts here and never reaches policy — the
//! design's "identity/authenticity failure → abort (never reach
//! policy)" edge.
//!
//! What this gate deliberately does **not** do: re-run the crypto
//! (that's the host's job, upstream), or judge a credential's
//! `status` / `issuer_trusted` (those are *facts the policy decides
//! on*, not authenticity preconditions — a revoked-but-genuinely-
//! verified credential is a valid fact for a policy to reject).

use serde_json::Value as JsonValue;
use vti_common::error::AppError;

use super::facts::{Facts, Purpose};

/// Facts that have passed the verification gate. Only constructable
/// via [`Self::assemble`]; the evaluate stage takes this, never a bare
/// [`Facts`].
///
/// The inner [`Facts`] is private so the only way to obtain a
/// `VerifiedFacts` is to go through the gate — there is no
/// `VerifiedFacts { .. }` literal and no `From<Facts>`.
#[derive(Debug, Clone, PartialEq)]
pub struct VerifiedFacts(Facts);

/// Why a set of facts failed the verification gate. Each variant maps
/// to an authenticity failure that must abort before policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
    /// A presentation was presented but its host verdict is
    /// `verified: false` — its proof or holder-binding did not check
    /// out.
    PresentationNotVerified,
    /// An invitation was presented but its host verdict is
    /// `verified: false` — its signature did not check out.
    InvitationNotVerified,
}

impl VerifyError {
    /// Stable code for audit + operator-facing surfaces.
    pub fn code(&self) -> &'static str {
        match self {
            VerifyError::PresentationNotVerified => "presentation-not-verified",
            VerifyError::InvitationNotVerified => "invitation-not-verified",
        }
    }
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VerifyError::PresentationNotVerified => f.write_str("presented VP failed verification"),
            VerifyError::InvitationNotVerified => {
                f.write_str("presented invitation failed verification")
            }
        }
    }
}

impl std::error::Error for VerifyError {}

impl From<VerifyError> for AppError {
    /// An authenticity failure is a `Forbidden` — the caller's
    /// evidence didn't check out, so the transition is refused before
    /// any policy runs. (Not `Validation`: the request was
    /// well-formed; its cryptographic claims were false.)
    fn from(e: VerifyError) -> Self {
        AppError::Forbidden(format!("{} ({})", e, e.code()))
    }
}

impl VerifiedFacts {
    /// Run [`Facts`] through the verification gate.
    ///
    /// Refuses any facts whose presented evidence carries a failing
    /// host verdict: a present-but-unverified presentation or
    /// invitation aborts the ceremony here. Evidence slots the actor
    /// didn't present are absent and impose no obligation — a
    /// directory query with no presentation passes the gate trivially.
    ///
    /// On success the facts are sealed into a `VerifiedFacts` that the
    /// evaluate stage will accept.
    pub fn assemble(facts: Facts) -> Result<Self, VerifyError> {
        if let Some(presentation) = &facts.evidence.presentation
            && !presentation.verified
        {
            return Err(VerifyError::PresentationNotVerified);
        }
        if let Some(invitation) = &facts.evidence.invitation
            && !invitation.verified
        {
            return Err(VerifyError::InvitationNotVerified);
        }
        Ok(VerifiedFacts(facts))
    }

    /// The verified facts, for read-only inspection (audit, effect
    /// handlers that need the subject DID, etc.).
    pub fn facts(&self) -> &Facts {
        &self.0
    }

    /// The ceremony these facts decide — selects the policy module and
    /// effect handler without unwrapping the whole struct.
    pub fn purpose(&self) -> Purpose {
        self.0.purpose
    }

    /// Serialize to the JSON `input` document the policy evaluates
    /// over. This is the only sanctioned way to feed facts to
    /// [`crate::policy::engine::evaluate`] — the engine's `input` is
    /// always the output of a verification gate.
    pub fn to_input(&self) -> Result<JsonValue, AppError> {
        serde_json::to_value(&self.0).map_err(AppError::from)
    }

    /// Consume the wrapper and return the inner facts. For the effect
    /// stage, which has already evaluated the policy and is applying
    /// the decision.
    pub fn into_inner(self) -> Facts {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ceremony::facts::{
        Actor, Context, Credential, CredentialStatus, Evidence, Invitation, Presentation, State,
        Subject,
    };
    use serde_json::json;

    fn base_facts(purpose: Purpose) -> Facts {
        Facts {
            purpose,
            now: "2026-05-30T12:00:00Z".parse().unwrap(),
            actor: Actor {
                did: "did:key:zActor".into(),
                role: None,
                authenticated: true,
            },
            subject: Subject {
                did: "did:key:zActor".into(),
            },
            context: Context {
                community_did: "did:webvh:acme.example".into(),
                channel: "rest".into(),
                member_count: 10,
            },
            evidence: Evidence::default(),
            state: State::default(),
        }
    }

    fn verified_presentation() -> Presentation {
        Presentation {
            verified: true,
            holder: "did:key:zActor".into(),
            credentials: vec![Credential {
                credential_type: "WitnessCredential".into(),
                issuer: "did:webvh:notary.example".into(),
                issuer_trusted: true,
                status: CredentialStatus::Valid,
                claims: json!({}),
                valid_until: None,
            }],
        }
    }

    /// A directory query with no presented evidence passes the gate —
    /// absent slots impose no obligation.
    #[test]
    fn empty_evidence_passes_the_gate() {
        let facts = base_facts(Purpose::Directory);
        let verified = VerifiedFacts::assemble(facts.clone()).expect("empty evidence is fine");
        assert_eq!(verified.facts(), &facts);
        assert_eq!(verified.purpose(), Purpose::Directory);
    }

    /// A verified presentation passes and is sealed in.
    #[test]
    fn verified_presentation_passes() {
        let mut facts = base_facts(Purpose::Join);
        facts.evidence.presentation = Some(verified_presentation());
        let verified = VerifiedFacts::assemble(facts).expect("verified presentation passes");
        // `to_input` reproduces the policy `input` document.
        let input = verified.to_input().unwrap();
        assert_eq!(input["evidence"]["presentation"]["verified"], true);
    }

    /// A presentation whose host verdict is `verified: false` aborts
    /// here — it never reaches policy.
    #[test]
    fn unverified_presentation_is_rejected() {
        let mut facts = base_facts(Purpose::Join);
        let mut pres = verified_presentation();
        pres.verified = false;
        facts.evidence.presentation = Some(pres);
        let err = VerifiedFacts::assemble(facts).expect_err("unverified presentation must abort");
        assert_eq!(err, VerifyError::PresentationNotVerified);

        // And it maps to a Forbidden, not a Validation.
        let app: AppError = err.into();
        assert!(matches!(app, AppError::Forbidden(_)), "got {app:?}");
    }

    /// An invitation whose host verdict is `verified: false` aborts.
    #[test]
    fn unverified_invitation_is_rejected() {
        let mut facts = base_facts(Purpose::Join);
        facts.evidence.invitation = Some(Invitation {
            verified: false,
            issuer: "did:webvh:acme.example".into(),
            issuer_role: Some("admin".into()),
            scopes: vec![],
            consumed: false,
        });
        let err = VerifiedFacts::assemble(facts).expect_err("unverified invitation must abort");
        assert_eq!(err, VerifyError::InvitationNotVerified);
    }

    /// A genuinely-verified-but-revoked credential is a *valid fact*
    /// for the policy to reject — the gate does not judge `status`, so
    /// these facts pass through to be decided by policy.
    #[test]
    fn revoked_but_verified_credential_passes_the_gate() {
        let mut facts = base_facts(Purpose::Join);
        let mut pres = verified_presentation();
        pres.credentials[0].status = CredentialStatus::Revoked;
        facts.evidence.presentation = Some(pres);
        // verified: true holds — the credential's authenticity is not
        // in question, only its status, which is the policy's call.
        VerifiedFacts::assemble(facts).expect("revoked-but-verified is a fact, not an abort");
    }
}
