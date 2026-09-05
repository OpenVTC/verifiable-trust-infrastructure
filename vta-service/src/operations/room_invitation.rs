//! Verifying a room invitation, and consuming it exactly once.
//!
//! This is the gate `rooms/keys/welcome` puts its weight on. A Welcome carries a group's
//! secrets, so anyone able to reach a VTA could otherwise push group state into it — filling
//! its storage at best, and at worst making it hold keys for a room nobody agreed to join.
//!
//! The answer was already in the design and only needed connecting: **joining a room is a
//! two-party act, and the invitation is the consent artefact**. This module is where that
//! stops being ceremonial. A VTA that accepted an uninvited Welcome would have made the
//! invitation decorative.
//!
//! # Five checks, and none of them is optional
//!
//! 1. It parses as a DTG credential, and it is an **invitation** — not some other credential
//!    the sender had lying around.
//! 2. Its **proof verifies**. Everything below is a claim until this holds; a well-formed
//!    invitation naming anyone is trivial to write.
//! 3. The **issuer is the room**. An invitation to a different room is not an invitation to
//!    this one, however valid.
//! 4. The **subject is us**. An invitation issued to somebody else is not transferable, and
//!    accepting one would let a third party place a member into a room they were invited to.
//! 5. It is **within its validity window**, and **not already consumed**.
//!
//! Dropping any one of them leaves a way in. The order is deliberate too: the cheap
//! structural checks come before the signature verification, which comes before the storage
//! read, so a malformed or irrelevant credential costs nothing.

use chrono::Utc;
use dtg_credentials::{DTGCredential, DTGCredentialType};
use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;
use vti_rooms_dtg::VerificationKeys;

/// A verified, not-yet-consumed invitation.
///
/// Constructible only by [`verify`], so a caller cannot reach the consumption step with an
/// invitation nobody checked — the same typestate discipline the workspace uses for verified
/// wire forms.
#[derive(Debug)]
pub struct VerifiedInvitation {
    credential_id: String,
    subject: String,
}

impl VerifiedInvitation {
    /// The credential's own id, which is what consumption records.
    pub fn credential_id(&self) -> &str {
        &self.credential_id
    }
    /// The party invited — established by the credential, not claimed by the sender.
    pub fn subject(&self) -> &str {
        &self.subject
    }
}

/// Verify an invitation for `room_id` naming `expected_subject`.
///
/// `keys` resolves the issuer's verification method. Failing to resolve is a refusal, never
/// a pass: a VTA that treated an unresolvable issuer as "probably fine" would have stopped
/// checking signatures.
pub async fn verify(
    encoded: &str,
    room_id: &str,
    expected_subject: &str,
    keys: &dyn VerificationKeys,
) -> Result<VerifiedInvitation, AppError> {
    let credential: DTGCredential = decode(encoded)?;

    if !matches!(credential.type_(), DTGCredentialType::Invitation) {
        return Err(AppError::Validation(format!(
            "the presented credential is a {}, not an invitation",
            credential.type_()
        )));
    }
    if credential.issuer() != room_id {
        return Err(AppError::Validation(format!(
            "the invitation was issued by `{}`, not by room `{room_id}`",
            credential.issuer()
        )));
    }
    if credential.subject() != expected_subject {
        return Err(AppError::Validation(format!(
            "the invitation names `{}`, not this member; an invitation is not transferable",
            credential.subject()
        )));
    }

    let now = Utc::now();
    let common = credential.credential();
    if common.valid_from > now {
        return Err(AppError::Validation(
            "the invitation is not valid yet".into(),
        ));
    }
    if let Some(until) = common.valid_until
        && until < now
    {
        return Err(AppError::Validation("the invitation has expired".into()));
    }

    // Everything above is a claim until this holds.
    let proof = common
        .proof
        .as_ref()
        .ok_or_else(|| AppError::Validation("the invitation carries no proof".into()))?;
    let key = keys
        .public_key(&proof.verification_method)
        .await
        .map_err(|e| {
            tracing::warn!(
                verification_method = %proof.verification_method,
                error = %e,
                "could not resolve an invitation's verification method"
            );
            AppError::Validation("the invitation could not be verified".into())
        })?;
    credential.verify_proof_with_public_key(&key).map_err(|e| {
        tracing::warn!(error = %e, "an invitation's proof did not verify");
        AppError::Validation("the invitation could not be verified".into())
    })?;

    Ok(VerifiedInvitation {
        credential_id: credential
            .id()
            .ok_or_else(|| {
                // Without an id there is nothing to record as consumed, so single-use
                // cannot be enforced — and an invitation that cannot be spent is one that
                // can be spent forever.
                AppError::Validation(
                    "the invitation carries no id, so it cannot be recorded as used".into(),
                )
            })?
            .to_string(),
        subject: credential.subject().to_string(),
    })
}

/// Accept base64url or bare JSON — the same profile the room verifier reads.
fn decode(encoded: &str) -> Result<DTGCredential, AppError> {
    use base64::Engine as _;
    let bytes = if encoded.trim_start().starts_with('{') {
        encoded.as_bytes().to_vec()
    } else {
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(encoded.trim())
            .map_err(|_| {
                AppError::Validation(
                    "the invitation is neither base64url nor JSON; one that cannot be read \
                     cannot be verified"
                        .into(),
                )
            })?
    };
    serde_json::from_slice(&bytes)
        .map_err(|e| AppError::Validation(format!("the invitation is not a DTG credential: {e}")))
}

/// Whether this invitation has already been spent.
pub async fn is_consumed(
    invitations: &KeyspaceHandle,
    credential_id: &str,
) -> Result<bool, AppError> {
    Ok(invitations
        .get_raw(super::room_groups::invitation_key(credential_id))
        .await
        .map_err(|e| AppError::Internal(format!("read the invitation record: {e}")))?
        .is_some())
}
