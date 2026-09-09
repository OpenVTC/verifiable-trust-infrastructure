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
//! # Six checks, and none of them is optional
//!
//! 1. It parses as a DTG credential, and it is an **invitation** — not some other credential
//!    the sender had lying around.
//! 2. The **issuer is the room**. An invitation to a different room is not an invitation to
//!    this one, however valid.
//! 3. The **subject is us**. An invitation issued to somebody else is not transferable, and
//!    accepting one would let a third party place a member into a room they were invited to.
//! 4. The proof's key **belongs to the issuer**. A proof that verifies only means *somebody*
//!    signed it, which is equally true of a forgery; this is what makes that somebody the
//!    room.
//! 5. Its **proof verifies**. Everything above is a claim until this holds; a well-formed
//!    invitation naming anyone is trivial to write.
//! 6. It is **within its validity window**, and **not already consumed**.
//!
//! Dropping any one of them leaves a way in. The order is deliberate too: the cheap
//! structural checks come before the signature verification, which comes before the storage
//! read, so a malformed or irrelevant credential costs nothing.
//!
//! Check 4 was absent until it was found by porting this module to a browser and writing a
//! test per clause rather than one "a bad invitation is refused" case — which passes with
//! any five of six, and did.

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

    // The proof's key must belong to the **issuer**, and nothing above implies it.
    //
    // Resolving whatever verification method the proof names and verifying against it
    // proves only that *somebody* signed the credential — which is equally true of a
    // forgery. Without this, an attacker mints an invitation naming the room as issuer,
    // signs it with their own key, points the proof at their own verification method, and
    // checks 1–4 above all pass: the room is right, the subject is right, the window is
    // right, and the signature verifies against the attacker's own key.
    //
    // Cheap, and deliberately before the resolver call: a credential that cannot be the
    // room's own is refused without a network round trip.
    let vm_controller = proof
        .verification_method
        .split('#')
        .next()
        .unwrap_or(&proof.verification_method);
    if vm_controller != credential.issuer() {
        tracing::warn!(
            issuer = %credential.issuer(),
            signer = %vm_controller,
            "an invitation claiming a room as issuer was signed by another party"
        );
        return Err(AppError::Validation(format!(
            "the invitation says room `{}` issued it but is signed by `{vm_controller}`",
            credential.issuer()
        )));
    }

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

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;

    /// Resolves a `did:key` verification method lexically — the key is the identifier, so
    /// there is nothing to look up. Enough to exercise this module without a network or a
    /// resolver cache, which is why it had no unit tests before.
    struct DidKeyOnly;

    #[async_trait::async_trait]
    impl vti_rooms_dtg::VerificationKeys for DidKeyOnly {
        async fn public_key(&self, verification_method: &str) -> Result<Vec<u8>, AppError> {
            let did = verification_method
                .split('#')
                .next()
                .unwrap_or(verification_method);
            let mb = did
                .strip_prefix("did:key:")
                .ok_or_else(|| AppError::Validation(format!("not a did:key: {did}")))?;
            let (_, bytes) = multibase::decode(mb)
                .map_err(|e| AppError::Validation(format!("decode {did}: {e}")))?;
            Ok(bytes[2..].to_vec())
        }
    }

    /// A `did:key` and the secret behind it.
    fn a_party(seed: u8) -> (String, affinidi_secrets_resolver::secrets::Secret) {
        let sk = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
        let pk = sk.verifying_key().to_bytes();
        let mut mc = vec![0xed, 0x01];
        mc.extend_from_slice(&pk);
        let did = format!(
            "did:key:{}",
            multibase::encode(multibase::Base::Base58Btc, &mc)
        );
        let secret = affinidi_secrets_resolver::secrets::Secret::from_str(
            &format!("{did}#{}", did.trim_start_matches("did:key:")),
            &serde_json::json!({
                "crv": "Ed25519",
                "d": B64.encode(sk.to_bytes()),
                "kty": "OKP",
                "x": B64.encode(pk),
            }),
        )
        .expect("build a signing secret");
        (did, secret)
    }

    /// An invitation from `issuer` to `subject`, signed by `signer`.
    ///
    /// `signer` is separate from `issuer` on purpose: a forgery is exactly the case where
    /// they differ, and a helper that could not express it could not test for it.
    async fn an_invitation(
        issuer: &str,
        signer: &affinidi_secrets_resolver::secrets::Secret,
        subject: &str,
        id: &str,
    ) -> String {
        let now = Utc::now();
        let mut vic = DTGCredential::new_vic(
            issuer.to_string(),
            subject.to_string(),
            now - chrono::Duration::minutes(1),
            Some(now + chrono::Duration::hours(1)),
        )
        .with_id(id);
        vic.sign(signer, None).await.expect("sign the invitation");
        serde_json::to_string(vic.credential()).expect("serialise")
    }

    #[tokio::test]
    async fn a_genuine_invitation_verifies() {
        let (room, room_secret) = a_party(0x41);
        let vic = an_invitation(&room, &room_secret, "did:key:zMember", "urn:uuid:i-1").await;

        let verified = verify(&vic, &room, "did:key:zMember", &DidKeyOnly)
            .await
            .expect("a genuine invitation must verify");
        assert_eq!(verified.credential_id(), "urn:uuid:i-1");
    }

    /// The check that was missing: an invitation naming the room as issuer but signed by
    /// somebody else.
    ///
    /// Every other clause passes here — it is an invitation, the issuer field is the room,
    /// the subject is the member, the window is open, and the proof verifies perfectly
    /// against the key it names. The only thing wrong is *whose* key that is, and without
    /// this check nothing looks at it: anyone could mint themselves an invitation to any
    /// room, join it, and hold its group keys.
    #[tokio::test]
    async fn an_invitation_signed_by_anyone_but_the_room_is_refused() {
        let (room, _room_secret) = a_party(0x42);
        let (_attacker, attacker_secret) = a_party(0x43);

        // Issuer says the room; the signature is the attacker's own.
        let forged =
            an_invitation(&room, &attacker_secret, "did:key:zMember", "urn:uuid:i-2").await;

        let err = verify(&forged, &room, "did:key:zMember", &DidKeyOnly)
            .await
            .expect_err("a forged invitation must be refused");
        assert!(
            format!("{err}").contains("is signed by"),
            "the refusal must name the mismatch rather than read as a bad signature: {err}"
        );
    }

    #[tokio::test]
    async fn an_invitation_to_another_room_is_refused() {
        let (room, _) = a_party(0x44);
        let (elsewhere, elsewhere_secret) = a_party(0x45);
        let vic = an_invitation(
            &elsewhere,
            &elsewhere_secret,
            "did:key:zMember",
            "urn:uuid:i-3",
        )
        .await;

        let err = verify(&vic, &room, "did:key:zMember", &DidKeyOnly)
            .await
            .expect_err("an invitation to another room is not one to this one");
        assert!(format!("{err}").contains("issued by"), "{err}");
    }

    #[tokio::test]
    async fn an_invitation_to_somebody_else_is_refused() {
        let (room, room_secret) = a_party(0x46);
        let vic = an_invitation(&room, &room_secret, "did:key:zSomeoneElse", "urn:uuid:i-4").await;

        let err = verify(&vic, &room, "did:key:zMember", &DidKeyOnly)
            .await
            .expect_err("an invitation is not transferable");
        assert!(format!("{err}").contains("not transferable"), "{err}");
    }
}
