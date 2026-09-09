//! Verifying a room invitation, in the browser.
//!
//! A **VIC** is the consent artefact: joining a room is a two-party act, and this is the
//! other party's half. The gate belongs on the *member's* side, which is the part that looks
//! wrong at first — an attacker would simply not check — so it is worth stating what it
//! actually defends.
//!
//! It is not defending the room. It defends **this key holder**:
//!
//! - Minting a KeyPackage retains a private key against a Welcome that may never come. A
//!   key holder that minted for anyone is one anyone can fill.
//! - A Welcome carries a group's secrets. A key holder that accepted an uninvited one would
//!   hold keys for a room nobody agreed to join — and would have made the invitation
//!   decorative.
//!
//! The room's own protection is separate and lives at the owner, who refuses to add a
//! KeyPackage from a DID it never invited. Two checks, two parties, two different threats;
//! neither substitutes for the other.
//!
//! # Five checks, and none is optional
//!
//! Ported from `vta-service`'s `operations::room_invitation`, deliberately including its
//! order — the cheap structural checks first, then the signature, then the spent-set — so a
//! malformed or irrelevant credential costs nothing.
//!
//! 1. It parses, and it is an **invitation** rather than some other credential the sender
//!    had lying around.
//! 2. The **issuer is this room**. An invitation to a different room is not one to this one,
//!    however valid.
//! 3. The **subject is us**. An invitation is not transferable.
//! 4. It is **within its validity window**, its proof's key **belongs to the issuer**, and
//!    the **proof verifies**. Everything above is a claim until this holds: a well-formed
//!    invitation naming anyone is trivial to write, and a proof that verifies only means
//!    *somebody* signed it — the binding to the issuer is what makes it the room.
//! 5. It is **not already spent**.
//!
//! Dropping any one leaves a way in. This is a second copy of a gate that already exists in
//! `vta-service`, which is exactly how one of them ends up a check short — it belongs in
//! `vti-rooms` where both can share it, and that is a follow-up rather than a demo concern.
//!
//! # Why no resolver
//!
//! The proof is checked against raw public-key bytes, and a room identified by a `did:key`
//! or a `did:peer` carries its own key in its identifier. So verification needs no network,
//! no cache, and nothing to be online for. The same guarantee `room-host` makes on the other
//! side, and since `vta-sdk`'s verifier learned `did:peer` the two agree about which methods
//! it covers.
//!
//! `did:peer` matters rather than being a bonus: only it can carry a **service block**, so
//! only it lets a room advertise the mediator its members reach its owner through. A
//! `did:webvh` room — what production mints — would need real resolution, and that is the
//! one thing this module would grow.

use chrono::Utc;
use dtg_credentials::{DTGCredential, DTGCredentialType};

/// What a verified invitation yields: the id to record as spent, and nothing else worth
/// carrying. Constructible only by [`verify`], so a caller cannot reach the spending step
/// with an invitation nobody checked.
#[derive(Debug)]
pub struct VerifiedInvitation {
    pub credential_id: String,
}

/// The Ed25519 public key a verification method names, with **no network**.
///
/// Two methods, and the same reason for both: they carry their keys in their identifiers,
/// so resolving one is arithmetic rather than a lookup. That is what lets a browser member
/// verify an invitation while offline, and it is the same guarantee `room-host` makes on
/// the other side — its verifier is configured for no I/O, and since
/// `vta-sdk`'s `TrustTaskVmResolver` learned `did:peer` the two agree about which methods
/// that covers.
///
/// - `did:key:z6Mk…#z6Mk…` — the fragment *is* the identifier; decode the multibase.
/// - `did:peer:2.Vz6Mk…` — resolved by `PeerResolver`, which the specification's own
///   implementation describes as "pure computation (no IO)". Not hand-decoded here: the
///   segment layout and the fragment convention are the resolver's to know, and a second
///   opinion about them is a second thing to get wrong.
///
/// A `did:webvh` room — what production mints — would need real resolution, and that is the
/// one thing this module would have to grow.
fn verification_key(verification_method: &str) -> Result<Vec<u8>, String> {
    let did = verification_method
        .split('#')
        .next()
        .unwrap_or(verification_method);

    if let Some(multibase) = did.strip_prefix("did:key:") {
        let (_base, bytes) =
            multibase::decode(multibase).map_err(|e| format!("decode `{did}`: {e}"))?;
        return match bytes.split_at_checked(2) {
            Some(([0xed, 0x01], key)) if key.len() == 32 => Ok(key.to_vec()),
            _ => Err(format!(
                "`{did}` does not name an Ed25519 key; a room signs with Ed25519"
            )),
        };
    }

    if did.starts_with("did:peer:") {
        use affinidi_did_common::DID;
        use affinidi_did_resolver_traits::{PeerResolver, Resolver};

        let parsed =
            DID::try_from(did).map_err(|e| format!("`{did}` is not a well-formed DID: {e}"))?;
        let doc = PeerResolver
            .resolve(&parsed)
            .ok_or_else(|| format!("`{did}` is not a did:peer this build resolves"))?
            .map_err(|e| format!("`{did}` did not resolve: {e}"))?;

        // A proof names a method absolutely; a document may name it relatively. Accept
        // both spellings of the same method rather than requiring the document to have
        // chosen ours.
        let relative = verification_method
            .split_once('#')
            .map(|(_, fragment)| format!("#{fragment}"))
            .unwrap_or_default();
        let entry = doc
            .verification_method
            .iter()
            .find(|m| m.id.as_str() == verification_method || m.id.as_str() == relative)
            .ok_or_else(|| {
                format!("`{verification_method}` is not in the DID document for `{did}`")
            })?;
        return entry
            .get_public_key_bytes()
            .map_err(|e| format!("`{verification_method}` public key: {e}"));
    }

    Err(format!(
        "`{did}` names a method this build cannot resolve without a network — only \
         `did:key` and `did:peer` carry their keys in the identifier"
    ))
}

/// Run the five checks. `spent` is the set of credential ids this key holder has already
/// consumed — held by the caller because that is where storage belongs, and passed in rather
/// than checked afterwards so that all five live in one place.
pub fn verify(
    encoded: &str,
    room_id: &str,
    expected_subject: &str,
    spent: &[String],
) -> Result<VerifiedInvitation, String> {
    // 1. It parses, and it is an invitation.
    let credential: DTGCredential = decode(encoded)?;
    if !matches!(credential.type_(), DTGCredentialType::Invitation) {
        return Err(format!(
            "the presented credential is a {}, not an invitation",
            credential.type_()
        ));
    }

    // 2. The issuer is this room.
    if credential.issuer() != room_id {
        return Err(format!(
            "the invitation was issued by `{}`, not by room `{room_id}`",
            credential.issuer()
        ));
    }

    // 3. The subject is us.
    if credential.subject() != expected_subject {
        return Err(format!(
            "the invitation names `{}`, not you — an invitation is not transferable",
            credential.subject()
        ));
    }

    // 4. In window, and the proof verifies.
    let now = Utc::now();
    let common = credential.credential();
    if common.valid_from > now {
        return Err("the invitation is not valid yet".into());
    }
    if let Some(until) = common.valid_until
        && until < now
    {
        return Err("the invitation has expired".into());
    }
    let proof = common
        .proof
        .as_ref()
        .ok_or("the invitation carries no proof")?;

    // The proof's key must belong to the **issuer**, and this is not implied by
    // anything above it.
    //
    // `verify_proof_with_public_key` checks a signature against whatever bytes it is
    // handed; resolving the verification method the proof names and verifying against
    // *that* proves only that somebody signed it — which is true of a forgery. Without
    // this line an attacker mints an invitation naming the room as issuer, signs it with
    // their own key, points the proof at their own verification method, and every other
    // check here passes.
    //
    // Found by writing a test per clause rather than one "a bad invitation is refused"
    // case: the forgery clause was the only one that did not bite.
    let vm_controller = proof
        .verification_method
        .split('#')
        .next()
        .unwrap_or(&proof.verification_method);
    if vm_controller != credential.issuer() {
        return Err(format!(
            "the invitation says room `{}` issued it but is signed by `{vm_controller}` — a \
             proof that verifies only means somebody signed it, not that the issuer did",
            credential.issuer()
        ));
    }

    let key = verification_key(&proof.verification_method)?;
    credential
        .verify_proof_with_public_key(&key)
        .map_err(|e| format!("the invitation's proof did not verify: {e}"))?;

    // 5. Not already spent. Without an id there is nothing to record, and an invitation
    //    that cannot be spent is one that can be spent forever.
    let credential_id = credential
        .id()
        .ok_or("the invitation carries no id, so it cannot be recorded as used")?
        .to_string();
    if spent.contains(&credential_id) {
        return Err(format!(
            "invitation `{credential_id}` has already been used"
        ));
    }

    Ok(VerifiedInvitation { credential_id })
}

/// Accept base64url or bare JSON — the same profile the room verifier reads.
fn decode(encoded: &str) -> Result<DTGCredential, String> {
    let trimmed = encoded.trim();
    if trimmed.starts_with('{') {
        return serde_json::from_str(trimmed).map_err(|e| format!("invitation JSON: {e}"));
    }
    use base64::Engine as _;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(trimmed.as_bytes())
        .map_err(|e| format!("invitation base64: {e}"))?;
    serde_json::from_slice(&bytes).map_err(|e| format!("invitation JSON: {e}"))
}
