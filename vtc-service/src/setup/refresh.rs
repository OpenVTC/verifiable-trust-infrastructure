//! Taking over the keys of a `did:webs` VTC after its VTA rotated them.
//!
//! A level-1 `did:webs` VTC (VTI-KEY-146) signs with its key event log's one
//! key-state key. `pnm webs rotate` replaces that key, and with it the key's id
//! (`<did>#<CESR key>`), so the bundle the VTC stored at setup then names a key
//! its document no longer lists: everything it signs from then on is material a
//! verifier must refuse (VTI-KEY-042). The VTC keeps no VTA credential, so the
//! new keys reach it the way every other secret does — sealed by the operator
//! (`pnm keys bundle <context>`) to a request this VTC wrote — and
//! [`successor_bundle`] decides whether what arrived may replace the bundle.
//!
//! Two rules make the replacement safe:
//!
//! - **The resolved document is the authority.** Each key the bundle will hold
//!   must be the one the VTC's current document publishes, under the id and in
//!   the relationship it publishes it in. A bundle sealed before another
//!   rotation, or for another DID, is refused before anything is written.
//! - **The derivation root stays.** The at-rest storage key, the install-token
//!   signer and the audit key derive from the bundle's root, which for a VTC
//!   set up before any rotation is its first signing key
//!   ([`VtcKeyBundle::carry_derivation_root_to`]). The successor carries that
//!   root, so the store stays readable.
//!
//! [`stale_signing_key`] is the same comparison run at boot: a VTC whose
//! document no longer lists its signing key refuses to start, naming the
//! command that fixes it.

use serde_json::Value;
use vta_sdk::did_secrets::DidSecretsBundle;
use vta_sdk::keys::KeyType;
use vta_sdk::node_keys::NodeKeyIds;
use vti_common::error::AppError;

use super::bundle::{
    VtcKeyBundle, decode_private_multibase, ed25519_priv_codec, encode_public_multibase,
    x25519_priv_codec,
};

/// The operator command that writes the request [`successor_bundle`]'s input
/// is sealed to. Named in every refusal that it fixes.
pub const REFRESH_COMMAND: &str = "vtc keys request";

/// What a sealed bundle means for the stored one.
#[derive(Debug)]
pub enum Refresh {
    /// The bundle holds the keys already stored: nothing to replace.
    Current,
    /// The bundle to store in place of the current one.
    Successor(Box<VtcKeyBundle>),
}

/// Build the bundle that replaces `current`, from the keys the VTA sealed
/// (`secrets`) and the VTC's freshly resolved `document`.
///
/// # Errors
/// [`AppError::Validation`] when the VTC is not a level-1 `did:webs`, the
/// bundle is for another DID, or a key it holds is not the one the document
/// publishes for its role; [`AppError::Conflict`] from
/// [`VtcKeyBundle::carry_derivation_root_to`].
pub fn successor_bundle(
    current: &VtcKeyBundle,
    secrets: &DidSecretsBundle,
    document: &Value,
) -> Result<Refresh, AppError> {
    let did = current.integration_did.as_str();
    if !did.starts_with("did:webs:") {
        return Err(AppError::Validation(format!(
            "{did} is not a did:webs: only a did:webs VTC's keys change under it (`pnm webs \
             rotate`), so there is nothing to take over"
        )));
    }
    if current.has_key_roles() || !current.additional_signing_keys.is_empty() {
        return Err(AppError::Validation(format!(
            "{did} holds keys by role or more than one signing key; taking over rotated keys \
             is implemented for a level-1 did:webs VTC (VTI-KEY-146) only"
        )));
    }
    if secrets.did != did {
        return Err(AppError::Validation(format!(
            "the bundle holds the keys of {}, not this VTC's {did}; seal this VTC's context \
             (`pnm keys bundle <context>`)",
            secrets.did
        )));
    }
    if document.get("keyRoles").is_some_and(Value::is_object) {
        return Err(AppError::Validation(format!(
            "{did}'s document now carries key roles; taking over rotated keys is implemented \
             for a level-1 did:webs VTC (VTI-KEY-146) only"
        )));
    }
    let ids = NodeKeyIds::from_document(did, document)
        .map_err(|e| AppError::Validation(format!("{did}'s document: {e}")))?;
    if ids.authentication != ids.signing {
        return Err(AppError::Validation(format!(
            "{did}'s document authenticates with {} and signs with {}; a level-1 did:webs \
             does both with its one key",
            ids.authentication, ids.signing
        )));
    }
    let ka_id = ids.key_agreement.clone().ok_or_else(|| {
        AppError::Validation(format!("{did}'s document lists no key agreement key"))
    })?;

    let signing = held_key(secrets, &ids.signing, KeyType::Ed25519)?;
    let ka = held_key(secrets, &ka_id, KeyType::X25519)?;

    let signing_private = decode_private_multibase(signing, ed25519_priv_codec())?;
    let signing_public = ed25519_dalek::SigningKey::from_bytes(&signing_private)
        .verifying_key()
        .to_bytes();
    let ka_private = decode_private_multibase(ka, x25519_priv_codec())?;
    let ka_public =
        x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(*ka_private)).to_bytes();
    check_published(document, did, &ids.signing, &signing_public)?;
    check_published(document, did, &ka_id, &ka_public)?;

    let mut next = VtcKeyBundle {
        integration_did: did.to_string(),
        ed25519_key_id: ids.signing.clone(),
        ed25519_public_multibase: encode_public_multibase(&signing_public, [0xed, 0x01]),
        ed25519_private_multibase: signing.to_string(),
        x25519_key_id: ka_id,
        x25519_public_multibase: encode_public_multibase(&ka_public, [0xec, 0x01]),
        x25519_private_multibase: ka.to_string(),
        additional_signing_keys: Vec::new(),
        authentication_key: None,
        derivation_root_multibase: current.derivation_root_multibase.clone(),
    };
    if next.ed25519_key_id == current.ed25519_key_id
        && next.ed25519_public_multibase == current.ed25519_public_multibase
        && next.x25519_key_id == current.x25519_key_id
        && next.x25519_public_multibase == current.x25519_public_multibase
    {
        return Ok(Refresh::Current);
    }
    current.carry_derivation_root_to(&mut next)?;
    Ok(Refresh::Successor(Box::new(next)))
}

/// Why `bundle`'s signing key no longer signs for `document`, or `None` when
/// the document still publishes it under the id the bundle stores.
///
/// Only a level-1 `did:webs` bundle is judged: its key ids are its keys
/// (`<did>#<CESR key>`), so a rotation changes them. Any other bundle answers
/// `None`.
pub fn stale_signing_key(bundle: &VtcKeyBundle, document: &Value) -> Option<String> {
    let did = bundle.integration_did.as_str();
    if !did.starts_with("did:webs:") || bundle.has_key_roles() {
        return None;
    }
    let ids = NodeKeyIds::from_document(did, document).ok()?;
    let stored = bundle.ed25519_key_id.as_str();
    let public =
        vta_sdk::did_key::decode_ed25519_public_key_multibase(&bundle.ed25519_public_multibase)
            .ok()?;
    if ids.signing == stored && published_key(document, did, stored).as_deref() == Some(&public) {
        return None;
    }
    Some(format!(
        "{did}'s document signs with {}, not the key this VTC holds ({stored}): its VTA \
         rotated the key (`pnm webs rotate`), and a verifier refuses what the retired key signs \
         (VTI-KEY-042). Take over the new keys with the VTC stopped: `{REFRESH_COMMAND}`, then \
         `pnm keys bundle <context> --recipient <request>` on the admin workstation, then `vtc \
         keys refresh --bundle <file> --digest <digest>`",
        ids.signing
    ))
}

/// The private key `secrets` holds for `id`, of `key_type`.
fn held_key<'a>(
    secrets: &'a DidSecretsBundle,
    id: &str,
    key_type: KeyType,
) -> Result<&'a str, AppError> {
    let entry = secrets
        .secrets
        .iter()
        .find(|s| s.key_id == id)
        .ok_or_else(|| {
            AppError::Validation(format!(
                "the bundle holds no key {id}, which {}'s document publishes: it was sealed \
                 before the document changed, or for another rotation; seal it again \
                 (`pnm keys bundle <context>`)",
                secrets.did
            ))
        })?;
    if entry.key_type != key_type {
        return Err(AppError::Validation(format!(
            "the bundle's key {id} is {:?}, not {key_type:?}",
            entry.key_type
        )));
    }
    Ok(&entry.private_key_multibase)
}

fn check_published(document: &Value, did: &str, id: &str, public: &[u8]) -> Result<(), AppError> {
    match published_key(document, did, id) {
        Some(published) if published == public => Ok(()),
        Some(_) => Err(AppError::Validation(format!(
            "the bundle's key {id} is not the key {did}'s document publishes under that id"
        ))),
        None => Err(AppError::Validation(format!(
            "{did}'s document lists {id} but carries no public key for it that this VTC can read"
        ))),
    }
}

/// The raw public key `document` publishes under `id` (`publicKeyJwk` of an
/// OKP key, or `publicKeyMultibase` with its two-byte multicodec prefix).
fn published_key(document: &Value, did: &str, id: &str) -> Option<Vec<u8>> {
    use base64::Engine as _;
    let vm = document
        .get("verificationMethod")?
        .as_array()?
        .iter()
        .find(|vm| {
            vm.get("id").and_then(Value::as_str).is_some_and(|vm_id| {
                vm_id == id
                    || vm_id
                        .strip_prefix('#')
                        .is_some_and(|f| format!("{did}#{f}") == id)
            })
        })?;
    if let Some(x) = vm
        .get("publicKeyJwk")
        .and_then(|jwk| jwk.get("x"))
        .and_then(Value::as_str)
    {
        return base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(x)
            .ok();
    }
    let multibase = vm.get("publicKeyMultibase").and_then(Value::as_str)?;
    let (_, bytes) = multibase::decode(multibase).ok()?;
    (bytes.len() == 34).then(|| bytes[2..].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::setup::bundle::bundle_from_raw;
    use crate::setup::bundle::level_one_tests::{KA, SIGNING, level_one_vtc_controlled};
    use affinidi_did_webs::{DidWebs, complete_rotation, prepare_rotation};
    use affinidi_keri::controller::{KeySigner, NextKey, Rotation};
    use affinidi_keri_core::threshold::Threshold;
    use affinidi_keri_crypto::Signer;
    use vta_sdk::did_secrets::SecretEntry;

    /// The pre-rotated successor of the fixture's signing key.
    const NEXT: [u8; 32] = [0x43; 32];

    struct Rotated {
        did: String,
        before: Value,
        after: Value,
    }

    /// The level-1 VTC of `level_one_tests`, before and after its VTA rotated
    /// the key-state key to the committed successor.
    fn rotated() -> Rotated {
        let (did, before, prior, state) = level_one_vtc_controlled();
        let successor = Signer::new("A", NEXT.to_vec()).unwrap();
        let after_next = Signer::new("A", vec![0x44; 32]).unwrap();
        let mut pending = prepare_rotation(
            &did,
            &prior,
            &state,
            &[successor.public_key().unwrap()],
            &Rotation::new(
                Threshold::Simple(1),
                vec![NextKey::PublicKey(after_next.public_key().unwrap())],
                Threshold::Simple(1),
            ),
        )
        .unwrap();
        pending.sign_with(&successor as &dyn KeySigner).unwrap();
        let rotated = complete_rotation(&did, &prior, pending).unwrap();
        let after = serde_json::to_value(
            affinidi_did_webs::resolve_from_artifacts(
                &DidWebs::parse(&did).unwrap(),
                &rotated.artifacts().keri_cesr,
                None,
            )
            .unwrap(),
        )
        .unwrap();
        Rotated { did, before, after }
    }

    /// The bundle setup stored, named by the document before the rotation.
    fn stored(did: &str, before: &Value) -> VtcKeyBundle {
        let ids = NodeKeyIds::from_document(did, before).unwrap();
        let mut bundle = bundle_from_raw(did, &SIGNING, &KA);
        bundle.ed25519_key_id = ids.signing;
        bundle.x25519_key_id = ids.key_agreement.unwrap();
        bundle
    }

    fn entry(id: &str, key_type: KeyType, raw: &[u8; 32]) -> SecretEntry {
        let codec = match key_type {
            KeyType::Ed25519 => ed25519_priv_codec(),
            _ => x25519_priv_codec(),
        };
        SecretEntry {
            key_id: id.to_string(),
            key_type,
            private_key_multibase: crate::setup::bundle::encode_private_multibase(raw, codec),
        }
    }

    /// What `pnm keys bundle` seals after the rotation: the keys the new
    /// document lists, under its ids.
    fn sealed_after(did: &str, after: &Value) -> DidSecretsBundle {
        let ids = NodeKeyIds::from_document(did, after).unwrap();
        DidSecretsBundle {
            did: did.to_string(),
            secrets: vec![
                entry(&ids.signing, KeyType::Ed25519, &NEXT),
                entry(&ids.key_agreement.unwrap(), KeyType::X25519, &KA),
            ],
        }
    }

    #[test]
    fn vti_key_042_a_rotated_key_is_taken_over_and_the_root_kept() {
        let r = rotated();
        let current = stored(&r.did, &r.before);
        let Refresh::Successor(next) =
            successor_bundle(&current, &sealed_after(&r.did, &r.after), &r.after).unwrap()
        else {
            panic!("a rotated key is a successor");
        };
        let ids = NodeKeyIds::from_document(&r.did, &r.after).unwrap();
        assert_eq!(next.ed25519_key_id, ids.signing);
        assert_ne!(next.ed25519_key_id, current.ed25519_key_id);
        assert_eq!(next.key_role_ids(&r.did), Some(ids));
        // Everything encrypted at rest derives as it did before.
        assert_eq!(*next.derivation_root().unwrap(), SIGNING);
        assert_eq!(stale_signing_key(&next, &r.after), None);
        // And the boot check refused the bundle it replaces.
        let stale = stale_signing_key(&current, &r.after).expect("the stored key is retired");
        assert!(stale.contains(REFRESH_COMMAND), "{stale}");
    }

    #[test]
    fn the_keys_already_held_are_current() {
        let r = rotated();
        let current = stored(&r.did, &r.before);
        let ids = NodeKeyIds::from_document(&r.did, &r.before).unwrap();
        let same = DidSecretsBundle {
            did: r.did.clone(),
            secrets: vec![
                entry(&ids.signing, KeyType::Ed25519, &SIGNING),
                entry(&ids.key_agreement.unwrap(), KeyType::X25519, &KA),
            ],
        };
        assert!(matches!(
            successor_bundle(&current, &same, &r.before).unwrap(),
            Refresh::Current
        ));
        assert_eq!(stale_signing_key(&current, &r.before), None);
    }

    /// A bundle sealed before the rotation names a key the document no longer
    /// lists: refused, with the command that seals a current one.
    #[test]
    fn a_bundle_older_than_the_document_is_refused() {
        let r = rotated();
        let current = stored(&r.did, &r.before);
        let ids = NodeKeyIds::from_document(&r.did, &r.before).unwrap();
        let old = DidSecretsBundle {
            did: r.did.clone(),
            secrets: vec![
                entry(&ids.signing, KeyType::Ed25519, &SIGNING),
                entry(&ids.key_agreement.unwrap(), KeyType::X25519, &KA),
            ],
        };
        let err = successor_bundle(&current, &old, &r.after).unwrap_err();
        assert!(err.to_string().contains("pnm keys bundle"), "{err}");
    }

    /// A key under the document's id that is not the key it publishes there.
    #[test]
    fn a_key_the_document_does_not_publish_is_refused() {
        let r = rotated();
        let current = stored(&r.did, &r.before);
        let mut forged = sealed_after(&r.did, &r.after);
        forged.secrets[0] = entry(
            &forged.secrets[0].key_id.clone(),
            KeyType::Ed25519,
            &[7; 32],
        );
        let err = successor_bundle(&current, &forged, &r.after).unwrap_err();
        assert!(err.to_string().contains("is not the key"), "{err}");
    }

    #[test]
    fn another_dids_keys_are_refused() {
        let r = rotated();
        let current = stored(&r.did, &r.before);
        let mut other = sealed_after(&r.did, &r.after);
        other.did = "did:webs:other.example:EAbc".into();
        let err = successor_bundle(&current, &other, &r.after).unwrap_err();
        assert!(err.to_string().contains("not this VTC's"), "{err}");
    }

    #[test]
    fn a_did_webvh_vtc_has_nothing_to_take_over() {
        let current = bundle_from_raw("did:webvh:QmX:vtc.example", &SIGNING, &KA);
        let secrets = DidSecretsBundle {
            did: current.integration_did.clone(),
            secrets: Vec::new(),
        };
        let err = successor_bundle(&current, &secrets, &serde_json::json!({})).unwrap_err();
        assert!(err.to_string().contains("not a did:webs"), "{err}");
        assert_eq!(stale_signing_key(&current, &serde_json::json!({})), None);
    }
}
