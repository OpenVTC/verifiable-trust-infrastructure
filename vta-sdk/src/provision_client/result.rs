//! Typed view of a successful `provision-integration` round-trip.
//!
//! Wraps the opened [`TemplateBootstrapPayload`] alongside the wire-level
//! metadata (bundle id, digest) and the VTA's own [`ProvisionSummary`] so
//! callers can audit / persist without digging back into the raw payload.
//!
//! `Clone` is derived so the value can ride [`super::event::VtaEvent`] from
//! a background runner task back to the consumer's main loop without extra
//! indirection. The underlying [`TemplateBootstrapPayload`] zeroizes on
//! drop — clones hold their own copies but carry the same contract.

use serde_json::Value;

use crate::provision_integration::http::{ProvisionIntegrationResponse, ProvisionSummary};
use crate::provision_integration::payload::{
    DidKeyMaterial, TemplateBootstrapPayload, TemplateOutput,
};
use crate::sealed_transfer::template_bootstrap::{DidKeyMaterialV2, TemplateBootstrapPayloadV2};
use crate::sealed_transfer::{SealedPayloadV1, armor, open_bundle};

use super::error::ProvisionError;

/// Result of a successful `provision-integration` round-trip.
#[derive(Debug, Clone)]
pub struct ProvisionResult {
    /// Hex-encoded `bundle_id` (16 bytes). Matches the nonce embedded in
    /// the original VP — useful for cross-checking audit logs.
    pub bundle_id_hex: String,
    /// SHA-256 digest of the armored ciphertext, as returned by the VTA.
    /// The local open already verified against this; downstream storage
    /// may record it for traceability.
    pub digest: String,
    /// Summary block the VTA includes on the response — `admin_did`,
    /// `integration_did`, `admin_rolled_over`, etc.
    pub summary: ProvisionSummary,
    /// Full payload. Private key material is zeroized on drop (via the
    /// payload's own impl).
    pub payload: TemplateBootstrapPayload,
}

impl ProvisionResult {
    /// Long-term admin DID the integration should authenticate as.
    /// Equals [`ProvisionSummary::client_did`] when no rollover happened,
    /// or the freshly-minted admin DID when
    /// [`ProvisionSummary::admin_rolled_over`] is `true`.
    pub fn admin_did(&self) -> &str {
        &self.summary.admin_did
    }

    /// The integration's own DID (rendered from the integration
    /// template). Always `Some(_)` when this `ProvisionResult` came
    /// from a `TemplateBootstrap` ask — `ProvisionResult` is only
    /// constructed by the `TemplateBootstrap` decode path, so callers
    /// can safely `.expect(...)` here in flows they know took the
    /// integration-mint route. The `Option` exists so the field can
    /// share a wire shape with the admin-only flows.
    pub fn integration_did(&self) -> Option<&str> {
        self.summary.integration_did.as_deref()
    }

    /// Private key material the integration needs to authenticate as its
    /// admin DID. Absent if the VTA didn't roll the admin over (legacy
    /// path) — in that case the integration reuses the setup DID's own
    /// private key.
    pub fn admin_key(&self) -> Option<&DidKeyMaterial> {
        self.payload.secrets.get(self.admin_did())
    }

    /// Private key material for the integration DID (the integration's
    /// own service identity). `None` when no integration DID was
    /// minted (e.g. the `AdminRotation` ask, though that flow does
    /// not produce a `ProvisionResult`).
    pub fn integration_key(&self) -> Option<&DidKeyMaterial> {
        self.payload.secrets.get(self.integration_did()?)
    }

    /// `did.jsonl` content for the integration DID when the integration
    /// template targets webvh. The integration writes this to its
    /// `/.well-known/did.jsonl` at startup. `None` when no integration
    /// DID exists.
    pub fn webvh_log(&self) -> Option<&str> {
        let integration_did = self.integration_did()?;
        self.payload
            .config
            .outputs
            .iter()
            .find_map(|out| match out {
                TemplateOutput::WebvhLog { did, log } if did == integration_did => {
                    Some(log.as_str())
                }
                _ => None,
            })
    }

    /// The authorization VC. Opaque JSON; archive for audit or feed to an
    /// `affinidi-vc` verifier if stronger checks are desired.
    pub fn authorization_vc(&self) -> &Value {
        &self.payload.authorization
    }

    /// REST URL for the VTA. `None` means the integration does not make
    /// outbound REST calls to this VTA (DIDComm-only deployment).
    /// Test-only accessor — production callers read the URL off the VTA
    /// session / persisted admin credential instead.
    #[cfg(test)]
    pub fn vta_url(&self) -> Option<&str> {
        self.payload.config.vta_url.as_deref()
    }
}

/// A provisioning result whose key material may include a signing key beyond
/// the primary one.
///
/// Separate from [`ProvisionResult`] rather than a change to it: that type's
/// `payload` field is public API a consumer in another repository already
/// reads, and widening its type would break them for a capability they have not
/// asked for. A consumer opts in by calling [`response_to_result_v2`].
///
/// **Both sealed variants arrive here as one shape.** A `TemplateBootstrap`
/// payload is lifted through [`DidKeyMaterialV2::from_v1`], so a caller that
/// has learned V2 never has to ask which variant it got — only whether any DID
/// carries extra keys, which is the question it actually has.
#[derive(Debug, Clone)]
pub struct ProvisionResultV2 {
    /// Hex-encoded `bundle_id` (16 bytes), matching the originating VP nonce.
    pub bundle_id_hex: String,
    /// SHA-256 digest of the armored ciphertext, as returned by the VTA.
    pub digest: String,
    /// Summary block the VTA includes on the response.
    pub summary: ProvisionSummary,
    /// Full payload, in the shape that can carry more than one signing key.
    pub payload: TemplateBootstrapPayloadV2,
}

impl ProvisionResultV2 {
    /// Long-term admin DID the integration should authenticate as.
    pub fn admin_did(&self) -> &str {
        &self.summary.admin_did
    }

    /// The integration's own DID, rendered from the integration template.
    pub fn integration_did(&self) -> Option<&str> {
        self.summary.integration_did.as_deref()
    }

    /// Key material for the integration DID — the primary signing key, the
    /// key-agreement key, and any additional signing keys the template asked
    /// for.
    pub fn integration_key(&self) -> Option<&DidKeyMaterialV2> {
        self.payload.secrets.get(self.integration_did()?)
    }

    /// Key material for the admin DID, when the VTA rolled it over.
    pub fn admin_key(&self) -> Option<&DidKeyMaterialV2> {
        self.payload.secrets.get(self.admin_did())
    }

    /// `did.jsonl` content for the integration DID when its template targets
    /// webvh.
    pub fn webvh_log(&self) -> Option<&str> {
        let integration_did = self.integration_did()?;
        self.payload
            .config
            .outputs
            .iter()
            .find_map(|out| match out {
                TemplateOutput::WebvhLog { did, log } if did == integration_did => {
                    Some(log.as_str())
                }
                _ => None,
            })
    }

    /// The authorization VC. Opaque JSON.
    pub fn authorization_vc(&self) -> &Value {
        &self.payload.authorization
    }
}

/// As [`response_to_result`], but accepting **either** template-bootstrap
/// variant and returning the shape that can hold more than one signing key.
///
/// A consumer whose template may declare extra key slots calls this; one whose
/// template cannot keeps calling [`response_to_result`] and is unaffected. A
/// `TemplateBootstrap` payload lifts losslessly, so this is also the right call
/// for a consumer that simply wants one code path across both.
pub fn response_to_result_v2(
    seed: &[u8; 32],
    vp_nonce: [u8; 16],
    response: ProvisionIntegrationResponse,
) -> Result<ProvisionResultV2, ProvisionError> {
    let (bundle_id_hex, digest, opened_payload) = open_provision_bundle(seed, vp_nonce, &response)?;

    let payload = match opened_payload {
        SealedPayloadV1::TemplateBootstrapV2(boxed) => *boxed,
        SealedPayloadV1::TemplateBootstrap(boxed) => {
            let v1 = *boxed;
            let mut secrets = std::collections::BTreeMap::new();
            for (did, material) in &v1.secrets {
                // A key whose multicodec names no algorithm this build knows is
                // refused rather than defaulted. Installing a key one cannot
                // classify is how a bundle's contents and a DID document come
                // apart, and a default here would be invisible.
                let lifted = DidKeyMaterialV2::from_v1(material).ok_or_else(|| {
                    ProvisionError::Armor(format!(
                        "key material for '{did}' carries a public key whose multicodec names \
                         no algorithm this build knows"
                    ))
                })?;
                secrets.insert(did.clone(), lifted);
            }
            TemplateBootstrapPayloadV2 {
                authorization: v1.authorization,
                secrets,
                config: v1.config,
            }
        }
        _ => return Err(ProvisionError::WrongPayload),
    };

    Ok(ProvisionResultV2 {
        bundle_id_hex,
        digest,
        summary: response.summary,
        payload,
    })
}

/// Decode the armor, check the bundle id against the VP nonce, and open.
///
/// Shared by both `response_to_result` entry points so the checks that make the
/// bundle trustworthy — the nonce binding and the digest pin — cannot come to
/// differ between them.
fn open_provision_bundle(
    seed: &[u8; 32],
    vp_nonce: [u8; 16],
    response: &ProvisionIntegrationResponse,
) -> Result<(String, String, SealedPayloadV1), ProvisionError> {
    let bundles =
        armor::decode(&response.bundle).map_err(|e| ProvisionError::Armor(e.to_string()))?;
    if bundles.len() != 1 {
        return Err(ProvisionError::Armor(format!(
            "expected exactly one armored bundle, found {}",
            bundles.len()
        )));
    }
    let bundle = &bundles[0];
    if bundle.bundle_id != vp_nonce {
        return Err(ProvisionError::Armor(
            "returned bundle_id does not match the VP nonce".into(),
        ));
    }

    let x_secret = crate::sealed_transfer::ed25519_seed_to_x25519_secret(seed);
    let expected = response
        .digest_multibase
        .as_deref()
        .map(crate::sealed_transfer::multibase_digest_to_hex)
        .transpose()
        .map_err(|e| ProvisionError::Armor(e.to_string()))?;
    let opened = open_bundle(&x_secret, bundle, expected.as_deref())?;

    Ok((
        hex_lower(&opened.bundle_id),
        expected.unwrap_or_default(),
        opened.payload,
    ))
}

/// Translate a [`ProvisionIntegrationResponse`] (from either DIDComm or
/// REST) into a [`ProvisionResult`]. Decodes the armored sealed bundle,
/// verifies the bundle id matches the originating VP nonce (so a swapped
/// bundle is rejected), opens the payload with the setup key's X25519
/// secret, and lifts the template-bootstrap payload into the result shape.
///
/// Shared by both transport runners — the wire payload is identical
/// across them.
pub fn response_to_result(
    seed: &[u8; 32],
    vp_nonce: [u8; 16],
    response: ProvisionIntegrationResponse,
) -> Result<ProvisionResult, ProvisionError> {
    let (bundle_id_hex, digest, opened_payload) = open_provision_bundle(seed, vp_nonce, &response)?;

    let payload = match opened_payload {
        SealedPayloadV1::TemplateBootstrap(boxed) => *boxed,
        // A `TemplateBootstrapV2` bundle reaches here only when the VTA minted
        // a key this caller has no field to put. `WrongPayload` is right: the
        // caller asked for the shape it can install and got another, and
        // silently dropping the extra key would defeat the point of having
        // asked for it. `response_to_result_v2` is the call that takes both.
        _ => return Err(ProvisionError::WrongPayload),
    };

    Ok(ProvisionResult {
        bundle_id_hex,
        digest,
        summary: response.summary,
        payload,
    })
}

/// Translate a [`ProvisionIntegrationResponse`] from the
/// `BootstrapAsk::AdminRotation` flow into an
/// [`super::intent::AdminCredentialReply`].
///
/// Shared by both transport runners. Decodes the armored bundle, opens
/// the payload, and asserts it is a [`SealedPayloadV1::AdminRotation`]
/// — anything else is a wiring bug. The opaque VC + VTA trust bundle
/// inside the payload are dropped; consumers only need the rotated
/// admin DID + its private key for the long-term credential.
pub fn admin_rotation_response_to_reply(
    seed: &[u8; 32],
    vp_nonce: [u8; 16],
    response: ProvisionIntegrationResponse,
) -> Result<super::intent::AdminCredentialReply, ProvisionError> {
    let bundles =
        armor::decode(&response.bundle).map_err(|e| ProvisionError::Armor(e.to_string()))?;
    if bundles.len() != 1 {
        return Err(ProvisionError::Armor(format!(
            "expected exactly one armored bundle, found {}",
            bundles.len()
        )));
    }
    let bundle = &bundles[0];
    if bundle.bundle_id != vp_nonce {
        return Err(ProvisionError::Armor(
            "returned bundle_id does not match the VP nonce".into(),
        ));
    }

    let x_secret = crate::sealed_transfer::ed25519_seed_to_x25519_secret(seed);
    // Decoded back to hex for the comparison: the pin travels as a multibase
    // multihash from 0.3 on, but `open_bundle` compares the hex it computes.
    // `None` is a real answer — the member is OPTIONAL, and a holder that does
    // not pin the bundle out of band sends no digest to check against.
    let expected = response
        .digest_multibase
        .as_deref()
        .map(crate::sealed_transfer::multibase_digest_to_hex)
        .transpose()
        .map_err(|e| ProvisionError::Armor(e.to_string()))?;
    let opened = open_bundle(&x_secret, bundle, expected.as_deref())?;

    let payload = match opened.payload {
        SealedPayloadV1::AdminRotation(boxed) => *boxed,
        _ => return Err(ProvisionError::WrongPayload),
    };

    Ok(super::intent::AdminCredentialReply {
        admin_did: payload.admin.did.clone(),
        admin_private_key_mb: payload.admin.signing_key.private_key_multibase.clone(),
    })
}

/// Decode a base64url-no-pad VP nonce string (as carried on
/// `BootstrapRequest::nonce`) back to the 16-byte sealed-bundle id.
///
/// Returns the raw bytes plus a one-line error string on failure.
#[allow(dead_code)] // wired up by the transport runners landing in subsequent tasks.
pub(crate) fn decode_nonce_b64url(s: &str) -> Result<[u8; 16], String> {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
    let raw = B64URL
        .decode(s)
        .map_err(|e| format!("VP nonce base64url: {e}"))?;
    raw.try_into()
        .map_err(|_| "VP nonce must be 16 bytes".to_string())
}

pub(crate) fn hex_lower(bytes: &[u8]) -> String {
    const T: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(T[(b >> 4) as usize] as char);
        s.push(T[(b & 0xf) as usize] as char);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provision_client::test_helpers::sample_provision_result;

    #[test]
    fn result_accessors_with_admin_rollover() {
        let r = sample_provision_result(true);
        assert_eq!(r.admin_did(), "did:key:z6MkAdmin");
        assert_eq!(
            r.integration_did(),
            Some("did:webvh:integration.example.com")
        );
        assert!(r.admin_key().is_some());
        assert!(r.integration_key().is_some());
        assert!(r.webvh_log().is_some());
        assert_eq!(r.vta_url(), Some("https://vta.example.com"));
    }

    #[test]
    fn result_accessors_without_admin_rollover_fall_back_to_client_did() {
        let r = sample_provision_result(false);
        assert_eq!(r.admin_did(), "did:key:z6MkSetup");
        assert!(r.admin_key().is_none());
        assert!(r.integration_key().is_some());
    }

    #[test]
    fn webvh_log_matches_integration_did_only() {
        let mut r = sample_provision_result(true);
        r.payload.config.outputs = vec![TemplateOutput::WebvhLog {
            did: "did:webvh:unrelated".into(),
            log: "noise".into(),
        }];
        assert!(r.webvh_log().is_none());
    }

    #[test]
    fn decode_nonce_b64url_round_trip() {
        use base64::Engine;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
        let bytes = [0xab; 16];
        let s = B64URL.encode(bytes);
        assert_eq!(decode_nonce_b64url(&s).unwrap(), bytes);
    }

    #[test]
    fn decode_nonce_b64url_rejects_wrong_length() {
        use base64::Engine;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
        let s = B64URL.encode([0u8; 8]);
        assert!(decode_nonce_b64url(&s).is_err());
    }

    #[test]
    fn hex_lower_matches_known_vector() {
        assert_eq!(hex_lower(&[0x00, 0xff, 0xab, 0x10]), "00ffab10");
    }
}
