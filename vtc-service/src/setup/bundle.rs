//! `VtcKeyBundle` — the secret-store payload that holds the VTC's
//! VTA-provisioned DID + key material.
//!
//! The VTC's identity is **always** provisioned by a VTA via the
//! `vtc-host` template. The resulting [`TemplateBootstrapPayload`]
//! carries:
//!
//! - The integration's DID (becomes [`AppConfig::vtc_did`]).
//! - One [`DidKeyMaterial`] entry with two keys: Ed25519 signing
//!   (serves both `assertionMethod` and `authentication`) and X25519
//!   key-agreement (`keyAgreement`).
//!
//! We persist exactly that subset as a `VtcKeyBundle` inside the
//! secret store. The on-disk format is JSON (Q2 of the
//! VTA-driven-keys design doc): forward-compat over wire-size
//! savings, and trivially inspectable for debugging.
//!
//! ## Key derivations downstream
//!
//! `init_auth` extracts the raw Ed25519 + X25519 private bytes
//! and feeds them to:
//!
//! - The DIDComm `Secret::generate_ed25519` / `generate_x25519`
//!   constructors — they become the VTC DID's `#key-0` and
//!   `#key-1` resolver entries.
//! - HKDF derivations for the at-rest storage key, the install-token
//!   signer, the audit key and the community's other long-lived keys
//!   (hidden-vetting, voting, tag mask, storage-credential
//!   fingerprint). Their IKM is the **derivation root**
//!   ([`VtcKeyBundle::derivation_root`]): the Ed25519 private bytes for
//!   every bundle that stores none — every VTC to date — and a stored
//!   root once the signing key can rotate, so a rotation of the
//!   signing key leaves them all unchanged. `info` strings
//!   (`vtc-storage-key/v1`, `vtc-install-jwt-key/v2`, `vtc-audit-key/v2`)
//!   domain-separate them.
//!
//! ## Keys by role
//!
//! A key-role identity — a `did:webs` VTC (VTI-KEY-001, the S7 step of
//! `docs/05-design-notes/did-webs-in-the-vta.md`) — carries a distinct
//! authentication (`operational`) key in
//! [`VtcKeyBundle::authentication_key`], and names every key by the
//! id its document gives it ([`VtcKeyBundle::key_role_ids`]); the
//! Ed25519 key is then its `attestation` key. Without one, the
//! `#key-0` / `#key-1` convention holds as before. Bumping from `/v1` is intentional —
//!   any pre-rework keyring entry derived from a 64-byte BIP-39
//!   seed produces different HKDF output under `/v2`, so a stale
//!   deployment fails loud at the verification step rather than
//!   silently accepting tokens minted under the old derivation.

use multibase::Base;
use serde::{Deserialize, Serialize};
use vti_common::error::AppError;
use zeroize::Zeroizing;

/// The persisted shape of the VTC's VTA-provisioned identity.
///
/// All public material is multibase-encoded (matching the
/// `DidKeyMaterial` wire shape from `vta-sdk`); private halves are
/// multibase-encoded strings at rest. Use the accessor methods
/// instead of touching the raw fields if you need a `Zeroizing`
/// buffer for the live key.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct VtcKeyBundle {
    /// The VTC's `did:webvh`. Matches [`crate::config::AppConfig::vtc_did`]
    /// after a successful setup.
    pub integration_did: String,
    /// DID URL for the Ed25519 signing key (e.g. `did:webvh:…#key-0`).
    pub ed25519_key_id: String,
    /// Multibase-encoded Ed25519 public key.
    pub ed25519_public_multibase: String,
    /// Multibase-encoded Ed25519 private key. Kept as `String` so the
    /// derived `Serialize`/`Deserialize` stays simple; access via
    /// [`Self::ed25519_private_zeroizing`] when feeding a signer.
    pub ed25519_private_multibase: String,
    /// DID URL for the X25519 key-agreement key (e.g. `did:webvh:…#key-1`).
    pub x25519_key_id: String,
    /// Multibase-encoded X25519 public key.
    pub x25519_public_multibase: String,
    /// Multibase-encoded X25519 private key. Access via
    /// [`Self::x25519_private_zeroizing`].
    pub x25519_private_multibase: String,
    /// Signing keys beyond `#key-0`, when the VTA minted any.
    ///
    /// Every credential this VTC issues carries a proof from each of these as
    /// well as from the Ed25519 key — one proof per cryptosuite, so a classical
    /// verifier and a post-quantum one each check the suite they understand.
    ///
    /// **Empty is the normal case and always will be for a VTC provisioned
    /// before the `vtc-host` template declared a post-quantum slot.** An empty
    /// list means one signing key, which means one proof object rather than an
    /// array — byte-identical to what this service has always issued. That is
    /// the whole no-migration property, and it is why this is a list rather
    /// than a flag.
    ///
    /// `#[serde(default)]` is what lets an existing on-disk bundle — written
    /// before this field existed — still load. The reverse direction does not
    /// hold: `deny_unknown_fields` means a bundle written *with* extra keys
    /// cannot be read by an older binary, so rolling vtc-service back past
    /// this change requires re-provisioning. Stated rather than discovered.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub additional_signing_keys: Vec<AdditionalSigningKey>,
    /// The key that authenticates this VTC, when it is not the Ed25519 key
    /// above: the `operational` key of a key-role identity (a `did:webs` VTC,
    /// VTI-KEY-072), which signs its Trust Task requests and responses
    /// (`proofPurpose: authentication`) and its DIDComm messages, while the
    /// Ed25519 key above is its `attestation` key and signs credentials.
    ///
    /// **Absent for every `did:webvh` VTC**, whose one Ed25519 `#key-0` serves
    /// both relationships. Its presence is what makes the bundle a key-role
    /// identity: the VTC then names its keys by the ids stored here rather than
    /// by the `#key-0` / `#key-1` convention.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authentication_key: Option<AdditionalSigningKey>,
    /// The secret the VTC's long-lived local keys derive from — the at-rest
    /// storage key, the install-token signer, the initial audit HMAC key and
    /// the community's other HKDF-derived keys — as base58btc multibase of the
    /// 32 raw bytes.
    ///
    /// **Absent means the Ed25519 private key above**, which is what every VTC
    /// to date derives from, so an existing bundle derives exactly what it
    /// always did. It is written down only when the signing key can stop being
    /// the key the VTC was set up with — a key-role rotation replaces the
    /// attestation key — because a root that followed the current signing key
    /// would make everything encrypted at rest unreadable on the first
    /// rotation. [`VtcKeyBundle::carry_derivation_root_to`] is how a successor
    /// bundle keeps it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub derivation_root_multibase: Option<String>,
}

/// One signing key beyond `#key-0`, as stored in the secret store.
///
/// Carries `key_type` because the private multibase alone is not a safe place
/// to rediscover it: the boot path feeds this to a signer, and a key fed to the
/// wrong cryptosuite fails at signing time with a message about an algorithm
/// nobody chose. The VTA knows the algorithm and says so; this is where it is
/// written down.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AdditionalSigningKey {
    /// The template key slot this was minted for (`pq-signing`).
    pub slot: String,
    /// The algorithm, as `keyType` spells it (`mldsa44`).
    pub key_type: vta_sdk::keys::KeyType,
    /// DID URL with fragment — the verification method the published DID
    /// document carries for this key.
    pub key_id: String,
    /// Multibase-encoded public key.
    pub public_key_multibase: String,
    /// Multibase-encoded private key.
    pub private_key_multibase: String,
}

// Manual Debug — `private_key_multibase` is live key material.
impl std::fmt::Debug for AdditionalSigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdditionalSigningKey")
            .field("slot", &self.slot)
            .field("key_type", &self.key_type)
            .field("key_id", &self.key_id)
            .field("public_key_multibase", &self.public_key_multibase)
            .field("private_key_multibase", &"<redacted>")
            .finish()
    }
}

// Manual Debug — the two `*_private_multibase` fields are live key
// material; a derived `Debug` would print them on any `{:?}`. Redact the
// private halves; DIDs + public keys are not secret.
impl std::fmt::Debug for VtcKeyBundle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VtcKeyBundle")
            .field("integration_did", &self.integration_did)
            .field("ed25519_key_id", &self.ed25519_key_id)
            .field("ed25519_public_multibase", &self.ed25519_public_multibase)
            .field("ed25519_private_multibase", &"<redacted>")
            .field("x25519_key_id", &self.x25519_key_id)
            .field("x25519_public_multibase", &self.x25519_public_multibase)
            .field("x25519_private_multibase", &"<redacted>")
            .field("additional_signing_keys", &self.additional_signing_keys)
            .field("authentication_key", &self.authentication_key)
            .field(
                "derivation_root_multibase",
                &self
                    .derivation_root_multibase
                    .as_ref()
                    .map(|_| "<redacted>"),
            )
            .finish()
    }
}

impl VtcKeyBundle {
    /// Take the Ed25519 private key out into a [`Zeroizing`] buffer.
    pub fn ed25519_private_zeroizing(&self) -> Zeroizing<String> {
        Zeroizing::new(self.ed25519_private_multibase.clone())
    }

    /// Take the X25519 private key out into a [`Zeroizing`] buffer.
    pub fn x25519_private_zeroizing(&self) -> Zeroizing<String> {
        Zeroizing::new(self.x25519_private_multibase.clone())
    }

    /// Decode the 32-byte Ed25519 private scalar.
    ///
    /// Multibase keys carry a 2-byte multicodec prefix (`0xed01`
    /// for Ed25519 private). The Rust SDK uses
    /// `affinidi_crypto::ed25519::decode_private_key_multibase` for
    /// this; we duplicate the strip-and-decode inline to avoid
    /// pulling the dep into vtc-service just for one call.
    pub fn ed25519_private_bytes(&self) -> Result<Zeroizing<[u8; 32]>, AppError> {
        decode_private_multibase(&self.ed25519_private_multibase, ED25519_PRIV_CODEC)
    }

    /// Decode the 32-byte X25519 private scalar.
    pub fn x25519_private_bytes(&self) -> Result<Zeroizing<[u8; 32]>, AppError> {
        decode_private_multibase(&self.x25519_private_multibase, X25519_PRIV_CODEC)
    }

    /// Serialize the bundle as the bytes that should land in the
    /// secret store. JSON for forward-compat.
    pub fn to_secret_store_bytes(&self) -> Result<Vec<u8>, AppError> {
        serde_json::to_vec(self).map_err(|e| AppError::Internal(format!("bundle serialize: {e}")))
    }

    /// Decode the bytes that came out of the secret store.
    pub fn from_secret_store_bytes(bytes: &[u8]) -> Result<Self, AppError> {
        serde_json::from_slice(bytes).map_err(|e| {
            AppError::Internal(format!(
                "secret store does not contain a VtcKeyBundle: {e}. Has this VTC been set up \
                 against a VTA? Run `vtc setup` to provision."
            ))
        })
    }
    /// Construct a bundle directly from a VTA-returned
    /// `DidKeyMaterial`. `integration_did` is supplied separately
    /// because `DidKeyMaterial` only carries it as part of the
    /// inner `KeyPair.key_id` (`did:webvh:…#key-0`) — promoting it
    /// to the top-level field keeps the bundle self-contained.
    pub fn from_did_key_material(
        integration_did: String,
        material: &vta_sdk::sealed_transfer::template_bootstrap::DidKeyMaterial,
    ) -> Self {
        Self {
            integration_did,
            ed25519_key_id: material.signing_key.key_id.clone(),
            ed25519_public_multibase: material.signing_key.public_key_multibase.clone(),
            ed25519_private_multibase: material.signing_key.private_key_multibase.clone(),
            x25519_key_id: material.ka_key.key_id.clone(),
            x25519_public_multibase: material.ka_key.public_key_multibase.clone(),
            x25519_private_multibase: material.ka_key.private_key_multibase.clone(),
            additional_signing_keys: Vec::new(),
            authentication_key: None,
            derivation_root_multibase: None,
        }
    }

    /// Construct from the VTA-returned [`DidKeyMaterialV2`], carrying every
    /// signing key the template asked for.
    ///
    /// The V1 constructor above stays because `DidKeyMaterial` is still the
    /// shape a v1 template's bundle uses; this is the path a `vtc-host`
    /// declaring a post-quantum slot takes. Both produce the same bundle type,
    /// differing only in whether `additional_signing_keys` has anything in it.
    ///
    /// **Key-agreement keys beyond the first, and anything that is not a
    /// signing key, are not carried** — the VTC has exactly one keyAgreement
    /// entry and `select_secret_kid` resolves an inbound JWE against it.
    /// Nothing here decides what a second one would mean, and the VTA refuses
    /// to mint one, so there is nothing to drop.
    pub fn from_did_key_material_v2(
        integration_did: String,
        material: &vta_sdk::sealed_transfer::template_bootstrap::DidKeyMaterialV2,
    ) -> Self {
        Self {
            integration_did,
            ed25519_key_id: material.signing_key.key_id.clone(),
            ed25519_public_multibase: material.signing_key.public_key_multibase.clone(),
            ed25519_private_multibase: material.signing_key.private_key_multibase.clone(),
            x25519_key_id: material.ka_key.key_id.clone(),
            x25519_public_multibase: material.ka_key.public_key_multibase.clone(),
            x25519_private_multibase: material.ka_key.private_key_multibase.clone(),
            additional_signing_keys: material
                .additional_signing_keys
                .iter()
                .map(|k| AdditionalSigningKey {
                    slot: k.slot.clone(),
                    key_type: k.key_type.clone(),
                    key_id: k.key_id.clone(),
                    public_key_multibase: k.public_key_multibase.clone(),
                    private_key_multibase: k.private_key_multibase.clone(),
                })
                .collect(),
            authentication_key: None,
            derivation_root_multibase: None,
        }
    }

    /// The 32-byte secret this VTC's long-lived local keys derive from (see
    /// [`Self::derivation_root_multibase`]): the stored root when there is one,
    /// otherwise the Ed25519 private key — byte-identical to the input every
    /// existing deployment has always derived from.
    pub fn derivation_root(&self) -> Result<Zeroizing<[u8; 32]>, AppError> {
        match &self.derivation_root_multibase {
            None => self.ed25519_private_bytes(),
            Some(mb) => {
                let (base, bytes) = multibase::decode(mb).map_err(|e| {
                    AppError::Internal(format!("derivation root multibase decode: {e}"))
                })?;
                let raw: [u8; 32] = bytes
                    .as_slice()
                    .try_into()
                    .ok()
                    .filter(|_| base == Base::Base58Btc)
                    .ok_or_else(|| {
                        AppError::Internal(
                            "the derivation root is not 32 bytes of base58btc multibase".into(),
                        )
                    })?;
                Ok(Zeroizing::new(raw))
            }
        }
    }

    /// Make `next` — a bundle that replaces this one, such as one carrying a
    /// rotated signing key — derive from the same root as this one, writing the
    /// root down when `next` does not already carry it.
    ///
    /// Every key encrypted at rest, the install-token signer and the audit key
    /// derive from the root, so a successor with another root is a VTC that can
    /// no longer read its own store. That is refused rather than written: the
    /// caller learns it before anything is replaced.
    pub fn carry_derivation_root_to(&self, next: &mut VtcKeyBundle) -> Result<(), AppError> {
        if next.integration_did != self.integration_did {
            return Err(AppError::Validation(format!(
                "the successor bundle is for {}, not this VTC's {}",
                next.integration_did, self.integration_did
            )));
        }
        let root = self.derivation_root()?;
        if next.derivation_root_multibase.is_some() {
            if *next.derivation_root()? != *root {
                return Err(AppError::Conflict(
                    "the successor bundle derives from another root: this VTC's at-rest \
                     storage key, install-token signer and audit key would all change, and \
                     everything it has encrypted would become unreadable — refusing to \
                     replace the bundle"
                        .into(),
                ));
            }
            return Ok(());
        }
        next.derivation_root_multibase = Some(multibase::encode(Base::Base58Btc, *root));
        Ok(())
    }

    /// Whether this is a key-role identity (see [`Self::authentication_key`]).
    pub fn has_key_roles(&self) -> bool {
        self.authentication_key.is_some()
    }

    /// The verification-method ids this bundle gives the VTC's keys by role,
    /// under `vtc_did` — for a key-role identity only; `None` for one that
    /// follows the `#key-0` / `#key-1` convention.
    ///
    /// The ids are the ones the VTA minted the keys under and published in the
    /// VTC's document, so they are the document's own ids, read from local
    /// state rather than resolved: the same shape
    /// [`vta_sdk::node_keys::NodeKeyIds::from_document`] reads from a key-role
    /// document (the attestation key signs and seals, the operational key
    /// authenticates, the messaging key agrees).
    ///
    /// A **level-1 `did:webs`** (VTI-KEY-146) has no key roles but names its
    /// keys by themselves (`<did>#<CESR key>` for the one signing key, in both
    /// `authentication` and `assertionMethod`, and the designated key
    /// agreement key under its own id), so a bundle whose ids are not the
    /// conventional `#key-0` / `#key-1` answers with them too, as
    /// [`vta_sdk::node_keys::NodeKeyIds::from_document`] reads such a
    /// document: signing and authentication the one key, no sealed-transfer
    /// key.
    pub fn key_role_ids(&self, vtc_did: &str) -> Option<vta_sdk::node_keys::NodeKeyIds> {
        let Some(authentication) = self.authentication_key.as_ref() else {
            return self.level_one_ids(vtc_did);
        };
        let signing = method_under(vtc_did, &self.ed25519_key_id);
        // `NodeKeyIds` is non-exhaustive: start from a value and set every field.
        let mut ids = vta_sdk::node_keys::NodeKeyIds::conventional(vtc_did);
        ids.authentication = method_under(vtc_did, &authentication.key_id);
        ids.key_agreement = Some(method_under(vtc_did, &self.x25519_key_id));
        ids.sealed_transfer = Some(signing.clone());
        ids.signing = signing;
        Some(ids)
    }
}

impl VtcKeyBundle {
    /// The ids of a bundle without key roles whose keys are not at `#key-0` /
    /// `#key-1` (a level-1 `did:webs`); `None` for the conventional ids.
    fn level_one_ids(&self, vtc_did: &str) -> Option<vta_sdk::node_keys::NodeKeyIds> {
        let conventional = vta_sdk::node_keys::NodeKeyIds::conventional(vtc_did);
        let signing = method_under(vtc_did, &self.ed25519_key_id);
        let key_agreement = method_under(vtc_did, &self.x25519_key_id);
        if signing == conventional.signing
            && Some(key_agreement.as_str()) == conventional.key_agreement.as_deref()
        {
            return None;
        }
        let mut ids = conventional;
        ids.authentication = signing.clone();
        ids.signing = signing;
        ids.key_agreement = Some(key_agreement);
        ids.sealed_transfer = None;
        Some(ids)
    }
}

/// `key_id`'s fragment under `did` (`key_id` itself when it has none).
fn method_under(did: &str, key_id: &str) -> String {
    match vta_sdk::node_keys::fragment(key_id) {
        Some(fragment) => format!("{did}#{fragment}"),
        None => key_id.to_string(),
    }
}

const ED25519_PRIV_CODEC: [u8; 2] = [0x80, 0x26];
const X25519_PRIV_CODEC: [u8; 2] = [0x82, 0x26];

fn decode_private_multibase(
    mb: &str,
    expected_codec: [u8; 2],
) -> Result<Zeroizing<[u8; 32]>, AppError> {
    let (base, decoded) =
        multibase::decode(mb).map_err(|e| AppError::Internal(format!("multibase decode: {e}")))?;
    if base != Base::Base58Btc {
        return Err(AppError::Internal(format!(
            "expected base58btc multibase, got {base:?}"
        )));
    }
    if decoded.len() != 2 + 32 {
        return Err(AppError::Internal(format!(
            "expected 34-byte multicodec-prefixed key, got {}",
            decoded.len()
        )));
    }
    if decoded[..2] != expected_codec {
        return Err(AppError::Internal(format!(
            "wrong multicodec prefix: expected {:02x}{:02x}, got {:02x}{:02x}",
            expected_codec[0], expected_codec[1], decoded[0], decoded[1]
        )));
    }
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&decoded[2..]);
    Ok(out)
}

/// Encode a 32-byte private scalar back into the multibase form
/// the bundle stores. Only used by tests + the wizard's
/// `from_bundle_bytes` fixture path; production bundles are built
/// from a `DidKeyMaterial` whose multibase fields are already
/// VTA-issued.
#[doc(hidden)]
pub fn encode_private_multibase(bytes: &[u8; 32], codec: [u8; 2]) -> String {
    let mut buf = Vec::with_capacity(2 + 32);
    buf.extend_from_slice(&codec);
    buf.extend_from_slice(bytes);
    multibase::encode(Base::Base58Btc, &buf)
}

#[doc(hidden)]
pub fn ed25519_priv_codec() -> [u8; 2] {
    ED25519_PRIV_CODEC
}

#[doc(hidden)]
pub fn x25519_priv_codec() -> [u8; 2] {
    X25519_PRIV_CODEC
}

/// Test-only fixture builder: produce a bundle from two raw 32-byte
/// scalars. Production code never calls this — bundles come from
/// the VTA via [`VtcKeyBundle::from_did_key_material`].
///
/// Exposed outside `#[cfg(test)]` so integration tests under
/// `vtc-service/tests/` can stage a bundle without needing a live
/// VTA. The function is otherwise harmless — given any two 32-byte
/// scalars it produces a syntactically-valid bundle.
#[doc(hidden)]
pub fn bundle_from_raw(
    integration_did: &str,
    ed25519_priv: &[u8; 32],
    x25519_priv: &[u8; 32],
) -> VtcKeyBundle {
    use ed25519_dalek::SigningKey;

    let signing = SigningKey::from_bytes(ed25519_priv);
    let ed25519_public = signing.verifying_key().to_bytes();
    let x25519_public_priv = x25519_dalek::StaticSecret::from(*x25519_priv);
    let x25519_public = x25519_dalek::PublicKey::from(&x25519_public_priv).to_bytes();

    VtcKeyBundle {
        integration_did: integration_did.to_string(),
        ed25519_key_id: format!("{integration_did}#key-0"),
        ed25519_public_multibase: encode_public_multibase(&ed25519_public, [0xed, 0x01]),
        ed25519_private_multibase: encode_private_multibase(ed25519_priv, ED25519_PRIV_CODEC),
        x25519_key_id: format!("{integration_did}#key-1"),
        x25519_public_multibase: encode_public_multibase(&x25519_public, [0xec, 0x01]),
        x25519_private_multibase: encode_private_multibase(x25519_priv, X25519_PRIV_CODEC),
        // The raw-bytes fixture path carries the historical pair only — it
        // exists for tests and the legacy bootstrap, neither of which mints a
        // post-quantum key.
        additional_signing_keys: Vec::new(),
        authentication_key: None,
        derivation_root_multibase: None,
    }
}

fn encode_public_multibase(bytes: &[u8; 32], codec: [u8; 2]) -> String {
    let mut buf = Vec::with_capacity(2 + 32);
    buf.extend_from_slice(&codec);
    buf.extend_from_slice(bytes);
    multibase::encode(Base::Base58Btc, &buf)
}

/// Decode whatever the secret store handed back into the VTC's
/// `(ed25519, x25519)` private-scalar pair.
///
/// Accepts both on-disk shapes, so every consumer (auth bootstrap in
/// `server.rs`, the `vtc status` trust-ping) reads keys the same way:
///
/// - **JSON `VtcKeyBundle`** — what `vtc setup` has written since the
///   VTA-driven-keys rework, i.e. every real deployment. The bundle's
///   `integration_did` is checked against `vtc_did` so a mismatched bundle
///   can't silently sign for the wrong DID.
/// - **Legacy 64 raw bytes** (`ed‖x`) — used by the integration-test
///   fixtures; split directly.
///
/// Returning the pair in [`Zeroizing`] buffers keeps the live scalars off
/// the heap-without-wipe path. The error is a display `String` because both
/// call sites only surface it (a warning log / a `Box<dyn Error>` bubble),
/// never match on it.
/// Every signing key the bundle holds, as [`Secret`]s ready for a signer.
///
/// The first is always the Ed25519 `#key-0`, which keeps
/// [`crate::credentials::LocalSigner`]'s primary — the assertion method every
/// existing consumer expects, and (without a stored derivation root) the key
/// whose seed the install-token, audit and storage derivations use.
///
/// Returns an error rather than skipping a key it cannot decode. A
/// post-quantum key the VTA minted, published in the DID document and sealed
/// into the bundle, that this binary then quietly dropped, would leave the VTC
/// issuing classical-only credentials against a document advertising two
/// assertion methods — and nothing would say so. That is the "key added for
/// post-quantum protection that quietly did nothing" outcome
/// `with_additional_key` already refuses at the other end.
pub fn additional_signing_secrets(
    bundle: &VtcKeyBundle,
) -> Result<Vec<affinidi_secrets_resolver::secrets::Secret>, AppError> {
    use affinidi_secrets_resolver::secrets::Secret;

    bundle
        .additional_signing_keys
        .iter()
        .map(|key| {
            // `from_multibase` dispatches on the multicodec, so an ML-DSA seed
            // becomes an ML-DSA secret without this code knowing the parameter
            // sets. The declared `key_type` is checked against what came back
            // rather than used to drive the decode: the prefix and the field
            // come from the same producer, so a disagreement is a bug worth
            // failing on, not a choice to arbitrate.
            let secret = Secret::from_multibase(&key.private_key_multibase, Some(&key.key_id))
                .map_err(|e| {
                    AppError::Config(format!(
                        "signing key '{}' ({}) could not be decoded: {e}. The VTA minted it and \
                         the DID document publishes it, so refusing to boot rather than issue \
                         credentials without it",
                        key.slot, key.key_id
                    ))
                })?;
            Ok(secret)
        })
        .collect()
}

pub fn decode_secret_store_value(
    vtc_did: &str,
    stored: &[u8],
) -> Result<(Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>), String> {
    if stored.len() == 64 {
        // Legacy raw-bytes shape — used by every integration-test
        // fixture today. Promote into a bundle-shaped pair via a
        // direct copy.
        let mut ed = Zeroizing::new([0u8; 32]);
        let mut x = Zeroizing::new([0u8; 32]);
        ed.copy_from_slice(&stored[..32]);
        x.copy_from_slice(&stored[32..]);
        return Ok((ed, x));
    }
    let bundle = VtcKeyBundle::from_secret_store_bytes(stored)
        .map_err(|e| format!("secret store payload not a VtcKeyBundle: {e}"))?;
    if bundle.integration_did != vtc_did {
        return Err(format!(
            "VtcKeyBundle DID '{}' does not match config.vtc_did '{}' — refusing to init auth",
            bundle.integration_did, vtc_did
        ));
    }
    let ed = bundle
        .ed25519_private_bytes()
        .map_err(|e| format!("bundle Ed25519 decode: {e}"))?;
    let x = bundle
        .x25519_private_bytes()
        .map_err(|e| format!("bundle X25519 decode: {e}"))?;
    Ok((ed, x))
}

/// The VTC's own key material by role, decoded from whatever the secret store
/// holds (both shapes [`decode_secret_store_value`] accepts).
pub struct OwnKeyMaterial {
    /// The Ed25519 private key: the attestation key, which signs credentials
    /// (and, without key roles, authenticates too).
    pub ed25519: Zeroizing<[u8; 32]>,
    /// The X25519 key-agreement private key.
    pub x25519: Zeroizing<[u8; 32]>,
    /// What the long-lived local keys derive from
    /// ([`VtcKeyBundle::derivation_root`]).
    pub derivation_root: Zeroizing<[u8; 32]>,
    /// The distinct authentication (`operational`) key of a key-role identity,
    /// as a secret named by its verification method; `None` without key roles.
    pub authentication: Option<affinidi_secrets_resolver::secrets::Secret>,
    /// The ids a key-role identity's bundle gives its keys
    /// ([`VtcKeyBundle::key_role_ids`]); `None` without key roles.
    pub key_role_ids: Option<vta_sdk::node_keys::NodeKeyIds>,
}

/// Decode the VTC's own key material by role (see [`OwnKeyMaterial`]).
///
/// Errors as [`decode_secret_store_value`] does, and when a key-role bundle's
/// authentication key does not decode or does not match the public key stored
/// beside it: the document publishes that key as the VTC's authentication
/// method, so booting without it would leave every Trust Task and DIDComm
/// message the VTC sends failing verification.
pub fn own_key_material(vtc_did: &str, stored: &[u8]) -> Result<OwnKeyMaterial, String> {
    let (ed25519, x25519) = decode_secret_store_value(vtc_did, stored)?;
    if stored.len() == 64 {
        return Ok(OwnKeyMaterial {
            derivation_root: ed25519.clone(),
            ed25519,
            x25519,
            authentication: None,
            key_role_ids: None,
        });
    }
    let bundle = VtcKeyBundle::from_secret_store_bytes(stored)
        .map_err(|e| format!("secret store payload not a VtcKeyBundle: {e}"))?;
    let derivation_root = bundle
        .derivation_root()
        .map_err(|e| format!("bundle derivation root: {e}"))?;
    let key_role_ids = bundle.key_role_ids(vtc_did);
    let authentication = match (&bundle.authentication_key, &key_role_ids) {
        (Some(key), Some(ids)) => {
            let secret = affinidi_secrets_resolver::secrets::Secret::from_multibase(
                &key.private_key_multibase,
                Some(&ids.authentication),
            )
            .map_err(|e| {
                format!(
                    "the authentication key '{}' does not decode: {e}",
                    key.key_id
                )
            })?;
            if secret.get_public_keymultibase().ok().as_deref()
                != Some(key.public_key_multibase.as_str())
            {
                return Err(format!(
                    "the authentication key '{}' does not match the public key stored with it",
                    key.key_id
                ));
            }
            Some(secret)
        }
        _ => None,
    };
    Ok(OwnKeyMaterial {
        ed25519,
        x25519,
        derivation_root,
        authentication,
        key_role_ids,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> VtcKeyBundle {
        bundle_from_raw("did:webvh:vtc.example.com:abc", &[0x11; 32], &[0x22; 32])
    }

    #[test]
    fn round_trip_secret_store_bytes() {
        let b = fixture();
        let bytes = b.to_secret_store_bytes().unwrap();
        let parsed = VtcKeyBundle::from_secret_store_bytes(&bytes).unwrap();
        assert_eq!(b, parsed);
    }

    #[test]
    fn debug_redacts_private_keys() {
        let b = fixture();
        let dbg = format!("{b:?}");
        assert!(dbg.contains("<redacted>"), "got {dbg}");
        // The actual private multibase strings must not appear.
        assert!(
            !dbg.contains(&b.ed25519_private_multibase),
            "ed25519 private leaked: {dbg}"
        );
        assert!(
            !dbg.contains(&b.x25519_private_multibase),
            "x25519 private leaked: {dbg}"
        );
        // Public material stays visible for diagnostics.
        assert!(dbg.contains(&b.integration_did));
    }

    #[test]
    fn ed25519_private_bytes_decodes() {
        let b = fixture();
        let raw = b.ed25519_private_bytes().unwrap();
        assert_eq!(&*raw, &[0x11; 32]);
    }

    #[test]
    fn x25519_private_bytes_decodes() {
        let b = fixture();
        let raw = b.x25519_private_bytes().unwrap();
        assert_eq!(&*raw, &[0x22; 32]);
    }

    #[test]
    fn from_secret_store_bytes_clear_error_on_garbage() {
        let err = VtcKeyBundle::from_secret_store_bytes(b"not a bundle").unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("Run `vtc setup`"),
            "expected operator hint in error, got: {msg}"
        );
    }

    #[test]
    fn from_secret_store_bytes_rejects_unknown_fields() {
        let bogus = br#"{"integration_did":"did:webvh:x","extra":"sneaky","ed25519_key_id":"x#0","ed25519_public_multibase":"z","ed25519_private_multibase":"z","x25519_key_id":"x#1","x25519_public_multibase":"z","x25519_private_multibase":"z"}"#;
        assert!(VtcKeyBundle::from_secret_store_bytes(bogus).is_err());
    }

    #[test]
    fn rejects_wrong_multicodec_prefix() {
        let mut b = fixture();
        // Swap the Ed25519 private's multicodec for the X25519 one.
        let raw = [0x11; 32];
        b.ed25519_private_multibase = encode_private_multibase(&raw, X25519_PRIV_CODEC);
        let err = b.ed25519_private_bytes().unwrap_err();
        assert!(format!("{err}").contains("wrong multicodec prefix"));
    }

    /// P0.19: the JSON `VtcKeyBundle` shape every real deployment writes
    /// decodes into the right scalar pair. This is the shape the `vtc
    /// status` trust-ping used to reject with a "not 64 bytes" error.
    #[test]
    fn decode_secret_store_value_accepts_json_bundle() {
        let b = fixture(); // did:webvh:vtc.example.com:abc, ed=0x11.., x=0x22..
        let bytes = b.to_secret_store_bytes().unwrap();
        let (ed, x) =
            decode_secret_store_value("did:webvh:vtc.example.com:abc", &bytes).expect("decodes");
        assert_eq!(&*ed, &[0x11; 32]);
        assert_eq!(&*x, &[0x22; 32]);
    }

    /// The legacy 64-raw-byte shape (test/CI fixtures) still splits
    /// cleanly — the DID is irrelevant for this path.
    #[test]
    fn decode_secret_store_value_accepts_legacy_64_bytes() {
        let mut raw = Vec::with_capacity(64);
        raw.extend_from_slice(&[0xAA; 32]);
        raw.extend_from_slice(&[0xBB; 32]);
        let (ed, x) = decode_secret_store_value("did:any", &raw).expect("64-byte split");
        assert_eq!(&*ed, &[0xAA; 32]);
        assert_eq!(&*x, &[0xBB; 32]);
    }

    /// A bundle whose DID doesn't match the configured `vtc_did` is
    /// refused — it must not silently sign for the wrong identity.
    #[test]
    fn decode_secret_store_value_rejects_did_mismatch() {
        let b = fixture();
        let bytes = b.to_secret_store_bytes().unwrap();
        let err = decode_secret_store_value("did:webvh:someone.else", &bytes).unwrap_err();
        assert!(
            err.contains("does not match"),
            "expected DID-mismatch error, got: {err}"
        );
    }
}

#[cfg(test)]
mod hybrid_tests {
    use super::*;
    use affinidi_secrets_resolver::secrets::Secret;

    const DID: &str = "did:webvh:vtc.example.com:abc";

    fn pq_key() -> AdditionalSigningKey {
        let secret = Secret::generate_ml_dsa_44(None, Some(&[0x33; 32]));
        AdditionalSigningKey {
            slot: "pq-signing".into(),
            key_type: vta_sdk::keys::KeyType::MlDsa44,
            key_id: format!("{DID}#key-2"),
            public_key_multibase: secret.get_public_keymultibase().expect("public"),
            private_key_multibase: secret.get_private_keymultibase().expect("private"),
        }
    }

    fn hybrid_bundle() -> VtcKeyBundle {
        let mut b = bundle_from_raw(DID, &[0x11; 32], &[0x22; 32]);
        b.additional_signing_keys = vec![pq_key()];
        b
    }

    /// **An existing on-disk bundle still loads.**
    ///
    /// Every VTC in the field was provisioned before this field existed, and
    /// its stored JSON has no `additional_signing_keys`. `serde(default)` is
    /// what makes that a non-event — without it the daemon refuses to boot on
    /// an identity that is perfectly valid, which is the worst possible way to
    /// ship a feature nobody asked that deployment to use.
    #[test]
    fn a_bundle_written_before_this_field_existed_still_loads() {
        let legacy = serde_json::json!({
            "integration_did": DID,
            "ed25519_key_id": format!("{DID}#key-0"),
            "ed25519_public_multibase": "z6MkPub",
            "ed25519_private_multibase": "zPriv0",
            "x25519_key_id": format!("{DID}#key-1"),
            "x25519_public_multibase": "z6LSPub",
            "x25519_private_multibase": "zPriv1",
        });
        let bundle =
            VtcKeyBundle::from_secret_store_bytes(&serde_json::to_vec(&legacy).expect("serialize"))
                .expect("a pre-existing bundle must still load");
        assert!(bundle.additional_signing_keys.is_empty());
    }

    /// And the converse, stated because it is the cost of this change rather
    /// than something to discover in an incident: `deny_unknown_fields` means a
    /// bundle written *with* extra keys cannot be read by an older binary, so
    /// rolling vtc-service back past this change requires re-provisioning.
    #[test]
    fn a_bundle_with_extra_keys_is_not_readable_by_an_older_shape() {
        #[derive(Debug, serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        #[allow(dead_code)]
        struct OldShape {
            integration_did: String,
            ed25519_key_id: String,
            ed25519_public_multibase: String,
            ed25519_private_multibase: String,
            x25519_key_id: String,
            x25519_public_multibase: String,
            x25519_private_multibase: String,
        }

        let bytes = hybrid_bundle().to_secret_store_bytes().expect("serialize");
        let err = serde_json::from_slice::<OldShape>(&bytes)
            .expect_err("an older binary cannot read a bundle carrying extra keys");
        assert!(
            err.to_string().contains("additional_signing_keys"),
            "got: {err}"
        );
    }

    /// An empty list is absent from the stored JSON, so a VTC with one signing
    /// key writes exactly the bytes it always did.
    #[test]
    fn an_empty_list_does_not_appear_in_the_stored_bundle() {
        let bytes = bundle_from_raw(DID, &[0x11; 32], &[0x22; 32])
            .to_secret_store_bytes()
            .expect("serialize");
        let text = String::from_utf8(bytes).expect("utf8");
        assert!(
            !text.contains("additional_signing_keys"),
            "an unchanged VTC must write an unchanged bundle: {text}"
        );
    }

    #[test]
    fn a_hybrid_bundle_round_trips_with_its_key_type() {
        let bytes = hybrid_bundle().to_secret_store_bytes().expect("serialize");
        let back = VtcKeyBundle::from_secret_store_bytes(&bytes).expect("deserialize");
        assert_eq!(back.additional_signing_keys.len(), 1);
        assert_eq!(back.additional_signing_keys[0].slot, "pq-signing");
        assert_eq!(
            back.additional_signing_keys[0].key_type,
            vta_sdk::keys::KeyType::MlDsa44,
            "the algorithm must survive storage as a value, not be re-derived at boot"
        );
    }

    /// The constructor that carries the VTA's bundle into storage.
    ///
    /// Tested separately from the round-trip because a constructor that dropped
    /// the extra keys would leave every other test in this module passing: they
    /// build the bundle directly, so nothing else would notice the material
    /// never arriving from the wire shape.
    #[test]
    fn the_v2_constructor_carries_every_signing_key_into_the_bundle() {
        use vta_sdk::sealed_transfer::template_bootstrap::{DidKeyMaterialV2, SlotKeyPair};

        let pq = pq_key();
        let material = DidKeyMaterialV2 {
            did: DID.into(),
            signing_key: SlotKeyPair {
                slot: "signing".into(),
                key_type: vta_sdk::keys::KeyType::Ed25519,
                key_id: format!("{DID}#key-0"),
                public_key_multibase: "z6MkPub".into(),
                private_key_multibase: "zPriv0".into(),
            },
            ka_key: SlotKeyPair {
                slot: "ka".into(),
                key_type: vta_sdk::keys::KeyType::X25519,
                key_id: format!("{DID}#key-1"),
                public_key_multibase: "z6LSPub".into(),
                private_key_multibase: "zPriv1".into(),
            },
            additional_signing_keys: vec![SlotKeyPair {
                slot: pq.slot.clone(),
                key_type: pq.key_type.clone(),
                key_id: pq.key_id.clone(),
                public_key_multibase: pq.public_key_multibase.clone(),
                private_key_multibase: pq.private_key_multibase.clone(),
            }],
        };

        let bundle = VtcKeyBundle::from_did_key_material_v2(DID.into(), &material);
        assert_eq!(bundle.ed25519_key_id, format!("{DID}#key-0"));
        assert_eq!(
            bundle.additional_signing_keys.len(),
            1,
            "the post-quantum key the VTA sealed must reach the stored bundle"
        );
        assert_eq!(bundle.additional_signing_keys[0].slot, "pq-signing");
        assert_eq!(
            bundle.additional_signing_keys[0].private_key_multibase, pq.private_key_multibase,
            "the private half must be carried verbatim, not re-encoded"
        );
    }

    /// **The last link, exercised rather than asserted.**
    ///
    /// A stored bundle carrying a post-quantum key produces a signer that puts
    /// a post-quantum proof on a credential. Everything before this — the
    /// template slot, the mint, the sealed variant, the bundle field — exists
    /// only to reach this, and every one of those pieces could be in place
    /// while the credential still came out classical-only.
    #[tokio::test]
    async fn a_stored_post_quantum_key_reaches_the_issued_credential() {
        let bytes = hybrid_bundle().to_secret_store_bytes().expect("serialize");
        let bundle = VtcKeyBundle::from_secret_store_bytes(&bytes).expect("deserialize");

        let extra = additional_signing_secrets(&bundle).expect("the stored key decodes");
        assert_eq!(extra.len(), 1);

        let ed = bundle.ed25519_private_bytes().expect("ed25519 bytes");
        let signer = extra.into_iter().fold(
            crate::credentials::LocalSigner::from_ed25519_seed(DID.into(), &ed),
            |s, secret| s.with_additional_key(secret),
        );
        assert_eq!(signer.key_count(), 2);

        let mut doc = serde_json::json!({
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "id": "urn:uuid:hybrid-probe",
            "type": ["VerifiableCredential"],
            "issuer": DID,
            "credentialSubject": { "id": "did:key:z6MkHolder" },
        });
        signer
            .sign_doc(&mut doc)
            .await
            .expect("signs with both keys");

        let proofs = doc
            .get("proof")
            .and_then(|p| p.as_array())
            .expect("two keys must produce a proof array");
        let suites: Vec<&str> = proofs
            .iter()
            .filter_map(|p| p.get("cryptosuite").and_then(|s| s.as_str()))
            .collect();
        assert!(
            suites.contains(&"eddsa-jcs-2022"),
            "the classical proof must remain, or every existing verifier breaks: {suites:?}"
        );
        assert!(
            suites.contains(&"mldsa44-jcs-2024"),
            "the post-quantum proof is the entire point of the workstream: {suites:?}"
        );
    }

    /// A key that cannot be decoded fails the boot instead of being skipped.
    ///
    /// The DID document publishes it as an assertion method, so a VTC that
    /// dropped it would issue credentials a verifier expecting two proofs reads
    /// as incomplete — with nothing anywhere saying why.
    #[test]
    fn an_undecodable_extra_key_refuses_rather_than_being_dropped() {
        let mut bundle = hybrid_bundle();
        bundle.additional_signing_keys[0].private_key_multibase = "znot-a-real-key".into();

        let err = additional_signing_secrets(&bundle)
            .expect_err("an undecodable signing key must not be silently skipped");
        let msg = err.to_string();
        assert!(
            msg.contains("pq-signing") && msg.contains("refusing to boot"),
            "the refusal must name the slot and say what it is refusing: {msg}"
        );
    }
}

/// A VTC whose own DID is a key-role did:webs (S7), and the derivation root
/// that keeps its long-lived keys stable across a signing-key rotation.
#[cfg(test)]
mod key_role_tests {
    use super::*;
    use affinidi_data_integrity::{DataIntegrityProof, VerifyOptions};
    use affinidi_secrets_resolver::secrets::Secret;
    use vta_sdk::node_keys::NodeKeyIds;

    const ATTESTATION: [u8; 32] = [0x31; 32];
    const OPERATIONAL: [u8; 32] = [0x32; 32];
    const MESSAGING: [u8; 32] = [0x33; 32];

    fn ed25519_public(seed: &[u8; 32]) -> [u8; 32] {
        ed25519_dalek::SigningKey::from_bytes(seed)
            .verifying_key()
            .to_bytes()
    }

    /// A key-role did:webs as the VTA mints one: distinct attestation,
    /// operational and messaging keys, the KEL's own key in no relationship.
    fn key_role_vtc() -> (String, serde_json::Value) {
        use affinidi_did_webs::key_roles::{KeyRoles, VerificationKey};
        use affinidi_did_webs::{CreateConfig, DidWebs, KeyAgreementKey, create_controlled};
        use affinidi_keri::controller::{Inception, KeySigner, NextKey};
        use affinidi_keri_core::threshold::Threshold;
        use affinidi_keri_crypto::Signer;

        let controller = Signer::new("A", vec![1u8; 32]).unwrap();
        let next = Signer::new("A", vec![2u8; 32]).unwrap();
        let x25519 =
            x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(MESSAGING)).to_bytes();
        let roles = KeyRoles::new()
            .with_attestation(VerificationKey::Ed25519(ed25519_public(&ATTESTATION)))
            .with_operational(VerificationKey::Ed25519(ed25519_public(&OPERATIONAL)))
            .with_messaging(KeyAgreementKey::X25519(x25519));
        let config = CreateConfig::builder("vtc.example")
            .controlled(Inception::new(
                vec![controller.public_key().unwrap()],
                Threshold::Simple(1),
                vec![NextKey::PublicKey(next.public_key().unwrap())],
                Threshold::Simple(1),
            ))
            .key_roles(roles)
            .build();
        let created = create_controlled(config, &[&controller as &dyn KeySigner]).unwrap();
        let did = created.did().to_string();
        let parsed = DidWebs::parse(&did).unwrap();
        let document = serde_json::to_value(
            affinidi_did_webs::resolve_from_artifacts(
                &parsed,
                &created.artifacts().keri_cesr,
                None,
            )
            .unwrap(),
        )
        .unwrap();
        (did, document)
    }

    /// The bundle the VTA would seal to such a VTC: each key under the id its
    /// document gives it.
    fn key_role_bundle(did: &str, document: &serde_json::Value) -> VtcKeyBundle {
        let ids = NodeKeyIds::from_document(did, document).expect("key-role ids");
        let mut bundle = bundle_from_raw(did, &ATTESTATION, &MESSAGING);
        bundle.ed25519_key_id = ids.signing.clone();
        bundle.x25519_key_id = ids.key_agreement.clone().expect("messaging key");
        let operational = Secret::generate_ed25519(None, Some(&OPERATIONAL));
        bundle.authentication_key = Some(AdditionalSigningKey {
            slot: "operational".into(),
            key_type: vta_sdk::keys::KeyType::Ed25519,
            key_id: ids.authentication.clone(),
            public_key_multibase: operational.get_public_keymultibase().unwrap(),
            private_key_multibase: operational.get_private_keymultibase().unwrap(),
        });
        bundle
    }

    fn signer_for(did: &str, bundle: &VtcKeyBundle) -> crate::credentials::LocalSigner {
        let stored = bundle.to_secret_store_bytes().unwrap();
        let own = own_key_material(did, &stored).expect("decodes");
        crate::credentials::LocalSigner::for_own_keys(did.into(), &own)
    }

    fn verify(doc: &serde_json::Value, public: &[u8; 32]) {
        let proof: DataIntegrityProof = serde_json::from_value(doc["proof"].clone()).unwrap();
        let mut unsigned = doc.clone();
        unsigned.as_object_mut().unwrap().remove("proof");
        proof
            .verify_with_public_key(&unsigned, public, VerifyOptions::new())
            .expect("the proof verifies under the key its method names");
    }

    #[test]
    fn a_key_role_bundle_names_its_keys_as_its_document_does() {
        let (did, document) = key_role_vtc();
        let bundle = key_role_bundle(&did, &document);
        assert!(bundle.has_key_roles());
        let from_document = NodeKeyIds::from_document(&did, &document).unwrap();
        assert_eq!(bundle.key_role_ids(&did), Some(from_document.clone()));
        assert_ne!(from_document.signing, from_document.authentication);
        assert!(!from_document.signing.ends_with("#key-0"));
    }

    /// S7: credentials are signed with the attestation key, Trust Task
    /// requests with the operational key, each under its document id.
    #[tokio::test]
    async fn a_did_webs_vtc_signs_credentials_with_attestation_and_trust_tasks_with_operational() {
        let (did, document) = key_role_vtc();
        let ids = NodeKeyIds::from_document(&did, &document).unwrap();
        let signer = signer_for(&did, &key_role_bundle(&did, &document));
        assert_eq!(signer.assertion_method_id(), ids.signing);
        assert_eq!(signer.authentication_method_id(), ids.authentication);

        let mut vc = serde_json::json!({
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "id": "urn:uuid:webs-vtc-probe",
            "type": ["VerifiableCredential"],
            "issuer": did,
            "credentialSubject": { "id": "did:key:z6MkHolder" },
        });
        signer
            .sign_doc(&mut vc)
            .await
            .expect("signs the credential");
        assert_eq!(vc["proof"]["verificationMethod"], ids.signing.as_str());
        assert_eq!(vc["proof"]["proofPurpose"], "assertionMethod");
        verify(&vc, &ed25519_public(&ATTESTATION));

        let task = vti_common::capability_client::build_document(
            &did,
            "did:web:registry.example",
            "https://trusttasks.org/spec/registry/record/put/0.3",
            serde_json::json!({}),
        );
        let mut task = serde_json::to_value(&task).unwrap();
        signer
            .sign_operational_doc(&mut task)
            .await
            .expect("signs the request");
        assert_eq!(
            task["proof"]["verificationMethod"],
            ids.authentication.as_str()
        );
        assert_eq!(task["proof"]["proofPurpose"], "authentication");
        verify(&task, &ed25519_public(&OPERATIONAL));

        // An attested response is an assertion: the attestation key.
        let mut attested = serde_json::json!({
            "type": "urn:example:attested-response",
            "payload": {},
        });
        signer.sign_attested_response(&mut attested).await.unwrap();
        assert_eq!(
            attested["proof"]["verificationMethod"],
            ids.signing.as_str()
        );
    }

    /// Without key roles nothing moves: `#key-0` signs everything.
    #[tokio::test]
    async fn a_did_webvh_vtc_still_signs_everything_as_key_0() {
        const DID: &str = "did:webvh:abc:vtc.example.com";
        let signer = signer_for(DID, &bundle_from_raw(DID, &[0x11; 32], &[0x22; 32]));
        assert_eq!(signer.assertion_method_id(), format!("{DID}#key-0"));
        assert_eq!(signer.authentication_method_id(), format!("{DID}#key-0"));
        assert!(signer.key_role_ids().is_none());
    }

    /// The derived keys of an existing did:webvh VTC are exactly what they were
    /// — golden values for the seed `0x11…`, computed with HKDF-SHA256 before
    /// the derivation root existed (IKM = the Ed25519 seed, no salt).
    #[test]
    fn an_existing_vtcs_derived_keys_are_unchanged() {
        const DID: &str = "did:webvh:abc:vtc.example.com";
        let stored = bundle_from_raw(DID, &[0x11; 32], &[0x22; 32])
            .to_secret_store_bytes()
            .unwrap();
        let own = own_key_material(DID, &stored).unwrap();
        assert_eq!(*own.derivation_root, [0x11; 32]);
        let storage = crate::server::derive_storage_key(&*own.derivation_root).unwrap();
        assert_eq!(
            hex::encode(storage),
            "61b49277009d388472d2e748c42f723d0936653268f427ba486db56327fec7f7"
        );
        let hkdf = |info: &[u8]| {
            let mut out = [0u8; 32];
            hkdf::Hkdf::<sha2::Sha256>::new(None, &*own.derivation_root)
                .expand(info, &mut out)
                .unwrap();
            hex::encode(out)
        };
        assert_eq!(
            hkdf(vti_common::audit::key_store::VTC_AUDIT_KEY_INFO),
            "224c148c2fd6dbf2980e3a68ec275bfbad16d612647ce4f5863725fc9c78c3b7"
        );
        assert_eq!(
            hkdf(b"vtc-install-jwt-key/v2"),
            "4397515aed931ed8af00b9157c8d662bd0bd03de67bce45938c04cdc1d626300"
        );
        // The signer's root (hidden-vetting, voting, mask, fingerprint keys)
        // is the same bytes.
        let signer = crate::credentials::LocalSigner::for_own_keys(DID.into(), &own);
        assert_eq!(signer.derivation_root().unwrap().as_bytes(), &[0x11; 32]);
        // And a legacy 64-byte fixture derives from its Ed25519 half.
        let mut raw = vec![0x11; 32];
        raw.extend_from_slice(&[0x22; 32]);
        assert_eq!(
            *own_key_material(DID, &raw).unwrap().derivation_root,
            [0x11; 32]
        );
        // An unchanged bundle writes no new field.
        let text = String::from_utf8(stored).unwrap();
        assert!(!text.contains("derivation_root"), "{text}");
        assert!(!text.contains("authentication_key"), "{text}");
    }

    /// A successor bundle with a rotated signing key keeps the root, so the
    /// storage key, install-token key and audit key survive the rotation.
    #[test]
    fn the_derived_keys_survive_a_signing_key_rotation() {
        const DID: &str = "did:webvh:abc:vtc.example.com";
        let current = bundle_from_raw(DID, &[0x11; 32], &[0x22; 32]);
        let mut rotated = bundle_from_raw(DID, &[0x44; 32], &[0x22; 32]);
        current.carry_derivation_root_to(&mut rotated).unwrap();

        let before = own_key_material(DID, &current.to_secret_store_bytes().unwrap()).unwrap();
        let after = own_key_material(DID, &rotated.to_secret_store_bytes().unwrap()).unwrap();
        assert_ne!(*before.ed25519, *after.ed25519, "the signing key rotated");
        assert_eq!(*before.derivation_root, *after.derivation_root);
        assert_eq!(
            crate::server::derive_storage_key(&*before.derivation_root),
            crate::server::derive_storage_key(&*after.derivation_root),
        );

        // An install token minted before the rotation verifies after it.
        use crate::install::token::{
            InstallTokenSigner, mint_passkey_install_token, parse_install_token,
        };
        let minted = mint_passkey_install_token(
            &InstallTokenSigner::from_master_seed(&*before.derivation_root).unwrap(),
            DID,
            3600,
        )
        .unwrap();
        parse_install_token(
            &InstallTokenSigner::from_master_seed(&*after.derivation_root).unwrap(),
            &minted.jwt,
        )
        .expect("an outstanding install token survives the rotation");

        // Carrying again is a no-op; a successor with another root is refused.
        let mut again = rotated.clone();
        rotated.carry_derivation_root_to(&mut again).unwrap();
        assert_eq!(again, rotated);
        let mut foreign = bundle_from_raw(DID, &[0x55; 32], &[0x22; 32]);
        foreign.derivation_root_multibase = Some(multibase::encode(Base::Base58Btc, [0x66; 32]));
        let err = current.carry_derivation_root_to(&mut foreign).unwrap_err();
        assert!(err.to_string().contains("another root"), "{err}");
        let mut other_did = bundle_from_raw("did:webvh:x:other.example", &[0x55; 32], &[0x22; 32]);
        assert!(current.carry_derivation_root_to(&mut other_did).is_err());
    }

    /// The root is redacted from `Debug`.
    #[test]
    fn the_root_is_redacted() {
        let mut b = bundle_from_raw("did:webvh:abc:vtc.example.com", &[0x11; 32], &[0x22; 32]);
        let root = multibase::encode(Base::Base58Btc, [0x66; 32]);
        b.derivation_root_multibase = Some(root.clone());
        assert!(!format!("{b:?}").contains(&root));
        assert_eq!(*b.derivation_root().unwrap(), [0x66; 32]);
    }

    /// A key-role bundle whose operational key does not match its stored
    /// public half refuses to load.
    #[test]
    fn a_mismatched_operational_key_refuses() {
        let (did, document) = key_role_vtc();
        let mut bundle = key_role_bundle(&did, &document);
        let other = Secret::generate_ed25519(None, Some(&[0x77; 32]));
        bundle
            .authentication_key
            .as_mut()
            .unwrap()
            .public_key_multibase = other.get_public_keymultibase().unwrap();
        let err = own_key_material(&did, &bundle.to_secret_store_bytes().unwrap())
            .err()
            .expect("refused");
        assert!(err.contains("does not match"), "{err}");
    }
}

/// A VTC whose own DID is a **level-1** did:webs (VTI-KEY-001, VTI-KEY-146), as
/// provision-integration mints one from `vtc-host-classical` with
/// `DID_METHOD=webs`: one key-state signing key named by itself, a designated
/// X25519 key agreement key, no key roles and no `#key-0`.
#[cfg(test)]
pub(crate) mod level_one_tests {
    use super::*;
    use affinidi_data_integrity::{DataIntegrityProof, VerifyOptions};
    use base64::Engine as _;
    use vta_sdk::node_keys::NodeKeyIds;

    pub(crate) const SIGNING: [u8; 32] = [0x41; 32];
    pub(crate) const KA: [u8; 32] = [0x42; 32];

    /// The level-1 did:webs and the document its stream derives.
    pub(crate) fn level_one_vtc() -> (String, serde_json::Value) {
        let (did, document, _) = level_one_vtc_with_stream();
        (did, document)
    }

    /// As [`level_one_vtc`], with the `keri.cesr` stream.
    pub(crate) fn level_one_vtc_with_stream() -> (String, serde_json::Value, String) {
        use affinidi_did_webs::{CreateConfig, DidWebs, KeyAgreementKey, create_controlled};
        use affinidi_keri::controller::{Inception, KeySigner, NextKey};
        use affinidi_keri_core::threshold::Threshold;
        use affinidi_keri_crypto::Signer;

        let controller = Signer::new("A", SIGNING.to_vec()).unwrap();
        let next = Signer::new("A", vec![0x43; 32]).unwrap();
        let x25519 =
            x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(KA)).to_bytes();
        let config = CreateConfig::builder("vtc.example")
            .controlled(Inception::new(
                vec![controller.public_key().unwrap()],
                Threshold::Simple(1),
                vec![NextKey::PublicKey(next.public_key().unwrap())],
                Threshold::Simple(1),
            ))
            .key_agreement(KeyAgreementKey::X25519(x25519))
            .build();
        let created = create_controlled(config, &[&controller as &dyn KeySigner]).unwrap();
        let did = created.did().to_string();
        let document = serde_json::to_value(
            affinidi_did_webs::resolve_from_artifacts(
                &DidWebs::parse(&did).unwrap(),
                &created.artifacts().keri_cesr,
                None,
            )
            .unwrap(),
        )
        .unwrap();
        let stream = String::from_utf8(created.artifacts().keri_cesr.to_vec()).unwrap();
        (did, document, stream)
    }

    /// The bundle the wizard stores from the VTA's: each key under the id the
    /// document gives it (`from_did_key_material_v2` copies the bundle's ids).
    fn level_one_bundle(did: &str, document: &serde_json::Value) -> VtcKeyBundle {
        let ids = NodeKeyIds::from_document(did, document).unwrap();
        let mut bundle = bundle_from_raw(did, &SIGNING, &KA);
        bundle.ed25519_key_id = ids.signing.clone();
        bundle.x25519_key_id = ids.key_agreement.clone().unwrap();
        bundle
    }

    /// The Ed25519 public key `document` publishes under `id`.
    fn published_key(document: &serde_json::Value, id: &str) -> [u8; 32] {
        let vm = document["verificationMethod"]
            .as_array()
            .unwrap()
            .iter()
            .find(|vm| {
                let vm_id = vm["id"].as_str().unwrap_or_default();
                vm_id == id || id.ends_with(vm_id)
            })
            .unwrap_or_else(|| panic!("{id} not in {document}"));
        let x = vm["publicKeyJwk"]["x"].as_str().expect("a JWK");
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(x)
            .unwrap()
            .try_into()
            .unwrap()
    }

    #[test]
    fn a_level_one_bundle_names_its_keys_as_its_document_does() {
        let (did, document) = level_one_vtc();
        let bundle = level_one_bundle(&did, &document);
        assert!(!bundle.has_key_roles());
        let from_document = NodeKeyIds::from_document(&did, &document).unwrap();
        assert_eq!(bundle.key_role_ids(&did), Some(from_document.clone()));
        assert_eq!(from_document.signing, from_document.authentication);
        assert!(
            !from_document.signing.ends_with("#key-0"),
            "{from_document:?}"
        );

        let own = own_key_material(&did, &bundle.to_secret_store_bytes().unwrap()).unwrap();
        assert!(
            own.authentication.is_none(),
            "one key authenticates and signs"
        );
        assert_eq!(own.key_role_ids, Some(from_document));
        assert_eq!(*own.derivation_root, SIGNING);
    }

    /// A credential a did:webs VTC issues, and a Trust Task it signs, each carry
    /// one eddsa proof naming the key-state key, and verify under the key the
    /// resolved document publishes there.
    #[tokio::test]
    async fn vti_key_001_a_did_webs_vtcs_credentials_and_trust_tasks_verify_against_its_document() {
        let (did, document) = level_one_vtc();
        let ids = NodeKeyIds::from_document(&did, &document).unwrap();
        let own = own_key_material(
            &did,
            &level_one_bundle(&did, &document)
                .to_secret_store_bytes()
                .unwrap(),
        )
        .unwrap();
        let signer = crate::credentials::LocalSigner::for_own_keys(did.clone(), &own);
        assert_eq!(signer.assertion_method_id(), ids.signing);
        assert_eq!(signer.authentication_method_id(), ids.signing);
        assert_eq!(signer.key_count(), 1, "no post-quantum key");

        let verify = |doc: &serde_json::Value| {
            assert!(doc["proof"].is_object(), "one proof, not a set: {doc}");
            let proof: DataIntegrityProof = serde_json::from_value(doc["proof"].clone()).unwrap();
            let public = published_key(&document, &proof.verification_method);
            let mut unsigned = doc.clone();
            unsigned.as_object_mut().unwrap().remove("proof");
            proof
                .verify_with_public_key(&unsigned, &public, VerifyOptions::new())
                .expect("verifies under the document's key");
        };

        let mut vc = serde_json::json!({
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "id": "urn:uuid:webs-l1-vtc-probe",
            "type": ["VerifiableCredential"],
            "issuer": did,
            "credentialSubject": { "id": "did:key:z6MkHolder" },
        });
        signer.sign_doc(&mut vc).await.unwrap();
        assert_eq!(vc["proof"]["verificationMethod"], ids.signing.as_str());
        assert_eq!(vc["proof"]["proofPurpose"], "assertionMethod");
        verify(&vc);

        let task = vti_common::capability_client::build_document(
            &did,
            "did:web:registry.example",
            "https://trusttasks.org/spec/registry/record/put/0.3",
            serde_json::json!({}),
        );
        let mut task = serde_json::to_value(&task).unwrap();
        signer.sign_operational_doc(&mut task).await.unwrap();
        assert_eq!(task["proof"]["verificationMethod"], ids.signing.as_str());
        assert_eq!(task["proof"]["proofPurpose"], "authentication");
        verify(&task);

        // A Trust Task reply, signed as the spine signs every response, and
        // verified the way a peer does: the proof's method resolved in the
        // VTC's did:webs document.
        let mut reply = serde_json::json!({
            "type": "https://trusttasks.org/spec/registry/record/put/0.3#response",
            "issuer": did,
            "recipient": "did:web:registry.example",
            "threadId": "urn:uuid:probe",
            "payload": {},
        });
        vti_trust_task_server::ResponseSigner::sign_response_document(&signer, &mut reply)
            .await
            .unwrap();
        assert_eq!(reply["proof"]["verificationMethod"], ids.signing.as_str());
        verify(&reply);
        let mut resolver = affinidi_did_resolver_cache_sdk::DIDCacheClient::new(
            affinidi_did_resolver_cache_sdk::config::DIDCacheConfigBuilder::default().build(),
        )
        .await
        .unwrap();
        resolver
            .add_did_document(&did, serde_json::from_value(document.clone()).unwrap())
            .await;
        let signed_by = vta_sdk::trust_task_proof::verify_trust_task_proof_value(
            &reply,
            &vta_sdk::trust_task_proof::TrustTaskVmResolver::new(resolver),
        )
        .await
        .expect("the reply verifies against the resolved did:webs document");
        assert_eq!(signed_by, did);

        // An attested response (sign-in step replies) is an assertion: the
        // same one key, under assertionMethod.
        let mut attested = serde_json::json!({ "type": "urn:example:attested", "payload": {} });
        signer.sign_attested_response(&mut attested).await.unwrap();
        assert_eq!(
            attested["proof"]["verificationMethod"],
            ids.signing.as_str()
        );
        assert_eq!(attested["proof"]["proofPurpose"], "assertionMethod");
        verify(&attested);
    }
}
