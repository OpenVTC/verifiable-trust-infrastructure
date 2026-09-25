//! Sealed bundle types — the producer-side artifact returned to the consumer.

use serde::{Deserialize, Serialize};

use crate::context_provision::ContextProvisionBundle;
use crate::credentials::CredentialBundle;
use crate::did_secrets::DidSecretsBundle;

/// A labeled key entry, used by the `AdminKeySet` payload variant for
/// multi-admin / future expansion.
#[derive(Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[serde(deny_unknown_fields)]
pub struct LabeledKey {
    pub label: String,
    /// Key bytes, base64url-no-pad.
    pub key_b64: String,
    /// Optional key type tag for downstream interpretation (e.g. "ed25519").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_type: Option<String>,
}

/// Written by hand so the private key never reaches a log: a derived `Debug` would print it.
impl std::fmt::Debug for LabeledKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LabeledKey")
            .field("label", &self.label)
            .field("key_b64", &"<redacted>")
            .field("key_type", &self.key_type)
            .finish()
    }
}

/// Tagged, extensible payload sealed inside a [`SealedBundle`].
///
/// Every sensitive bundle type in the workspace is a variant here — after the
/// final phase of the rollout, sealed-transfer is the only way these move.
///
/// The two largest variants (`ContextProvision`, `DidSecrets`) are boxed so
/// the whole enum fits in one pointer on the stack regardless of which
/// variant is in play. `RawPrivateKey` (smallest) stays inline.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SealedPayloadV1 {
    AdminCredential(Box<CredentialBundle>),
    ContextProvision(Box<ContextProvisionBundle>),
    DidSecrets(Box<DidSecretsBundle>),
    AdminKeySet(Vec<LabeledKey>),
    /// A single raw private key bound to its algorithm tag. Used by the
    /// `POST /keys/import` flow: the client seals the key material to the
    /// server's ephemeral wrapping pubkey via sealed-transfer; the server
    /// opens it and imports.
    RawPrivateKey(RawPrivateKey),
    /// Generic template-driven integration bootstrap. Carries a VC-issued
    /// admin authorization + minted integration key material + first-boot
    /// config. Produced by `vta bootstrap provision-integration` and
    /// its `pnm` bridge equivalent.
    ///
    /// See `docs/02-vta/provision-integration.md` for the full design.
    TemplateBootstrap(Box<super::template_bootstrap::TemplateBootstrapPayload>),
    /// As [`Self::TemplateBootstrap`], for a DID that holds more than one
    /// signing key.
    ///
    /// A separate variant rather than a field on the existing payload because
    /// both `TemplateBootstrapPayload` and `DidKeyMaterial` carry
    /// `#[serde(deny_unknown_fields)]`: a new key field makes every existing
    /// opener reject the payload with `unknown field ...`, which reads as a
    /// corrupted bundle. An unknown *variant* names itself, which is the
    /// failure a consumer can act on — and is why CLAUDE.md's sealed-transfer
    /// rule says never to reshape an existing variant.
    ///
    /// **A producer emits this only when the rendered template declares a key
    /// slot beyond `signing` / `ka`.** Every v1 template keeps producing
    /// [`Self::TemplateBootstrap`] byte-identically, so no existing opener sees
    /// this until someone deliberately provisions from a template asking for
    /// keys that opener cannot install.
    TemplateBootstrapV2(Box<super::template_bootstrap::TemplateBootstrapPayloadV2>),
    /// Admin-DID rotation only — no integration DID. Carries the
    /// VTA-issued admin authorization VC + freshly-minted admin DID
    /// key material + VTA trust anchor. Produced by the
    /// `BootstrapAsk::AdminRotation` server flow.
    ///
    /// Use this when the consumer brings its own integration DID and
    /// only needs to roll the ephemeral setup `did:key` over to a
    /// long-term admin identity at the VTA.
    AdminRotation(Box<super::template_bootstrap::AdminRotationPayload>),
    /// An issued credential sealed for an invite / unknown-holder (spec §6,
    /// task 3.6). The issuer seals a freshly-minted credential to the holder's
    /// known `did:key`; the holder opens it and receives it into its vault. See
    /// [`IssuedCredentialBundle`].
    IssuedCredential(Box<IssuedCredentialBundle>),
    /// Platform credentials for a `vti-message-bridge` connector — Signal
    /// registration, bot tokens, SMTP creds, Matrix access tokens, etc.
    ///
    /// Per the bridge's design (§10.1) platform secrets never ride in the DID
    /// template; they normally live in the connector's local `SeedStore`. When
    /// a connector is provisioned **remotely**, the secrets are delivered
    /// sealed via sealed-transfer instead — this variant is that payload,
    /// sealed to the connector's X25519 key-agreement derivation. Additive
    /// variant — no existing variant changes (issue #512). See
    /// [`MessagingBridgeCredentialsBundle`].
    MessagingBridgeCredentials(Box<MessagingBridgeCredentialsBundle>),
    /// A TEE VTA's BIP-39 seed mnemonic, released once during the first-boot
    /// export window (`POST /attestation/mnemonic`) for an offline paper
    /// backup.
    ///
    /// Sealed rather than returned as JSON: the mnemonic is the VTA's root
    /// derivation material (VTI-VTA-001, VTI-KEY-033), and a plaintext response
    /// exists in the clear wherever TLS terminates. Sealed to the operator's
    /// ephemeral `did:key` under an `Attested` producer assertion, it is
    /// readable only by that key and provably came from the enclave. Additive
    /// variant — no existing variant changes.
    SeedMnemonic(Box<SeedMnemonicBundle>),
}

/// The payload of [`SealedPayloadV1::SeedMnemonic`].
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SeedMnemonicBundle {
    /// The BIP-39 mnemonic phrase.
    pub mnemonic: String,
    /// The VTA whose seed this is, when it has a DID yet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vta_did: Option<String>,
}

/// Written by hand so the mnemonic never reaches a log.
impl std::fmt::Debug for SeedMnemonicBundle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SeedMnemonicBundle")
            .field("mnemonic", &"<redacted>")
            .field("vta_did", &self.vta_did)
            .finish()
    }
}

/// Platform credentials for a single `vti-message-bridge` connector. Mirrors
/// the bridge's `provisioning::PlatformCredentials`: `platform` is the
/// platform key (`signal`, `telegram`, `whatsapp`, `email`, `matrix`, …) and
/// `fields` carries the platform-specific secret name/value pairs. Sealed to
/// the connector's key-agreement DID derivation via sealed-transfer.
///
/// No `arbitrary` derive (it carries a `serde_json::Map`, same as
/// [`IssuedCredentialBundle`]); the fuzz harness covers the framing layer, not
/// this leaf payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MessagingBridgeCredentialsBundle {
    /// Platform key — `signal`, `telegram`, `whatsapp`, `email`, `matrix`, …
    pub platform: String,
    /// Platform-specific secret fields (the bridge interprets these per
    /// `platform`). Free-form so new platforms need no new variant.
    pub fields: serde_json::Map<String, serde_json::Value>,
}

/// An issued credential sealed for delivery to a holder the issuer cannot yet
/// reach over DIDComm — the **invite / unknown-holder** issuance case (spec
/// §6, task 3.6). The issuer mints the credential bound to the holder's known
/// `did:key` (from the invite), seals it to that holder's X25519 derivation,
/// and frames it in armor. The holder opens it with the same derived key and
/// receives it into its vault via the format-agnostic receive path.
///
/// The `credential` carries the issued credential exactly as an OID4VCI
/// credential response does — a JSON **string** for an SD-JWT-VC compact
/// serialization, or a JSON **object** for a W3C Data-Integrity VC (with its
/// `proof`). The holder infers the format from the value shape, identically to
/// the over-DIDComm `credential-exchange/issue` path.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssuedCredentialBundle {
    /// The issued credential — an SD-JWT-VC compact string or a W3C DI VC object.
    pub credential: serde_json::Value,
    /// The issuer DID, recorded as provenance on the stored credential.
    pub issuer_did: String,
    /// Optional human label / context hint shown to the holder at open time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

/// A single raw private key transferred inside a sealed bundle. The
/// `key_type` tag travels with the bytes so the server can reject a mismatch
/// between the outer request's declared key type and what was actually
/// sealed — a defence against a compromised client mis-declaring its key.
#[derive(Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[serde(deny_unknown_fields)]
pub struct RawPrivateKey {
    /// One of: `ed25519`, `x25519`, `p256`.
    pub key_type: String,
    /// Raw private key bytes, base64url-no-pad.
    pub key_bytes_b64: String,
}

/// Written by hand so the private key never reaches a log: a derived `Debug` would print it.
impl std::fmt::Debug for RawPrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RawPrivateKey")
            .field("key_type", &self.key_type)
            .field("key_bytes_b64", &"<redacted>")
            .finish()
    }
}

/// A digital signature over the producer's pubkey + the bundle digest, by a
/// known DID. Used in Modes A and C when the consumer knows the VTA's DID up
/// front.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[serde(deny_unknown_fields)]
pub struct DidSignedAssertion {
    pub did: String,
    /// Detached signature bytes (interpretation depends on the DID's key type),
    /// base64url-no-pad.
    pub signature_b64: String,
    /// Verification method id used (e.g. `did:webvh:.../keys#key-0`).
    pub verification_method: String,
}

/// An attestation quote (e.g. AWS Nitro CBOR document) committing to the
/// producer's pubkey + nonce + VTA pubkey. Used in Mode B (TEE first-boot).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[serde(deny_unknown_fields)]
pub struct AttestationQuoteAssertion {
    /// Vendor / format tag, e.g. "aws-nitro-v1".
    pub format: String,
    /// Raw attestation document, base64url-no-pad.
    pub quote_b64: String,
}

/// How the consumer establishes that the producer pubkey it pinned is the right
/// one for this bundle.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AssertionProof {
    /// DID-signed assertion. The consumer resolves the DID and verifies.
    DidSigned(DidSignedAssertion),
    /// Attestation quote. The consumer verifies the quote against vendor roots
    /// and matches `user_data`.
    Attested(AttestationQuoteAssertion),
    /// No further proof — the consumer is relying on the pinned pubkey alone.
    /// Out-of-band digest verification is the only integrity anchor.
    PinnedOnly,
}

/// The producer's claim that it owns the did:key embedded in chunk 0.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[serde(deny_unknown_fields)]
pub struct ProducerAssertion {
    /// Producer's ephemeral Ed25519 `did:key`. Pinned by the consumer
    /// out-of-band (PinnedOnly), bound into the attestation user_data
    /// (Attested), or cross-checked against the signing DID (DidSigned).
    pub producer_did: String,
    pub proof: AssertionProof,
}

/// Top-level sealed bundle. Carries one or more armored chunks plus the
/// metadata needed to verify and reassemble them.
///
/// In the wire format (armor), each chunk is a separate `BEGIN/END` block
/// sharing a `Bundle-Id`. This struct is the in-memory representation produced
/// by the armor parser.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct SealedBundle {
    pub bundle_id: [u8; 16],
    pub digest_algo: String,
    pub chunks: Vec<ArmoredChunk>,
}

/// One armored chunk of a sealed bundle.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct ArmoredChunk {
    pub chunk_index: u16,
    pub total_chunks: u16,
    /// HPKE-sealed payload (the `HpkeSealed` wire struct, CBOR-encoded).
    pub sealed_bytes: Vec<u8>,
}
