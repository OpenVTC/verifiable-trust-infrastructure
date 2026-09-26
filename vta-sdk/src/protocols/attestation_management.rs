//! DIDComm protocol types for TEE attestation management.

/// Request TEE detection status.
pub const GET_TEE_STATUS: &str = "https://firstperson.network/vta/1.0/attestation/status";
/// Response with TEE detection status.
pub const GET_TEE_STATUS_RESULT: &str =
    "https://firstperson.network/vta/1.0/attestation/status-result";

/// Request a fresh attestation report (body includes nonce).
pub const REQUEST_ATTESTATION: &str = "https://firstperson.network/vta/1.0/attestation/request";
/// Response with attestation report.
pub const ATTESTATION_RESULT: &str = "https://firstperson.network/vta/1.0/attestation/result";

/// Payload of `spec/vta/attestation/mnemonic-export/1.0`
/// ([`crate::trust_tasks::TASK_ATTESTATION_MNEMONIC_EXPORT_1_0`]): whom to seal
/// the mnemonic to. The same two values as a sealed-transfer
/// `BootstrapRequest` (`pnm bootstrap request`), in the Trust-Task wire form.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MnemonicExportBody {
    /// The requester's ephemeral Ed25519 `did:key`. The bundle is sealed to
    /// its X25519 counterpart.
    pub client_did: String,
    /// Random 16-byte nonce, base64url without padding. It becomes the
    /// bundle id, and the attestation quote binds it.
    pub nonce: String,
    /// Operator-visible label. Never part of what is sealed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// Ecosystem-defined extension members (SPEC §4.5.1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ext: Option<serde_json::Value>,
}

/// Response to `spec/vta/attestation/mnemonic-export/1.0`
/// ([`crate::trust_tasks::TASK_ATTESTATION_MNEMONIC_EXPORT_1_0`]): a TEE VTA's
/// BIP-39 seed mnemonic, sealed to the requester.
///
/// The request is a sealed-transfer `BootstrapRequest` (`pnm bootstrap request`):
/// the requester's ephemeral `did:key` and a fresh nonce. The bundle carries a
/// `SeedMnemonic` payload sealed to that key under an `Attested` producer
/// assertion; open it with `pnm bootstrap open --expect-digest <digest>`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MnemonicExportResultBody {
    /// ASCII-armored sealed bundle.
    pub bundle: String,
    /// SHA-256 of the bundle — confirm it out of band before opening.
    pub digest: String,
    /// Seconds that were left in the export window.
    pub window_remaining_secs: u64,
}
